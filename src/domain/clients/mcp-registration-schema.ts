import { z } from "zod";

import { DEFAULT_MCP_SCOPES } from "../oidc/resource-policy";

const isLoopbackHost = (hostname: string) =>
  hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";

const mcpRedirectUriSchema = z.string().min(1).superRefine((value, context) => {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "redirect uri must be an absolute URL"
    });
    return;
  }

  if (url.username || url.password || url.search || url.hash) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "redirect uri must not contain credentials, query parameters, or fragments"
    });
    return;
  }

  const isLoopbackHttp = url.protocol === "http:" && isLoopbackHost(url.hostname);
  const isHttps = url.protocol === "https:";

  if (!isLoopbackHttp && !isHttps) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "MCP clients may use HTTPS or loopback HTTP redirect URIs"
    });
  }
});

const mcpScopeSchema = z.string().trim().min(1).superRefine((value, context) => {
  if (value === "openid" || !/^[a-z][a-z0-9._:-]{0,63}$/u.test(value)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "scope is not supported by the MCP resource"
    });
  }
});

/**
 * Public DCR accepts only the metadata needed for an MCP PKCE client.
 * Connector platforms often send minimal RFC 7591 metadata: omitted fields take the
 * public-PKCE defaults, unknown descriptive fields (logo_uri, client_uri, software_id…)
 * are dropped rather than failing the registration, and a scope without openid gets it
 * added. Security-relevant fields are still validated strictly and never taken from the
 * request (trust, audience and hooks are server-assigned).
 */
export const mcpClientRegistrationSchema = z
  .object({
    client_name: z.string().trim().min(1).max(200).default("MCP client"),
    application_type: z.enum(["web", "native"]).default("web"),
    grant_types: z
      .array(z.enum(["authorization_code", "refresh_token"]))
      .min(1)
      .max(2)
      .default(["authorization_code"])
      .superRefine((value, context) => {
        if (!value.includes("authorization_code")) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message: "grant_types must include authorization_code",
            path: ["grant_types"]
          });
        }
        if (new Set(value).size !== value.length) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message: "grant_types must not contain duplicates",
            path: ["grant_types"]
          });
        }
      }),
    redirect_uris: z.array(mcpRedirectUriSchema).min(1).max(16),
    response_types: z.array(z.literal("code")).length(1).default(["code"]),
    token_endpoint_auth_method: z.literal("none").default("none"),
    resource: z.string().trim().min(1).optional(),
    scope: z
      .string()
      .trim()
      .default(`openid ${DEFAULT_MCP_SCOPES[0]}`)
      .transform((value) => {
        const scopes = [...new Set(value.split(/\s+/u).filter(Boolean))];
        return (scopes.includes("openid") ? scopes : ["openid", ...scopes]).join(" ");
      })
      .superRefine((value, context) => {
        const scopes = value.split(" ");
        for (const scope of scopes.filter((entry) => entry !== "openid")) {
          mcpScopeSchema.safeParse(scope).success ||
            context.addIssue({
              code: z.ZodIssueCode.custom,
              message: `scope ${scope} is not supported by the MCP resource`,
              path: ["scope"]
            });
        }
      })
  })
  .strip()
  .superRefine((value, context) => {
    if (value.application_type === "web") {
      for (const redirectUri of value.redirect_uris) {
        const url = new URL(redirectUri);
        if (url.protocol !== "https:") {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message: "web MCP clients must use HTTPS redirect URIs",
            path: ["redirect_uris"]
          });
        }
      }
    }
  });

export type McpClientRegistrationInput = z.infer<typeof mcpClientRegistrationSchema>;
