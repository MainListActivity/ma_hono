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

/** Public DCR accepts only the metadata needed for an MCP PKCE client. */
export const mcpClientRegistrationSchema = z
  .object({
    client_name: z.string().trim().min(1).max(200),
    application_type: z.enum(["web", "native"]),
    grant_types: z.array(z.literal("authorization_code")).length(1),
    redirect_uris: z.array(mcpRedirectUriSchema).min(1).max(16),
    response_types: z.array(z.literal("code")).length(1),
    token_endpoint_auth_method: z.literal("none"),
    resource: z.string().trim().min(1).optional(),
    scope: z
      .string()
      .trim()
      .default(`openid ${DEFAULT_MCP_SCOPES[0]}`)
      .superRefine((value, context) => {
        const scopes = [...new Set(value.split(/\s+/u).filter(Boolean))];
        if (!scopes.includes("openid")) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message: "scope must include openid"
          });
        }
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
  .strict()
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
