import { z } from "zod";

const supportedGrantTypes = z.enum(["authorization_code"]);
const supportedResponseTypes = z.enum(["code"]);

const redirectUriSchema = z.string().superRefine((value, ctx) => {
  try {
    const url = new URL(value);

    if (url.protocol.length < 2) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "redirect uri must be absolute"
      });
    }
  } catch {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "redirect uri must be a valid absolute url"
    });
  }
});

export const dynamicClientRegistrationSchema = z.object({
  client_name: z.string().min(1),
  application_type: z.enum(["web", "native"]),
  grant_types: z.array(supportedGrantTypes).min(1),
  redirect_uris: z.array(redirectUriSchema).min(1),
  response_types: z.array(supportedResponseTypes).min(1),
  token_endpoint_auth_method: z.enum([
    "client_secret_basic",
    "client_secret_post",
    "none"
  ])
}).superRefine((value, context) => {
  if (
    value.token_endpoint_auth_method === "none" &&
    value.application_type === "web"
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "web applications must use a confidential or key-based auth method",
      path: ["token_endpoint_auth_method"]
    });
  }
});

export type DynamicClientRegistrationInput = z.infer<typeof dynamicClientRegistrationSchema>;
