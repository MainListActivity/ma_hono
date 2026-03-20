import { z } from "zod";

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
  grant_types: z.array(z.string()).min(1),
  redirect_uris: z.array(redirectUriSchema).min(1),
  response_types: z.array(z.string()).min(1),
  token_endpoint_auth_method: z.enum([
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "none"
  ])
});

export type DynamicClientRegistrationInput = z.infer<typeof dynamicClientRegistrationSchema>;
