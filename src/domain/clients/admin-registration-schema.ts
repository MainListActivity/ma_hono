import { z } from "zod";

import {
  ALLOWED_USER_FIELDS,
  RESERVED_CLAIM_NAMES
} from "./access-token-claims-types";

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

const customClaimSchema = z
  .object({
    claim_name: z.string().min(1),
    source_type: z.enum(["fixed", "user_field"]),
    fixed_value: z.string().min(1).optional(),
    user_field: z.enum(ALLOWED_USER_FIELDS as [string, ...string[]]).optional()
  })
  .superRefine((value, ctx) => {
    if (RESERVED_CLAIM_NAMES.has(value.claim_name)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `claim name "${value.claim_name}" is reserved`,
        path: ["claim_name"]
      });
    }

    if (value.source_type === "fixed" && value.fixed_value === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "fixed claims require a non-empty fixed_value",
        path: ["fixed_value"]
      });
    }

    if (value.source_type === "user_field" && value.user_field === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "user_field claims require an allowed user_field",
        path: ["user_field"]
      });
    }
  });

export const adminClientRegistrationSchema = z
  .object({
    client_name: z.string().min(1),
    client_profile: z.enum(["spa", "web", "native"]),
    application_type: z.enum(["web", "native"]),
    grant_types: z.array(z.enum(["authorization_code"])).min(1),
    redirect_uris: z.array(redirectUriSchema).min(1),
    response_types: z.array(z.enum(["code"])).min(1),
    trust_level: z.literal("first_party_trusted").default("first_party_trusted"),
    consent_policy: z.literal("skip").default("skip"),
    token_endpoint_auth_method: z.enum([
      "client_secret_basic",
      "client_secret_post",
      "none"
    ]),
    access_token_audience: z.string().min(1).optional(),
    access_token_custom_claims: z.array(customClaimSchema).max(20).optional()
  })
  .superRefine((value, ctx) => {
    if (value.client_profile === "spa") {
      if (value.application_type !== "web") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SPA clients must have application_type web",
          path: ["application_type"]
        });
      }

      if (value.token_endpoint_auth_method !== "none") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SPA clients must use token_endpoint_auth_method none",
          path: ["token_endpoint_auth_method"]
        });
      }

      if (value.access_token_audience === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SPA clients require an access_token_audience",
          path: ["access_token_audience"]
        });
      }
    }

    if (value.access_token_custom_claims) {
      const names = value.access_token_custom_claims.map((c) => c.claim_name);
      const duplicates = names.filter(
        (name, index) => names.indexOf(name) !== index
      );

      for (const dup of new Set(duplicates)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `duplicate claim name "${dup}"`,
          path: ["access_token_custom_claims"]
        });
      }
    }

    if (value.client_profile === "web") {
      if (value.token_endpoint_auth_method === "none") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "web clients must use a confidential auth method",
          path: ["token_endpoint_auth_method"]
        });
      }
    }
  });

export type AdminClientRegistrationInput = z.infer<
  typeof adminClientRegistrationSchema
>;
