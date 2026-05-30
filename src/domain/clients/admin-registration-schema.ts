import { z } from "zod";

import {
  ALLOWED_USER_FIELDS,
  RESERVED_CLAIM_NAMES
} from "./access-token-claims-types";

const REGEX_PREFIX = "regex:";

const redirectUriSchema = z.string().superRefine((value, ctx) => {
  if (value.startsWith(REGEX_PREFIX)) {
    const pattern = value.slice(REGEX_PREFIX.length);
    if (pattern.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "regex pattern must not be empty"
      });
      return;
    }
    try {
      new RegExp(pattern);
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "redirect uri contains an invalid regex pattern"
      });
    }
    return;
  }

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

const httpHeaderNamePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

const claimHookUrlSchema = z.string().trim().min(1).superRefine((value, ctx) => {
  try {
    const url = new URL(value);

    if (url.protocol !== "https:" && url.protocol !== "http:") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "claim hook url must use http or https"
      });
    }
  } catch {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "claim hook url must be a valid absolute url"
    });
  }
});

const claimHookHeaderNameSchema = z
  .string()
  .trim()
  .min(1)
  .regex(httpHeaderNamePattern, "claim hook auth header name must be a valid HTTP header name");

const claimHookHeaderValueSchema = z.string().trim().min(1);

const validateClaimHookHeaderPair = (
  value: {
    claim_hook_auth_header_name?: string | null;
    claim_hook_auth_header_value?: string | null;
  },
  ctx: z.RefinementCtx
) => {
  const hasHeaderName =
    value.claim_hook_auth_header_name !== undefined &&
    value.claim_hook_auth_header_name !== null;
  const hasHeaderValue =
    value.claim_hook_auth_header_value !== undefined &&
    value.claim_hook_auth_header_value !== null;

  if (hasHeaderName !== hasHeaderValue) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "claim hook auth header requires both name and value",
      path: ["claim_hook_auth_header_name"]
    });
  }
};

const customClaimSchema = z
  .object({
    claim_name: z.string().min(1),
    source_type: z.enum(["fixed", "user_field", "hook"]),
    fixed_value: z.string().min(1).optional(),
    user_field: z.enum(ALLOWED_USER_FIELDS as [string, ...string[]]).optional(),
    hook_field: z.string().min(1).optional()
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

    if (value.source_type === "hook" && value.hook_field === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "hook claims require a non-empty hook_field",
        path: ["hook_field"]
      });
    }
  });

export const adminClientRegistrationSchema = z
  .object({
    client_name: z.string().min(1),
    client_profile: z.enum(["spa", "web", "native", "db"]),
    application_type: z.enum(["web", "native"]),
    grant_types: z.array(z.enum(["authorization_code"])),
    redirect_uris: z.array(redirectUriSchema),
    response_types: z.array(z.enum(["code"])),
    trust_level: z.literal("first_party_trusted").default("first_party_trusted"),
    consent_policy: z.literal("skip").default("skip"),
    token_endpoint_auth_method: z.enum([
      "client_secret_basic",
      "client_secret_post",
      "none"
    ]),
    access_token_audience: z.string().min(1).optional(),
    claim_hook_url: claimHookUrlSchema.optional(),
    claim_hook_auth_header_name: claimHookHeaderNameSchema.optional(),
    claim_hook_auth_header_value: claimHookHeaderValueSchema.optional(),
    access_token_custom_claims: z.array(customClaimSchema).max(20).optional()
  })
  .superRefine((value, ctx) => {
    validateClaimHookHeaderPair(value, ctx);

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

    if (value.client_profile !== "db") {
      if (value.grant_types.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "interactive clients require at least one grant type",
          path: ["grant_types"]
        });
      }

      if (value.response_types.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "interactive clients require at least one response type",
          path: ["response_types"]
        });
      }

      if (value.redirect_uris.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "interactive clients require at least one redirect uri",
          path: ["redirect_uris"]
        });
      }
    }

    if (value.client_profile === "db") {
      if (value.application_type !== "web") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must have application_type web",
          path: ["application_type"]
        });
      }

      if (value.token_endpoint_auth_method !== "none") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must use token_endpoint_auth_method none",
          path: ["token_endpoint_auth_method"]
        });
      }

      if (value.grant_types.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must not declare interactive grant types",
          path: ["grant_types"]
        });
      }

      if (value.response_types.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must not declare interactive response types",
          path: ["response_types"]
        });
      }

      if (value.redirect_uris.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must not declare redirect uris",
          path: ["redirect_uris"]
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

      if (value.client_profile === "db") {
        for (const [index, claim] of value.access_token_custom_claims.entries()) {
          if (claim.source_type !== "fixed") {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: "DB client custom claims must use fixed values",
              path: ["access_token_custom_claims", index, "source_type"]
            });
          }
        }
      }

      if (
        value.access_token_custom_claims.some((claim) => claim.source_type === "hook") &&
        value.claim_hook_url === undefined
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "hook custom claims require claim_hook_url",
          path: ["claim_hook_url"]
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

export const adminClientUpdateSchema = z
  .object({
    client_name: z.string().min(1).optional(),
    client_profile: z.enum(["spa", "web", "native", "db"]).optional(),
    application_type: z.enum(["web", "native"]).optional(),
    token_endpoint_auth_method: z
      .enum(["client_secret_basic", "client_secret_post", "none"])
      .optional(),
    redirect_uris: z.array(redirectUriSchema).optional(),
    grant_types: z.array(z.enum(["authorization_code"])).optional(),
    response_types: z.array(z.enum(["code"])).optional(),
    access_token_audience: z.string().min(1).nullable().optional(),
    claim_hook_url: claimHookUrlSchema.nullable().optional(),
    claim_hook_auth_header_name: claimHookHeaderNameSchema.nullable().optional(),
    claim_hook_auth_header_value: claimHookHeaderValueSchema.nullable().optional(),
    access_token_custom_claims: z.array(customClaimSchema).max(20).optional()
  })
  .superRefine((value, ctx) => {
    const profile = value.client_profile;

    if (profile === "spa") {
      if (value.application_type !== undefined && value.application_type !== "web") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SPA clients must have application_type web",
          path: ["application_type"]
        });
      }
      if (
        value.token_endpoint_auth_method !== undefined &&
        value.token_endpoint_auth_method !== "none"
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SPA clients must use token_endpoint_auth_method none",
          path: ["token_endpoint_auth_method"]
        });
      }
    }

    if (profile === "web") {
      if (value.token_endpoint_auth_method === "none") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "web clients must use a confidential auth method",
          path: ["token_endpoint_auth_method"]
        });
      }
    }

    if (profile === "db") {
      if (value.application_type !== undefined && value.application_type !== "web") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must have application_type web",
          path: ["application_type"]
        });
      }

      if (
        value.token_endpoint_auth_method !== undefined &&
        value.token_endpoint_auth_method !== "none"
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must use token_endpoint_auth_method none",
          path: ["token_endpoint_auth_method"]
        });
      }

      if (value.grant_types !== undefined && value.grant_types.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must not declare interactive grant types",
          path: ["grant_types"]
        });
      }

      if (value.response_types !== undefined && value.response_types.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must not declare interactive response types",
          path: ["response_types"]
        });
      }

      if (value.redirect_uris !== undefined && value.redirect_uris.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DB clients must not declare redirect uris",
          path: ["redirect_uris"]
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

      if (profile === "db") {
        for (const [index, claim] of value.access_token_custom_claims.entries()) {
          if (claim.source_type !== "fixed") {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: "DB client custom claims must use fixed values",
              path: ["access_token_custom_claims", index, "source_type"]
            });
          }
        }
      }
    }
  });

export type AdminClientUpdateInput = z.infer<typeof adminClientUpdateSchema>;
