import { z } from "zod";

const d1BindingSchema = z.custom<D1Database>(
  (value): value is D1Database => typeof value === "object" && value !== null,
  "D1 binding is required"
);

const kvBindingSchema = z.custom<KVNamespace>(
  (value): value is KVNamespace => typeof value === "object" && value !== null,
  "KV binding is required"
);

const r2BindingSchema = z.custom<R2Bucket>(
  (value): value is R2Bucket => typeof value === "object" && value !== null,
  "R2 binding is required"
);

const runtimeConfigSchema = z.object({
  ADMIN_BOOTSTRAP_PASSWORD: z.string().min(1),
  ADMIN_WHITELIST: z.string().min(1),
  ADMIN_SESSIONS_KV: kvBindingSchema,
  DB: d1BindingSchema,
  KEY_MATERIAL_R2: r2BindingSchema,
  MANAGEMENT_API_TOKEN: z.string().min(1),
  PLATFORM_HOST: z.string().min(1),
  REGISTRATION_TOKENS_KV: kvBindingSchema,
  USER_SESSIONS_KV: kvBindingSchema
});

export interface RuntimeConfig {
  adminBootstrapPassword: string;
  adminWhitelist: string[];
  adminSessionsKv: KVNamespace;
  db: D1Database;
  keyMaterialBucket: R2Bucket;
  managementApiToken: string;
  platformHost: string;
  registrationTokensKv: KVNamespace;
  userSessionsKv: KVNamespace;
}

export const readRuntimeConfig = (
  env: Record<string, unknown>
): RuntimeConfig => {
  const parsed = runtimeConfigSchema.parse(env);

  return {
    adminBootstrapPassword: parsed.ADMIN_BOOTSTRAP_PASSWORD,
    adminWhitelist: parsed.ADMIN_WHITELIST.split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
    adminSessionsKv: parsed.ADMIN_SESSIONS_KV,
    db: parsed.DB,
    keyMaterialBucket: parsed.KEY_MATERIAL_R2,
    managementApiToken: parsed.MANAGEMENT_API_TOKEN,
    platformHost: parsed.PLATFORM_HOST,
    registrationTokensKv: parsed.REGISTRATION_TOKENS_KV,
    userSessionsKv: parsed.USER_SESSIONS_KV
  };
};
