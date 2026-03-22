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
  ADMIN_SESSIONS_KV: kvBindingSchema,
  DB: d1BindingSchema,
  KEY_MATERIAL_R2: r2BindingSchema,
  REGISTRATION_TOKENS_KV: kvBindingSchema,
  USER_SESSIONS_KV: kvBindingSchema
});

export interface RuntimeConfig {
  adminSessionsKv: KVNamespace;
  db: D1Database;
  keyMaterialBucket: R2Bucket;
  registrationTokensKv: KVNamespace;
  userSessionsKv: KVNamespace;
}

export const readRuntimeConfig = (
  env: Record<string, unknown>
): RuntimeConfig => {
  const parsed = runtimeConfigSchema.parse(env);

  return {
    adminSessionsKv: parsed.ADMIN_SESSIONS_KV,
    db: parsed.DB,
    keyMaterialBucket: parsed.KEY_MATERIAL_R2,
    registrationTokensKv: parsed.REGISTRATION_TOKENS_KV,
    userSessionsKv: parsed.USER_SESSIONS_KV
  };
};
