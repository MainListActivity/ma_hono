import { z } from "zod";

const runtimeConfigSchema = z.object({
  ADMIN_BOOTSTRAP_PASSWORD: z.string().min(1),
  ADMIN_WHITELIST: z.string().min(1),
  MANAGEMENT_API_TOKEN: z.string().min(1),
  PLATFORM_HOST: z.string().min(1)
});

export interface RuntimeConfig {
  adminBootstrapPassword: string;
  adminWhitelist: string[];
  managementApiToken: string;
  platformHost: string;
}

export const readRuntimeConfig = (
  env: Record<string, string | undefined>
): RuntimeConfig => {
  const parsed = runtimeConfigSchema.parse(env);

  return {
    adminBootstrapPassword: parsed.ADMIN_BOOTSTRAP_PASSWORD,
    adminWhitelist: parsed.ADMIN_WHITELIST.split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
    managementApiToken: parsed.MANAGEMENT_API_TOKEN,
    platformHost: parsed.PLATFORM_HOST
  };
};
