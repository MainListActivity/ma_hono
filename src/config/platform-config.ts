const REQUIRED_KEYS = [
  "admin_bootstrap_password_hash",
  "admin_whitelist",
  "management_api_token",
  "platform_host"
] as const;

export interface PlatformConfig {
  adminBootstrapPasswordHash: string;
  adminWhitelist: string[];
  managementApiToken: string;
  platformHost: string;
}

export const loadPlatformConfig = async (
  db: D1Database
): Promise<PlatformConfig | null> => {
  const { results } = await db
    .prepare(
      `SELECT key, value FROM platform_config WHERE key IN (?, ?, ?, ?)`
    )
    .bind(...REQUIRED_KEYS)
    .all<{ key: string; value: string }>();

  const map = new Map(results.map((r) => [r.key, r.value]));

  for (const key of REQUIRED_KEYS) {
    if (!map.has(key)) {
      return null;
    }
  }

  return {
    adminBootstrapPasswordHash: map.get("admin_bootstrap_password_hash")!,
    adminWhitelist: map
      .get("admin_whitelist")!
      .split(",")
      .map((v) => v.trim())
      .filter((v) => v.length > 0),
    managementApiToken: map.get("management_api_token")!,
    platformHost: map.get("platform_host")!
  };
};
