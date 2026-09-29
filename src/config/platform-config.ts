import {
  createContentReaderIssuancePolicy,
  DEFAULT_CONTENT_READER_MAX_TTL_SECONDS,
  type ContentReaderIssuancePolicy
} from "../domain/tokens/content-reader-policy";

const REQUIRED_KEYS = [
  "admin_bootstrap_password_hash",
  "admin_whitelist",
  "management_api_token",
  "root_domain"
] as const;

const CONTENT_READER_KEYS = [
  "content_reader_allowed_client_ids",
  "content_reader_allowed_tenant_ids",
  "content_reader_allowed_databases",
  "content_reader_max_ttl_seconds"
] as const;

export interface PlatformConfig {
  adminBootstrapPasswordHash: string;
  adminWhitelist: string[];
  managementApiToken: string;
  /** Root domain, e.g. "maplayer.top". Derives authDomain = auth.{root} and oidcHost = o.{root}. */
  rootDomain: string;
}

const splitCsv = (value: string | undefined): string[] =>
  (value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

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
    adminWhitelist: splitCsv(map.get("admin_whitelist")),
    managementApiToken: map.get("management_api_token")!,
    rootDomain: map.get("root_domain")!
  };
};

/**
 * Optional content_reader issuance allowlist.
 * Requires `content_reader_allowed_client_ids`; databases default to `platform_content`.
 */
export const loadContentReaderIssuancePolicy = async (
  db: D1Database
): Promise<ContentReaderIssuancePolicy | null> => {
  const { results } = await db
    .prepare(
      `SELECT key, value FROM platform_config WHERE key IN (?, ?, ?, ?)`
    )
    .bind(...CONTENT_READER_KEYS)
    .all<{ key: string; value: string }>();

  const map = new Map(results.map((row) => [row.key, row.value]));
  const allowedClientIds = splitCsv(map.get("content_reader_allowed_client_ids"));

  if (allowedClientIds.length === 0) {
    return null;
  }

  const allowedContentDatabases = splitCsv(map.get("content_reader_allowed_databases"));
  const maxTtlRaw = map.get("content_reader_max_ttl_seconds");
  const maxTtlSeconds =
    maxTtlRaw === undefined || maxTtlRaw.trim().length === 0
      ? DEFAULT_CONTENT_READER_MAX_TTL_SECONDS
      : Number(maxTtlRaw);

  try {
    return createContentReaderIssuancePolicy({
      allowedClientIds,
      allowedTenantIds: splitCsv(map.get("content_reader_allowed_tenant_ids")),
      allowedContentDatabases:
        allowedContentDatabases.length > 0 ? allowedContentDatabases : ["platform_content"],
      maxTtlSeconds
    });
  } catch {
    return null;
  }
};
