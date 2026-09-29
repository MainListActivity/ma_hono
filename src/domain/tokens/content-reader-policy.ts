/**
 * Server-side policy for short-lived content_reader credential issuance.
 * Commercial entitlement facts are verified by the confidential app client;
 * this policy only constrains which clients/tenants/databases may mint tokens.
 */

export const CONTENT_READER_CONTRACT = "content_reader.v1" as const;

export const DEFAULT_CONTENT_READER_MAX_TTL_SECONDS = 15 * 60;

export interface ContentReaderIssuancePolicy {
  /** OAuth client_id values permitted to request content_reader tokens. */
  allowedClientIds: readonly string[];
  /**
   * Tenant IDs permitted to issue content_reader tokens.
   * Empty means any tenant that presents an allowlisted confidential client.
   */
  allowedTenantIds: readonly string[];
  /** SurrealDB database names allowed as `db` on content_reader tokens. */
  allowedContentDatabases: readonly string[];
  /** Hard ceiling for content_reader token lifetime in seconds. */
  maxTtlSeconds: number;
}

export const CONTENT_READER_PURPOSE_CLAIM_KEYS = [
  "ac",
  "db",
  "workspace_id",
  "entitlement_revision",
  "RL"
] as const;

const identityPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export const isContentReaderIdentity = (value: unknown): value is string =>
  typeof value === "string" && identityPattern.test(value);

export const createContentReaderIssuancePolicy = ({
  allowedClientIds,
  allowedTenantIds = [],
  allowedContentDatabases,
  maxTtlSeconds = DEFAULT_CONTENT_READER_MAX_TTL_SECONDS
}: {
  allowedClientIds: readonly string[];
  allowedTenantIds?: readonly string[];
  allowedContentDatabases: readonly string[];
  maxTtlSeconds?: number;
}): ContentReaderIssuancePolicy => {
  const clients = [
    ...new Set(allowedClientIds.map((value) => value.trim()).filter((value) => value.length > 0))
  ];
  const tenants = [
    ...new Set(allowedTenantIds.map((value) => value.trim()).filter((value) => value.length > 0))
  ];
  const databases = [
    ...new Set(
      allowedContentDatabases.map((value) => value.trim()).filter((value) => value.length > 0)
    )
  ];

  if (clients.length === 0) {
    throw new Error("content_reader policy requires at least one allowed client_id");
  }

  if (databases.length === 0) {
    throw new Error("content_reader policy requires at least one allowed content database");
  }

  if (
    !Number.isInteger(maxTtlSeconds) ||
    maxTtlSeconds <= 0 ||
    maxTtlSeconds > 24 * 60 * 60
  ) {
    throw new Error("content_reader maxTtlSeconds must be an integer from 1 to 86400");
  }

  return {
    allowedClientIds: clients,
    allowedTenantIds: tenants,
    allowedContentDatabases: databases,
    maxTtlSeconds
  };
};

export const isContentReaderIssuanceAllowed = ({
  clientId,
  policy,
  tenantId
}: {
  clientId: string;
  policy: ContentReaderIssuancePolicy | null | undefined;
  tenantId: string;
}): boolean => {
  if (policy === null || policy === undefined) {
    return false;
  }

  if (!policy.allowedClientIds.includes(clientId)) {
    return false;
  }

  if (policy.allowedTenantIds.length > 0 && !policy.allowedTenantIds.includes(tenantId)) {
    return false;
  }

  return true;
};

/**
 * Claim merge for content_reader:
 * 1. Resolve configured claims (fixed → user_field → hook, in config order).
 * 2. Drop purpose-boundary keys from configured/hook output.
 * 3. Overlay the fixed content_reader claims (ac/db/workspace/revision).
 * Config and hooks cannot widen purpose, database, or inject RL/publisher rights.
 */
export const mergeContentReaderClaims = ({
  configuredClaims,
  contentClaims
}: {
  configuredClaims: Record<string, unknown>;
  contentClaims: Record<string, unknown>;
}): Record<string, unknown> => {
  const merged: Record<string, unknown> = { ...configuredClaims };

  for (const key of CONTENT_READER_PURPOSE_CLAIM_KEYS) {
    delete merged[key];
  }

  return {
    ...merged,
    ...contentClaims
  };
};

export const computeContentReaderTtlSeconds = ({
  leaseEndSeconds,
  maxTtlSeconds,
  nowSeconds,
  subjectExpiresAt
}: {
  leaseEndSeconds: number;
  maxTtlSeconds: number;
  nowSeconds: number;
  subjectExpiresAt: number;
}): { ok: true; ttlSeconds: number } | { ok: false } => {
  if (
    !Number.isInteger(leaseEndSeconds) ||
    !Number.isInteger(subjectExpiresAt) ||
    !Number.isInteger(nowSeconds)
  ) {
    return { ok: false };
  }

  const remainingSubject = subjectExpiresAt - nowSeconds;
  const remainingLease = leaseEndSeconds - nowSeconds;

  if (remainingSubject <= 0 || remainingLease <= 0) {
    return { ok: false };
  }

  const ttlSeconds = Math.min(remainingSubject, remainingLease, maxTtlSeconds);

  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    return { ok: false };
  }

  return { ok: true, ttlSeconds };
};
