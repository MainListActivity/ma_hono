CREATE TABLE access_token_revocations (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, client_id) REFERENCES oidc_clients(tenant_id, client_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX access_token_revocations_token_hash_unique
  ON access_token_revocations(token_hash);
CREATE INDEX access_token_revocations_expires_at_idx
  ON access_token_revocations(expires_at);
