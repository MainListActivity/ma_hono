CREATE TABLE IF NOT EXISTS user_provision_proofs (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  PRIMARY KEY (tenant_id, token_hash)
);
