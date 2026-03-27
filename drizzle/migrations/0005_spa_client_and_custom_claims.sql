ALTER TABLE oidc_clients ADD COLUMN client_profile TEXT NOT NULL DEFAULT 'web';
ALTER TABLE oidc_clients ADD COLUMN access_token_audience TEXT;

CREATE TABLE client_access_token_claims (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  claim_name TEXT NOT NULL,
  source_type TEXT NOT NULL,
  fixed_value TEXT,
  user_field TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX client_access_token_claims_tenant_id_idx ON client_access_token_claims(tenant_id);
CREATE INDEX client_access_token_claims_client_id_idx ON client_access_token_claims(client_id);
CREATE UNIQUE INDEX client_access_token_claims_client_claim_unique
  ON client_access_token_claims(client_id, claim_name);
