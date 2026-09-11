CREATE TABLE consent_challenges (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT,
  state TEXT,
  nonce TEXT,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, client_id) REFERENCES oidc_clients(tenant_id, client_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX consent_challenges_tenant_id_idx ON consent_challenges(tenant_id);
CREATE UNIQUE INDEX consent_challenges_token_hash_active_unique
  ON consent_challenges(token_hash)
  WHERE consumed_at IS NULL;
