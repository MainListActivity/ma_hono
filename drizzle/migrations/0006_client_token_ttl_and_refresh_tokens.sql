ALTER TABLE client_auth_method_policies
  ADD COLUMN password_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600;

ALTER TABLE client_auth_method_policies
  ADD COLUMN magic_link_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600;
ALTER TABLE client_auth_method_policies
  ADD COLUMN mfa_required INTEGER NOT NULL DEFAULT 0;

ALTER TABLE client_auth_method_policies
  ADD COLUMN passkey_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600;

ALTER TABLE client_auth_method_policies
  ADD COLUMN google_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600;

ALTER TABLE client_auth_method_policies
  ADD COLUMN apple_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600;

ALTER TABLE client_auth_method_policies
  ADD COLUMN facebook_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600;

ALTER TABLE client_auth_method_policies
  ADD COLUMN wechat_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600;

ALTER TABLE login_challenges
  ADD COLUMN auth_method TEXT;

ALTER TABLE authorization_codes
  ADD COLUMN auth_method TEXT;

CREATE TABLE refresh_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  auth_method TEXT,
  token_hash TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  consumed_at TEXT,
  parent_token_id TEXT,
  replaced_by_token_id TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, client_id) REFERENCES oidc_clients(tenant_id, client_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX refresh_tokens_tenant_id_idx
  ON refresh_tokens(tenant_id);

CREATE INDEX refresh_tokens_client_id_idx
  ON refresh_tokens(client_id);

CREATE INDEX refresh_tokens_user_id_idx
  ON refresh_tokens(user_id);

CREATE UNIQUE INDEX refresh_tokens_token_hash_active_unique
  ON refresh_tokens(token_hash)
  WHERE consumed_at IS NULL;
