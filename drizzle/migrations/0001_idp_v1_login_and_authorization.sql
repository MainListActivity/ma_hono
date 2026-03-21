PRAGMA foreign_keys = ON;

ALTER TABLE oidc_clients ADD COLUMN trust_level TEXT NOT NULL DEFAULT 'first_party_trusted';
ALTER TABLE oidc_clients ADD COLUMN consent_policy TEXT NOT NULL DEFAULT 'skip';

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  email_verified INTEGER NOT NULL,
  username TEXT,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_id_email_unique
  ON users (tenant_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_id_username_unique
  ON users (tenant_id, username);
CREATE INDEX IF NOT EXISTS users_tenant_id_idx
  ON users (tenant_id);

CREATE TABLE IF NOT EXISTS user_password_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS user_password_credentials_user_id_unique
  ON user_password_credentials (user_id);
CREATE INDEX IF NOT EXISTS user_password_credentials_tenant_id_idx
  ON user_password_credentials (tenant_id);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT,
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS webauthn_credentials_credential_id_unique
  ON webauthn_credentials (credential_id);
CREATE INDEX IF NOT EXISTS webauthn_credentials_tenant_id_idx
  ON webauthn_credentials (tenant_id);
CREATE INDEX IF NOT EXISTS webauthn_credentials_user_id_idx
  ON webauthn_credentials (user_id);

CREATE TABLE IF NOT EXISTS tenant_auth_method_policies (
  tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  password_enabled INTEGER NOT NULL,
  email_magic_link_enabled INTEGER NOT NULL,
  passkey_enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS tenant_auth_method_policies_password_enabled_idx
  ON tenant_auth_method_policies (password_enabled);

CREATE TABLE IF NOT EXISTS user_invitations (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS user_invitations_tenant_id_idx
  ON user_invitations (tenant_id);
CREATE INDEX IF NOT EXISTS user_invitations_user_id_idx
  ON user_invitations (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS user_invitations_token_hash_active_unique
  ON user_invitations (token_hash)
  WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS login_challenges (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  state TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS login_challenges_tenant_id_idx
  ON login_challenges (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS login_challenges_token_hash_active_unique
  ON login_challenges (token_hash)
  WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS authorization_codes (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  nonce TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS authorization_codes_tenant_id_idx
  ON authorization_codes (tenant_id);
CREATE INDEX IF NOT EXISTS authorization_codes_user_id_idx
  ON authorization_codes (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS authorization_codes_token_hash_active_unique
  ON authorization_codes (token_hash)
  WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS email_login_tokens (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  redirect_after_login TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS email_login_tokens_tenant_id_idx
  ON email_login_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS email_login_tokens_user_id_idx
  ON email_login_tokens (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS email_login_tokens_token_hash_active_unique
  ON email_login_tokens (token_hash)
  WHERE consumed_at IS NULL;
