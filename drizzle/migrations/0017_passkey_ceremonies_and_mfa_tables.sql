-- Server-side WebAuthn ceremonies: one-time, expiring challenges for passkey registration
-- and passkey login. Replaces the client-echoed enrollment/assertion sessions.
CREATE TABLE IF NOT EXISTS passkey_ceremonies (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  challenge TEXT NOT NULL,
  user_id TEXT,
  login_challenge_id TEXT,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON UPDATE NO ACTION ON DELETE CASCADE,
  FOREIGN KEY (login_challenge_id) REFERENCES login_challenges(id) ON UPDATE NO ACTION ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON UPDATE NO ACTION ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS passkey_ceremonies_tenant_id_idx ON passkey_ceremonies (tenant_id);
CREATE INDEX IF NOT EXISTS passkey_ceremonies_expires_at_idx ON passkey_ceremonies (expires_at);

-- totp_credentials and mfa_passkey_challenges exist in the root drizzle/0000 schema but were
-- never created by drizzle/migrations. Production lacked both tables, so the MFA paths failed
-- there. IF NOT EXISTS keeps this migration a no-op where they already exist.
CREATE TABLE IF NOT EXISTS totp_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  secret_encrypted TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  digits INTEGER NOT NULL,
  period INTEGER NOT NULL,
  last_used_window INTEGER DEFAULT 0 NOT NULL,
  enrolled_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON UPDATE NO ACTION ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE NO ACTION ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON UPDATE NO ACTION ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS totp_credentials_tenant_id_idx ON totp_credentials (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS totp_credentials_tenant_user_unique ON totp_credentials (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS mfa_passkey_challenges (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  login_challenge_id TEXT NOT NULL,
  challenge_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON UPDATE NO ACTION ON DELETE CASCADE,
  FOREIGN KEY (login_challenge_id) REFERENCES login_challenges(id) ON UPDATE NO ACTION ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS mfa_passkey_challenges_tenant_id_idx ON mfa_passkey_challenges (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS mfa_passkey_challenges_challenge_hash_active_unique
  ON mfa_passkey_challenges (challenge_hash) WHERE consumed_at IS NULL;
