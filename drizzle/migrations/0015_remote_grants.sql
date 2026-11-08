ALTER TABLE users ADD COLUMN expires_at TEXT;
ALTER TABLE users ADD COLUMN test_origin TEXT;

ALTER TABLE refresh_tokens ADD COLUMN remote_grant_id TEXT;

CREATE TABLE remote_grants (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  code_expires_at TEXT NOT NULL,
  code_consumed_at TEXT,
  resources_json TEXT NOT NULL,
  task_ref TEXT,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX remote_grants_code_hash_unique
  ON remote_grants(code_hash);
CREATE INDEX remote_grants_tenant_user_idx
  ON remote_grants(tenant_id, user_id);
