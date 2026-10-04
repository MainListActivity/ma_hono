CREATE TABLE admin_service_principals (
  id TEXT PRIMARY KEY NOT NULL,
  label TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  scopes TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  created_by TEXT NOT NULL
);

CREATE UNIQUE INDEX admin_service_principals_token_hash_unique
  ON admin_service_principals(token_hash);
CREATE INDEX admin_service_principals_status_idx
  ON admin_service_principals(status);
