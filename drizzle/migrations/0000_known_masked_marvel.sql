PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY NOT NULL,
  slug TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS tenants_slug_unique ON tenants (slug);
CREATE INDEX IF NOT EXISTS tenants_status_idx ON tenants (status);

CREATE TABLE IF NOT EXISTS tenant_issuers (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  issuer_type TEXT NOT NULL,
  issuer_url TEXT NOT NULL,
  domain TEXT,
  is_primary INTEGER NOT NULL,
  verification_status TEXT NOT NULL,
  verified_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS tenant_issuers_issuer_url_unique
  ON tenant_issuers (issuer_url);
CREATE UNIQUE INDEX IF NOT EXISTS tenant_issuers_domain_unique
  ON tenant_issuers (domain);
CREATE INDEX IF NOT EXISTS tenant_issuers_tenant_id_idx
  ON tenant_issuers (tenant_id);

CREATE TABLE IF NOT EXISTS oidc_clients (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  client_secret_hash TEXT,
  client_name TEXT NOT NULL,
  application_type TEXT NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  response_types TEXT NOT NULL,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS oidc_clients_client_id_unique
  ON oidc_clients (client_id);
CREATE INDEX IF NOT EXISTS oidc_clients_tenant_id_idx
  ON oidc_clients (tenant_id);

CREATE TABLE IF NOT EXISTS signing_keys (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE,
  kid TEXT NOT NULL,
  alg TEXT NOT NULL,
  kty TEXT NOT NULL,
  public_jwk TEXT NOT NULL,
  private_key_ref TEXT,
  status TEXT NOT NULL,
  activated_at TEXT,
  retire_at TEXT,
  created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_kid_unique ON signing_keys (kid);
CREATE INDEX IF NOT EXISTS signing_keys_tenant_id_idx ON signing_keys (tenant_id);

CREATE TABLE IF NOT EXISTS admin_users (
  id TEXT PRIMARY KEY NOT NULL,
  email TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS admin_users_email_unique ON admin_users (email);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  payload TEXT,
  occurred_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_events_tenant_id_idx ON audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS audit_events_event_type_idx ON audit_events (event_type);
