ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'human';

ALTER TABLE client_access_token_claims ADD COLUMN value_type TEXT NOT NULL DEFAULT 'string';

ALTER TABLE oidc_clients ADD COLUMN machine_token_ttl_seconds INTEGER;
ALTER TABLE oidc_clients ADD COLUMN agent_token_exchange_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_clients ADD COLUMN agent_claim_source_client_id TEXT;
