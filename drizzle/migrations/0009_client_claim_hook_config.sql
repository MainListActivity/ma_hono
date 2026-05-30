ALTER TABLE oidc_clients ADD COLUMN claim_hook_url TEXT;
ALTER TABLE oidc_clients ADD COLUMN claim_hook_auth_header_name TEXT;
ALTER TABLE oidc_clients ADD COLUMN claim_hook_auth_header_value TEXT;
