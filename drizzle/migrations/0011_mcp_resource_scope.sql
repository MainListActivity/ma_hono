ALTER TABLE login_challenges ADD COLUMN resource TEXT;
ALTER TABLE authorization_codes ADD COLUMN resource TEXT;
ALTER TABLE refresh_tokens ADD COLUMN resource TEXT;
ALTER TABLE oidc_clients ADD COLUMN allowed_scopes TEXT;

CREATE INDEX IF NOT EXISTS login_challenges_resource_idx
  ON login_challenges(resource);
CREATE INDEX IF NOT EXISTS authorization_codes_resource_idx
  ON authorization_codes(resource);
CREATE INDEX IF NOT EXISTS refresh_tokens_resource_idx
  ON refresh_tokens(resource);
