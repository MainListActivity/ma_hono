-- 幂等登记 remote-grant 公开 client（token-exchange + refresh_token）。
-- 用法：wrangler d1 execute DB --remote --file scripts/register-remote-client.sql
-- 下面两个占位值执行前替换：__REMOTE_CLIENT_ID__、__PRODUCT_CLIENT_ID__
-- access_token_audience / claim_hook_* / client_auth_method_policies 均从产品 client 行复制，不含任何 secret。

INSERT INTO oidc_clients (
  id, tenant_id, client_id, client_secret_hash, client_name, application_type,
  trust_level, consent_policy, client_profile, access_token_audience,
  allowed_scopes, initiate_login_uri, claim_hook_url,
  claim_hook_auth_header_name, claim_hook_auth_header_value,
  token_endpoint_auth_method, redirect_uris, grant_types, response_types,
  created_by, created_at, updated_at
)
SELECT
  lower(hex(randomblob(16))), p.tenant_id, '__REMOTE_CLIENT_ID__', NULL, 'remote-grant client', 'native',
  p.trust_level, 'skip', 'web', p.access_token_audience,
  p.allowed_scopes, NULL, p.claim_hook_url,
  p.claim_hook_auth_header_name, p.claim_hook_auth_header_value,
  'none', '[]', '["urn:ietf:params:oauth:grant-type:token-exchange","refresh_token"]', '[]',
  'register-remote-client.sql', datetime('now'), datetime('now')
FROM oidc_clients p
WHERE p.client_id = '__PRODUCT_CLIENT_ID__'
ON CONFLICT(client_id) DO NOTHING;

INSERT INTO client_auth_method_policies (
  client_id, tenant_id,
  password_enabled, password_allow_registration, password_token_ttl_seconds,
  magic_link_enabled, magic_link_allow_registration, magic_link_token_ttl_seconds,
  passkey_enabled, passkey_allow_registration, passkey_token_ttl_seconds,
  google_enabled, google_token_ttl_seconds,
  apple_enabled, apple_token_ttl_seconds,
  facebook_enabled, facebook_token_ttl_seconds,
  wechat_enabled, wechat_token_ttl_seconds,
  mfa_required, created_at, updated_at
)
SELECT
  r.id, r.tenant_id,
  p.password_enabled, p.password_allow_registration, p.password_token_ttl_seconds,
  p.magic_link_enabled, p.magic_link_allow_registration, p.magic_link_token_ttl_seconds,
  p.passkey_enabled, p.passkey_allow_registration, p.passkey_token_ttl_seconds,
  p.google_enabled, p.google_token_ttl_seconds,
  p.apple_enabled, p.apple_token_ttl_seconds,
  p.facebook_enabled, p.facebook_token_ttl_seconds,
  p.wechat_enabled, p.wechat_token_ttl_seconds,
  p.mfa_required, datetime('now'), datetime('now')
FROM oidc_clients r
JOIN client_auth_method_policies p ON p.client_id = (
  SELECT id FROM oidc_clients WHERE client_id = '__PRODUCT_CLIENT_ID__'
)
WHERE r.client_id = '__REMOTE_CLIENT_ID__'
ON CONFLICT(client_id) DO NOTHING;
