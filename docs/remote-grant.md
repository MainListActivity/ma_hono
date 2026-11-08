# 远程一次性兑换授权（remote grant）

## 数据模型

- `users.expires_at` / `users.test_origin`：非 NULL `expires_at` 即测试账号；到期后所有登录与续期被拒，并被每日 cron 级联清除。
- `remote_grants`：`id / tenant_id / user_id / client_id(OAuth client_id 字符串) / code_hash(sha256 base64url) / code_expires_at / code_consumed_at / resources_json(audience 数组) / task_ref / expires_at / status('active'|'revoked') / created_at / revoked_at`。
- `refresh_tokens.remote_grant_id`：标记该 refresh 属于哪个 grant 族。

## 兑换语义

`POST /t/:tenant/token`，`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`、`subject_token_type=urn:ma-hono:params:oauth:token-type:remote-grant-code`、`subject_token=<兑换码>`、`client_id=<public client>`。公开 client（`token_endpoint_auth_method=none`），且其 `grant_types` 必须包含该 grant type；`client_id` 须等于 grant 登记 client。可选 `resource`（必须 ∈ `resources_json`，缺省取第一个）。兑换是单条原子 UPDATE 实现的一次性消费；失败一律 `invalid_grant`，不区分原因。

## 续期与撤销

- 新 access token TTL = min(策略 TTL, grant 剩余秒)；refresh `absolute_expires_at` = `grant.expires_at`（≤31 天上限由签发方控制 grant 期限）。
- refresh 时 grant 必须仍 active 未过期；`resource` 须在允许列表；用户到期/非 active 一律 `invalid_grant`。
- remote 族 refresh token 重放（已消费票再次出现）→ grant 整体置 revoked + 审计 `oidc.remote_grant.revoked_on_reuse`。
- 审计：`oidc.remote_grant.redeemed` / `redeem_failed`（payload 只有 grant_id/client_id/reason，绝不含码）。

## 运维代理需写入的 D1 行

`users`（expires_at、test_origin 非空）+ `remote_grants`（码只存 `code_hash`，与 `sha256Base64Url` 一致）。示例：

```sql
INSERT INTO remote_grants (id, tenant_id, user_id, client_id, code_hash,
  code_expires_at, code_consumed_at, resources_json, task_ref,
  expires_at, status, created_at, revoked_at)
VALUES ('rg_<uuid>', '<tenant>', '<user_id>', '<remote_client_id>',
  '<sha256_base64url(code)>', '<code 到期 ISO>', NULL,
  '["<audience>"]', '<task-ref>', '<grant 到期 ISO>', 'active', '<now ISO>', NULL);
```

## 清理 cron

`wrangler.jsonc` `triggers.crons: ["17 19 * * *"]` → `scheduled` handler → `purgeExpiredTestUsers`：每批 ≤200，只处理 `expires_at IS NOT NULL AND expires_at <= now` 的用户，级联删除全部 user_id 数据（审计表保留），逐用户 `user.expired_purged` 审计，单用户失败不影响其它。

## client 登记

`scripts/register-remote-client.sql`：`wrangler d1 execute DB --remote --file scripts/register-remote-client.sql`（先替换 `__REMOTE_CLIENT_ID__`/`__PRODUCT_CLIENT_ID__`）。public client，audience/hook/策略从产品 client 行复制。
