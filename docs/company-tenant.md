# 公司租户开通（company tenant）

本文说明如何用管理 API 为公司统一认证开通一个租户：建租户，登记四个 OIDC client，开一个 agent 用户，并配置 agent 令牌换发与各 client 的 fixed claim。

除第 0 步（人类管理员登录并铸造服务主体）和第 8 步末尾（吊销服务主体）外，示例都用服务主体令牌调用管理 API，不使用人类管理员密码。服务主体只能由人类管理员铸造和吊销，细节见 [admin-service-principals.md](./admin-service-principals.md)。

## 约定

- 管理 API 与 OIDC 宿主为 `o.maplayer.top`。租户 slug 为 `company`，issuer 为 `https://o.maplayer.top/t/company`。
- 尖括号内的值是占位符，需替换。`*.company.example` 为占位域名，需换成实际域名。
- 示例中的 fixed claim 只是示意。`ac`、`ns`、`db`、`rl` 的取值必须与公司 SurrealDB 的 access 定义、namespace 和 database 一致。
- `rl` 是 JSON 数组，因此 `fixed_value` 写 JSON 文本，并把 `value_type` 设为 `json`。
- `client_id` 由服务端生成，每次创建后从响应中取出，用于后续步骤。
- `client_secret` 只在创建或重置的响应中返回一次。立即存入调用方的 secret 存储，不写入日志、工单或文档。

## 第 0 步：准备服务主体（人类管理员）

开通期间的服务主体需要以下 scope。

| scope | 用途 |
| --- | --- |
| `tenant.read` | 列出租户（重跑时用于找到已建的租户） |
| `tenant.write` | 建租户 |
| `client.read` | 核对 client 配置 |
| `client.write` | 建 client，设置 fixed claim 与 agent 策略 |
| `user.read` | 核对 agent 用户（第 7 步） |
| `user.write` | 开 agent 用户 |

人类管理员登录后铸造服务主体。`token` 只返回一次。

```bash
# 人类管理员登录，仅在运维机上执行
curl -X POST https://o.maplayer.top/admin/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<whitelist-email>","password":"<bootstrap-password>"}'
# → { "email": "...", "session_token": "<session-token>" }

curl -X POST https://o.maplayer.top/admin/service-principals \
  -H "Authorization: Bearer <session-token>" \
  -H "Content-Type: application/json" \
  -d '{"label":"company-tenant-bootstrap","scopes":["tenant.read","tenant.write","client.read","client.write","user.read","user.write"]}'
# → { "id": "<principal-id>", "scopes": [...], "status": "active", "token": "<service-token>" }
```

后续命令使用以下变量：

```bash
export API="https://o.maplayer.top"
export SVC="<service-token>"
```

开通完成后，撤销这个服务主体（见第 8 步）。

## 第 1 步：建租户

```bash
curl -X POST "$API/admin/tenants" \
  -H "Authorization: Bearer $SVC" \
  -H "Content-Type: application/json" \
  -d '{"slug":"company","display_name":"Company"}'
# → 201 { "id": "<tenant-id>", "slug": "company", "display_name": "Company", "issuer": "https://o.maplayer.top/t/company" }

export TENANT_ID="<tenant-id>"
```

slug 已存在时返回 `409 conflict`。这时不要重复建租户，改为列出租户，取出 slug 为 `company` 的 `id`，再 `export TENANT_ID`。`GET /admin/tenants` 返回全部租户，不支持按 slug 过滤。

```bash
curl "$API/admin/tenants" \
  -H "Authorization: Bearer $SVC"
# → 200 { "tenants": [ { "id": "<tenant-id>", "slug": "company", "display_name": "Company", "status": "active", "issuer": "..." } ] }
```

## 第 2 步：建 agent claim 来源 client

agent 令牌的 fixed claim 从这个 client 复制（见第 4 步）。它只承载 claim，不用来换取令牌，因此不保存它的 secret。

```bash
curl -X POST "$API/admin/tenants/$TENANT_ID/clients" \
  -H "Authorization: Bearer $SVC" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Company agent claims",
    "client_profile": "web",
    "application_type": "web",
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["client_credentials"],
    "redirect_uris": [],
    "response_types": [],
    "access_token_custom_claims": [
      { "claim_name": "ac", "source_type": "fixed", "fixed_value": "agent" },
      { "claim_name": "ns", "source_type": "fixed", "fixed_value": "company" },
      { "claim_name": "db", "source_type": "fixed", "fixed_value": "main" },
      { "claim_name": "rl", "source_type": "fixed", "fixed_value": "[\"Editor\"]", "value_type": "json" }
    ]
  }'
# → 201 { "client_id": "<agent-claims-client-id>", "client_secret": "<returned once, do not store>", ... }

export AGENT_CLAIMS_CLIENT_ID="<agent-claims-client-id>"
```

agent 的权限取 `Editor`，比 runner 的 `Owner` 低，符合最小权限。

## 第 3 步：建 company-console（公开 SPA client）

console 是浏览器里的公开 client，使用 authorization code 加 PKCE，没有 secret。

```bash
curl -X POST "$API/admin/tenants/$TENANT_ID/clients" \
  -H "Authorization: Bearer $SVC" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Company console",
    "client_profile": "spa",
    "application_type": "web",
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "redirect_uris": ["https://console.company.example/auth/callback"],
    "access_token_audience": "company-api",
    "access_token_custom_claims": [
      { "claim_name": "ac", "source_type": "fixed", "fixed_value": "company_console" },
      { "claim_name": "ns", "source_type": "fixed", "fixed_value": "company" },
      { "claim_name": "db", "source_type": "fixed", "fixed_value": "main" },
      { "claim_name": "rl", "source_type": "fixed", "fixed_value": "[\"Editor\"]", "value_type": "json" }
    ]
  }'
# → 201 { "client_id": "<console-client-id>", ... }

export CONSOLE_CLIENT_ID="<console-client-id>"
```

`access_token_audience` 按公司 API 的 audience 填写，示例为 `company-api`。

fixed claim 对该 client 的所有登录用户都相同。如果 `rl` 需要按用户区分，不要用 fixed claim，应改用 hook claim（本文不展开）。

## 第 4 步：建 company-runner（机密 client，允许换发 agent 令牌）

runner 用 `client_credentials` 取得自身的机器令牌，并用 token exchange 为 agent 换发令牌。

```bash
curl -X POST "$API/admin/tenants/$TENANT_ID/clients" \
  -H "Authorization: Bearer $SVC" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Company runner",
    "client_profile": "web",
    "application_type": "web",
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["client_credentials"],
    "redirect_uris": [],
    "response_types": [],
    "machine_token_ttl_seconds": 900,
    "agent_token_exchange_enabled": true,
    "agent_claim_source_client_id": "'"$AGENT_CLAIMS_CLIENT_ID"'",
    "access_token_custom_claims": [
      { "claim_name": "ac", "source_type": "fixed", "fixed_value": "company_runner" },
      { "claim_name": "ns", "source_type": "fixed", "fixed_value": "company" },
      { "claim_name": "db", "source_type": "fixed", "fixed_value": "main" },
      { "claim_name": "rl", "source_type": "fixed", "fixed_value": "[\"Owner\"]", "value_type": "json" }
    ]
  }'
# → 201 { "client_id": "<runner-client-id>", "client_secret": "<returned once, store it>",
#         "agent_token_exchange_enabled": true, "agent_claim_source_client_id": "<agent-claims-client-id>", ... }

export RUNNER_CLIENT_ID="<runner-client-id>"
```

上面的 JSON 中 `agent_claim_source_client_id` 使用第 2 步的变量。`rl` 为 `Owner`，因为 runner 负责维护公司 namespace。如果不需要，改为 `Editor`。

`agent_token_exchange_enabled` 默认为 `false`。只有这个 client 需要换发 agent 令牌时才开启。

## 第 5 步：建 company-cron（机密 client）

cron 是定时任务，只用 `client_credentials` 取机器令牌，不换发 agent 令牌。

```bash
curl -X POST "$API/admin/tenants/$TENANT_ID/clients" \
  -H "Authorization: Bearer $SVC" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Company cron",
    "client_profile": "web",
    "application_type": "web",
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["client_credentials"],
    "redirect_uris": [],
    "response_types": [],
    "machine_token_ttl_seconds": 900,
    "access_token_custom_claims": [
      { "claim_name": "ac", "source_type": "fixed", "fixed_value": "company_cron" },
      { "claim_name": "ns", "source_type": "fixed", "fixed_value": "company" },
      { "claim_name": "db", "source_type": "fixed", "fixed_value": "main" },
      { "claim_name": "rl", "source_type": "fixed", "fixed_value": "[\"Editor\"]", "value_type": "json" }
    ]
  }'
# → 201 { "client_id": "<cron-client-id>", "client_secret": "<returned once, store it>", ... }

export CRON_CLIENT_ID="<cron-client-id>"
```

## 第 6 步：开 agent 用户

agent 用户以 `kind: "agent"` 开户。开户即 `active`，不发激活邀请，也没有密码。runner 用它的用户 id 作为 `subject_token` 换发令牌。

```bash
curl -X POST "$API/admin/tenants/$TENANT_ID/users" \
  -H "Authorization: Bearer $SVC" \
  -H "Content-Type: application/json" \
  -d '{"email":"company-agent@agents.company.example","display_name":"Company agent","kind":"agent"}'
# → 201 { "user": { "id": "<agent-user-id>", "kind": "agent", "status": "active", ... },
#         "invitation_token": null, "activation_url": null }

export AGENT_USER_ID="<agent-user-id>"
```

`kind` 只能在开户时指定，之后不能修改。

## 第 7 步：核对配置

```bash
curl "$API/admin/tenants/$TENANT_ID/clients" \
  -H "Authorization: Bearer $SVC"

curl "$API/admin/tenants/$TENANT_ID/clients/$RUNNER_CLIENT_ID" \
  -H "Authorization: Bearer $SVC"
# 确认 agent_token_exchange_enabled 为 true，agent_claim_source_client_id 指向第 2 步的 client，
# access_token_custom_claims 中 rl 的 value_type 为 json。响应不含 client_secret。

curl "$API/admin/tenants/$TENANT_ID/users?kind=agent" \
  -H "Authorization: Bearer $SVC"
# 确认 agent 用户存在，kind 为 agent。
```

## 第 8 步：日常运维

修改 fixed claim。`PATCH` 中的 `access_token_custom_claims` 会整体替换原有列表，因此要提交完整列表。不带该字段则保持不变。

```bash
curl -X PATCH "$API/admin/tenants/$TENANT_ID/clients/$CRON_CLIENT_ID" \
  -H "Authorization: Bearer $SVC" \
  -H "Content-Type: application/json" \
  -d '{"access_token_custom_claims":[
    { "claim_name": "ac", "source_type": "fixed", "fixed_value": "company_cron" },
    { "claim_name": "ns", "source_type": "fixed", "fixed_value": "company" },
    { "claim_name": "db", "source_type": "fixed", "fixed_value": "main" },
    { "claim_name": "rl", "source_type": "fixed", "fixed_value": "[\"Owner\"]", "value_type": "json" }
  ]}'
```

重置 client secret。旧 secret 立即失效，新 secret 只返回一次。

```bash
curl -X POST "$API/admin/tenants/$TENANT_ID/clients/$CRON_CLIENT_ID/secret/reset" \
  -H "Authorization: Bearer $SVC"
# → 200 { "client_id": "...", "client_secret": "<returned once>" }
```

停用或重新启用 agent 用户。停用后，它的换发请求会被拒绝。

```bash
curl -X PATCH "$API/admin/tenants/$TENANT_ID/users/$AGENT_USER_ID" \
  -H "Authorization: Bearer $SVC" \
  -H "Content-Type: application/json" \
  -d '{"status":"disabled"}'
```

轮换签名密钥。这个操作需要 `key.rotate` scope，开通服务主体不包含该 scope。

```bash
curl -X POST "$API/admin/tenants/$TENANT_ID/keys/rotate" \
  -H "Authorization: Bearer <service-token-with-key-rotate>"
# → 200 { "kid": "...", "alg": "RS256", "rotated_at": "..." }
```

开通完成后撤销开通用的服务主体。这需要人类管理员会话。

```bash
curl -X POST "$API/admin/service-principals/<principal-id>/revoke" \
  -H "Authorization: Bearer <session-token>"
```

## 第 9 步：运行时令牌

以下令牌由 OIDC token 端点签发，不属于管理 API。

| 调用方 | 请求 | 结果 |
| --- | --- | --- |
| company-cron、company-runner | `POST /t/company/token`，`grant_type=client_credentials`，`client_secret_basic` 认证 | access token，`exp` 最长 900 秒，不返回 refresh token 与 id token |
| company-runner 换发 agent 令牌 | `POST /t/company/token`，`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`，`subject_token_type=urn:ma-hono:params:oauth:token-type:agent-id`，`subject_token=<agent-user-id>`，`task_id`，可选 `ttl`（秒，最长 900） | `sub` 为 agent 用户 id，`task` 为 `task_id`，`act.sub` 为 runner 的 `client_id`（`$RUNNER_CLIENT_ID`），fixed claim 来自第 2 步的 client，不返回 refresh token 与 id token |

`task_id` 为 1 到 128 位的 `[A-Za-z0-9_-]`。

请求示例。client secret 从调用方的 secret 存储注入为 `$CRON_CLIENT_SECRET` 与 `$RUNNER_CLIENT_SECRET`，不要写进命令或 shell 历史。

```bash
# company-cron 取机器令牌
curl -X POST "$API/t/company/token" \
  -u "$CRON_CLIENT_ID:$CRON_CLIENT_SECRET" \
  -d "grant_type=client_credentials"
# → 200 { "access_token": "...", "token_type": "Bearer", "expires_in": 900 }

# company-runner 用 agent 用户 id 换发 agent 令牌，有效期 600 秒
curl -X POST "$API/t/company/token" \
  -u "$RUNNER_CLIENT_ID:$RUNNER_CLIENT_SECRET" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token_type=urn:ma-hono:params:oauth:token-type:agent-id" \
  -d "subject_token=$AGENT_USER_ID" \
  -d "task_id=task-42" \
  -d "ttl=600"
# → 200 { "access_token": "...", "token_type": "Bearer", "expires_in": 600 }
```

换发失败时的错误码：

| 情况 | 错误码 |
| --- | --- |
| 调用方是公开 client，或 secret 错误 | `invalid_client` |
| 调用方未开启 `agent_token_exchange_enabled` | `unauthorized_client` |
| `task_id` 缺失或格式不对，`ttl` 不是正整数 | `invalid_request` |
| agent 用户不存在、是 human、已停用、已过期，或属于其他租户 | `invalid_grant` |
| claim 来源 client 缺失或属于其他租户 | `server_error`（fail closed，不签发） |

## 注意事项

- `ac`、`ns`、`db`、`rl` 不是保留 claim 名。`sub`、`aud`、`act`、`task` 等 OIDC 与本系统保留的名字不能用作 fixed claim。
- agent 用户（`kind=agent`）不能用密码、magic link 或 passkey 登录，也不能通过授权码或 remote grant 取得人类令牌。
- 客户端 secret、服务主体令牌和人类管理员密码都不应出现在 curl 历史、日志或工单中。示例中的变量请用 secret 存储注入。
