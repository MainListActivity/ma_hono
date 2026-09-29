Status: done
Label: verified
Assignee: unassigned
ID: IDP-OM-02
Repository: ma_hono

# 提供受限 MCP 动态客户端注册

Parent: [跨仓 OAuth 规格](../PRD.md)

## Dependencies

- [01-resource-policy](01-resource-policy.md)

## Scope

- 新增面向 MCP 的 DCR 及 discovery registration_endpoint，保留原管理注册端点保护，不向客户端暴露 managementApiToken。
- 注册产生 public client + PKCE S256，仅允许受管资源和 scope；请求不能自授 trusted、skip-consent、数据库 claims 或平台能力。
- 校验回调 URI，适配 Codex 实际 public/native 回调；精确匹配和 loopback 规则遵循协议并测试。
- 注册输入限制、限速和客户端状态治理；刷新支持与已授 grant 一致。

## Acceptance

- [x] 无预注册 Codex 能完成注册；注册本身不发用户 token 或运营权限。
- [x] 恶意元数据、越界 audience、回调变更和管理配置注入被拒绝。
- [x] 现有管理注册及其它 tenant 行为不退化。
- [x] 返回的 registration client URI 支持注册令牌保护的元数据读取与客户端删除，删除同时清理注册令牌并写入审计。

## Verification

- `pnpm typecheck`
- `pnpm test`（29 files / 248 tests；含公共 MCP DCR、生命周期、恶意 metadata、loopback redirect 与管理注册回归）
- `pnpm db:check`

公共注册端点为 `/connect/mcp/register`（及 tenant 路径），只接受 `authorization_code` + PKCE、`token_endpoint_auth_method=none`、HTTPS/loopback 回调和受管 resource/scope；原 `/connect/register` 仍要求 management bearer。

## Boundaries

- 遵循本仓 AGENTS.md：pnpm、Workers、Hono、D1/Drizzle、Vitest。
- 此票创建不表示已修改实现或获准部署；线上 client、密钥和迁移变更在实施发布阶段明确执行。
