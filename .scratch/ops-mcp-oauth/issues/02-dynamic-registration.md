Status: blocked
Label: needs-triage
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

- [ ] 无预注册 Codex 能完成注册；注册本身不发用户 token 或运营权限。
- [ ] 恶意元数据、越界 audience、回调变更和管理配置注入被拒绝。
- [ ] 现有管理注册及其它 tenant 行为不退化。

## Boundaries

- 遵循本仓 AGENTS.md：pnpm、Workers、Hono、D1/Drizzle、Vitest。
- 此票创建不表示已修改实现或获准部署；线上 client、密钥和迁移变更在实施发布阶段明确执行。
