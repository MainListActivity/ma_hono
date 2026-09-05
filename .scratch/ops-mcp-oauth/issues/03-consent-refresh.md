Status: blocked
Label: needs-triage
Assignee: unassigned
ID: IDP-OM-03
Repository: ma_hono

# 完善第三方授权、刷新与撤销

Parent: [跨仓 OAuth 规格](../PRD.md)

## Dependencies

- [01-resource-policy](01-resource-policy.md)
- [02-dynamic-registration](02-dynamic-registration.md)

## Scope

- 第三方 client 展示应用身份、目标资源及请求权限，记录真人 consent；禁止沿用 first_party_trusted/skip 默认。
- 支持授权取消、refresh 生命周期及撤销，绑定 client/tenant/user/resource/scope，刷新不扩大权限。
- 输出发现元数据和 MCP 联调配置示例，不提交 secret；与 surreal_ck 运营资格检查明确分工。

## Acceptance

- [ ] 拒绝 consent 不签发可用授权；重放授权码、PKCE失败、跨client refresh 被拒绝。
- [ ] refresh/重新登录正常，撤销后不能继续刷新；MCP 服务的运营撤权测试由 SCK-LCM-10 覆盖。
- [ ] 从未预注册 Codex 实测全链路并记录版本，人工 token 不算验收。

## Boundaries

- 遵循本仓 AGENTS.md：pnpm、Workers、Hono、D1/Drizzle、Vitest。
- 此票创建不表示已修改实现或获准部署；线上 client、密钥和迁移变更在实施发布阶段明确执行。

