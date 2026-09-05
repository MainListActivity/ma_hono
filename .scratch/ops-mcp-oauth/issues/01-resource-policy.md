Status: open
Label: ready-for-agent
Assignee: unassigned
ID: IDP-OM-01
Repository: ma_hono

# 实现 MCP 资源与 scope 策略

Parent: [跨仓 OAuth 规格](../PRD.md)

## Dependencies

- 无前置实施票；与 surreal_ck SCK-LCM-01 并行，资源策略先作为受管配置实现。

## Scope

- 在现有授权码、token 与 refresh 流程加入 resource 解析及持久化绑定；MCP resource/audience 从服务端受管注册表解析，不接受任意目标。
- 按 tenant/client 约束 scope，issuer/public sub 沿用现有账号模型；ops/MCP 不配置 workspace db/ac/RL hook，客户客户端保持原流程。
- 保持 Cloudflare Workers/Hono/D1/Drizzle 架构，不引入 Node 服务或自定义 token grant。

## Acceptance

- [ ] 授权、换token、refresh 的 resource/aud/scope 一致，越界请求拒绝。
- [ ] 相同租户用户跨客户端 sub 一致，不同租户隔离；客户原登录回归通过。

## Boundaries

- 遵循本仓 AGENTS.md：pnpm、Workers、Hono、D1/Drizzle、Vitest。
- 此票创建不表示已修改实现或获准部署；线上 client、密钥和迁移变更在实施发布阶段明确执行。

