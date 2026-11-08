# 01 — IdP 签发独立的短期内容读取凭证

**What to build:** 已登录真人在应用确认其工作区内容资格后，获得仅用于平台内容读取的短期凭证；原工作区登录继续可用，普通客户不能自行扩大读取范围或换得管理员身份。

**Blocked by:** None — can start immediately（无阻塞，可立即开始）。

**Status:** done

**ID:** IDP-LCR-01
**确认时序号:** 3
**Repository:** ma_hono
**Parent:** [本簇实施规格](../PRD.md)

## Acceptance criteria

- [x] 复用既有 OIDC 身份、签名、JWKS 和受保护换票机制，固定版本化输入/输出契约：调用者 subject token、目标内容 access、应用核验的工作区及授权修订身份、受约束的 lease 截止时间；下游获得明确字段、类型、错误与示例夹具。
- [x] 新签发分支只对获准的租户和 confidential client 开放；验证调用者 token 的 issuer、客户端/受众关联、有效期和用户状态。workspace 商业资格由可信应用入口验证，普通浏览器传入的授权事实不能直接被 IdP 采信。
- [x] content_reader 仅能绑定配置允许的内容数据库与读取用途；claim 白名单拒绝任意数据库、access、subject、授权列表或发布者权限注入，不扩展为任意 JWT 签发器。
- [x] 短期 TTL 同时受原 subject token 剩余期限、应用已核验的授权 lease 截止及服务端最大时长约束；过期/负值/超界请求有确定拒绝行为，不接受客户任意覆盖 exp。
- [x] 换发内容凭证不修改最近工作区、持久默认 scope 或原 token；同一真人能够保留两类独立会话。content_reader token 不能被用作提升为 admin、participant 或发布者的凭据。
- [x] 现有 admin/participant 与配置 claim 的行为保留兼容；明确钩子、固定角色配置与内容 claim 的合并顺序。不能以删除 RL 代替 RECORD 权限证明，也不能让配置覆盖内容读取的用途边界。
- [x] 错误区分无效 client、无效身份、scope 不被允许、期限无效及签发不可用；成功响应不可缓存，审计只保存必要身份、作用域与结果，不记录 token、secret 或完整授权事实。
- [x] 在本仓实际运行时与测试框架下验证有效签发、并存会话、跨租户/跨 client、错误受众、禁用用户、伪造或过期 subject token、超期 lease、任意 claim 注入和旧接口回归。
- [x] 使用真实验证器按 JWKS 验签并确认 sub、目标 scope、workspace/revision 身份和 exp；不得以未签名载荷或手工长效 token 代替验收。
- [x] 向应用仓库交付 client 允许列表配置、固定契约、负例夹具和部署顺序；凭证正确签发不等于客户已获数据库权限，真实读取由下游独立验证。

## 范围与交接

遵守本仓 TypeScript、Hono、Cloudflare Workers、D1/Drizzle、jose 和 pnpm 约束。此票不引入内容存储或产品套餐解析，不依赖客户应用先完成读取页面，不修改已有 MCP DCR/consent 父票。

下游：[SCK-LCA-03 — 订阅成员打开一篇获授权的法律内容](/Users/y/IdeaProjects/surreal_ck/.scratch/legal-content-access/issues/03-authorized-content-reader.md)。

完成时在 Comments 记录契约、实现与验证证据，将本票标为 done，并说明应用可以开始联调的条件。

## Comments

- 2026-09-24：用户确认 15 张拆分后发布。本票对应跨仓第 3 项；当前为规格，尚未实现或验收。
- 2026-09-24（实现）：在既有 `POST /scope` + `issueScopeToken` 上增加 `content_reader` 分支，未另起协议。
  - **实现范围：** `content-reader-policy.ts`（allowlist/TTL/merge）；`token-service.ts` 模式分支与 elevation 拒绝；`app.ts` 审计事件 `oidc.scope.content_reader.*`；`platform_config` 可选加载；handoff [`../handoff-surreal-ck.md`](../handoff-surreal-ck.md)。
  - **契约 `content_reader.v1`：** request claims = `{ ac:"content_reader", db, workspace_id, entitlement_revision, lease_end }`；response 同 workspace scope；JWT 含上述身份 + 短 TTL；错误区分 `invalid_client` / `invalid_grant` / `invalid_scope` / `invalid_lifetime` / `invalid_request` / `temporarily_unavailable`。
  - **合并顺序：** workspace = configured(fixed→user_field→hook) 后 request overlay；content_reader = configured 后剥离 purpose 键，再强制 overlay content claims。
  - **验证：** `pnpm test`（273 passed）、`pnpm typecheck` 通过；核心夹具 `tests/oidc/content-reader-scope.test.ts` + 旧接口 `tests/oidc/scope-endpoint.test.ts`。
  - **限制：** IdP 不解析套餐/不写内容库；未配置 `content_reader_allowed_client_ids` 时 content_reader 一律 `invalid_scope`。
  - **应用可联调条件：** 部署本仓变更 → 写入 platform_config allowlist → surreal_ck 服务端按 handoff 调用 `/scope` → SCK-LCA-03 独立验收 DB RECORD 读取。
