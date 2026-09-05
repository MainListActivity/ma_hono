Status: open
Label: ready-for-agent

# 运营 MCP OAuth / 动态注册实施规格

## 目标

为 surreal_ck 的运营数据 MCP 提供同账号体系的 OAuth + DCR，让未预注册 Codex 客户端从 MCP 地址完成自动发现、客户端注册和真人授权。沿用 ma_hono 的 Workers/Hono/D1/Drizzle 技术栈。

## 来源与边界

- [总集成规格](/Users/y/IdeaProjects/surreal_ck/.scratch/legal-content-mcp/PRD.md)
- [只读核查](/Users/y/IdeaProjects/surreal_ck/.scratch/legal-data-product-wayfinder/research/idp-mcp-oauth-readiness.md)
- [已确认 MCP 流程](/Users/y/IdeaProjects/surreal_ck/.scratch/legal-data-product-wayfinder/issues/12-legal-content-ingestion.md)
- 同 tenant 下复用 public sub，运营能力由 surreal_ck 检查；IdP 不复制 workspace 成员或平台业务授权表。
- 不开放原管理注册接口，不下发 managementApiToken，不把动态客户端默认当 trusted/skip consent。
- 平台运营与客户 workspace claim hook 分开配置；不通过数据库管理员 token 解决无 workspace 登录。
- OAuth resource/scope、PKCE、回调、refresh 与 tenant/client 绑定必须全链路一致。

## 任务

| ID | 任务 | 依赖 |
|---|---|---|
| IDP-OM-01 | [资源与 scope 策略](issues/01-resource-policy.md) | 无，可现在开始 |
| IDP-OM-02 | [受限动态注册](issues/02-dynamic-registration.md) | 01 |
| IDP-OM-03 | [第三方 consent、刷新与撤销](issues/03-consent-refresh.md) | 01、02 |

与 SCK-LCM-07 联调，SCK-LCM-10 为最终真实 Codex 验收。若目标客户端行为与协议配置存在差异，记录版本与可复现请求后处理，不能改用人工复制 token 宣称成功。

## 交付

本目录只有实施计划。没有修改 IdP 代码、数据库、client 配置或线上设置。schema 迁移、配置及部署按本仓工程流程在实施阶段执行。
