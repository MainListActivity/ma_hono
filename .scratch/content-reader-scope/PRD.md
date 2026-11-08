Status: ready-for-agent

# 调用者短期内容读取凭证

本簇承接用户于 2026-09-24 确认的法律内容访问实施拆分第 3 项，仅包含 IDP-LCR-01。对应应用仓库承担商业权益、成员资格、内容投影与数据库读取，IdP 承担可信身份和限定 scope 的短期签发。

应用总规格：[法律内容访问权、订阅生效与授权 AI 研究](/Users/y/IdeaProjects/surreal_ck/.scratch/legal-content-access/PRD.md)。

## 路线图

| ID | 任务 | Blocked by |
|---|---|---|
| IDP-LCR-01 | [签发独立短期内容读取凭证](issues/01-content-reader-token-exchange.md) | 无，可立即开始 |

## 已确认边界

- 一个真人可以同时持有工作区会话与内容读取会话；换发内容凭证不改变其最近选择的工作区，也不覆盖原工作区 token。
- 内容凭证包含可验证的调用者、目标内容 access、工作区与内容授权修订身份，不承载完整内容授权列表、数据库 root 或发布者权限。
- 内容资格由应用的 Workspace Scope Module 校验并请求签发；IdP 不复制套餐解析器，也不维护跨应用法律内容 ACL。
- 复用既有 OIDC/JWKS 与受保护换票能力，遵守本仓协议和 Cloudflare Workers 架构；不开放任意 JWT claim 签发。
- 兼容既有 admin/participant，content_reader 不具备提升为管理员或发布者的换票权利。
- 本票独立使用受信 client 和输入夹具即可验证签发与拒绝。应用凭证消费、数据库权限与浏览器联调由下游票验收，因此没有反向依赖。

## 下游

- [SCK-LCA-03 — 订阅成员打开一篇获授权的法律内容](/Users/y/IdeaProjects/surreal_ck/.scratch/legal-content-access/issues/03-authorized-content-reader.md)。
- 交付包括已固定的换票输入/输出、claim 与期限契约、错误语义、客户端配置和验证证据。

## 来源与状态

本簇为本地 Markdown tracker：一票一文件，Status: ready-for-agent 为可领取规格，完成后在本票记证据并标 done。产品设计父票及现有 MCP OAuth 簇保持原状。

