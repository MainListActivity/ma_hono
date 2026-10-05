import { html } from "hono/html";

/**
 * `/activate-account` 的浏览器落地页：一次性邀请链接（?token=…）打开后，
 * 用户在此自设密码完成激活。纯表单 POST（无 JS），与 POST /activate-account
 * 的 form-encoded 分支配套；该分支对浏览器请求回 HTML、对 JSON 请求维持原 API 契约。
 */

export const ACTIVATION_PAGE_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff"
};

const shell = (title: string, body: ReturnType<typeof html>) =>
  html`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, "PingFang SC", sans-serif; background: #f5f5f5; margin: 0; padding: 2rem; }
    .card { max-width: 440px; margin: 0 auto; background: #fff; border-radius: 8px; padding: 2rem; box-shadow: 0 1px 4px rgba(0,0,0,.12); }
    h1 { margin: 0 0 .5rem; font-size: 1.4rem; }
    p.subtitle { color: #666; margin: 0 0 1.5rem; font-size: .9rem; line-height: 1.5; }
    label { display: block; font-size: .85rem; font-weight: 600; margin-bottom: .25rem; }
    input[type=text], input[type=password] { width: 100%; padding: .5rem .75rem; border: 1px solid #ccc; border-radius: 4px; font-size: .95rem; }
    .field { margin-bottom: 1.25rem; }
    .hint { color: #888; font-size: .8rem; margin-top: .25rem; }
    button { width: 100%; padding: .65rem; background: #1a56db; color: #fff; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
    button:hover { background: #1448c8; }
    .banner { background: #fef2c0; border: 1px solid #d4a800; border-radius: 4px; padding: .75rem 1rem; margin-bottom: 1.5rem; font-size: .88rem; }
    .banner.error { background: #fde8e8; border-color: #c00; color: #7f1d1d; }
    .done { text-align: center; }
    .done .mark { font-size: 2.4rem; color: #1a7f37; margin-bottom: .75rem; }
  </style>
</head>
<body>
  <div class="card">
    ${body}
  </div>
</body>
</html>`;

export const renderActivationForm = (input: { token: string; error?: string }) =>
  shell(
    "激活账号",
    html`
    <h1>激活账号</h1>
    <p class="subtitle">请设置你的登录密码。链接仅可使用一次，有效期 24 小时。</p>
    ${input.error ? html`<div class="banner error">${input.error}</div>` : ""}
    <form method="POST" action="/activate-account">
      ${input.token.length > 0
        ? html`<input type="hidden" name="invitation_token" value="${input.token}" />`
        : html`<div class="field">
            <label for="invitation_token">激活码</label>
            <input type="text" id="invitation_token" name="invitation_token" required
              autocomplete="off" placeholder="请粘贴邀请方提供的一次性激活码" />
          </div>`}
      <div class="field">
        <label for="password">登录密码</label>
        <input type="password" id="password" name="password" required minlength="8"
          autocomplete="new-password" placeholder="至少 8 位" />
      </div>
      <div class="field">
        <label for="password_confirm">确认密码</label>
        <input type="password" id="password_confirm" name="password_confirm" required minlength="8"
          autocomplete="new-password" />
      </div>
      <button type="submit">激活账号</button>
      <div class="hint">激活后请返回应用，用你的邮箱和刚设置的密码登录。</div>
    </form>`
  );

export const renderActivationDone = () =>
  shell(
    "激活完成",
    html`
    <div class="done">
      <div class="mark">✓</div>
      <h1>账号已激活</h1>
      <p class="subtitle">请回到应用页面，用你的邮箱和刚设置的密码登录。此链接已失效，可关闭本页。</p>
    </div>`
  );
