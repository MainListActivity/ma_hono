import { Hono } from "hono";
import { html } from "hono/html";
import { hashPasswordPbkdf2 } from "../lib/pbkdf2";

const isValidHostname = (value: string): boolean => {
  if (value.includes("://") || value.includes("/")) {
    return false;
  }
  return value.length > 0 && /^[a-zA-Z0-9._:-]+$/.test(value);
};

interface FormValues {
  platformHost: string;
  adminWhitelist: string;
  adminBootstrapPassword: string;
  adminBootstrapPasswordConfirm: string;
  managementApiToken: string;
}

interface FormErrors {
  platformHost?: string;
  adminWhitelist?: string;
  adminBootstrapPassword?: string;
  adminBootstrapPasswordConfirm?: string;
  managementApiToken?: string;
  general?: string;
}

const renderSetupPage = (values: Partial<FormValues> = {}, errors: FormErrors = {}) =>
  html`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Platform Setup</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: #f5f5f5; margin: 0; padding: 2rem; }
    .card { max-width: 480px; margin: 0 auto; background: #fff; border-radius: 8px; padding: 2rem; box-shadow: 0 1px 4px rgba(0,0,0,.12); }
    h1 { margin: 0 0 .5rem; font-size: 1.4rem; }
    p.subtitle { color: #666; margin: 0 0 1.5rem; font-size: .9rem; }
    label { display: block; font-size: .85rem; font-weight: 600; margin-bottom: .25rem; }
    input[type=text], input[type=password] { width: 100%; padding: .5rem .75rem; border: 1px solid #ccc; border-radius: 4px; font-size: .95rem; }
    input.error-field { border-color: #c00; }
    .field { margin-bottom: 1.25rem; }
    .error-msg { color: #c00; font-size: .8rem; margin-top: .25rem; }
    .hint { color: #888; font-size: .8rem; margin-top: .25rem; }
    button { width: 100%; padding: .65rem; background: #1a56db; color: #fff; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
    button:hover { background: #1448c8; }
    .banner { background: #fef2c0; border: 1px solid #d4a800; border-radius: 4px; padding: .75rem 1rem; margin-bottom: 1.5rem; font-size: .88rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Platform Setup</h1>
    <p class="subtitle">Complete this form to initialize the platform. This page will not appear again after setup is complete.</p>
    ${errors.general ? html`<div class="banner">${errors.general}</div>` : ""}
    <form method="POST" action="/setup">
      <div class="field">
        <label for="platform_host">Platform Host</label>
        <input type="text" id="platform_host" name="platform_host"
          value="${values.platformHost ?? ""}"
          class="${errors.platformHost ? "error-field" : ""}"
          placeholder="auth.example.com" />
        ${errors.platformHost ? html`<div class="error-msg">${errors.platformHost}</div>` : ""}
        <div class="hint">Hostname only — no https:// prefix, no trailing slash.</div>
      </div>
      <div class="field">
        <label for="admin_whitelist">Admin Email(s)</label>
        <input type="text" id="admin_whitelist" name="admin_whitelist"
          value="${values.adminWhitelist ?? ""}"
          class="${errors.adminWhitelist ? "error-field" : ""}"
          placeholder="admin@example.com" />
        ${errors.adminWhitelist ? html`<div class="error-msg">${errors.adminWhitelist}</div>` : ""}
        <div class="hint">Comma-separated. These emails will be allowed to log into the admin console.</div>
      </div>
      <div class="field">
        <label for="admin_bootstrap_password">Admin Password</label>
        <input type="password" id="admin_bootstrap_password" name="admin_bootstrap_password"
          class="${errors.adminBootstrapPassword ? "error-field" : ""}" />
        ${errors.adminBootstrapPassword ? html`<div class="error-msg">${errors.adminBootstrapPassword}</div>` : ""}
      </div>
      <div class="field">
        <label for="admin_bootstrap_password_confirm">Confirm Password</label>
        <input type="password" id="admin_bootstrap_password_confirm" name="admin_bootstrap_password_confirm"
          class="${errors.adminBootstrapPasswordConfirm ? "error-field" : ""}" />
        ${errors.adminBootstrapPasswordConfirm ? html`<div class="error-msg">${errors.adminBootstrapPasswordConfirm}</div>` : ""}
      </div>
      <div class="field">
        <label for="management_api_token">Management API Token</label>
        <input type="text" id="management_api_token" name="management_api_token"
          value="${values.managementApiToken ?? ""}"
          class="${errors.managementApiToken ? "error-field" : ""}"
          placeholder="tok_..." />
        ${errors.managementApiToken ? html`<div class="error-msg">${errors.managementApiToken}</div>` : ""}
        <div class="hint">Used to authenticate programmatic calls to the management API.</div>
      </div>
      <button type="submit">Initialize Platform</button>
    </form>
  </div>
</body>
</html>`;

export const createSetupApp = (db: D1Database) => {
  const app = new Hono();

  app.get("/", (c) => c.redirect("/setup"));

  app.get("/setup", (c) => {
    const host = c.req.header("host") ?? "";
    return c.html(renderSetupPage({ platformHost: host }) as string);
  });

  app.post("/setup", async (c) => {
    const body = await c.req.parseBody();
    const platformHost = String(body["platform_host"] ?? "").trim();
    const adminWhitelist = String(body["admin_whitelist"] ?? "").trim();
    const adminBootstrapPassword = String(body["admin_bootstrap_password"] ?? "");
    const adminBootstrapPasswordConfirm = String(body["admin_bootstrap_password_confirm"] ?? "");
    const managementApiToken = String(body["management_api_token"] ?? "").trim();

    const values: FormValues = {
      platformHost,
      adminWhitelist,
      adminBootstrapPassword: "",
      adminBootstrapPasswordConfirm: "",
      managementApiToken
    };

    const errors: FormErrors = {};

    if (!platformHost) {
      errors.platformHost = "Platform host is required.";
    } else if (!isValidHostname(platformHost)) {
      errors.platformHost = "Enter a hostname only (no https://, no path).";
    }

    if (!adminWhitelist) {
      errors.adminWhitelist = "At least one admin email is required.";
    }

    if (!adminBootstrapPassword) {
      errors.adminBootstrapPassword = "Password is required.";
    }

    if (adminBootstrapPassword !== adminBootstrapPasswordConfirm) {
      errors.adminBootstrapPasswordConfirm = "Passwords do not match.";
    }

    if (!managementApiToken) {
      errors.managementApiToken = "Management API token is required.";
    }

    if (Object.keys(errors).length > 0) {
      return c.html(renderSetupPage(values, errors) as string, 400);
    }

    const passwordHash = await hashPasswordPbkdf2(adminBootstrapPassword);
    const now = new Date().toISOString();

    await db.batch([
      db.prepare("INSERT OR REPLACE INTO platform_config (key, value, updated_at) VALUES (?, ?, ?)")
        .bind("admin_bootstrap_password_hash", passwordHash, now),
      db.prepare("INSERT OR REPLACE INTO platform_config (key, value, updated_at) VALUES (?, ?, ?)")
        .bind("admin_whitelist", adminWhitelist, now),
      db.prepare("INSERT OR REPLACE INTO platform_config (key, value, updated_at) VALUES (?, ?, ?)")
        .bind("management_api_token", managementApiToken, now),
      db.prepare("INSERT OR REPLACE INTO platform_config (key, value, updated_at) VALUES (?, ?, ?)")
        .bind("platform_host", platformHost, now)
    ]);

    return c.redirect("/admin");
  });

  return app;
};
