# Setup Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hard-fail Worker secret validation with a D1-backed setup wizard that intercepts all requests when the platform is uninitialized and guides the operator through first-time configuration.

**Architecture:** A new `platform_config` D1 table stores four platform config values. The Worker entry point reads this table on every request; if any key is missing it routes to a standalone minimal Hono setup app instead of the main app. Password is stored as a PBKDF2 hash using `crypto.subtle`.

**Tech Stack:** TypeScript, Hono, Drizzle ORM, Cloudflare D1, `crypto.subtle` (Workers-native), Vitest

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `drizzle/migrations/0002_setup_wizard.sql` | Add `platform_config` table |
| Modify | `src/adapters/db/drizzle/schema.ts` | Add `platformConfig` Drizzle table def |
| Create | `src/lib/pbkdf2.ts` | `hashPasswordPbkdf2` / `verifyPasswordPbkdf2` |
| Create | `src/lib/pbkdf2.test.ts` | Unit tests for PBKDF2 functions |
| Create | `src/config/platform-config.ts` | `loadPlatformConfig` — reads D1, returns `PlatformConfig \| null` |
| Create | `src/config/platform-config.test.ts` | Unit tests for `loadPlatformConfig` |
| Create | `src/app/setup-app.ts` | Standalone setup wizard Hono app |
| Create | `src/app/setup-app.test.ts` | Integration tests for setup wizard routes |
| Modify | `src/config/env.ts` | Remove 4 string fields from schema and interface |
| Modify | `src/domain/admin-auth/service.ts` | Replace plaintext compare with PBKDF2 verify |
| Modify | `src/app/app.ts` | Make 4 config fields required in `AppOptions` |
| Modify | `src/index.ts` | Add platform config detection, route to setup or main app |

---

## Task 1: Database migration — `platform_config` table

**Files:**
- Create: `drizzle/migrations/0002_setup_wizard.sql`
- Modify: `src/adapters/db/drizzle/schema.ts`

- [ ] **Step 1: Create migration file**

Create `drizzle/migrations/0002_setup_wizard.sql`:

```sql
CREATE TABLE platform_config (
  key        TEXT PRIMARY KEY NOT NULL,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

- [ ] **Step 2: Add Drizzle table definition to schema**

In `src/adapters/db/drizzle/schema.ts`, append after the last table export:

```typescript
export const platformConfig = sqliteTable("platform_config", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: text("updated_at").notNull()
});
```

- [ ] **Step 3: Apply migration locally to verify SQL is valid**

```bash
pnpm db:migrate:local
```

Expected: Migration applies without error.

- [ ] **Step 4: Commit**

```bash
git add drizzle/migrations/0002_setup_wizard.sql src/adapters/db/drizzle/schema.ts
git commit -m "feat: add platform_config D1 table"
```

---

## Task 2: PBKDF2 hash/verify utilities

**Files:**
- Create: `src/lib/pbkdf2.ts`
- Create: `src/lib/pbkdf2.test.ts`

The hash format is `<iterations>:<salt_base64url>:<derived_key_base64url>` — all three parts encoded in a single colon-delimited string. This is self-contained and needs no external library.

- [ ] **Step 1: Write the failing tests**

Create `src/lib/pbkdf2.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { hashPasswordPbkdf2, verifyPasswordPbkdf2 } from "./pbkdf2";

describe("hashPasswordPbkdf2", () => {
  it("returns a string with format iterations:salt:hash", async () => {
    const hash = await hashPasswordPbkdf2("secret");
    const parts = hash.split(":");
    expect(parts).toHaveLength(3);
    expect(parts[0]).toBe("100000");
    expect(parts[1].length).toBeGreaterThan(0);
    expect(parts[2].length).toBeGreaterThan(0);
  });

  it("produces different hashes for the same password (random salt)", async () => {
    const hash1 = await hashPasswordPbkdf2("secret");
    const hash2 = await hashPasswordPbkdf2("secret");
    expect(hash1).not.toBe(hash2);
  });
});

describe("verifyPasswordPbkdf2", () => {
  it("returns true for correct password", async () => {
    const hash = await hashPasswordPbkdf2("correct-horse-battery-staple");
    expect(await verifyPasswordPbkdf2("correct-horse-battery-staple", hash)).toBe(true);
  });

  it("returns false for wrong password", async () => {
    const hash = await hashPasswordPbkdf2("correct-horse-battery-staple");
    expect(await verifyPasswordPbkdf2("wrong-password", hash)).toBe(false);
  });

  it("returns false for malformed hash string", async () => {
    expect(await verifyPasswordPbkdf2("password", "notahash")).toBe(false);
    expect(await verifyPasswordPbkdf2("password", "a:b")).toBe(false);
    expect(await verifyPasswordPbkdf2("password", "")).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pnpm test src/lib/pbkdf2.test.ts
```

Expected: FAIL — `pbkdf2` module not found.

- [ ] **Step 3: Implement `src/lib/pbkdf2.ts`**

```typescript
import { encodeBase64Url } from "./base64url";

const ITERATIONS = 100_000;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;

const textEncoder = new TextEncoder();

const importKey = (password: string) =>
  crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

const deriveBits = (key: CryptoKey, salt: Uint8Array) =>
  crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: ITERATIONS
    },
    key,
    KEY_LENGTH * 8
  );

export const hashPasswordPbkdf2 = async (password: string): Promise<string> => {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await importKey(password);
  const derived = await deriveBits(key, salt);

  return `${ITERATIONS}:${encodeBase64Url(salt)}:${encodeBase64Url(derived)}`;
};

const decodeBase64Url = (str: string): Uint8Array => {
  const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
};

export const verifyPasswordPbkdf2 = async (
  password: string,
  hash: string
): Promise<boolean> => {
  try {
    const parts = hash.split(":");

    if (parts.length !== 3) {
      return false;
    }

    const [iterationsStr, saltB64, expectedB64] = parts;
    const iterations = parseInt(iterationsStr, 10);

    if (!Number.isInteger(iterations) || iterations <= 0) {
      return false;
    }

    const salt = decodeBase64Url(saltB64);
    const expected = decodeBase64Url(expectedB64);
    const key = await crypto.subtle.importKey(
      "raw",
      textEncoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const derived = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations
      },
      key,
      expected.byteLength * 8
    );
    const derivedBytes = new Uint8Array(derived);

    if (derivedBytes.length !== expected.length) {
      return false;
    }

    // Constant-time comparison
    let diff = 0;

    for (let i = 0; i < derivedBytes.length; i++) {
      diff |= derivedBytes[i] ^ expected[i];
    }

    return diff === 0;
  } catch {
    return false;
  }
};
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pnpm test src/lib/pbkdf2.test.ts
```

Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/pbkdf2.ts src/lib/pbkdf2.test.ts
git commit -m "feat: add PBKDF2 password hash/verify utilities"
```

---

## Task 3: `loadPlatformConfig` module

**Files:**
- Create: `src/config/platform-config.ts`
- Create: `src/config/platform-config.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `src/config/platform-config.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { loadPlatformConfig } from "./platform-config";

const makeDb = (rows: Array<{ key: string; value: string }>) => ({
  prepare: (sql: string) => ({
    bind: (..._args: unknown[]) => ({
      all: async () => ({ results: rows })
    }),
    all: async () => ({ results: rows })
  }),
  batch: async (stmts: unknown[]) => stmts.map(() => ({ results: [] }))
}) as unknown as D1Database;

describe("loadPlatformConfig", () => {
  it("returns null when no rows exist", async () => {
    const db = makeDb([]);
    expect(await loadPlatformConfig(db)).toBeNull();
  });

  it("returns null when only some keys exist", async () => {
    const db = makeDb([
      { key: "platform_host", value: "auth.example.com" },
      { key: "admin_whitelist", value: "admin@example.com" }
    ]);
    expect(await loadPlatformConfig(db)).toBeNull();
  });

  it("returns config when all four keys exist", async () => {
    const db = makeDb([
      { key: "admin_bootstrap_password_hash", value: "100000:salt:hash" },
      { key: "admin_whitelist", value: "admin@example.com,ops@example.com" },
      { key: "management_api_token", value: "tok_abc123" },
      { key: "platform_host", value: "auth.example.com" }
    ]);
    const config = await loadPlatformConfig(db);
    expect(config).not.toBeNull();
    expect(config!.platformHost).toBe("auth.example.com");
    expect(config!.managementApiToken).toBe("tok_abc123");
    expect(config!.adminBootstrapPasswordHash).toBe("100000:salt:hash");
    expect(config!.adminWhitelist).toEqual(["admin@example.com", "ops@example.com"]);
  });

  it("trims and filters empty entries in admin_whitelist", async () => {
    const db = makeDb([
      { key: "admin_bootstrap_password_hash", value: "100000:salt:hash" },
      { key: "admin_whitelist", value: " admin@example.com , , ops@example.com " },
      { key: "management_api_token", value: "tok" },
      { key: "platform_host", value: "host.example.com" }
    ]);
    const config = await loadPlatformConfig(db);
    expect(config!.adminWhitelist).toEqual(["admin@example.com", "ops@example.com"]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pnpm test src/config/platform-config.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/config/platform-config.ts`**

```typescript
const REQUIRED_KEYS = [
  "admin_bootstrap_password_hash",
  "admin_whitelist",
  "management_api_token",
  "platform_host"
] as const;

export interface PlatformConfig {
  adminBootstrapPasswordHash: string;
  adminWhitelist: string[];
  managementApiToken: string;
  platformHost: string;
}

export const loadPlatformConfig = async (
  db: D1Database
): Promise<PlatformConfig | null> => {
  const { results } = await db
    .prepare(
      `SELECT key, value FROM platform_config WHERE key IN (?, ?, ?, ?)`
    )
    .bind(...REQUIRED_KEYS)
    .all<{ key: string; value: string }>();

  const map = new Map(results.map((r) => [r.key, r.value]));

  for (const key of REQUIRED_KEYS) {
    if (!map.has(key)) {
      return null;
    }
  }

  return {
    adminBootstrapPasswordHash: map.get("admin_bootstrap_password_hash")!,
    adminWhitelist: map
      .get("admin_whitelist")!
      .split(",")
      .map((v) => v.trim())
      .filter((v) => v.length > 0),
    managementApiToken: map.get("management_api_token")!,
    platformHost: map.get("platform_host")!
  };
};
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pnpm test src/config/platform-config.test.ts
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/config/platform-config.ts src/config/platform-config.test.ts
git commit -m "feat: add loadPlatformConfig from D1"
```

---

## Task 4: Setup wizard Hono app

**Files:**
- Create: `src/app/setup-app.ts`
- Create: `src/app/setup-app.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `src/app/setup-app.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { createSetupApp } from "./setup-app";

const makeMockDb = () => {
  const written: Array<{ key: string; value: string }> = [];
  const db = {
    prepare: (_sql: string) => ({
      bind: (...args: unknown[]) => ({
        all: async () => ({ results: [] }),
        run: async () => ({ success: true })
      }),
      run: async () => ({ success: true })
    }),
    batch: async (stmts: unknown[]) => {
      return stmts.map(() => ({ success: true, results: [] }));
    },
    _written: written
  } as unknown as D1Database & { _written: typeof written };
  return db;
};

describe("GET /", () => {
  it("redirects to /setup", async () => {
    const app = createSetupApp(makeMockDb());
    const res = await app.fetch(new Request("http://localhost/"));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/setup");
  });
});

describe("GET /setup", () => {
  it("renders form with 200", async () => {
    const app = createSetupApp(makeMockDb());
    const res = await app.fetch(new Request("http://localhost/setup", {
      headers: { host: "auth.example.com" }
    }));
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("auth.example.com");
    expect(body).toContain("platform_host");
    expect(body).toContain("admin_whitelist");
    expect(body).toContain("admin_bootstrap_password");
    expect(body).toContain("management_api_token");
  });
});

describe("POST /setup", () => {
  const validBody = new URLSearchParams({
    platform_host: "auth.example.com",
    admin_whitelist: "admin@example.com",
    admin_bootstrap_password: "s3cur3P@ssw0rd!",
    admin_bootstrap_password_confirm: "s3cur3P@ssw0rd!",
    management_api_token: "tok_abc"
  });

  it("redirects to /admin on valid submission", async () => {
    const app = createSetupApp(makeMockDb());
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: validBody.toString()
    }));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/admin");
  });

  it("returns 400 when passwords do not match", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("admin_bootstrap_password_confirm", "different");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("do not match");
  });

  it("returns 400 when a required field is empty", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("admin_whitelist", "");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
  });

  it("returns 400 when platform_host contains scheme", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("platform_host", "https://auth.example.com");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pnpm test src/app/setup-app.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/app/setup-app.ts`**

```typescript
import { Hono } from "hono";
import { html } from "hono/html";
import { hashPasswordPbkdf2 } from "../lib/pbkdf2";

const isValidHostname = (value: string): boolean => {
  if (value.includes("://") || value.includes("/")) {
    return false;
  }
  // Basic hostname check: at least one dot or localhost
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pnpm test src/app/setup-app.test.ts
```

Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/app/setup-app.ts src/app/setup-app.test.ts
git commit -m "feat: add setup wizard Hono app"
```

---

## Task 5: Remove env string fields from `env.ts`

**Files:**
- Modify: `src/config/env.ts`

- [ ] **Step 1: Edit `src/config/env.ts`**

Remove `ADMIN_BOOTSTRAP_PASSWORD`, `ADMIN_WHITELIST`, `MANAGEMENT_API_TOKEN`, `PLATFORM_HOST` from `runtimeConfigSchema`, the `RuntimeConfig` interface, and the `readRuntimeConfig` return object.

The file should become:

```typescript
import { z } from "zod";

const d1BindingSchema = z.custom<D1Database>(
  (value): value is D1Database => typeof value === "object" && value !== null,
  "D1 binding is required"
);

const kvBindingSchema = z.custom<KVNamespace>(
  (value): value is KVNamespace => typeof value === "object" && value !== null,
  "KV binding is required"
);

const r2BindingSchema = z.custom<R2Bucket>(
  (value): value is R2Bucket => typeof value === "object" && value !== null,
  "R2 binding is required"
);

const runtimeConfigSchema = z.object({
  ADMIN_SESSIONS_KV: kvBindingSchema,
  DB: d1BindingSchema,
  KEY_MATERIAL_R2: r2BindingSchema,
  REGISTRATION_TOKENS_KV: kvBindingSchema,
  USER_SESSIONS_KV: kvBindingSchema
});

export interface RuntimeConfig {
  adminSessionsKv: KVNamespace;
  db: D1Database;
  keyMaterialBucket: R2Bucket;
  registrationTokensKv: KVNamespace;
  userSessionsKv: KVNamespace;
}

export const readRuntimeConfig = (
  env: Record<string, unknown>
): RuntimeConfig => {
  const parsed = runtimeConfigSchema.parse(env);

  return {
    adminSessionsKv: parsed.ADMIN_SESSIONS_KV,
    db: parsed.DB,
    keyMaterialBucket: parsed.KEY_MATERIAL_R2,
    registrationTokensKv: parsed.REGISTRATION_TOKENS_KV,
    userSessionsKv: parsed.USER_SESSIONS_KV
  };
};
```

- [ ] **Step 2: Run typecheck to catch all callsites that passed these fields**

```bash
pnpm typecheck
```

Expected: TypeScript errors at any site that still references `adminBootstrapPassword`, `adminWhitelist`, `managementApiToken`, or `platformHost` on `RuntimeConfig`.

Note the errors — you will fix them in Task 6 (index.ts) and Task 7 (app.ts).

- [ ] **Step 3: Commit the env.ts change alone**

```bash
git add src/config/env.ts
git commit -m "refactor: remove platform config fields from env.ts"
```

---

## Task 6: Update `domain/admin-auth/service.ts` — PBKDF2 password verification

**Files:**
- Modify: `src/domain/admin-auth/service.ts`

- [ ] **Step 1: Replace plaintext compare with PBKDF2 verify**

Change the `loginAdmin` function signature and implementation:

```typescript
import { verifyPasswordPbkdf2 } from "../../lib/pbkdf2";

export const loginAdmin = async ({
  adminBootstrapPasswordHash,   // renamed from adminBootstrapPassword
  adminWhitelist,
  adminRepository,
  email,
  password
}: {
  adminBootstrapPasswordHash: string;   // renamed
  adminWhitelist: string[];
  adminRepository: AdminRepository;
  email: string;
  password: string;
}): Promise<
  | { ok: true; sessionToken: string; user: AdminUser }
  | { ok: false; reason: "forbidden" | "unauthorized" }
> => {
  if (!adminWhitelist.includes(email)) {
    return { ok: false, reason: "forbidden" };
  }

  const isValid = await verifyPasswordPbkdf2(password, adminBootstrapPasswordHash);

  if (!isValid) {
    return { ok: false, reason: "unauthorized" };
  }

  // ... rest of function unchanged
```

- [ ] **Step 2: Run typecheck**

```bash
pnpm typecheck
```

Expected: Errors at the `loginAdmin` call site in `app.ts` (passes `adminBootstrapPassword`). Fix that in Task 7.

- [ ] **Step 3: Commit**

```bash
git add src/domain/admin-auth/service.ts
git commit -m "refactor: use PBKDF2 verify in loginAdmin"
```

---

## Task 7: Update `app.ts` — make config fields required, fix loginAdmin callsite

**Files:**
- Modify: `src/app/app.ts`

- [ ] **Step 1: Make 4 fields required in `AppOptions`**

In the `AppOptions` interface, change from optional to required:

```typescript
export interface AppOptions {
  adminBootstrapPasswordHash: string;    // was adminBootstrapPassword?: string
  adminWhitelist: string[];              // was adminWhitelist?: string[]
  // ... all other fields unchanged ...
  managementApiToken: string;            // was managementApiToken?: string
  platformHost: string;                  // was platformHost?: string
  // ... rest unchanged
}
```

- [ ] **Step 2: Update `createApp` to use new field names**

Remove the `?? ""` fallback defaults for these four fields. Change:

```typescript
// OLD:
const adminBootstrapPassword = options.adminBootstrapPassword ?? "";
const adminWhitelist = options.adminWhitelist ?? [];
const managementApiToken = options.managementApiToken ?? "";
const platformHost = options.platformHost ?? "localhost";

// NEW:
const adminBootstrapPasswordHash = options.adminBootstrapPasswordHash;
const adminWhitelist = options.adminWhitelist;
const managementApiToken = options.managementApiToken;
const platformHost = options.platformHost;
```

- [ ] **Step 3: Fix `loginAdmin` callsite in `app.ts`**

Find the call to `loginAdmin` in `app.ts` and update `adminBootstrapPassword` → `adminBootstrapPasswordHash`:

```typescript
// OLD:
loginAdmin({ adminBootstrapPassword, ... })

// NEW:
loginAdmin({ adminBootstrapPasswordHash, ... })
```

- [ ] **Step 4: Run typecheck to verify no errors remain**

```bash
pnpm typecheck
```

Expected: No errors.

- [ ] **Step 5: Run all tests**

```bash
pnpm test
```

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/app/app.ts
git commit -m "refactor: make platform config fields required in AppOptions"
```

---

## Task 8: Update `src/index.ts` — entry point detection

**Files:**
- Modify: `src/index.ts`

- [ ] **Step 1: Update `src/index.ts`**

Read the current file carefully before editing. Add the platform config detection between `readRuntimeConfig` and `createApp`. The new flow:

```typescript
import { createApp } from "./app/app";
import { createSetupApp } from "./app/setup-app";
import { createRuntimeRepositories } from "./adapters/db/drizzle/runtime";
import { readRuntimeConfig } from "./config/env";
import { loadPlatformConfig } from "./config/platform-config";
// ... other existing imports unchanged ...

export default {
  async fetch(request: Request, env: RuntimeEnv, executionContext: ExecutionContext) {
    const runtimeConfig = readRuntimeConfig(env);

    const platformConfig = await loadPlatformConfig(runtimeConfig.db);

    if (platformConfig === null) {
      const setupApp = createSetupApp(runtimeConfig.db);
      return setupApp.fetch(request);
    }

    const repositories = await createRuntimeRepositories(runtimeConfig);
    const browserSessionRepository = createKvBrowserSessionRepository(runtimeConfig.userSessionsKv);
    const app = createApp({
      adminBootstrapPasswordHash: platformConfig.adminBootstrapPasswordHash,
      adminWhitelist: platformConfig.adminWhitelist,
      adminRepository: repositories.adminRepository,
      auditRepository: repositories.auditRepository,
      authorizationCodeRepository: repositories.authorizationCodeRepository,
      authorizeSessionResolver: async (context) => {
        // ... existing resolver logic unchanged ...
      },
      clientRepository: repositories.clientRepository,
      keyRepository: repositories.keyRepository,
      loginChallengeLookupRepository: repositories.authenticationLoginChallengeRepository,
      loginChallengeRepository: repositories.loginChallengeRepository,
      managementApiToken: platformConfig.managementApiToken,
      platformHost: platformConfig.platformHost,
      browserSessionRepository,
      registrationAccessTokenRepository: repositories.registrationAccessTokenRepository,
      signer: repositories.signer,
      tenantRepository: repositories.tenantRepository,
      userRepository: repositories.userRepository
    });

    try {
      return await app.fetch(request, env, executionContext);
    } finally {
      await repositories.close();
    }
  }
};
```

Note: Keep all existing helper functions (`createKvBrowserSessionRepository`, `getCookieValue`) unchanged. Only the `fetch` handler body changes.

- [ ] **Step 2: Run typecheck**

```bash
pnpm typecheck
```

Expected: No errors.

- [ ] **Step 3: Run all tests**

```bash
pnpm test
```

Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add src/index.ts
git commit -m "feat: route to setup wizard when platform config is absent"
```

---

## Task 9: Update deployment script and verify end-to-end

**Files:**
- Modify: `scripts/setup-cf-resources.sh`

- [ ] **Step 1: Add migration apply step to setup script**

In `scripts/setup-cf-resources.sh`, add a migration apply step before `npx wrangler deploy`:

```bash
# --- Apply D1 migrations ---
echo "[D1] Applying migrations ..."
npx wrangler d1 migrations apply "$D1_NAME" --remote
echo "[D1] Migrations applied"
```

Place this after the D1 database ID is written to `wrangler.jsonc` and before `npx wrangler deploy`.

- [ ] **Step 2: Verify there are no remaining references to the removed env secrets**

```bash
grep -r "ADMIN_BOOTSTRAP_PASSWORD\|ADMIN_WHITELIST\|MANAGEMENT_API_TOKEN\|PLATFORM_HOST" \
  src/ scripts/ wrangler.jsonc
```

Expected: No matches (these should all be gone from env/config files).

- [ ] **Step 3: Run full typecheck and tests one final time**

```bash
pnpm typecheck && pnpm test
```

Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add scripts/setup-cf-resources.sh
git commit -m "chore: apply D1 migrations in deploy script"
```

---

## Task 10: Final — update existing spec doc

**Files:**
- Modify: `docs/superpowers/specs/2026-03-20-oidc-foundation-design.md`

- [ ] **Step 1: Update the OIDC foundation design spec**

Find the section describing admin authentication (search for "Fixed-whitelist" or "admin" in the doc). Add a note that admin credentials are stored in the `platform_config` D1 table rather than Worker secrets, and add `platform_config` to the Data Model section alongside the other tables.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-03-20-oidc-foundation-design.md
git commit -m "docs: update OIDC foundation spec — platform config stored in D1"
```
