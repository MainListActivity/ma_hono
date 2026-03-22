# Setup Wizard Design

## Goal

Replace hard-fail Worker secret validation with a database-backed setup wizard that guides the operator through first-time platform configuration on first access.

When the platform has not been initialized, any incoming request is intercepted and redirected to a setup page. The operator fills in the four required platform configuration values, which are persisted to D1. Subsequent requests load configuration from D1 and proceed normally.

This eliminates the requirement for `wrangler secret put` as a deployment prerequisite and replaces it with an in-browser guided initialization flow.

## Scope

### In Scope

- `platform_config` D1 table for persistent platform configuration
- `src/config/platform-config.ts` module for loading config from D1
- `src/app/setup-app.ts` isolated Hono application for the setup wizard
- `src/lib/pbkdf2.ts` PBKDF2 hash and verify utilities using `crypto.subtle`
- Entry point detection in `src/index.ts`: uninitialized → setup app, initialized → main app
- Drizzle schema and migration for `platform_config`
- Removal of `ADMIN_BOOTSTRAP_PASSWORD`, `ADMIN_WHITELIST`, `MANAGEMENT_API_TOKEN`, `PLATFORM_HOST` from `env.ts` Zod validation
- Update `domain/admin-auth/service.ts` to use PBKDF2 password verification

### Out of Scope

- Post-setup modification of admin whitelist or other config values (future work)
- Multi-step wizard with progress indicator
- Email verification of admin whitelist entries
- Re-initialization or config reset flow

## Data Model

### `platform_config` Table

```sql
CREATE TABLE platform_config (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

Drizzle schema:

```typescript
export const platformConfig = sqliteTable("platform_config", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: text("updated_at").notNull()
});
```

### Config Keys

| Key | Value format | Notes |
|-----|-------------|-------|
| `admin_bootstrap_password_hash` | `<iterations>:<salt_base64url>:<hash_base64url>` | PBKDF2-SHA256, never stored as plaintext |
| `admin_whitelist` | Comma-separated email addresses | e.g. `admin@example.com,ops@example.com` |
| `management_api_token` | Plaintext token string | Operator-supplied |
| `root_domain` | Root domain without scheme or subdomain | e.g. `maplayer.top` — derives `auth.maplayer.top` (Pages/API) and `o.maplayer.top` (OIDC) |

All four keys must be present for the platform to be considered initialized. If any are missing, the setup wizard is shown.

## Module: `src/config/platform-config.ts`

```typescript
export interface PlatformConfig {
  adminBootstrapPasswordHash: string;
  adminWhitelist: string[];
  managementApiToken: string;
  rootDomain: string;
}

// Returns null if any required key is absent — platform is uninitialized
export const loadPlatformConfig = async (db: D1Database): Promise<PlatformConfig | null>
```

Reads all four keys in a single `SELECT WHERE key IN (...)` query. Returns `null` if any key is missing.

## Entry Point: `src/index.ts`

```
fetch(request, env):
  1. readRuntimeConfig(env)     — validates D1/KV/R2 bindings only; throws on missing binding
  2. loadPlatformConfig(db)     — reads platform_config table
  3. if null                    → return setupApp.fetch(request, { db, request })
  4. else                       → return mainApp.fetch(request, env, ctx)
```

`createApp` signature changes: `adminBootstrapPassword`, `adminWhitelist`, `managementApiToken`, and `platformHost` become required (non-optional) fields, since `createApp` is only called when config is confirmed present.

## Setup Application: `src/app/setup-app.ts`

A standalone minimal Hono application. It has no dependency on the main app and no access to admin sessions, tenant repositories, or signing keys.

### Routes

| Method | Path | Action |
|--------|------|--------|
| `GET` | `/` | 302 redirect to `/setup` |
| `GET` | `/setup` | Render setup form HTML |
| `POST` | `/setup` | Process form, write to D1, redirect to `https://auth.{platform_host}/` |

### Form Fields

| Field name | Label | Notes |
|-----------|-------|-------|
| `root_domain` | Root Domain | e.g. `maplayer.top` — derives `auth.maplayer.top` and `o.maplayer.top`; pre-filled by guessing from `request.headers.get("host")`, user may edit |
| `admin_whitelist` | Admin Email(s) | Placeholder: `admin@example.com` — comma-separated |
| `admin_bootstrap_password` | Admin Password | Password input |
| `admin_bootstrap_password_confirm` | Confirm Password | Must match |
| `management_api_token` | Management API Token | Plain text input |

### POST Processing

1. Validate all fields non-empty
2. Validate `admin_bootstrap_password === admin_bootstrap_password_confirm`
3. Validate `root_domain` is a valid bare domain (no scheme, no path, no subdomain prefix)
4. Hash `admin_bootstrap_password` with `hashPasswordPbkdf2`
5. Write all four records to `platform_config` in a single D1 batch (`root_domain` replaces the former `platform_host` key)
6. On success: 302 redirect to `https://auth.{root_domain}/`
7. On validation failure: re-render form with inline error messages, preserving all field values except password fields

### UI

Inline HTML string rendered by Hono's `html` helper. Matches the visual style of the existing admin UI. No external template engine or asset pipeline required.

## Password Hashing: `src/lib/pbkdf2.ts`

Uses `crypto.subtle` (available in Cloudflare Workers without any import).

Hash format: `<iterations>:<salt_base64url>:<derived_key_base64url>`

Example: `100000:abc123...:xyz789...`

```typescript
export const hashPasswordPbkdf2 = async (password: string): Promise<string>
export const verifyPasswordPbkdf2 = async (password: string, hash: string): Promise<boolean>
```

Parameters:
- Algorithm: PBKDF2-SHA256
- Iterations: 100,000
- Key length: 32 bytes
- Salt: 16 random bytes per hash

## `domain/admin-auth/service.ts` Adjustment

`loginAdmin` currently uses plaintext comparison:

```typescript
if (password !== adminBootstrapPassword) { ... }
```

This changes to:

```typescript
const isValid = await verifyPasswordPbkdf2(password, adminBootstrapPasswordHash);
if (!isValid) { ... }
```

The parameter `adminBootstrapPassword: string` is renamed to `adminBootstrapPasswordHash: string` to make the contract explicit.

## `src/config/env.ts` Adjustment

Remove from `runtimeConfigSchema`:
- `ADMIN_BOOTSTRAP_PASSWORD`
- `ADMIN_WHITELIST`
- `MANAGEMENT_API_TOKEN`
- `PLATFORM_HOST`

Remove from `RuntimeConfig` interface and `readRuntimeConfig` return value:
- `adminBootstrapPassword`
- `adminWhitelist`
- `managementApiToken`
- `platformHost`

Only D1, KV, and R2 bindings remain in `runtimeConfigSchema`.

## Database Migration

New migration file in `drizzle/migrations/`:

```sql
CREATE TABLE platform_config (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

Migration is applied automatically during deployment via `wrangler d1 migrations apply` (already called in `setup-cf-resources.sh` or equivalent deploy step).

## Deployment Impact

`setup-cf-resources.sh` no longer needs to set any Worker secrets for the four platform config values. The script only needs to ensure:

1. D1 database exists and migrations are applied
2. KV namespaces exist
3. R2 bucket exists
4. Worker is deployed

On first visit after deployment, the operator is guided through the setup wizard to supply all configuration values.

## Existing Spec Updates

### `2026-03-20-oidc-foundation-design.md`

- Update "Fixed-whitelist admin authentication" section: note that admin credentials and whitelist are stored in `platform_config` D1 table, not Worker secrets
- Add `platform_config` to the Data Model section
- Remove any mention of `wrangler secret put` from deployment instructions

### `2026-03-21-idp-v1-login-and-authorization-design.md`

- No references to the four env vars were found in this document; no changes required

## Non-Goals

- This design does not add a re-initialization or "reset setup" flow. If an operator needs to change config, they must modify `platform_config` directly via D1 console or a future admin settings page.
- This design does not validate that the `platform_host` value matches the actual Worker route. That is the operator's responsibility.
