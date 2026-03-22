# Client-Level Auth Method Policy Design

**Date:** 2026-03-22
**Status:** Approved
**Scope:** Admin UI, backend API, login page, self-registration flow

---

## Overview

Add per-client authentication method configuration, replacing the existing tenant-level `TenantAuthMethodPolicy`. Each OIDC client has its own policy specifying which login methods are enabled and whether self-registration is allowed per method. The login page respects this policy at runtime by querying the client associated with the active login challenge.

---

## Background / Motivation

The existing `tenant_auth_method_policies` table controls login methods at the tenant level. This is too coarse: different clients under the same tenant may need different login experiences (e.g., a native mobile app enables passkeys but not self-registration; a web app enables password login with self-registration allowed). Moving policy to the client level resolves this and sets the foundation for per-client social login configuration.

---

## Data Model

### New table: `client_auth_method_policies`

One row per OIDC client. Created automatically when a client is created (all methods disabled by default).

```sql
client_auth_method_policies (
  client_id                     TEXT PRIMARY KEY  -- FK -> oidc_clients.id (UUID PK) ON DELETE CASCADE
                                                  -- NOTE: this is oidc_clients.id (UUID), NOT oidc_clients.client_id (the OAuth string)
  tenant_id                     TEXT NOT NULL     -- FK -> tenants.id ON DELETE CASCADE (for efficient tenant-scoped queries)
  password_enabled              INTEGER NOT NULL DEFAULT 0
  password_allow_registration   INTEGER NOT NULL DEFAULT 0
  magic_link_enabled            INTEGER NOT NULL DEFAULT 0
  magic_link_allow_registration INTEGER NOT NULL DEFAULT 0
  passkey_enabled               INTEGER NOT NULL DEFAULT 0
  passkey_allow_registration    INTEGER NOT NULL DEFAULT 0
  google_enabled                INTEGER NOT NULL DEFAULT 0  -- reserved
  apple_enabled                 INTEGER NOT NULL DEFAULT 0  -- reserved
  facebook_enabled              INTEGER NOT NULL DEFAULT 0  -- reserved
  wechat_enabled                INTEGER NOT NULL DEFAULT 0  -- reserved
  created_at                    TEXT NOT NULL
  updated_at                    TEXT NOT NULL
)
```

**FK clarification:** `client_auth_method_policies.client_id` references `oidc_clients.id` (the UUID primary key), not `oidc_clients.client_id` (the OAuth client identifier string). The Drizzle schema must use `.references(() => oidcClients.id, { onDelete: "cascade" })`. The `ClientAuthMethodPolicyRepository` interface uses the internal UUID (`client.id`) as its lookup key, not the OAuth `client_id` string. Callers must resolve the UUID from the client record before interacting with this repository.

Social login providers (`google`, `apple`, `facebook`, `wechat`) have an `enabled` flag but no `allow_registration` flag — user identity for social login is managed by the upstream provider.

### Deprecation of `tenant_auth_method_policies`

- The table is **not dropped** (no destructive migration).
- `findAuthMethodPolicyByTenantId` is no longer called anywhere in the active login path.
- `handleChallengeInfo` switches to `findClientAuthMethodPolicyByClientId`.
- The `UserRepository.findAuthMethodPolicyByTenantId` method is retained in the interface for backwards compatibility but becomes a no-op in the login path.

### Domain types

```typescript
export interface ClientAuthMethodPolicy {
  clientId: string;
  tenantId: string;
  password: { enabled: boolean; allowRegistration: boolean };
  emailMagicLink: { enabled: boolean; allowRegistration: boolean };
  passkey: { enabled: boolean; allowRegistration: boolean };
  google: { enabled: boolean };
  apple: { enabled: boolean };
  facebook: { enabled: boolean };
  wechat: { enabled: boolean };
}
```

`Client` type gains an optional `authMethodPolicy?: ClientAuthMethodPolicy` field, embedded in list/get responses.

---

## Repository

### `ClientAuthMethodPolicyRepository` (new interface)

```typescript
interface ClientAuthMethodPolicyRepository {
  // clientId here is oidc_clients.id (UUID), not the OAuth client_id string
  create(policy: ClientAuthMethodPolicy): Promise<void>;
  findByClientId(clientId: string): Promise<ClientAuthMethodPolicy | null>;
  // update accepts a full ClientAuthMethodPolicy (read-then-write for partial updates)
  update(policy: ClientAuthMethodPolicy): Promise<void>;
}
```

Implementations: Drizzle (D1) and in-memory (for tests).

**Wiring in `app.ts`:** `ClientAuthMethodPolicyRepository` is added to `AppOptions` as an optional field (`clientAuthMethodPolicyRepository?`) with an `EmptyClientAuthMethodPolicyRepository` fallback (same pattern as other repositories). `EmptyClientAuthMethodPolicyRepository.findByClientId` returns `null`; `create` and `update` are no-ops. Returning `null` from `findByClientId` is the fail-safe: the login path treats it as all methods disabled. It is injected into `handleChallengeInfo` via the closure over the `createApp` scope. The `POST /admin/tenants/:tenantId/clients` handler and the new `POST /t/:tenant/register` handler also receive it through the same closure.

---

## Backend API Changes

### Admin endpoints

| Method | Path | Change |
|--------|------|--------|
| `GET` | `/admin/tenants/:tenantId/clients` | Each client object now includes `auth_method_policy` |
| `POST` | `/admin/tenants/:tenantId/clients` | Creates default policy row alongside client (see atomicity note below) |
| `GET` | `/admin/tenants/:tenantId/clients/:clientId` | New endpoint, returns single client with embedded policy. If no policy row exists (e.g. pre-migration clients), synthesizes and persists a default all-disabled policy row on first access, then returns it. This ensures the modal always has a row to update via PATCH. |
| `PATCH` | `/admin/tenants/:tenantId/clients/:clientId/auth-method-policy` | Updates method policy |

**Atomicity for client creation:** When `POST /admin/tenants/:tenantId/clients` creates a client, it must also create the default policy row. If the policy insert fails after the client insert succeeds, the client must be rolled back (D1 does not support multi-statement transactions in the same way as traditional SQL, so use a D1 batch operation to execute both inserts atomically). If batch execution is not available in the adapter layer, delete the client and throw — same cleanup pattern used for `registrationAccessToken` failures in the existing code.

#### `PATCH` request body

```json
{
  "password": { "enabled": true, "allow_registration": true },
  "magic_link": { "enabled": true, "allow_registration": false },
  "passkey": { "enabled": false, "allow_registration": false },
  "google": { "enabled": false },
  "apple": { "enabled": false },
  "facebook": { "enabled": false },
  "wechat": { "enabled": false }
}
```

All fields are optional (partial update — omitting a field leaves the existing value unchanged). Unrecognized fields are ignored. The handler performs a read-then-write: it fetches the current policy, merges the supplied fields, then calls `update(mergedPolicy)` on the repository. If no policy row exists for the client, return `404`.

### Login challenge info endpoint

Two route forms are registered in `app.ts` (one for custom-domain tenants, one for platform-path tenants). Both must be updated:
- `GET /login/challenge-info?login_challenge=xxx` (custom-domain)
- `GET /login/:tenant/challenge-info?login_challenge=xxx` (platform-path)

**Before:**
```json
{
  "tenant_display_name": "Acme",
  "methods": ["password", "magic_link"]
}
```

**After:**
```json
{
  "tenant_display_name": "Acme",
  "methods": [
    { "method": "password", "allow_registration": true },
    { "method": "magic_link", "allow_registration": false },
    { "method": "passkey", "allow_registration": false }
  ]
}
```

The endpoint resolves the `clientId` from the login challenge, looks up `client_auth_method_policies`, and returns only enabled methods. If no policy row exists for the client, returns an empty methods array (fail-safe: deny all).

### User self-registration endpoint (new)

`POST /t/:tenant/register`

The `:tenant` parameter is the tenant slug (same as other `/t/:tenant/*` endpoints). The handler uses `resolveIssuerContextBySlug` to resolve the tenant — the same pattern used by `/t/:tenant/authorize`. Cross-tenant protection: the resolved `tenantId` from the slug must match `loginChallenge.tenantId`; if they differ, return `400 invalid_login_challenge`.

```json
{
  "login_challenge": "...",
  "email": "user@example.com",
  "username": "optional_username",
  "password": "..."
}
```

**Behavior:**
1. Resolve tenant from `:tenant` slug via `resolveIssuerContextBySlug`. If not found, `404`.
2. Validate `login_challenge` — must be valid, unconsumed, and `tenantId` must match the resolved tenant. If not, `400 invalid_login_challenge`.
3. Look up client policy for `loginChallenge.clientId` — `password.allow_registration` must be `true`, else `403 registration_not_allowed`.
4. Validate input (email format, password minimum length via Zod). If invalid, `400 invalid_request`.
5. Create user with status `active` (no invitation flow — self-registered users are immediately active).
6. Create `PasswordCredential` (hash password with same mechanism as existing password auth).
7. Create `BrowserSession` for the new user.
8. Consume login challenge and create `AuthorizationCode`.
9. Emit audit event: `user.self_registration.succeeded` with `actorType: "end_user"`, `actorId: newUser.id`, `tenantId`.
10. Return `302` redirect to `loginChallenge.redirectUri` with `code` + `state` (same response shape as password login success path).

**Response format:** HTTP `302` redirect (not a JSON body with redirect_uri). The frontend `RegisterForm` must handle this the same way `PasswordForm` handles login: detect `res.status === 302 || res.type === "opaqueredirect"`, read `res.headers.get("location")`, and assign `window.location.href`.

**Errors:**
- `registration_not_allowed` (403) — client policy disallows registration
- `email_already_exists` (409) — user with that email already exists in the tenant
- `invalid_request` (400) — validation failure
- `invalid_login_challenge` (400) — expired, unknown, or cross-tenant challenge

---

## Admin UI Changes

### `TenantClientsPage.tsx`

- Table column layout adds an **"AUTH POLICY"** action button per client row (alongside the existing "▶ TEST" button).
- Clicking "AUTH POLICY" opens an `AuthMethodPolicyModal` which:
  - Fetches current policy via `GET /admin/tenants/:tenantId/clients/:clientId`.
  - Renders a table of methods with toggle switches for `enabled` and (where applicable) `allow_registration`.
  - Submits via `PATCH /admin/tenants/:tenantId/clients/:clientId/auth-method-policy`.
  - Shows success/error feedback inline.

**Modal layout:**

```
AUTH METHOD POLICY — {client_name}

METHOD         ENABLED    ALLOW REGISTRATION
─────────────────────────────────────────────
Password       [toggle]   [toggle]
Magic Link     [toggle]   [toggle]
Passkey        [toggle]   [toggle]
─────────────────────────────────────────────
Google         [toggle]   —
Apple          [toggle]   —
Facebook       [toggle]   —
WeChat         [toggle]   —

                    [ SAVE ]
```

Social login rows show `—` in the "Allow Registration" column.

### `api/client.ts`

New/updated types and functions:

```typescript
// Updated
export interface ChallengeInfo {
  tenant_display_name: string;
  methods: { method: string; allow_registration: boolean }[];
}

// New
export interface ClientAuthMethodPolicy { ... }
export const getClient = (token, tenantId, clientId) => ...
export const updateClientAuthMethodPolicy = (token, tenantId, clientId, policy) => ...
export const registerUser = (tenantSlug, payload) => ...
```

### `TenantLoginPage.tsx`

**`PasswordForm` component changes:**
- Receives `allowRegistration: boolean` prop.
- When `allowRegistration` is `true`, renders a "Don't have an account? Register" link below the Sign In button.
- Clicking the link toggles into a `RegisterForm` view (within the same card, no navigation).

**`RegisterForm` component (new, inline):**
- Fields: Email, Username (optional), Password, Confirm Password.
- Submits to `POST /t/:tenant/register` with the active `login_challenge`.
- On success (302 or redirect_uri): navigates to `redirect_uri` (same as password login).
- On `email_already_exists`: shows "An account with this email already exists. Please sign in."
- "Back to sign in" link returns to `PasswordForm`.

**`ChallengeInfo` type update:**
- `methods` changes from `string[]` to `{ method: string; allow_registration: boolean }[]`.
- `activeMethod` state initialized to `data.methods[0]?.method ?? null`.

---

## Migration

1. Add Drizzle schema entry for `client_auth_method_policies`.
2. Generate and apply D1 migration SQL.
3. For existing clients that have no policy row: the `findByClientId` returning `null` is treated as "all methods disabled" (fail-safe). Operators must explicitly configure policies via admin UI after migration.

No data is migrated from `tenant_auth_method_policies` — the old table is left in place but becomes dead code.

---

## Error Handling

- If `client_auth_method_policies` row is missing for a client during challenge-info lookup: return empty `methods` array (do not fall back to tenant policy).
- If `PATCH` is called for a non-existent client or wrong tenant: `404`.
- Registration endpoint validates that the challenge has not been consumed and has not expired before creating the user.

---

## Affected Files

### Backend (`src/`)
- `src/adapters/db/drizzle/schema.ts` — new table
- `src/domain/clients/types.ts` — add `ClientAuthMethodPolicy`, update `Client`
- `src/domain/clients/repository.ts` — add `ClientAuthMethodPolicyRepository`
- `src/adapters/db/drizzle/runtime.ts` — implement Drizzle repository
- `src/adapters/db/memory/memory-client-repository.ts` — implement in-memory repository
- `src/app/app.ts` — new/modified routes, wire new repository

### Admin UI (`admin/`)
- `admin/src/api/client.ts` — updated types, new API functions
- `admin/src/pages/TenantClientsPage.tsx` — AUTH POLICY button + modal
- `admin/src/pages/TenantLoginPage.tsx` — registration flow in PasswordForm
