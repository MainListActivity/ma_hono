# Tenant JWKS Key Rotation — Design Spec

**Date:** 2026-03-29
**Scope:** Admin UI + backend API for rotating a single tenant's signing key

---

## Overview

Add a "Rotate Key" action to the admin tenant list. Clicking it immediately retires the tenant's current active signing key and generates a new one. The new key is used for all subsequent token issuance and appears in the tenant's JWKS endpoint. Previously issued tokens signed with the old key become invalid immediately.

---

## Architecture

### Backend

**New function: `rotateSigningKeyForTenant`** in `src/adapters/db/drizzle/runtime.ts`

```
rotateSigningKeyForTenant({
  db,
  signer,
  tenantId
}): Promise<{ kid: string; alg: string; rotated_at: string }>
```

Steps:
1. `UPDATE signing_keys SET status='retired', retireAt=now WHERE tenantId=? AND status='active'`
2. Call `signer.ensureActiveSigningKeyMaterial(tenantId)` — this finds no active key and bootstraps a new RS256 keypair, persisting the private JWK to R2 and the public record to D1
3. Return the new key's `kid`, `alg`, and `rotated_at` timestamp

The existing `rotateSigningKeysForTenants` (bulk, all tenants) is unchanged.

**New route:** `POST /api/admin/tenants/:tenantId/keys/rotate`

- Protected by existing admin auth middleware
- Validates tenant exists (404 if not)
- Calls `rotateSigningKeyForTenant`
- Returns `200 { kid, alg, rotated_at }`

This route follows the same pattern as other admin tenant routes in `src/app/app.ts`.

### Frontend

**`admin/src/api/client.ts`**

New export:
```ts
export const rotateTenantKey = async (
  token: string,
  tenantId: string
): Promise<{ kid: string; alg: string; rotated_at: string }>
```

**`admin/src/pages/TenantsPage.tsx`**

- New `ROTATE` button in each tenant row's Actions cell, styled in amber/warning color (`#f59e0b`) to distinguish from EDIT (cyan) and DEL (red)
- Click opens a confirmation Modal with destructive warning: "This will immediately retire the current signing key. All tokens issued with the old key will become invalid."
- Confirmation triggers API call with loading state on the button
- On success: close modal (no page reload needed — key rotation doesn't change tenant list data)
- On error: show inline error in modal

New state per tenant row (keyed by tenantId):
- `rotatingTenant: TenantSummary | null` — which tenant's rotate modal is open
- `rotateSubmitting: boolean`
- `rotateError: string | null`

---

## Data Flow

```
Admin clicks ROTATE
  → confirmation modal opens
  → admin confirms
  → POST /api/admin/tenants/:tenantId/keys/rotate
      → retire active keys in D1
      → generate new RS256 keypair (Web Crypto)
      → store private JWK in R2
      → insert new signing_keys row in D1
  → return { kid, alg, rotated_at }
  → modal closes
```

Next token issuance for that tenant:
```
signer.ensureActiveSigningKeyMaterial(tenantId)
  → D1KeyRepository.listActiveKeysForTenant → finds new key
  → loads private JWK from R2
  → signs JWT with new key (kid in header)
```

JWKS endpoint (`GET /t/:slug/.well-known/jwks.json`):
```
buildJwks → KeyRepository.listActiveKeysForTenant → returns only new key's publicJwk
```

---

## Error Handling

- Tenant not found → 404
- DB update fails → 500, no new key generated (atomic: retire happens first, but failure here leaves tenant temporarily without a key until retry)
- R2 write fails → bootstrapper rolls back D1 insert (existing behavior in `D1SigningKeyBootstrapper`)
- Frontend API error → shown inline in confirmation modal

---

## Out of Scope

- Grace period / key overlap (old key stays in JWKS temporarily) — explicitly excluded per spec
- Bulk rotation UI — existing cron/scheduled path handles this
- Key history view — not needed for this feature
