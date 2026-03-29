# Tenant JWKS Key Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-tenant signing key rotation action to the admin UI, backed by a new API endpoint that retires the current active key and generates a fresh RS256 keypair.

**Architecture:** New function `rotateSigningKeyForTenant` in `src/adapters/db/drizzle/runtime.ts` handles the DB+R2 side-effects. A new `POST /api/admin/tenants/:tenantId/keys/rotate` route in `src/app/app.ts` calls it. The admin UI gains a ROTATE button per tenant row with a confirmation modal.

**Tech Stack:** TypeScript, Hono, Drizzle ORM (D1), R2 (key material), Vitest, React

---

## File Map

| File | Change |
|------|--------|
| `src/adapters/db/drizzle/runtime.ts` | Add `rotateSigningKeyForTenant` function |
| `src/app/app.ts` | Add `POST /api/admin/tenants/:tenantId/keys/rotate` route |
| `admin/src/api/client.ts` | Add `rotateTenantKey` API function |
| `admin/src/pages/TenantsPage.tsx` | Add ROTATE button + confirmation modal |
| `tests/rotate-signing-key.test.ts` | Unit test for `rotateSigningKeyForTenant` |

---

## Task 1: Add `rotateSigningKeyForTenant` to runtime.ts

**Files:**
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Test: `tests/rotate-signing-key.test.ts`

The existing `rotateSigningKeysForTenants` (line 364) retires ALL tenants' keys at once. We need a single-tenant version.

- [ ] **Step 1: Create the test file**

```ts
// tests/rotate-signing-key.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SigningKeySigner } from "../src/domain/keys/signer";

// Minimal in-memory stand-in for the D1 drizzle instance
// We test the logic by verifying what the signer receives and what the DB receives.

describe("rotateSigningKeyForTenant", () => {
  it("retires active keys for the tenant and bootstraps a new one", async () => {
    const updatedRows: { tenantId: string; status: string }[] = [];

    // Fake drizzle db that captures UPDATE calls
    const fakeDb = {
      update: () => ({
        set: (values: { status: string; retireAt: string }) => ({
          where: (condition: unknown) => {
            // Record what was updated — condition is opaque, so we just record the set values
            updatedRows.push({ tenantId: "tenant-abc", status: values.status });
            return Promise.resolve();
          }
        })
      })
    } as unknown as Parameters<typeof import("../src/adapters/db/drizzle/runtime").rotateSigningKeyForTenant>[0]["db"];

    let bootstrappedForTenant: string | null = null;
    const fakeSigner: SigningKeySigner = {
      ensureActiveSigningKeyMaterial: async (tenantId: string) => {
        bootstrappedForTenant = tenantId;
        return {
          key: {
            id: "new-key-id",
            tenantId,
            kid: `bootstrap-${tenantId}-rs256`,
            alg: "RS256",
            kty: "RSA",
            status: "active",
            publicJwk: { kty: "RSA", use: "sig", alg: "RS256", kid: `bootstrap-${tenantId}-rs256` }
          },
          privateJwk: { kty: "RSA", alg: "RS256", kid: `bootstrap-${tenantId}-rs256` }
        };
      },
      loadActiveSigningKeyMaterial: async () => null
    };

    const { rotateSigningKeyForTenant } = await import(
      "../src/adapters/db/drizzle/runtime"
    );

    const result = await rotateSigningKeyForTenant({
      db: fakeDb,
      signer: fakeSigner,
      tenantId: "tenant-abc"
    });

    expect(updatedRows).toHaveLength(1);
    expect(updatedRows[0].status).toBe("retired");

    expect(bootstrappedForTenant).toBe("tenant-abc");

    expect(result.kid).toBe("bootstrap-tenant-abc-rs256");
    expect(result.alg).toBe("RS256");
    expect(result.rotated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
pnpm vitest run tests/rotate-signing-key.test.ts
```

Expected: FAIL — `rotateSigningKeyForTenant is not a function` (export does not exist yet)

- [ ] **Step 3: Add `rotateSigningKeyForTenant` to `src/adapters/db/drizzle/runtime.ts`**

Add immediately after the closing `}` of `rotateSigningKeysForTenants` (around line 388):

```ts
export const rotateSigningKeyForTenant = async ({
  db,
  signer,
  tenantId
}: {
  db: ReturnType<typeof drizzle>;
  signer: SigningKeySigner;
  tenantId: string;
}): Promise<{ kid: string; alg: string; rotated_at: string }> => {
  const retiredAt = new Date().toISOString();

  await db
    .update(signingKeys)
    .set({ status: "retired", retireAt: retiredAt })
    .where(and(eq(signingKeys.status, "active"), eq(signingKeys.tenantId, tenantId)));

  const material = await signer.ensureActiveSigningKeyMaterial(tenantId);

  return {
    kid: material.key.kid,
    alg: material.key.alg,
    rotated_at: retiredAt
  };
};
```

Note: `SigningKeySigner` is already imported in this file at line 30 area. Verify the import exists:
```ts
import type { SigningKeySigner } from "../../../domain/keys/signer";
```
If missing, add it alongside the other domain imports at the top of the file.

- [ ] **Step 4: Run the test to confirm it passes**

```bash
pnpm vitest run tests/rotate-signing-key.test.ts
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/adapters/db/drizzle/runtime.ts tests/rotate-signing-key.test.ts
git commit -m "feat: add rotateSigningKeyForTenant function"
```

---

## Task 2: Add the API route to app.ts

**Files:**
- Modify: `src/app/app.ts`

The `signer` is already part of the app dependencies (line 325: `signer?: SigningKeySigner`). The new route follows the exact pattern of the existing `DELETE /admin/tenants/:tenantId`.

- [ ] **Step 1: Add the route in `src/app/app.ts`**

Find the `app.delete("/admin/tenants/:tenantId"` block (around line 2878). Add the new route **after** the closing `});` of `app.patch("/admin/tenants/:tenantId"` (around line 2876) and **before** `app.delete`:

```ts
  app.post("/admin/tenants/:tenantId/keys/rotate", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    if (signer === undefined) {
      return context.json({ error: "key_rotation_unavailable" }, 503);
    }
    const tenantId = context.req.param("tenantId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) {
      return context.notFound();
    }
    const result = await rotateSigningKeyForTenant({ db, signer, tenantId });
    return context.json(result, 200);
  });
```

- [ ] **Step 2: Add the import for `rotateSigningKeyForTenant`**

In `src/app/app.ts`, find the existing import of `rotateSigningKeysForTenants` from the runtime file. It will look similar to:

```ts
import { rotateSigningKeysForTenants, ... } from "../adapters/db/drizzle/runtime";
```

Add `rotateSigningKeyForTenant` to the same import. If the import is destructured across lines, add it as another entry. Search for `rotateSigningKeysForTenants` in the imports section to find the exact line.

```bash
grep -n "rotateSigningKeysForTenants" src/app/app.ts | head -5
```

Then edit that import line to also include `rotateSigningKeyForTenant`.

- [ ] **Step 3: Verify TypeScript compiles cleanly**

```bash
pnpm tsc --noEmit
```

Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add src/app/app.ts
git commit -m "feat: add POST /admin/tenants/:tenantId/keys/rotate route"
```

---

## Task 3: Add `rotateTenantKey` to the admin API client

**Files:**
- Modify: `admin/src/api/client.ts`

- [ ] **Step 1: Add the function**

In `admin/src/api/client.ts`, append after `deleteTenant` (around line 91):

```ts
export const rotateTenantKey = async (
  token: string,
  tenantId: string
): Promise<{ kid: string; alg: string; rotated_at: string }> => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/keys/rotate`, {
      method: "POST",
      headers: authHeaders(token)
    })
  );
  return res.json() as Promise<{ kid: string; alg: string; rotated_at: string }>;
};
```

- [ ] **Step 2: Verify TypeScript compiles in admin**

```bash
cd admin && pnpm tsc --noEmit
```

Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add admin/src/api/client.ts
git commit -m "feat: add rotateTenantKey API client function"
```

---

## Task 4: Add ROTATE button and confirmation modal to TenantsPage

**Files:**
- Modify: `admin/src/pages/TenantsPage.tsx`

The page currently has EDIT and DEL buttons. We add ROTATE with amber color. New state tracks which tenant's rotate modal is open.

- [ ] **Step 1: Add the import for `rotateTenantKey`**

At the top of `admin/src/pages/TenantsPage.tsx`, find the existing import:

```ts
import { createTenant, updateTenant, deleteTenant, listTenants, type TenantSummary } from "../api/client";
```

Add `rotateTenantKey` to it:

```ts
import { createTenant, updateTenant, deleteTenant, listTenants, rotateTenantKey, type TenantSummary } from "../api/client";
```

- [ ] **Step 2: Add rotate state variables**

Inside the `TenantsPage` component, after the existing delete state (around line 53):

```ts
  // Rotate key confirm
  const [rotatingTenant, setRotatingTenant] = useState<TenantSummary | null>(null);
  const [rotateSubmitting, setRotateSubmitting] = useState(false);
  const [rotateError, setRotateError] = useState<string | null>(null);
```

- [ ] **Step 3: Add the `handleRotate` handler**

After the `handleDelete` function (around line 135):

```ts
  const handleRotate = async () => {
    if (!rotatingTenant) return;
    setRotateError(null);
    setRotateSubmitting(true);
    try {
      await rotateTenantKey(token!, rotatingTenant.id);
      setRotatingTenant(null);
    } catch {
      setRotateError("ROTATION FAILED");
    } finally {
      setRotateSubmitting(false);
    }
  };
```

- [ ] **Step 4: Add the ROTATE button to each tenant row**

Find the Actions cell in the tenant row (around line 313). It currently renders EDIT and DEL buttons inside a `<div style={{ display: 'flex', gap: '6px' }}>`. The grid column is `120px`. Change it to `180px` to fit the third button, and add the ROTATE button:

Change the gridTemplateColumns from:
```ts
gridTemplateColumns: '1fr 1.2fr 90px 1.8fr 120px',
```
to:
```ts
gridTemplateColumns: '1fr 1.2fr 90px 1.8fr 180px',
```

This change appears in **two places**: the header row and the data row. Update both.

Then add the ROTATE button inside the actions div, between EDIT and DEL:

```tsx
<button
  onClick={e => { e.stopPropagation(); setRotatingTenant(t); setRotateError(null); }}
  style={{
    background: 'transparent', border: '1px solid var(--border)',
    color: 'var(--text-muted)', padding: '4px 8px',
    fontSize: '9px', fontFamily: "'Space Mono', monospace",
    letterSpacing: '0.1em', cursor: 'pointer', textTransform: 'uppercase'
  }}
  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = '#f59e0b'; (e.currentTarget as HTMLButtonElement).style.color = '#f59e0b'; }}
  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-muted)'; }}
>ROTATE</button>
```

- [ ] **Step 5: Add the rotate confirmation modal**

After the delete confirm modal closing `)}` (around line 401), add:

```tsx
      {/* Rotate key confirm modal */}
      {rotatingTenant && (
        <Modal title="ROTATE SIGNING KEY" onClose={() => setRotatingTenant(null)}>
          <div style={{ marginBottom: '20px', padding: '12px', background: 'rgba(245,158,11,0.05)', border: '1px solid rgba(245,158,11,0.3)' }}>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-primary)', marginBottom: '6px' }}>
              Rotate signing key for <strong style={{ fontFamily: "'Space Mono', monospace", color: '#f59e0b' }}>{rotatingTenant.slug}</strong>?
            </p>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-muted)' }}>
              The current active key will be immediately retired. All tokens signed with the old key will become invalid. New tokens will use the freshly generated key.
            </p>
          </div>
          {rotateError && (
            <div style={{ padding: '8px 12px', marginBottom: '16px', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)' }}>
              <span className="font-display" style={{ fontSize: '10px', color: '#ef4444', letterSpacing: '0.08em' }}>✕ {rotateError}</span>
            </div>
          )}
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => setRotatingTenant(null)}
              style={{ flex: 1, background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.12em', textTransform: 'uppercase', cursor: 'pointer' }}
            >
              CANCEL
            </button>
            <button
              onClick={handleRotate}
              disabled={rotateSubmitting}
              style={{ flex: 1, background: 'rgba(245,158,11,0.08)', border: '1px solid #f59e0b', color: rotateSubmitting ? 'var(--text-muted)' : '#f59e0b', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.12em', textTransform: 'uppercase', cursor: rotateSubmitting ? 'not-allowed' : 'pointer' }}
            >
              {rotateSubmitting ? 'ROTATING...' : 'ROTATE KEY'}
            </button>
          </div>
        </Modal>
      )}
```

- [ ] **Step 6: Verify TypeScript compiles in admin**

```bash
cd admin && pnpm tsc --noEmit
```

Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add admin/src/pages/TenantsPage.tsx
git commit -m "feat: add ROTATE KEY button and confirmation modal to tenant list"
```

---

## Self-Review Checklist

- [x] Spec: single-tenant rotation → Task 1 (`rotateSigningKeyForTenant`)
- [x] Spec: old key immediately retired (status='retired') → Task 1 step 3
- [x] Spec: new key used for subsequent token issuance → handled by `ensureActiveSigningKeyMaterial` returning new material
- [x] Spec: new key appears in JWKS → `buildJwks` calls `listActiveKeysForTenant` which returns only active keys
- [x] Spec: admin UI ROTATE button → Task 4
- [x] Spec: confirmation modal with destructive warning → Task 4 step 5
- [x] Spec: 404 if tenant not found → Task 2 step 1 (`context.notFound()`)
- [x] Spec: 503 if signer unavailable → Task 2 step 1 (`signer === undefined` guard)
- [x] No TBD/TODO placeholders
- [x] Type consistency: `rotateSigningKeyForTenant` returns `{ kid, alg, rotated_at }` — used consistently in Task 2 route and Task 3 client
