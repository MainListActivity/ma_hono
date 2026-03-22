# Client Auth Method Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace tenant-level auth method policy with per-client policy, add admin UI to configure it, and add self-registration via password on the login page.

**Architecture:** New `client_auth_method_policies` D1 table (keyed by `oidc_clients.id` UUID) holds per-client method toggles + registration flags. A new `ClientAuthMethodPolicyRepository` is wired into `app.ts` following the existing empty-class fallback pattern. The login challenge-info endpoint switches from tenant policy to client policy lookup. A new `POST /t/:tenant/register` endpoint handles self-registration. Admin UI gains an "AUTH POLICY" modal per client. Login page's `PasswordForm` gains an inline `RegisterForm` when `allow_registration` is true.

**Tech Stack:** TypeScript strict, Hono, Drizzle ORM, D1 (SQLite), Zod, Vitest (app.ts integration tests), React + Tailwind (admin SPA)

---

## File Map

| File | Change |
|------|--------|
| `src/adapters/db/drizzle/schema.ts` | Add `clientAuthMethodPolicies` table |
| `src/domain/clients/types.ts` | Add `ClientAuthMethodPolicy` type; add optional `authMethodPolicy?` to `Client` |
| `src/domain/clients/repository.ts` | Add `ClientAuthMethodPolicyRepository` interface |
| `src/adapters/db/memory/memory-client-auth-method-policy-repository.ts` | New in-memory impl for tests |
| `src/adapters/db/drizzle/runtime.ts` | Add `D1ClientAuthMethodPolicyRepository` class; wire into `createRuntimeRepositories` |
| `src/app/app.ts` | Add `EmptyClientAuthMethodPolicyRepository`; add to `AppOptions`; update `handleChallengeInfo`; update `POST /admin/tenants/:tenantId/clients`; add `GET /admin/tenants/:tenantId/clients/:clientId`; add `PATCH .../auth-method-policy`; add `POST /t/:tenant/register`; update `GET /admin/tenants/:tenantId/clients` list response |
| `admin/src/api/client.ts` | Update `ChallengeInfo` type; add `ClientAuthMethodPolicy` type; add `getClient`, `updateClientAuthMethodPolicy`, `registerUser` functions |
| `admin/src/pages/TenantClientsPage.tsx` | Add AUTH POLICY button + `AuthMethodPolicyModal` component |
| `admin/src/pages/TenantLoginPage.tsx` | Update `ChallengeInfo` consumption; add `allowRegistration` prop to `PasswordForm`; add inline `RegisterForm` component |

---

## Task 1: Drizzle Schema — Add `client_auth_method_policies` table

**Files:**
- Modify: `src/adapters/db/drizzle/schema.ts`

- [ ] **Step 1: Add the table definition**

Open `src/adapters/db/drizzle/schema.ts`. After the `tenantAuthMethodPolicies` table (line ~211), add:

```typescript
export const clientAuthMethodPolicies = sqliteTable(
  "client_auth_method_policies",
  {
    clientId: text("client_id")
      .primaryKey()
      .references(() => oidcClients.id, { onDelete: "cascade" }),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    passwordEnabled: integer("password_enabled", { mode: "boolean" }).notNull().default(false),
    passwordAllowRegistration: integer("password_allow_registration", { mode: "boolean" }).notNull().default(false),
    magicLinkEnabled: integer("magic_link_enabled", { mode: "boolean" }).notNull().default(false),
    magicLinkAllowRegistration: integer("magic_link_allow_registration", { mode: "boolean" }).notNull().default(false),
    passkeyEnabled: integer("passkey_enabled", { mode: "boolean" }).notNull().default(false),
    passkeyAllowRegistration: integer("passkey_allow_registration", { mode: "boolean" }).notNull().default(false),
    googleEnabled: integer("google_enabled", { mode: "boolean" }).notNull().default(false),
    appleEnabled: integer("apple_enabled", { mode: "boolean" }).notNull().default(false),
    facebookEnabled: integer("facebook_enabled", { mode: "boolean" }).notNull().default(false),
    wechatEnabled: integer("wechat_enabled", { mode: "boolean" }).notNull().default(false),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    tenantIdIdx: index("client_auth_method_policies_tenant_id_idx").on(table.tenantId)
  })
);
```

- [ ] **Step 2: Generate migration**

```bash
cd /Users/y/IdeaProjects/ma_hono
pnpm drizzle-kit generate
```

Expected: A new SQL migration file appears in `drizzle/` or `migrations/` directory. Inspect it — it should contain `CREATE TABLE client_auth_method_policies`.

- [ ] **Step 3: Commit**

```bash
git add src/adapters/db/drizzle/schema.ts
git add drizzle/  # or migrations/ — wherever the migration landed
git commit -m "feat: add client_auth_method_policies schema and migration"
```

---

## Task 2: Domain Types — `ClientAuthMethodPolicy`

**Files:**
- Modify: `src/domain/clients/types.ts`
- Modify: `src/domain/clients/repository.ts`

- [ ] **Step 1: Add `ClientAuthMethodPolicy` to types.ts**

In `src/domain/clients/types.ts`, add after the existing `ClientConsentPolicy` type:

```typescript
export interface ClientAuthMethodPolicy {
  clientId: string; // oidc_clients.id (UUID), NOT the OAuth client_id string
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

Also add `authMethodPolicy?: ClientAuthMethodPolicy` to the `Client` interface:

```typescript
export interface Client {
  id: string;
  tenantId: string;
  clientId: string;
  clientName: string;
  applicationType: ClientApplicationType;
  grantTypes: string[];
  redirectUris: string[];
  responseTypes: string[];
  tokenEndpointAuthMethod: ClientTokenEndpointAuthMethod;
  clientSecretHash: string | null;
  trustLevel: ClientTrustLevel;
  consentPolicy: ClientConsentPolicy;
  authMethodPolicy?: ClientAuthMethodPolicy; // optional — not always loaded
}
```

- [ ] **Step 2: Add `ClientAuthMethodPolicyRepository` to repository.ts**

In `src/domain/clients/repository.ts`, add after the existing `ClientRepository`:

```typescript
import type { Client, ClientAuthMethodPolicy } from "./types";

export interface ClientAuthMethodPolicyRepository {
  // clientId is oidc_clients.id (UUID), not the OAuth client_id string
  create(policy: ClientAuthMethodPolicy): Promise<void>;
  findByClientId(clientId: string): Promise<ClientAuthMethodPolicy | null>;
  update(policy: ClientAuthMethodPolicy): Promise<void>;
}
```

- [ ] **Step 3: Commit**

```bash
git add src/domain/clients/types.ts src/domain/clients/repository.ts
git commit -m "feat: add ClientAuthMethodPolicy domain types and repository interface"
```

---

## Task 3: In-Memory Repository (for tests)

**Files:**
- Create: `src/adapters/db/memory/memory-client-auth-method-policy-repository.ts`

- [ ] **Step 1: Create the file**

```typescript
import type { ClientAuthMethodPolicyRepository } from "../../../domain/clients/repository";
import type { ClientAuthMethodPolicy } from "../../../domain/clients/types";

export class MemoryClientAuthMethodPolicyRepository
  implements ClientAuthMethodPolicyRepository
{
  private policies: ClientAuthMethodPolicy[] = [];

  async create(policy: ClientAuthMethodPolicy): Promise<void> {
    this.policies.push({ ...policy });
  }

  async findByClientId(clientId: string): Promise<ClientAuthMethodPolicy | null> {
    return this.policies.find((p) => p.clientId === clientId) ?? null;
  }

  async update(policy: ClientAuthMethodPolicy): Promise<void> {
    const idx = this.policies.findIndex((p) => p.clientId === policy.clientId);
    if (idx !== -1) {
      this.policies[idx] = { ...policy };
    }
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/adapters/db/memory/memory-client-auth-method-policy-repository.ts
git commit -m "feat: add MemoryClientAuthMethodPolicyRepository for tests"
```

---

## Task 4: Drizzle Repository Implementation

**Files:**
- Modify: `src/adapters/db/drizzle/runtime.ts`

- [ ] **Step 1: Add import for new schema table**

In `src/adapters/db/drizzle/runtime.ts`, add `clientAuthMethodPolicies` to the schema import (around line 41):

```typescript
import {
  adminUsers,
  auditEvents,
  authorizationCodes,
  clientAuthMethodPolicies,  // add this
  emailLoginTokens,
  loginChallenges,
  oidcClients,
  signingKeys,
  tenantAuthMethodPolicies,
  tenantIssuers,
  tenants,
  userInvitations,
  userPasswordCredentials,
  users,
  webauthnCredentials
} from "./schema";
```

Also add type imports at the top:

```typescript
import type { ClientAuthMethodPolicyRepository } from "../../../domain/clients/repository";
import type { ClientAuthMethodPolicy } from "../../../domain/clients/types";
```

- [ ] **Step 2: Add helper function to convert row to domain type**

Add this helper before the class definition (place it near the other `to*` helper functions):

```typescript
const toClientAuthMethodPolicy = (
  row: typeof clientAuthMethodPolicies.$inferSelect
): ClientAuthMethodPolicy => ({
  clientId: row.clientId,
  tenantId: row.tenantId,
  password: { enabled: row.passwordEnabled, allowRegistration: row.passwordAllowRegistration },
  emailMagicLink: { enabled: row.magicLinkEnabled, allowRegistration: row.magicLinkAllowRegistration },
  passkey: { enabled: row.passkeyEnabled, allowRegistration: row.passkeyAllowRegistration },
  google: { enabled: row.googleEnabled },
  apple: { enabled: row.appleEnabled },
  facebook: { enabled: row.facebookEnabled },
  wechat: { enabled: row.wechatEnabled }
});
```

- [ ] **Step 3: Add `D1ClientAuthMethodPolicyRepository` class**

Add before `createRuntimeRepositories` (after the `KvRegistrationAccessTokenRepository` class):

```typescript
class D1ClientAuthMethodPolicyRepository implements ClientAuthMethodPolicyRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(policy: ClientAuthMethodPolicy): Promise<void> {
    const now = new Date().toISOString();
    await this.db.insert(clientAuthMethodPolicies).values({
      clientId: policy.clientId,
      tenantId: policy.tenantId,
      passwordEnabled: policy.password.enabled,
      passwordAllowRegistration: policy.password.allowRegistration,
      magicLinkEnabled: policy.emailMagicLink.enabled,
      magicLinkAllowRegistration: policy.emailMagicLink.allowRegistration,
      passkeyEnabled: policy.passkey.enabled,
      passkeyAllowRegistration: policy.passkey.allowRegistration,
      googleEnabled: policy.google.enabled,
      appleEnabled: policy.apple.enabled,
      facebookEnabled: policy.facebook.enabled,
      wechatEnabled: policy.wechat.enabled,
      createdAt: now,
      updatedAt: now
    });
  }

  async findByClientId(clientId: string): Promise<ClientAuthMethodPolicy | null> {
    const [row] = await this.db
      .select()
      .from(clientAuthMethodPolicies)
      .where(eq(clientAuthMethodPolicies.clientId, clientId))
      .limit(1);
    return row === undefined ? null : toClientAuthMethodPolicy(row);
  }

  async update(policy: ClientAuthMethodPolicy): Promise<void> {
    const now = new Date().toISOString();
    await this.db
      .update(clientAuthMethodPolicies)
      .set({
        passwordEnabled: policy.password.enabled,
        passwordAllowRegistration: policy.password.allowRegistration,
        magicLinkEnabled: policy.emailMagicLink.enabled,
        magicLinkAllowRegistration: policy.emailMagicLink.allowRegistration,
        passkeyEnabled: policy.passkey.enabled,
        passkeyAllowRegistration: policy.passkey.allowRegistration,
        googleEnabled: policy.google.enabled,
        appleEnabled: policy.apple.enabled,
        facebookEnabled: policy.facebook.enabled,
        wechatEnabled: policy.wechat.enabled,
        updatedAt: now
      })
      .where(eq(clientAuthMethodPolicies.clientId, policy.clientId));
  }
}
```

- [ ] **Step 4: Wire into `createRuntimeRepositories`**

In `createRuntimeRepositories`, add `clientAuthMethodPolicies` to the drizzle schema object:

```typescript
const db = drizzle(config.db, {
  schema: {
    adminUsers,
    auditEvents,
    authorizationCodes,
    clientAuthMethodPolicies,  // add this
    emailLoginTokens,
    // ... rest unchanged
  }
});
```

And add to the returned object:

```typescript
return {
  // ... existing entries ...
  clientAuthMethodPolicyRepository: new D1ClientAuthMethodPolicyRepository(db),
  // ...
};
```

- [ ] **Step 5: Commit**

```bash
git add src/adapters/db/drizzle/runtime.ts
git commit -m "feat: add D1ClientAuthMethodPolicyRepository"
```

---

## Task 5: Wire `app.ts` — Empty Fallback + Options

**Files:**
- Modify: `src/app/app.ts`

- [ ] **Step 1: Add import**

Add near the top of `app.ts` with the other client imports:

```typescript
import type { ClientAuthMethodPolicyRepository } from "../domain/clients/repository";
import type { ClientAuthMethodPolicy } from "../domain/clients/types";
```

- [ ] **Step 2: Add `EmptyClientAuthMethodPolicyRepository` class**

Add after `EmptyClientRepository` (around line 97):

```typescript
class EmptyClientAuthMethodPolicyRepository implements ClientAuthMethodPolicyRepository {
  async create(): Promise<void> { return; }
  async findByClientId(): Promise<null> { return null; }
  async update(): Promise<void> { return; }
}
```

- [ ] **Step 3: Add to `AppOptions` interface**

In the `AppOptions` interface (around line 241), add:

```typescript
clientAuthMethodPolicyRepository?: ClientAuthMethodPolicyRepository;
```

- [ ] **Step 4: Wire in `createApp`**

In the `createApp` function body (around line 278), add:

```typescript
const clientAuthMethodPolicyRepository =
  options.clientAuthMethodPolicyRepository ?? new EmptyClientAuthMethodPolicyRepository();
```

- [ ] **Step 5: Commit**

```bash
git add src/app/app.ts
git commit -m "feat: wire ClientAuthMethodPolicyRepository into app.ts options"
```

---

## Task 6: Update `handleChallengeInfo` — Switch to Client Policy

**Files:**
- Modify: `src/app/app.ts`

This task changes `handleChallengeInfo` to look up the client's policy instead of the tenant's policy.

- [ ] **Step 1: Rewrite `handleChallengeInfo`**

Find `handleChallengeInfo` (around line 553). Replace the policy lookup section:

**Before** (lines ~573-583):
```typescript
const policy = await userRepository.findAuthMethodPolicyByTenantId(issuerContext.tenant.id);
const methods: string[] = [];

if (policy === null || policy.password.enabled) methods.push("password");
if (policy === null || policy.emailMagicLink.enabled) methods.push("magic_link");
if (policy === null || policy.passkey.enabled) methods.push("passkey");

return context.json({
  tenant_display_name: issuerContext.tenant.displayName,
  methods
});
```

**After:**
```typescript
// Look up client policy using the oidcClients.id (UUID) from the challenge's clientId (OAuth string)
const client = await clientRepository.findByClientId(challenge.clientId);
const policy = client !== null
  ? await clientAuthMethodPolicyRepository.findByClientId(client.id)
  : null;

const methods: { method: string; allow_registration: boolean }[] = [];

if (policy !== null) {
  if (policy.password.enabled) {
    methods.push({ method: "password", allow_registration: policy.password.allowRegistration });
  }
  if (policy.emailMagicLink.enabled) {
    methods.push({ method: "magic_link", allow_registration: policy.emailMagicLink.allowRegistration });
  }
  if (policy.passkey.enabled) {
    methods.push({ method: "passkey", allow_registration: policy.passkey.allowRegistration });
  }
}
// If policy is null (no row), return empty methods array (fail-safe: deny all)

return context.json({
  tenant_display_name: issuerContext.tenant.displayName,
  methods
});
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd /Users/y/IdeaProjects/ma_hono
pnpm tsc --noEmit
```

Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/app/app.ts
git commit -m "feat: update handleChallengeInfo to use client-level auth method policy"
```

---

## Task 7: Update Admin Client List Endpoint

**Files:**
- Modify: `src/app/app.ts`

The `GET /admin/tenants/:tenantId/clients` response must include `auth_method_policy` per client.

- [ ] **Step 1: Add a helper to serialize policy to wire format**

Add a helper function inside `createApp` (near the other helpers):

```typescript
const policyToWire = (policy: ClientAuthMethodPolicy | undefined) =>
  policy === undefined ? null : {
    password: { enabled: policy.password.enabled, allow_registration: policy.password.allowRegistration },
    magic_link: { enabled: policy.emailMagicLink.enabled, allow_registration: policy.emailMagicLink.allowRegistration },
    passkey: { enabled: policy.passkey.enabled, allow_registration: policy.passkey.allowRegistration },
    google: { enabled: policy.google.enabled },
    apple: { enabled: policy.apple.enabled },
    facebook: { enabled: policy.facebook.enabled },
    wechat: { enabled: policy.wechat.enabled }
  };
```

- [ ] **Step 2: Update `GET /admin/tenants/:tenantId/clients`**

Find the list handler (line ~1895). After fetching clients, also fetch their policies:

```typescript
const clients = await clientRepository.listByTenantId(tenantId);

// Fetch policies for all clients in parallel
const policies = await Promise.all(
  clients.map((c) => clientAuthMethodPolicyRepository.findByClientId(c.id))
);

return context.json({
  clients: clients.map((c, i) => ({
    id: c.id,
    client_id: c.clientId,
    client_name: c.clientName,
    application_type: c.applicationType,
    redirect_uris: c.redirectUris,
    grant_types: c.grantTypes,
    response_types: c.responseTypes,
    token_endpoint_auth_method: c.tokenEndpointAuthMethod,
    trust_level: c.trustLevel,
    consent_policy: c.consentPolicy,
    auth_method_policy: policyToWire(policies[i] ?? undefined)
  }))
});
```

- [ ] **Step 3: Commit**

```bash
git add src/app/app.ts
git commit -m "feat: include auth_method_policy in admin client list response"
```

---

## Task 8: Add `GET /admin/tenants/:tenantId/clients/:clientId`

**Files:**
- Modify: `src/app/app.ts`

- [ ] **Step 1: Add the new endpoint**

After the `GET /admin/tenants/:tenantId/clients` handler (around line 1923), add:

```typescript
app.get("/admin/tenants/:tenantId/clients/:clientId", async (context) => {
  const session = await authenticateAdminSession({
    adminRepository,
    authorizationHeader: context.req.header("authorization")
  });
  if (session === null) {
    return context.json({ error: "unauthorized" }, 401);
  }
  const tenantId = context.req.param("tenantId");
  const clientId = context.req.param("clientId");
  const tenant = await tenantRepository.findById(tenantId);
  if (tenant === null) return context.notFound();

  const client = await clientRepository.findByClientId(clientId);
  if (client === null || client.tenantId !== tenantId) return context.notFound();

  let policy = await clientAuthMethodPolicyRepository.findByClientId(client.id);
  if (policy === null) {
    // Synthesize and persist default all-disabled policy on first access (handles pre-migration clients)
    policy = {
      clientId: client.id,
      tenantId: client.tenantId,
      password: { enabled: false, allowRegistration: false },
      emailMagicLink: { enabled: false, allowRegistration: false },
      passkey: { enabled: false, allowRegistration: false },
      google: { enabled: false },
      apple: { enabled: false },
      facebook: { enabled: false },
      wechat: { enabled: false }
    };
    await clientAuthMethodPolicyRepository.create(policy);
  }

  return context.json({
    id: client.id,
    client_id: client.clientId,
    client_name: client.clientName,
    application_type: client.applicationType,
    redirect_uris: client.redirectUris,
    grant_types: client.grantTypes,
    response_types: client.responseTypes,
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    trust_level: client.trustLevel,
    consent_policy: client.consentPolicy,
    auth_method_policy: policyToWire(policy)
  });
});
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
pnpm tsc --noEmit
```

Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/app/app.ts
git commit -m "feat: add GET /admin/tenants/:tenantId/clients/:clientId endpoint"
```

---

## Task 9: Add `PATCH /admin/tenants/:tenantId/clients/:clientId/auth-method-policy`

**Files:**
- Modify: `src/app/app.ts`

- [ ] **Step 1: Add the PATCH endpoint**

After the `GET .../clients/:clientId` handler, add:

```typescript
app.patch("/admin/tenants/:tenantId/clients/:clientId/auth-method-policy", async (context) => {
  const session = await authenticateAdminSession({
    adminRepository,
    authorizationHeader: context.req.header("authorization")
  });
  if (session === null) {
    return context.json({ error: "unauthorized" }, 401);
  }
  const tenantId = context.req.param("tenantId");
  const clientId = context.req.param("clientId");
  const tenant = await tenantRepository.findById(tenantId);
  if (tenant === null) return context.notFound();

  const client = await clientRepository.findByClientId(clientId);
  if (client === null || client.tenantId !== tenantId) return context.notFound();

  const existing = await clientAuthMethodPolicyRepository.findByClientId(client.id);
  if (existing === null) {
    return context.json({ error: "policy_not_found" }, 404);
  }

  let body: Record<string, unknown>;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "invalid_request" }, 400);
  }

  // Partial merge — only override fields that are present in the body
  const pw = typeof body.password === "object" && body.password !== null
    ? body.password as Record<string, unknown> : {};
  const ml = typeof body.magic_link === "object" && body.magic_link !== null
    ? body.magic_link as Record<string, unknown> : {};
  const pk = typeof body.passkey === "object" && body.passkey !== null
    ? body.passkey as Record<string, unknown> : {};
  const go = typeof body.google === "object" && body.google !== null
    ? body.google as Record<string, unknown> : {};
  const ap = typeof body.apple === "object" && body.apple !== null
    ? body.apple as Record<string, unknown> : {};
  const fb = typeof body.facebook === "object" && body.facebook !== null
    ? body.facebook as Record<string, unknown> : {};
  const wc = typeof body.wechat === "object" && body.wechat !== null
    ? body.wechat as Record<string, unknown> : {};

  const merged: ClientAuthMethodPolicy = {
    clientId: existing.clientId,
    tenantId: existing.tenantId,
    password: {
      enabled: typeof pw.enabled === "boolean" ? pw.enabled : existing.password.enabled,
      allowRegistration: typeof pw.allow_registration === "boolean"
        ? pw.allow_registration : existing.password.allowRegistration
    },
    emailMagicLink: {
      enabled: typeof ml.enabled === "boolean" ? ml.enabled : existing.emailMagicLink.enabled,
      allowRegistration: typeof ml.allow_registration === "boolean"
        ? ml.allow_registration : existing.emailMagicLink.allowRegistration
    },
    passkey: {
      enabled: typeof pk.enabled === "boolean" ? pk.enabled : existing.passkey.enabled,
      allowRegistration: typeof pk.allow_registration === "boolean"
        ? pk.allow_registration : existing.passkey.allowRegistration
    },
    google: { enabled: typeof go.enabled === "boolean" ? go.enabled : existing.google.enabled },
    apple: { enabled: typeof ap.enabled === "boolean" ? ap.enabled : existing.apple.enabled },
    facebook: { enabled: typeof fb.enabled === "boolean" ? fb.enabled : existing.facebook.enabled },
    wechat: { enabled: typeof wc.enabled === "boolean" ? wc.enabled : existing.wechat.enabled }
  };

  await clientAuthMethodPolicyRepository.update(merged);

  await auditRepository.record({
    id: crypto.randomUUID(),
    actorType: "admin_user",
    actorId: session.adminUserId,
    tenantId,
    eventType: "oidc.client.auth_method_policy.updated",
    targetType: "oidc_client",
    targetId: client.clientId,
    payload: policyToWire(merged),
    occurredAt: new Date().toISOString()
  });

  return context.json({ auth_method_policy: policyToWire(merged) });
});
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
pnpm tsc --noEmit
```

- [ ] **Step 3: Commit**

```bash
git add src/app/app.ts
git commit -m "feat: add PATCH auth-method-policy admin endpoint"
```

---

## Task 10: Update `POST /admin/tenants/:tenantId/clients` — Create Default Policy

**Files:**
- Modify: `src/app/app.ts`

- [ ] **Step 1: Update client creation handler to also create default policy**

Find the `POST /admin/tenants/:tenantId/clients` handler (around line 1925). After the `registerClient` call succeeds and the `registrationAccessToken` is stored, add default policy creation.

The cleanup pattern follows the existing rollback: if policy creation fails after client is created, delete client and registration token then throw.

Replace the inner try/catch block:

```typescript
try {
  const result = await registerClient({ clientRepository, input: payload, issuerContext });
  const tokenHash = await sha256Base64Url(result.registrationAccessToken);
  try {
    await registrationAccessTokenRepository.store({
      clientId: result.client.clientId,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      issuer: issuerContext.issuer,
      tenantId,
      tokenHash
    });
    // Create default all-disabled auth method policy
    await clientAuthMethodPolicyRepository.create({
      clientId: result.client.id,
      tenantId: result.client.tenantId,
      password: { enabled: false, allowRegistration: false },
      emailMagicLink: { enabled: false, allowRegistration: false },
      passkey: { enabled: false, allowRegistration: false },
      google: { enabled: false },
      apple: { enabled: false },
      facebook: { enabled: false },
      wechat: { enabled: false }
    });
    await auditRepository.record({
      id: crypto.randomUUID(),
      actorType: "admin_user",
      actorId: session.adminUserId,
      tenantId,
      eventType: "oidc.client.registered",
      targetType: "oidc_client",
      targetId: result.client.clientId,
      payload: {
        application_type: result.client.applicationType,
        client_name: result.client.clientName
      },
      occurredAt: new Date().toISOString()
    });
  } catch (error) {
    await Promise.allSettled([
      clientRepository.deleteByClientId(result.client.clientId),
      registrationAccessTokenRepository.deleteByTokenHash(tokenHash)
    ]);
    throw error;
  }
  // ... return response unchanged
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
pnpm tsc --noEmit
```

- [ ] **Step 3: Commit**

```bash
git add src/app/app.ts
git commit -m "feat: create default client auth method policy on client registration"
```

---

## Task 11: Add `POST /t/:tenant/register` Self-Registration Endpoint

**Files:**
- Modify: `src/app/app.ts`

- [ ] **Step 1: Add the registration endpoint**

Add after the `GET /admin/tenants/:tenantId/clients` area, but before the `app.post("/activate-account", ...)` handler. This endpoint uses the same `/t/:tenant/*` path pattern.

```typescript
app.post("/t/:tenant/register", async (context) => {
  const issuerContext = await resolveIssuerContextBySlug({
    slug: context.req.param("tenant"),
    oidcHost,
    tenantRepository
  });
  if (issuerContext === null) {
    return context.notFound();
  }

  let payload: { login_challenge?: string; email?: string; username?: string; password?: string };
  try {
    payload = await context.req.json();
  } catch {
    return context.json({ error: "invalid_request" }, 400);
  }

  const loginChallengeToken = (payload.login_challenge ?? "").trim();
  if (!loginChallengeToken) {
    return context.json({ error: "invalid_request" }, 400);
  }

  const { sha256Base64Url: hashFn } = await import("../lib/hash");
  const tokenHash = await hashFn(loginChallengeToken);
  const challenge = await loginChallengeLookupRepository.findByTokenHash(tokenHash);

  if (challenge === null || challenge.consumedAt !== null) {
    return context.json({ error: "invalid_login_challenge" }, 400);
  }
  if (challenge.tenantId !== issuerContext.tenant.id) {
    return context.json({ error: "invalid_login_challenge" }, 400);
  }

  // Look up client policy — registration must be allowed
  const client = await clientRepository.findByClientId(challenge.clientId);
  const policy = client !== null
    ? await clientAuthMethodPolicyRepository.findByClientId(client.id)
    : null;

  if (policy === null || !policy.password.allowRegistration) {
    return context.json({ error: "registration_not_allowed" }, 403);
  }

  // Validate input
  const email = (payload.email ?? "").trim().toLowerCase();
  const username = (payload.username ?? "").trim() || null;
  const password = payload.password ?? "";

  if (!email.includes("@") || password.length < 8) {
    return context.json({ error: "invalid_request" }, 400);
  }

  // Check for duplicate email
  const existing = await userRepository.findUserByEmail(issuerContext.tenant.id, email);
  if (existing !== null) {
    return context.json({ error: "email_already_exists" }, 409);
  }

  const now = new Date().toISOString();
  const newUser = {
    id: crypto.randomUUID(),
    tenantId: issuerContext.tenant.id,
    email,
    emailVerified: false,
    username,
    displayName: username ?? email.split("@")[0],
    status: "active" as const,
    createdAt: now,
    updatedAt: now
  };

  const { hashPassword } = await import("../domain/users/passwords");
  const passwordHash = await hashPassword(password);

  const credential = {
    id: crypto.randomUUID(),
    tenantId: issuerContext.tenant.id,
    userId: newUser.id,
    passwordHash,
    createdAt: now,
    updatedAt: now
  };

  await userRepository.createProvisionedUserWithInvitation({
    user: newUser,
    invitation: {
      id: crypto.randomUUID(),
      tenantId: issuerContext.tenant.id,
      userId: newUser.id,
      tokenHash: crypto.randomUUID(), // placeholder — not used for self-reg
      purpose: "account_activation",
      expiresAt: new Date(Date.now() + 1000).toISOString(), // already expired — never usable
      consumedAt: now, // mark consumed immediately
      createdAt: now
    }
  });
  await userRepository.upsertPasswordCredential(credential);

  const { session, sessionToken } = await createBrowserSession({
    sessionRepository: browserSessionRepository,
    tenantId: newUser.tenantId,
    userId: newUser.id
  });

  await recordAuditEventBestEffort({
    actorType: "end_user",
    actorId: newUser.id,
    tenantId: issuerContext.tenant.id,
    eventType: "user.self_registration.succeeded",
    targetType: "user",
    targetId: newUser.id,
    payload: { client_id: challenge.clientId }
  });

  context.header(
    "Set-Cookie",
    buildBrowserSessionCookie({
      expiresAt: session.expiresAt,
      secure: new URL(issuerContext.issuer).protocol === "https:",
      sessionToken
    })
  );

  const authorizationResult = await authorizeRequest({
    authorizationCodeRepository,
    clientRepository,
    issuerContext,
    loginChallengeRepository,
    request: {
      clientId: challenge.clientId,
      redirectUri: challenge.redirectUri,
      responseType: "code",
      scope: challenge.scope,
      state: challenge.state.length === 0 ? null : challenge.state,
      nonce: challenge.nonce,
      codeChallenge: challenge.codeChallenge,
      codeChallengeMethod: challenge.codeChallengeMethod
    },
    session: { userId: newUser.id, tenantId: newUser.tenantId }
  });

  if (authorizationResult.kind !== "authorization_granted") {
    return context.json({ error: "authorization_failed" }, 500);
  }

  const redirectUrl = new URL(authorizationResult.request.redirectUri);
  redirectUrl.searchParams.set("code", authorizationResult.code);
  if (authorizationResult.request.state !== null) {
    redirectUrl.searchParams.set("state", authorizationResult.request.state);
  }
  return context.redirect(redirectUrl.toString(), 302);
});
```

**Note on user creation:** `createProvisionedUserWithInvitation` is used because it is the existing method that creates both a user row and an invitation row in one batch. We create an invitation with `consumedAt` set to `now` — this means the invitation is immediately consumed and can never be used for account activation. The user is created with `status: "active"` so no activation step is needed.

- [ ] **Step 2: Add `hashPassword` import check**

Verify `hashPassword` exists in `src/domain/users/passwords.ts`:

```bash
grep -n "hashPassword\|export" src/domain/users/passwords.ts
```

If the function is named differently, adjust the import accordingly.

- [ ] **Step 3: Verify TypeScript compiles**

```bash
pnpm tsc --noEmit
```

- [ ] **Step 4: Commit**

```bash
git add src/app/app.ts
git commit -m "feat: add POST /t/:tenant/register self-registration endpoint"
```

---

## Task 12: Admin API Client — Update Types and Add Functions

**Files:**
- Modify: `admin/src/api/client.ts`

- [ ] **Step 1: Update `ChallengeInfo` type**

Find (around line 178):
```typescript
export interface ChallengeInfo {
  tenant_display_name: string;
  methods: ("password" | "magic_link" | "passkey")[];
}
```

Replace with:
```typescript
export interface ChallengeInfo {
  tenant_display_name: string;
  methods: { method: string; allow_registration: boolean }[];
}
```

- [ ] **Step 2: Update `ClientSummary` to include policy**

Find `ClientSummary` (around line 134). Add:
```typescript
export interface AuthMethodPolicyWire {
  password: { enabled: boolean; allow_registration: boolean };
  magic_link: { enabled: boolean; allow_registration: boolean };
  passkey: { enabled: boolean; allow_registration: boolean };
  google: { enabled: boolean };
  apple: { enabled: boolean };
  facebook: { enabled: boolean };
  wechat: { enabled: boolean };
}

export interface ClientSummary {
  id: string;
  client_id: string;
  client_name: string;
  application_type: "web" | "native";
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  trust_level: string;
  consent_policy: string;
  auth_method_policy: AuthMethodPolicyWire | null;
}
```

- [ ] **Step 3: Add `getClient` function**

After `listClients`, add:

```typescript
export const getClient = async (token: string, tenantId: string, clientId: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/clients/${clientId}`, {
      headers: authHeaders(token)
    })
  );
  return res.json() as Promise<ClientSummary>;
};
```

- [ ] **Step 4: Add `updateClientAuthMethodPolicy` function**

```typescript
export const updateClientAuthMethodPolicy = async (
  token: string,
  tenantId: string,
  clientId: string,
  policy: Partial<AuthMethodPolicyWire>
) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/clients/${clientId}/auth-method-policy`, {
      method: "PATCH",
      headers: authHeaders(token),
      body: JSON.stringify(policy)
    })
  );
  return res.json() as Promise<{ auth_method_policy: AuthMethodPolicyWire }>;
};
```

- [ ] **Step 5: Add `registerUser` function**

```typescript
export const registerUser = async (
  tenantSlug: string,
  payload: {
    login_challenge: string;
    email: string;
    username?: string;
    password: string;
  }
): Promise<Response> => {
  return fetch(`${BASE_URL}/t/${tenantSlug}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    redirect: "manual"
  });
};
```

- [ ] **Step 6: Commit**

```bash
git add admin/src/api/client.ts
git commit -m "feat: update admin API client types and add policy/registration functions"
```

---

## Task 13: Admin UI — `TenantClientsPage.tsx` Auth Policy Modal

**Files:**
- Modify: `admin/src/pages/TenantClientsPage.tsx`

- [ ] **Step 1: Add import for new API functions**

At the top of the file, update the import from `../api/client`:

```typescript
import {
  getTenant,
  listClients,
  createClient,
  getClient,
  updateClientAuthMethodPolicy,
  type TenantSummary,
  type ClientSummary,
  type AuthMethodPolicyWire
} from "../api/client";
```

- [ ] **Step 2: Add `AuthMethodPolicyModal` component**

Add this component before the `TenantClientsPage` export. It fetches the policy on open, shows a toggle grid, and PATCHes on save:

```tsx
function AuthMethodPolicyModal({
  token,
  tenantId,
  client,
  onClose
}: {
  token: string;
  tenantId: string;
  client: ClientSummary;
  onClose: () => void;
}) {
  const [policy, setPolicy] = useState<AuthMethodPolicyWire | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    getClient(token, tenantId, client.client_id).then((c) => {
      setPolicy(c.auth_method_policy ?? defaultPolicy());
    }).catch(() => setError("FAILED TO LOAD POLICY")).finally(() => setLoading(false));
  }, []);

  const defaultPolicy = (): AuthMethodPolicyWire => ({
    password: { enabled: false, allow_registration: false },
    magic_link: { enabled: false, allow_registration: false },
    passkey: { enabled: false, allow_registration: false },
    google: { enabled: false },
    apple: { enabled: false },
    facebook: { enabled: false },
    wechat: { enabled: false }
  });

  const handleSave = async () => {
    if (!policy) return;
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      await updateClientAuthMethodPolicy(token, tenantId, client.client_id, policy);
      setSaved(true);
    } catch {
      setError("FAILED TO SAVE");
    } finally {
      setSaving(false);
    }
  };

  const toggleStyle = (active: boolean): React.CSSProperties => ({
    display: 'inline-block',
    width: '36px',
    height: '18px',
    background: active ? 'var(--accent-cyan)' : 'var(--bg-elevated)',
    border: `1px solid ${active ? 'var(--accent-cyan)' : 'var(--border)'}`,
    cursor: 'pointer',
    position: 'relative',
    transition: 'all 0.15s',
    verticalAlign: 'middle'
  });

  const knobStyle = (active: boolean): React.CSSProperties => ({
    position: 'absolute',
    top: '2px',
    left: active ? '18px' : '2px',
    width: '12px',
    height: '12px',
    background: active ? 'var(--bg-base)' : 'var(--text-muted)',
    transition: 'left 0.15s'
  });

  const Toggle = ({ active, onChange }: { active: boolean; onChange: (v: boolean) => void }) => (
    <button
      type="button"
      onClick={() => onChange(!active)}
      style={toggleStyle(active)}
      aria-label={active ? "enabled" : "disabled"}
    >
      <div style={knobStyle(active)} />
    </button>
  );

  if (loading) {
    return (
      <Modal title={`AUTH METHOD POLICY — ${client.client_name}`} onClose={onClose}>
        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: "'Space Mono', monospace", fontSize: '11px' }}>LOADING...</div>
      </Modal>
    );
  }

  const methods: { key: keyof AuthMethodPolicyWire; label: string; hasReg: boolean }[] = [
    { key: 'password', label: 'Password', hasReg: true },
    { key: 'magic_link', label: 'Magic Link', hasReg: true },
    { key: 'passkey', label: 'Passkey', hasReg: true },
    { key: 'google', label: 'Google', hasReg: false },
    { key: 'apple', label: 'Apple', hasReg: false },
    { key: 'facebook', label: 'Facebook', hasReg: false },
    { key: 'wechat', label: 'WeChat', hasReg: false }
  ];

  return (
    <Modal title={`AUTH METHOD POLICY — ${client.client_name}`} onClose={onClose}>
      {error && (
        <div style={{ padding: '8px 12px', marginBottom: '16px', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)' }}>
          <span className="font-display" style={{ fontSize: '10px', color: '#ef4444', letterSpacing: '0.08em' }}>✕ {error}</span>
        </div>
      )}
      {saved && (
        <div style={{ padding: '8px 12px', marginBottom: '16px', background: 'rgba(0,229,128,0.05)', border: '1px solid rgba(0,229,128,0.2)' }}>
          <span className="font-display" style={{ fontSize: '10px', color: 'var(--accent-green)', letterSpacing: '0.08em' }}>✓ SAVED</span>
        </div>
      )}
      <div style={{ marginBottom: '20px' }}>
        {/* Table header */}
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1.5fr', padding: '6px 0', borderBottom: '1px solid var(--border)', marginBottom: '8px' }}>
          {['METHOD', 'ENABLED', 'ALLOW REG.'].map(h => (
            <span key={h} className="font-display" style={{ fontSize: '9px', letterSpacing: '0.15em', color: 'var(--text-dim)' }}>{h}</span>
          ))}
        </div>
        {policy && methods.map(({ key, label, hasReg }, i) => {
          const val = policy[key] as { enabled: boolean; allow_registration?: boolean };
          return (
            <div key={key}>
              {i === 3 && <div style={{ borderTop: '1px solid var(--border)', margin: '8px 0' }} />}
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1.5fr', padding: '6px 0', alignItems: 'center' }}>
                <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{label}</span>
                <Toggle
                  active={val.enabled}
                  onChange={(v) => setPolicy({ ...policy, [key]: { ...val, enabled: v } })}
                />
                {hasReg ? (
                  <Toggle
                    active={val.allow_registration ?? false}
                    onChange={(v) => setPolicy({ ...policy, [key]: { ...val, allow_registration: v } })}
                  />
                ) : (
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: "'Space Mono', monospace" }}>—</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
      <button
        type="button"
        onClick={handleSave}
        disabled={saving}
        style={{ width: '100%', background: 'transparent', border: '1px solid var(--accent-cyan)', color: saving ? 'var(--text-muted)' : 'var(--accent-cyan)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', cursor: saving ? 'not-allowed' : 'pointer' }}
      >
        {saving ? 'SAVING...' : 'SAVE'}
      </button>
    </Modal>
  );
}
```

- [ ] **Step 3: Add state and button in `TenantClientsPage`**

Add state variable at the top of `TenantClientsPage`:
```typescript
const [policyClient, setPolicyClient] = useState<ClientSummary | null>(null);
```

In the table row actions `<div>`, add the AUTH POLICY button next to the TEST button:
```tsx
<button
  onClick={() => setPolicyClient(c)}
  style={{ ...btnStyle('var(--accent-amber, #fbbf24)'), padding: '5px 10px' }}
  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(251,191,36,0.08)'; }}
  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
>
  AUTH
</button>
```

Also update the grid template for the table header and rows to accommodate the extra button — change `160px` to `220px` in both the header div and each row div.

- [ ] **Step 4: Render the modal**

At the bottom of the returned JSX, after the `createdSecret` modal, add:
```tsx
{policyClient && (
  <AuthMethodPolicyModal
    token={token!}
    tenantId={tenantId!}
    client={policyClient}
    onClose={() => setPolicyClient(null)}
  />
)}
```

- [ ] **Step 5: Commit**

```bash
git add admin/src/pages/TenantClientsPage.tsx
git commit -m "feat: add AUTH POLICY modal to admin client list page"
```

---

## Task 14: Login Page — `TenantLoginPage.tsx` Registration Flow

**Files:**
- Modify: `admin/src/pages/TenantLoginPage.tsx`

- [ ] **Step 1: Update `ChallengeInfo` usage and `activeMethod` init**

In `TenantLoginPage`, the `info.methods` is now `{ method: string; allow_registration: boolean }[]`. Update the usage:

Line ~383 (init of `activeMethod`):
```typescript
if (data.methods.length > 0) setActiveMethod(data.methods[0].method);
```

Line ~447 (tabs loop):
```tsx
{info.methods.map(({ method }) => (
  <button
    key={method}
    type="button"
    onClick={() => setActiveMethod(method)}
    style={tabButtonStyle(activeMethod === method)}
  >
    {METHOD_LABELS[method] ?? method}
  </button>
))}
```

Line ~467 (active method content):
```tsx
{info.methods.length === 0 ? (
  <p>No login methods available...</p>
) : activeMethod === "password" ? (
  <PasswordForm
    tenantSlug={tenantSlug!}
    loginChallenge={loginChallenge}
    allowRegistration={
      info.methods.find((m) => m.method === "password")?.allow_registration ?? false
    }
  />
) : activeMethod === "magic_link" ? (
  <MagicLinkForm tenantSlug={tenantSlug!} loginChallenge={loginChallenge} />
) : activeMethod === "passkey" ? (
  <PasskeyForm tenantSlug={tenantSlug!} loginChallenge={loginChallenge} />
) : null}
```

- [ ] **Step 2: Add `registerUser` import**

Update the import from `../api/client` to include `registerUser`.

- [ ] **Step 3: Add `RegisterForm` component**

Add before `PasswordForm`:

```tsx
function RegisterForm({
  tenantSlug,
  loginChallenge,
  onBackToSignIn
}: {
  tenantSlug: string;
  loginChallenge: string;
  onBackToSignIn: () => void;
}) {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    setLoading(true);
    try {
      const res = await registerUser(tenantSlug, {
        login_challenge: loginChallenge,
        email,
        ...(username.trim() ? { username: username.trim() } : {}),
        password
      });
      if (res.status === 302 || res.type === "opaqueredirect") {
        const location = res.headers.get("location");
        if (location) { window.location.href = location; return; }
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        if (body.error === "email_already_exists") {
          setError("An account with this email already exists. Please sign in.");
        } else {
          setError(body.error ?? "Registration failed");
        }
        return;
      }
    } catch {
      setError("Network error — please try again");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 12px", border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.05)" }}>
          <span className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em" }}>✕ {error}</span>
        </div>
      )}
      <div style={{ marginBottom: "14px" }}>
        <label className="font-display" style={labelStyle}>Email</label>
        <input type="email" value={email} onChange={e => setEmail(e.target.value)} required autoComplete="email"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <div style={{ marginBottom: "14px" }}>
        <label className="font-display" style={labelStyle}>Username (optional)</label>
        <input type="text" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <div style={{ marginBottom: "14px" }}>
        <label className="font-display" style={labelStyle}>Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} required autoComplete="new-password"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <div style={{ marginBottom: "20px" }}>
        <label className="font-display" style={labelStyle}>Confirm Password</label>
        <input type="password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} required autoComplete="new-password"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <button type="submit" disabled={loading} style={primaryButtonStyle(loading)}>
        {loading ? "Creating account..." : "Create Account"}
      </button>
      <div style={{ textAlign: "center", marginTop: "16px" }}>
        <button type="button" onClick={onBackToSignIn}
          style={{ background: "none", border: "none", color: "var(--text-muted)", fontSize: "12px", cursor: "pointer", textDecoration: "underline" }}>
          Back to sign in
        </button>
      </div>
    </form>
  );
}
```

- [ ] **Step 4: Update `PasswordForm` to accept `allowRegistration` and show Register link**

Change the `PasswordForm` signature:
```typescript
function PasswordForm({
  tenantSlug,
  loginChallenge,
  allowRegistration
}: {
  tenantSlug: string;
  loginChallenge: string;
  allowRegistration: boolean;
}) {
```

Add `showRegister` state:
```typescript
const [showRegister, setShowRegister] = useState(false);
```

At the top of the return:
```tsx
if (showRegister) {
  return (
    <RegisterForm
      tenantSlug={tenantSlug}
      loginChallenge={loginChallenge}
      onBackToSignIn={() => setShowRegister(false)}
    />
  );
}
```

After the Sign In button (at the bottom of the form, before closing `</form>`), add:
```tsx
{allowRegistration && (
  <div style={{ textAlign: "center", marginTop: "16px" }}>
    <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
      Don't have an account?{" "}
      <button type="button" onClick={() => setShowRegister(true)}
        style={{ background: "none", border: "none", color: "var(--accent-cyan)", fontSize: "12px", cursor: "pointer", textDecoration: "underline" }}>
        Register
      </button>
    </span>
  </div>
)}
```

- [ ] **Step 5: Commit**

```bash
git add admin/src/pages/TenantLoginPage.tsx
git commit -m "feat: add self-registration flow to login page password form"
```

---

## Task 15: Verify the Full Build

- [ ] **Step 1: Build backend TypeScript**

```bash
cd /Users/y/IdeaProjects/ma_hono
pnpm tsc --noEmit
```

Expected: No errors.

- [ ] **Step 2: Build admin SPA**

```bash
cd /Users/y/IdeaProjects/ma_hono/admin
pnpm tsc --noEmit
```

Expected: No errors.

- [ ] **Step 3: Run backend tests (if any)**

```bash
cd /Users/y/IdeaProjects/ma_hono
pnpm test
```

Expected: All existing tests pass.

- [ ] **Step 4: Build admin dist (smoke test)**

```bash
cd /Users/y/IdeaProjects/ma_hono/admin
pnpm build
```

Expected: Build succeeds with no errors.

- [ ] **Step 5: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: address build issues from full integration"
```

---

## Notes for Implementer

**`hashPassword` location:** Check `src/domain/users/passwords.ts` — the function may be named `hashPassword` or exported differently. The existing `password-auth-service.ts` shows how to use it; follow the same pattern.

**`createProvisionedUserWithInvitation` for self-reg:** This method was designed for admin-invited users and inserts both a user row and an invitation row in a single D1 batch. For self-registration, create a dummy invitation that is immediately consumed (setting `consumedAt: now`). This avoids adding a new repository method while keeping the D1 batch atomicity. If a cleaner separation is desired in future, a dedicated `createSelfRegisteredUser` method can be added.

**D1 batch atomicity:** Task 10 adds policy creation inside the existing try/catch cleanup block. D1's `db.batch([])` could make this truly atomic, but the cleanup pattern (delete-on-failure) is acceptable and consistent with the rest of the codebase. If D1 batch is available via `this.db.batch`, the Task 4 `D1ClientAuthMethodPolicyRepository` can be enhanced to support batch-compatible inserts — but this is optional for the initial implementation.

**Migration:** After deploying schema changes, existing clients will have no policy row. The `GET /admin/tenants/:tenantId/clients/:clientId` endpoint synthesizes and persists a default all-disabled policy on first access, so operators can configure them via the admin UI without any data migration script.
