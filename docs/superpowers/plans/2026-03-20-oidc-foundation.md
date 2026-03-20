# OIDC Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first runnable OIDC foundation slice: a portable Hono app with issuer resolution, discovery metadata, JWKS, controlled Dynamic Client Registration, and whitelist-only admin management APIs.

**Architecture:** Use a modular monolith with a single Hono app, domain modules for tenants/clients/keys/oidc/admin-auth, and adapter boundaries for persistence and runtime concerns. Start with portable repository interfaces and in-memory implementations for app-level tests, while also adding Drizzle PostgreSQL schema files so the persistence model is concretely defined and ready for replacement.

**Tech Stack:** TypeScript, Hono, Zod, jose, Drizzle ORM, PostgreSQL schema definitions, Vitest, pnpm, Wrangler.

---

### Task 1: Bootstrap Workspace And Tooling

**Files:**
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `tsconfig.json`
- Create: `vitest.config.ts`
- Create: `wrangler.jsonc`
- Create: `.editorconfig`
- Create: `.npmrc`
- Create: `src/index.ts`
- Create: `src/app/app.ts`
- Create: `tests/smoke/app-smoke.test.ts`

- [ ] **Step 1: Write the failing smoke test**

```ts
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/app/app";

describe("app smoke", () => {
  it("responds 404 for unknown routes", async () => {
    const app = createApp();
    const response = await app.request("http://localhost/unknown");
    expect(response.status).toBe(404);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/smoke/app-smoke.test.ts`
Expected: fail because project files and dependencies do not exist yet

- [ ] **Step 3: Create the minimal toolchain and app bootstrap**

Add package metadata, scripts, TypeScript config, Vitest config, Wrangler config, and a `createApp()` function returning a Hono app.

- [ ] **Step 4: Run the smoke test to verify it passes**

Run: `corepack pnpm vitest run tests/smoke/app-smoke.test.ts`
Expected: pass with one successful test

- [ ] **Step 5: Commit**

```bash
git add package.json pnpm-workspace.yaml tsconfig.json vitest.config.ts wrangler.jsonc .editorconfig .npmrc src/index.ts src/app/app.ts tests/smoke/app-smoke.test.ts
git commit -m "build: bootstrap hono oidc workspace"
```

### Task 2: Add Tenant And Issuer Resolution Domain

**Files:**
- Create: `src/domain/tenants/types.ts`
- Create: `src/domain/tenants/repository.ts`
- Create: `src/domain/tenants/issuer-resolution.ts`
- Create: `src/adapters/db/memory/memory-tenant-repository.ts`
- Modify: `src/app/app.ts`
- Test: `tests/tenants/issuer-resolution.test.ts`

- [ ] **Step 1: Write the failing issuer resolution tests**

Cover:
- platform path issuer resolution on `http://idp.example.test/t/acme`
- custom domain resolution on `http://login.acme.test`
- 404 resolution failure for unknown tenant/domain

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/tenants/issuer-resolution.test.ts`
Expected: fail because issuer resolution code does not exist

- [ ] **Step 3: Implement tenant types, repository contract, and resolver**

Implement a resolver that:
- checks custom-domain issuer by host first
- falls back to platform host + `/t/:tenant`
- returns a typed resolution result with `tenant`, `issuer`, and `issuerPathPrefix`

- [ ] **Step 4: Run tests to verify they pass**

Run: `corepack pnpm vitest run tests/tenants/issuer-resolution.test.ts`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/domain/tenants src/adapters/db/memory/memory-tenant-repository.ts src/app/app.ts tests/tenants/issuer-resolution.test.ts
git commit -m "feat: add tenant issuer resolution"
```

### Task 3: Implement Discovery Metadata Endpoint

**Files:**
- Create: `src/domain/oidc/discovery.ts`
- Create: `src/domain/oidc/issuer-context.ts`
- Modify: `src/app/app.ts`
- Test: `tests/oidc/discovery.test.ts`

- [ ] **Step 1: Write the failing discovery tests**

Cover:
- platform-path issuer metadata uses `issuer` and `jwks_uri` under `/t/:tenant`
- custom-domain issuer metadata uses the custom host
- unresolved issuer returns `404`

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/oidc/discovery.test.ts`
Expected: fail because discovery route and builder do not exist

- [ ] **Step 3: Implement the discovery builder and route**

Return conservative metadata containing:
- `issuer`
- `jwks_uri`
- `registration_endpoint`
- `subject_types_supported`
- `id_token_signing_alg_values_supported`

- [ ] **Step 4: Run tests to verify they pass**

Run: `corepack pnpm vitest run tests/oidc/discovery.test.ts`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/domain/oidc src/app/app.ts tests/oidc/discovery.test.ts
git commit -m "feat: add oidc discovery endpoint"
```

### Task 4: Implement Signing Keys And JWKS

**Files:**
- Create: `src/domain/keys/types.ts`
- Create: `src/domain/keys/repository.ts`
- Create: `src/domain/keys/jwks.ts`
- Create: `src/adapters/db/memory/memory-key-repository.ts`
- Create: `src/adapters/crypto/dev-key-material.ts`
- Modify: `src/app/app.ts`
- Test: `tests/oidc/jwks.test.ts`

- [ ] **Step 1: Write the failing JWKS tests**

Cover:
- platform-path issuer JWKS returns public keys only
- custom-domain issuer JWKS uses the same issuer context rules
- inactive keys are excluded

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/oidc/jwks.test.ts`
Expected: fail because key repository and JWKS route do not exist

- [ ] **Step 3: Implement key model, dev key generator, and JWKS builder**

Use `jose` to generate development key material and export only public JWK values from the endpoint.

- [ ] **Step 4: Run tests to verify they pass**

Run: `corepack pnpm vitest run tests/oidc/jwks.test.ts`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/domain/keys src/adapters/db/memory/memory-key-repository.ts src/adapters/crypto/dev-key-material.ts src/app/app.ts tests/oidc/jwks.test.ts
git commit -m "feat: add jwks endpoint"
```

### Task 5: Implement Controlled Dynamic Client Registration

**Files:**
- Create: `src/domain/clients/types.ts`
- Create: `src/domain/clients/repository.ts`
- Create: `src/domain/clients/registration-schema.ts`
- Create: `src/domain/clients/register-client.ts`
- Create: `src/adapters/db/memory/memory-client-repository.ts`
- Modify: `src/app/app.ts`
- Test: `tests/clients/dynamic-registration.test.ts`

- [ ] **Step 1: Write the failing registration tests**

Cover:
- successful registration with valid redirect URI and management credential
- rejection without a management credential
- rejection for invalid redirect URI
- custom-domain registration emits issuer-correct `registration_client_uri`

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/clients/dynamic-registration.test.ts`
Expected: fail because registration code does not exist

- [ ] **Step 3: Implement schema validation and registration flow**

Rules:
- require a bearer management token
- validate payload with Zod
- generate `client_id`
- generate secret when auth method requires it
- hash stored client secret
- emit a registration access token

- [ ] **Step 4: Run tests to verify they pass**

Run: `corepack pnpm vitest run tests/clients/dynamic-registration.test.ts`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/domain/clients src/adapters/db/memory/memory-client-repository.ts src/app/app.ts tests/clients/dynamic-registration.test.ts
git commit -m "feat: add dynamic client registration"
```

### Task 6: Add Admin Whitelist Auth And Admin APIs

**Files:**
- Create: `src/domain/admin-auth/types.ts`
- Create: `src/domain/admin-auth/repository.ts`
- Create: `src/domain/admin-auth/service.ts`
- Create: `src/adapters/db/memory/memory-admin-repository.ts`
- Create: `src/app/routes/admin.ts`
- Modify: `src/app/app.ts`
- Test: `tests/admin/admin-auth.test.ts`

- [ ] **Step 1: Write the failing admin tests**

Cover:
- whitelist user can create tenant after login
- non-whitelist user is rejected
- unauthenticated request returns `401`

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/admin/admin-auth.test.ts`
Expected: fail because admin auth and admin routes do not exist

- [ ] **Step 3: Implement minimal admin auth and tenant/client creation APIs**

Use signed or opaque session tokens stored hashed in the admin session repository. Keep the implementation minimal and isolated from future public-user auth.

- [ ] **Step 4: Run tests to verify they pass**

Run: `corepack pnpm vitest run tests/admin/admin-auth.test.ts`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/domain/admin-auth src/adapters/db/memory/memory-admin-repository.ts src/app/routes/admin.ts src/app/app.ts tests/admin/admin-auth.test.ts
git commit -m "feat: add admin auth and management apis"
```

### Task 7: Add Drizzle Schema And Runtime Wiring

**Files:**
- Create: `drizzle.config.ts`
- Create: `src/adapters/db/drizzle/schema.ts`
- Create: `src/config/env.ts`
- Modify: `package.json`
- Modify: `src/index.ts`
- Test: `tests/config/env.test.ts`

- [ ] **Step 1: Write the failing environment/schema tests**

Cover:
- environment loader requires platform host and admin whitelist config
- schema exports tenant, issuer, client, admin, and audit tables

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/config/env.test.ts`
Expected: fail because env loader and schema do not exist

- [ ] **Step 3: Implement env config and Drizzle schema**

Define PostgreSQL tables that match the approved design and wire minimal runtime bootstrapping from environment bindings.

- [ ] **Step 4: Run tests to verify they pass**

Run: `corepack pnpm vitest run tests/config/env.test.ts`
Expected: all tests pass

- [ ] **Step 5: Run the full suite**

Run: `corepack pnpm vitest run`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add drizzle.config.ts src/adapters/db/drizzle/schema.ts src/config/env.ts package.json src/index.ts tests/config/env.test.ts
git commit -m "feat: add drizzle schema and runtime wiring"
```
