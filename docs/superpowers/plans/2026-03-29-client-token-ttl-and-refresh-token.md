# Client Token TTL And Refresh Token Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-auth-method token TTL configuration in the admin client auth policy UI and implement rotating refresh tokens that can renew `id_token` and `access_token`.

**Architecture:** Extend the existing client auth policy structure with method-specific TTL fields, add a hashed refresh token persistence layer, and split `/token` handling by grant type while keeping current client authentication and authorization code validation rules intact.

**Tech Stack:** TypeScript, Hono, Drizzle ORM, Vitest, jose, Cloudflare Workers-compatible storage

---

### Task 1: Add failing tests for auth policy TTL fields

**Files:**
- Modify: `tests/admin/mfa-policy.test.ts`
- Modify: `tests/admin/admin-read-endpoints.test.ts`

- [ ] **Step 1: Add PATCH auth-method-policy assertions for `token_ttl_seconds`**
- [ ] **Step 2: Run targeted admin tests and verify they fail for missing TTL fields**
- [ ] **Step 3: Add GET client/list assertions that returned policy objects include TTL values**
- [ ] **Step 4: Re-run targeted admin tests and verify failure is due to missing implementation**

### Task 2: Add failing tests for refresh token grant and TTL-driven token expiry

**Files:**
- Modify: `tests/oidc/token-endpoint.test.ts`
- Modify: `tests/oidc/discovery.test.ts`

- [ ] **Step 1: Add token exchange test that expects `refresh_token` in `authorization_code` response**
- [ ] **Step 2: Add token exchange test that seeds a policy TTL and asserts `expires_in` plus JWT expiry reflect it**
- [ ] **Step 3: Add refresh token rotation test for `grant_type=refresh_token`**
- [ ] **Step 4: Add refresh token reuse rejection test**
- [ ] **Step 5: Add discovery metadata assertion for `refresh_token`**
- [ ] **Step 6: Run targeted OIDC tests and verify they fail for the new behavior**

### Task 3: Extend policy types, schema, and repositories

**Files:**
- Modify: `src/domain/clients/types.ts`
- Modify: `src/app/app.ts`
- Modify: `src/adapters/db/memory/memory-client-auth-method-policy-repository.ts`
- Modify: `src/adapters/db/drizzle/schema.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `drizzle/migrations/0005_spa_client_and_custom_claims.sql` only if unsuitable for new migration numbering reference
- Create: `drizzle/migrations/0006_client_token_ttl_and_refresh_tokens.sql`

- [ ] **Step 1: Add `tokenTtlSeconds` to each auth method domain type**
- [ ] **Step 2: Update default policy creation paths in `app.ts` to set `3600`**
- [ ] **Step 3: Extend wire mapping and PATCH merge logic for `token_ttl_seconds`**
- [ ] **Step 4: Add migration and Drizzle schema for policy TTL columns and `refresh_tokens` table**
- [ ] **Step 5: Add Drizzle repository implementation for refresh tokens**

### Task 4: Add refresh token domain and token service behavior

**Files:**
- Create: `src/domain/tokens/refresh-token-repository.ts`
- Modify: `src/domain/authorization/types.ts`
- Modify: `src/domain/tokens/claims.ts`
- Modify: `src/domain/tokens/token-service.ts`
- Modify: `src/domain/oidc/token-response.ts`

- [ ] **Step 1: Add auth-method tracking to authorization code records**
- [ ] **Step 2: Add helper to resolve TTL from auth method policy**
- [ ] **Step 3: Add refresh token repository interface and token family record type**
- [ ] **Step 4: Split token exchange into `authorization_code` and `refresh_token` flows**
- [ ] **Step 5: Issue refresh tokens on code exchange**
- [ ] **Step 6: Rotate refresh tokens and re-issue JWTs on refresh exchange**
- [ ] **Step 7: Keep success and error response shapes standards-compliant**

### Task 5: Wire new repositories through the app and memory adapters

**Files:**
- Modify: `src/app/app.ts`
- Create: `src/adapters/db/memory/memory-refresh-token-repository.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`

- [ ] **Step 1: Add empty and memory refresh token repositories**
- [ ] **Step 2: Add `refreshTokenRepository` to `AppOptions` and route wiring**
- [ ] **Step 3: Ensure `/token` handler passes all needed dependencies**

### Task 6: Update admin API client types and AUTH modal

**Files:**
- Modify: `admin/src/api/client.ts`
- Modify: `admin/src/pages/TenantClientsPage.tsx`

- [ ] **Step 1: Extend `AuthMethodPolicyWire` with `token_ttl_seconds`**
- [ ] **Step 2: Add TTL inputs to each auth method row in the AUTH modal**
- [ ] **Step 3: Keep defaults stable for pre-existing clients with synthesized policy rows**
- [ ] **Step 4: Verify create/edit/list flows still compile with the updated wire type**

### Task 7: Verify and clean up

**Files:**
- Verify only

- [ ] **Step 1: Run targeted Vitest suites for admin and OIDC flows**
- [ ] **Step 2: Run any additional focused tests required by touched modules**
- [ ] **Step 3: Fix regressions**
- [ ] **Step 4: Summarize outcomes and residual risks**
