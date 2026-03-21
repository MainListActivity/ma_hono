# IdP V1 Login And Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first production-usable IdP version with tenant-aware user provisioning, interactive OIDC Authorization Code + PKCE, username/password login, email magic link login, and passkey enrollment/login on Cloudflare Workers.

**Architecture:** Extend the current OIDC foundation without replacing it. Keep tenant/issuer/client/discovery/JWKS/token semantics in first-party domain modules, add D1-backed one-time authorization state for atomic consumption, keep browser sessions in KV, store signing key material in R2, and add standards-oriented local auth + WebAuthn adapters instead of pushing core IdP behavior into a third-party auth framework.

**Tech Stack:** TypeScript, Hono, Zod, jose, Drizzle ORM with D1/SQLite, Cloudflare Workers bindings, KV, R2, Vitest, pnpm, Wrangler, `@simplewebauthn/server` if Workers-compatible.

---

## File Structure Map

This plan assumes the current foundation files remain in place and adds focused modules around them.

### Files To Create

- `src/domain/users/types.ts`
  Tenant-scoped end-user types and auth-method policy types.
- `src/domain/users/repository.ts`
  User, credential, invitation, and policy repository contracts.
- `src/domain/users/passwords.ts`
  Password hashing and verification helpers.
- `src/domain/users/provision-user.ts`
  Admin-driven user provisioning and invitation issuance orchestration.
- `src/domain/users/activate-user.ts`
  Invitation consumption and initial password setup orchestration.
- `src/domain/authentication/types.ts`
  Browser user session and login-challenge types.
- `src/domain/authentication/repository.ts`
  Browser session repository contract.
- `src/domain/authentication/login-challenge-repository.ts`
  D1-backed login challenge repository contract.
- `src/domain/authentication/session-service.ts`
  Create and authenticate end-user browser sessions.
- `src/domain/authorization/types.ts`
  Authorize request, validated request, and authorization code types.
- `src/domain/authorization/repository.ts`
  Authorization code repository contract.
- `src/domain/authorization/authorize-request.ts`
  `/authorize` validation and redirect-decision service.
- `src/domain/authorization/pkce.ts`
  PKCE challenge verification.
- `src/domain/tokens/token-service.ts`
  Authorization code exchange and token issuance orchestration.
- `src/domain/tokens/claims.ts`
  ID token and access token claim builders.
- `src/domain/keys/signer.ts`
  JWT signer abstraction backed by D1 metadata + R2 material.
- `src/domain/oidc/token-response.ts`
  Token endpoint response helpers.
- `src/adapters/db/memory/memory-user-repository.ts`
  In-memory user/policy/invitation repository for tests.
- `src/adapters/db/memory/memory-login-challenge-repository.ts`
  In-memory login challenge repository.
- `src/adapters/db/memory/memory-authorization-code-repository.ts`
  In-memory authorization code repository.
- `src/adapters/db/memory/memory-user-session-repository.ts`
  In-memory browser session repository.
- `src/adapters/auth/local-auth/password-auth-service.ts`
  Password login adapter against first-party tables.
- `src/adapters/auth/local-auth/magic-link-service.ts`
  Magic-link issue/consume adapter against first-party tables.
- `src/adapters/auth/webauthn/webauthn-service.ts`
  Passkey challenge generation and verification adapter.
- `src/adapters/kv/user-session-repository.ts`
  KV-backed end-user browser session repository.
- `tests/users/provision-and-activation.test.ts`
  Admin provisioning and invitation activation coverage.
- `tests/authorization/authorize-request.test.ts`
  `/authorize` validation and unauthenticated redirect coverage.
- `tests/oidc/token-endpoint.test.ts`
  Authorization code exchange and signed token response coverage.
- `tests/authentication/password-login.test.ts`
  Username/password login flow coverage.
- `tests/authentication/magic-link-login.test.ts`
  Magic-link issue/consume coverage.
- `tests/authentication/passkey-login.test.ts`
  Passkey enrollment/login coverage.
- `tests/oidc/e2e-login-flow.test.ts`
  End-to-end login to token exchange coverage across platform-path and custom-domain issuers.

### Files To Modify

- `src/adapters/db/drizzle/schema.ts`
  Extend D1 schema for users, policies, invitations, login challenges, authorization codes, email login tokens, and client trust fields.
- `src/adapters/db/drizzle/runtime.ts`
  Add D1 repositories for user/provisioning/auth state, authorization state, key bootstrap, and KV-backed user sessions.
- `src/domain/clients/types.ts`
  Add `trustLevel` and `consentPolicy`.
- `src/domain/clients/registration-schema.ts`
  Restrict or default trust/consent semantics for V1 first-party clients.
- `src/domain/clients/register-client.ts`
  Persist `trustLevel` and `consentPolicy`.
- `src/domain/oidc/discovery.ts`
  Publish authorization/token endpoints and V1 capabilities.
- `src/domain/audit/types.ts`
  Add auth and OIDC audit event names/payload shapes.
- `src/app/app.ts`
  Add `/authorize`, `/token`, login endpoints, invitation activation, passkey routes, and admin user provisioning routes.
- `src/config/env.ts`
  Add `USER_SESSIONS_KV` and any V1 email/passkey config needed for Workers runtime.
- `src/index.ts`
  Inject the new repositories and services.
- `drizzle/migrations/0000_oidc_foundation.sql`
  Leave intact.
- `drizzle/migrations/0001_idp_v1_login_and_authorization.sql`
  Add V1 tables, columns, indexes, and constraints.
- `wrangler.jsonc`
  Add `USER_SESSIONS_KV` and any V1 runtime vars.
- `package.json`
  Add any new scripts or dependencies such as WebAuthn library support.
- `tests/config/env.test.ts`
  Cover the new Workers bindings.
- `tests/oidc/discovery.test.ts`
  Extend metadata assertions for authorization/token endpoints and PKCE support.
- `README.md`
  Replace the placeholder text with real local/dev/deploy instructions after implementation.

## Task 1: Extend Runtime Bindings And Persistence Schema

**Files:**
- Modify: `src/adapters/db/drizzle/schema.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `src/config/env.ts`
- Modify: `src/index.ts`
- Modify: `wrangler.jsonc`
- Modify: `package.json`
- Create: `drizzle/migrations/0001_idp_v1_login_and_authorization.sql`
- Modify: `tests/config/env.test.ts`

- [ ] **Step 1: Write the failing config and schema tests**

Add assertions for:
- `USER_SESSIONS_KV` binding requirement
- new D1 tables and client trust/consent columns existing in the schema surface

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/config/env.test.ts`
Expected: FAIL because the new binding and schema exports do not exist yet

- [ ] **Step 3: Extend the D1 schema and runtime bindings**

Implement:
- `oidc_clients.trust_level`
- `oidc_clients.consent_policy`
- `users`
- `user_password_credentials`
- `webauthn_credentials`
- `tenant_auth_method_policies`
- `user_invitations`
- `login_challenges`
- `authorization_codes`
- `email_login_tokens`

Add indexes/uniques for:
- `(tenant_id, email)`
- `(tenant_id, username)`
- `credential_id`
- token hashes
- unconsumed artifact lookup fields

Add `USER_SESSIONS_KV` to env and wrangler config.

- [ ] **Step 4: Add the migration**

Create `drizzle/migrations/0001_idp_v1_login_and_authorization.sql` with the full D1 materialization for the new tables and client columns.

- [ ] **Step 5: Run targeted verification**

Run:
- `corepack pnpm vitest run tests/config/env.test.ts`
- `corepack pnpm exec drizzle-kit check`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/adapters/db/drizzle/schema.ts src/adapters/db/drizzle/runtime.ts src/config/env.ts src/index.ts wrangler.jsonc package.json drizzle/migrations/0001_idp_v1_login_and_authorization.sql tests/config/env.test.ts
git commit -m "feat: add idp v1 runtime schema"
```

## Task 2: Add Signing-Key Bootstrap, Discovery Metadata, And Token Signer

**Files:**
- Create: `src/domain/keys/signer.ts`
- Modify: `src/domain/keys/types.ts`
- Modify: `src/domain/oidc/discovery.ts`
- Modify: `src/adapters/r2/r2-key-material-store.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `src/app/app.ts`
- Test: `tests/oidc/discovery.test.ts`
- Test: `tests/oidc/jwks.test.ts`

- [ ] **Step 1: Write the failing discovery and signer tests**

Extend coverage for:
- `authorization_endpoint`
- `token_endpoint`
- `grant_types_supported`
- `response_types_supported`
- `code_challenge_methods_supported`
- `token_endpoint_auth_methods_supported`
- key bootstrap selecting an active signing key for token issuance

- [ ] **Step 2: Run test to verify it fails**

Run:
- `corepack pnpm vitest run tests/oidc/discovery.test.ts`
- `corepack pnpm vitest run tests/oidc/jwks.test.ts`

Expected: FAIL because the new metadata and signer behavior are missing

- [ ] **Step 3: Implement the minimal metadata and signer service**

Add:
- discovery metadata for V1 interactive OIDC
- signer interface that loads active key metadata from D1 and private key material from R2
- a bootstrap path for initial signing-key material if the service has none yet
- minimal non-404 placeholder `/authorize` and `/token` routes that return an explicit temporary not-implemented response until Task 3 and Task 6 land real behavior

- [ ] **Step 4: Run test to verify it passes**

Run:
- `corepack pnpm vitest run tests/oidc/discovery.test.ts`
- `corepack pnpm vitest run tests/oidc/jwks.test.ts`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/domain/keys src/domain/oidc/discovery.ts src/adapters/r2/r2-key-material-store.ts src/adapters/db/drizzle/runtime.ts src/app/app.ts tests/oidc/discovery.test.ts tests/oidc/jwks.test.ts
git commit -m "feat: add v1 discovery metadata and signer"
```

## Task 3: Implement `/authorize`, Client Trust Validation, And D1 Authorization State

**Files:**
- Create: `src/domain/authorization/types.ts`
- Create: `src/domain/authorization/repository.ts`
- Create: `src/domain/authorization/authorize-request.ts`
- Create: `src/domain/authorization/pkce.ts`
- Create: `src/adapters/db/memory/memory-login-challenge-repository.ts`
- Create: `src/adapters/db/memory/memory-authorization-code-repository.ts`
- Modify: `src/domain/clients/types.ts`
- Modify: `src/domain/clients/registration-schema.ts`
- Modify: `src/domain/clients/register-client.ts`
- Modify: `src/adapters/db/memory/memory-client-repository.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `src/domain/audit/types.ts`
- Modify: `src/app/app.ts`
- Test: `tests/authorization/authorize-request.test.ts`

- [ ] **Step 1: Write the failing authorization-request tests**

Cover:
- invalid client or redirect URI is rejected
- disabled tenant authorization is rejected
- unauthenticated valid request creates a login challenge and redirects to login
- authenticated valid request skips consent only for `first_party_trusted + skip`
- authorization code issuance persists issuer, client, redirect URI, and PKCE challenge
- authorization success and failure both emit audit events

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/authorization/authorize-request.test.ts`
Expected: FAIL because `/authorize` and its repositories do not exist

- [ ] **Step 3: Implement minimal authorization validation and persistence**

Implement:
- trusted-client fields
- registration schema defaulting or validation for V1 client trust semantics
- authorize-request validation
- disabled-tenant rejection
- login challenge creation in D1-compatible repositories
- authorization code creation with one-time semantics
- authorization audit events
- `/authorize` route wiring

- [ ] **Step 4: Run test to verify it passes**

Run: `corepack pnpm vitest run tests/authorization/authorize-request.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/domain/authorization src/domain/clients/types.ts src/domain/clients/registration-schema.ts src/domain/clients/register-client.ts src/adapters/db/memory/memory-client-repository.ts src/adapters/db/memory/memory-login-challenge-repository.ts src/adapters/db/memory/memory-authorization-code-repository.ts src/adapters/db/drizzle/runtime.ts src/domain/audit/types.ts src/app/app.ts tests/authorization/authorize-request.test.ts
git commit -m "feat: add oidc authorize flow"
```

## Task 4: Add End-User Session, User, Policy, And Invitation Domain Contracts

**Files:**
- Create: `src/domain/users/types.ts`
- Create: `src/domain/users/repository.ts`
- Create: `src/domain/users/passwords.ts`
- Create: `src/domain/users/provision-user.ts`
- Create: `src/domain/users/activate-user.ts`
- Create: `src/domain/authentication/types.ts`
- Create: `src/domain/authentication/repository.ts`
- Create: `src/domain/authentication/login-challenge-repository.ts`
- Create: `src/domain/authentication/session-service.ts`
- Create: `src/adapters/db/memory/memory-user-repository.ts`
- Create: `src/adapters/db/memory/memory-user-session-repository.ts`
- Test: `tests/users/provision-and-activation.test.ts`

- [ ] **Step 1: Write the failing provisioning and activation tests**

Cover:
- admin provisions a tenant user and creates an invitation
- invitation can be consumed once to set the initial password
- expired or already-consumed invitation is rejected
- browser session creation returns an opaque session token

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/users/provision-and-activation.test.ts`
Expected: FAIL because the domain contracts and services do not exist

- [ ] **Step 3: Implement minimal user and session domain logic**

Implement:
- tenant user types and statuses
- tenant auth-method policy types and reads
- password hash/verify helpers
- invitation issuance and one-time consumption semantics
- end-user browser session creation and lookup

- [ ] **Step 4: Run test to verify it passes**

Run: `corepack pnpm vitest run tests/users/provision-and-activation.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/domain/users src/domain/authentication src/adapters/db/memory/memory-user-repository.ts src/adapters/db/memory/memory-user-session-repository.ts tests/users/provision-and-activation.test.ts
git commit -m "feat: add user provisioning and activation domain"
```

## Task 5: Implement Admin User Provisioning And Invitation Activation Routes

**Files:**
- Modify: `src/app/app.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `src/domain/audit/types.ts`
- Test: `tests/users/provision-and-activation.test.ts`

- [ ] **Step 1: Write the failing route-level tests**

Extend coverage for:
- authenticated admin can provision a tenant user
- provisioning emits an invitation token or activation URL
- activation endpoint sets the initial password and consumes the invitation
- admin provisioning and activation emit audit events

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/users/provision-and-activation.test.ts`
Expected: FAIL because the HTTP routes do not exist

- [ ] **Step 3: Implement minimal admin and activation routes**

Add:
- `POST /admin/tenants/:tenantId/users`
- `POST /activate-account`

Keep the flow API-first for V1 if full admin UI is not yet built.

- [ ] **Step 4: Run test to verify it passes**

Run: `corepack pnpm vitest run tests/users/provision-and-activation.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/app/app.ts src/adapters/db/drizzle/runtime.ts src/domain/audit/types.ts tests/users/provision-and-activation.test.ts
git commit -m "feat: add admin user provisioning routes"
```

## Task 6: Implement `/token` And Signed Token Exchange

**Files:**
- Create: `src/domain/tokens/token-service.ts`
- Create: `src/domain/tokens/claims.ts`
- Create: `src/domain/oidc/token-response.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `src/domain/audit/types.ts`
- Modify: `src/app/app.ts`
- Test: `tests/oidc/token-endpoint.test.ts`

- [ ] **Step 1: Write the failing token-endpoint tests**

Cover:
- valid code + PKCE exchange returns `id_token` and signed JWT `access_token`
- reused or expired code is rejected
- client auth methods `client_secret_basic`, `client_secret_post`, and `none` behave correctly
- returned tokens use issuer-correct `iss` and `aud`
- token exchange failure emits an audit event

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/oidc/token-endpoint.test.ts`
Expected: FAIL because `/token` does not exist

- [ ] **Step 3: Implement minimal token exchange**

Implement:
- authorization code lookup and atomic consumption
- PKCE verification
- client authentication
- ID token claims
- JWT access token claims
- token-exchange audit events
- `/token` route

- [ ] **Step 4: Run test to verify it passes**

Run: `corepack pnpm vitest run tests/oidc/token-endpoint.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/domain/tokens src/domain/oidc/token-response.ts src/adapters/db/drizzle/runtime.ts src/domain/audit/types.ts src/app/app.ts tests/oidc/token-endpoint.test.ts
git commit -m "feat: add oidc token endpoint"
```

## Task 7: Implement Username/Password Login And Authorization Resume

**Files:**
- Create: `src/adapters/auth/local-auth/password-auth-service.ts`
- Modify: `src/domain/authentication/session-service.ts`
- Modify: `src/domain/audit/types.ts`
- Modify: `src/app/app.ts`
- Test: `tests/authentication/password-login.test.ts`

- [ ] **Step 1: Write the failing password-login tests**

Cover:
- valid username/password login consumes the login challenge and redirects back with `code`
- invalid password returns a login failure without leaking tenant state
- disabled tenant or disabled user is rejected
- tenant password policy disables the flow when configured off
- login success and failure emit audit events

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/authentication/password-login.test.ts`
Expected: FAIL because password-login routes and resume logic do not exist

- [ ] **Step 3: Implement minimal password-login flow**

Add:
- tenant-aware password verification
- tenant auth-method policy enforcement
- login challenge lookup and consumption
- browser session creation
- authorization resume to code issuance
- password-login audit events

- [ ] **Step 4: Run test to verify it passes**

Run: `corepack pnpm vitest run tests/authentication/password-login.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/adapters/auth/local-auth/password-auth-service.ts src/domain/authentication/session-service.ts src/domain/audit/types.ts src/app/app.ts tests/authentication/password-login.test.ts
git commit -m "feat: add password login flow"
```

## Task 8: Implement Email Magic Link Login

**Files:**
- Create: `src/adapters/auth/local-auth/magic-link-service.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `src/domain/audit/types.ts`
- Modify: `src/app/app.ts`
- Test: `tests/authentication/magic-link-login.test.ts`

- [ ] **Step 1: Write the failing magic-link tests**

Cover:
- existing tenant user can request a magic link
- consuming the magic link creates a session and resumes authorization
- expired or previously consumed magic link is rejected
- tenant magic-link policy disables the flow when configured off
- magic-link request and consume emit audit events

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/authentication/magic-link-login.test.ts`
Expected: FAIL because magic-link issue/consume routes do not exist

- [ ] **Step 3: Implement minimal magic-link flow**

Implement:
- issue one-time D1 token for an existing user
- tenant auth-method policy enforcement
- consume the token atomically
- create browser session
- resume the stored login challenge
- magic-link audit events

For V1 tests, the delivery adapter can return the link payload directly until an email adapter is added.

- [ ] **Step 4: Run test to verify it passes**

Run: `corepack pnpm vitest run tests/authentication/magic-link-login.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/adapters/auth/local-auth/magic-link-service.ts src/adapters/db/drizzle/runtime.ts src/domain/audit/types.ts src/app/app.ts tests/authentication/magic-link-login.test.ts
git commit -m "feat: add magic link login"
```

## Task 9: Implement Passkey Enrollment And Passkey Login

**Files:**
- Create: `src/adapters/auth/webauthn/webauthn-service.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `src/domain/audit/types.ts`
- Modify: `src/app/app.ts`
- Test: `tests/authentication/passkey-login.test.ts`

- [ ] **Step 1: Write the failing passkey tests**

Cover:
- authenticated user can start and complete passkey enrollment
- enrolled passkey can satisfy a login challenge
- signature counter and credential ownership are verified
- tenant passkey policy disables enrollment/login when configured off
- passkey enrollment and login emit audit events

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/authentication/passkey-login.test.ts`
Expected: FAIL because WebAuthn routes and persistence do not exist

- [ ] **Step 3: Implement minimal passkey flow**

Add:
- enrollment challenge generation
- enrollment verification and credential persistence
- tenant auth-method policy enforcement
- login assertion challenge generation
- login verification and authorization resume
- passkey audit events

- [ ] **Step 4: Run test to verify it passes**

Run: `corepack pnpm vitest run tests/authentication/passkey-login.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/adapters/auth/webauthn/webauthn-service.ts src/adapters/db/drizzle/runtime.ts src/domain/audit/types.ts src/app/app.ts tests/authentication/passkey-login.test.ts
git commit -m "feat: add passkey enrollment and login"
```

## Task 10: Add End-To-End Flow Coverage, Admin Policy Controls, And Docs

**Files:**
- Modify: `src/app/app.ts`
- Modify: `src/adapters/db/drizzle/runtime.ts`
- Modify: `README.md`
- Test: `tests/oidc/e2e-login-flow.test.ts`

- [ ] **Step 1: Write the failing end-to-end tests**

Cover:
- platform-path issuer end-to-end login with password to code to token
- custom-domain issuer end-to-end login with magic link or passkey to code to token
- discovery metadata and JWKS validate the returned tokens
- client trust and tenant auth-method policy are enforced
- disabled tenant authorization is rejected end-to-end

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm vitest run tests/oidc/e2e-login-flow.test.ts`
Expected: FAIL because the full V1 flow is not wired together yet

- [ ] **Step 3: Implement the minimal missing integration and docs**

Add:
- any missing policy routes or admin knobs required by the test
- README instructions for local setup, D1 migrations, key bootstrap, user provisioning, and Workers deployment

- [ ] **Step 4: Run full verification**

Run:
- `corepack pnpm vitest run`
- `corepack pnpm typecheck`
- `corepack pnpm exec drizzle-kit check`
- `corepack pnpm exec wrangler deploy --dry-run`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/app/app.ts src/adapters/db/drizzle/runtime.ts README.md tests/oidc/e2e-login-flow.test.ts
git commit -m "feat: complete idp v1 login flow"
```
