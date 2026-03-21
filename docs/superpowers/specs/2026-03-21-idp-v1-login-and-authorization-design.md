# IdP V1 Login And Authorization Design

## Goal

Deliver the first production-usable version of this multi-tenant identity provider on Cloudflare Workers.

This version must support a complete first-party OpenID Connect login flow:

- a relying party starts an OIDC authorization request
- the end user authenticates against this service
- the service issues an authorization code
- the relying party exchanges the code with PKCE
- the service returns issuer-correct tokens that can be validated through discovery metadata and JWKS

The goal of this phase is not more foundation work. The goal is a runnable, testable, deployable V1 that can act as a real IdP for first-party applications.

## Scope

### In Scope

- Authorization Code + PKCE
- OIDC authorization endpoint
- OIDC token endpoint
- ID token issuance
- signed JWT access token issuance for first-party relying applications
- browser login session for end users
- tenant-aware login entry and issuer-aware authorization flow
- tenant-scoped user provisioning by admin
- invitation-based account activation
- initial password setup for provisioned users
- username/password login
- email magic link login for existing users
- passkey enrollment for authenticated users
- passkey login
- trusted first-party clients with consent skipped by default
- signing key initialization and token signing
- tenant-aware user model
- tenant-aware local credential model
- tenant-aware passkey credential model
- audit events for login and authorization actions
- Cloudflare Workers-only runtime with D1, KV, and R2

### Out Of Scope

- Google login
- Apple login
- Facebook login
- WeChat QR login
- SMS MFA
- TOTP MFA
- passkey step-up MFA
- refresh tokens
- third-party client consent UX
- dynamic third-party federation policy
- public self-service sign-up
- self-hosted runtime support

## Product Constraints

Repository-level constraints remain mandatory:

- TypeScript only
- Hono only for the HTTP application layer
- Cloudflare Workers only
- D1, KV, and R2 as the default storage services
- multi-tenant issuer-aware design
- standards-first OIDC behavior

This V1 must behave as an IdP, not as a generic app-auth session layer.

## Recommended Architecture

The recommended architecture is a modular monolith with a single Hono Workers application.

The system remains split into:

- domain logic
- protocol logic
- runtime and storage adapters
- minimal login UI routes

An authentication adapter boundary is required, but the IdP remains the system authority for issuer, tenant, client, user, and OIDC protocol semantics.

That means:

- helper libraries may be used where they reduce ceremony without taking over the domain model
- this codebase remains the source of truth for tenants, issuers, clients, users, authorization requests, authorization codes, token claims, signing keys, and OIDC responses
- any authentication framework integration must sit behind an adapter boundary

Preferred V1 library posture:

- password and magic-link flows are implemented against first-party domain tables
- WebAuthn should use a standards-oriented library such as `@simplewebauthn/server` if Workers-compatible
- a framework such as `Better Auth` may be evaluated later as an acceleration layer for additional providers, but it is not a hard dependency of this V1 design

## System Boundaries

This phase extends the existing OIDC foundation into a real first-party login and authorization product.

The delivered system must be able to:

- resolve the active issuer from host and path
- validate an incoming `/authorize` request for a tenant-aware client
- route an unauthenticated user into the correct tenant login flow
- authenticate the user with one of the supported V1 methods
- establish an authenticated browser session
- resume the authorization request after login
- issue a short-lived authorization code bound to the original request and PKCE challenge
- exchange that code at `/token`
- issue issuer-correct signed tokens
- expose consistent discovery metadata and JWKS for those tokens

The delivered system must not advertise unsupported grant types or incomplete login methods.

## Authentication Strategy

### V1 Supported Login Methods

The initial production login set is:

- username/password
- email magic link
- passkey

These methods must be modeled as tenant capabilities.

### Account Lifecycle

V1 does not include public sign-up.

V1 account creation and enrollment must work as follows:

- an admin provisions a user under a tenant
- the system can issue an invitation or activation token to that user
- the user can set an initial password through the invitation flow
- email magic link login is allowed only for an existing tenant user whose email is already present
- passkey enrollment requires an existing authenticated user session

This keeps the first release operationally realistic without mixing self-service registration into the initial IdP launch.

### Trusted Client And Consent Policy

V1 supports trusted first-party clients only.

Rules:

- the client must exist in the tenant that owns the current issuer
- the redirect URI must exactly match a registered redirect URI
- the client must have `trust_level=first_party_trusted`
- the client must have `consent_policy=skip`
- authorization proceeds immediately after successful login

The client model must persist these fields explicitly so the server can enforce which clients are allowed to bypass consent.

## Protocol Design

### Authorization Endpoint

The system must add an authorization endpoint under the issuer surface:

- platform issuer: `/t/:tenant/authorize`
- custom-domain issuer: `/authorize`

Supported V1 request shape:

- `response_type=code`
- `client_id`
- `redirect_uri`
- `scope` containing at least `openid`
- `state`
- `code_challenge`
- `code_challenge_method=S256`

Validation rules:

- the issuer must resolve successfully
- the tenant must be active
- the client must belong to the same tenant
- the client must support `authorization_code`
- the redirect URI must match exactly
- PKCE is required

When the user is not authenticated:

- create a resumable login challenge
- persist the authorization request and login challenge in D1
- redirect the browser to the tenant-aware login entry

When the user is authenticated:

- skip consent
- create an authorization code record in D1
- redirect to the client callback with `code` and `state`

### Login Flow

The tenant-aware login entry must be able to offer:

- username/password form
- email magic link request
- passkey initiation

All login flows must resolve back to the original authorization challenge.

Required properties:

- login challenge is issuer-aware
- login challenge is tenant-aware
- login challenge expires quickly
- login challenge can only be consumed once
- successful login creates a browser session scoped to the tenant user

### Token Endpoint

The system must add a token endpoint under the issuer surface:

- platform issuer: `/t/:tenant/token`
- custom-domain issuer: `/token`

Supported V1 grant:

- `authorization_code`

Rules:

- code must exist
- code must not be expired
- code must not be reused
- code must belong to the same issuer and tenant
- code must belong to the same client
- `redirect_uri` must match the original request
- PKCE verifier must match the original challenge

Supported client auth methods in V1:

- `client_secret_basic`
- `client_secret_post`
- `none` for public clients

### Token Shape

V1 must issue:

- `id_token`
- `access_token`
- `token_type=Bearer`
- `expires_in`

The `id_token` must contain at least:

- `iss`
- `sub`
- `aud`
- `exp`
- `iat`
- optional `email`
- optional `email_verified`
- optional `preferred_username`

`sub` must be stable per tenant user.

V1 access tokens are signed JWT bearer tokens.

V1 access-token contract:

- `iss` is the resolved issuer
- `sub` is the tenant user subject
- `aud` is the requesting `client_id`
- `client_id` is included as a separate claim
- `scope` reflects the approved scope string
- `exp` and `iat` are required

V1 access tokens are intended for first-party relying applications controlled by the same tenant. They are not yet a general multi-resource authorization contract and do not use separate resource indicators in this phase.

V1 relying applications validate access tokens using the same issuer discovery metadata and JWKS used for ID token validation.

Token issuer and JWKS selection must follow the resolved issuer exactly. Custom-domain issuer requests must not receive tokens minted for the platform-path issuer.

### Discovery Metadata Requirements

The discovery document must be extended beyond the foundation slice.

V1 discovery metadata must publish at least:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`
- `registration_endpoint`
- `response_types_supported` with `code`
- `grant_types_supported` with `authorization_code`
- `code_challenge_methods_supported` with `S256`
- `subject_types_supported`
- `id_token_signing_alg_values_supported`
- `token_endpoint_auth_methods_supported`
- `scopes_supported` including `openid`

## Module Layout

The existing layout should be extended rather than replaced.

```text
src/
  app/
    app.ts
  domain/
    admin-auth/
    audit/
    authentication/
    authorization/
    clients/
    keys/
    oidc/
    tenants/
    tokens/
    users/
  adapters/
    auth/
      local-auth/
      webauthn/
    crypto/
    db/
      drizzle/
    kv/
    r2/
  config/
  lib/
```

Module responsibilities:

- `domain/users`: tenant-scoped user identity and status rules
- `domain/authentication`: login challenge and browser session rules
- `domain/authorization`: `/authorize` request validation and authorization code issuance
- `domain/tokens`: token exchange and claim assembly
- `adapters/auth/local-auth`: password and magic-link authentication services against first-party user tables
- `adapters/auth/webauthn`: passkey challenge and verification integration
- `adapters/db/drizzle`: D1-backed repositories
- `adapters/kv`: browser session storage and low-risk cache state
- `adapters/r2`: private signing key material storage

## Data Model

The V1 persistence model is distributed across D1, KV, and R2.

### D1 Tables

Existing tables continue to apply:

- `tenants`
- `tenant_issuers`
- `oidc_clients`
- `signing_keys`
- `admin_users`
- `audit_events`

New structured tables are required.

### `oidc_clients`

The existing client table must be extended with:

- `trust_level`
- `consent_policy`

V1 allowed values:

- `trust_level=first_party_trusted`
- `consent_policy=skip`

### `users`

Purpose: tenant-scoped end-user identity.

Suggested columns:

- `id`
- `tenant_id`
- `email`
- `email_verified`
- `username`
- `display_name`
- `status`
- `created_at`
- `updated_at`

Constraints:

- unique `(tenant_id, email)` when email is present
- unique `(tenant_id, username)` when username is present

### `user_password_credentials`

Purpose: local password credential metadata.

Suggested columns:

- `id`
- `tenant_id`
- `user_id`
- `password_hash`
- `created_at`
- `updated_at`

### `webauthn_credentials`

Purpose: passkey credential registration metadata.

Suggested columns:

- `id`
- `tenant_id`
- `user_id`
- `credential_id`
- `public_key`
- `counter`
- `transports`
- `device_type`
- `backed_up`
- `created_at`
- `updated_at`

Constraints:

- unique `credential_id`

### `tenant_auth_method_policies`

Purpose: tenant-level enablement policy for V1 login methods.

Suggested columns:

- `tenant_id`
- `password_enabled`
- `email_magic_link_enabled`
- `passkey_enabled`
- `created_at`
- `updated_at`

This can be normalized later if policy grows. V1 only needs enough shape to avoid baking auth-method enablement into code.

### `user_invitations`

Purpose: invitation and initial account activation for provisioned users.

Suggested columns:

- `id`
- `tenant_id`
- `user_id`
- `token_hash`
- `purpose`
- `expires_at`
- `consumed_at`
- `created_at`

### `login_challenges`

Purpose: resumable authorization-login state with one-time consumption.

Suggested columns:

- `id`
- `tenant_id`
- `issuer`
- `client_id`
- `redirect_uri`
- `scope`
- `state`
- `code_challenge`
- `code_challenge_method`
- `expires_at`
- `consumed_at`
- `created_at`

### `authorization_codes`

Purpose: one-time authorization code records with atomic consumption.

Suggested columns:

- `id`
- `tenant_id`
- `issuer`
- `client_id`
- `user_id`
- `redirect_uri`
- `scope`
- `nonce`
- `code_challenge`
- `code_challenge_method`
- `expires_at`
- `consumed_at`
- `created_at`

### `email_login_tokens`

Purpose: one-time magic-link login records with atomic consumption.

Suggested columns:

- `id`
- `tenant_id`
- `user_id`
- `issuer`
- `token_hash`
- `redirect_after_login`
- `expires_at`
- `consumed_at`
- `created_at`

### KV Namespaces

Existing namespaces continue:

- `ADMIN_SESSIONS_KV`
- `REGISTRATION_TOKENS_KV`

V1 should add a dedicated namespace for end-user browser sessions:

- `USER_SESSIONS_KV`

High-value one-time security artifacts must not use KV as the system of record. They require atomic consume semantics and must therefore live in D1 with `consumed_at` tracking and conditional updates.

### R2

The existing `KEY_MATERIAL_R2` bucket remains the store for private signing key material.

Private keys must not be embedded inline in D1. D1 stores metadata and the `private_key_ref`; R2 stores the actual object body.

## Request And State Flow

### Unauthenticated Authorization Request

1. Client calls `/authorize`.
2. The system resolves the issuer.
3. The system validates client, redirect URI, response type, scope, and PKCE.
4. The system stores a login challenge in D1 with:
   - issuer
   - tenant id
   - client id
   - redirect URI
   - scope
   - state
   - PKCE challenge
   - expiry
5. The browser is redirected to the tenant login entry.

### Successful Login

1. The user completes username/password, magic link, or passkey authentication.
2. The system resolves the authenticated tenant user.
3. The system creates a browser session in `USER_SESSIONS_KV`.
4. The system resumes the login challenge.
5. The system issues a single-use authorization code in D1.
6. The browser is redirected to the relying-party callback with `code` and `state`.

### Token Exchange

1. Client posts to `/token`.
2. The system authenticates the client.
3. The system loads and validates the authorization code.
4. The system verifies PKCE.
5. The system loads the tenant signing key metadata from D1 and private material from R2.
6. The system issues signed tokens.
7. The authorization code is atomically marked consumed in D1.

### Atomic Consumption Rule

The following one-time artifacts require atomic consume semantics in D1:

- login challenges
- authorization codes
- email login tokens
- user invitation or activation tokens

Consume operations must update the row only when:

- the token or code exists
- the row is unconsumed
- the row is not expired

If the update affects zero rows, the artifact is invalid, expired, or already consumed.

## Authentication Adapter Requirements

The authentication adapter layer must satisfy these constraints:

- tenant context must be known before authentication starts
- authentication handlers must respect tenant boundaries
- successful authentication must yield a tenant user identifier from the system's own `users` table
- adapter-specific state must not replace the IdP browser authorization session unless the two are intentionally unified through a thin adapter

Preferred V1 approach:

- password verification and magic-link token issuance are implemented directly against first-party tables
- passkey challenge and verification use a Workers-compatible WebAuthn library behind `adapters/auth/webauthn`
- any future framework integration must read and write the same first-party source-of-truth user and credential model

## Security Requirements

This phase is security-sensitive and must prioritize correctness.

Important requirements:

- PKCE required for all interactive clients
- redirect URI exact match
- authorization codes are one-time use and short-lived
- login challenges are one-time use and short-lived
- email login tokens are one-time use and short-lived
- browser user sessions use opaque tokens stored in KV
- passwords must use a strong adaptive hash compatible with Workers constraints
- passkey verification must track counters and credential ownership
- audit events are emitted for login success/failure, magic link request/consume, authorization success/failure, and token exchange failure
- disabled tenants cannot log in or authorize
- issuer mismatch must fail closed

## Error Handling

Three classes of errors must stay separate.

### Protocol Errors

For `/authorize` and `/token`:

- use OAuth/OIDC-compatible error responses
- for authorization requests, redirect with protocol errors when appropriate
- for token requests, return JSON error bodies such as `invalid_request`, `invalid_client`, `invalid_grant`, or `unauthorized_client`

### Login Errors

For username/password, magic link, and passkey:

- return login-page-level failures
- do not leak whether a tenant contains a given user when policy forbids disclosure
- keep expired or consumed magic-link handling generic

### System Errors

- return generic `5xx`
- do not leak D1/KV/R2 internals
- record an audit event when the failure occurs in a security-sensitive path

## Testing Strategy

V1 must be verified around the full login-to-token chain.

### Unit Tests

Cover:

- authorize request validation
- PKCE hashing and verification
- redirect URI validation
- authorization code issuance and consumption
- token claim construction
- tenant auth-method policy checks

### Integration Tests

Cover:

- unauthenticated `/authorize` redirects into login
- username/password login completes the flow and returns a code
- code exchange returns `id_token` and `access_token`
- token issuer matches discovery metadata
- custom-domain issuer works end-to-end
- disabled tenant is rejected

### Adapter Tests

Cover:

- invitation activation and password setup
- magic link token issuance and one-time consumption
- passkey challenge generation and verification
- D1/KV/R2 repository behavior on success and partial failure

## Delivery Sequence

Implement in this order:

1. V1 schema extension for users, passwords, passkeys, client trust fields, invitation flow, one-time D1 state tables, and user-session KV
2. signing-key bootstrap and token signer service
3. `/authorize` validation and login challenge storage
4. end-user browser session model
5. admin user provisioning and invitation activation
6. `/token` with authorization code + PKCE
7. username/password login
8. email magic link login
9. passkey enrollment and login
10. admin APIs and UI updates for user-facing auth policy and key bootstrap
11. deployment and initialization documentation

This order keeps the OIDC core ahead of the login methods, so every new method lands on a working authorization backbone.

## Acceptance Criteria

This phase is complete when all of the following are true:

- a registered trusted client can complete `authorization_code + PKCE`
- the user can log in with username/password
- the user can log in with email magic link
- the user can log in with passkey
- an admin can provision a user and the user can activate the account
- `/token` returns an issuer-correct signed `id_token`
- `/token` returns a signed JWT `access_token` whose audience is the requesting client
- the token can be validated with published discovery metadata and JWKS
- disabled tenants cannot authenticate or authorize
- all runtime state is stored in Cloudflare D1, KV, and R2 according to the design
- the Workers application can be deployed with documented bindings and initialization steps
