# OIDC Foundation Design

## Goal

Build the first production-oriented slice of a multi-tenant identity provider using TypeScript and Hono, with Cloudflare Workers as the only runtime target and Cloudflare-native storage services as the default infrastructure.

This phase delivers the OIDC trust foundation:

- tenant-aware issuer modeling
- discovery metadata
- JWKS publication
- signing key lifecycle primitives
- dynamic client registration
- an admin console for tenant and client management
- fixed-whitelist admin login

This phase does not yet deliver end-user interactive login, authorization code execution, user accounts, social login, MFA, or passkey flows.

## Scope

### In Scope

- Multi-tenant tenant model
- Platform-path issuer support
- Tenant custom-domain issuer support
- OpenID Provider metadata endpoint
- JWKS endpoint
- Signing key metadata and active-key selection
- OIDC Dynamic Client Registration
- Admin UI and admin APIs for tenant and client creation
- Fixed-whitelist admin authentication
- Audit events for sensitive administrative actions
- D1 persistence with Drizzle ORM
- KV-backed short-lived token and session storage
- R2-backed private key material storage

### Out of Scope

- Authorization Code + PKCE execution
- User authentication and session flows for relying-party users
- Consent UI
- Refresh token issuance
- Username/password login
- Email magic link or one-time code login
- Passkey login
- Social login providers
- SMS MFA
- TOTP MFA
- Passkey step-up authentication

## Product Constraints

The repository-level constraints remain mandatory:

- TypeScript only
- Hono only for the HTTP application layer
- Cloudflare Workers only
- Cloudflare-native bindings for runtime and storage
- standards-first OIDC/OAuth design
- multi-tenancy modeled from the start

## Architectural Direction

The recommended architecture is a modular monolith with clear boundaries between protocol logic, domain logic, runtime integration, and infrastructure adapters.

One Hono application exposes:

- public OIDC routes
- admin UI routes
- admin API routes

Core rules:

- domain logic should remain separated from direct binding access
- HTTP routing must not contain issuer or client validation rules inline
- D1, KV, and R2 access must be isolated behind adapter modules
- custom-domain issuer handling must not fork the app into alternate runtimes

## System Boundaries

This phase establishes the service as a trusted OIDC issuer platform rather than as a complete end-user authentication product.

The delivered system must be able to:

- resolve the current tenant and issuer from request host and path
- publish issuer-correct discovery metadata
- publish issuer-correct JWKS
- register and manage OIDC clients
- maintain signing keys and expose active public keys
- allow administrators to create tenants and clients from an admin console

The delivered system must not yet pretend to implement endpoints or flows that do not exist. Discovery metadata must only advertise supported capabilities.

## Issuer Model

### Primary Platform Pattern

The default issuer form is path-based under the platform domain:

`https://idp.example.com/t/{tenant}`

Examples:

- `https://idp.example.com/t/acme`
- `https://idp.example.com/t/example-co`

### Custom Domain Pattern

Tenants may configure and verify a custom domain that becomes the full OIDC issuer:

`https://login.acme.com`

If a tenant uses a custom domain as issuer, that domain is authoritative for:

- discovery metadata `issuer`
- `jwks_uri`
- future token `iss`
- future authorization and token endpoint URLs

The system must not return metadata from one issuer while minting tokens for another issuer identity.

### Issuer Resolution Rules

Requests are resolved as follows:

1. If the request host matches a verified tenant custom domain, treat that host root as the issuer.
2. Otherwise, if the request host is the platform domain, require a path prefix `/t/:tenant`.
3. If neither rule resolves a valid issuer, return `404`.

### Issuer Persistence Model

Issuer configuration is modeled separately from the tenant record. This avoids hard-coding a one-to-one relationship between tenant and issuer and leaves room for:

- custom-domain verification state
- issuer migration
- primary issuer switching
- future support for multiple issuer entries per tenant

## Module Layout

Proposed source structure:

```text
src/
  app/
    app.ts
    routes/
      admin.ts
      oidc.ts
  domain/
    admin-auth/
    audit/
    clients/
    keys/
    oidc/
    tenants/
  adapters/
    db/
      d1/
    kv/
    r2/
    crypto/
  ui/
    admin/
  config/
  lib/
```

Module responsibilities:

- `domain/tenants`: tenant entity rules, issuer bindings, domain verification state
- `domain/clients`: client metadata rules, redirect URI validation, registration policies
- `domain/keys`: signing key metadata, active-key selection, rotation state
- `domain/oidc`: discovery composition, issuer resolution, JWKS serialization, registration handlers
- `domain/admin-auth`: whitelist login, session validation, admin identity lookup
- `domain/audit`: audit event schemas and write API
- `adapters/db`: Drizzle D1 schema and repository implementations
- `adapters/kv`: KV-backed session, cache, and short-lived token adapters
- `adapters/r2`: R2-backed key material and object storage adapters
- `adapters/crypto`: JOSE key generation/loading abstractions
- `ui/admin`: tenant and client management screens

## Data Model

The initial persistence design is split across D1 tables, KV namespaces, and an R2 bucket.

### D1 Tables

The structured system-of-record tables should include at least the following.

### `tenants`

Purpose: tenant identity and high-level status.

Suggested columns:

- `id`
- `slug`
- `display_name`
- `status`
- `created_at`
- `updated_at`

### `tenant_issuers`

Purpose: issuer bindings and custom domain modeling.

Suggested columns:

- `id`
- `tenant_id`
- `issuer_type` with values like `platform_path` or `custom_domain`
- `issuer_url`
- `domain`
- `is_primary`
- `verification_status`
- `verified_at`
- `created_at`
- `updated_at`

### `oidc_clients`

Purpose: registered clients.

Suggested columns:

- `id`
- `tenant_id`
- `client_id`
- `client_secret_hash`
- `client_name`
- `application_type`
- `token_endpoint_auth_method`
- `created_by`
- `created_at`
- `updated_at`

### `oidc_client_redirect_uris`

Purpose: normalized redirect URIs.

Suggested columns:

- `id`
- `client_id`
- `redirect_uri`
- `created_at`

### `oidc_client_metadata`

Purpose: dynamic registration metadata that is optional or multi-valued.

Suggested columns:

- `id`
- `client_id`
- `grant_types`
- `response_types`
- `scope`
- `jwks_uri`
- `logo_uri`
- `tos_uri`
- `policy_uri`
- `contacts`
- `software_id`
- `software_version`
- `raw_metadata`

This can be modeled either as explicit JSON columns or split tables. For the first phase, JSON columns for low-frequency registration metadata are acceptable as long as validation is strict at the domain layer.

### `signing_keys`

Purpose: signing key registry and lifecycle state.

Suggested columns:

- `id`
- `tenant_id` nullable if platform-wide keys are used initially
- `kid`
- `alg`
- `kty`
- `public_jwk`
- `private_key_ref`
- `status`
- `activated_at`
- `retire_at`
- `created_at`

Private key material should not be stored inline in D1 rows. The `private_key_ref` should point to an R2 object key or equivalent Cloudflare-native object reference.

### `admin_users`

Purpose: fixed-whitelist admin identities.

Suggested columns:

- `id`
- `email`
- `status`
- `created_at`

### `audit_events`

Purpose: append-only audit log.

Suggested columns:

- `id`
- `actor_type`
- `actor_id`
- `tenant_id`
- `event_type`
- `target_type`
- `target_id`
- `payload`
- `occurred_at`

### KV Namespaces

#### `ADMIN_SESSIONS_KV`

Purpose: short-lived admin sessions keyed by hashed token.

#### `REGISTRATION_TOKENS_KV`

Purpose: Dynamic Client Registration access tokens and other short-lived token state.

### R2 Bucket

#### `KEY_MATERIAL_R2`

Purpose: private signing key material and other object-style security artifacts. D1 stores metadata and references; R2 stores the object body.

## Protocol Surface

### Platform-Path Issuer Routes

- `GET /t/:tenant/.well-known/openid-configuration`
- `GET /t/:tenant/jwks.json`

### Custom-Domain Issuer Routes

- `GET /.well-known/openid-configuration`
- `GET /jwks.json`

### Dynamic Client Registration Routes

The exact path should be emitted from discovery metadata and remain issuer-relative. For platform-path issuers, registration should remain under the tenant path. For custom domains, it should be rooted under the custom domain.

Suggested path shape:

- `POST {issuer}/connect/register`
- `GET {issuer}/connect/register/{clientId}` or issuer-relative admin-backed client read endpoint

The final path naming can be adjusted during implementation, but the following rule is mandatory:

- registration endpoints must be issuer-correct

### Admin Routes

Suggested routes:

- `GET /admin/login`
- `POST /admin/login`
- `POST /admin/logout`
- `GET /admin`
- `GET /admin/tenants`
- `POST /admin/tenants`
- `GET /admin/tenants/:tenantId`
- `POST /admin/tenants/:tenantId/issuers`
- `GET /admin/tenants/:tenantId/clients`
- `POST /admin/tenants/:tenantId/clients`

Admin UI routes and admin JSON APIs may share handlers or be split, but auth checks must be centralized.

## Discovery Metadata

The service should publish conservative metadata. It must only advertise endpoints and capabilities that are actually implemented.

Initial metadata should include at least:

- `issuer`
- `jwks_uri`
- `registration_endpoint`
- `subject_types_supported`
- `id_token_signing_alg_values_supported`

Recommended first values:

- `subject_types_supported`: `["public"]`
- `id_token_signing_alg_values_supported`: implementation choice such as `["ES256"]`

The following fields should be added only when the corresponding protocol endpoints or behaviors are actually implemented:

- `response_types_supported`
- `grant_types_supported`
- `token_endpoint_auth_methods_supported`
- `authorization_endpoint`
- `token_endpoint`

Even if `authorization_code` is declared as the strategic direction, metadata should not advertise authorization or token endpoints until those endpoints are implemented, unless there is a deliberate placeholder strategy with clear non-production gating. The safer default is to omit unfinished endpoint URLs and capability declarations.

## JWKS Behavior

JWKS must return only public keys.

Rules:

- include all currently valid public keys that may verify issued tokens
- ensure the currently active signing key is present
- retain retiring keys long enough for token verification overlap
- never expose private key material
- keep `kid` stable once published

If keys are tenant-specific in the future, the resolver must select keys by issuer context. The initial phase may use a platform signing key model if that accelerates delivery, but the table structure should not block per-tenant keys later.

## Signing Key Lifecycle

This phase needs key lifecycle primitives, not a full automated rotation platform.

Required behaviors:

- create a signing key record
- mark one key active for an issuer or tenant context
- expose active and still-valid public keys in JWKS
- record activation and retirement timestamps
- make future rotation possible without schema changes

Non-goals for this phase:

- automatic scheduled rotation
- HSM integration
- distributed key ceremony workflows

## Dynamic Client Registration

Dynamic Client Registration is in scope, but it should be controlled rather than anonymously open.

Recommended initial policy:

- registration follows the standard Dynamic Client Registration shape but is protected by an initial access token or equivalent management credential
- client metadata is validated strictly with Zod
- invalid combinations are rejected before persistence
- generated client secrets are returned only once in plaintext
- stored secrets are hashed, never stored plaintext
- registration access tokens are stored in KV rather than in the structured client row
- registration writes an audit event

Validation requirements include:

- redirect URIs must be valid absolute URIs
- insecure redirect URI rules must be explicit for local development and forbidden in production paths unless intentionally allowed
- `grant_types`, `response_types`, and auth methods must be semantically compatible
- duplicate `client_id` must be impossible
- metadata returned to the caller must reflect persisted state

If client read support is implemented in this phase, it should use a registration access token model compatible with the Dynamic Client Registration protocol instead of a custom admin-only read contract.

## Admin Authentication

The admin console is intentionally separate from future end-user authentication.

Initial admin auth rules:

- only preconfigured whitelist accounts may log in
- no self-service signup
- no tenant-driven admin federation in this phase
- admin sessions are scoped to management access only and stored in KV
- admin login failure and success are audited

The exact login mechanism for whitelist admins can be lightweight in this phase, but it must not be conflated with the future public IdP login system. If passwordless email for admins is chosen later, it should still remain an admin-only auth path.

## Error Handling

Protocol errors and system errors must be separated.

### Protocol Errors

Use standards-aligned status codes and bodies for:

- invalid issuer resolution
- invalid client metadata
- unauthorized registration
- unsupported metadata values
- malformed redirect URIs

### System Errors

Map internal failures to generic `5xx` responses. Do not leak:

- storage adapter details
- private key references
- domain verification internals
- stack traces

### Not Found Handling

For discovery and JWKS:

- unresolved tenant or issuer returns `404`
- do not silently return empty metadata or a generic issuer

### Admin Auth Errors

- unauthenticated admin access redirects to login UI or returns `401` for API callers
- unauthorized admin actions return `403`

## Audit Logging

Sensitive operations that must emit audit events:

- admin login success
- admin login failure
- tenant creation
- issuer creation
- custom-domain verification state changes
- primary issuer switching
- client registration
- client secret reset
- signing key creation
- signing key activation
- signing key retirement

## Testing Strategy

Testing priority is protocol correctness and issuer consistency.

### Unit Tests

Cover:

- issuer resolution
- discovery metadata composition
- client metadata validation
- redirect URI validation
- signing key selection

### Integration Tests

Run Hono app integration tests for:

- platform-path issuer discovery
- custom-domain issuer discovery
- platform-path JWKS
- custom-domain JWKS
- controlled client registration
- admin auth happy path
- admin auth rejection path

### Persistence Tests

Cover repository behavior for:

- tenant creation
- issuer lookup by host/path
- client registration persistence
- signing key lookup

### Contract Tests

Assert that issuer-derived URLs are consistent:

- `issuer`
- `jwks_uri`
- `registration_endpoint`

This is especially important for custom domains. A request received on a tenant custom domain must not emit platform-domain URLs in metadata.

## Implementation Sequence

Recommended implementation order:

1. Bootstrap the workspace with `pnpm`, TypeScript strict mode, Hono, Vitest, Zod, Drizzle D1 schema support, Workers bindings, and Wrangler configuration.
2. Implement tenant and issuer models with host/path resolution.
3. Implement discovery metadata and JWKS endpoints.
4. Implement signing key metadata in D1 and private key material storage in R2.
5. Implement Dynamic Client Registration with strict validation, KV-backed registration tokens, and audited writes.
6. Implement fixed-whitelist admin auth with KV-backed admin sessions.
7. Implement admin UI and APIs for tenants and clients.
8. Add documentation and Cloudflare binding setup.

Each step should produce working, testable software rather than placeholders.

## Risks and Design Notes

### Metadata Overstatement Risk

Advertising unsupported OIDC endpoints too early creates a false contract with relying parties. The implementation must keep discovery metadata conservative.

### Custom Domain Consistency Risk

Custom-domain issuers can easily regress into mixed-domain output. This must be prevented by centralizing issuer resolution and metadata composition.

### Key Storage Risk

Signing key support must not encourage plaintext private-key storage. Even if the first development adapter is simple, the abstraction should preserve a secure upgrade path.

### Admin/Auth Coupling Risk

The admin console must not become the accidental foundation for the public user authentication model. Keep admin auth isolated.

## Deferred Work After This Phase

Planned next layers after the foundation is stable:

- authorization code + PKCE
- end-user account model
- username/password and email sign-in
- WebAuthn and passkey flows
- MFA enrollment and challenge flows
- social login provider adapters
- consent, session, and token issuance flows

## Acceptance Criteria

This design is successful when the implementation can demonstrate:

- a tenant can be created
- the tenant has a resolvable issuer
- discovery metadata is served correctly for platform-path issuers
- discovery metadata is served correctly for verified custom-domain issuers
- JWKS is issuer-correct and exposes public keys only
- a client can be registered with validated metadata
- client secrets are stored hashed and only returned once
- admins can log in through the whitelist-only admin path
- sensitive management actions produce audit events
- the Workers Hono application can run with D1, KV, and R2 bindings configured
