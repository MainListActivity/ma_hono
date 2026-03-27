# SPA Client And Custom Access Token Claims Design

## Goal

Enable `ma_hono` to act like an Auth0-style OIDC provider for third-party single-page applications that authenticate users with Authorization Code + PKCE and then present `ma_hono`-issued access tokens to downstream resource servers such as SurrealDB.

This slice adds a first-class SPA client profile, per-client access token audience configuration, and per-client custom access token claims that support both fixed values and a constrained set of user-field mappings.

## Problem Statement

The current codebase already provides the OIDC foundation required for discovery, JWKS publication, Authorization Code + PKCE, and token issuance. It also provides an admin flow for creating OIDC clients.

However, the current client model is still biased toward the earlier OIDC foundation assumptions:

- `web` applications are treated as confidential clients
- access token `aud` defaults to the OAuth `client_id`
- clients cannot configure custom access token claims
- the admin UI cannot model an Auth0-style SPA application directly

That makes it awkward to use `ma_hono` as the issuer for another SPA that expects the same integration shape described in SurrealDB's Auth0 tutorial.

## User Outcome

An administrator can create a tenant-scoped SPA client from the admin UI, configure its redirect URIs, configure the access token audience, and define custom access token claims for that client.

During login:

1. the SPA redirects the browser to `ma_hono`'s `/authorize` endpoint using PKCE
2. `ma_hono` authenticates the user and returns an authorization code
3. the SPA exchanges the code at `/token` without a client secret
4. `ma_hono` issues an access token whose `aud` matches the configured audience and whose payload includes the configured custom claims
5. the downstream resource server validates the token through discovery metadata and JWKS

## Scope

### In Scope

- New SPA-oriented client profile in the `ma_hono` product model
- Public SPA clients using Authorization Code + PKCE
- Per-client access token audience configuration
- Per-client custom access token claims for access tokens only
- Two claim source types:
  - fixed literal value
  - user-field mapping from a constrained allowlist
- Admin API and admin UI support for creating and viewing these settings
- Token issuance changes so `aud` and custom claims come from client configuration
- Tests covering schema validation, admin creation flows, and token issuance

### Out of Scope

- Arbitrary scripting or expression-based claim mapping
- Conditional claim rules
- ID token custom claims
- New consent behavior
- Dynamic scopes that alter claim shape
- Resource indicator support beyond a single configured audience
- Token introspection

## Existing System Context

The current implementation already contains the main protocol surface needed for this work:

- discovery metadata via [`src/domain/oidc/discovery.ts`](/Users/y/IdeaProjects/ma_hono/src/domain/oidc/discovery.ts)
- authorization request validation via [`src/domain/authorization/authorize-request.ts`](/Users/y/IdeaProjects/ma_hono/src/domain/authorization/authorize-request.ts)
- token issuance via [`src/domain/tokens/token-service.ts`](/Users/y/IdeaProjects/ma_hono/src/domain/tokens/token-service.ts)
- client registration logic via [`src/domain/clients/register-client.ts`](/Users/y/IdeaProjects/ma_hono/src/domain/clients/register-client.ts)
- admin client creation API via [`src/app/app.ts`](/Users/y/IdeaProjects/ma_hono/src/app/app.ts)
- admin client management UI via [`admin/src/pages/TenantClientsPage.tsx`](/Users/y/IdeaProjects/ma_hono/admin/src/pages/TenantClientsPage.tsx)

The design should extend these paths rather than introducing a parallel client model.

## Approaches Considered

### Approach 1: Relax Existing `web` Clients In Place

Treat some `web` clients as public clients by allowing `token_endpoint_auth_method = none` without adding any new product-level profile.

Pros:

- smallest schema delta
- minimal implementation changes

Cons:

- product semantics become unclear in the admin UI
- difficult to distinguish SPA constraints from confidential web app constraints
- validation logic becomes more implicit and more fragile over time

### Approach 2: Add A Product-Level Client Profile

Keep OIDC metadata aligned with standards but add an internal `clientProfile` field that reflects how `ma_hono` wants to model client types.

Profiles:

- `spa`
- `web`
- `native`

Pros:

- explicit product semantics
- clear admin UI and validation behavior
- preserves standards-based OIDC fields while allowing product-specific rules

Cons:

- requires a schema migration
- requires mapping logic between profile and OIDC metadata

### Approach 3: Generalized Token Profile Engine

Abstract audiences, claims, and token behavior into a highly configurable policy system.

Pros:

- maximal flexibility

Cons:

- substantially more complexity than the current requirement needs
- high risk of over-design in a security-sensitive area

## Recommended Approach

Use Approach 2.

`ma_hono` should add a product-level client profile while keeping standard OIDC fields explicit in storage and APIs. This makes SPA support intentional rather than incidental, and it gives the admin UI a clear, stable model for creating Auth0-like SPA clients.

## Design

### Client Model

Extend the client domain model with:

- `clientProfile: "spa" | "web" | "native"`
- `accessTokenAudience: string | null`
- `accessTokenCustomClaims: AccessTokenCustomClaim[]`

New claim type:

```ts
type AccessTokenClaimSourceType = "fixed" | "user_field";

type AccessTokenClaimUserField =
  | "id"
  | "email"
  | "email_verified"
  | "username"
  | "display_name";

interface AccessTokenCustomClaim {
  id: string;
  clientId: string; // internal oidc_clients.id UUID
  tenantId: string;
  claimName: string;
  sourceType: AccessTokenClaimSourceType;
  fixedValue: string | null;
  userField: AccessTokenClaimUserField | null;
  createdAt: string;
  updatedAt: string;
}
```

### Profile Semantics

`clientProfile` determines product constraints:

- `spa`
  - `applicationType` must be `web`
  - `tokenEndpointAuthMethod` must be `none`
  - `grantTypes` must be exactly `["authorization_code"]`
  - `responseTypes` must be exactly `["code"]`
  - PKCE remains mandatory through the existing `/authorize` validation
  - `accessTokenAudience` is required
- `web`
  - current confidential web-client behavior remains valid
  - `tokenEndpointAuthMethod` must not be `none`
  - `accessTokenAudience` optional
- `native`
  - current native behavior remains valid
  - `tokenEndpointAuthMethod = none` remains allowed
  - `accessTokenAudience` optional

This keeps the existing public/native path intact while adding a separate, explicit SPA path.

### Access Token Claims Behavior

Custom claim rules apply only to access tokens.

Access token construction becomes:

1. derive base claims
2. set `aud` from `client.accessTokenAudience` when configured, otherwise fall back to the OAuth `client_id`
3. preserve `client_id` as the OAuth client identifier
4. append client-configured custom claims

Claim resolution rules:

- `fixed` claims copy the configured literal string value into the token
- `user_field` claims read from the authenticated user record
- if a user-mapped field is `null`, empty, or absent, omit that custom claim from the token
- custom claims must not override reserved core claims:
  - `iss`
  - `sub`
  - `aud`
  - `exp`
  - `iat`
  - `nbf`
  - `jti`
  - `scope`
  - `client_id`
  - `nonce`

The server should reject client configuration that attempts to register a reserved claim name.

### Database Changes

Add columns to `oidc_clients`:

- `client_profile TEXT NOT NULL DEFAULT 'web'`
- `access_token_audience TEXT`

Add new table `client_access_token_claims`:

- `id TEXT PRIMARY KEY`
- `client_id TEXT NOT NULL` referencing `oidc_clients.id` with cascade delete
- `tenant_id TEXT NOT NULL` referencing `tenants.id` with cascade delete
- `claim_name TEXT NOT NULL`
- `source_type TEXT NOT NULL`
- `fixed_value TEXT`
- `user_field TEXT`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`

Indexes and constraints:

- index on `tenant_id`
- index on `client_id`
- unique `(client_id, claim_name)` to avoid duplicate claim definitions for the same client
- validation in application code to ensure:
  - `fixed_value` is present only for `fixed`
  - `user_field` is present only for `user_field`
  - `user_field` belongs to the allowed enum

The custom claims should live in a separate table instead of a JSON blob because:

- validation stays explicit
- admin edit paths remain straightforward
- auditability is better
- the structure matches the repository's existing normalized policy tables

### Repository Changes

Add a dedicated repository:

- `AccessTokenClaimRepository`

Responsibilities:

- create claims for a client
- replace all claims for a client
- list claims by internal client id

This keeps client persistence focused and avoids overloading the existing `ClientRepository` interface with claim-specific write behavior.

### Registration Validation

The current registration schema in [`src/domain/clients/registration-schema.ts`](/Users/y/IdeaProjects/ma_hono/src/domain/clients/registration-schema.ts) should expand to validate:

- `client_profile`
- `access_token_audience`
- `access_token_custom_claims`

Validation rules:

- `client_profile` required for admin-created clients
- when `client_profile = "spa"`:
  - `application_type` must be `web`
  - `token_endpoint_auth_method` must be `none`
  - `grant_types` must equal `["authorization_code"]`
  - `response_types` must equal `["code"]`
  - `access_token_audience` must be non-empty
- when `client_profile = "web"`:
  - `token_endpoint_auth_method` must be `client_secret_basic` or `client_secret_post`
- claim names must be non-empty and not reserved
- fixed claims require a non-empty `fixed_value`
- user-field claims require an allowed `user_field`

### Admin API Changes

Extend the existing admin client creation endpoint in [`src/app/app.ts`](/Users/y/IdeaProjects/ma_hono/src/app/app.ts) so that it accepts and returns:

- `client_profile`
- `access_token_audience`
- `access_token_custom_claims`

The admin list/get endpoints should also include these fields so the UI can render them later without needing parallel APIs.

The public dynamic client registration endpoint should not be widened to support arbitrary claim configuration in this slice. This feature is intended for trusted tenant administration through the admin UI and admin API, not for open-ended third-party self-registration.

### Admin UI Changes

The client creation flow in [`admin/src/pages/TenantClientsPage.tsx`](/Users/y/IdeaProjects/ma_hono/admin/src/pages/TenantClientsPage.tsx) should add:

- `Application Profile` selector:
  - `SPA`
  - `Web`
  - `Native`
- `Access Token Audience` field
- `Access Token Claims` editor

Behavior:

- selecting `SPA` auto-sets:
  - `application_type = web`
  - `token_endpoint_auth_method = none`
  - `grant_types = ["authorization_code"]`
  - `response_types = ["code"]`
- selecting `Web` keeps current confidential client options
- selecting `Native` keeps current native options

Claim editor behavior:

- allow multiple rows
- each row contains:
  - claim name input
  - source type select
  - fixed value input or user-field select
- user-field select options are limited to:
  - `id`
  - `email`
  - `email_verified`
  - `username`
  - `display_name`

The client detail/list views should surface:

- profile
- configured audience
- configured custom claims count

That gives administrators enough visibility to confirm the client matches downstream expectations such as SurrealDB namespace, database, and access control claim naming.

### Token Service Changes

The token flow in [`src/domain/tokens/token-service.ts`](/Users/y/IdeaProjects/ma_hono/src/domain/tokens/token-service.ts) currently uses the OAuth client id as the access token audience.

It should be changed to:

- load the full client record including access token audience and custom claims
- build ID token claims exactly as today
- build access token claims with:
  - `aud = client.accessTokenAudience ?? client.clientId`
  - `client_id = client.clientId`
- resolve custom claims from the authenticated user and merge them into the access token payload

If the custom claim resolution layer cannot load the user record, token issuance must fail with a server error rather than silently issuing incomplete security-sensitive tokens. This is stricter than the missing-field behavior described above:

- missing optional field value on a loaded user: omit the individual claim
- inability to load the user needed to resolve mappings: fail the token exchange

### Audit Events

Record an audit event when an admin creates or updates client token settings.

Suggested events:

- `oidc.client.registered`
- `oidc.client.token_profile.updated`

The payload should include:

- `client_profile`
- `access_token_audience`
- summary of configured custom claims

Do not log secret values beyond what is already intentionally part of client metadata.

## Data Flow

### Client Creation

1. Admin opens tenant client page
2. Admin selects `SPA`
3. UI forces public SPA-safe metadata
4. Admin supplies redirect URIs, audience, and custom claim rules
5. Admin API validates and stores:
   - client row
   - registration access token
   - default auth method policy
   - access token custom claim rows
6. API returns the created client and optional client secret
   - SPA clients will have no client secret

### Token Issuance

1. User authenticates through `/authorize`
2. Client exchanges the code at `/token`
3. Server authenticates the client according to its configured method
4. Server loads client metadata and user record
5. Server builds:
   - ID token with current behavior
   - access token with configured audience and custom claims
6. Server signs tokens with the tenant signing key

## Error Handling

Admin creation/update failures:

- invalid profile/auth method combinations return `400`
- missing audience for SPA returns `400`
- reserved claim names return `400`
- malformed claim rows return `400`

Token issuance failures:

- invalid client authentication still returns existing `invalid_client` behavior
- user lookup failure during mapped claim resolution returns `server_error`
- invalid persisted claim configuration should also return `server_error` and be treated as an operator misconfiguration

## Testing Strategy

Add or update tests in these areas:

- registration schema validation
  - reject SPA without audience
  - reject SPA with confidential auth method
  - reject reserved claim names
  - reject bad user-field mappings
- admin client creation endpoint
  - create SPA client with no secret
  - persist configured audience
  - persist configured custom claims
- token endpoint
  - access token uses configured audience
  - fixed claims appear in access token
  - user-field mapped claims appear when user data exists
  - missing mapped optional field omits that claim
  - ID token does not include custom access token claims
- admin UI tests if present, otherwise component-level logic review

## Security Notes

- Reserved claims must be protected from override
- Public SPA clients still rely on PKCE and redirect URI validation
- Claim names should prefer namespaced URIs to reduce collisions
- Claim mapping must be allowlist-based, not arbitrary object-path evaluation
- The custom-claims feature should remain admin-only in this phase

## Rollout Notes

This feature is backward-compatible for existing clients if the migration defaults are:

- `client_profile = "web"`
- `access_token_audience = null`

Existing tokens continue to behave as before unless a client is newly created or explicitly updated with a custom audience or custom claim configuration.

## Summary

This design adds an explicit SPA client profile and a constrained access token customization model that is sufficient for SurrealDB-style integrations without introducing a general-purpose token policy engine.

It keeps the system standards-first, tenant-scoped, and compatible with the existing OIDC foundation while exposing the product-level configuration needed to make `ma_hono` usable as the OIDC issuer for third-party SPAs.
