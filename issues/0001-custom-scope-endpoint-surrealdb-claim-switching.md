Status: todo
Label: enhancement
Type: AFK

# Add custom scope endpoint for SurrealDB claim switching

## Parent

- `/Users/y/IdeaProjects/surreal_ck/.scratch/workspace-as-db/issues/03-workspace-scope-module.md`
- `/Users/y/IdeaProjects/surreal_ck/.scratch/workspace-as-db/issues/06-workspace-create-lifecycle.md`
- `/Users/y/IdeaProjects/surreal_ck/.scratch/web-frontend-migration/issues/05-workspace-switcher.md`

## What to build

Add a tenant-scoped issuer endpoint that lets the same authenticated OIDC client switch a user's mutable SurrealDB token claims and receive a freshly signed token response immediately.

Endpoint shape:

- Platform issuer: `POST https://o.<root-domain>/t/<tenant-slug>/scope`
- Custom-domain issuer: `POST https://<custom-issuer-domain>/scope`

This is a project-specific extension, not an OIDC standard endpoint. Standard OIDC/OAuth token issuance remains on `/token`; this endpoint exists to support the `surreal_ck` Workspace Scope Module flow where a user switches workspace and needs a token whose claims point at the new SurrealDB database/access pair.

The initial mutable claim allowlist is:

- `https://surrealdb.com/db`
- `https://surrealdb.com/ac`

`can_create_workspace` is deprecated and must not be mutable through this endpoint.

The endpoint must authenticate the OIDC client with its `client_id` and `client_secret`, require the caller to present the current end-user token as `subject_token`, then mint the replacement for the same issuer tenant, subject, and client. Do not allow a caller to mint arbitrary-subject tokens from a platform-level management secret.

The success response should return a fresh token response directly from `/scope`, including at least a new `access_token`, `token_type`, `expires_in`, and `scope`. Include `id_token` only if the existing local token response contract requires it for the same client flow. Existing refresh-token behavior must remain compatible; `/token` should continue to work unchanged.

## Acceptance criteria

- [ ] `POST /t/:tenant/scope` accepts an authenticated client request and returns a freshly signed token response containing updated allowlisted claims.
- [ ] Custom-domain issuer requests support `POST /scope` with the same behavior and issuer-correct token signing.
- [ ] The implementation rejects invalid auth, unknown tenant, invalid subject token, tenant/client mismatch, unsupported claim names, invalid `https://surrealdb.com/ac` values, and malformed claim values with JSON errors.
- [ ] Only the allowlisted mutable claims can be changed; reserved JWT/OIDC claims and arbitrary custom claims cannot be overwritten through this endpoint.
- [ ] The returned access token contains the updated `https://surrealdb.com/db` and/or `https://surrealdb.com/ac` values and validates against the tenant's JWKS.
- [ ] Existing `/authorize`, `/token`, refresh-token rotation, discovery metadata, and configured access-token custom claim behavior continue to pass existing tests.
- [ ] Audit events are recorded for successful and failed scope switches without logging access tokens, subject tokens, or client secrets.
- [ ] Tests cover successful db/ac switch, custom-domain issuer signing, invalid client authentication, forbidden claim name, invalid `ac`, cross-tenant isolation, invalid subject token, and returned-token validation.

## Blocked by

None - can start immediately
