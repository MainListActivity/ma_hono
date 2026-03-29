# Client Token TTL And Refresh Token Design

**Date:** 2026-03-29
**Status:** Approved
**Scope:** Admin UI, client auth policy API, OIDC token endpoint, token persistence

---

## Overview

Add per-auth-method token TTL configuration to each client's auth policy and implement OAuth 2.1 style refresh token support for the OIDC token endpoint.

Each client auth method row gains a configurable `token_ttl_seconds` field, defaulting to `3600`. The configured TTL applies to both the `access_token` and `id_token` issued for that authentication method. Refresh tokens are opaque, stored hashed, rotated on every successful use, and expire absolutely after 60 days.

---

## Requirements

### Per-auth-method token TTL

- The admin `AUTH` modal for a client shows a token TTL input for every auth method.
- The unit is seconds.
- Default value for every method is `3600`.
- Tenant admins may edit the value directly.
- The configured TTL applies to:
  - `expires_in` in the token response
  - `exp` in the issued `access_token`
  - `exp` in the issued `id_token`
- The TTL used for a token exchange is determined by the login method that originally authenticated the user.

### Refresh token support

- `authorization_code` token exchange now returns `refresh_token` in addition to `access_token` and `id_token`.
- `grant_type=refresh_token` is supported at `/token`.
- Refresh tokens are opaque random values, not JWTs.
- The server stores only a hash of the refresh token.
- Refresh tokens expire 60 days after initial issuance.
- Refresh tokens are rotated on every successful refresh.
- A successful refresh returns:
  - new `access_token`
  - new `id_token`
  - new `refresh_token`
  - unchanged `scope`
  - `token_type=Bearer`
  - `expires_in` derived from the original auth method TTL
- Refresh does not expand scope, change user, or change client binding.
- Reuse of a consumed refresh token returns `invalid_grant`.

---

## Data Model

### `client_auth_method_policies`

Add integer columns with default `3600`:

- `password_token_ttl_seconds`
- `magic_link_token_ttl_seconds`
- `passkey_token_ttl_seconds`
- `google_token_ttl_seconds`
- `apple_token_ttl_seconds`
- `facebook_token_ttl_seconds`
- `wechat_token_ttl_seconds`

These values are required and must be positive integers.

### `refresh_tokens`

Create a new table:

```sql
refresh_tokens (
  id                   TEXT PRIMARY KEY,
  tenant_id            TEXT NOT NULL,
  issuer               TEXT NOT NULL,
  client_id            TEXT NOT NULL,
  user_id              TEXT NOT NULL,
  scope                TEXT NOT NULL,
  auth_method          TEXT NOT NULL,
  token_hash           TEXT NOT NULL,
  absolute_expires_at  TEXT NOT NULL,
  consumed_at          TEXT,
  parent_token_id      TEXT,
  replaced_by_token_id TEXT,
  created_at           TEXT NOT NULL
)
```

Constraints and indexes:

- foreign keys:
  - `tenant_id -> tenants.id`
  - `(tenant_id, client_id) -> oidc_clients(tenant_id, client_id)`
  - `(tenant_id, user_id) -> users(tenant_id, id)`
- unique active token hash lookup
- tenant/client/user indexes for auditability and cleanup

`auth_method` stores the original authentication method used to establish the token family, for example `password`, `magic_link`, or `passkey`. Refresh operations keep using that method's TTL.

---

## Domain Model

### `ClientAuthMethodPolicy`

Each method gains `tokenTtlSeconds`:

```ts
password: { enabled: boolean; allowRegistration: boolean; tokenTtlSeconds: number };
emailMagicLink: { enabled: boolean; allowRegistration: boolean; tokenTtlSeconds: number };
passkey: { enabled: boolean; allowRegistration: boolean; tokenTtlSeconds: number };
google: { enabled: boolean; tokenTtlSeconds: number };
apple: { enabled: boolean; tokenTtlSeconds: number };
facebook: { enabled: boolean; tokenTtlSeconds: number };
wechat: { enabled: boolean; tokenTtlSeconds: number };
```

### Refresh token record

Add a domain type and repository for refresh token families:

- create token
- find active token by hash
- consume and rotate atomically
- optionally mark replacement linkage

---

## Token Behavior

### Authorization code exchange

On successful `grant_type=authorization_code`:

1. Authenticate the client exactly as today.
2. Validate and consume the authorization code exactly as today.
3. Determine the login auth method for the code exchange.
4. Load the client's auth method policy.
5. Resolve the method-specific `token_ttl_seconds`, defaulting to `3600` when no policy row exists.
6. Issue `access_token` and `id_token` with that TTL.
7. Create and persist a refresh token record with:
   - same tenant
   - same issuer
   - same client
   - same user
   - same scope
   - original auth method
   - `absolute_expires_at = now + 60 days`
8. Return the opaque refresh token string in the response.

### Refresh token exchange

On `grant_type=refresh_token`:

1. Authenticate client using the same token endpoint auth rules.
2. Require a non-empty `refresh_token` parameter.
3. Hash the supplied token and load an active record.
4. Validate tenant, issuer, client, and absolute expiry.
5. Reject consumed or expired tokens with `invalid_grant`.
6. Atomically consume the current record.
7. Issue new `access_token` and `id_token` using the original auth method TTL.
8. Create a replacement refresh token with the same absolute expiry window.
9. Link old and new records via `parent_token_id` / `replaced_by_token_id`.
10. Return the rotated token set.

---

## API Changes

### Admin client auth policy wire format

Each method object gains `token_ttl_seconds`.

Example:

```json
{
  "password": {
    "enabled": true,
    "allow_registration": true,
    "token_ttl_seconds": 3600
  },
  "magic_link": {
    "enabled": true,
    "allow_registration": false,
    "token_ttl_seconds": 7200
  },
  "passkey": {
    "enabled": true,
    "allow_registration": false,
    "token_ttl_seconds": 1800
  },
  "google": {
    "enabled": false,
    "token_ttl_seconds": 3600
  },
  "mfa_required": false
}
```

PATCH semantics remain partial merge. If `token_ttl_seconds` is omitted for a method, the existing value is preserved.

### OIDC discovery metadata

`grant_types_supported` becomes:

```json
["authorization_code", "refresh_token"]
```

### OIDC token response

Success responses now include `refresh_token`.

---

## Admin UI

In `admin/src/pages/TenantClientsPage.tsx`, the `AUTH` modal table changes from:

- method
- enabled
- allow reg.

to:

- method
- enabled
- allow reg.
- token ttl (seconds)

Behavior:

- input is numeric
- default value shows as `3600`
- social login rows keep `allow reg.` as `—`
- save submits the full edited values through the existing PATCH endpoint

---

## Validation

- `token_ttl_seconds` must be an integer
- `token_ttl_seconds` must be greater than zero
- reject malformed JSON bodies with `400 invalid_request`
- reject invalid refresh token requests with:
  - `invalid_request` when required fields are missing
  - `invalid_grant` when the refresh token is unknown, expired, consumed, or bound to another client or issuer
  - `unsupported_grant_type` for unknown grant types

---

## Testing

Add or extend tests for:

- admin auth policy PATCH accepts and persists `token_ttl_seconds`
- admin client GET returns `token_ttl_seconds`
- authorization code exchange returns `refresh_token`
- authorization code exchange uses auth-method TTL for `expires_in` and JWT `exp`
- refresh token exchange returns rotated token set
- reused refresh token is rejected
- refresh token bound to another client is rejected
- discovery advertises `refresh_token`

