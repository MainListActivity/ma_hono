# Handoff: content_reader.v1 scope exchange (IDP-LCR-01)

Contract id: `content_reader.v1`  
Endpoint (unchanged): `POST /t/:tenant/scope` or custom-domain `POST /scope`  
Auth: confidential client only (`client_secret_basic` / `client_secret_post`)

Issuance correctness ≠ database permission. SurrealDB RECORD / schema enforcement remains SCK-LCA-03.

## Request

```json
{
  "subject_token": "<workspace access_token>",
  "claims": {
    "ac": "content_reader",
    "db": "platform_content",
    "workspace_id": "ws_alpha",
    "entitlement_revision": "entrev_2026_09_24",
    "lease_end": 1780000000
  }
}
```

| Field | Rule |
|---|---|
| `subject_token` | Current workspace access token for the same client/issuer/audience; must not itself be `content_reader` |
| `claims.ac` | Must be exactly `content_reader` (branch selector) |
| `claims.db` | Must be on IdP allowlist (default `platform_content`) |
| `claims.workspace_id` | App-verified workspace identity string (`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`) |
| `claims.entitlement_revision` | App-verified revision identity (same pattern) |
| `claims.lease_end` | Unix seconds; app-verified authorization lease end |

No other claim keys are accepted in this mode (no `RL`, entitlement lists, publisher flags, alternate `ac`/`db`).

Browser-supplied entitlement facts must not be forwarded as authority. Only the trusted app Workspace Scope Module should call this endpoint after verifying membership and commercial eligibility.

## Success response

Same shape as workspace `/scope` switch; not cacheable (`Cache-Control: no-store`).

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 120,
  "scope": "openid profile"
}
```

### Issued access token claims (verify via JWKS)

| Claim | Value |
|---|---|
| `sub` | Same human as subject token |
| `ac` | `content_reader` |
| `db` | Allowlisted content database |
| `workspace_id` | Echo of request identity |
| `entitlement_revision` | Echo of request identity |
| `exp` | `iat + expires_in` |
| `aud` / `client_id` / `iss` / `scope` | Bound to the confidential client and issuer |

TTL = `min(subject remaining lifetime, lease_end - now, server max TTL)`.
Default server max TTL: 900 seconds. Clients cannot override `exp`.

`RL` is intentionally omitted. Absence of `RL` is not a RECORD-permission proof; RECORD is enforced downstream.

## Errors

| `error` | Meaning |
|---|---|
| `invalid_client` | Bad confidential client auth |
| `invalid_grant` | Invalid identity: bad/forged/expired subject token, client/audience mismatch, disabled user |
| `invalid_scope` | Client/tenant/db not allowlisted, or subject token is already `content_reader` (no elevation) |
| `invalid_lifetime` | `lease_end` expired/non-positive/out of range relative to now |
| `invalid_request` | Malformed claims / unknown keys |
| `temporarily_unavailable` | Signer/config unavailable for content_reader issuance |

## Claim merge order

**Workspace switch (`ac` = admin/participant):**  
configured claims (fixed → user_field → hook, config order) then request claims overlay.

**content_reader:**  
1. Resolve configured claims the same way.  
2. Drop purpose-boundary keys from that result: `ac`, `db`, `workspace_id`, `entitlement_revision`, `RL`.  
3. Overlay fixed content_reader claims.  
Config/hooks cannot widen purpose or inject publisher/workspace admin rights.

## Session independence

Minting a content_reader token does not revoke or rewrite the workspace token, durable default scope, or last-selected workspace. Keep both tokens client-side. A content_reader token cannot call `/scope` to obtain admin/participant/publisher credentials.

## IdP deployment config (`platform_config`)

| Key | Required | Example |
|---|---|---|
| `content_reader_allowed_client_ids` | yes | `surreal_ck_web` |
| `content_reader_allowed_tenant_ids` | no (empty = all) | `tenant_acme` |
| `content_reader_allowed_databases` | no (default `platform_content`) | `platform_content` |
| `content_reader_max_ttl_seconds` | no (default `900`) | `900` |

Until `content_reader_allowed_client_ids` is set, content_reader requests return `invalid_scope`.

## Deployment order

1. Deploy ma_hono with this change.
2. Confirm the four `content_reader_*` platform_config rows already provisioned for the surreal_ck confidential client / tenants / content DB; do not insert duplicates.
3. surreal_ck Workspace Scope Module calls `/scope` with the contract above (server-side only).
4. Proceed with SCK-LCA-03 consumption + SurrealDB RECORD verification.

## Negative fixtures (IdP Vitest)

Covered in `tests/oidc/content-reader-scope.test.ts`:

- valid JWKS-verified issuance
- workspace + content tokens coexist
- elevation from content_reader → admin rejected
- cross-tenant / non-allowlisted client
- wrong audience / cross-client subject
- disabled user
- forged / expired subject token
- past lease → `invalid_lifetime`; long lease capped by server max
- arbitrary claim injection / wrong `db`
- hook/fixed claims cannot override purpose
- unconfigured policy → `invalid_scope`
- existing admin/participant `/scope` regression (`tests/oidc/scope-endpoint.test.ts`)

## Verify

```bash
pnpm test
pnpm typecheck
pnpm vitest run tests/oidc/content-reader-scope.test.ts tests/oidc/scope-endpoint.test.ts
```
