# Admin service principals (revocable machine tokens)

Machine-facing admin credentials for the invite / provisioning path. Opaque bearer tokens; only a SHA-256 base64url hash is stored. Tokens are individually revocable.

## What this is for

Surreal CK (and similar callers) need to:

1. `GET /admin/tenants` — resolve tenant by slug (`tenant.read`)
2. `GET /admin/tenants/:tenantId/users` — look up users (`user.read`)
3. `POST /admin/tenants/:tenantId/users` — provision a user (`user.provision`)

without embedding the human admin bootstrap password in application secrets.

## Red line: human admin password

- Human admin login remains whitelist email + one shared PBKDF2 bootstrap hash.
- Service configuration **must not** reference the human admin password.
- Putting the admin password into GitHub secrets, CI env, or app config is a **red line**.
- Rotating a service principal never touches the human password.

`management_api_token` remains client-registration only. It is not a substitute for these principals and cannot call the user-provision routes.

## Allowed scopes

| Scope | Route |
| --- | --- |
| `tenant.read` | `GET /admin/tenants` |
| `user.read` | `GET /admin/tenants/:tenantId/users` |
| `user.provision` | `POST /admin/tenants/:tenantId/users` |

Any other `/admin/*` route returns **403** for a service principal (including mint/revoke/list of principals, tenant create/delete, clients, key rotate).

## Auth outcomes

| Condition | Status |
| --- | --- |
| Missing / malformed / unknown bearer | 401 |
| Hash found, `status=revoked` | 403 |
| Active principal, route outside its scopes | 403 |

## Mint (human admin session only)

```bash
# 1. Human admin login (interactive / operator machine only)
curl -X POST https://o.maplayer.top/admin/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<whitelist-email>","password":"<bootstrap-password>"}'
# → { "session_token": "..." }

# 2. Mint a principal
curl -X POST https://o.maplayer.top/admin/service-principals \
  -H "Authorization: Bearer <session_token>" \
  -H "Content-Type: application/json" \
  -d '{"label":"surreal-ck-invite","scopes":["tenant.read","user.read","user.provision"]}'
# → { "id":"...", "label":"...", "scopes":[...], "status":"active", "token":"<ONCE>" }
```

Store `token` in the caller secret store immediately. It is returned **once** and is never written to audit payloads, logs, or list responses.

## List

```bash
curl https://o.maplayer.top/admin/service-principals \
  -H "Authorization: Bearer <session_token>"
# → { "service_principals": [ { id, label, scopes, status, created_at, revoked_at, created_by } ] }
```

No `token` or hash fields.

## Revoke

```bash
curl -X POST https://o.maplayer.top/admin/service-principals/<principal-id>/revoke \
  -H "Authorization: Bearer <session_token>"
```

The same bearer then receives **403** on all admin routes. Existing users are untouched.

## Rotate

1. Mint a new principal with the same scopes.
2. Update the caller to the new token.
3. Revoke the old principal id.

Do not change the human bootstrap password as part of rotation.

## Call with a service token

```bash
curl https://o.maplayer.top/admin/tenants \
  -H "Authorization: Bearer <service-token>"

curl -X POST https://o.maplayer.top/admin/tenants/<tenantId>/users \
  -H "Authorization: Bearer <service-token>" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","display_name":"User"}'
```

Successful `user.provisioned` / `user.provision.failed` audit events use `actorType=service_principal` and `actorId=<principal id>` (table id, not the token). Payloads never include the bearer, invitation token, or activation URL.

## Storage

D1 table `admin_service_principals` (migration `0014_admin_service_principals.sql`): append-only schema. Sessions stay in KV; principals live in D1 so revocation survives Worker restarts.
