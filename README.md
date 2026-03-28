# ma_hono

A tenant-aware OIDC Identity Provider built on Cloudflare Workers with Hono, Drizzle ORM (D1/SQLite), and jose.

## Features

- OIDC Authorization Code + PKCE flow
- Username/password login
- Email magic link login
- Passkey (WebAuthn) enrollment and login
- Multi-tenant with platform-path (`/t/:slug`) and custom-domain issuers
- JWT-signed ID tokens and access tokens (RS256)
- Admin API for tenant and user management
- Audit event logging

## Local Development

### Prerequisites

- Node.js 20+
- pnpm (`corepack enable`)
- Wrangler (`pnpm add -g wrangler`)

### Setup

```bash
pnpm install
```

### Run tests

```bash
pnpm test
# or watch mode:
pnpm vitest
```

### Typecheck

```bash
pnpm typecheck
```

## Database Migrations

Migrations live in `drizzle/migrations/`. Apply them to a local D1 database:

```bash
# Create a local D1 database for development
wrangler d1 create ma-hono-dev

# Apply all migrations
wrangler d1 migrations apply ma-hono-dev --local

# Or apply to a remote database
wrangler d1 migrations apply ma-hono-dev --remote
```

Check migration consistency:

```bash
pnpm exec drizzle-kit check
```

## Key Bootstrap

On startup, the IdP retires any existing active signing keys and ensures each tenant has its own active `RS256` signing key. Private key material is stored in R2 and key metadata in D1.

## User Provisioning

Provision a user via the admin API (requires a valid admin session):

```bash
# Login as admin
curl -X POST https://your-idp.example.com/admin/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"your-password"}'

# Provision a user for a tenant
curl -X POST https://your-idp.example.com/admin/tenants/{tenantId}/users \
  -H "Authorization: Bearer <admin-session-token>" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","display_name":"Alice","username":"alice"}'

# The response includes an invitation_token for account activation
# Share the activation_url with the user or call it directly:
curl -X POST https://your-idp.example.com/activate-account \
  -H "Content-Type: application/json" \
  -d '{"invitation_token":"<token>","password":"new-password"}'
```

## OIDC Flow

```
Client → GET /t/{tenant}/authorize?client_id=...&code_challenge=...
       ← 302 /t/{tenant}/login?login_challenge=<token>

# Password login
Client → POST /t/{tenant}/login/password
         login_challenge=<token>&username=alice&password=...
       ← 302 https://app.example.com/callback?code=...&state=...

# Magic link
Client → POST /t/{tenant}/login/magic-link/request
         email=alice@...&login_challenge=<token>
       ← 200 {"magic_link_token":"<token>"}  (deliver to user by email)

Client → POST /t/{tenant}/login/magic-link/consume
         token=<magic_link_token>
       ← 302 https://app.example.com/callback?code=...&state=...

# Passkey
Client → POST /t/{tenant}/passkey/enroll/start   (enrollment)
         {"user_id":"..."}
       ← 200 {"challenge":"...","enrollment_session_id":"..."}

Client → POST /t/{tenant}/passkey/enroll/finish
         {"enrollment_session_id":"...","credential_id":"...","public_key_cbor":"...","sign_count":0}
       ← 200 {"enrolled":true}

Client → POST /t/{tenant}/login/passkey/start    (login)
         login_challenge=<token>
       ← 200 {"challenge":"...","assertion_session_id":"..."}

Client → POST /t/{tenant}/login/passkey/finish
         {"assertion_session_id":"...","credential_id":"...","sign_count":1}
       ← 302 https://app.example.com/callback?code=...&state=...

# Token exchange
Client → POST /t/{tenant}/token
         grant_type=authorization_code&code=...&redirect_uri=...&code_verifier=...
         Authorization: Basic <client_id:client_secret>
       ← 200 {"id_token":"...","access_token":"...","token_type":"Bearer"}
```

## Wrangler Deployment

```bash
# Dry run
pnpm exec wrangler deploy --dry-run

# Deploy
pnpm exec wrangler deploy
```

Make sure `wrangler.jsonc` has your D1 database ID, R2 bucket, and `USER_SESSIONS_KV` binding configured.
