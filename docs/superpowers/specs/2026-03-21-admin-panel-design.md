# Admin Panel Design

## Goal

Provide a browser-based admin panel for platform operators to manage tenants and their users, and a login interface for tenant end-users. Both are React SPA pages deployed together on Cloudflare Pages at `auth.{domain}`.

The setup wizard already redirects to `/admin` after initialization; this design fulfills that destination.

The SPA communicates with the Hono Worker JSON API via the `auth.{domain}/api/*` route. It covers: admin login, tenant creation and listing, user provisioning per tenant, and tenant end-user login.

## Deployment Topology

```
auth.{domain}         → Cloudflare Pages (this SPA, /* /index.html 200)
auth.{domain}/api/*   → Cloudflare Worker route (all JSON API endpoints, takes priority over Pages)
o.{domain}/*          → Cloudflare Worker route (OIDC protocol endpoints only)
```

The `auth.{domain}/api/*` Worker route takes priority over the Pages catch-all. All API calls from the SPA use the `/api/` prefix. Pages handles everything else.

## Route Namespace Separation

| Path prefix | Handled by | Purpose |
|-------------|-----------|---------|
| `auth.{domain}/api/*` | Worker | JSON API for admin + login |
| `auth.{domain}/login/:tenant` | Pages SPA | Tenant end-user login UI |
| `auth.{domain}/admin` | Pages SPA | Admin panel UI |
| `o.{domain}/t/:tenant/*` | Worker | OIDC protocol endpoints |

The `o.{domain}` subdomain is reserved exclusively for machine-facing OIDC traffic. Human-facing login pages live at `auth.{domain}/login/:tenant`.

## Architecture

```
Cloudflare Pages (admin/)         Cloudflare Worker (src/)
  React SPA                    →  /api/admin/login              POST
  Vite + TypeScript            →  /api/admin/tenants            GET, POST
  Tailwind CSS                 →  /api/admin/tenants/:id        GET
                               →  /api/admin/tenants/:id/users  GET, POST
                               →  /api/login/:tenant/password   POST
                               →  /api/login/:tenant/magic-link/request  POST
                               →  /api/login/:tenant/magic-link/consume  POST
                               →  /api/login/:tenant/passkey/start       POST
                               →  /api/login/:tenant/passkey/finish      POST
```

The SPA is entirely static — no server-side rendering. All state lives in the browser. The Worker remains the single source of truth.

## Directory Structure

```
ma_hono/
├── src/                          # Existing Worker (unchanged except API additions)
├── admin/                        # New — React SPA
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx               # Router setup, auth context
│   │   ├── api/
│   │   │   └── client.ts         # Typed fetch wrappers for all /admin/* endpoints
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx
│   │   │   ├── TenantsPage.tsx
│   │   │   ├── TenantUsersPage.tsx
│   │   └── components/
│   │       ├── AuthGuard.tsx     # Redirects unauthenticated users to /login
│   │       ├── Layout.tsx        # Nav, page shell
│   │       └── Modal.tsx         # Shared create-form modal
│   ├── index.html
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── tailwind.config.ts
│   └── package.json
└── wrangler.jsonc                # Worker config (add ADMIN_ORIGIN var)
```

## Frontend Routes

| Path | Component | Description |
|------|-----------|-------------|
| `/login` | `AdminLoginPage` | Admin email + password form |
| `/tenants` | `TenantsPage` | Tenant list + create tenant |
| `/tenants/:id/users` | `TenantUsersPage` | User list + provision user |
| `/login/:tenant` | `TenantLoginPage` | Tenant end-user login (password, magic link, passkey) |
| `/activate` | `AccountActivationPage` | Invitation token → initial password setup |
| `/` | redirect | → `/tenants` if admin authenticated, else `/login` |

## Authentication

- `POST /api/admin/login` returns `{ email, session_token }`.
- Token stored in `sessionStorage` under key `admin_session_token`. `sessionStorage` is preferred over `localStorage` because it is not shared across tabs and is cleared when the browser tab closes, limiting the exposure window.
- All subsequent admin requests send `Authorization: Bearer <token>` header.
- `AuthGuard` component wraps all protected admin routes; redirects to `/login` if no token in sessionStorage.
- API client intercepts 401 responses, clears sessionStorage, and redirects to `/login`.

No token refresh or expiry display in this MVP — token is used until it fails.

**Logout:** A "Sign out" link is present in the nav. Clicking it clears `sessionStorage` and redirects to `/login`. No server-side revocation endpoint exists in this MVP — the session record in the admin repository remains valid until it expires or is cleaned up. This is a known limitation: a stolen token remains usable server-side after client-side logout. A `POST /admin/logout` revocation endpoint is deferred to a future iteration.

**XSS note:** `sessionStorage` is still accessible to JavaScript on the same origin and is not immune to XSS. The Cloudflare Pages origin must not load untrusted third-party scripts. A future hardening step could move to short-lived tokens issued as `httpOnly` cookies, but that requires additional CSRF protection and is deferred.

## Frontend Pages

### Login Page (`/login`)

- Email input + password input + submit button.
- On success: store token, navigate to `/tenants`.
- On failure: display error message inline.

### Tenants Page (`/tenants`)

- Table: tenant id, slug, display name, status (`active` | `disabled`), issuer URL. `status` is defined on the `Tenant` domain type and must be included in the `GET /admin/tenants` response. The issuer URL displayed is the primary issuer's `issuerUrl` (where `isPrimary: true`); if no primary issuer exists, display an empty cell.
- "New Tenant" button opens a modal with slug + display name fields.
- `POST /admin/tenants` on submit; reload list on success.
- Row click navigates to `/tenants/:id/users`.

### Tenant Users Page (`/tenants/:id/users`)

- Header: tenant slug + display name.
- Table: user email, display name, status.
- "Provision User" button opens a modal with email, display name, optional username fields.
- `POST /admin/tenants/:id/users` on submit; reload list on success.

### Tenant Login Page (`/login/:tenant`)

The universal login page for end-users of a given tenant. This page is reached when `/authorize` redirects unauthenticated users.

**URL shape:** `/login/:tenant?login_challenge=<token>`

**Page load:**
1. Extract `login_challenge` from query string. If absent, render an error state ("No active login session").
2. Call `GET /api/login/:tenant/challenge-info?login_challenge=<token>` to fetch tenant display info and available login methods. Response:
   ```json
   {
     "tenant_display_name": "Acme Corp",
     "methods": ["password", "magic_link", "passkey"]
   }
   ```
3. Render login method tabs/options based on `methods`. Default to the first available method.

**Password tab:**
- Username field + password field.
- On submit: `POST /api/login/:tenant/password` with form body `{ login_challenge, username, password }`.
- On 302 redirect in response: follow to callback (authorization code flow resumes).
- On error: display inline message.

**Magic link tab:**
- Email field.
- On submit: `POST /api/login/:tenant/magic-link/request` with `{ email, login_challenge }`.
- On 200: show "Check your email" confirmation. No polling — user clicks the link in the email.
- The magic link itself calls `POST /api/login/:tenant/magic-link/consume` with `{ token }` via a separate page load (same SPA, same route handles the `token` query parameter).

**Passkey tab:**
- Single "Sign in with passkey" button.
- On click: `POST /api/login/:tenant/passkey/start` with `{ login_challenge }` → receive WebAuthn assertion options.
- Use `navigator.credentials.get()` with those options.
- `POST /api/login/:tenant/passkey/finish` with assertion result → follow redirect.

**Magic link consume flow (same page, token in URL):**
- If `?token=<magic_link_token>` is present in the URL (alongside `login_challenge`), immediately `POST /api/login/:tenant/magic-link/consume`.
- On 302: follow redirect. On error: show error with option to restart.

**Worker API addition — `GET /login/:tenant/challenge-info`:**

New endpoint returning tenant info and available methods for a login challenge:

```
GET /login/:tenant/challenge-info?login_challenge=<token>
→ 200 { tenant_display_name: string, methods: ("password" | "magic_link" | "passkey")[] }
→ 404 if tenant not found
→ 400 if login_challenge is absent or expired
```

Implementation reads from `loginChallengeLookupRepository` to verify the challenge exists, and from `userRepository.findAuthMethodPolicyByTenantId` to determine available methods. No session or admin auth required — this is a public endpoint called by the login SPA.

### Account Activation Page (`/activate?token=<invitation_token>`)

Reached when the admin provisions a user and the invitation link is sent to the user.

- On load: validate token by calling `GET /api/activate-account?token=<token>` (or inline in the POST — either works).
- Form: password + confirm password.
- On submit: `POST /api/activate-account` with `{ token, password }`.
- On success: redirect to `/login/:tenant` with a success banner, or to the original `redirect_uri` if the invitation carried one.
- On error (`token_expired`, `already_initialized`, etc.): display error with link to contact admin.

## UI Stack

- **React 19** with React Router v7 in **library mode** (manual routes). Framework/Remix mode is not compatible with a static Cloudflare Pages deployment and must not be used.
- **Tailwind CSS** for styling — no component library.
- **Vite** for build tooling.
- No state management library; React context for auth token only.

**Package structure:** `admin/` is a standalone package, not a pnpm workspace member. The root `pnpm-workspace.yaml` currently lists only `"."`. `admin/` has its own `package.json` and is installed/built independently (`cd admin && pnpm install && pnpm build`). React Router v7 minimum version: `^7.2.0`. React 19 is compatible with React Router v7 library mode.

## Worker Changes

### API Prefix

All Worker endpoints are served under the `/api/` prefix. This prefix is required so that the Cloudflare Worker route `auth.{domain}/api/*` intercepts these requests before the Pages catch-all serves the SPA.

- Previous: `/admin/login`, `/admin/tenants`, etc.
- Current: `/api/admin/login`, `/api/admin/tenants`, etc.

### New Read Endpoints

All GET endpoints use the same snake_case wire format as the existing POST endpoints. Domain type camelCase fields are mapped to snake_case before serialization.

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/api/admin/tenants` | `{ tenants: [{ id, slug, display_name, status, issuer }] }` — `issuer` is the primary issuer's `issuerUrl`, or `null` |
| `GET` | `/api/admin/tenants/:tenantId` | `{ id, slug, display_name, status, issuer }` — `issuer` is the primary issuer's `issuerUrl`, or `null` |
| `GET` | `/api/admin/tenants/:tenantId/users` | `{ users: [{ id, email, display_name, status }] }` |

All three endpoints require `Authorization: Bearer <token>` (admin session) and follow the same per-route `authenticateAdminSession` call pattern.

`GET /api/admin/tenants/:tenantId` is needed by `TenantUsersPage` to load the tenant header on direct URL navigation and page refresh (router state from `TenantsPage` is lost on refresh). `issuer` can only be `null` if all issuers have been removed, which is not currently supported via the API; this is a defensive guard.

### Repository Changes

- `TenantRepository` interface: add `list(): Promise<Tenant[]>`
- `UserRepository` interface: add `listByTenantId(tenantId: string): Promise<User[]>`

All four concrete implementations must be updated:

| Class | File |
|-------|------|
| `MemoryTenantRepository` | `src/adapters/db/memory/memory-tenant-repository.ts` |
| `MemoryUserRepository` | `src/adapters/db/memory/memory-user-repository.ts` |
| Drizzle `TenantRepository` | `src/adapters/db/drizzle/runtime.ts` |
| Drizzle `UserRepository` | `src/adapters/db/drizzle/runtime.ts` |

### CORS

CORS is not needed between the SPA and the Worker API because both are served under the same `auth.{domain}` hostname. The Worker route `auth.{domain}/api/*` and the Pages deployment share the same origin from the browser's perspective.

The `ADMIN_ORIGIN` variable and CORS middleware are no longer required and should be removed.

For custom-domain tenant login (where the SPA may be embedded on a different origin in future), CORS can be added to the login API routes at that time.

## Cloudflare Pages Configuration

- **Project name**: `ma-hono-admin`
- **Custom domain**: `auth.{domain}` (same as the primary user-facing hostname)
- **Root directory**: `admin/`
- **Build command**: `pnpm build`
- **Build output**: `dist/`
- **SPA fallback**: `admin/public/_redirects` containing `/* /index.html 200`. Vite copies `public/` verbatim to `dist/`, so this becomes `admin/dist/_redirects`. This only works when the Pages "Root directory" is set to `admin/` — if the root is misconfigured as the repo root, the `_redirects` file will not be in the build output and SPA routing will break.
- **Worker route override**: `auth.{domain}/api/*` is a Cloudflare Worker route that takes priority over the Pages deployment. The SPA only handles non-`/api/` paths.
- **Environment variable**: `VITE_API_BASE_URL` is not needed — the SPA calls `/api/*` relative to its own origin.

## Data Flow

```
Browser → auth.{domain}           → Pages CDN (static SPA assets, /* /index.html 200)
Browser → auth.{domain}/api/*     → Worker (API requests, route takes priority over Pages)
Browser → o.{domain}/t/:tenant/*  → Worker (OIDC protocol requests)
```

Admin flow:
```
Browser → Pages /login                          → AdminLoginPage SPA
Browser → Worker /api/admin/login               → session_token → sessionStorage
Browser → Worker /api/admin/tenants (Bearer)    → tenant list
Browser → Worker /api/admin/tenants/:id/users   → user list
```

Tenant end-user login flow:
```
Browser → Pages /login/:tenant                         → TenantLoginPage SPA
Browser → Worker /api/login/:tenant/password           → authenticate
Browser → Worker redirects to o.{domain}/t/:tenant/authorize → OIDC flow resumes
```

## Security Notes

- Admin session tokens are opaque bearer tokens validated server-side on every request.
- `ADMIN_ORIGIN` limits CORS to the known admin SPA origin; wildcard `*` is not used.
- No admin functionality is exposed without a valid session token.
- The SPA itself is public static content but contains no sensitive data.

## Out of Scope

- Tenant configuration editing (auth methods, MFA policy, branding).
- Admin user management (adding/removing admin whitelist entries).
- Audit log viewer.
- Pagination (initial implementation loads all records; add when needed).
- Dark mode.
- `POST /admin/logout` server-side session revocation (client-side sessionStorage clear on sign-out is accepted for MVP).
- CSRF protection (not needed while using `Authorization: Bearer` header; required if/when switching to `httpOnly` cookie auth).

## Future Roadmap

The following capabilities are intentionally deferred but should be kept in mind when evolving the data model and API.

### Admin-configurable login methods per tenant

Currently the `tenant_auth_method_policies` table exists and controls which methods are active per tenant. The admin panel does not yet expose UI to edit this policy.

Future work:
- Add `PUT /api/admin/tenants/:id/auth-methods` endpoint accepting `{ password, magic_link, passkey }` boolean flags.
- Add a "Login Methods" tab to the tenant detail page in the admin panel.
- The `GET /login/:tenant/challenge-info` endpoint already returns only enabled methods, so the login SPA requires no changes.

### Login page branding customization

Tenants should be able to supply branding: logo URL, primary color, and custom copy. This requires:
- A new `tenant_branding` table: `{ tenant_id, logo_url, primary_color, display_name_override, updated_at }`.
- Admin UI to upload/set branding assets.
- `GET /login/:tenant/challenge-info` extended to return `branding: { logo_url, primary_color }`.
- `TenantLoginPage` applies the branding at render time via CSS custom properties.

No server-side rendering is required — the SPA applies branding dynamically from the API response.

### Custom domain login pages

Custom-domain tenants (e.g. `login.acme.com`) already route login traffic through the same Worker (`/login` without a `:tenant` param). The SPA is served from `auth.{domain}`, so it is not currently embedded on custom domains.

For full custom-domain login UI:
- The tenant's custom domain must serve the login SPA directly (via a separate Cloudflare Pages deployment or a Worker-rendered HTML shell).
- CORS must be added to the `GET /login/challenge-info` and `POST /login/*` endpoints for that custom origin.
- This is a significant operational change and is deferred to a later phase.

In the interim, custom-domain tenants can redirect to `auth.{domain}/login/:tenant` for the login UI while keeping the OIDC issuer URL at the custom domain — this is already the behavior when `issuerType=custom_domain` and no custom-domain login SPA exists.
