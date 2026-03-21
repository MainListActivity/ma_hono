# Admin Panel Design

## Goal

Provide a browser-based admin panel at `/admin` for platform operators to manage tenants and their users. The setup wizard already redirects to `/admin` after initialization; this design fulfills that destination.

The admin panel is a React SPA deployed to Cloudflare Pages, communicating with the existing Worker JSON API via CORS. It covers: login, tenant creation and listing, and user provisioning per tenant.

## Architecture

```
Cloudflare Pages (admin/)       Cloudflare Worker (src/)
  React SPA                  →  /admin/login              POST (existing)
  Vite + TypeScript          →  /admin/tenants            GET (new), POST (existing)
  Tailwind CSS               →  /admin/tenants/:id        GET (new)
                             →  /admin/tenants/:id/users  GET (new), POST (existing)
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
| `/login` | `LoginPage` | Email + password form |
| `/tenants` | `TenantsPage` | Tenant list + create tenant |
| `/tenants/:id/users` | `TenantUsersPage` | User list + provision user |
| `/` | redirect | → `/tenants` if authenticated, else `/login` |

## Authentication

- `POST /admin/login` returns `{ email, session_token }`.
- Token stored in `sessionStorage` under key `admin_session_token`. `sessionStorage` is preferred over `localStorage` because it is not shared across tabs and is cleared when the browser tab closes, limiting the exposure window.
- All subsequent requests send `Authorization: Bearer <token>` header.
- `AuthGuard` component wraps all protected routes; redirects to `/login` if no token in sessionStorage.
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

## UI Stack

- **React 19** with React Router v7 in **library mode** (manual routes). Framework/Remix mode is not compatible with a static Cloudflare Pages deployment and must not be used.
- **Tailwind CSS** for styling — no component library.
- **Vite** for build tooling.
- No state management library; React context for auth token only.

**Package structure:** `admin/` is a standalone package, not a pnpm workspace member. The root `pnpm-workspace.yaml` currently lists only `"."`. `admin/` has its own `package.json` and is installed/built independently (`cd admin && pnpm install && pnpm build`). React Router v7 minimum version: `^7.2.0`. React 19 is compatible with React Router v7 library mode.

## Worker Changes

### New Read Endpoints

All new GET endpoints use the same snake_case wire format as the existing POST endpoints. Domain type camelCase fields are mapped to snake_case before serialization.

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/admin/tenants` | `{ tenants: [{ id, slug, display_name, status, issuer }] }` — `issuer` is the primary issuer's `issuerUrl`, or `null` |
| `GET` | `/admin/tenants/:tenantId` | `{ id, slug, display_name, status, issuer }` — `issuer` is the primary issuer's `issuerUrl`, or `null` |
| `GET` | `/admin/tenants/:tenantId/users` | `{ users: [{ id, email, display_name, status }] }` |

All three endpoints require `Authorization: Bearer <token>` (admin session) and follow the same per-route `authenticateAdminSession` call pattern as the existing `POST /admin/tenants` and `POST /admin/tenants/:tenantId/users` routes — no new Hono middleware group is introduced.

`GET /admin/tenants/:tenantId` is needed by `TenantUsersPage` to load the tenant header on direct URL navigation and page refresh (router state from `TenantsPage` is lost on refresh). `issuer` can only be `null` if all issuers have been removed, which is not currently supported via the API; this is a defensive guard.

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

- New environment variable: `ADMIN_ORIGIN` — the Cloudflare Pages URL (e.g. `https://ma-hono-admin.pages.dev`).
- Declared in `wrangler.jsonc` under `"vars"` (not a binding — it is a plain string, not a D1/KV/R2 resource).
- Added as `adminOrigin: z.string().optional()` to `runtimeConfigSchema` in `src/config/env.ts`, and exposed as `adminOrigin?: string` on the `RuntimeConfig` interface.
- If `ADMIN_ORIGIN` is unset, the CORS middleware omits `Access-Control-Allow-Origin` entirely, blocking all cross-origin requests. This is the safe default. `ADMIN_ORIGIN` is a required deployment variable for the admin panel to function.
- A Hono middleware on `/admin/*` routes adds:
  - `Access-Control-Allow-Origin: <ADMIN_ORIGIN>`
  - `Access-Control-Allow-Methods: GET, POST, OPTIONS`
  - `Access-Control-Allow-Headers: Authorization, Content-Type`
- `OPTIONS /admin/*` preflight handler returns 204.

## Cloudflare Pages Configuration

- **Project name**: `ma-hono-admin`
- **Root directory**: `admin/`
- **Build command**: `pnpm build`
- **Build output**: `dist/`
- **SPA fallback**: `admin/public/_redirects` containing `/* /index.html 200`. Vite copies `public/` verbatim to `dist/`, so this becomes `admin/dist/_redirects`. This only works when the Pages "Root directory" is set to `admin/` — if the root is misconfigured as the repo root, the `_redirects` file will not be in the build output and SPA routing will break.
- **Environment variable**: `VITE_API_BASE_URL` set to the Worker URL (e.g. `https://auth.maplayer.top`)

## Data Flow

```
Browser → Pages CDN → (static assets)
Browser → Worker /admin/login → session_token → sessionStorage
Browser → Worker /admin/tenants (Bearer token) → tenant list
Browser → Worker /admin/tenants/:id/users (Bearer token) → user list
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
