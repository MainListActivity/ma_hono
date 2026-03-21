# Admin Panel Design

## Goal

Provide a browser-based admin panel at `/admin` for platform operators to manage tenants and their users. The setup wizard already redirects to `/admin` after initialization; this design fulfills that destination.

The admin panel is a React SPA deployed to Cloudflare Pages, communicating with the existing Worker JSON API via CORS. It covers: login, tenant creation and listing, and user provisioning per tenant.

## Architecture

```
Cloudflare Pages (admin/)       Cloudflare Worker (src/)
  React SPA                  →  /admin/login        POST
  Vite + TypeScript          →  /admin/tenants       GET, POST
  Tailwind CSS               →  /admin/tenants/:id   GET (new)
                             →  /admin/tenants/:id/users  GET (new), POST
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
└── wrangler.toml                 # Worker config (unchanged)
```

## Frontend Routes

| Path | Component | Description |
|------|-----------|-------------|
| `/login` | `LoginPage` | Email + password form |
| `/tenants` | `TenantsPage` | Tenant list + create tenant |
| `/tenants/:id/users` | `TenantUsersPage` | User list + provision user |
| `/` | redirect | → `/tenants` if authenticated, else `/login` |

## Authentication

- `POST /admin/login` returns `{ session_token }`.
- Token stored in `localStorage` under key `admin_session_token`.
- All subsequent requests send `Authorization: Bearer <token>` header.
- `AuthGuard` component wraps all protected routes; redirects to `/login` if no token in localStorage.
- API client intercepts 401 responses, clears localStorage, and redirects to `/login`.

No token refresh or expiry display in this MVP — token is used until it fails.

## Frontend Pages

### Login Page (`/login`)

- Email input + password input + submit button.
- On success: store token, navigate to `/tenants`.
- On failure: display error message inline.

### Tenants Page (`/tenants`)

- Table: tenant id, slug, display name, status, issuer URL.
- "New Tenant" button opens a modal with slug + display name fields.
- `POST /admin/tenants` on submit; reload list on success.
- Row click navigates to `/tenants/:id/users`.

### Tenant Users Page (`/tenants/:id/users`)

- Header: tenant slug + display name.
- Table: user email, display name, status.
- "Provision User" button opens a modal with email, display name, optional username fields.
- `POST /admin/tenants/:id/users` on submit; reload list on success.

## UI Stack

- **React 19** with React Router v7 (file-based or manual routes).
- **Tailwind CSS** for styling — no component library.
- **Vite** for build tooling.
- No state management library; React context for auth token only.

## Worker Changes

### New Read Endpoints

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/admin/tenants` | `{ tenants: Tenant[] }` |
| `GET` | `/admin/tenants/:tenantId` | `{ id, slug, display_name, status, issuer }` |
| `GET` | `/admin/tenants/:tenantId/users` | `{ users: User[] }` |

All three require `Authorization: Bearer <token>` (admin session).

### Repository Changes

- `TenantRepository`: add `list(): Promise<Tenant[]>`
- `UserRepository`: add `listByTenantId(tenantId: string): Promise<User[]>`
- Implement both on `MemoryTenantRepository`, `MemoryUserRepository`, and Drizzle adapters.

### CORS

- New environment variable: `ADMIN_ORIGIN` — the Cloudflare Pages URL (e.g. `https://ma-hono-admin.pages.dev`).
- Added to `runtimeConfigSchema` in `src/config/env.ts`.
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
- **SPA fallback**: `admin/public/_redirects` containing `/* /index.html 200`
- **Environment variable**: `VITE_API_BASE_URL` set to the Worker URL (e.g. `https://auth.maplayer.top`)

## Data Flow

```
Browser → Pages CDN → (static assets)
Browser → Worker /admin/login → session_token → localStorage
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
