# Admin Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a React SPA admin panel on Cloudflare Pages that lets platform operators log in, manage tenants, and provision users — backed by new read endpoints and CORS support on the existing Hono Worker.

**Architecture:** Two independent parts: (1) Worker changes — three new GET endpoints + CORS middleware + repository interface additions, and (2) a standalone `admin/` React SPA that calls those endpoints. The SPA is deployed to Cloudflare Pages; it has no server side. All persistence remains in the Worker/D1.

**Tech Stack:** Hono (Worker), Vitest (Worker tests), React 19 + React Router v7 library mode + Tailwind CSS + Vite (SPA), pnpm (both), Cloudflare Pages (SPA hosting).

---

## File Map

### Worker (existing codebase — `src/`)

| File | Change |
|------|--------|
| `src/domain/tenants/repository.ts` | Add `list(): Promise<Tenant[]>` to interface |
| `src/domain/users/repository.ts` | Add `listByTenantId(tenantId: string): Promise<User[]>` to interface |
| `src/adapters/db/memory/memory-tenant-repository.ts` | Implement `list()` |
| `src/adapters/db/memory/memory-user-repository.ts` | Implement `listByTenantId()` |
| `src/adapters/db/drizzle/runtime.ts` | Implement `list()` on `D1TenantRepository`; implement `listByTenantId()` on `D1UserRepository` |
| `src/config/env.ts` | Add `adminOrigin?: string` to schema and `RuntimeConfig` |
| `src/app/app.ts` | Add CORS middleware + OPTIONS handler + 3 GET routes |
| `wrangler.jsonc` | Add `ADMIN_ORIGIN` under `"vars"` |
| `tests/admin/admin-read-endpoints.test.ts` | New test file for the three GET routes |

### SPA (new — `admin/`)

| File | Purpose |
|------|---------|
| `admin/package.json` | Standalone package with React, React Router, Vite, Tailwind deps |
| `admin/tsconfig.json` | TypeScript config for the SPA |
| `admin/vite.config.ts` | Vite config — base path `/`, output `dist/` |
| `admin/tailwind.config.ts` | Tailwind config |
| `admin/index.html` | HTML entry point |
| `admin/public/_redirects` | `/* /index.html 200` for Pages SPA routing |
| `admin/src/main.tsx` | React root render |
| `admin/src/App.tsx` | Router setup + AuthContext provider |
| `admin/src/api/client.ts` | Typed fetch wrapper for all `/admin/*` endpoints |
| `admin/src/pages/LoginPage.tsx` | Login form |
| `admin/src/pages/TenantsPage.tsx` | Tenant list + create tenant modal |
| `admin/src/pages/TenantUsersPage.tsx` | User list + provision user modal |
| `admin/src/components/AuthGuard.tsx` | Redirect unauthenticated users to `/login` |
| `admin/src/components/Layout.tsx` | Nav shell with "Sign out" link |
| `admin/src/components/Modal.tsx` | Reusable modal dialog |

---

## Task 1: Extend TenantRepository and UserRepository interfaces

**Files:**
- Modify: `src/domain/tenants/repository.ts`
- Modify: `src/domain/users/repository.ts`

- [ ] **Step 1: Add `list()` to TenantRepository**

Open `src/domain/tenants/repository.ts`. Add the new method to the interface:

```typescript
import type { Tenant } from "./types";

export interface TenantRepository {
  create(tenant: Tenant): Promise<void>;
  findById(id: string): Promise<Tenant | null>;
  findBySlug(slug: string): Promise<Tenant | null>;
  findByCustomDomain(domain: string): Promise<Tenant | null>;
  list(): Promise<Tenant[]>;
}
```

- [ ] **Step 2: Add `listByTenantId()` to UserRepository**

Open `src/domain/users/repository.ts`. Add to the `UserRepository` interface (after `findUserByUsername`):

```typescript
listByTenantId(tenantId: string): Promise<User[]>;
```

- [ ] **Step 3: Run TypeScript check — expect compile errors on all implementing classes**

```bash
cd /path/to/ma_hono && pnpm tsc --noEmit
```

Expected: errors on `MemoryTenantRepository`, `D1TenantRepository`, `MemoryUserRepository`, `D1UserRepository`, `EmptyTenantRepository`, `EmptyUserRepository` — all missing the new methods.

- [ ] **Step 4: Commit**

```bash
git add src/domain/tenants/repository.ts src/domain/users/repository.ts
git commit -m "feat: add list() and listByTenantId() to repository interfaces"
```

---

## Task 2: Implement list() on MemoryTenantRepository

**Files:**
- Modify: `src/adapters/db/memory/memory-tenant-repository.ts`

- [ ] **Step 1: Add `list()` implementation**

```typescript
async list(): Promise<Tenant[]> {
  return [...this.tenants];
}
```

Add this after the `findByCustomDomain` method.

- [ ] **Step 2: Run TypeScript check — one fewer error**

```bash
pnpm tsc --noEmit
```

---

## Task 3: Implement listByTenantId() on MemoryUserRepository

**Files:**
- Modify: `src/adapters/db/memory/memory-user-repository.ts`

- [ ] **Step 1: Add `listByTenantId()` implementation**

Add after the `findUserByUsername` method:

```typescript
async listByTenantId(tenantId: string): Promise<User[]> {
  return this.users.filter((user) => user.tenantId === tenantId);
}
```

- [ ] **Step 2: Run TypeScript check**

```bash
pnpm tsc --noEmit
```

---

## Task 4: Implement list() on D1TenantRepository

**Files:**
- Modify: `src/adapters/db/drizzle/runtime.ts` (class `D1TenantRepository`, around line 187)

- [ ] **Step 1: Add `list()` implementation after `findByCustomDomain`**

The existing pattern fetches tenant rows then issuer rows separately. Follow the same pattern but for all tenants:

```typescript
async list(): Promise<Tenant[]> {
  const tenantRows = await this.db.select().from(tenants);
  if (tenantRows.length === 0) return [];

  const tenantIds = tenantRows.map((t) => t.id);
  const issuerRows = await this.db
    .select()
    .from(tenantIssuers)
    .where(
      tenantIds.length === 1
        ? eq(tenantIssuers.tenantId, tenantIds[0]!)
        : or(...tenantIds.map((id) => eq(tenantIssuers.tenantId, id)))
    );

  return tenantRows.map((tenantRow) =>
    toTenant(
      tenantRow,
      issuerRows.filter((r) => r.tenantId === tenantRow.id)
    )
  );
}
```

Note: `or` is already imported at the top of the file.

- [ ] **Step 2: Run TypeScript check**

```bash
pnpm tsc --noEmit
```

---

## Task 5: Implement listByTenantId() on D1UserRepository

**Files:**
- Modify: `src/adapters/db/drizzle/runtime.ts` (class `D1UserRepository`, around line 613)

- [ ] **Step 1: Add `listByTenantId()` implementation**

Add after the `findUserByUsername` method. The `users` table and `eq` are already imported:

```typescript
async listByTenantId(tenantId: string): Promise<User[]> {
  const rows = await this.db
    .select()
    .from(users)
    .where(eq(users.tenantId, tenantId));

  return rows.map((row) => ({
    id: row.id,
    tenantId: row.tenantId,
    email: row.email,
    emailVerified: row.emailVerified,
    username: row.username,
    displayName: row.displayName,
    status: row.status as User["status"],
    createdAt: row.createdAt,
    updatedAt: row.updatedAt
  }));
}
```

- [ ] **Step 2: Fix EmptyUserRepository and EmptyTenantRepository stubs in app.ts**

In `src/app/app.ts`, `EmptyTenantRepository` needs `list()` and `EmptyUserRepository` needs `listByTenantId()`:

```typescript
// In EmptyTenantRepository:
async list(): Promise<[]> {
  return [];
}

// In EmptyUserRepository:
async listByTenantId(): Promise<[]> {
  return [];
}
```

- [ ] **Step 3: Run TypeScript check — expect zero errors**

```bash
pnpm tsc --noEmit
```

- [ ] **Step 4: Run existing tests — expect all pass**

```bash
pnpm test
```

- [ ] **Step 5: Commit**

```bash
git add src/adapters/db/memory/memory-tenant-repository.ts \
        src/adapters/db/memory/memory-user-repository.ts \
        src/adapters/db/drizzle/runtime.ts \
        src/app/app.ts
git commit -m "feat: implement list() and listByTenantId() on all repository classes"
```

---

## Task 6: Add ADMIN_ORIGIN to env config

**Files:**
- Modify: `src/config/env.ts`
- Modify: `wrangler.jsonc`

- [ ] **Step 1: Add `ADMIN_ORIGIN` to runtimeConfigSchema and RuntimeConfig**

In `src/config/env.ts`, update the schema and interface:

```typescript
const runtimeConfigSchema = z.object({
  ADMIN_ORIGIN: z.string().optional(),
  ADMIN_SESSIONS_KV: kvBindingSchema,
  DB: d1BindingSchema,
  KEY_MATERIAL_R2: r2BindingSchema,
  REGISTRATION_TOKENS_KV: kvBindingSchema,
  USER_SESSIONS_KV: kvBindingSchema
});

export interface RuntimeConfig {
  adminOrigin?: string;
  adminSessionsKv: KVNamespace;
  db: D1Database;
  keyMaterialBucket: R2Bucket;
  registrationTokensKv: KVNamespace;
  userSessionsKv: KVNamespace;
}
```

Update `readRuntimeConfig` to include:

```typescript
adminOrigin: parsed.ADMIN_ORIGIN,
```

- [ ] **Step 2: Add ADMIN_ORIGIN placeholder to wrangler.jsonc**

Open `wrangler.jsonc` and add a `"vars"` section (if not present) with:

```jsonc
"vars": {
  "ADMIN_ORIGIN": ""
}
```

Leave the value empty — operators set it to their Pages URL after deployment.

- [ ] **Step 3: Run TypeScript check**

```bash
pnpm tsc --noEmit
```

- [ ] **Step 4: Commit**

```bash
git add src/config/env.ts wrangler.jsonc
git commit -m "feat: add ADMIN_ORIGIN env var to runtime config"
```

---

## Task 7: Write failing tests for the new GET endpoints

**Files:**
- Create: `tests/admin/admin-read-endpoints.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `tests/admin/admin-read-endpoints.test.ts`:

```typescript
import { describe, expect, it } from "vitest";

import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { Tenant } from "../../src/domain/tenants/types";

const ADMIN_ORIGIN = "https://ma-hono-admin.pages.dev";

const acmeTenant: Tenant = {
  id: "tenant_acme",
  slug: "acme",
  displayName: "Acme Corp",
  status: "active",
  issuers: [
    {
      id: "issuer_1",
      issuerType: "platform_path",
      issuerUrl: "https://idp.example.test/t/acme",
      domain: null,
      isPrimary: true,
      verificationStatus: "verified"
    }
  ]
};

const makeApp = (tenants: Tenant[] = [], users = []) => {
  const tenantRepository = new MemoryTenantRepository(tenants);
  const userRepository = new MemoryUserRepository({ users });
  const adminRepository = new MemoryAdminRepository({
    adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
  });

  return createApp({
    adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
    adminWhitelist: ["admin@example.test"],
    adminOrigin: ADMIN_ORIGIN,
    adminRepository,
    auditRepository: new MemoryAuditRepository(),
    managementApiToken: "",
    platformHost: "idp.example.test",
    tenantRepository,
    userRepository
  });
};

const loginAs = async (app: ReturnType<typeof makeApp>) => {
  const res = await app.request("https://idp.example.test/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "admin@example.test", password: "bootstrap-secret" })
  });
  const body = (await res.json()) as { session_token: string };
  return body.session_token;
};

describe("GET /admin/tenants", () => {
  it("returns 401 without auth", async () => {
    const app = makeApp();
    const res = await app.request("https://idp.example.test/admin/tenants");
    expect(res.status).toBe(401);
  });

  it("returns empty tenants list", async () => {
    const app = makeApp();
    const token = await loginAs(app);
    const res = await app.request("https://idp.example.test/admin/tenants", {
      headers: { authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ tenants: [] });
  });

  it("returns tenants with primary issuer", async () => {
    const app = makeApp([acmeTenant]);
    const token = await loginAs(app);
    const res = await app.request("https://idp.example.test/admin/tenants", {
      headers: { authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      tenants: [
        {
          id: "tenant_acme",
          slug: "acme",
          display_name: "Acme Corp",
          status: "active",
          issuer: "https://idp.example.test/t/acme"
        }
      ]
    });
  });

  it("includes CORS header for allowed origin", async () => {
    const app = makeApp();
    const token = await loginAs(app);
    const res = await app.request("https://idp.example.test/admin/tenants", {
      headers: {
        authorization: `Bearer ${token}`,
        origin: ADMIN_ORIGIN
      }
    });
    expect(res.headers.get("access-control-allow-origin")).toBe(ADMIN_ORIGIN);
  });

  it("handles OPTIONS preflight", async () => {
    const app = makeApp();
    const res = await app.request("https://idp.example.test/admin/tenants", {
      method: "OPTIONS",
      headers: {
        origin: ADMIN_ORIGIN,
        "access-control-request-method": "GET",
        "access-control-request-headers": "authorization"
      }
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe(ADMIN_ORIGIN);
  });
});

describe("GET /admin/tenants/:tenantId", () => {
  it("returns 401 without auth", async () => {
    const app = makeApp([acmeTenant]);
    const res = await app.request("https://idp.example.test/admin/tenants/tenant_acme");
    expect(res.status).toBe(401);
  });

  it("returns 404 for unknown tenant", async () => {
    const app = makeApp();
    const token = await loginAs(app);
    const res = await app.request("https://idp.example.test/admin/tenants/missing", {
      headers: { authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(404);
  });

  it("returns tenant detail", async () => {
    const app = makeApp([acmeTenant]);
    const token = await loginAs(app);
    const res = await app.request("https://idp.example.test/admin/tenants/tenant_acme", {
      headers: { authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      id: "tenant_acme",
      slug: "acme",
      display_name: "Acme Corp",
      status: "active",
      issuer: "https://idp.example.test/t/acme"
    });
  });
});

describe("GET /admin/tenants/:tenantId/users", () => {
  it("returns 401 without auth", async () => {
    const app = makeApp([acmeTenant]);
    const res = await app.request("https://idp.example.test/admin/tenants/tenant_acme/users");
    expect(res.status).toBe(401);
  });

  it("returns 404 for unknown tenant", async () => {
    const app = makeApp();
    const token = await loginAs(app);
    const res = await app.request("https://idp.example.test/admin/tenants/missing/users", {
      headers: { authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(404);
  });

  it("returns empty user list", async () => {
    const app = makeApp([acmeTenant]);
    const token = await loginAs(app);
    const res = await app.request("https://idp.example.test/admin/tenants/tenant_acme/users", {
      headers: { authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ users: [] });
  });

  it("returns provisioned users", async () => {
    const users = [
      {
        id: "user_1",
        tenantId: "tenant_acme",
        email: "alice@acme.example",
        emailVerified: false,
        username: null,
        displayName: "Alice",
        status: "provisioned" as const,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z"
      }
    ];
    const app = makeApp([acmeTenant], users);
    const token = await loginAs(app);
    const res = await app.request("https://idp.example.test/admin/tenants/tenant_acme/users", {
      headers: { authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      users: [
        {
          id: "user_1",
          email: "alice@acme.example",
          display_name: "Alice",
          status: "provisioned"
        }
      ]
    });
  });
});
```

- [ ] **Step 2: Run tests — expect failures (routes and userRepository not wired yet)**

```bash
pnpm test tests/admin/admin-read-endpoints.test.ts
```

Expected: many failures — `createApp` doesn't accept `adminOrigin` or `userRepository` yet; routes 404.

- [ ] **Step 3: Commit the failing tests**

```bash
git add tests/admin/admin-read-endpoints.test.ts
git commit -m "test: add failing tests for admin read endpoints and CORS"
```

---

## Task 8: Wire userRepository into createApp and add new GET routes + CORS

**Files:**
- Modify: `src/app/app.ts`

This is the largest Worker change. Read the full `createApp` function signature first (around line 220 in app.ts) to see all existing options.

- [ ] **Step 1: Add `adminOrigin` and `userRepository` to AppOptions**

Find the `AppOptions` interface (or the destructured parameter of `createApp`) and add:

```typescript
adminOrigin?: string;
userRepository: UserRepository;
```

Also add `userRepository` to the destructuring inside `createApp`.

- [ ] **Step 2: Add CORS middleware for /admin/* routes**

After the existing `app.use(...)` calls (near the top of `createApp`), add:

```typescript
app.use("/admin/*", async (context, next) => {
  await next();
  if (adminOrigin) {
    context.res.headers.set("Access-Control-Allow-Origin", adminOrigin);
    context.res.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    context.res.headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  }
});

app.options("/admin/*", (context) => {
  if (adminOrigin) {
    return context.body(null, 204, {
      "Access-Control-Allow-Origin": adminOrigin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type"
    });
  }
  return context.body(null, 204);
});
```

- [ ] **Step 3: Add helper to serialize a Tenant to wire format**

Add this helper function near the existing admin routes (before or after the `app.post("/admin/login")` handler):

```typescript
const tenantToWire = (tenant: Tenant) => ({
  id: tenant.id,
  slug: tenant.slug,
  display_name: tenant.displayName,
  status: tenant.status,
  issuer: tenant.issuers.find((i) => i.isPrimary)?.issuerUrl ?? null
});
```

You need to import `Tenant` type from `"../domain/tenants/types"` if not already imported.

- [ ] **Step 4: Add GET /admin/tenants route**

After the existing `app.post("/admin/tenants", ...)` handler:

```typescript
app.get("/admin/tenants", async (context) => {
  const session = await authenticateAdminSession({
    adminRepository,
    authorizationHeader: context.req.header("authorization")
  });

  if (session === null) {
    return context.json({ error: "unauthorized" }, 401);
  }

  const allTenants = await tenantRepository.list();
  return context.json({ tenants: allTenants.map(tenantToWire) });
});
```

- [ ] **Step 5: Add GET /admin/tenants/:tenantId route**

```typescript
app.get("/admin/tenants/:tenantId", async (context) => {
  const session = await authenticateAdminSession({
    adminRepository,
    authorizationHeader: context.req.header("authorization")
  });

  if (session === null) {
    return context.json({ error: "unauthorized" }, 401);
  }

  const tenantId = context.req.param("tenantId");
  const tenant = await tenantRepository.findById(tenantId);

  if (tenant === null) {
    return context.notFound();
  }

  return context.json(tenantToWire(tenant));
});
```

- [ ] **Step 6: Add GET /admin/tenants/:tenantId/users route**

```typescript
app.get("/admin/tenants/:tenantId/users", async (context) => {
  const session = await authenticateAdminSession({
    adminRepository,
    authorizationHeader: context.req.header("authorization")
  });

  if (session === null) {
    return context.json({ error: "unauthorized" }, 401);
  }

  const tenantId = context.req.param("tenantId");
  const tenant = await tenantRepository.findById(tenantId);

  if (tenant === null) {
    return context.notFound();
  }

  const userList = await userRepository.listByTenantId(tenantId);

  return context.json({
    users: userList.map((u) => ({
      id: u.id,
      email: u.email,
      display_name: u.displayName,
      status: u.status
    }))
  });
});
```

- [ ] **Step 7: Update callers of createApp in tests and index.ts**

All test files that call `createApp` need `userRepository` added. Search for all usages:

```bash
grep -rn "createApp(" tests/ src/
```

For any test file that doesn't pass `userRepository`, add:

```typescript
userRepository: new MemoryUserRepository()
```

Also update `src/index.ts` to pass `userRepository` from the runtime. (Read `src/index.ts` first to see how `createApp` is called there and add `userRepository` from the Drizzle runtime.)

- [ ] **Step 8: Run TypeScript check**

```bash
pnpm tsc --noEmit
```

- [ ] **Step 9: Run all tests — expect new tests pass, existing tests still pass**

```bash
pnpm test
```

- [ ] **Step 10: Commit**

```bash
git add src/app/app.ts src/index.ts tests/
git commit -m "feat: add admin read endpoints, CORS middleware, and userRepository wiring"
```

---

## Task 9: Scaffold the admin/ SPA package

**Files:**
- Create all files listed in the SPA file map above

- [ ] **Step 1: Create admin/package.json**

```json
{
  "name": "ma-hono-admin",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "react-router": "^7.2.0"
  },
  "devDependencies": {
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "@vitejs/plugin-react": "^4.3.4",
    "autoprefixer": "^10.4.20",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.17",
    "typescript": "^5.7.2",
    "vite": "^6.0.5"
  }
}
```

- [ ] **Step 2: Create admin/tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Create admin/vite.config.ts**

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist"
  }
});
```

- [ ] **Step 4: Create admin/tailwind.config.ts**

```typescript
import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {}
  },
  plugins: []
} satisfies Config;
```

- [ ] **Step 5: Create admin/postcss.config.js**

```javascript
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {}
  }
};
```

- [ ] **Step 6: Create admin/index.html**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Admin Panel</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 7: Create admin/public/_redirects**

```
/* /index.html 200
```

- [ ] **Step 8: Install dependencies**

```bash
cd admin && pnpm install
```

- [ ] **Step 9: Commit scaffold**

```bash
cd ..
git add admin/
git commit -m "feat: scaffold admin SPA package with Vite, React, Tailwind"
```

---

## Task 10: Build the API client

**Files:**
- Create: `admin/src/api/client.ts`

- [ ] **Step 1: Create the typed API client**

```typescript
const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

export interface TenantSummary {
  id: string;
  slug: string;
  display_name: string;
  status: "active" | "disabled";
  issuer: string | null;
}

export interface UserSummary {
  id: string;
  email: string;
  display_name: string;
  status: string;
}

class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
  }
}

const authHeaders = (token: string) => ({
  Authorization: `Bearer ${token}`,
  "Content-Type": "application/json"
});

const checkOk = async (res: Response) => {
  if (res.status === 401) {
    sessionStorage.removeItem("admin_session_token");
    window.location.href = "/login";
    throw new ApiError(401, "unauthorized");
  }
  if (!res.ok) {
    throw new ApiError(res.status, `Request failed: ${res.status}`);
  }
  return res;
};

export const login = async (email: string, password: string) => {
  const res = await fetch(`${BASE_URL}/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) throw new ApiError(res.status, "Login failed");
  return res.json() as Promise<{ email: string; session_token: string }>;
};

export const listTenants = async (token: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants`, { headers: authHeaders(token) })
  );
  return res.json() as Promise<{ tenants: TenantSummary[] }>;
};

export const getTenant = async (token: string, tenantId: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}`, { headers: authHeaders(token) })
  );
  return res.json() as Promise<TenantSummary>;
};

export const createTenant = async (token: string, slug: string, displayName: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ slug, display_name: displayName })
    })
  );
  return res.json() as Promise<{ id: string; slug: string; display_name: string; issuer: string }>;
};

export const listUsers = async (token: string, tenantId: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/users`, { headers: authHeaders(token) })
  );
  return res.json() as Promise<{ users: UserSummary[] }>;
};

export const provisionUser = async (
  token: string,
  tenantId: string,
  email: string,
  displayName: string,
  username?: string
) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({
        email,
        display_name: displayName,
        ...(username ? { username } : {})
      })
    })
  );
  return res.json();
};
```

- [ ] **Step 2: Commit**

```bash
git add admin/src/api/client.ts
git commit -m "feat: add typed API client for admin endpoints"
```

---

## Task 11: Build auth context and App shell

**Files:**
- Create: `admin/src/main.tsx`
- Create: `admin/src/App.tsx`

- [ ] **Step 1: Create admin/src/main.tsx**

```typescript
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
```

- [ ] **Step 2: Create admin/src/index.css**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

- [ ] **Step 3: Create admin/src/App.tsx**

```typescript
import { createContext, useContext, useState } from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes
} from "react-router";
import LoginPage from "./pages/LoginPage";
import TenantsPage from "./pages/TenantsPage";
import TenantUsersPage from "./pages/TenantUsersPage";
import AuthGuard from "./components/AuthGuard";

interface AuthContextValue {
  token: string | null;
  setToken: (token: string | null) => void;
}

export const AuthContext = createContext<AuthContextValue>({
  token: null,
  setToken: () => {}
});

export const useAuth = () => useContext(AuthContext);

export default function App() {
  const [token, setTokenState] = useState<string | null>(
    () => sessionStorage.getItem("admin_session_token")
  );

  const setToken = (t: string | null) => {
    if (t === null) {
      sessionStorage.removeItem("admin_session_token");
    } else {
      sessionStorage.setItem("admin_session_token", t);
    }
    setTokenState(t);
  };

  return (
    <AuthContext.Provider value={{ token, setToken }}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<AuthGuard />}>
            <Route path="/tenants" element={<TenantsPage />} />
            <Route path="/tenants/:tenantId/users" element={<TenantUsersPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/tenants" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthContext.Provider>
  );
}
```

- [ ] **Step 4: Commit**

```bash
git add admin/src/main.tsx admin/src/index.css admin/src/App.tsx
git commit -m "feat: add auth context and app router"
```

---

## Task 12: Build shared components

**Files:**
- Create: `admin/src/components/AuthGuard.tsx`
- Create: `admin/src/components/Layout.tsx`
- Create: `admin/src/components/Modal.tsx`

- [ ] **Step 1: Create AuthGuard.tsx**

```typescript
import { Navigate, Outlet } from "react-router";
import { useAuth } from "../App";
import Layout from "./Layout";

export default function AuthGuard() {
  const { token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return <Layout><Outlet /></Layout>;
}
```

- [ ] **Step 2: Create Layout.tsx**

```typescript
import type { ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { useAuth } from "../App";

export default function Layout({ children }: { children: ReactNode }) {
  const { setToken } = useAuth();
  const navigate = useNavigate();

  const signOut = () => {
    setToken(null);
    navigate("/login");
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white border-b border-gray-200 px-6 py-3 flex items-center justify-between">
        <Link to="/tenants" className="font-semibold text-gray-900">Admin Panel</Link>
        <button
          onClick={signOut}
          className="text-sm text-gray-500 hover:text-gray-900"
        >
          Sign out
        </button>
      </nav>
      <main className="max-w-5xl mx-auto px-6 py-8">{children}</main>
    </div>
  );
}
```

- [ ] **Step 3: Create Modal.tsx**

```typescript
import type { ReactNode } from "react";

interface ModalProps {
  title: string;
  onClose: () => void;
  children: ReactNode;
}

export default function Modal({ title, onClose, children }: ModalProps) {
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-700 text-xl leading-none">&times;</button>
        </div>
        {children}
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Commit**

```bash
git add admin/src/components/
git commit -m "feat: add AuthGuard, Layout, and Modal components"
```

---

## Task 13: Build LoginPage

**Files:**
- Create: `admin/src/pages/LoginPage.tsx`

- [ ] **Step 1: Create LoginPage.tsx**

```typescript
import { useState } from "react";
import { useNavigate } from "react-router";
import { login } from "../api/client";
import { useAuth } from "../App";

export default function LoginPage() {
  const { setToken } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await login(email, password);
      setToken(res.session_token);
      navigate("/tenants");
    } catch {
      setError("Invalid email or password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="bg-white rounded-lg shadow p-8 w-full max-w-sm">
        <h1 className="text-xl font-semibold mb-6">Admin Sign In</h1>
        {error && (
          <div className="mb-4 text-sm text-red-600 bg-red-50 border border-red-200 rounded p-2">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium rounded py-2 text-sm"
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add admin/src/pages/LoginPage.tsx
git commit -m "feat: add LoginPage"
```

---

## Task 14: Build TenantsPage

**Files:**
- Create: `admin/src/pages/TenantsPage.tsx`

- [ ] **Step 1: Create TenantsPage.tsx**

```typescript
import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { createTenant, listTenants, type TenantSummary } from "../api/client";
import { useAuth } from "../App";
import Modal from "../components/Modal";

export default function TenantsPage() {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [tenants, setTenants] = useState<TenantSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [slug, setSlug] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const load = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const data = await listTenants(token);
      setTenants(data.tenants);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [token]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!slug.trim() || !displayName.trim()) {
      setFormError("All fields are required.");
      return;
    }
    setSubmitting(true);
    try {
      await createTenant(token!, slug.trim(), displayName.trim());
      setShowModal(false);
      setSlug("");
      setDisplayName("");
      await load();
    } catch {
      setFormError("Failed to create tenant. Slug may already exist.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-semibold">Tenants</h1>
        <button
          onClick={() => setShowModal(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded"
        >
          New Tenant
        </button>
      </div>

      {loading ? (
        <p className="text-gray-500 text-sm">Loading…</p>
      ) : tenants.length === 0 ? (
        <p className="text-gray-500 text-sm">No tenants yet.</p>
      ) : (
        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-600">
              <tr>
                <th className="text-left px-4 py-3 font-medium">Slug</th>
                <th className="text-left px-4 py-3 font-medium">Display Name</th>
                <th className="text-left px-4 py-3 font-medium">Status</th>
                <th className="text-left px-4 py-3 font-medium">Issuer</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {tenants.map((t) => (
                <tr
                  key={t.id}
                  onClick={() => navigate(`/tenants/${t.id}/users`)}
                  className="cursor-pointer hover:bg-gray-50"
                >
                  <td className="px-4 py-3 font-mono">{t.slug}</td>
                  <td className="px-4 py-3">{t.display_name}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${
                      t.status === "active" ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-600"
                    }`}>
                      {t.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs font-mono">{t.issuer ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && (
        <Modal title="New Tenant" onClose={() => setShowModal(false)}>
          <form onSubmit={handleCreate} className="space-y-4">
            {formError && (
              <p className="text-sm text-red-600">{formError}</p>
            )}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Slug</label>
              <input
                type="text"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="acme"
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Acme Corp"
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              />
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium rounded py-2 text-sm"
            >
              {submitting ? "Creating…" : "Create Tenant"}
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add admin/src/pages/TenantsPage.tsx
git commit -m "feat: add TenantsPage with tenant list and create modal"
```

---

## Task 15: Build TenantUsersPage

**Files:**
- Create: `admin/src/pages/TenantUsersPage.tsx`

- [ ] **Step 1: Create TenantUsersPage.tsx**

```typescript
import { useEffect, useState } from "react";
import { useParams } from "react-router";
import { getTenant, listUsers, provisionUser, type TenantSummary, type UserSummary } from "../api/client";
import { useAuth } from "../App";
import Modal from "../components/Modal";

export default function TenantUsersPage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const { token } = useAuth();
  const [tenant, setTenant] = useState<TenantSummary | null>(null);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const load = async () => {
    if (!token || !tenantId) return;
    setLoading(true);
    try {
      const [tenantData, usersData] = await Promise.all([
        getTenant(token, tenantId),
        listUsers(token, tenantId)
      ]);
      setTenant(tenantData);
      setUsers(usersData.users);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [token, tenantId]);

  const handleProvision = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!email.trim() || !displayName.trim()) {
      setFormError("Email and display name are required.");
      return;
    }
    setSubmitting(true);
    try {
      await provisionUser(token!, tenantId!, email.trim(), displayName.trim(), username.trim() || undefined);
      setShowModal(false);
      setEmail("");
      setDisplayName("");
      setUsername("");
      await load();
    } catch {
      setFormError("Failed to provision user. Email may already exist.");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <p className="text-gray-500 text-sm">Loading…</p>;
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold">{tenant?.display_name ?? tenantId}</h1>
        {tenant && <p className="text-sm text-gray-500 font-mono mt-1">{tenant.slug}</p>}
      </div>

      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-medium">Users</h2>
        <button
          onClick={() => setShowModal(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded"
        >
          Provision User
        </button>
      </div>

      {users.length === 0 ? (
        <p className="text-gray-500 text-sm">No users yet.</p>
      ) : (
        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-600">
              <tr>
                <th className="text-left px-4 py-3 font-medium">Email</th>
                <th className="text-left px-4 py-3 font-medium">Display Name</th>
                <th className="text-left px-4 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="px-4 py-3">{u.email}</td>
                  <td className="px-4 py-3">{u.display_name}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${
                      u.status === "active"
                        ? "bg-green-100 text-green-800"
                        : u.status === "provisioned"
                        ? "bg-yellow-100 text-yellow-800"
                        : "bg-gray-100 text-gray-600"
                    }`}>
                      {u.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && (
        <Modal title="Provision User" onClose={() => setShowModal(false)}>
          <form onSubmit={handleProvision} className="space-y-4">
            {formError && <p className="text-sm text-red-600">{formError}</p>}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Username <span className="text-gray-400 font-normal">(optional)</span>
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              />
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium rounded py-2 text-sm"
            >
              {submitting ? "Provisioning…" : "Provision User"}
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add admin/src/pages/TenantUsersPage.tsx
git commit -m "feat: add TenantUsersPage with user list and provision modal"
```

---

## Task 16: Verify SPA builds cleanly

- [ ] **Step 1: Run TypeScript check on SPA**

```bash
cd admin && pnpm tsc --noEmit
```

Expected: zero errors.

- [ ] **Step 2: Run build**

```bash
pnpm build
```

Expected: `dist/` directory created with `index.html`, JS/CSS bundles, and `_redirects`.

- [ ] **Step 3: Verify _redirects is in build output**

```bash
ls dist/_redirects
```

Expected: file exists.

- [ ] **Step 4: Run all Worker tests to confirm no regressions**

```bash
cd .. && pnpm test
```

Expected: all pass.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: complete admin panel SPA — login, tenants, user management"
```

---

## Task 17: Cloudflare Pages setup (manual — operator instructions)

These steps are performed by the operator in the Cloudflare dashboard, not by code.

- [ ] **Step 1: Create a new Cloudflare Pages project**
  - Name: `ma-hono-admin`
  - Connect to the same Git repository
  - Root directory: `admin/`
  - Build command: `pnpm install && pnpm build`
  - Build output: `dist/`

- [ ] **Step 2: Set environment variable in Pages**
  - Variable name: `VITE_API_BASE_URL`
  - Value: the deployed Worker URL (e.g., `https://auth.maplayer.top`)

- [ ] **Step 3: Deploy and note the Pages URL**
  - After first deploy, note the URL (e.g., `https://ma-hono-admin.pages.dev`)

- [ ] **Step 4: Set ADMIN_ORIGIN in Worker**
  - Update `wrangler.jsonc` `"vars"."ADMIN_ORIGIN"` to the Pages URL, or set it as a Worker secret
  - Redeploy the Worker: `wrangler deploy`

- [ ] **Step 5: Verify admin panel**
  - Visit `https://ma-hono-admin.pages.dev/login`
  - Log in with the credentials set during the setup wizard
  - Create a tenant, provision a user
