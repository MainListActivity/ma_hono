# SPA Client & Custom Access Token Claims Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SPA client profile, per-client access token audience, and per-client custom access token claims so `ma_hono` can serve as an Auth0-style OIDC provider for third-party SPAs (e.g. SurrealDB integration).

**Architecture:** Extend the existing client model with a `clientProfile` field ("spa" | "web" | "native") and new fields for access token audience and custom claims. Custom claims live in a dedicated `client_access_token_claims` table. Token issuance reads the client's audience and custom claims config, resolves user-field mappings, and merges them into the access token payload.

**Tech Stack:** TypeScript, Hono, Drizzle ORM (D1), Zod, jose, Vitest

**Spec:** `docs/superpowers/specs/2026-03-27-spa-client-custom-access-token-claims-design.md`

---

## File Structure

### New Files
- `src/domain/clients/access-token-claims-types.ts` — types for custom access token claims
- `src/domain/clients/access-token-claims-repository.ts` — repository interface
- `src/domain/clients/admin-registration-schema.ts` — admin-specific registration schema with profile, audience, claims
- `src/domain/clients/resolve-custom-claims.ts` — claim resolution logic (user-field mapping + fixed values)
- `src/adapters/db/memory/memory-access-token-claims-repository.ts` — in-memory test implementation
- `drizzle/migrations/0005_spa_client_and_custom_claims.sql` — D1 migration
- `tests/clients/admin-client-registration.test.ts` — admin client creation tests (SPA profile, claims)
- `tests/clients/access-token-custom-claims.test.ts` — claim resolution + token issuance tests

### Modified Files
- `src/domain/clients/types.ts` — add `clientProfile`, `accessTokenAudience` to `Client`
- `src/domain/clients/repository.ts` — export `AccessTokenClaimsRepository`
- `src/domain/clients/registration-schema.ts` — relax web+none validation for SPA profile
- `src/domain/clients/register-client.ts` — accept and persist profile + audience
- `src/domain/tokens/claims.ts` — accept custom audience + extra claims
- `src/domain/tokens/token-service.ts` — load claims config, resolve, merge into access token
- `src/domain/audit/types.ts` — add new audit event types
- `src/adapters/db/drizzle/schema.ts` — add columns and new table
- `src/adapters/db/drizzle/runtime.ts` — update D1ClientRepository, add D1AccessTokenClaimsRepository
- `src/adapters/db/memory/memory-client-repository.ts` — handle new Client fields
- `src/app/app.ts` — wire new repository, update admin API endpoints
- `admin/src/api/client.ts` — update wire types and createClient payload
- `admin/src/pages/TenantClientsPage.tsx` — add profile selector, audience field, claims editor

---

## Task 1: Domain Types — Client Profile, Audience, Custom Claims

**Files:**
- Modify: `src/domain/clients/types.ts`
- Create: `src/domain/clients/access-token-claims-types.ts`

- [ ] **Step 1: Add profile and audience to Client type**

In `src/domain/clients/types.ts`, add new types and extend `Client`:

```ts
// Add after ClientConsentPolicy
export type ClientProfile = "spa" | "web" | "native";
```

Add to `Client` interface (after `consentPolicy`):
```ts
  clientProfile: ClientProfile;
  accessTokenAudience: string | null;
```

- [ ] **Step 2: Create access token claims types**

Create `src/domain/clients/access-token-claims-types.ts`:

```ts
export type AccessTokenClaimSourceType = "fixed" | "user_field";

export type AccessTokenClaimUserField =
  | "id"
  | "email"
  | "email_verified"
  | "username"
  | "display_name";

export const ALLOWED_USER_FIELDS: AccessTokenClaimUserField[] = [
  "id",
  "email",
  "email_verified",
  "username",
  "display_name"
];

export const RESERVED_CLAIM_NAMES = new Set([
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  "scope",
  "client_id",
  "nonce"
]);

export interface AccessTokenCustomClaim {
  id: string;
  clientId: string;
  tenantId: string;
  claimName: string;
  sourceType: AccessTokenClaimSourceType;
  fixedValue: string | null;
  userField: AccessTokenClaimUserField | null;
  createdAt: string;
  updatedAt: string;
}
```

- [ ] **Step 3: Verify types compile**

Run: `npx tsc --noEmit`
Expected: no errors related to new files

- [ ] **Step 4: Commit**

```bash
git add src/domain/clients/types.ts src/domain/clients/access-token-claims-types.ts
git commit -m "feat: add client profile, audience, and custom claims domain types"
```

---

## Task 2: Access Token Claims Repository Interface & Memory Implementation

**Files:**
- Create: `src/domain/clients/access-token-claims-repository.ts`
- Create: `src/adapters/db/memory/memory-access-token-claims-repository.ts`

- [ ] **Step 1: Create repository interface**

Create `src/domain/clients/access-token-claims-repository.ts`:

```ts
import type { AccessTokenCustomClaim } from "./access-token-claims-types";

export interface AccessTokenClaimsRepository {
  createMany(claims: AccessTokenCustomClaim[]): Promise<void>;
  replaceAllForClient(clientId: string, claims: AccessTokenCustomClaim[]): Promise<void>;
  listByClientId(clientId: string): Promise<AccessTokenCustomClaim[]>;
}
```

- [ ] **Step 2: Create memory implementation**

Create `src/adapters/db/memory/memory-access-token-claims-repository.ts`:

```ts
import type { AccessTokenClaimsRepository } from "../../../domain/clients/access-token-claims-repository";
import type { AccessTokenCustomClaim } from "../../../domain/clients/access-token-claims-types";

export class MemoryAccessTokenClaimsRepository implements AccessTokenClaimsRepository {
  private claims: AccessTokenCustomClaim[] = [];

  async createMany(claims: AccessTokenCustomClaim[]): Promise<void> {
    this.claims.push(...claims);
  }

  async replaceAllForClient(clientId: string, claims: AccessTokenCustomClaim[]): Promise<void> {
    this.claims = this.claims.filter((c) => c.clientId !== clientId);
    this.claims.push(...claims);
  }

  async listByClientId(clientId: string): Promise<AccessTokenCustomClaim[]> {
    return this.claims.filter((c) => c.clientId === clientId);
  }
}
```

- [ ] **Step 3: Verify types compile**

Run: `npx tsc --noEmit`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add src/domain/clients/access-token-claims-repository.ts src/adapters/db/memory/memory-access-token-claims-repository.ts
git commit -m "feat: add AccessTokenClaimsRepository interface and memory implementation"
```

---

## Task 3: Admin Registration Schema with Profile Validation

**Files:**
- Create: `src/domain/clients/admin-registration-schema.ts`
- Test: `tests/clients/admin-client-registration.test.ts`

- [ ] **Step 1: Write failing tests for admin registration schema**

Create `tests/clients/admin-client-registration.test.ts`:

```ts
import { describe, expect, it } from "vitest";

import { adminClientRegistrationSchema } from "../../src/domain/clients/admin-registration-schema";

describe("Admin Client Registration Schema", () => {
  const baseSpa = {
    client_name: "My SPA",
    client_profile: "spa",
    application_type: "web",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code"],
    response_types: ["code"],
    redirect_uris: ["https://app.example.com/callback"],
    access_token_audience: "https://api.example.com"
  };

  it("accepts a valid SPA client", () => {
    const result = adminClientRegistrationSchema.safeParse(baseSpa);
    expect(result.success).toBe(true);
  });

  it("rejects SPA without audience", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_audience: undefined
    });
    expect(result.success).toBe(false);
  });

  it("rejects SPA with confidential auth method", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      token_endpoint_auth_method: "client_secret_basic"
    });
    expect(result.success).toBe(false);
  });

  it("rejects SPA with application_type native", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      application_type: "native"
    });
    expect(result.success).toBe(false);
  });

  it("accepts a valid web client without audience", () => {
    const result = adminClientRegistrationSchema.safeParse({
      client_name: "My Web App",
      client_profile: "web",
      application_type: "web",
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: ["https://app.example.com/callback"]
    });
    expect(result.success).toBe(true);
  });

  it("rejects web client with auth method none", () => {
    const result = adminClientRegistrationSchema.safeParse({
      client_name: "My Web App",
      client_profile: "web",
      application_type: "web",
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: ["https://app.example.com/callback"]
    });
    expect(result.success).toBe(false);
  });

  it("rejects reserved claim names", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "sub", source_type: "fixed", fixed_value: "override" }
      ]
    });
    expect(result.success).toBe(false);
  });

  it("rejects user_field claims with invalid field", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "role", source_type: "user_field", user_field: "password_hash" }
      ]
    });
    expect(result.success).toBe(false);
  });

  it("accepts valid custom claims", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "ns", source_type: "fixed", fixed_value: "my_namespace" },
        { claim_name: "user_email", source_type: "user_field", user_field: "email" }
      ]
    });
    expect(result.success).toBe(true);
  });

  it("rejects fixed claims without fixed_value", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "ns", source_type: "fixed" }
      ]
    });
    expect(result.success).toBe(false);
  });

  it("rejects user_field claims without user_field", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "user_email", source_type: "user_field" }
      ]
    });
    expect(result.success).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/clients/admin-client-registration.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Create admin registration schema**

Create `src/domain/clients/admin-registration-schema.ts`:

```ts
import { z } from "zod";
import { ALLOWED_USER_FIELDS, RESERVED_CLAIM_NAMES } from "./access-token-claims-types";

const redirectUriSchema = z.string().superRefine((value, ctx) => {
  try {
    const url = new URL(value);
    if (url.protocol.length < 2) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "redirect uri must be absolute" });
    }
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "redirect uri must be a valid absolute url" });
  }
});

const customClaimSchema = z
  .object({
    claim_name: z.string().min(1),
    source_type: z.enum(["fixed", "user_field"]),
    fixed_value: z.string().min(1).optional(),
    user_field: z.enum(ALLOWED_USER_FIELDS as [string, ...string[]]).optional()
  })
  .superRefine((value, ctx) => {
    if (RESERVED_CLAIM_NAMES.has(value.claim_name)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `claim name "${value.claim_name}" is reserved`,
        path: ["claim_name"]
      });
    }
    if (value.source_type === "fixed" && value.fixed_value === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "fixed claims require a non-empty fixed_value",
        path: ["fixed_value"]
      });
    }
    if (value.source_type === "user_field" && value.user_field === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "user_field claims require an allowed user_field",
        path: ["user_field"]
      });
    }
  });

export const adminClientRegistrationSchema = z
  .object({
    client_name: z.string().min(1),
    client_profile: z.enum(["spa", "web", "native"]),
    application_type: z.enum(["web", "native"]),
    grant_types: z.array(z.enum(["authorization_code"])).min(1),
    redirect_uris: z.array(redirectUriSchema).min(1),
    response_types: z.array(z.enum(["code"])).min(1),
    trust_level: z.literal("first_party_trusted").default("first_party_trusted"),
    consent_policy: z.literal("skip").default("skip"),
    token_endpoint_auth_method: z.enum([
      "client_secret_basic",
      "client_secret_post",
      "none"
    ]),
    access_token_audience: z.string().min(1).optional(),
    access_token_custom_claims: z.array(customClaimSchema).optional()
  })
  .superRefine((value, ctx) => {
    if (value.client_profile === "spa") {
      if (value.application_type !== "web") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SPA clients must have application_type web",
          path: ["application_type"]
        });
      }
      if (value.token_endpoint_auth_method !== "none") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SPA clients must use token_endpoint_auth_method none",
          path: ["token_endpoint_auth_method"]
        });
      }
      if (value.access_token_audience === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SPA clients require an access_token_audience",
          path: ["access_token_audience"]
        });
      }
    }
    if (value.client_profile === "web") {
      if (value.token_endpoint_auth_method === "none") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "web clients must use a confidential auth method",
          path: ["token_endpoint_auth_method"]
        });
      }
    }
  });

export type AdminClientRegistrationInput = z.infer<typeof adminClientRegistrationSchema>;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/clients/admin-client-registration.test.ts`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/domain/clients/admin-registration-schema.ts tests/clients/admin-client-registration.test.ts
git commit -m "feat: add admin registration schema with SPA profile and custom claims validation"
```

---

## Task 4: Custom Claims Resolution Logic

**Files:**
- Create: `src/domain/clients/resolve-custom-claims.ts`
- Test: `tests/clients/access-token-custom-claims.test.ts`

- [ ] **Step 1: Write failing tests for claim resolution**

Create `tests/clients/access-token-custom-claims.test.ts`:

```ts
import { describe, expect, it } from "vitest";

import { resolveCustomClaims } from "../../src/domain/clients/resolve-custom-claims";
import type { AccessTokenCustomClaim } from "../../src/domain/clients/access-token-claims-types";
import type { User } from "../../src/domain/users/types";

const baseUser: User = {
  id: "user_1",
  tenantId: "tenant_1",
  email: "alice@example.com",
  emailVerified: true,
  username: "alice",
  displayName: "Alice Smith",
  status: "active",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z"
};

const makeClaim = (overrides: Partial<AccessTokenCustomClaim>): AccessTokenCustomClaim => ({
  id: "claim_1",
  clientId: "client_1",
  tenantId: "tenant_1",
  claimName: "custom",
  sourceType: "fixed",
  fixedValue: null,
  userField: null,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  ...overrides
});

describe("resolveCustomClaims", () => {
  it("resolves fixed claims", () => {
    const claims = [makeClaim({ claimName: "ns", sourceType: "fixed", fixedValue: "my_ns" })];
    const result = resolveCustomClaims(claims, baseUser);
    expect(result).toEqual({ ns: "my_ns" });
  });

  it("resolves user_field id", () => {
    const claims = [makeClaim({ claimName: "uid", sourceType: "user_field", userField: "id" })];
    const result = resolveCustomClaims(claims, baseUser);
    expect(result).toEqual({ uid: "user_1" });
  });

  it("resolves user_field email", () => {
    const claims = [makeClaim({ claimName: "user_email", sourceType: "user_field", userField: "email" })];
    const result = resolveCustomClaims(claims, baseUser);
    expect(result).toEqual({ user_email: "alice@example.com" });
  });

  it("resolves user_field email_verified", () => {
    const claims = [makeClaim({ claimName: "ev", sourceType: "user_field", userField: "email_verified" })];
    const result = resolveCustomClaims(claims, baseUser);
    expect(result).toEqual({ ev: true });
  });

  it("resolves user_field username", () => {
    const claims = [makeClaim({ claimName: "uname", sourceType: "user_field", userField: "username" })];
    const result = resolveCustomClaims(claims, baseUser);
    expect(result).toEqual({ uname: "alice" });
  });

  it("resolves user_field display_name", () => {
    const claims = [makeClaim({ claimName: "name", sourceType: "user_field", userField: "display_name" })];
    const result = resolveCustomClaims(claims, baseUser);
    expect(result).toEqual({ name: "Alice Smith" });
  });

  it("omits user_field claim when value is null", () => {
    const user = { ...baseUser, username: null };
    const claims = [makeClaim({ claimName: "uname", sourceType: "user_field", userField: "username" })];
    const result = resolveCustomClaims(claims, user);
    expect(result).toEqual({});
  });

  it("resolves multiple claims", () => {
    const claims = [
      makeClaim({ id: "c1", claimName: "ns", sourceType: "fixed", fixedValue: "my_ns" }),
      makeClaim({ id: "c2", claimName: "user_email", sourceType: "user_field", userField: "email" })
    ];
    const result = resolveCustomClaims(claims, baseUser);
    expect(result).toEqual({ ns: "my_ns", user_email: "alice@example.com" });
  });

  it("returns empty object when no claims", () => {
    const result = resolveCustomClaims([], baseUser);
    expect(result).toEqual({});
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/clients/access-token-custom-claims.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement claim resolution**

Create `src/domain/clients/resolve-custom-claims.ts`:

```ts
import type { AccessTokenCustomClaim } from "./access-token-claims-types";
import type { User } from "../users/types";

const resolveUserField = (
  user: User,
  field: string
): string | boolean | null => {
  switch (field) {
    case "id":
      return user.id;
    case "email":
      return user.email;
    case "email_verified":
      return user.emailVerified;
    case "username":
      return user.username;
    case "display_name":
      return user.displayName;
    default:
      return null;
  }
};

export const resolveCustomClaims = (
  claims: AccessTokenCustomClaim[],
  user: User
): Record<string, unknown> => {
  const result: Record<string, unknown> = {};

  for (const claim of claims) {
    if (claim.sourceType === "fixed") {
      if (claim.fixedValue !== null) {
        result[claim.claimName] = claim.fixedValue;
      }
    } else if (claim.sourceType === "user_field" && claim.userField !== null) {
      const value = resolveUserField(user, claim.userField);
      if (value !== null && value !== "") {
        result[claim.claimName] = value;
      }
    }
  }

  return result;
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/clients/access-token-custom-claims.test.ts`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/domain/clients/resolve-custom-claims.ts tests/clients/access-token-custom-claims.test.ts
git commit -m "feat: add custom claims resolution logic with user-field mapping"
```

---

## Task 5: Database Migration

**Files:**
- Create: `drizzle/migrations/0005_spa_client_and_custom_claims.sql`
- Modify: `src/adapters/db/drizzle/schema.ts`

- [ ] **Step 1: Create migration SQL**

Create `drizzle/migrations/0005_spa_client_and_custom_claims.sql`:

```sql
-- Add client profile and access token audience to oidc_clients
ALTER TABLE oidc_clients ADD COLUMN client_profile TEXT NOT NULL DEFAULT 'web';
ALTER TABLE oidc_clients ADD COLUMN access_token_audience TEXT;

-- Create client_access_token_claims table
CREATE TABLE client_access_token_claims (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  claim_name TEXT NOT NULL,
  source_type TEXT NOT NULL,
  fixed_value TEXT,
  user_field TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX client_access_token_claims_tenant_id_idx ON client_access_token_claims(tenant_id);
CREATE INDEX client_access_token_claims_client_id_idx ON client_access_token_claims(client_id);
CREATE UNIQUE INDEX client_access_token_claims_client_claim_unique ON client_access_token_claims(client_id, claim_name);
```

- [ ] **Step 2: Update Drizzle schema**

In `src/adapters/db/drizzle/schema.ts`, add to the `oidcClients` table definition (after `consentPolicy`):

```ts
    clientProfile: text("client_profile").notNull().default("web"),
    accessTokenAudience: text("access_token_audience"),
```

Add a new table definition after the existing tables:

```ts
export const clientAccessTokenClaims = sqliteTable(
  "client_access_token_claims",
  {
    id: text("id").primaryKey(),
    clientId: text("client_id")
      .notNull()
      .references(() => oidcClients.id, { onDelete: "cascade" }),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    claimName: text("claim_name").notNull(),
    sourceType: text("source_type").notNull(),
    fixedValue: text("fixed_value"),
    userField: text("user_field"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    tenantIdIdx: index("client_access_token_claims_tenant_id_idx").on(table.tenantId),
    clientIdIdx: index("client_access_token_claims_client_id_idx").on(table.clientId),
    clientClaimUnique: uniqueIndex("client_access_token_claims_client_claim_unique").on(
      table.clientId,
      table.claimName
    )
  })
);
```

- [ ] **Step 3: Verify types compile**

Run: `npx tsc --noEmit`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add drizzle/migrations/0005_spa_client_and_custom_claims.sql src/adapters/db/drizzle/schema.ts
git commit -m "feat: add migration for client_profile, access_token_audience, and claims table"
```

---

## Task 6: Update D1 and Memory Client Repositories

**Files:**
- Modify: `src/adapters/db/drizzle/runtime.ts` (D1ClientRepository)
- Modify: `src/adapters/db/memory/memory-client-repository.ts`

- [ ] **Step 1: Update D1ClientRepository**

In `src/adapters/db/drizzle/runtime.ts`, update `D1ClientRepository`:

In the `create` method, add to the `.values({...})` object:
```ts
      clientProfile: client.clientProfile,
      accessTokenAudience: client.accessTokenAudience,
```

In the `findByClientId` method, add to the return mapping:
```ts
          clientProfile: row.clientProfile as Client["clientProfile"],
          accessTokenAudience: row.accessTokenAudience,
```

In the `listByTenantId` method, add to the `.map()` return:
```ts
      clientProfile: row.clientProfile as Client["clientProfile"],
      accessTokenAudience: row.accessTokenAudience,
```

- [ ] **Step 2: Add D1AccessTokenClaimsRepository**

In `src/adapters/db/drizzle/runtime.ts`, add a new class after `D1ClientRepository`:

```ts
class D1AccessTokenClaimsRepository implements AccessTokenClaimsRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async createMany(claims: AccessTokenCustomClaim[]): Promise<void> {
    if (claims.length === 0) return;
    await this.db.insert(clientAccessTokenClaims).values(
      claims.map((c) => ({
        id: c.id,
        clientId: c.clientId,
        tenantId: c.tenantId,
        claimName: c.claimName,
        sourceType: c.sourceType,
        fixedValue: c.fixedValue,
        userField: c.userField,
        createdAt: c.createdAt,
        updatedAt: c.updatedAt
      }))
    );
  }

  async replaceAllForClient(clientId: string, claims: AccessTokenCustomClaim[]): Promise<void> {
    await this.db.delete(clientAccessTokenClaims).where(eq(clientAccessTokenClaims.clientId, clientId));
    await this.createMany(claims);
  }

  async listByClientId(clientId: string): Promise<AccessTokenCustomClaim[]> {
    const rows = await this.db
      .select()
      .from(clientAccessTokenClaims)
      .where(eq(clientAccessTokenClaims.clientId, clientId));

    return rows.map((row) => ({
      id: row.id,
      clientId: row.clientId,
      tenantId: row.tenantId,
      claimName: row.claimName,
      sourceType: row.sourceType as AccessTokenCustomClaim["sourceType"],
      fixedValue: row.fixedValue,
      userField: row.userField as AccessTokenCustomClaim["userField"],
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    }));
  }
}
```

Add the necessary imports at the top of the file:
```ts
import type { AccessTokenClaimsRepository } from "../../../domain/clients/access-token-claims-repository";
import type { AccessTokenCustomClaim } from "../../../domain/clients/access-token-claims-types";
import { clientAccessTokenClaims } from "./schema";
```

- [ ] **Step 3: Wire D1AccessTokenClaimsRepository into createRuntimeRepositories**

In `src/adapters/db/drizzle/runtime.ts`:

First, add `clientAccessTokenClaims` to the Drizzle schema object in `createRuntimeRepositories` (around line 1347):
```ts
    schema: {
      // ... existing tables ...
      clientAccessTokenClaims
    }
```

Then add the new repository to the return object (around line 1385):
```ts
    accessTokenClaimsRepository: new D1AccessTokenClaimsRepository(db),
```

- [ ] **Step 4: Wire accessTokenClaimsRepository into createApp in src/index.ts**

In `src/index.ts`, add to the `createApp({...})` call (around line 83):
```ts
      accessTokenClaimsRepository: repositories.accessTokenClaimsRepository,
```

- [ ] **Step 5: Verify types compile**

Run: `npx tsc --noEmit`
Expected: errors about missing `clientProfile` and `accessTokenAudience` in test fixtures — these will be fixed in subsequent tasks

- [ ] **Step 6: Commit**

```bash
git add src/adapters/db/drizzle/runtime.ts src/index.ts
git commit -m "feat: update D1 and memory client repositories for profile and audience fields"
```

---

## Task 7: Update Client Registration Logic

**Files:**
- Modify: `src/domain/clients/register-client.ts`
- Modify: `src/domain/clients/registration-schema.ts`

- [ ] **Step 1: Update dynamic registration schema**

In `src/domain/clients/registration-schema.ts`, the existing refinement rejects `web + none`. This conflicts with SPA clients. However, the dynamic registration endpoint (public) should **not** support SPA creation — only the admin API does. So the dynamic registration schema stays as-is. No changes needed here.

- [ ] **Step 2: Create admin registration function**

In `src/domain/clients/register-client.ts`, add a new export for admin registration that uses the admin schema:

```ts
import {
  adminClientRegistrationSchema,
  type AdminClientRegistrationInput
} from "./admin-registration-schema";
import type { AccessTokenClaimsRepository } from "./access-token-claims-repository";
import type { AccessTokenCustomClaim } from "./access-token-claims-types";

export const registerClientFromAdmin = async ({
  accessTokenClaimsRepository,
  clientRepository,
  input,
  issuerContext
}: {
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  clientRepository: ClientRepository;
  input: unknown;
  issuerContext: ResolvedIssuerContext;
}): Promise<RegisterClientResult> => {
  const payload = adminClientRegistrationSchema.parse(input);
  const clientId = crypto.randomUUID();
  const clientSecret = requiresClientSecret(payload.token_endpoint_auth_method)
    ? createRandomToken()
    : null;
  const registrationAccessToken = createRandomToken();
  const internalId = crypto.randomUUID();
  const now = new Date().toISOString();

  const client: Client = {
    id: internalId,
    tenantId: issuerContext.tenant.id,
    clientId,
    clientName: payload.client_name,
    applicationType: payload.application_type,
    grantTypes: payload.grant_types,
    redirectUris: payload.redirect_uris,
    responseTypes: payload.response_types,
    tokenEndpointAuthMethod: payload.token_endpoint_auth_method,
    clientSecretHash: clientSecret === null ? null : await sha256Base64Url(clientSecret),
    trustLevel: payload.trust_level,
    consentPolicy: payload.consent_policy,
    clientProfile: payload.client_profile,
    accessTokenAudience: payload.access_token_audience ?? null
  };

  await clientRepository.create(client);

  // Persist custom claims if provided
  const claimInputs = payload.access_token_custom_claims ?? [];
  if (claimInputs.length > 0) {
    const claims: AccessTokenCustomClaim[] = claimInputs.map((c) => ({
      id: crypto.randomUUID(),
      clientId: internalId,
      tenantId: issuerContext.tenant.id,
      claimName: c.claim_name,
      sourceType: c.source_type,
      fixedValue: c.source_type === "fixed" ? (c.fixed_value ?? null) : null,
      userField: c.source_type === "user_field" ? (c.user_field ?? null) : null,
      createdAt: now,
      updatedAt: now
    }));
    await accessTokenClaimsRepository.createMany(claims);
  }

  return { client, clientSecret, registrationAccessToken };
};
```

- [ ] **Step 3: Update existing registerClient to include new fields with defaults**

In the existing `registerClient` function, update the `Client` construction to add:
```ts
    clientProfile: "web" as const,
    accessTokenAudience: null,
```

- [ ] **Step 4: Verify types compile**

Run: `npx tsc --noEmit`
Expected: remaining errors in tests that construct Client objects (expected — to be fixed next)

- [ ] **Step 5: Commit**

```bash
git add src/domain/clients/register-client.ts
git commit -m "feat: add admin client registration with profile, audience, and custom claims"
```

---

## Task 8: Update Token Service for Custom Audience and Claims

**Files:**
- Modify: `src/domain/tokens/claims.ts`
- Modify: `src/domain/tokens/token-service.ts`

- [ ] **Step 1: Update buildAccessTokenClaims to accept extra claims**

In `src/domain/tokens/claims.ts`, update `buildAccessTokenClaims`:

```ts
export const buildAccessTokenClaims = ({
  audience,
  clientId,
  extraClaims,
  issuer,
  nowSeconds,
  scope,
  userId
}: BaseTokenClaimsInput & {
  clientId: string;
  extraClaims?: Record<string, unknown>;
}): AccessTokenClaims => ({
  iss: issuer,
  sub: userId,
  aud: audience,
  client_id: clientId,
  iat: nowSeconds,
  exp: nowSeconds + 60 * 60,
  scope,
  ...extraClaims
});
```

Note: `BaseTokenClaimsInput.audience` is now the resolved audience (from client config or fallback to clientId), and we add a separate `clientId` parameter.

- [ ] **Step 2: Refactor authenticateClient to return full Client object**

In `src/domain/tokens/token-service.ts`, the `authenticateClient` function (line 85) already loads the full `Client` object from the repository at line 142 but discards it, returning only `{ clientId, tenantId }`. This causes a redundant DB lookup when we need the full client later.

Update the success return type of `authenticateClient` from:
```ts
  | { ok: true; clientId: string; tenantId: string }
```
to:
```ts
  | { ok: true; client: Client }
```

Update all three success return paths (lines 163, 206, ~210) to return:
```ts
    return { ok: true, client };
```

Update the caller in `exchangeAuthorizationCode` to use `authenticatedClient.client.clientId` and `authenticatedClient.client.tenantId` where it currently uses `authenticatedClient.clientId` and `authenticatedClient.tenantId`.

Add the import:
```ts
import type { Client } from "../clients/types";
```

- [ ] **Step 3: Add custom claims resolution to exchangeAuthorizationCode**

In `src/domain/tokens/token-service.ts`, update the `exchangeAuthorizationCode` function:

Add new dependencies to the function signature:
```ts
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  userRepository: UserRepository;
```

After the authorization code validation succeeds and before token building, add:

```ts
    // Load custom claims config and resolve them
    const client = authenticatedClient.client;
    const customClaimConfigs = await accessTokenClaimsRepository.listByClientId(client.id);

    let extraClaims: Record<string, unknown> = {};
    if (customClaimConfigs.length > 0) {
      const user = await userRepository.findUserById(codeRecord.tenantId, codeRecord.userId);
      if (user === null) {
        return {
          kind: "error",
          clientId: client.clientId,
          error: "server_error",
          status: 400
        };
      }
      extraClaims = resolveCustomClaims(customClaimConfigs, user);
    }

    const resolvedAudience = client.accessTokenAudience ?? client.clientId;
```

Update the `buildAccessTokenClaims` call:
```ts
    const accessTokenClaims = buildAccessTokenClaims({
      audience: resolvedAudience,
      clientId: client.clientId,
      extraClaims,
      issuer: issuerContext.issuer,
      nowSeconds,
      scope: codeRecord.scope,
      userId: codeRecord.userId
    });
```

Add the necessary imports:
```ts
import type { AccessTokenClaimsRepository } from "../clients/access-token-claims-repository";
import type { UserRepository } from "../users/repository";
import { resolveCustomClaims } from "../clients/resolve-custom-claims";
```

- [ ] **Step 4: ID token stays unchanged**

The `buildIdTokenClaims` call stays the same — it uses `client.clientId` as the audience, unchanged.

- [ ] **Step 4: Verify types compile**

Run: `npx tsc --noEmit`
Expected: errors in test files that call `exchangeAuthorizationCode` without new params — expected

- [ ] **Step 5: Commit**

```bash
git add src/domain/tokens/claims.ts src/domain/tokens/token-service.ts
git commit -m "feat: support custom audience and extra claims in access token issuance"
```

---

## Task 9: Update Admin API Endpoints

**Files:**
- Modify: `src/app/app.ts`
- Modify: `src/domain/audit/types.ts`

- [ ] **Step 1: Add audit event type**

In `src/domain/audit/types.ts`, add to the `AuditEventType` union:
```ts
  | "oidc.client.token_profile.updated"
```

- [ ] **Step 2: Wire accessTokenClaimsRepository in AppOptions**

In `src/app/app.ts`, add to `AppOptions` interface:
```ts
  accessTokenClaimsRepository?: AccessTokenClaimsRepository;
```

In `createApp`, add:
```ts
  const accessTokenClaimsRepository = options.accessTokenClaimsRepository ?? new EmptyAccessTokenClaimsRepository();
```

Add an empty implementation (near the other Empty* classes at the top of the file):
```ts
class EmptyAccessTokenClaimsRepository implements AccessTokenClaimsRepository {
  async createMany(): Promise<void> {}
  async replaceAllForClient(): Promise<void> {}
  async listByClientId(): Promise<AccessTokenCustomClaim[]> { return []; }
}
```

Add imports:
```ts
import type { AccessTokenClaimsRepository } from "../domain/clients/access-token-claims-repository";
import type { AccessTokenCustomClaim } from "../domain/clients/access-token-claims-types";
import { registerClientFromAdmin } from "../domain/clients/register-client";
```

- [ ] **Step 3: Update POST /admin/tenants/:tenantId/clients (line 3060)**

Replace the `registerClient` call at **line 3088** in the admin endpoint (`POST /admin/tenants/:tenantId/clients`) with `registerClientFromAdmin`. Do **NOT** change the dynamic registration endpoint at line 2224 — that endpoint uses the public `registerClient` function and must remain unchanged.

```ts
      const result = await registerClientFromAdmin({
        accessTokenClaimsRepository,
        clientRepository,
        input: payload,
        issuerContext
      });
```

Update the response to include new fields:
```ts
      return context.json(
        {
          client_id: result.client.clientId,
          client_secret: result.clientSecret,
          client_name: result.client.clientName,
          redirect_uris: result.client.redirectUris,
          application_type: result.client.applicationType,
          token_endpoint_auth_method: result.client.tokenEndpointAuthMethod,
          grant_types: result.client.grantTypes,
          response_types: result.client.responseTypes,
          trust_level: result.client.trustLevel,
          consent_policy: result.client.consentPolicy,
          client_profile: result.client.clientProfile,
          access_token_audience: result.client.accessTokenAudience
        },
        201
      );
```

Update the audit event payload to include:
```ts
          payload: {
            application_type: result.client.applicationType,
            client_name: result.client.clientName,
            client_profile: result.client.clientProfile,
            access_token_audience: result.client.accessTokenAudience
          },
```

- [ ] **Step 4: Update GET list and GET single endpoints**

In both the list endpoint (around line 2896) and the single-client endpoint (around line 2946), add to the response objects:
```ts
        client_profile: c.clientProfile,
        access_token_audience: c.accessTokenAudience,
```

For the single-client GET, also load and return claims count:
```ts
    const claims = await accessTokenClaimsRepository.listByClientId(client.id);
```
And add to the response:
```ts
      access_token_custom_claims_count: claims.length,
```

- [ ] **Step 5: Update exchangeAuthorizationCode call in the token endpoint**

Find where `exchangeAuthorizationCode` is called in `app.ts` (line 2059) and add the new dependencies:
```ts
      accessTokenClaimsRepository,
      userRepository,
```

Also update any code that reads from the `result` object to use `result.clientId` (which is already a string from the success/error results — no change needed there since the result types are unchanged).

- [ ] **Step 6: Verify types compile**

Run: `npx tsc --noEmit`
Expected: test compilation errors only

- [ ] **Step 7: Commit**

```bash
git add src/app/app.ts src/domain/audit/types.ts
git commit -m "feat: wire admin API endpoints for SPA client profile, audience, and claims"
```

---

## Task 10: Fix Existing Tests

**Files:**
- Modify: various test files that construct Client objects

- [ ] **Step 1: Find all test files that construct Client objects**

Run: `grep -rn "clientProfile\|applicationType.*web\|applicationType.*native" tests/` and identify any Client literal constructions that are missing the new fields.

Also search for direct `registerClient` calls and `exchangeAuthorizationCode` calls in tests.

- [ ] **Step 2: Add default fields to all Client fixtures in tests**

For every test that constructs a `Client` object directly, add:
```ts
    clientProfile: "web",
    accessTokenAudience: null,
```

For tests that call `exchangeAuthorizationCode`, add the new required params:
```ts
    accessTokenClaimsRepository: new MemoryAccessTokenClaimsRepository(),
    userRepository,
```

- [ ] **Step 3: Run full test suite**

Run: `npx vitest run`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add tests/
git commit -m "fix: update test fixtures for new client profile and audience fields"
```

---

## Task 11: Token Issuance Integration Test

**Files:**
- Add to: `tests/clients/access-token-custom-claims.test.ts`

- [ ] **Step 1: Write integration tests for token endpoint with custom claims**

Add to `tests/clients/access-token-custom-claims.test.ts`:

```ts
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryAccessTokenClaimsRepository } from "../../src/adapters/db/memory/memory-access-token-claims-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryRegistrationAccessTokenRepository } from "../../src/adapters/db/memory/memory-registration-access-token-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { createApp } from "../../src/app/app";
import { decodeJwt } from "jose";

// ... set up tenant, client, and user fixtures as needed

describe("Token endpoint with custom claims", () => {
  it("includes configured audience in access token", async () => {
    // Create an SPA client via admin API with access_token_audience
    // Perform the full PKCE flow
    // Exchange code for tokens
    // Decode the access token and verify aud matches the configured audience
    // Verify client_id is still the OAuth client_id (not the audience)
  });

  it("includes fixed custom claims in access token", async () => {
    // Create SPA client with fixed custom claims
    // Complete the token exchange
    // Decode access token and verify fixed claims are present
  });

  it("includes user-field mapped claims in access token", async () => {
    // Create SPA client with user_field custom claims
    // Complete the token exchange
    // Decode access token and verify user field values are present
  });

  it("does NOT include custom claims in ID token", async () => {
    // Create SPA client with custom claims
    // Complete the token exchange
    // Decode ID token and verify custom claims are NOT present
  });
});
```

**Important:** The test bodies above are skeleton placeholders. Implement full test bodies following the PKCE flow patterns in `tests/oidc/token-endpoint.test.ts` — specifically how it sets up a client, creates an authorization code, and performs the token exchange. Use `decodeJwt` from `jose` to inspect the access token payload without verifying the signature.

- [ ] **Step 2: Run the integration tests**

Run: `npx vitest run tests/clients/access-token-custom-claims.test.ts`
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add tests/clients/access-token-custom-claims.test.ts
git commit -m "test: add integration tests for token endpoint with custom audience and claims"
```

---

## Task 12: Admin UI — Profile Selector and Audience Field

**Files:**
- Modify: `admin/src/api/client.ts`
- Modify: `admin/src/pages/TenantClientsPage.tsx`

- [ ] **Step 1: Update wire types**

In `admin/src/api/client.ts`, update `ClientSummary`:
```ts
export interface ClientSummary {
  id: string;
  client_id: string;
  client_name: string;
  application_type: "web" | "native";
  client_profile: "spa" | "web" | "native";
  access_token_audience: string | null;
  access_token_custom_claims_count?: number;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  trust_level: string;
  consent_policy: string;
  auth_method_policy: AuthMethodPolicyWire | null;
}
```

Update `createClient` payload type to include the new fields:
```ts
export const createClient = async (
  token: string,
  tenantId: string,
  payload: {
    client_name: string;
    client_profile: "spa" | "web" | "native";
    application_type: "web" | "native";
    redirect_uris: string[];
    token_endpoint_auth_method: string;
    grant_types: string[];
    response_types: string[];
    access_token_audience?: string;
    access_token_custom_claims?: {
      claim_name: string;
      source_type: "fixed" | "user_field";
      fixed_value?: string;
      user_field?: string;
    }[];
  }
) => {
  // ... existing fetch logic
};
```

- [ ] **Step 2: Add profile selector to client creation form**

In `admin/src/pages/TenantClientsPage.tsx`, in the client creation form:

1. Add a `Client Profile` selector above the existing `Application Type` field:
   - Options: `SPA`, `Web`, `Native`
   - Default: `Web`

2. When `SPA` is selected, auto-set and disable:
   - `application_type = "web"`
   - `token_endpoint_auth_method = "none"`
   - `grant_types = ["authorization_code"]`
   - `response_types = ["code"]`

3. Show the `Access Token Audience` input field (required for SPA, optional otherwise)

4. Wire the new fields into the `createClient` API call

- [ ] **Step 3: Update client list display**

In the client list grid, add a `Profile` column showing `SPA`, `Web`, or `Native`.

Show configured audience in the client detail view if present.

- [ ] **Step 4: Commit**

```bash
git add admin/src/api/client.ts admin/src/pages/TenantClientsPage.tsx
git commit -m "feat: add SPA profile selector and audience field to admin UI"
```

---

## Task 13: Admin UI — Custom Claims Editor

**Files:**
- Modify: `admin/src/pages/TenantClientsPage.tsx`

- [ ] **Step 1: Add claims editor to creation form**

Below the audience field, add a "Custom Access Token Claims" section:

- "Add Claim" button that adds a new row
- Each row has:
  - Claim Name text input
  - Source Type select (Fixed Value / User Field)
  - If Fixed: text input for the value
  - If User Field: select dropdown with options: `id`, `email`, `email_verified`, `username`, `display_name`
  - Remove row button (X)
- Claims array is sent as `access_token_custom_claims` in the API payload

- [ ] **Step 2: Wire claims into the createClient call**

Map the form state to the API payload format:
```ts
access_token_custom_claims: claims.map(c => ({
  claim_name: c.claimName,
  source_type: c.sourceType,
  ...(c.sourceType === "fixed" ? { fixed_value: c.fixedValue } : { user_field: c.userField })
}))
```

- [ ] **Step 3: Show claims count in client list**

In the client list, show a badge or count next to the profile column if `access_token_custom_claims_count > 0`.

- [ ] **Step 4: Commit**

```bash
git add admin/src/pages/TenantClientsPage.tsx
git commit -m "feat: add custom access token claims editor to admin UI"
```

---

## Task 14: Full Test Suite Pass & Cleanup

- [ ] **Step 1: Run the complete test suite**

Run: `npx vitest run`
Expected: all PASS

- [ ] **Step 2: Run type check**

Run: `npx tsc --noEmit`
Expected: no errors

- [ ] **Step 3: Run linter if configured**

Run: `npx eslint src/ tests/ admin/src/ --ext .ts,.tsx` (or whatever lint config exists)
Expected: no new warnings

- [ ] **Step 4: Final commit if any cleanup was needed**

```bash
git add -A
git commit -m "chore: final cleanup for SPA client and custom claims feature"
```
