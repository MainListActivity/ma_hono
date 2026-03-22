import { describe, expect, it } from "vitest";

import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { Tenant } from "../../src/domain/tenants/types";

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

const makeApp = (tenantList: Tenant[] = [], userList: Array<{
  id: string;
  tenantId: string;
  email: string;
  emailVerified: boolean;
  username: string | null;
  displayName: string;
  status: "provisioned" | "active" | "disabled";
  createdAt: string;
  updatedAt: string;
}> = []) => {
  const tenantRepository = new MemoryTenantRepository(tenantList);
  const userRepository = new MemoryUserRepository({ users: userList });
  const adminRepository = new MemoryAdminRepository({
    adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
  });

  return createApp({
    adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
    adminWhitelist: ["admin@example.test"],
    adminRepository,
    auditRepository: new MemoryAuditRepository(),
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
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
