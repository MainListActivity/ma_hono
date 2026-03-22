import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { createApp } from "../../src/app/app";

interface AdminLoginResponse {
  session_token: string;
}

describe("admin auth and management api", () => {
  it("allows a whitelist admin to log in and create a tenant", async () => {
    const tenantRepository = new MemoryTenantRepository();
    const adminRepository = new MemoryAdminRepository({
      adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
    });
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
      adminWhitelist: ["admin@example.test"],
      adminRepository,
      auditRepository,
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "bootstrap-secret"
      })
    });

    expect(loginResponse.status).toBe(200);
    const loginBody = (await loginResponse.json()) as AdminLoginResponse;

    expect(loginBody.session_token).toBeTypeOf("string");

    const createTenantResponse = await app.request("https://idp.example.test/admin/tenants", {
      method: "POST",
      headers: {
        authorization: `Bearer ${loginBody.session_token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        display_name: "Acme",
        slug: "acme"
      })
    });

    expect(createTenantResponse.status).toBe(201);
    await expect(createTenantResponse.json()).resolves.toMatchObject({
      slug: "acme",
      display_name: "Acme"
    });

    const tenant = await tenantRepository.findBySlug("acme");

    expect(tenant).not.toBeNull();
    expect(tenant?.displayName).toBe("Acme");
    expect(auditRepository.listEvents().map((event) => event.eventType)).toEqual([
      "admin.login.succeeded",
      "tenant.created"
    ]);
  });

  it("rejects a non-whitelist admin login", async () => {
    const app = createApp({
      adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
      }),
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository: new MemoryTenantRepository()
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "not-allowed@example.test",
        password: "bootstrap-secret"
      })
    });

    expect(loginResponse.status).toBe(403);
  });

  it("writes an audit event for failed admin login attempts", async () => {
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository(),
      auditRepository,
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository: new MemoryTenantRepository()
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "not-allowed@example.test",
        password: "bootstrap-secret"
      })
    });

    expect(loginResponse.status).toBe(403);
    expect(auditRepository.listEvents().map((event) => event.eventType)).toEqual([
      "admin.login.failed"
    ]);
  });

  it("returns 401 for an unauthenticated tenant create request", async () => {
    const app = createApp({
      adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
      }),
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository: new MemoryTenantRepository()
    });

    const createTenantResponse = await app.request("https://idp.example.test/admin/tenants", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        display_name: "Acme",
        slug: "acme"
      })
    });

    expect(createTenantResponse.status).toBe(401);
  });

  it("rejects login for a seeded admin who is not in the configured whitelist", async () => {
    const app = createApp({
      adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "ops@example.test", id: "admin_2", status: "active" }]
      }),
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository: new MemoryTenantRepository()
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "ops@example.test",
        password: "bootstrap-secret"
      })
    });

    expect(loginResponse.status).toBe(403);
  });

  it("rejects duplicate tenant slugs", async () => {
    const tenantRepository = new MemoryTenantRepository();
    const adminRepository = new MemoryAdminRepository({
      adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
    });
    const app = createApp({
      adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
      adminWhitelist: ["admin@example.test"],
      adminRepository,
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "bootstrap-secret"
      })
    });
    const loginBody = (await loginResponse.json()) as AdminLoginResponse;

    const createTenant = () =>
      app.request("https://idp.example.test/admin/tenants", {
        method: "POST",
        headers: {
          authorization: `Bearer ${loginBody.session_token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          display_name: "Acme",
          slug: "acme"
        })
      });

    expect((await createTenant()).status).toBe(201);
    expect((await createTenant()).status).toBe(409);
  });
});
