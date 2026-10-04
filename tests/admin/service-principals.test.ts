import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { createApp } from "../../src/app/app";
import { sha256Base64Url } from "../../src/lib/hash";

interface AdminLoginResponse {
  session_token: string;
}

interface MintResponse {
  id: string;
  label: string;
  scopes: string[];
  status: string;
  token: string;
  created_at: string;
  revoked_at: string | null;
  created_by: string;
}

const bootstrapHash = "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI";

const createFixture = () => {
  const adminRepository = new MemoryAdminRepository({
    adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
  });
  const auditRepository = new MemoryAuditRepository();
  const tenantRepository = new MemoryTenantRepository([
    {
      id: "tenant_ck",
      slug: "ck",
      displayName: "CK",
      status: "active",
      issuers: [
        {
          id: "issuer_ck",
          issuerType: "platform_path",
          issuerUrl: "https://idp.example.test/t/ck",
          domain: null,
          isPrimary: true,
          verificationStatus: "verified"
        }
      ]
    }
  ]);
  const userRepository = new MemoryUserRepository();
  const app = createApp({
    adminBootstrapPasswordHash: bootstrapHash,
    adminWhitelist: ["admin@example.test"],
    adminRepository,
    auditRepository,
    managementApiToken: "mgmt-token-not-for-provision",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    tenantRepository,
    userRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });

  return { app, adminRepository, auditRepository, tenantRepository, userRepository };
};

const loginAsAdmin = async (app: ReturnType<typeof createApp>) => {
  const loginResponse = await app.request("https://idp.example.test/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: "admin@example.test",
      password: "bootstrap-secret"
    })
  });
  expect(loginResponse.status).toBe(200);
  const body = (await loginResponse.json()) as AdminLoginResponse;
  return body.session_token;
};

const mintPrincipal = async (
  app: ReturnType<typeof createApp>,
  sessionToken: string,
  scopes = ["tenant.read", "user.read", "user.provision"]
) => {
  const response = await app.request("https://idp.example.test/admin/service-principals", {
    method: "POST",
    headers: {
      authorization: `Bearer ${sessionToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      label: "surreal-ck-invite",
      scopes
    })
  });
  expect(response.status).toBe(201);
  return (await response.json()) as MintResponse;
};

describe("admin service principals", () => {
  it("lets a human admin mint a principal that only stores a hash", async () => {
    const { app, adminRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken);

    expect(minted.token).toBeTypeOf("string");
    expect(minted.token.length).toBeGreaterThan(20);
    expect(minted.status).toBe("active");
    expect(minted.created_by).toBe("admin_1");

    const stored = adminRepository.listServicePrincipalsRaw();
    expect(stored).toHaveLength(1);
    expect(stored[0]?.tokenHash).toBe(await sha256Base64Url(minted.token));
    expect(JSON.stringify(stored)).not.toContain(minted.token);

    const listResponse = await app.request("https://idp.example.test/admin/service-principals", {
      headers: { authorization: `Bearer ${sessionToken}` }
    });
    expect(listResponse.status).toBe(200);
    const listBody = (await listResponse.json()) as {
      service_principals: Array<Record<string, unknown>>;
    };
    expect(listBody.service_principals).toHaveLength(1);
    expect(listBody.service_principals[0]).not.toHaveProperty("token");
    expect(listBody.service_principals[0]).not.toHaveProperty("token_hash");
    expect(listBody.service_principals[0]).not.toHaveProperty("tokenHash");
  });

  it("allows an active service token on the three invite scopes and audits provision as service_principal", async () => {
    const { app, auditRepository, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken);

    const tenantsResponse = await app.request("https://idp.example.test/admin/tenants", {
      headers: { authorization: `Bearer ${minted.token}` }
    });
    expect(tenantsResponse.status).toBe(200);
    await expect(tenantsResponse.json()).resolves.toMatchObject({
      tenants: [{ slug: "ck" }]
    });

    const usersResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_ck/users",
      { headers: { authorization: `Bearer ${minted.token}` } }
    );
    expect(usersResponse.status).toBe(200);

    const provisionResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_ck/users",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${minted.token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          email: "lawyer@example.test",
          display_name: "Lawyer"
        })
      }
    );
    expect(provisionResponse.status).toBe(201);
    const provisionBody = (await provisionResponse.json()) as {
      user: { id: string; email: string };
      invitation_token: string;
      activation_url: string;
    };
    expect(provisionBody.user.email).toBe("lawyer@example.test");
    expect(provisionBody.invitation_token).toBeTypeOf("string");
    expect(provisionBody.activation_url).toContain("token=");

    expect(userRepository.listUsers()).toHaveLength(1);

    const provisioned = auditRepository
      .listEvents()
      .find((event) => event.eventType === "user.provisioned");
    expect(provisioned).toMatchObject({
      actorType: "service_principal",
      actorId: minted.id,
      targetId: provisionBody.user.id,
      payload: { email: "lawyer@example.test" }
    });
    expect(JSON.stringify(provisioned)).not.toContain(minted.token);
    expect(JSON.stringify(provisioned)).not.toContain(provisionBody.invitation_token);
    expect(JSON.stringify(provisioned)).not.toContain(provisionBody.activation_url);
  });

  it("rejects a revoked service token with 403 and does not create a user", async () => {
    const { app, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken);

    const revokeResponse = await app.request(
      `https://idp.example.test/admin/service-principals/${minted.id}/revoke`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${sessionToken}` }
      }
    );
    expect(revokeResponse.status).toBe(200);
    await expect(revokeResponse.json()).resolves.toMatchObject({
      id: minted.id,
      status: "revoked"
    });

    const provisionResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_ck/users",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${minted.token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          email: "after-revoke@example.test",
          display_name: "After Revoke"
        })
      }
    );
    expect(provisionResponse.status).toBe(403);
    expect(userRepository.listUsers()).toHaveLength(0);
  });

  it("returns 403 when a service token calls out-of-scope admin routes including mint", async () => {
    const { app } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken);

    const createTenant = await app.request("https://idp.example.test/admin/tenants", {
      method: "POST",
      headers: {
        authorization: `Bearer ${minted.token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({ display_name: "Other", slug: "other" })
    });
    expect(createTenant.status).toBe(403);

    const mintAgain = await app.request("https://idp.example.test/admin/service-principals", {
      method: "POST",
      headers: {
        authorization: `Bearer ${minted.token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        label: "should-fail",
        scopes: ["tenant.read"]
      })
    });
    expect(mintAgain.status).toBe(403);

    const rotate = await app.request(
      "https://idp.example.test/admin/tenants/tenant_ck/keys/rotate",
      {
        method: "POST",
        headers: { authorization: `Bearer ${minted.token}` }
      }
    );
    expect(rotate.status).toBe(403);
  });

  it("returns 401 for missing or unknown bearer on scoped routes", async () => {
    const { app, userRepository } = createFixture();

    const missing = await app.request("https://idp.example.test/admin/tenants");
    expect(missing.status).toBe(401);

    const unknown = await app.request(
      "https://idp.example.test/admin/tenants/tenant_ck/users",
      {
        method: "POST",
        headers: {
          authorization: "Bearer totally-unknown-token",
          "content-type": "application/json"
        },
        body: JSON.stringify({
          email: "nope@example.test",
          display_name: "Nope"
        })
      }
    );
    expect(unknown.status).toBe(401);
    expect(userRepository.listUsers()).toHaveLength(0);
  });

  it("keeps human admin login and the three invite routes working", async () => {
    const { app, auditRepository, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);

    const tenantsResponse = await app.request("https://idp.example.test/admin/tenants", {
      headers: { authorization: `Bearer ${sessionToken}` }
    });
    expect(tenantsResponse.status).toBe(200);

    const usersResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_ck/users",
      { headers: { authorization: `Bearer ${sessionToken}` } }
    );
    expect(usersResponse.status).toBe(200);

    const provisionResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_ck/users",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${sessionToken}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          email: "human-provision@example.test",
          display_name: "Human Provision"
        })
      }
    );
    expect(provisionResponse.status).toBe(201);
    expect(userRepository.listUsers()).toHaveLength(1);

    const provisioned = auditRepository
      .listEvents()
      .find((event) => event.eventType === "user.provisioned");
    expect(provisioned).toMatchObject({
      actorType: "admin_user",
      actorId: "admin_1"
    });
  });

  it("does not accept management_api_token as a service principal", async () => {
    const { app } = createFixture();

    const response = await app.request("https://idp.example.test/admin/tenants", {
      headers: { authorization: "Bearer mgmt-token-not-for-provision" }
    });
    expect(response.status).toBe(401);
  });

  it("returns 403 when an active token lacks the route scope", async () => {
    const { app } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken, ["tenant.read"]);

    const provisionResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_ck/users",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${minted.token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          email: "missing-scope@example.test",
          display_name: "Missing Scope"
        })
      }
    );
    expect(provisionResponse.status).toBe(403);
  });
});
