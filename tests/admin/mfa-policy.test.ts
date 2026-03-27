import { describe, expect, it } from "vitest";

import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
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

const makeApp = (tenantList: Tenant[] = []) => {
  const tenantRepository = new MemoryTenantRepository(tenantList);
  const userRepository = new MemoryUserRepository({ users: [] });
  const clientRepository = new MemoryClientRepository();
  const clientAuthMethodPolicyRepository = new MemoryClientAuthMethodPolicyRepository();
  const adminRepository = new MemoryAdminRepository({
    adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
  });

  return {
    app: createApp({
      adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
      adminWhitelist: ["admin@example.test"],
      adminRepository,
      auditRepository: new MemoryAuditRepository(),
      managementApiToken: "",
      oidcHost: "idp.example.test",
      authDomain: "auth.example.test",
      tenantRepository,
      userRepository,
      clientRepository,
      clientAuthMethodPolicyRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
    }),
    clientRepository
  };
};

const loginAs = async (app: ReturnType<typeof makeApp>["app"]) => {
  const res = await app.request("https://idp.example.test/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "admin@example.test", password: "bootstrap-secret" })
  });
  const body = (await res.json()) as { session_token: string };
  return body.session_token;
};

describe("PATCH /admin/tenants/:tenantId/clients/:clientId/auth-method-policy", () => {
  it("should set mfa_required to true and return it in the response", async () => {
    const { app, clientRepository } = makeApp([acmeTenant]);
    const token = await loginAs(app);

    // First, create a client
    const client = await clientRepository.create({
      id: "client_1",
      tenantId: "tenant_acme",
      clientId: "test-client",
      clientName: "Test Client",
      applicationType: "web",
      grantTypes: ["authorization_code"],
      redirectUris: ["https://app.example.test/callback"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "none",
      clientSecretHash: null,
      trustLevel: "first_party_trusted",
      consentPolicy: "skip",
      clientProfile: "web",
      accessTokenAudience: null
    });

    // PATCH the auth-method-policy with mfa_required: true
    const patchRes = await app.request(
      `https://idp.example.test/admin/tenants/tenant_acme/clients/test-client/auth-method-policy`,
      {
        method: "PATCH",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({ mfa_required: true })
      }
    );

    expect(patchRes.status).toBe(200);
    const patchBody = (await patchRes.json()) as Record<string, unknown>;
    expect(patchBody.auth_method_policy).toHaveProperty("mfa_required", true);
  });

  it("should toggle mfa_required from true to false", async () => {
    const { app, clientRepository } = makeApp([acmeTenant]);
    const token = await loginAs(app);

    // Create a client
    await clientRepository.create({
      id: "client_2",
      tenantId: "tenant_acme",
      clientId: "test-client-2",
      clientName: "Test Client 2",
      applicationType: "web",
      grantTypes: ["authorization_code"],
      redirectUris: ["https://app.example.test/callback"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "none",
      clientSecretHash: null,
      trustLevel: "first_party_trusted",
      consentPolicy: "skip",
      clientProfile: "web",
      accessTokenAudience: null
    });

    // First PATCH: set mfa_required to true
    await app.request(
      `https://idp.example.test/admin/tenants/tenant_acme/clients/test-client-2/auth-method-policy`,
      {
        method: "PATCH",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({ mfa_required: true })
      }
    );

    // Second PATCH: set mfa_required to false
    const patchRes = await app.request(
      `https://idp.example.test/admin/tenants/tenant_acme/clients/test-client-2/auth-method-policy`,
      {
        method: "PATCH",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({ mfa_required: false })
      }
    );

    expect(patchRes.status).toBe(200);
    const patchBody = (await patchRes.json()) as Record<string, unknown>;
    expect(patchBody.auth_method_policy).toHaveProperty("mfa_required", false);
  });
});
