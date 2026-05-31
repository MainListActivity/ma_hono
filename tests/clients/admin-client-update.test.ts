import { describe, expect, it } from "vitest";

import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { createApp } from "../../src/app/app";
import { sha256Base64Url } from "../../src/lib/hash";
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

const makeApp = () => {
  const clientRepository = new MemoryClientRepository();
  const app = createApp({
    adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
    adminWhitelist: ["admin@example.test"],
    adminRepository: new MemoryAdminRepository({
      adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
    }),
    auditRepository: new MemoryAuditRepository(),
    clientAuthMethodPolicyRepository: new MemoryClientAuthMethodPolicyRepository(),
    clientRepository,
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    tenantRepository: new MemoryTenantRepository([acmeTenant]),
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });

  return { app, clientRepository };
};

const loginAsAdmin = async (app: ReturnType<typeof makeApp>["app"]) => {
  const response = await app.request("https://idp.example.test/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "admin@example.test", password: "bootstrap-secret" })
  });
  const body = (await response.json()) as { session_token: string };
  return body.session_token;
};

describe("PATCH /admin/tenants/:tenantId/clients/:clientId", () => {
  it("generates and stores a secret when a SPA client becomes a web client", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);

    await clientRepository.create({
      id: "client_spa",
      tenantId: "tenant_acme",
      clientId: "spa-client",
      clientName: "SPA Client",
      applicationType: "web",
      grantTypes: ["authorization_code"],
      redirectUris: ["https://app.example.test/callback"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "none",
      clientSecretHash: null,
      trustLevel: "first_party_trusted",
      consentPolicy: "skip",
      clientProfile: "spa",
      accessTokenAudience: "https://api.example.test"
    });

    const response = await app.request(
      "https://idp.example.test/admin/tenants/tenant_acme/clients/spa-client",
      {
        method: "PATCH",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          client_profile: "web",
          application_type: "web",
          token_endpoint_auth_method: "client_secret_basic",
          redirect_uris: ["https://app.example.test/callback"],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          access_token_audience: null
        })
      }
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as { client_secret?: string };
    expect(body.client_secret).toBeTypeOf("string");

    const stored = await clientRepository.findByClientId("spa-client");
    expect(stored?.clientProfile).toBe("web");
    expect(stored?.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(stored?.clientSecretHash).toBe(
      await sha256Base64Url(body.client_secret as string)
    );
    expect(stored?.clientSecretHash).not.toBe(body.client_secret);
  });
});
