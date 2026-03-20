import { describe, expect, it } from "vitest";

import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { createApp } from "../../src/app/app";

const tenantRepository = new MemoryTenantRepository([
  {
    id: "tenant_acme",
    slug: "acme",
    displayName: "Acme",
    status: "active",
    issuers: [
      {
        id: "issuer_platform_acme",
        issuerType: "platform_path",
        issuerUrl: "https://idp.example.test/t/acme",
        domain: null,
        isPrimary: true,
        verificationStatus: "verified"
      },
      {
        id: "issuer_custom_acme",
        issuerType: "custom_domain",
        issuerUrl: "https://login.acme.test",
        domain: "login.acme.test",
        isPrimary: false,
        verificationStatus: "verified"
      }
    ]
  }
]);

describe("OIDC discovery", () => {
  it("returns issuer-correct metadata for a platform-path issuer", async () => {
    const app = createApp({
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://idp.example.test/t/acme/.well-known/openid-configuration"
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      issuer: "https://idp.example.test/t/acme",
      jwks_uri: "https://idp.example.test/t/acme/jwks.json",
      registration_endpoint: "https://idp.example.test/t/acme/connect/register",
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"]
    });
  });

  it("returns issuer-correct metadata for a custom-domain issuer", async () => {
    const app = createApp({
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://login.acme.test/.well-known/openid-configuration");

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      issuer: "https://login.acme.test",
      jwks_uri: "https://login.acme.test/jwks.json",
      registration_endpoint: "https://login.acme.test/connect/register"
    });
  });

  it("returns 404 when the issuer cannot be resolved", async () => {
    const app = createApp({
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://idp.example.test/t/missing/.well-known/openid-configuration"
    );

    expect(response.status).toBe(404);
  });
});
