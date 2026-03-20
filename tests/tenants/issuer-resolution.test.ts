import { describe, expect, it } from "vitest";

import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { resolveIssuerContext } from "../../src/domain/tenants/issuer-resolution";

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

describe("resolveIssuerContext", () => {
  it("resolves a platform path issuer from the platform host", async () => {
    const result = await resolveIssuerContext({
      platformHost: "idp.example.test",
      requestUrl: "https://idp.example.test/t/acme/.well-known/openid-configuration",
      tenantRepository
    });

    expect(result).toMatchObject({
      issuer: "https://idp.example.test/t/acme",
      issuerPathPrefix: "/t/acme",
      source: "platform_path"
    });
    expect(result?.tenant.slug).toBe("acme");
  });

  it("resolves a custom domain issuer by host before platform path matching", async () => {
    const result = await resolveIssuerContext({
      platformHost: "idp.example.test",
      requestUrl: "https://login.acme.test/.well-known/openid-configuration",
      tenantRepository
    });

    expect(result).toMatchObject({
      issuer: "https://login.acme.test",
      issuerPathPrefix: "",
      source: "custom_domain"
    });
    expect(result?.tenant.slug).toBe("acme");
  });

  it("returns null when the request host and path do not resolve a known issuer", async () => {
    const result = await resolveIssuerContext({
      platformHost: "idp.example.test",
      requestUrl: "https://idp.example.test/t/unknown/.well-known/openid-configuration",
      tenantRepository
    });

    expect(result).toBeNull();
  });
});
