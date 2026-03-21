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
      },
      {
        id: "issuer_custom_acme_cn",
        issuerType: "custom_domain",
        issuerUrl: "https://login.acme.cn",
        domain: "login.acme.cn",
        isPrimary: false,
        verificationStatus: "verified"
      }
    ]
  },
  {
    id: "tenant_disabled",
    slug: "disabled",
    displayName: "Disabled",
    status: "disabled",
    issuers: [
      {
        id: "issuer_platform_disabled",
        issuerType: "platform_path",
        issuerUrl: "https://idp.example.test/t/disabled",
        domain: null,
        isPrimary: true,
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
      authorization_endpoint: "https://idp.example.test/t/acme/authorize",
      token_endpoint: "https://idp.example.test/t/acme/token",
      grant_types_supported: ["authorization_code"],
      response_types_supported: ["code"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
        "none"
      ],
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
      registration_endpoint: "https://login.acme.test/connect/register",
      authorization_endpoint: "https://login.acme.test/authorize",
      token_endpoint: "https://login.acme.test/token",
      grant_types_supported: ["authorization_code"],
      response_types_supported: ["code"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
        "none"
      ]
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

  it("returns 404 for a platform-path discovery route requested on a custom-domain host", async () => {
    const app = createApp({
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://login.acme.test/t/acme/.well-known/openid-configuration"
    );

    expect(response.status).toBe(404);
  });

  it("returns 404 for disabled tenants", async () => {
    const app = createApp({
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://idp.example.test/t/disabled/.well-known/openid-configuration"
    );

    expect(response.status).toBe(404);
  });

  it("returns live error semantics for authorize and token endpoints", async () => {
    const app = createApp({
      platformHost: "idp.example.test",
      tenantRepository
    });

    const authorizeResponse = await app.request(
      "https://idp.example.test/t/acme/authorize"
    );
    const tokenResponse = await app.request("https://login.acme.test/token", {
      method: "POST"
    });
    const unknownHostResponse = await app.request("https://unknown.example.test/authorize");
    const disabledTenantResponse = await app.request(
      "https://idp.example.test/t/disabled/token",
      {
        method: "POST"
      }
    );
    const invalidCombinationResponse = await app.request(
      "https://login.acme.test/t/acme/authorize"
    );

    expect(authorizeResponse.status).toBe(400);
    await expect(authorizeResponse.json()).resolves.toMatchObject({
      error: "invalid_client"
    });

    expect(tokenResponse.status).toBe(400);
    await expect(tokenResponse.json()).resolves.toMatchObject({
      error: "invalid_request"
    });

    expect(unknownHostResponse.status).toBe(404);
    expect(disabledTenantResponse.status).toBe(404);
    expect(invalidCombinationResponse.status).toBe(404);
  });
});
