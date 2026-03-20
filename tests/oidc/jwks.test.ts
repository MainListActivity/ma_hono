import { describe, expect, it } from "vitest";

import { MemoryKeyRepository } from "../../src/adapters/db/memory/memory-key-repository";
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

const keyRepository = new MemoryKeyRepository([
  {
    id: "key_active_acme",
    tenantId: "tenant_acme",
    kid: "kid-active",
    alg: "ES256",
    kty: "EC",
    status: "active",
    publicJwk: {
      kid: "kid-active",
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
      use: "sig",
      x: "f83OJ3D2xF4xT5cU6d1b6q8L6o-l7Yx31xHn0SI7g0Y",
      y: "x_FEzRu9pG2bGS7dUdr9YzQKQwe4S4n1lWv1q5rE6E8"
    }
  },
  {
    id: "key_inactive_acme",
    tenantId: "tenant_acme",
    kid: "kid-inactive",
    alg: "ES256",
    kty: "EC",
    status: "retired",
    publicJwk: {
      kid: "kid-inactive",
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
      use: "sig",
      x: "4B2YVZxjzG5b1W3oJ6iQf0WQkXxwA7s1W8vM3v7F8I0",
      y: "7lP3zM7Q6Lq2iA9gH9hT1qT9mWk4xA5bD1rJ6qS2pLQ"
    }
  }
]);

describe("OIDC JWKS", () => {
  it("returns only active public keys for a platform-path issuer", async () => {
    const app = createApp({
      keyRepository,
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://idp.example.test/t/acme/jwks.json");

    expect(response.status).toBe(200);
    const body = await response.json();

    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]).toMatchObject({
      kid: "kid-active",
      kty: "EC",
      alg: "ES256",
      use: "sig"
    });
    expect(body.keys[0]).not.toHaveProperty("d");
  });

  it("returns issuer-context keys for a custom-domain issuer", async () => {
    const app = createApp({
      keyRepository,
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://login.acme.test/jwks.json");

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      keys: [expect.objectContaining({ kid: "kid-active" })]
    });
  });

  it("returns 404 when the jwks issuer cannot be resolved", async () => {
    const app = createApp({
      keyRepository,
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://idp.example.test/t/missing/jwks.json");

    expect(response.status).toBe(404);
  });
});
