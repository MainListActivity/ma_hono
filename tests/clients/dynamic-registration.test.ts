import { describe, expect, it } from "vitest";

import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
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

describe("Dynamic Client Registration", () => {
  it("registers a client with a valid management credential and stores only secret hashes", async () => {
    const clientRepository = new MemoryClientRepository();
    const app = createApp({
      clientRepository,
      managementApiToken: "manage-acme",
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://idp.example.test/t/acme/connect/register", {
      method: "POST",
      headers: {
        authorization: "Bearer manage-acme",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        client_name: "Acme Web",
        application_type: "web",
        grant_types: ["authorization_code"],
        redirect_uris: ["https://app.acme.test/callback"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_basic"
      })
    });

    expect(response.status).toBe(201);
    const body = await response.json();

    expect(body.client_id).toBeTypeOf("string");
    expect(body.client_secret).toBeTypeOf("string");
    expect(body.registration_access_token).toBeTypeOf("string");
    expect(body.registration_client_uri).toBe(
      `https://idp.example.test/t/acme/connect/register/${body.client_id}`
    );

    const storedClient = await clientRepository.findByClientId(body.client_id);

    expect(storedClient).not.toBeNull();
    expect(storedClient?.clientSecretHash).not.toBe(body.client_secret);
    expect(storedClient?.registrationAccessTokenHash).not.toBe(body.registration_access_token);
  });

  it("rejects registration without a valid management credential", async () => {
    const app = createApp({
      clientRepository: new MemoryClientRepository(),
      managementApiToken: "manage-acme",
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://idp.example.test/t/acme/connect/register", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        client_name: "Acme Web",
        application_type: "web",
        grant_types: ["authorization_code"],
        redirect_uris: ["https://app.acme.test/callback"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_basic"
      })
    });

    expect(response.status).toBe(401);
  });

  it("rejects registration when redirect uris are invalid", async () => {
    const app = createApp({
      clientRepository: new MemoryClientRepository(),
      managementApiToken: "manage-acme",
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://idp.example.test/t/acme/connect/register", {
      method: "POST",
      headers: {
        authorization: "Bearer manage-acme",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        client_name: "Acme Web",
        application_type: "web",
        grant_types: ["authorization_code"],
        redirect_uris: ["not-a-valid-url"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_basic"
      })
    });

    expect(response.status).toBe(400);
  });

  it("returns an issuer-correct registration client uri for a custom-domain issuer", async () => {
    const app = createApp({
      clientRepository: new MemoryClientRepository(),
      managementApiToken: "manage-acme",
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://login.acme.test/connect/register", {
      method: "POST",
      headers: {
        authorization: "Bearer manage-acme",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        client_name: "Acme Native",
        application_type: "native",
        grant_types: ["authorization_code"],
        redirect_uris: ["com.acme.app:/oauth/callback"],
        response_types: ["code"],
        token_endpoint_auth_method: "none"
      })
    });

    expect(response.status).toBe(201);
    const body = await response.json();

    expect(body.registration_client_uri).toBe(
      `https://login.acme.test/connect/register/${body.client_id}`
    );
  });
});
