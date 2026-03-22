import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryRegistrationAccessTokenRepository } from "../../src/adapters/db/memory/memory-registration-access-token-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { createApp } from "../../src/app/app";
import type { AuditRepository } from "../../src/domain/audit/repository";
import type { RegistrationAccessTokenRecord, RegistrationAccessTokenRepository } from "../../src/domain/clients/registration-access-token-repository";

interface DynamicClientRegistrationResponse {
  client_id: string;
  client_secret: string | null;
  registration_access_token: string;
  registration_client_uri: string;
}

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
  class FailingRegistrationAccessTokenRepository
    implements RegistrationAccessTokenRepository
  {
    async store(_record: RegistrationAccessTokenRecord): Promise<void> {
      throw new Error("KV unavailable");
    }

    async deleteByTokenHash(): Promise<void> {
      return;
    }
  }

  it("registers a client with a valid management credential and stores only secret hashes", async () => {
    const clientRepository = new MemoryClientRepository();
    const auditRepository = new MemoryAuditRepository();
    const registrationAccessTokenRepository = new MemoryRegistrationAccessTokenRepository();
    const app = createApp({
      auditRepository,
      clientRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "manage-acme",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      registrationAccessTokenRepository,
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
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
    const body = (await response.json()) as DynamicClientRegistrationResponse;

    expect(body.client_id).toBeTypeOf("string");
    expect(body.client_secret).toBeTypeOf("string");
    expect(body.registration_access_token).toBeTypeOf("string");
    expect(body.registration_client_uri).toBe(
      `https://idp.example.test/t/acme/connect/register/${body.client_id}`
    );

    const storedClient = await clientRepository.findByClientId(body.client_id);

    expect(storedClient).not.toBeNull();
    expect(storedClient?.clientSecretHash).not.toBe(body.client_secret);
    expect(registrationAccessTokenRepository.listTokens()).toHaveLength(1);
    expect(registrationAccessTokenRepository.listTokens()[0]?.clientId).toBe(body.client_id);
    expect(registrationAccessTokenRepository.listTokens()[0]?.tokenHash).not.toBe(
      body.registration_access_token
    );
    expect(auditRepository.listEvents().map((event) => event.eventType)).toEqual([
      "oidc.client.registered"
    ]);
  });

  it("rejects registration without a valid management credential", async () => {
    const app = createApp({
      clientRepository: new MemoryClientRepository(),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "manage-acme",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
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
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "manage-acme",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
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
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "manage-acme",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
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
    const body = (await response.json()) as DynamicClientRegistrationResponse;

    expect(body.registration_client_uri).toBe(
      `https://login.acme.test/connect/register/${body.client_id}`
    );
  });

  it("rejects unsupported response and grant types", async () => {
    const app = createApp({
      clientRepository: new MemoryClientRepository(),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "manage-acme",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
    });

    const response = await app.request("https://idp.example.test/t/acme/connect/register", {
      method: "POST",
      headers: {
        authorization: "Bearer manage-acme",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        client_name: "Acme SPA",
        application_type: "web",
        grant_types: ["implicit"],
        redirect_uris: ["https://app.acme.test/callback"],
        response_types: ["token"],
        token_endpoint_auth_method: "none"
      })
    });

    expect(response.status).toBe(400);
  });

  it("rejects private_key_jwt until client key material is supported", async () => {
    const app = createApp({
      clientRepository: new MemoryClientRepository(),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "manage-acme",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
    });

    const response = await app.request("https://idp.example.test/t/acme/connect/register", {
      method: "POST",
      headers: {
        authorization: "Bearer manage-acme",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        client_name: "Acme Service",
        application_type: "web",
        grant_types: ["authorization_code"],
        redirect_uris: ["https://app.acme.test/callback"],
        response_types: ["code"],
        token_endpoint_auth_method: "private_key_jwt"
      })
    });

    expect(response.status).toBe(400);
  });

  it("does not leave a client behind when registration token storage fails", async () => {
    const clientRepository = new MemoryClientRepository();
    const app = createApp({
      clientRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "manage-acme",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      registrationAccessTokenRepository: new FailingRegistrationAccessTokenRepository(),
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
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

    expect(response.status).toBe(500);
    expect(clientRepository.listClients()).toHaveLength(0);
  });

  it("attempts both cleanup actions when post-registration persistence fails", async () => {
    class DeleteFailingClientRepository extends MemoryClientRepository {
      deleteAttempted = false;

      override async deleteByClientId(_clientId: string): Promise<void> {
        this.deleteAttempted = true;
        throw new Error("D1 delete unavailable");
      }
    }

    class TrackingRegistrationAccessTokenRepository
      extends MemoryRegistrationAccessTokenRepository
    {
      deleteAttempted = false;

      override async deleteByTokenHash(tokenHash: string): Promise<void> {
        this.deleteAttempted = true;
        await super.deleteByTokenHash(tokenHash);
      }
    }

    class FailingAuditRepository implements AuditRepository {
      async record(): Promise<void> {
        throw new Error("audit unavailable");
      }
    }

    const clientRepository = new DeleteFailingClientRepository();
    const registrationAccessTokenRepository = new TrackingRegistrationAccessTokenRepository();
    const app = createApp({
      auditRepository: new FailingAuditRepository(),
      clientRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "manage-acme",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      registrationAccessTokenRepository,
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
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

    expect(response.status).toBe(500);
    expect(clientRepository.deleteAttempted).toBe(true);
    expect(registrationAccessTokenRepository.deleteAttempted).toBe(true);
  });
});
