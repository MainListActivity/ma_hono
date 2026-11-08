import { exportJWK, generateKeyPair, importJWK, jwtVerify, type JWK } from "jose";
import { describe, expect, it } from "vitest";

import { MemoryAccessTokenClaimsRepository } from "../../src/adapters/db/memory/memory-access-token-claims-repository";
import { MemoryAccessTokenRevocationRepository } from "../../src/adapters/db/memory/memory-access-token-revocation-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryRefreshTokenRepository } from "../../src/adapters/db/memory/memory-refresh-token-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { createApp } from "../../src/app/app";
import type { AccessTokenCustomClaim } from "../../src/domain/clients/access-token-claims-types";
import type { Client } from "../../src/domain/clients/types";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import { sha256Base64Url } from "../../src/lib/hash";

const ISSUER = "https://idp.example.test/t/acme";
const TOKEN_URL = "https://idp.example.test/t/acme/token";

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
        issuerUrl: ISSUER,
        domain: null,
        isPrimary: true,
        verificationStatus: "verified"
      }
    ]
  }
]);

const createSigner = async (): Promise<{
  material: SigningKeyMaterial;
  signer: SigningKeySigner;
}> => {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: true
  });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const material: SigningKeyMaterial = {
    key: {
      id: "key_acme",
      tenantId: "tenant_acme",
      kid: "kid-acme",
      alg: "RS256",
      kty: "RSA",
      status: "active",
      publicJwk: {
        ...publicJwk,
        alg: "RS256",
        kid: "kid-acme",
        use: "sig"
      }
    },
    privateJwk: {
      ...privateJwk,
      alg: "RS256",
      kid: "kid-acme"
    }
  };

  return {
    material,
    signer: {
      async ensureActiveSigningKeyMaterial() {
        return material;
      },
      async loadActiveSigningKeyMaterial() {
        return material;
      }
    }
  };
};

const createMachineClient = async ({
  clientId = "company_runner",
  secret = "runner-secret",
  authMethod = "client_secret_basic",
  grantTypes = ["client_credentials"],
  tenantId = "tenant_acme",
  accessTokenAudience = "https://api.acme.test",
  machineTokenTtlSeconds = null
}: {
  clientId?: string;
  secret?: string | null;
  authMethod?: Client["tokenEndpointAuthMethod"];
  grantTypes?: string[];
  tenantId?: string;
  accessTokenAudience?: string | null;
  machineTokenTtlSeconds?: number | null;
} = {}): Promise<Client> => ({
  id: `record_${clientId}`,
  tenantId,
  clientId,
  clientName: clientId,
  applicationType: "web",
  grantTypes,
  redirectUris: [],
  responseTypes: [],
  tokenEndpointAuthMethod: authMethod,
  clientSecretHash: secret === null ? null : await sha256Base64Url(secret),
  trustLevel: "first_party_trusted",
  consentPolicy: "skip",
  clientProfile: "web",
  accessTokenAudience,
  machineTokenTtlSeconds
});

const makeClaim = (
  overrides: Partial<AccessTokenCustomClaim>
): AccessTokenCustomClaim => ({
  id: "claim_1",
  clientId: "record_company_runner",
  tenantId: "tenant_acme",
  claimName: "custom",
  sourceType: "fixed",
  fixedValue: null,
  userField: null,
  hookField: null,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  ...overrides
});

const createTestApp = async ({
  client,
  claims = []
}: {
  client: Client;
  claims?: AccessTokenCustomClaim[];
}) => {
  const { material, signer } = await createSigner();
  const auditRepository = new MemoryAuditRepository();
  const accessTokenClaimsRepository = new MemoryAccessTokenClaimsRepository();

  if (claims.length > 0) {
    await accessTokenClaimsRepository.createMany(claims);
  }

  const app = createApp({
    accessTokenClaimsRepository,
    auditRepository,
    authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
    clientAuthMethodPolicyRepository: new MemoryClientAuthMethodPolicyRepository(),
    clientRepository: new MemoryClientRepository([client]),
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    accessTokenRevocationRepository: new MemoryAccessTokenRevocationRepository(),
    refreshTokenRepository: new MemoryRefreshTokenRepository(),
    signer,
    tenantRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });

  return { app, auditRepository, material };
};

const requestToken = ({
  app,
  basic,
  body = {}
}: {
  app: ReturnType<typeof createApp>;
  basic?: { clientId: string; secret: string };
  body?: Record<string, string>;
}) => {
  const params = new URLSearchParams({
    grant_type: "client_credentials",
    ...body
  });
  const headers = new Headers({
    "content-type": "application/x-www-form-urlencoded"
  });

  if (basic !== undefined) {
    headers.set("authorization", `Basic ${btoa(`${basic.clientId}:${basic.secret}`)}`);
  }

  return app.request(TOKEN_URL, {
    method: "POST",
    headers,
    body: params.toString()
  });
};

const verifyAccessToken = async (material: SigningKeyMaterial, token: string) => {
  const publicKey = await importJWK(material.key.publicJwk as JWK, "RS256");
  const verification = await jwtVerify(token, publicKey, { issuer: ISSUER });

  return verification.payload as Record<string, unknown>;
};

describe("client_credentials grant", () => {
  it("issues a machine access token with sub set to the client id", async () => {
    const client = await createMachineClient();
    const { app, material } = await createTestApp({ client });

    const response = await requestToken({
      app,
      basic: { clientId: client.clientId, secret: "runner-secret" }
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.token_type).toBe("Bearer");
    expect(body.refresh_token).toBeUndefined();
    expect(body.id_token).toBeUndefined();

    const payload = await verifyAccessToken(material, body.access_token as string);
    expect(payload.sub).toBe(client.clientId);
    expect(payload.client_id).toBe(client.clientId);
    expect(payload.aud).toBe("https://api.acme.test");
    expect(payload.scope).toBe("");
    expect(payload.task).toBeUndefined();
    expect(payload.act).toBeUndefined();
  });

  it("caps the lifetime at 900 seconds by default", async () => {
    const client = await createMachineClient();
    const { app, material } = await createTestApp({ client });

    const response = await requestToken({
      app,
      basic: { clientId: client.clientId, secret: "runner-secret" }
    });
    const body = (await response.json()) as { access_token: string; expires_in: number };
    const payload = await verifyAccessToken(material, body.access_token);

    expect(body.expires_in).toBe(900);
    expect((payload.exp as number) - (payload.iat as number)).toBe(900);
  });

  it("lets the client policy shorten the lifetime but never extend it", async () => {
    const shortened = await createMachineClient({ machineTokenTtlSeconds: 120 });
    const shortenedApp = await createTestApp({ client: shortened });
    const shortenedResponse = await requestToken({
      app: shortenedApp.app,
      basic: { clientId: shortened.clientId, secret: "runner-secret" }
    });
    const shortenedBody = (await shortenedResponse.json()) as { access_token: string; expires_in: number };
    const shortenedPayload = await verifyAccessToken(shortenedApp.material, shortenedBody.access_token);

    expect(shortenedBody.expires_in).toBe(120);
    expect((shortenedPayload.exp as number) - (shortenedPayload.iat as number)).toBe(120);

    const extended = await createMachineClient({
      clientId: "company_cron",
      machineTokenTtlSeconds: 86_400
    });
    const extendedApp = await createTestApp({ client: extended });
    const extendedResponse = await requestToken({
      app: extendedApp.app,
      basic: { clientId: extended.clientId, secret: "runner-secret" }
    });
    const extendedBody = (await extendedResponse.json()) as { expires_in: number };

    expect(extendedBody.expires_in).toBe(900);
  });

  it("accepts client_secret_post credentials in the request body", async () => {
    const client = await createMachineClient({ authMethod: "client_secret_post" });
    const { app, material } = await createTestApp({ client });

    const response = await requestToken({
      app,
      body: { client_id: client.clientId, client_secret: "runner-secret" }
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { access_token: string };
    const payload = await verifyAccessToken(material, body.access_token);
    expect(payload.sub).toBe(client.clientId);
  });

  it("includes fixed claims, parsing json values into arrays", async () => {
    const client = await createMachineClient();
    const { app, material } = await createTestApp({
      client,
      claims: [
        makeClaim({
          clientId: client.id,
          claimName: "rl",
          fixedValue: '["Editor"]',
          valueType: "json"
        }),
        makeClaim({
          id: "claim_2",
          clientId: client.id,
          claimName: "ac",
          fixedValue: "company_runner"
        }),
        makeClaim({
          id: "claim_3",
          clientId: client.id,
          claimName: "ns",
          fixedValue: "company"
        })
      ]
    });

    const response = await requestToken({
      app,
      basic: { clientId: client.clientId, secret: "runner-secret" }
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { access_token: string };
    const payload = await verifyAccessToken(material, body.access_token);
    expect(payload.rl).toEqual(["Editor"]);
    expect(payload.ac).toBe("company_runner");
    expect(payload.ns).toBe("company");
  });

  it("rejects a wrong client secret with invalid_client and a Basic challenge", async () => {
    const client = await createMachineClient();
    const { app, auditRepository } = await createTestApp({ client });

    const response = await requestToken({
      app,
      basic: { clientId: client.clientId, secret: "wrong-secret" }
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "invalid_client" });
    expect(response.headers.get("www-authenticate")).toContain('error="invalid_client"');

    const failed = auditRepository.listEvents().filter(
      (event) => event.eventType === "oidc.client_credentials.failed"
    );
    expect(failed).toHaveLength(1);
    expect(failed[0]?.payload).toEqual({ reason: "invalid_client" });
  });

  it("rejects an unknown client with invalid_client", async () => {
    const client = await createMachineClient();
    const { app } = await createTestApp({ client });

    const response = await requestToken({
      app,
      basic: { clientId: "no_such_client", secret: "runner-secret" }
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "invalid_client" });
  });

  it("rejects a client in another tenant with invalid_client", async () => {
    const client = await createMachineClient({ tenantId: "tenant_other" });
    const { app } = await createTestApp({ client });

    const response = await requestToken({
      app,
      basic: { clientId: client.clientId, secret: "runner-secret" }
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "invalid_client" });
  });

  it("rejects a public client because it cannot authenticate", async () => {
    const client = await createMachineClient({
      authMethod: "none",
      secret: null
    });
    const { app } = await createTestApp({ client });

    const response = await requestToken({
      app,
      body: { client_id: client.clientId }
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "invalid_client" });
  });

  it("rejects requests that carry no client credentials", async () => {
    const client = await createMachineClient();
    const { app } = await createTestApp({ client });

    const response = await requestToken({ app });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "invalid_client" });
  });

  it("rejects an authenticated client that lacks the client_credentials grant with unauthorized_client", async () => {
    const client = await createMachineClient({
      clientId: "web_only",
      grantTypes: ["authorization_code"]
    });
    const { app, auditRepository } = await createTestApp({ client });

    const response = await requestToken({
      app,
      basic: { clientId: client.clientId, secret: "runner-secret" }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "unauthorized_client" });

    const failed = auditRepository.listEvents().filter(
      (event) => event.eventType === "oidc.client_credentials.failed"
    );
    expect(failed[0]?.payload).toEqual({ reason: "unauthorized_client" });
  });

  it("records success without a user id and without token material", async () => {
    const client = await createMachineClient();
    const { app, auditRepository } = await createTestApp({ client });

    const response = await requestToken({
      app,
      basic: { clientId: client.clientId, secret: "runner-secret" }
    });
    const body = (await response.json()) as { access_token: string };

    const succeeded = auditRepository.listEvents().filter(
      (event) => event.eventType === "oidc.client_credentials.succeeded"
    );
    expect(succeeded).toHaveLength(1);
    expect(succeeded[0]?.actorId).toBe(client.clientId);
    expect(succeeded[0]?.payload).not.toHaveProperty("user_id");
    expect(JSON.stringify(succeeded[0]?.payload ?? {})).not.toContain(body.access_token);
  });
});
