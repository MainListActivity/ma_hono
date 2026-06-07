import { exportJWK, generateKeyPair, importJWK, jwtVerify, type JWK } from "jose";
import { describe, expect, it } from "vitest";

import { MemoryAccessTokenClaimsRepository } from "../../src/adapters/db/memory/memory-access-token-claims-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { AuthorizationCode } from "../../src/domain/authorization/types";
import type { Client } from "../../src/domain/clients/types";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import type { User } from "../../src/domain/users/types";
import { sha256Base64Url } from "../../src/lib/hash";

const baseUser: User = {
  id: "user_123",
  tenantId: "tenant_acme",
  email: "alice@example.com",
  emailVerified: true,
  username: "alice",
  displayName: "Alice",
  status: "active",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z"
};

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
  },
  {
    id: "tenant_beta",
    slug: "beta",
    displayName: "Beta",
    status: "active",
    issuers: [
      {
        id: "issuer_platform_beta",
        issuerType: "platform_path",
        issuerUrl: "https://idp.example.test/t/beta",
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

const scopeClientSecret = "scope-client-secret";
const scopeClientSecretHash = "kF_RNoyORN3mloG3XP-dalKI9OelNtyPRdRGykDItgM";

const createClient = ({
  clientId = "scope_client",
  tenantId = "tenant_acme"
}: {
  clientId?: string;
  tenantId?: string;
} = {}): Client => ({
  id: `record_${clientId}`,
  tenantId,
  clientId,
  clientName: clientId,
  applicationType: "web",
  grantTypes: ["authorization_code"],
  redirectUris: ["https://app.acme.test/callback"],
  responseTypes: ["code"],
  tokenEndpointAuthMethod: "client_secret_basic",
  clientSecretHash: scopeClientSecretHash,
  trustLevel: "first_party_trusted",
  consentPolicy: "skip",
  clientProfile: "spa",
  accessTokenAudience: "https://auth.example.test"
});

const seedAuthorizationCode = async ({
  clientId,
  code,
  codeRepository,
  issuer,
  tenantId = "tenant_acme",
  userId = baseUser.id
}: {
  clientId: string;
  code: string;
  codeRepository: MemoryAuthorizationCodeRepository;
  issuer: string;
  tenantId?: string;
  userId?: string;
}) => {
  const authorizationCode: AuthorizationCode = {
    id: `authorization_code_${code}`,
    tenantId,
    issuer,
    clientId,
    userId,
    redirectUri: "https://app.acme.test/callback",
    scope: "openid profile",
    nonce: "nonce_123",
    codeChallenge: await sha256Base64Url("verifier-123456"),
    codeChallengeMethod: "S256",
    tokenHash: await sha256Base64Url(code),
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    consumedAt: null,
    createdAt: new Date().toISOString()
  };

  await codeRepository.create(authorizationCode);
};

const exchangeCode = async ({
  app,
  clientId,
  code,
  clientSecret = scopeClientSecret,
  requestUrl
}: {
  app: ReturnType<typeof createApp>;
  clientId: string;
  code: string;
  clientSecret?: string | null;
  requestUrl: string;
}) => {
  const body = new URLSearchParams({
    code,
    code_verifier: "verifier-123456",
    grant_type: "authorization_code",
    redirect_uri: "https://app.acme.test/callback"
  });

  const headers = new Headers({
    "content-type": "application/x-www-form-urlencoded"
  });

  if (clientSecret === null) {
    body.set("client_id", clientId);
  } else {
    headers.set("authorization", `Basic ${btoa(`${clientId}:${clientSecret}`)}`);
  }

  const response = await app.request(requestUrl, {
    method: "POST",
    headers,
    body: body.toString()
  });

  expect(response.status).toBe(200);
  return (await response.json()) as { access_token: string };
};

const callScopeEndpoint = async ({
  app,
  claims,
  clientId = "scope_client",
  clientSecret = scopeClientSecret,
  requestUrl = "https://idp.example.test/t/acme/scope",
  subjectToken
}: {
  app: ReturnType<typeof createApp>;
  claims: Record<string, unknown>;
  clientId?: string;
  clientSecret?: string | null;
  requestUrl?: string;
  subjectToken: string;
}) => {
  const headers = new Headers({
    "content-type": "application/json"
  });
  const body: Record<string, unknown> = {
    subject_token: subjectToken,
    claims
  };

  if (clientSecret === null) {
    body.client_id = clientId;
  } else {
    headers.set("authorization", `Basic ${btoa(`${clientId}:${clientSecret}`)}`);
  }

  return app.request(requestUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(body)
  });
};

const createScopeTestApp = async ({
  clients = [createClient()],
  users = [baseUser]
}: {
  clients?: Client[];
  users?: User[];
} = {}) => {
  const { material, signer } = await createSigner();
  const auditRepository = new MemoryAuditRepository();
  const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
  const app = createApp({
    accessTokenClaimsRepository: new MemoryAccessTokenClaimsRepository(),
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    auditRepository,
    authorizationCodeRepository,
    clientRepository: new MemoryClientRepository(clients),
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    signer,
    tenantRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0),
    userRepository: new MemoryUserRepository({ users })
  });

  return { app, auditRepository, authorizationCodeRepository, material };
};

describe("Scope endpoint", () => {
  it("returns a fresh access token with updated SurrealDB claims", async () => {
    const client = createClient();
    const { app, auditRepository, authorizationCodeRepository, material } =
      await createScopeTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-platform",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-platform",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: {
        db: "ws_alpha",
        ac: "admin",
        email: baseUser.email,
        RL: ["Viewer", "Editor"]
      }
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      access_token: string;
      expires_in: number;
      id_token?: string;
      scope: string;
      token_type: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.scope).toBe("openid profile");
    expect(body.id_token).toBeUndefined();

    const verificationKey = await importJWK(material.key.publicJwk as JWK, "RS256");
    const { payload } = await jwtVerify(body.access_token, verificationKey, {
      issuer: "https://idp.example.test/t/acme"
    });

    expect(payload.sub).toBe(baseUser.id);
    expect(payload.client_id).toBe(client.clientId);
    expect(payload.db).toBe("ws_alpha");
    expect(payload.ac).toBe("admin");
    expect(payload.email).toBe(baseUser.email);
    expect(payload["https://surrealdb.com/db"]).toBeUndefined();
    expect(payload["https://surrealdb.com/ac"]).toBeUndefined();
    expect(payload["https://surrealdb.com/email"]).toBeUndefined();
    expect(payload.RL).toEqual(["Viewer", "Editor"]);
    expect(auditRepository.listEvents().some((event) => event.eventType === "oidc.scope.switch.succeeded")).toBe(true);
  });

  it("supports custom-domain issuers and signs the returned token for that issuer", async () => {
    const client = createClient({ clientId: "scope_custom_client" });
    const { app, authorizationCodeRepository, material } =
      await createScopeTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-custom",
      codeRepository: authorizationCodeRepository,
      issuer: "https://login.acme.test"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-custom",
      requestUrl: "https://login.acme.test/token"
    });

    const response = await callScopeEndpoint({
      app,
      clientId: client.clientId,
      requestUrl: "https://login.acme.test/scope",
      subjectToken: tokenBody.access_token,
      claims: {
        db: "ws_custom",
        ac: "participant"
      }
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { access_token: string };
    const verificationKey = await importJWK(material.key.publicJwk as JWK, "RS256");
    const { payload } = await jwtVerify(body.access_token, verificationKey, {
      issuer: "https://login.acme.test"
    });

    expect(payload.iss).toBe("https://login.acme.test");
    expect(payload.db).toBe("ws_custom");
    expect(payload.ac).toBe("participant");
  });

  it("rejects invalid client secret authentication", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createScopeTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-unauthorized",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-unauthorized",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      clientSecret: "wrong-secret",
      subjectToken: tokenBody.access_token,
      claims: {
        db: "ws_alpha"
      }
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "invalid_client" });
  });

  it("rejects unsupported claim names", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createScopeTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-forbidden-claim",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-forbidden-claim",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: {
        can_create_workspace: true
      }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("rejects prefixed SurrealDB claim names", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createScopeTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-prefixed-claim",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-prefixed-claim",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: {
        "https://surrealdb.com/db": "ws_alpha"
      }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("rejects invalid SurrealDB access values", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createScopeTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-invalid-ac",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-invalid-ac",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: {
        ac: "owner"
      }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("rejects SurrealDB email claims that do not match the token subject", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createScopeTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-invalid-email",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-invalid-email",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: {
        email: "mallory@example.com"
      }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("rejects invalid SurrealDB RL values", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createScopeTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-invalid-rl",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-invalid-rl",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: {
        RL: ["Owner", "Admin"]
      }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("rejects subject tokens issued to a different client", async () => {
    const tokenClient = createClient({ clientId: "scope_token_client" });
    const callerClient = createClient({ clientId: "scope_caller_client" });
    const { app, authorizationCodeRepository } = await createScopeTestApp({
      clients: [tokenClient, callerClient]
    });
    await seedAuthorizationCode({
      clientId: tokenClient.clientId,
      code: "code-scope-client-mismatch",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: tokenClient.clientId,
      code: "code-scope-client-mismatch",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      clientId: callerClient.clientId,
      subjectToken: tokenBody.access_token,
      claims: {
        db: "ws_alpha"
      }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_grant" });
  });

  it("rejects subject tokens from another issuer context", async () => {
    const acmeClient = createClient();
    const client = createClient({ clientId: "scope_cross_tenant_client", tenantId: "tenant_beta" });
    const betaUser = { ...baseUser, tenantId: "tenant_beta" };
    const { app, authorizationCodeRepository } = await createScopeTestApp({
      clients: [acmeClient, client],
      users: [betaUser]
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-scope-beta",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/beta",
      tenantId: "tenant_beta",
      userId: betaUser.id
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-scope-beta",
      requestUrl: "https://idp.example.test/t/beta/token"
    });

    const response = await callScopeEndpoint({
      app,
      requestUrl: "https://idp.example.test/t/acme/scope",
      subjectToken: tokenBody.access_token,
      claims: {
        db: "ws_alpha"
      }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_grant" });
  });

  it("rejects malformed subject tokens", async () => {
    const { app } = await createScopeTestApp();

    const response = await callScopeEndpoint({
      app,
      subjectToken: "not-a-jwt",
      claims: {
        db: "ws_alpha"
      }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_grant" });
  });
});
