import { exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT, type JWK } from "jose";
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
import type { AccessTokenCustomClaim } from "../../src/domain/clients/access-token-claims-types";
import type { Client } from "../../src/domain/clients/types";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import {
  createContentReaderIssuancePolicy,
  DEFAULT_CONTENT_READER_MAX_TTL_SECONDS
} from "../../src/domain/tokens/content-reader-policy";
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

const scopeClientSecret = "scope-client-secret";
const scopeClientSecretHash = "kF_RNoyORN3mloG3XP-dalKI9OelNtyPRdRGykDItgM";

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

const createClient = ({
  clientId = "scope_client",
  tenantId = "tenant_acme",
  accessTokenAudience = "https://auth.example.test"
}: {
  clientId?: string;
  tenantId?: string;
  accessTokenAudience?: string | null;
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
  clientProfile: "web",
  accessTokenAudience
});

const defaultContentReaderPolicy = createContentReaderIssuancePolicy({
  allowedClientIds: ["scope_client"],
  allowedTenantIds: ["tenant_acme"],
  allowedContentDatabases: ["platform_content"],
  maxTtlSeconds: DEFAULT_CONTENT_READER_MAX_TTL_SECONDS
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
  requestUrl
}: {
  app: ReturnType<typeof createApp>;
  clientId: string;
  code: string;
  requestUrl: string;
}) => {
  const body = new URLSearchParams({
    code,
    code_verifier: "verifier-123456",
    grant_type: "authorization_code",
    redirect_uri: "https://app.acme.test/callback"
  });

  const response = await app.request(requestUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`${clientId}:${scopeClientSecret}`)}`
    },
    body: body.toString()
  });

  expect(response.status).toBe(200);
  return (await response.json()) as { access_token: string; expires_in: number };
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

const createContentReaderTestApp = async ({
  clients = [createClient()],
  users = [baseUser],
  contentReaderPolicy = defaultContentReaderPolicy,
  customClaims = [] as AccessTokenCustomClaim[],
  claimHookFetcher
}: {
  clients?: Client[];
  users?: User[];
  contentReaderPolicy?: ReturnType<typeof createContentReaderIssuancePolicy> | null;
  customClaims?: AccessTokenCustomClaim[];
  claimHookFetcher?: (
    config: { url: string },
    context: { subject: string; email: string | null }
  ) => Promise<Record<string, unknown>>;
} = {}) => {
  const { material, signer } = await createSigner();
  const auditRepository = new MemoryAuditRepository();
  const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
  const accessTokenClaimsRepository = new MemoryAccessTokenClaimsRepository();
  if (customClaims.length > 0) {
    await accessTokenClaimsRepository.createMany(customClaims);
  }
  const app = createApp({
    accessTokenClaimsRepository,
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    auditRepository,
    authorizationCodeRepository,
    clientRepository: new MemoryClientRepository(clients),
    contentReaderPolicy,
    claimHookFetcher,
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

const contentReaderClaims = ({
  db = "platform_content",
  workspaceId = "ws_alpha",
  entitlementRevision = "entrev_2026_09_24",
  leaseEnd = Math.floor(Date.now() / 1000) + 5 * 60
}: {
  db?: string;
  workspaceId?: string;
  entitlementRevision?: string;
  leaseEnd?: number;
} = {}) => ({
  ac: "content_reader",
  db,
  workspace_id: workspaceId,
  entitlement_revision: entitlementRevision,
  lease_end: leaseEnd
});

describe("content_reader scope issuance", () => {
  it("issues a short-lived content_reader token verified against JWKS claims", async () => {
    const client = createClient();
    const { app, auditRepository, authorizationCodeRepository, material } =
      await createContentReaderTestApp({ clients: [client] });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-content-reader",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-content-reader",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const leaseEnd = Math.floor(Date.now() / 1000) + 120;
    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims({ leaseEnd })
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = (await response.json()) as {
      access_token: string;
      expires_in: number;
      scope: string;
      token_type: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.scope).toBe("openid profile");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.expires_in).toBeLessThanOrEqual(120);

    const verificationKey = await importJWK(material.key.publicJwk as JWK, "RS256");
    const { payload } = await jwtVerify(body.access_token, verificationKey, {
      issuer: "https://idp.example.test/t/acme",
      audience: "https://auth.example.test"
    });

    expect(payload.sub).toBe(baseUser.id);
    expect(payload.client_id).toBe(client.clientId);
    expect(payload.ac).toBe("content_reader");
    expect(payload.db).toBe("platform_content");
    expect(payload.workspace_id).toBe("ws_alpha");
    expect(payload.entitlement_revision).toBe("entrev_2026_09_24");
    expect(payload.RL).toBeUndefined();
    expect(typeof payload.exp).toBe("number");
    expect((payload.exp as number) - (payload.iat as number)).toBe(body.expires_in);
    expect(
      auditRepository
        .listEvents()
        .some((event) => event.eventType === "oidc.scope.content_reader.succeeded")
    ).toBe(true);
  });

  it("keeps the original workspace token usable after content_reader issuance", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository, material } = await createContentReaderTestApp({
      clients: [client]
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-coexist",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-coexist",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const workspaceSwitch = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: {
        db: "ws_alpha",
        ac: "admin",
        RL: ["Owner"]
      }
    });
    expect(workspaceSwitch.status).toBe(200);
    const workspaceBody = (await workspaceSwitch.json()) as { access_token: string };

    const contentResponse = await callScopeEndpoint({
      app,
      subjectToken: workspaceBody.access_token,
      claims: contentReaderClaims()
    });
    expect(contentResponse.status).toBe(200);
    const contentBody = (await contentResponse.json()) as { access_token: string };

    const verificationKey = await importJWK(material.key.publicJwk as JWK, "RS256");
    const original = await jwtVerify(tokenBody.access_token, verificationKey, {
      issuer: "https://idp.example.test/t/acme"
    });
    const workspace = await jwtVerify(workspaceBody.access_token, verificationKey, {
      issuer: "https://idp.example.test/t/acme"
    });
    const content = await jwtVerify(contentBody.access_token, verificationKey, {
      issuer: "https://idp.example.test/t/acme"
    });

    expect(original.payload.sub).toBe(baseUser.id);
    expect(workspace.payload.ac).toBe("admin");
    expect(workspace.payload.db).toBe("ws_alpha");
    expect(content.payload.ac).toBe("content_reader");
    expect(content.payload.db).toBe("platform_content");
  });

  it("rejects content_reader tokens as subject tokens for further scope elevation", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createContentReaderTestApp({
      clients: [client]
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-no-elevate",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-no-elevate",
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    const contentResponse = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims()
    });
    const contentBody = (await contentResponse.json()) as { access_token: string };

    const elevate = await callScopeEndpoint({
      app,
      subjectToken: contentBody.access_token,
      claims: {
        db: "ws_alpha",
        ac: "admin"
      }
    });

    expect(elevate.status).toBe(400);
    expect(await elevate.json()).toEqual({ error: "invalid_scope" });
  });

  it("rejects clients that are not on the content_reader allowlist", async () => {
    const client = createClient({ clientId: "other_client" });
    const { app, authorizationCodeRepository } = await createContentReaderTestApp({
      clients: [client],
      contentReaderPolicy: defaultContentReaderPolicy
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-not-allowlisted",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-not-allowlisted",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      clientId: client.clientId,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims()
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_scope" });
  });

  it("rejects cross-tenant content_reader requests", async () => {
    const betaClient = createClient({
      clientId: "scope_client",
      tenantId: "tenant_beta"
    });
    const betaUser = { ...baseUser, tenantId: "tenant_beta" };
    const { app, authorizationCodeRepository } = await createContentReaderTestApp({
      clients: [betaClient],
      users: [betaUser],
      contentReaderPolicy: createContentReaderIssuancePolicy({
        allowedClientIds: ["scope_client"],
        allowedTenantIds: ["tenant_acme"],
        allowedContentDatabases: ["platform_content"]
      })
    });
    await seedAuthorizationCode({
      clientId: betaClient.clientId,
      code: "code-beta",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/beta",
      tenantId: "tenant_beta",
      userId: betaUser.id
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: betaClient.clientId,
      code: "code-beta",
      requestUrl: "https://idp.example.test/t/beta/token"
    });

    const response = await callScopeEndpoint({
      app,
      requestUrl: "https://idp.example.test/t/beta/scope",
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims()
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_scope" });
  });

  it("rejects subject tokens bound to a different client", async () => {
    const tokenClient = createClient({ clientId: "token_client" });
    const callerClient = createClient({ clientId: "scope_client" });
    const { app, authorizationCodeRepository } = await createContentReaderTestApp({
      clients: [tokenClient, callerClient]
    });
    await seedAuthorizationCode({
      clientId: tokenClient.clientId,
      code: "code-client-mismatch",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: tokenClient.clientId,
      code: "code-client-mismatch",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      clientId: callerClient.clientId,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims()
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_grant" });
  });

  it("rejects subject tokens with the wrong audience", async () => {
    const client = createClient();
    const { app, material } = await createContentReaderTestApp({ clients: [client] });
    const privateKey = await importJWK(material.privateJwk as JWK, "RS256");
    const now = Math.floor(Date.now() / 1000);
    const forged = await new SignJWT({
      sub: baseUser.id,
      client_id: client.clientId,
      scope: "openid profile",
      ac: "admin",
      db: "ws_alpha"
    })
      .setProtectedHeader({ alg: "RS256", kid: material.key.kid, typ: "JWT" })
      .setIssuer("https://idp.example.test/t/acme")
      .setAudience("https://wrong.audience.test")
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(privateKey);

    const response = await callScopeEndpoint({
      app,
      subjectToken: forged,
      claims: contentReaderClaims()
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_grant" });
  });

  it("rejects disabled users", async () => {
    const client = createClient();
    const disabledUser = { ...baseUser, status: "disabled" as const };
    const { app, authorizationCodeRepository } = await createContentReaderTestApp({
      clients: [client],
      users: [disabledUser]
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-disabled",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-disabled",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims()
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_grant" });
  });

  it("rejects forged and expired subject tokens", async () => {
    const client = createClient();
    const { app, material } = await createContentReaderTestApp({ clients: [client] });

    const forgedResponse = await callScopeEndpoint({
      app,
      subjectToken: "not-a-jwt",
      claims: contentReaderClaims()
    });
    expect(forgedResponse.status).toBe(400);
    expect(await forgedResponse.json()).toEqual({ error: "invalid_grant" });

    const privateKey = await importJWK(material.privateJwk as JWK, "RS256");
    const now = Math.floor(Date.now() / 1000);
    const expired = await new SignJWT({
      sub: baseUser.id,
      client_id: client.clientId,
      scope: "openid profile"
    })
      .setProtectedHeader({ alg: "RS256", kid: material.key.kid, typ: "JWT" })
      .setIssuer("https://idp.example.test/t/acme")
      .setAudience("https://auth.example.test")
      .setIssuedAt(now - 7200)
      .setExpirationTime(now - 3600)
      .sign(privateKey);

    const expiredResponse = await callScopeEndpoint({
      app,
      subjectToken: expired,
      claims: contentReaderClaims()
    });
    expect(expiredResponse.status).toBe(400);
    expect(await expiredResponse.json()).toEqual({ error: "invalid_grant" });
  });

  it("rejects over-long or past lease_end values", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createContentReaderTestApp({
      clients: [client],
      contentReaderPolicy: createContentReaderIssuancePolicy({
        allowedClientIds: ["scope_client"],
        allowedContentDatabases: ["platform_content"],
        maxTtlSeconds: 60
      })
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-lease",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-lease",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const pastLease = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims({ leaseEnd: Math.floor(Date.now() / 1000) - 10 })
    });
    expect(pastLease.status).toBe(400);
    expect(await pastLease.json()).toEqual({ error: "invalid_lifetime" });

    const longLease = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims({ leaseEnd: Math.floor(Date.now() / 1000) + 3600 })
    });
    expect(longLease.status).toBe(200);
    const longBody = (await longLease.json()) as { expires_in: number };
    expect(longBody.expires_in).toBeLessThanOrEqual(60);
  });

  it("rejects arbitrary claim injection and disallowed content databases", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createContentReaderTestApp({
      clients: [client]
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-inject",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-inject",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const injected = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: {
        ...contentReaderClaims(),
        RL: ["Owner"],
        collections: ["all"]
      }
    });
    expect(injected.status).toBe(400);
    expect(await injected.json()).toEqual({ error: "invalid_request" });

    const wrongDb = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims({ db: "ws_alpha" })
    });
    expect(wrongDb.status).toBe(400);
    expect(await wrongDb.json()).toEqual({ error: "invalid_scope" });
  });

  it("does not let configured/hook claims override content_reader purpose claims", async () => {
    const client = createClient();
    client.claimHookUrl = "https://hook.example.test/scope";
    const customClaims: AccessTokenCustomClaim[] = [
      {
        id: "claim_ac",
        clientId: client.id,
        tenantId: client.tenantId,
        claimName: "ac",
        sourceType: "fixed",
        fixedValue: "admin",
        userField: null,
        hookField: null,
        createdAt: "2026-01-01T00:00:00Z",
        updatedAt: "2026-01-01T00:00:00Z"
      },
      {
        id: "claim_db",
        clientId: client.id,
        tenantId: client.tenantId,
        claimName: "db",
        sourceType: "hook",
        fixedValue: null,
        userField: null,
        hookField: "db",
        createdAt: "2026-01-01T00:00:00Z",
        updatedAt: "2026-01-01T00:00:00Z"
      },
      {
        id: "claim_email",
        clientId: client.id,
        tenantId: client.tenantId,
        claimName: "email",
        sourceType: "user_field",
        fixedValue: null,
        userField: "email",
        hookField: null,
        createdAt: "2026-01-01T00:00:00Z",
        updatedAt: "2026-01-01T00:00:00Z"
      }
    ];
    const { app, authorizationCodeRepository, material } = await createContentReaderTestApp({
      clients: [client],
      customClaims,
      claimHookFetcher: async () => ({
        db: "ws_from_hook",
        RL: ["Owner"]
      })
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-merge",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-merge",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims()
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { access_token: string };
    const verificationKey = await importJWK(material.key.publicJwk as JWK, "RS256");
    const { payload } = await jwtVerify(body.access_token, verificationKey, {
      issuer: "https://idp.example.test/t/acme"
    });

    expect(payload.ac).toBe("content_reader");
    expect(payload.db).toBe("platform_content");
    expect(payload.email).toBe(baseUser.email);
    expect(payload.RL).toBeUndefined();
    expect(payload.workspace_id).toBe("ws_alpha");
  });

  it("rejects content_reader when issuance policy is not configured", async () => {
    const client = createClient();
    const { app, authorizationCodeRepository } = await createContentReaderTestApp({
      clients: [client],
      contentReaderPolicy: null
    });
    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-unconfigured",
      codeRepository: authorizationCodeRepository,
      issuer: "https://idp.example.test/t/acme"
    });
    const tokenBody = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-unconfigured",
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    const response = await callScopeEndpoint({
      app,
      subjectToken: tokenBody.access_token,
      claims: contentReaderClaims()
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_scope" });
  });
});
