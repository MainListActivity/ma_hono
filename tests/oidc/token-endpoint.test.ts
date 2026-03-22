import { exportJWK, generateKeyPair, importJWK, jwtVerify, type JWK } from "jose";
import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { createApp } from "../../src/app/app";
import type { AuthorizationCode } from "../../src/domain/authorization/types";
import type { Client } from "../../src/domain/clients/types";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import { sha256Base64Url } from "../../src/lib/hash";

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

const createSigner = async (): Promise<{ signer: SigningKeySigner; material: SigningKeyMaterial }> => {
  const { privateKey, publicKey } = await generateKeyPair("ES256", {
    extractable: true
  });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const material: SigningKeyMaterial = {
    key: {
      id: "key_acme",
      tenantId: "tenant_acme",
      kid: "kid-acme",
      alg: "ES256",
      kty: "EC",
      status: "active",
      publicJwk: {
        ...publicJwk,
        alg: "ES256",
        kid: "kid-acme",
        use: "sig"
      }
    },
    privateJwk: {
      ...privateJwk,
      alg: "ES256",
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

const createClient = async ({
  authMethod,
  clientId,
  secret
}: {
  authMethod: Client["tokenEndpointAuthMethod"];
  clientId: string;
  secret: string | null;
}): Promise<Client> => ({
  id: `record_${clientId}`,
  tenantId: "tenant_acme",
  clientId,
  clientName: clientId,
  applicationType: "web",
  grantTypes: ["authorization_code"],
  redirectUris: ["https://app.acme.test/callback"],
  responseTypes: ["code"],
  tokenEndpointAuthMethod: authMethod,
  clientSecretHash: secret === null ? null : await sha256Base64Url(secret),
  trustLevel: "first_party_trusted",
  consentPolicy: "skip"
});

const seedAuthorizationCode = async ({
  code,
  clientId,
  codeRepository,
  expiresAt,
  issuer
}: {
  code: string;
  clientId: string;
  codeRepository: MemoryAuthorizationCodeRepository;
  expiresAt: string;
  issuer: string;
}) => {
  const authorizationCode: AuthorizationCode = {
    id: `authorization_code_${code}`,
    tenantId: "tenant_acme",
    issuer,
    clientId,
    userId: "user_123",
    redirectUri: "https://app.acme.test/callback",
    scope: "openid profile",
    nonce: "nonce_123",
    codeChallenge: await sha256Base64Url("verifier-123456"),
    codeChallengeMethod: "S256",
    tokenHash: await sha256Base64Url(code),
    expiresAt,
    consumedAt: null,
    createdAt: new Date().toISOString()
  };

  await codeRepository.create(authorizationCode);
};

const exchangeCode = async ({
  app,
  clientId,
  code,
  codeVerifier,
  includeBodyCredentials,
  includeClientIdInBody = true,
  includeClientSecretInBody = true,
  basicAuthScheme = "Basic",
  redirectUri,
  secret,
  skipGrantType = false,
  useBasicAuth,
  requestUrl
}: {
  app: ReturnType<typeof createApp>;
  clientId: string;
  code: string;
  codeVerifier: string;
  includeBodyCredentials?: boolean;
  includeClientIdInBody?: boolean;
  includeClientSecretInBody?: boolean;
  basicAuthScheme?: string;
  redirectUri: string;
  secret: string | null;
  skipGrantType?: boolean;
  useBasicAuth: boolean;
  requestUrl: string;
}) => {
  const body = new URLSearchParams({
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier
  });

  if (!skipGrantType) {
    body.set("grant_type", "authorization_code");
  }

  const shouldIncludeBodyCredentials = includeBodyCredentials ?? !useBasicAuth;

  if (shouldIncludeBodyCredentials && includeClientIdInBody) {
    body.set("client_id", clientId);
  }

  if (shouldIncludeBodyCredentials && includeClientSecretInBody && secret !== null) {
    body.set("client_secret", secret);
  }

  const headers = new Headers({
    "content-type": "application/x-www-form-urlencoded"
  });

  if (useBasicAuth && secret !== null) {
    const credential = btoa(`${clientId}:${secret}`);

    headers.set("authorization", `${basicAuthScheme} ${credential}`);
  }

  return app.request(requestUrl, {
    method: "POST",
    headers,
    body: body.toString()
  });
};

describe("/token", () => {
  it("returns id_token and signed jwt access_token for valid code + PKCE exchange", async () => {
    const { material, signer } = await createSigner();
    const client = await createClient({
      authMethod: "client_secret_basic",
      clientId: "client_basic",
      secret: "basic-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();

    await seedAuthorizationCode({
      code: "code-valid-basic",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });
    const response = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-valid-basic",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "basic-secret",
      useBasicAuth: true,
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      access_token: string;
      id_token: string;
      token_type: string;
      expires_in: number;
    };

    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.id_token).toBeTypeOf("string");
    expect(body.access_token).toBeTypeOf("string");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");

    const verificationKey = await importJWK(material.key.publicJwk as JWK, "ES256");
    const idToken = await jwtVerify(body.id_token, verificationKey, {
      issuer: "https://idp.example.test/t/acme",
      audience: client.clientId
    });
    const accessToken = await jwtVerify(body.access_token, verificationKey, {
      issuer: "https://idp.example.test/t/acme",
      audience: client.clientId
    });

    expect(idToken.payload.sub).toBe("user_123");
    expect(idToken.payload.nonce).toBe("nonce_123");
    expect(idToken.payload.auth_time).toBeUndefined();
    expect(accessToken.payload.sub).toBe("user_123");
    expect(accessToken.payload.scope).toBe("openid profile");
  });

  it("rejects reused and expired authorization codes", async () => {
    const { signer } = await createSigner();
    const client = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_post",
      secret: "post-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();

    await seedAuthorizationCode({
      code: "code-one-time",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });
    await seedAuthorizationCode({
      code: "code-expired",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });

    const firstExchange = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-one-time",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "post-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(firstExchange.status).toBe(200);

    const reused = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-one-time",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "post-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(reused.status).toBe(400);
    await expect(reused.json()).resolves.toEqual({ error: "invalid_grant" });

    const expired = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-expired",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "post-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(expired.status).toBe(400);
    await expect(expired.json()).resolves.toEqual({ error: "invalid_grant" });
  });

  it("supports client_secret_basic, client_secret_post, and none client auth methods", async () => {
    const { signer } = await createSigner();
    const basicClient = await createClient({
      authMethod: "client_secret_basic",
      clientId: "client_basic_auth",
      secret: "basic-secret"
    });
    const postClient = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_post_auth",
      secret: "post-secret"
    });
    const noneClient = await createClient({
      authMethod: "none",
      clientId: "client_public",
      secret: null
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();

    await seedAuthorizationCode({
      code: "code-basic-auth",
      clientId: basicClient.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });
    await seedAuthorizationCode({
      code: "code-post-auth",
      clientId: postClient.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });
    await seedAuthorizationCode({
      code: "code-public-auth",
      clientId: noneClient.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });
    await seedAuthorizationCode({
      code: "code-public-with-secret",
      clientId: noneClient.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([basicClient, postClient, noneClient]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });

    const basicSuccess = await exchangeCode({
      app,
      clientId: basicClient.clientId,
      code: "code-basic-auth",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "basic-secret",
      useBasicAuth: true,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(basicSuccess.status).toBe(200);

    const postSuccess = await exchangeCode({
      app,
      clientId: postClient.clientId,
      code: "code-post-auth",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "post-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(postSuccess.status).toBe(200);

    const noneSuccess = await exchangeCode({
      app,
      clientId: noneClient.clientId,
      code: "code-public-auth",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: null,
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(noneSuccess.status).toBe(200);

    const noneWithSecretRejected = await exchangeCode({
      app,
      clientId: noneClient.clientId,
      code: "code-public-with-secret",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "should-not-be-sent",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(noneWithSecretRejected.status).toBe(401);
    await expect(noneWithSecretRejected.json()).resolves.toEqual({ error: "invalid_client" });
  });

  it("rejects mismatched client auth transport and mixed auth without consuming a valid code", async () => {
    const { signer } = await createSigner();
    const basicClient = await createClient({
      authMethod: "client_secret_basic",
      clientId: "client_basic_negative",
      secret: "basic-secret"
    });
    const postClient = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_post_negative",
      secret: "post-secret"
    });
    const mixedClient = await createClient({
      authMethod: "client_secret_basic",
      clientId: "client_mixed_negative",
      secret: "mixed-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();
    const validCode = "code-still-usable";

    await seedAuthorizationCode({
      code: "code-basic-wrong-transport",
      clientId: basicClient.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });
    await seedAuthorizationCode({
      code: "code-post-wrong-transport",
      clientId: postClient.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });
    await seedAuthorizationCode({
      code: validCode,
      clientId: mixedClient.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([basicClient, postClient, mixedClient]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });

    const basicSentInBody = await exchangeCode({
      app,
      clientId: basicClient.clientId,
      code: "code-basic-wrong-transport",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "basic-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(basicSentInBody.status).toBe(401);
    await expect(basicSentInBody.json()).resolves.toEqual({ error: "invalid_client" });

    const postSentInBasic = await exchangeCode({
      app,
      clientId: postClient.clientId,
      code: "code-post-wrong-transport",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "post-secret",
      useBasicAuth: true,
      includeBodyCredentials: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(postSentInBasic.status).toBe(401);
    await expect(postSentInBasic.json()).resolves.toEqual({ error: "invalid_client" });
    expect(postSentInBasic.headers.get("www-authenticate")).toBe(
      'Basic realm="token", error="invalid_client"'
    );

    const mixedAuth = await exchangeCode({
      app,
      clientId: mixedClient.clientId,
      code: validCode,
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "mixed-secret",
      useBasicAuth: true,
      includeBodyCredentials: true,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(mixedAuth.status).toBe(401);
    await expect(mixedAuth.json()).resolves.toEqual({ error: "invalid_client" });

    const validAfterFailedMixed = await exchangeCode({
      app,
      clientId: mixedClient.clientId,
      code: validCode,
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "mixed-secret",
      useBasicAuth: true,
      includeBodyCredentials: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(validAfterFailedMixed.status).toBe(200);
  });

  it("does not burn authorization code when grant validation fails before exchange", async () => {
    const { signer } = await createSigner();
    const client = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_binding_negative",
      secret: "binding-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();
    const code = "code-binding-retryable";

    await seedAuthorizationCode({
      code,
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });

    const wrongRedirect = await exchangeCode({
      app,
      clientId: client.clientId,
      code,
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/wrong",
      secret: "binding-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(wrongRedirect.status).toBe(400);
    await expect(wrongRedirect.json()).resolves.toEqual({ error: "invalid_grant" });

    const validAfterWrongRedirect = await exchangeCode({
      app,
      clientId: client.clientId,
      code,
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "binding-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(validAfterWrongRedirect.status).toBe(200);
  });

  it("issues tokens with issuer-correct iss and aud for platform-path and custom-domain issuers", async () => {
    const { material, signer } = await createSigner();
    const client = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_issuer_claims",
      secret: "issuer-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();

    await seedAuthorizationCode({
      code: "code-platform",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });
    await seedAuthorizationCode({
      code: "code-custom",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://login.acme.test"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });
    const verificationKey = await importJWK(material.key.publicJwk as JWK, "ES256");

    const platformResponse = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-platform",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "issuer-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(platformResponse.status).toBe(200);
    const platformBody = (await platformResponse.json()) as { id_token: string; access_token: string };
    const platformIdToken = await jwtVerify(platformBody.id_token, verificationKey);
    const platformAccessToken = await jwtVerify(platformBody.access_token, verificationKey);

    expect(platformIdToken.payload.iss).toBe("https://idp.example.test/t/acme");
    expect(platformIdToken.payload.aud).toBe(client.clientId);
    expect(platformAccessToken.payload.iss).toBe("https://idp.example.test/t/acme");
    expect(platformAccessToken.payload.aud).toBe(client.clientId);

    const customResponse = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-custom",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "issuer-secret",
      useBasicAuth: false,
      requestUrl: "https://login.acme.test/token"
    });
    expect(customResponse.status).toBe(200);
    const customBody = (await customResponse.json()) as { id_token: string; access_token: string };
    const customIdToken = await jwtVerify(customBody.id_token, verificationKey);
    const customAccessToken = await jwtVerify(customBody.access_token, verificationKey);

    expect(customIdToken.payload.iss).toBe("https://login.acme.test");
    expect(customIdToken.payload.aud).toBe(client.clientId);
    expect(customAccessToken.payload.iss).toBe("https://login.acme.test");
    expect(customAccessToken.payload.aud).toBe(client.clientId);
  });

  it("emits a token exchange audit failure event on failed exchange", async () => {
    const { signer } = await createSigner();
    const client = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_audited_failure",
      secret: "failure-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();
    const auditRepository = new MemoryAuditRepository();

    await seedAuthorizationCode({
      code: "code-failure",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository,
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });
    const response = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-failure",
      codeVerifier: "wrong-verifier",
      redirectUri: "https://app.acme.test/callback",
      secret: "failure-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_grant" });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    expect(auditRepository.listEvents()).toHaveLength(1);
    expect(auditRepository.listEvents()[0]).toMatchObject({
      tenantId: "tenant_acme",
      eventType: "oidc.token.exchange.failed",
      targetType: "oidc_client",
      targetId: client.clientId,
      payload: {
        reason: "invalid_grant"
      }
    });
  });

  it("returns OAuth-compliant server_error when token signing cannot proceed", async () => {
    const client = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_server_error",
      secret: "server-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();

    await seedAuthorizationCode({
      code: "code-server-error",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository
    });

    const response = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-server-error",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "server-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "server_error" });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
  });

  it("emits a token exchange audit success event on successful exchange", async () => {
    const { signer } = await createSigner();
    const client = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_audited_success",
      secret: "success-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();
    const auditRepository = new MemoryAuditRepository();

    await seedAuthorizationCode({
      code: "code-success-audit",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository,
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });
    const response = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-success-audit",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "success-secret",
      useBasicAuth: false,
      requestUrl: "https://idp.example.test/t/acme/token"
    });

    expect(response.status).toBe(200);
    expect(auditRepository.listEvents()).toHaveLength(1);
    expect(auditRepository.listEvents()[0]).toMatchObject({
      tenantId: "tenant_acme",
      eventType: "oidc.token.exchange.succeeded",
      targetType: "oidc_client",
      targetId: client.clientId,
      payload: {
        user_id: "user_123"
      }
    });
  });

  it("allows only one winner for near-concurrent code exchanges", async () => {
    const { signer } = await createSigner();
    const client = await createClient({
      authMethod: "client_secret_post",
      clientId: "client_concurrent",
      secret: "concurrent-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();

    await seedAuthorizationCode({
      code: "code-concurrent",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });

    const [first, second] = await Promise.all([
      exchangeCode({
        app,
        clientId: client.clientId,
        code: "code-concurrent",
        codeVerifier: "verifier-123456",
        redirectUri: "https://app.acme.test/callback",
        secret: "concurrent-secret",
        useBasicAuth: false,
        requestUrl: "https://idp.example.test/t/acme/token"
      }),
      exchangeCode({
        app,
        clientId: client.clientId,
        code: "code-concurrent",
        codeVerifier: "verifier-123456",
        redirectUri: "https://app.acme.test/callback",
        secret: "concurrent-secret",
        useBasicAuth: false,
        requestUrl: "https://idp.example.test/t/acme/token"
      })
    ]);

    const statuses = [first.status, second.status].sort();

    expect(statuses).toEqual([200, 400]);
  });

  it("accepts case-insensitive basic scheme and preserves challenge behavior", async () => {
    const { signer } = await createSigner();
    const client = await createClient({
      authMethod: "client_secret_basic",
      clientId: "client_basic_case",
      secret: "case-secret"
    });
    const codeRepository = new MemoryAuthorizationCodeRepository();

    await seedAuthorizationCode({
      code: "code-basic-lowercase",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });
    await seedAuthorizationCode({
      code: "code-basic-mixed-invalid",
      clientId: client.clientId,
      codeRepository,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      issuer: "https://idp.example.test/t/acme"
    });

    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: codeRepository,
      clientRepository: new MemoryClientRepository([client]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      signer,
      tenantRepository
    });

    const lowercaseSuccess = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-basic-lowercase",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "case-secret",
      useBasicAuth: true,
      basicAuthScheme: "basic",
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(lowercaseSuccess.status).toBe(200);

    const mixedCaseInvalid = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-basic-mixed-invalid",
      codeVerifier: "verifier-123456",
      redirectUri: "https://app.acme.test/callback",
      secret: "wrong-secret",
      useBasicAuth: true,
      basicAuthScheme: "bAsIc",
      requestUrl: "https://idp.example.test/t/acme/token"
    });
    expect(mixedCaseInvalid.status).toBe(401);
    await expect(mixedCaseInvalid.json()).resolves.toEqual({ error: "invalid_client" });
    expect(mixedCaseInvalid.headers.get("www-authenticate")).toBe(
      'Basic realm="token", error="invalid_client"'
    );
  });
});
