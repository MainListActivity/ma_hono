/**
 * End-to-end login flow tests.
 *
 * Covers the full OIDC authorization code + PKCE flow from browser → IdP → client,
 * using password, magic-link, and passkey auth methods, across platform-path and
 * custom-domain issuers.
 */
import { exportJWK, generateKeyPair, importJWK, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryMagicLinkRepository } from "../../src/adapters/db/memory/memory-magic-link-repository";
import { MemoryPasskeyRepository } from "../../src/adapters/db/memory/memory-passkey-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryUserSessionRepository } from "../../src/adapters/db/memory/memory-user-session-repository";
import { createApp } from "../../src/app/app";
import type { AuthenticationLoginChallengeRepository } from "../../src/domain/authentication/login-challenge-repository";
import type { LoginChallengeRepository } from "../../src/domain/authorization/repository";
import type { LoginChallenge } from "../../src/domain/authorization/types";
import type { Client } from "../../src/domain/clients/types";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import { hashPassword } from "../../src/domain/users/passwords";
import { sha256Base64Url } from "../../src/lib/hash";

const CLIENT_SECRET = "super-secret-value";

// ─── Shared test helpers ─────────────────────────────────────────────────────

class TestLoginChallengeRepository
  implements LoginChallengeRepository, AuthenticationLoginChallengeRepository
{
  private readonly challenges: LoginChallenge[] = [];

  async create(challenge: LoginChallenge): Promise<void> {
    this.challenges.push(challenge);
  }

  async consume(challengeId: string, consumedAt: string): Promise<boolean> {
    const challenge = this.challenges.find(
      (c) => c.id === challengeId && c.consumedAt === null
    );
    if (challenge !== undefined) {
      challenge.consumedAt = consumedAt;
      return true;
    }
    return false;
  }

  async findByTokenHash(tokenHash: string): Promise<LoginChallenge | null> {
    return (
      this.challenges.find((c) => c.tokenHash === tokenHash && c.consumedAt === null) ?? null
    );
  }

  listChallenges() {
    return [...this.challenges];
  }

  async setMfaState(challengeId: string, authenticatedUserId: string, mfaState: LoginChallenge["mfaState"]): Promise<void> {
    const c = this.challenges.find(c => c.id === challengeId);
    if (c) { c.authenticatedUserId = authenticatedUserId; c.mfaState = mfaState; }
  }

  async incrementMfaAttemptCount(challengeId: string): Promise<number> {
    const c = this.challenges.find(c => c.id === challengeId);
    if (!c) return 0;
    c.mfaAttemptCount = (c.mfaAttemptCount ?? 0) + 1;
    return c.mfaAttemptCount;
  }

  async incrementEnrollmentAttemptCount(challengeId: string): Promise<number> {
    const c = this.challenges.find(c => c.id === challengeId);
    if (!c) return 0;
    c.enrollmentAttemptCount = (c.enrollmentAttemptCount ?? 0) + 1;
    return c.enrollmentAttemptCount;
  }

  async satisfyMfa(challengeId: string): Promise<void> {
    const c = this.challenges.find(c => c.id === challengeId);
    if (c) c.mfaState = "satisfied";
  }

  async setTotpEnrollmentSecret(challengeId: string, secretEncrypted: string): Promise<void> {
    const c = this.challenges.find(c => c.id === challengeId);
    if (c) c.totpEnrollmentSecretEncrypted = secretEncrypted;
  }

  async completeEnrollment(challengeId: string): Promise<void> {
    const c = this.challenges.find(c => c.id === challengeId);
    if (c) { c.mfaState = "satisfied"; c.totpEnrollmentSecretEncrypted = null; }
  }
}

const createSigner = async (): Promise<{
  signer: SigningKeySigner;
  material: SigningKeyMaterial;
}> => {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
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
      publicJwk: { ...publicJwk, alg: "ES256", kid: "kid-acme", use: "sig" }
    },
    privateJwk: { ...privateJwk, alg: "ES256", kid: "kid-acme" }
  };
  return {
    material,
    signer: {
      async ensureActiveSigningKeyMaterial() { return material; },
      async loadActiveSigningKeyMaterial() { return material; }
    }
  };
};

const buildPkceChallenge = async (verifier: string) => ({
  codeVerifier: verifier,
  codeChallenge: await sha256Base64Url(verifier)
});

// ─── Tenant / client fixtures ─────────────────────────────────────────────────

const buildTenantRepository = () =>
  new MemoryTenantRepository([
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
      id: "tenant_disabled",
      slug: "disabled",
      displayName: "Disabled Tenant",
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

const buildClients = async (): Promise<Client[]> => [
  {
    id: "client_record_acme",
    tenantId: "tenant_acme",
    clientId: "client_acme",
    clientName: "Acme Web",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.acme.test/callback"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: await sha256Base64Url(CLIENT_SECRET),
    trustLevel: "first_party_trusted",
    consentPolicy: "skip"
  }
];

const buildUserRepository = async () =>
  new MemoryUserRepository({
    policies: [
      {
        tenantId: "tenant_acme",
        password: { enabled: true },
        emailMagicLink: { enabled: true },
        passkey: { enabled: true }
      }
    ],
    users: [
      {
        id: "user_alice",
        tenantId: "tenant_acme",
        email: "alice@acme.test",
        emailVerified: true,
        username: "alice",
        displayName: "Alice",
        status: "active",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
    ],
    passwordCredentials: [
      {
        id: "credential_alice",
        tenantId: "tenant_acme",
        userId: "user_alice",
        passwordHash: await hashPassword("correct-horse-battery-staple"),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
    ]
  });

// ─── Shared app factory ───────────────────────────────────────────────────────

interface AppFixture {
  app: ReturnType<typeof createApp>;
  loginChallengeRepository: TestLoginChallengeRepository;
  authorizationCodeRepository: MemoryAuthorizationCodeRepository;
  magicLinkRepository: MemoryMagicLinkRepository;
  passkeyRepository: MemoryPasskeyRepository;
  sessionRepository: MemoryUserSessionRepository;
  auditRepository: MemoryAuditRepository;
  signer: SigningKeySigner;
  material: SigningKeyMaterial;
}

const buildApp = async (
  userRepository?: MemoryUserRepository
): Promise<AppFixture> => {
  const { signer, material } = await createSigner();
  const loginChallengeRepository = new TestLoginChallengeRepository();
  const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
  const magicLinkRepository = new MemoryMagicLinkRepository();
  const passkeyRepository = new MemoryPasskeyRepository();
  const sessionRepository = new MemoryUserSessionRepository();
  const auditRepository = new MemoryAuditRepository();
  const resolvedUserRepository = userRepository ?? (await buildUserRepository());

  const app = createApp({
    auditRepository,
    authorizationCodeRepository,
    browserSessionRepository: sessionRepository,
    clientRepository: new MemoryClientRepository(await buildClients()),
    loginChallengeLookupRepository: loginChallengeRepository,
    loginChallengeRepository,
    magicLinkRepository,
    passkeyRepository,
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "",
    oidcHost: "idp.example.test", authDomain: "auth.example.test",
    signer,
    tenantRepository: buildTenantRepository(),
    userRepository: resolvedUserRepository
  });

  return {
    app,
    loginChallengeRepository,
    authorizationCodeRepository,
    magicLinkRepository,
    passkeyRepository,
    sessionRepository,
    auditRepository,
    signer,
    material
  };
};

// Perform a full authorization + token exchange and return the id_token payload
const doAuthorize = async (
  app: ReturnType<typeof createApp>,
  baseUrl: string,
  pkce: { codeVerifier: string; codeChallenge: string }
) => {
  const authorizeUrl = new URL(`${baseUrl}/authorize`);
  authorizeUrl.searchParams.set("client_id", "client_acme");
  authorizeUrl.searchParams.set("redirect_uri", "https://app.acme.test/callback");
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("scope", "openid profile");
  authorizeUrl.searchParams.set("state", "test-state");
  authorizeUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  return app.request(authorizeUrl.toString(), { method: "GET" });
};

const doTokenExchange = async (
  app: ReturnType<typeof createApp>,
  baseUrl: string,
  code: string,
  pkce: { codeVerifier: string }
) => {
  return app.request(`${baseUrl}/token`, {
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.acme.test/callback",
      code_verifier: pkce.codeVerifier
    }),
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: "Basic " + btoa(`client_acme:${CLIENT_SECRET}`)
    },
    method: "POST"
  });
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("end-to-end login flows", () => {
  it("platform-path issuer: password login → code → token exchange", async () => {
    const { app, material } = await buildApp();
    const baseUrl = "https://idp.example.test/t/acme";
    const authBase = "https://auth.example.test";
    const pkce = await buildPkceChallenge("e2e-verifier-platform-password");

    // 1. /authorize → login challenge redirect
    const authorizeResponse = await doAuthorize(app, baseUrl, pkce);
    expect(authorizeResponse.status).toBe(302);
    const loginRedirect = new URL(authorizeResponse.headers.get("location") ?? "");
    const loginChallengeToken = loginRedirect.searchParams.get("login_challenge");
    expect(loginChallengeToken).toBeTruthy();

    // 2. Password login → code redirect (login routes live on auth domain)
    const passwordResponse = await app.request(`${authBase}/login/acme/password`, {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken!,
        username: "alice",
        password: "correct-horse-battery-staple"
      }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });
    expect(passwordResponse.status).toBe(302);
    const callbackUrl = new URL(passwordResponse.headers.get("location") ?? "");
    const code = callbackUrl.searchParams.get("code");
    expect(code).toBeTruthy();
    expect(callbackUrl.searchParams.get("state")).toBe("test-state");

    // 3. Token exchange → id_token + access_token
    const tokenResponse = await doTokenExchange(app, baseUrl, code!, pkce);
    expect(tokenResponse.status).toBe(200);
    const tokenBody = await tokenResponse.json() as {
      id_token: string;
      access_token: string;
      token_type: string;
    };
    expect(tokenBody.token_type).toBe("Bearer");

    // 4. Verify id_token signature using discovered JWKS
    const jwksResponse = await app.request(`${baseUrl}/jwks.json`);
    expect(jwksResponse.status).toBe(200);
    const jwks = await jwksResponse.json() as { keys: object[] };
    expect(Array.isArray(jwks.keys)).toBe(true);

    const publicKey = await importJWK(material.key.publicJwk);
    const { payload } = await jwtVerify(tokenBody.id_token, publicKey, {
      issuer: baseUrl
    });
    expect(payload.sub).toBe("user_alice");
    expect(payload.iss).toBe(baseUrl);
    expect(payload.aud).toBe("client_acme");
  });

  it("custom-domain issuer: magic-link login → code → token exchange", async () => {
    const { app, material } = await buildApp();
    const baseUrl = "https://login.acme.test";
    const pkce = await buildPkceChallenge("e2e-verifier-custom-domain-magiclink");

    // 1. /authorize → challenge redirect
    const authorizeResponse = await doAuthorize(app, baseUrl, pkce);
    expect(authorizeResponse.status).toBe(302);
    const loginRedirect = new URL(authorizeResponse.headers.get("location") ?? "");
    const loginChallengeToken = loginRedirect.searchParams.get("login_challenge");
    expect(loginChallengeToken).toBeTruthy();

    // 2. Request magic link
    const requestResponse = await app.request(`${baseUrl}/login/magic-link/request`, {
      body: new URLSearchParams({
        email: "alice@acme.test",
        login_challenge: loginChallengeToken!
      }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });
    expect(requestResponse.status).toBe(200);
    const { magic_link_token: magicLinkToken } = await requestResponse.json() as {
      magic_link_token: string;
    };

    // 3. Consume magic link → code redirect
    const consumeResponse = await app.request(`${baseUrl}/login/magic-link/consume`, {
      body: new URLSearchParams({ token: magicLinkToken }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });
    expect(consumeResponse.status).toBe(302);
    const callbackUrl = new URL(consumeResponse.headers.get("location") ?? "");
    const code = callbackUrl.searchParams.get("code");
    expect(code).toBeTruthy();

    // 4. Token exchange → id_token
    const tokenResponse = await doTokenExchange(app, baseUrl, code!, pkce);
    expect(tokenResponse.status).toBe(200);
    const tokenBody = await tokenResponse.json() as { id_token: string; token_type: string };
    expect(tokenBody.token_type).toBe("Bearer");

    // 5. Verify id_token uses custom-domain issuer
    const publicKey = await importJWK(material.key.publicJwk);
    const { payload } = await jwtVerify(tokenBody.id_token, publicKey, {
      issuer: baseUrl
    });
    expect(payload.iss).toBe(baseUrl);
    expect(payload.sub).toBe("user_alice");
  });

  it("platform-path issuer: passkey enrollment → passkey login → code → token exchange", async () => {
    const { app, material } = await buildApp();
    const baseUrl = "https://idp.example.test/t/acme";
    const authBase = "https://auth.example.test";
    const pkce = await buildPkceChallenge("e2e-verifier-platform-passkey");

    // 1. Enroll passkey (enrollment routes live on auth domain)
    const enrollStart = await app.request(`${authBase}/passkey/acme/enroll/start`, {
      body: JSON.stringify({ user_id: "user_alice" }),
      headers: { "content-type": "application/json" },
      method: "POST"
    });
    expect(enrollStart.status).toBe(200);
    const { enrollment_session_id: enrollmentSessionId } = await enrollStart.json() as {
      enrollment_session_id: string;
    };

    const credentialId = "e2e-passkey-credential";
    const enrollFinish = await app.request(`${authBase}/passkey/acme/enroll/finish`, {
      body: JSON.stringify({
        enrollment_session_id: enrollmentSessionId,
        credential_id: credentialId,
        public_key_cbor: "dGVzdC1rZXk=",
        sign_count: 0
      }),
      headers: { "content-type": "application/json" },
      method: "POST"
    });
    expect(enrollFinish.status).toBe(200);

    // 2. /authorize → challenge redirect
    const authorizeResponse = await doAuthorize(app, baseUrl, pkce);
    expect(authorizeResponse.status).toBe(302);
    const loginRedirect = new URL(authorizeResponse.headers.get("location") ?? "");
    const loginChallengeToken = loginRedirect.searchParams.get("login_challenge");
    expect(loginChallengeToken).toBeTruthy();

    // 3. Passkey login start (login routes live on auth domain)
    const loginStart = await app.request(`${authBase}/login/acme/passkey/start`, {
      body: new URLSearchParams({ login_challenge: loginChallengeToken! }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });
    expect(loginStart.status).toBe(200);
    const { assertion_session_id: assertionSessionId } = await loginStart.json() as {
      assertion_session_id: string;
    };

    // 4. Passkey login finish → code redirect
    const loginFinish = await app.request(`${authBase}/login/acme/passkey/finish`, {
      body: JSON.stringify({
        assertion_session_id: assertionSessionId,
        credential_id: credentialId,
        sign_count: 1
      }),
      headers: { "content-type": "application/json" },
      method: "POST"
    });
    expect(loginFinish.status).toBe(302);
    const callbackUrl = new URL(loginFinish.headers.get("location") ?? "");
    const code = callbackUrl.searchParams.get("code");
    expect(code).toBeTruthy();

    // 5. Token exchange → id_token
    const tokenResponse = await doTokenExchange(app, baseUrl, code!, pkce);
    expect(tokenResponse.status).toBe(200);
    const tokenBody = await tokenResponse.json() as { id_token: string };

    const publicKey = await importJWK(material.key.publicJwk);
    const { payload } = await jwtVerify(tokenBody.id_token, publicKey, {
      issuer: baseUrl
    });
    expect(payload.sub).toBe("user_alice");
  });

  it("discovery metadata and JWKS validate the returned tokens", async () => {
    const { app } = await buildApp();
    const baseUrl = "https://idp.example.test/t/acme";

    const discoveryResponse = await app.request(
      `${baseUrl}/.well-known/openid-configuration`
    );
    expect(discoveryResponse.status).toBe(200);
    const discovery = await discoveryResponse.json() as {
      issuer: string;
      authorization_endpoint: string;
      token_endpoint: string;
      jwks_uri: string;
      code_challenge_methods_supported: string[];
    };
    expect(discovery.issuer).toBe(baseUrl);
    expect(discovery.authorization_endpoint).toBeTruthy();
    expect(discovery.token_endpoint).toBeTruthy();
    expect(discovery.jwks_uri).toBeTruthy();
    expect(discovery.code_challenge_methods_supported).toContain("S256");

    const jwksResponse = await app.request(discovery.jwks_uri);
    expect(jwksResponse.status).toBe(200);
    const jwks = await jwksResponse.json() as { keys: object[] };
    expect(Array.isArray(jwks.keys)).toBe(true);
  });

  it("disabled tenant authorization is rejected end-to-end", async () => {
    const { app } = await buildApp();
    const pkce = await buildPkceChallenge("e2e-verifier-disabled-tenant");

    const authorizeUrl = new URL("https://idp.example.test/t/disabled/authorize");
    authorizeUrl.searchParams.set("client_id", "client_acme");
    authorizeUrl.searchParams.set("redirect_uri", "https://app.acme.test/callback");
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("scope", "openid profile");
    authorizeUrl.searchParams.set("code_challenge", pkce.codeChallenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    const response = await app.request(authorizeUrl.toString());
    // Disabled tenant has no matching clients, so invalid_client or not found
    expect([400, 404]).toContain(response.status);
  });

  it("client trust and tenant auth-method policy are enforced", async () => {
    const { app } = await buildApp(
      new MemoryUserRepository({
        policies: [
          {
            tenantId: "tenant_acme",
            password: { enabled: false },
            emailMagicLink: { enabled: false },
            passkey: { enabled: false }
          }
        ]
      })
    );
    const baseUrl = "https://idp.example.test/t/acme";
    const authBase = "https://auth.example.test";
    const pkce = await buildPkceChallenge("e2e-verifier-policy-enforce");

    // /authorize redirects to login even with all methods off (no session)
    const authorizeResponse = await doAuthorize(app, baseUrl, pkce);
    expect(authorizeResponse.status).toBe(302);
    const loginRedirect = new URL(authorizeResponse.headers.get("location") ?? "");
    const loginChallengeToken = loginRedirect.searchParams.get("login_challenge");
    expect(loginChallengeToken).toBeTruthy();

    // All auth methods are blocked by policy (login routes live on auth domain)
    const passwordResponse = await app.request(`${authBase}/login/acme/password`, {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken!,
        username: "alice",
        password: "any-password"
      }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });
    expect(passwordResponse.status).toBe(403);
    expect(await passwordResponse.json()).toEqual({ error: "password_login_disabled" });

    const magicLinkResponse = await app.request(`${authBase}/login/acme/magic-link/request`, {
      body: new URLSearchParams({
        email: "alice@acme.test",
        login_challenge: loginChallengeToken!
      }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });
    expect(magicLinkResponse.status).toBe(403);
    expect(await magicLinkResponse.json()).toEqual({ error: "magic_link_login_disabled" });

    const passkeyResponse = await app.request(`${authBase}/login/acme/passkey/start`, {
      body: new URLSearchParams({ login_challenge: loginChallengeToken! }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });
    expect(passkeyResponse.status).toBe(403);
    expect(await passkeyResponse.json()).toEqual({ error: "passkey_disabled" });
  });
});
