import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryPasskeyRepository } from "../../src/adapters/db/memory/memory-passkey-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryUserSessionRepository } from "../../src/adapters/db/memory/memory-user-session-repository";
import { createApp } from "../../src/app/app";
import type { AuthenticationLoginChallengeRepository } from "../../src/domain/authentication/login-challenge-repository";
import { createBrowserSession } from "../../src/domain/authentication/session-service";
import type { LoginChallengeRepository } from "../../src/domain/authorization/repository";
import type { LoginChallenge } from "../../src/domain/authorization/types";
import type { Client } from "../../src/domain/clients/types";
import type { User } from "../../src/domain/users/types";
import { sha256Base64Url } from "../../src/lib/hash";
import {
  createVirtualAuthenticator,
  type VirtualAuthenticator
} from "../support/webauthn-authenticator";

class TestLoginChallengeRepository
  implements LoginChallengeRepository, AuthenticationLoginChallengeRepository
{
  private readonly challenges: LoginChallenge[];

  constructor(initialChallenges: LoginChallenge[] = []) {
    this.challenges = [...initialChallenges];
  }

  async create(challenge: LoginChallenge): Promise<void> {
    this.challenges.push(challenge);
  }

  async consume(challengeId: string, consumedAt: string): Promise<boolean> {
    const challenge = this.challenges.find(
      (candidate) => candidate.id === challengeId && candidate.consumedAt === null
    );
    if (challenge !== undefined) {
      challenge.consumedAt = consumedAt;
      return true;
    }
    return false;
  }

  async findByTokenHash(tokenHash: string): Promise<LoginChallenge | null> {
    return (
      this.challenges.find(
        (challenge) => challenge.tokenHash === tokenHash && challenge.consumedAt === null
      ) ?? null
    );
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

const tenantId = "tenant_acme";
const clientRecordId = "client_record_acme_first_party";
const oidcHost = "idp.example.test";
const authDomain = "auth.example.test";
// The relying party is the login host (auth domain) for platform-path tenants.
const rpId = authDomain;
const origin = `https://${authDomain}`;
const platformBase = `https://${oidcHost}`;

const tenantRepository = new MemoryTenantRepository([
  {
    id: tenantId,
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
  }
]);

const clients: Client[] = [
  {
    id: clientRecordId,
    tenantId,
    clientId: "client_acme_first_party",
    clientName: "Acme Web",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.acme.test/callback"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: "hashed-secret",
    trustLevel: "first_party_trusted",
    consentPolicy: "skip",
    clientProfile: "web",
    accessTokenAudience: null
  }
];

const buildChallenge = async (token: string): Promise<LoginChallenge> => ({
  id: `challenge_${token}`,
  tenantId,
  issuer: "https://idp.example.test/t/acme",
  clientId: "client_acme_first_party",
  redirectUri: "https://app.acme.test/callback",
  scope: "openid profile",
  state: "opaque-state",
  codeChallenge: "pkce-challenge",
  codeChallengeMethod: "S256",
  nonce: "nonce_123",
  tokenHash: await sha256Base64Url(token),
  expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  consumedAt: null,
  authenticatedUserId: null,
  mfaState: "none" as const,
  mfaAttemptCount: 0,
  enrollmentAttemptCount: 0,
  totpEnrollmentSecretEncrypted: null,
  createdAt: new Date().toISOString()
});

const buildActiveUser = (id = "user_123"): User => ({
  id,
  tenantId,
  email: `${id}@acme.test`,
  emailVerified: true,
  username: id,
  displayName: id,
  status: "active",
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString()
});

const buildApp = async ({
  users = [buildActiveUser()],
  tenantPasskeyEnabled = true,
  clientPasskeyEnabled = true,
  loginChallenges = []
}: {
  users?: User[];
  tenantPasskeyEnabled?: boolean;
  clientPasskeyEnabled?: boolean;
  loginChallenges?: LoginChallenge[];
} = {}) => {
  const passkeyRepository = new MemoryPasskeyRepository();
  const loginChallengeRepository = new TestLoginChallengeRepository(loginChallenges);
  const sessionRepository = new MemoryUserSessionRepository();
  const auditRepository = new MemoryAuditRepository();
  const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
  const clientAuthMethodPolicyRepository = new MemoryClientAuthMethodPolicyRepository();

  await clientAuthMethodPolicyRepository.create({
    clientId: clientRecordId,
    tenantId,
    password: { enabled: true, allowRegistration: false },
    emailMagicLink: { enabled: false, allowRegistration: false },
    passkey: { enabled: clientPasskeyEnabled, allowRegistration: false },
    google: { enabled: false },
    apple: { enabled: false },
    facebook: { enabled: false },
    wechat: { enabled: false },
    mfaRequired: false
  });

  const app = createApp({
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    auditRepository,
    authDomain,
    authorizationCodeRepository,
    browserSessionRepository: sessionRepository,
    clientAuthMethodPolicyRepository,
    clientRepository: new MemoryClientRepository(clients),
    loginChallengeLookupRepository: loginChallengeRepository,
    loginChallengeRepository,
    managementApiToken: "",
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    oidcHost,
    passkeyRepository,
    tenantRepository,
    totpEncryptionKey: new Uint8Array(32).fill(7),
    totpRepository: new MemoryTotpRepository(),
    userRepository: new MemoryUserRepository({
      policies: [
        {
          tenantId,
          password: { enabled: true },
          emailMagicLink: { enabled: true },
          passkey: { enabled: tenantPasskeyEnabled }
        }
      ],
      users
    })
  });

  return {
    app,
    auditRepository,
    authorizationCodeRepository,
    loginChallengeRepository,
    passkeyRepository,
    sessionRepository
  };
};

// Cookie for a browser session created by a prior password login.
const sessionCookieFor = async (
  sessionRepository: MemoryUserSessionRepository,
  userId = "user_123"
): Promise<string> => {
  const { sessionToken } = await createBrowserSession({
    sessionRepository,
    tenantId,
    userId
  });
  return `user_session=${sessionToken}`;
};

// Hono's request() returns Response | Promise<Response>, so the helper type accepts both.
type TestApp = { request: (url: string, init?: RequestInit) => Response | Promise<Response> };

const startEnrollment = (app: TestApp, cookie: string) =>
  app.request(`${platformBase}/passkey/acme/enroll/start`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie },
    body: JSON.stringify({})
  });

const finishEnrollment = (
  app: TestApp,
  cookie: string,
  body: unknown
) =>
  app.request(`${platformBase}/passkey/acme/enroll/finish`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie },
    body: JSON.stringify(body)
  });

// Registers a passkey through the real start/finish endpoints and returns the ceremony state.
const enrollPasskey = async (
  app: TestApp,
  cookie: string,
  authenticator: VirtualAuthenticator
) => {
  const start = await startEnrollment(app, cookie);
  expect(start.status).toBe(200);
  const { ceremony_id, options } = (await start.json()) as {
    ceremony_id: string;
    options: { challenge: string };
  };

  const finish = await finishEnrollment(app, cookie, {
    ceremony_id,
    credential: authenticator.createRegistrationResponse({
      challenge: options.challenge,
      origin,
      rpId
    })
  });

  return { ceremonyId: ceremony_id, finish };
};

const startLogin = (
  app: TestApp,
  loginChallengeToken: string
) =>
  app.request(`${platformBase}/login/acme/passkey/start`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ login_challenge: loginChallengeToken })
  });

const finishLogin = (
  app: TestApp,
  body: unknown
) =>
  app.request(`${platformBase}/login/acme/passkey/finish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });

// Starts a login ceremony and returns the server-issued challenge.
const beginLogin = async (
  app: TestApp,
  loginChallengeToken: string
) => {
  const start = await startLogin(app, loginChallengeToken);
  expect(start.status).toBe(200);
  const { ceremony_id, options } = (await start.json()) as {
    ceremony_id: string;
    options: { challenge: string };
  };
  return { ceremonyId: ceremony_id, challenge: options.challenge };
};

describe("passkey registration", () => {
  it("requires an authenticated session to start or finish enrollment", async () => {
    const { app } = await buildApp();

    const start = await app.request(`${platformBase}/passkey/acme/enroll/start`, {
      method: "POST"
    });
    expect(start.status).toBe(401);
    expect(await start.json()).toEqual({ error: "authentication_required" });

    const finish = await app.request(`${platformBase}/passkey/acme/enroll/finish`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ceremony_id: "forged", credential: {} })
    });
    expect(finish.status).toBe(401);
    expect(await finish.json()).toEqual({ error: "authentication_required" });
  });

  it("takes the registering user from the session and ignores a foreign user_id", async () => {
    const { app, sessionRepository } = await buildApp({
      users: [buildActiveUser("user_123"), buildActiveUser("user_other")]
    });
    const cookie = await sessionCookieFor(sessionRepository, "user_123");

    const start = await app.request(`${platformBase}/passkey/acme/enroll/start`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify({ user_id: "user_other" })
    });

    expect(start.status).toBe(200);
    const body = (await start.json()) as { options: { user: { id: string } } };
    expect(Buffer.from(body.options.user.id, "base64url").toString("utf8")).toBe("user_123");
  });

  it("does not register a passkey for an agent account", async () => {
    const agent = { ...buildActiveUser("agent_123"), username: null, kind: "agent" as const };
    const { app, sessionRepository } = await buildApp({ users: [agent] });
    const cookie = await sessionCookieFor(sessionRepository, "agent_123");

    const start = await startEnrollment(app, cookie);

    expect(start.status).toBe(403);
    expect(await start.json()).toEqual({ error: "passkey_enrollment_not_allowed" });
  });

  it("stores a real ES256 credential from a verified registration", async () => {
    const { app, passkeyRepository, sessionRepository, auditRepository } = await buildApp();
    const cookie = await sessionCookieFor(sessionRepository);
    const authenticator = createVirtualAuthenticator();

    const { finish } = await enrollPasskey(app, cookie, authenticator);

    expect(finish.status).toBe(200);
    expect(await finish.json()).toEqual({ enrolled: true });
    expect(passkeyRepository.listCredentials()).toEqual([
      expect.objectContaining({
        tenantId,
        userId: "user_123",
        credentialId: authenticator.credentialId,
        signCount: 0,
        transports: ["internal"],
        deviceType: "singleDevice",
        backedUp: false,
        publicKey: expect.any(String)
      })
    ]);
    expect(auditRepository.listEvents().map((e) => e.eventType)).toContain(
      "user.passkey.enrollment.succeeded"
    );
  });

  it("rejects a registration response bound to another origin or RP ID", async () => {
    const { app, passkeyRepository, sessionRepository, auditRepository } = await buildApp();
    const cookie = await sessionCookieFor(sessionRepository);
    const authenticator = createVirtualAuthenticator();

    for (const wrong of [
      { origin: "https://evil.example.test", rpId },
      { origin, rpId: "evil.example.test" }
    ]) {
      const start = await startEnrollment(app, cookie);
      const { ceremony_id, options } = (await start.json()) as {
        ceremony_id: string;
        options: { challenge: string };
      };
      const finish = await finishEnrollment(app, cookie, {
        ceremony_id,
        credential: authenticator.createRegistrationResponse({
          challenge: options.challenge,
          ...wrong
        })
      });

      expect(finish.status).toBe(400);
      expect(await finish.json()).toEqual({ error: "verification_failed" });
    }

    expect(passkeyRepository.listCredentials()).toHaveLength(0);
    expect(auditRepository.listEvents().map((e) => e.eventType)).toContain(
      "user.passkey.enrollment.failed"
    );
  });

  it("rejects a registration ceremony that is replayed", async () => {
    const { app, passkeyRepository, sessionRepository } = await buildApp();
    const cookie = await sessionCookieFor(sessionRepository);
    const authenticator = createVirtualAuthenticator();

    const { ceremonyId, finish } = await enrollPasskey(app, cookie, authenticator);
    expect(finish.status).toBe(200);

    const replay = await finishEnrollment(app, cookie, {
      ceremony_id: ceremonyId,
      credential: authenticator.createRegistrationResponse({
        challenge: "unrelated-challenge",
        origin,
        rpId
      })
    });

    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: "invalid_ceremony" });
    expect(passkeyRepository.listCredentials()).toHaveLength(1);
  });

  it("rejects legacy enrollment fields", async () => {
    const { app, sessionRepository } = await buildApp();
    const cookie = await sessionCookieFor(sessionRepository);

    const response = await finishEnrollment(app, cookie, {
      enrollment_session_id: "session",
      credential_id: "test-credential-id",
      public_key_cbor: "dGVzdC1wdWJsaWMta2V5",
      sign_count: 0
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("blocks enrollment when the tenant passkey policy is off", async () => {
    const { app, sessionRepository } = await buildApp({ tenantPasskeyEnabled: false });
    const cookie = await sessionCookieFor(sessionRepository);

    const response = await startEnrollment(app, cookie);

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "passkey_disabled" });
  });
});

describe("passkey login", () => {
  it("logs in with a registered passkey and advances the signature counter", async () => {
    const firstToken = "challenge-passkey-first";
    const secondToken = "challenge-passkey-second";
    const { app, auditRepository, authorizationCodeRepository, passkeyRepository, sessionRepository } =
      await buildApp({
        loginChallenges: [await buildChallenge(firstToken), await buildChallenge(secondToken)]
      });
    const cookie = await sessionCookieFor(sessionRepository);
    const authenticator = createVirtualAuthenticator();
    await enrollPasskey(app, cookie, authenticator);

    const first = await beginLogin(app, firstToken);
    const firstFinish = await finishLogin(app, {
      ceremony_id: first.ceremonyId,
      login_challenge: firstToken,
      credential: authenticator.createAssertionResponse({
        challenge: first.challenge,
        origin,
        rpId
      })
    });

    expect(firstFinish.status).toBe(200);
    const firstBody = (await firstFinish.json()) as { redirect_uri: string };
    const location = new URL(firstBody.redirect_uri);
    expect(location.origin + location.pathname).toBe("https://app.acme.test/callback");
    expect(location.searchParams.get("code")).toEqual(expect.any(String));
    expect(firstFinish.headers.get("set-cookie")).toMatch(/^user_session=/);
    expect(authorizationCodeRepository.listAuthorizationCodes()).toHaveLength(1);
    expect(passkeyRepository.listCredentials()[0].signCount).toBe(1);

    const second = await beginLogin(app, secondToken);
    const secondFinish = await finishLogin(app, {
      ceremony_id: second.ceremonyId,
      login_challenge: secondToken,
      credential: authenticator.createAssertionResponse({
        challenge: second.challenge,
        origin,
        rpId
      })
    });

    expect(secondFinish.status).toBe(200);
    expect(passkeyRepository.listCredentials()[0].signCount).toBe(2);

    const eventTypes = auditRepository.listEvents().map((e) => e.eventType);
    expect(eventTypes).toContain("user.passkey.enrollment.succeeded");
    expect(eventTypes.filter((type) => type === "user.passkey.login.succeeded")).toHaveLength(2);
  });

  it("rejects an assertion signed by another key that uses a registered credential id", async () => {
    const token = "challenge-passkey-forged";
    const { app, auditRepository, passkeyRepository, sessionRepository } = await buildApp({
      loginChallenges: [await buildChallenge(token)]
    });
    const cookie = await sessionCookieFor(sessionRepository);
    const victim = createVirtualAuthenticator();
    await enrollPasskey(app, cookie, victim);

    const attacker = createVirtualAuthenticator();
    const { ceremonyId, challenge } = await beginLogin(app, token);
    const forged = attacker.createAssertionResponse({ challenge, origin, rpId });
    forged.id = victim.credentialId;
    forged.rawId = victim.credentialId;

    const sessionsBefore = sessionRepository.listSessions().length;
    const response = await finishLogin(app, {
      ceremony_id: ceremonyId,
      login_challenge: token,
      credential: forged
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "invalid_credentials" });
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(sessionRepository.listSessions()).toHaveLength(sessionsBefore);
    expect(passkeyRepository.listCredentials()[0].signCount).toBe(0);
    expect(auditRepository.listEvents().map((e) => e.eventType)).toContain(
      "user.passkey.login.failed"
    );
  });

  it("rejects a replayed assertion from an earlier login ceremony", async () => {
    const firstToken = "challenge-passkey-replay-first";
    const secondToken = "challenge-passkey-replay-second";
    const { app, sessionRepository } = await buildApp({
      loginChallenges: [await buildChallenge(firstToken), await buildChallenge(secondToken)]
    });
    const cookie = await sessionCookieFor(sessionRepository);
    const authenticator = createVirtualAuthenticator();
    await enrollPasskey(app, cookie, authenticator);

    const first = await beginLogin(app, firstToken);
    const capturedAssertion = authenticator.createAssertionResponse({
      challenge: first.challenge,
      origin,
      rpId
    });
    const firstFinish = await finishLogin(app, {
      ceremony_id: first.ceremonyId,
      login_challenge: firstToken,
      credential: capturedAssertion
    });
    expect(firstFinish.status).toBe(200);

    const second = await beginLogin(app, secondToken);
    const replay = await finishLogin(app, {
      ceremony_id: second.ceremonyId,
      login_challenge: secondToken,
      credential: capturedAssertion
    });

    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({ error: "invalid_credentials" });
  });

  it("consumes the login ceremony on the first finish attempt", async () => {
    const token = "challenge-passkey-ceremony-once";
    const { app, sessionRepository } = await buildApp({
      loginChallenges: [await buildChallenge(token)]
    });
    const cookie = await sessionCookieFor(sessionRepository);
    const authenticator = createVirtualAuthenticator();
    await enrollPasskey(app, cookie, authenticator);

    const { ceremonyId, challenge } = await beginLogin(app, token);
    const wrongOrigin = await finishLogin(app, {
      ceremony_id: ceremonyId,
      login_challenge: token,
      credential: authenticator.createAssertionResponse({
        challenge,
        origin: "https://evil.example.test",
        rpId
      })
    });
    expect(wrongOrigin.status).toBe(401);

    const retry = await finishLogin(app, {
      ceremony_id: ceremonyId,
      login_challenge: token,
      credential: authenticator.createAssertionResponse({ challenge, origin, rpId })
    });

    expect(retry.status).toBe(400);
    expect(await retry.json()).toEqual({ error: "invalid_ceremony" });
  });

  it("rejects assertions bound to another origin or RP ID", async () => {
    const token = "challenge-passkey-binding";
    const { app, sessionRepository } = await buildApp({
      loginChallenges: [await buildChallenge(token)]
    });
    const cookie = await sessionCookieFor(sessionRepository);
    const authenticator = createVirtualAuthenticator();
    await enrollPasskey(app, cookie, authenticator);

    for (const wrong of [
      { origin: "https://evil.example.test", rpId },
      { origin, rpId: "evil.example.test" }
    ]) {
      const { ceremonyId, challenge } = await beginLogin(app, token);
      const response = await finishLogin(app, {
        ceremony_id: ceremonyId,
        login_challenge: token,
        credential: authenticator.createAssertionResponse({ challenge, ...wrong })
      });

      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "invalid_credentials" });
    }
  });

  it("rejects an assertion whose signature counter does not advance", async () => {
    const firstToken = "challenge-passkey-counter-first";
    const secondToken = "challenge-passkey-counter-second";
    const { app, sessionRepository } = await buildApp({
      loginChallenges: [await buildChallenge(firstToken), await buildChallenge(secondToken)]
    });
    const cookie = await sessionCookieFor(sessionRepository);
    const authenticator = createVirtualAuthenticator();
    await enrollPasskey(app, cookie, authenticator);

    const first = await beginLogin(app, firstToken);
    const firstFinish = await finishLogin(app, {
      ceremony_id: first.ceremonyId,
      login_challenge: firstToken,
      credential: authenticator.createAssertionResponse({
        challenge: first.challenge,
        origin,
        rpId,
        signCount: 5
      })
    });
    expect(firstFinish.status).toBe(200);

    const second = await beginLogin(app, secondToken);
    const cloned = await finishLogin(app, {
      ceremony_id: second.ceremonyId,
      login_challenge: secondToken,
      credential: authenticator.createAssertionResponse({
        challenge: second.challenge,
        origin,
        rpId,
        signCount: 5
      })
    });

    expect(cloned.status).toBe(401);
    expect(await cloned.json()).toEqual({ error: "invalid_credentials" });
  });

  it("rejects legacy login fields such as credential_id and sign_count", async () => {
    const token = "challenge-passkey-legacy";
    const { app } = await buildApp({ loginChallenges: [await buildChallenge(token)] });
    const { ceremonyId } = await beginLogin(app, token);

    const response = await finishLogin(app, {
      assertion_session_id: ceremonyId,
      login_challenge: token,
      credential_id: "anything",
      sign_count: 1
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("blocks login start when the client passkey policy is off", async () => {
    const token = "challenge-passkey-client-off";
    const { app } = await buildApp({
      clientPasskeyEnabled: false,
      loginChallenges: [await buildChallenge(token)]
    });

    const response = await startLogin(app, token);

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "passkey_disabled" });
  });

  it("blocks login start when the tenant passkey policy is off", async () => {
    const token = "challenge-passkey-policy-off";
    const { app } = await buildApp({
      tenantPasskeyEnabled: false,
      loginChallenges: [await buildChallenge(token)]
    });

    const response = await startLogin(app, token);

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "passkey_disabled" });
  });

  it("rejects an unknown login challenge", async () => {
    const { app } = await buildApp();

    const response = await startLogin(app, "no-such-challenge");

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });
});
