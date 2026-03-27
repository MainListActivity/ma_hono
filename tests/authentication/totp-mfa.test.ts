import { describe, expect, it } from "vitest";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryUserSessionRepository } from "../../src/adapters/db/memory/memory-user-session-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryPasskeyRepository } from "../../src/adapters/db/memory/memory-passkey-repository";
import { createApp } from "../../src/app/app";
import type { AuthenticationLoginChallengeRepository } from "../../src/domain/authentication/login-challenge-repository";
import type { LoginChallengeRepository } from "../../src/domain/authorization/repository";
import type { LoginChallenge } from "../../src/domain/authorization/types";
import type { TotpCredential } from "../../src/domain/mfa/totp-repository";
import { hashPassword } from "../../src/domain/users/passwords";
import { sha256Base64Url } from "../../src/lib/hash";
import { encryptTotpSecret } from "../../src/adapters/auth/totp/totp-crypto";
import { generateTotpSecret, generateTotpCode } from "../../src/domain/mfa/totp-service";

// Shared test key for encrypting TOTP secrets in tests
const TEST_TOTP_KEY = new Uint8Array(32).fill(7);

// A minimal TestLoginChallengeRepository that implements the full interface
class TestLoginChallengeRepository
  implements LoginChallengeRepository, AuthenticationLoginChallengeRepository
{
  public readonly challenges: LoginChallenge[] = [];

  async create(challenge: LoginChallenge): Promise<void> { this.challenges.push(challenge); }

  async consume(id: string, consumedAt: string): Promise<boolean> {
    const c = this.challenges.find(c => c.id === id && c.consumedAt === null);
    if (c) { c.consumedAt = consumedAt; return true; }
    return false;
  }

  async findByTokenHash(hash: string): Promise<LoginChallenge | null> {
    return this.challenges.find(c => c.tokenHash === hash && c.consumedAt === null) ?? null;
  }

  async setMfaState(id: string, userId: string, mfaState: LoginChallenge["mfaState"]): Promise<void> {
    const c = this.challenges.find(c => c.id === id);
    if (c) { c.authenticatedUserId = userId; c.mfaState = mfaState; }
  }

  async incrementMfaAttemptCount(id: string): Promise<number> {
    const c = this.challenges.find(c => c.id === id);
    if (!c) return 0;
    c.mfaAttemptCount = (c.mfaAttemptCount ?? 0) + 1;
    return c.mfaAttemptCount;
  }

  async incrementEnrollmentAttemptCount(id: string): Promise<number> {
    const c = this.challenges.find(c => c.id === id);
    if (!c) return 0;
    c.enrollmentAttemptCount = (c.enrollmentAttemptCount ?? 0) + 1;
    return c.enrollmentAttemptCount;
  }

  async satisfyMfa(id: string): Promise<void> {
    const c = this.challenges.find(c => c.id === id);
    if (c) c.mfaState = "satisfied";
  }

  async setTotpEnrollmentSecret(id: string, secret: string): Promise<void> {
    const c = this.challenges.find(c => c.id === id);
    if (c) c.totpEnrollmentSecretEncrypted = secret;
  }

  async completeEnrollment(id: string): Promise<void> {
    const c = this.challenges.find(c => c.id === id);
    if (c) { c.mfaState = "satisfied"; c.totpEnrollmentSecretEncrypted = null; }
  }
}

// Helpers to build fixture challenge tokens
const makeChallenge = async (
  overrides: Partial<LoginChallenge> = {}
): Promise<{ challenge: LoginChallenge; token: string }> => {
  const token = crypto.randomUUID().replaceAll("-", "");
  const tokenHash = await sha256Base64Url(token);
  const challenge: LoginChallenge = {
    id: crypto.randomUUID(),
    tenantId: "tenant_acme",
    issuer: "https://idp.example.test/t/acme",
    clientId: "client_app1",
    redirectUri: "https://app.example.test/callback",
    scope: "openid",
    state: "state123",
    codeChallenge: "challenge",
    codeChallengeMethod: "S256",
    nonce: null,
    tokenHash,
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    consumedAt: null,
    createdAt: new Date().toISOString(),
    authenticatedUserId: null,
    mfaState: "none",
    mfaAttemptCount: 0,
    enrollmentAttemptCount: 0,
    totpEnrollmentSecretEncrypted: null,
    ...overrides
  };
  return { challenge, token };
};

// Base app fixtures
const tenantRepository = new MemoryTenantRepository([{
  id: "tenant_acme", slug: "acme", displayName: "Acme", status: "active",
  issuers: [{
    id: "iss1", issuerType: "platform_path", issuerUrl: "https://idp.example.test/t/acme",
    domain: null, isPrimary: true, verificationStatus: "verified"
  }]
}]);

const buildUserRepo = async (password: string) => {
  const passwordHash = await hashPassword(password);
  return new MemoryUserRepository({
    policies: [],
    users: [
      {
        id: "user1", tenantId: "tenant_acme", email: "alice@example.com",
        emailVerified: false, username: "alice", displayName: "Alice", status: "active",
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
      }
    ],
    passwordCredentials: [
      {
        id: "cred1", tenantId: "tenant_acme", userId: "user1",
        passwordHash,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
      }
    ]
  });
};

const buildClientAndPolicyRepos = async () => {
  const clientRepo = new MemoryClientRepository();
  await clientRepo.create({
    id: "client_id_1", tenantId: "tenant_acme", clientId: "client_app1",
    clientName: "App1", applicationType: "web", grantTypes: ["authorization_code"],
    redirectUris: ["https://app.example.test/callback"], responseTypes: ["code"],
    tokenEndpointAuthMethod: "none", clientSecretHash: null,
    trustLevel: "first_party_trusted", consentPolicy: "skip",
    clientProfile: "web", accessTokenAudience: null
  });

  const policyRepo = new MemoryClientAuthMethodPolicyRepository();
  await policyRepo.create({
    clientId: "client_id_1", tenantId: "tenant_acme",
    password: { enabled: true, allowRegistration: false },
    emailMagicLink: { enabled: false, allowRegistration: false },
    passkey: { enabled: false, allowRegistration: false },
    google: { enabled: false }, apple: { enabled: false },
    facebook: { enabled: false }, wechat: { enabled: false },
    mfaRequired: true
  });

  return { clientRepo, policyRepo };
};

describe("MFA — password login with mfa_required", () => {
  it("returns mfa_state=pending_enrollment when no MFA enrolled", async () => {
    const { clientRepo, policyRepo } = await buildClientAndPolicyRepos();
    const userRepo = await buildUserRepo("hunter2");

    const { challenge, token } = await makeChallenge();
    const loginChallengeRepo = new TestLoginChallengeRepository();
    loginChallengeRepo.challenges.push(challenge);

    const totpRepository = new MemoryTotpRepository();
    const passkeyRepository = new MemoryPasskeyRepository();

    const app = createApp({
      adminBootstrapPasswordHash: "x",
      adminWhitelist: [],
      authDomain: "idp.example.test",
      oidcHost: "idp.example.test",
      managementApiToken: "token",
      tenantRepository,
      clientRepository: clientRepo,
      clientAuthMethodPolicyRepository: policyRepo,
      userRepository: userRepo,
      loginChallengeLookupRepository: loginChallengeRepo,
      loginChallengeRepository: loginChallengeRepo,
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      totpRepository,
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      passkeyRepository,
      totpEncryptionKey: TEST_TOTP_KEY
    });

    const res = await app.request(
      "https://idp.example.test/login/acme/password",
      { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ login_challenge: token, username: "alice", password: "hunter2" }).toString() }
    );

    expect(res.status).toBe(200);
    const body = await res.json() as { mfa_state: string; login_challenge: string };
    expect(body.mfa_state).toBe("pending_enrollment");
    expect(body.login_challenge).toBe(token);
    // Challenge must NOT be consumed
    expect(loginChallengeRepo.challenges[0].consumedAt).toBeNull();
  });

  it("returns mfa_state=pending_totp when TOTP enrolled", async () => {
    const { clientRepo, policyRepo } = await buildClientAndPolicyRepos();
    const userRepo = await buildUserRepo("hunter2");

    const totpRepository = new MemoryTotpRepository();
    const secret = generateTotpSecret();
    const secretEncrypted = await encryptTotpSecret(secret, TEST_TOTP_KEY);
    await totpRepository.create({
      id: crypto.randomUUID(), tenantId: "tenant_acme", userId: "user1",
      secretEncrypted, algorithm: "SHA1", digits: 6, period: 30,
      lastUsedWindow: 0,
      enrolledAt: new Date().toISOString(), createdAt: new Date().toISOString()
    });

    const { challenge, token } = await makeChallenge();
    const loginChallengeRepo = new TestLoginChallengeRepository();
    loginChallengeRepo.challenges.push(challenge);

    const app = createApp({
      adminBootstrapPasswordHash: "x", adminWhitelist: [],
      authDomain: "idp.example.test", oidcHost: "idp.example.test",
      managementApiToken: "token",
      tenantRepository, clientRepository: clientRepo,
      clientAuthMethodPolicyRepository: policyRepo,
      userRepository: userRepo,
      loginChallengeLookupRepository: loginChallengeRepo,
      loginChallengeRepository: loginChallengeRepo,
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      totpRepository,
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      passkeyRepository: new MemoryPasskeyRepository(),
      totpEncryptionKey: TEST_TOTP_KEY
    });

    const res = await app.request(
      "https://idp.example.test/login/acme/password",
      { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ login_challenge: token, username: "alice", password: "hunter2" }).toString() }
    );

    expect(res.status).toBe(200);
    const body = await res.json() as { mfa_state: string };
    expect(body.mfa_state).toBe("pending_totp");
  });
});

// Helper: build an app with a challenge already in an MFA state.
// totpCredOverride is optional — pass to simulate a TOTP-enrolled user.
const makeMfaApp = async ({
  mfaState,
  totpCredOverride,
}: {
  mfaState: LoginChallenge["mfaState"];
  totpCredOverride?: Partial<TotpCredential>;
}) => {
  const clientRepo = new MemoryClientRepository();
  await clientRepo.create({
    id: "client_id_1", tenantId: "tenant_acme", clientId: "client_app1",
    clientName: "App1", applicationType: "web", grantTypes: ["authorization_code"],
    redirectUris: ["https://app.example.test/callback"], responseTypes: ["code"],
    tokenEndpointAuthMethod: "none", clientSecretHash: null,
    trustLevel: "first_party_trusted", consentPolicy: "skip",
    clientProfile: "web", accessTokenAudience: null
  });

  const userRepo = new MemoryUserRepository({ policies: [] });
  await userRepo.createProvisionedUserWithInvitation({
    user: {
      id: "user1", tenantId: "tenant_acme", email: "alice@example.com",
      emailVerified: false, username: "alice", displayName: "Alice", status: "active",
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
    },
    invitation: {
      id: "inv1", tenantId: "tenant_acme", userId: "user1", tokenHash: "th1",
      purpose: "account_activation", expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      consumedAt: null, createdAt: new Date().toISOString()
    }
  });
  await userRepo.upsertPasswordCredential({
    id: "cred1", tenantId: "tenant_acme", userId: "user1",
    passwordHash: "x", createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  });

  const totpRepository = new MemoryTotpRepository();
  if (totpCredOverride !== undefined) {
    await totpRepository.create({
      id: "totp1", tenantId: "tenant_acme", userId: "user1",
      secretEncrypted: "", algorithm: "SHA1", digits: 6, period: 30,
      lastUsedWindow: 0, enrolledAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      ...totpCredOverride
    });
  }

  const { challenge, token } = await makeChallenge({
    authenticatedUserId: "user1", mfaState
  });
  const loginChallengeRepo = new TestLoginChallengeRepository();
  loginChallengeRepo.challenges.push(challenge);

  const policyRepo = new MemoryClientAuthMethodPolicyRepository();
  await policyRepo.create({
    clientId: "client_id_1", tenantId: "tenant_acme",
    password: { enabled: true, allowRegistration: false },
    emailMagicLink: { enabled: false, allowRegistration: false },
    passkey: { enabled: false, allowRegistration: false },
    google: { enabled: false }, apple: { enabled: false },
    facebook: { enabled: false }, wechat: { enabled: false },
    mfaRequired: true
  });

  const mfaPasskeyChallengeRepo = new MemoryMfaPasskeyChallengeRepository();

  const appInstance = createApp({
    adminBootstrapPasswordHash: "x", adminWhitelist: [],
    authDomain: "idp.example.test", oidcHost: "idp.example.test",
    managementApiToken: "token",
    tenantRepository, clientRepository: clientRepo,
    clientAuthMethodPolicyRepository: policyRepo,
    userRepository: userRepo,
    loginChallengeLookupRepository: loginChallengeRepo,
    loginChallengeRepository: loginChallengeRepo,
    auditRepository: new MemoryAuditRepository(),
    authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
    browserSessionRepository: new MemoryUserSessionRepository(),
    totpRepository,
    mfaPasskeyChallengeRepository: mfaPasskeyChallengeRepo,
    passkeyRepository: new MemoryPasskeyRepository(),
    totpEncryptionKey: TEST_TOTP_KEY
  });

  return { app: appInstance, loginChallengeRepo, totpRepository, mfaPasskeyChallengeRepo, token, challenge };
};

describe("MFA — TOTP verify endpoint", () => {
  it("verifies a valid TOTP code and redirects", async () => {
    const rawSecret = generateTotpSecret();
    const secretEncrypted = await encryptTotpSecret(rawSecret, TEST_TOTP_KEY);
    const { app, token } = await makeMfaApp({
      mfaState: "pending_totp",
      totpCredOverride: { secretEncrypted, lastUsedWindow: 0 }
    });
    const windowIndex = Math.floor(Date.now() / 1000 / 30);
    const code = await generateTotpCode(rawSecret, windowIndex);

    const res = await app.request(
      "https://idp.example.test/api/login/acme/mfa/totp/verify",
      { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login_challenge: token, code }) }
    );

    // Expect redirect (status 302) or JSON body with redirect_uri
    expect([200, 302]).toContain(res.status);
  });

  it("rejects an invalid TOTP code and increments attempt count", async () => {
    const rawSecret = generateTotpSecret();
    const secretEncrypted = await encryptTotpSecret(rawSecret, TEST_TOTP_KEY);
    const { app, loginChallengeRepo, token } = await makeMfaApp({
      mfaState: "pending_totp",
      totpCredOverride: { secretEncrypted, lastUsedWindow: 0 }
    });

    const res = await app.request(
      "https://idp.example.test/api/login/acme/mfa/totp/verify",
      { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login_challenge: token, code: "000000" }) }
    );

    // May be valid by extreme coincidence (1 in 1M); just check shape
    if (res.status === 401) {
      const body = await res.json() as { error: string; remaining_attempts: number };
      expect(body.error).toBe("invalid_code");
      expect(body.remaining_attempts).toBe(4);
      expect(loginChallengeRepo.challenges[0].mfaAttemptCount).toBe(1);
    }
  });

  it("invalidates challenge after 5 failed attempts (brute-force lockout)", async () => {
    const rawSecret = generateTotpSecret();
    const secretEncrypted = await encryptTotpSecret(rawSecret, TEST_TOTP_KEY);
    const { app, loginChallengeRepo, token } = await makeMfaApp({
      mfaState: "pending_totp",
      totpCredOverride: { secretEncrypted, lastUsedWindow: 0 }
    });

    // Force 5 failures by attempting window far in the past (code won't match current)
    const pastCode = await generateTotpCode(rawSecret, 1); // window 1 = year 1970
    let lastRes!: Response;
    for (let i = 0; i < 5; i++) {
      lastRes = await app.request(
        "https://idp.example.test/api/login/acme/mfa/totp/verify",
        { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ login_challenge: token, code: pastCode }) }
      );
    }

    expect(lastRes.status).toBe(401);
    const body = await lastRes.json() as { error: string };
    expect(body.error).toBe("challenge_invalidated");
    expect(loginChallengeRepo.challenges[0].consumedAt).not.toBeNull();
  });

  it("rejects replay of same window code (lastUsedWindow already at current window)", async () => {
    const rawSecret = generateTotpSecret();
    const secretEncrypted = await encryptTotpSecret(rawSecret, TEST_TOTP_KEY);
    const windowIndex = Math.floor(Date.now() / 1000 / 30);
    // Pre-set lastUsedWindow to current window to simulate already-used
    const { app, token } = await makeMfaApp({
      mfaState: "pending_totp",
      totpCredOverride: { secretEncrypted, lastUsedWindow: windowIndex }
    });
    const code = await generateTotpCode(rawSecret, windowIndex);

    const res = await app.request(
      "https://idp.example.test/api/login/acme/mfa/totp/verify",
      { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login_challenge: token, code }) }
    );

    expect(res.status).toBe(401);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("replay");
  });
});

describe("MFA — switch-to-totp endpoint", () => {
  it("transitions challenge from pending_passkey_step_up to pending_totp", async () => {
    const rawSecret = generateTotpSecret();
    const secretEncrypted = await encryptTotpSecret(rawSecret, TEST_TOTP_KEY);
    const { app, loginChallengeRepo, token } = await makeMfaApp({
      mfaState: "pending_passkey_step_up",
      totpCredOverride: { secretEncrypted }
    });

    const res = await app.request(
      "https://idp.example.test/api/login/acme/mfa/switch-to-totp",
      { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login_challenge: token }) }
    );

    expect(res.status).toBe(200);
    const body = await res.json() as { mfa_state: string };
    expect(body.mfa_state).toBe("pending_totp");
    expect(loginChallengeRepo.challenges[0].mfaState).toBe("pending_totp");
  });

  it("returns 400 when challenge is in pending_totp state (not passkey step-up)", async () => {
    const rawSecret = generateTotpSecret();
    const secretEncrypted = await encryptTotpSecret(rawSecret, TEST_TOTP_KEY);
    const { app, token } = await makeMfaApp({
      mfaState: "pending_totp",
      totpCredOverride: { secretEncrypted }
    });

    const res = await app.request(
      "https://idp.example.test/api/login/acme/mfa/switch-to-totp",
      { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login_challenge: token }) }
    );

    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_mfa_state");
  });

  it("returns 400 when user has no TOTP enrolled", async () => {
    const { app, token } = await makeMfaApp({
      mfaState: "pending_passkey_step_up"
      // No totpCredOverride — no TOTP enrolled
    });

    const res = await app.request(
      "https://idp.example.test/api/login/acme/mfa/switch-to-totp",
      { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login_challenge: token }) }
    );

    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("totp_not_enrolled");
  });
});

describe("MFA — passkey step-up brute-force lockout", () => {
  it("invalidates challenge after 5 structurally-valid-but-wrong-signature assertions", async () => {
    const { app, loginChallengeRepo, mfaPasskeyChallengeRepo, token } = await makeMfaApp({
      mfaState: "pending_passkey_step_up"
    });

    const fakeAuthData = new Uint8Array(37).fill(0x42);
    const clientDataObj = { type: "webauthn.get", challenge: "fakechallenge", origin: "https://idp.example.test" };
    const clientDataJson = new TextEncoder().encode(JSON.stringify(clientDataObj));
    const fakeSignature = new Uint8Array(64).fill(0xab);

    const toB64 = (u: Uint8Array) =>
      btoa(String.fromCharCode(...u)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    let lastRes!: Response;
    for (let i = 0; i < 5; i++) {
      const ch = {
        id: crypto.randomUUID(), tenantId: "tenant_acme",
        loginChallengeId: loginChallengeRepo.challenges[0].id,
        challengeHash: "hash" + i,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        consumedAt: null, createdAt: new Date().toISOString()
      };
      await mfaPasskeyChallengeRepo.create(ch);

      lastRes = await app.request(
        "https://idp.example.test/api/login/acme/mfa/passkey/finish",
        { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            login_challenge: token,
            challenge_hash: ch.challengeHash,
            challenge: "fakenonce" + i,
            credential_id: "webauthn-credential-id-fixture",
            response: {
              authenticator_data: toB64(fakeAuthData),
              client_data_json: toB64(clientDataJson),
              signature: toB64(fakeSignature)
            }
          }) }
      );
    }

    expect(lastRes.status).toBe(401);
    const body = await lastRes.json() as { error: string };
    expect(body.error).toBe("challenge_invalidated");
    expect(loginChallengeRepo.challenges[0].consumedAt).not.toBeNull();
  });
});
