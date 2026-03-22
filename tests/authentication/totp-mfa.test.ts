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
import { hashPassword } from "../../src/domain/users/passwords";
import { sha256Base64Url } from "../../src/lib/hash";
import { encryptTotpSecret } from "../../src/adapters/auth/totp/totp-crypto";
import { generateTotpSecret } from "../../src/domain/mfa/totp-service";

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
    trustLevel: "first_party_trusted", consentPolicy: "skip"
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
