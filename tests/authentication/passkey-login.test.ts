import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryUserSessionRepository } from "../../src/adapters/db/memory/memory-user-session-repository";
import { MemoryPasskeyRepository } from "../../src/adapters/db/memory/memory-passkey-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { createApp } from "../../src/app/app";
import type { AuthenticationLoginChallengeRepository } from "../../src/domain/authentication/login-challenge-repository";
import type { LoginChallengeRepository } from "../../src/domain/authorization/repository";
import type { LoginChallenge } from "../../src/domain/authorization/types";
import type { Client } from "../../src/domain/clients/types";
import { sha256Base64Url } from "../../src/lib/hash";

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
  }
]);

const clients: Client[] = [
  {
    id: "client_record_acme_first_party",
    tenantId: "tenant_acme",
    clientId: "client_acme_first_party",
    clientName: "Acme Web",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.acme.test/callback"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: "hashed-secret",
    trustLevel: "first_party_trusted",
    consentPolicy: "skip"
  }
];

const buildChallenge = async (token: string): Promise<LoginChallenge> => ({
  id: `challenge_${token}`,
  tenantId: "tenant_acme",
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

const buildActiveUser = () => ({
  id: "user_123",
  tenantId: "tenant_acme",
  email: "alice@acme.test",
  emailVerified: true,
  username: "alice",
  displayName: "Alice",
  status: "active" as const,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString()
});

describe("passkey enrollment and login", () => {
  it("authenticated user can start passkey enrollment (receive challenge)", async () => {
    const userRepository = new MemoryUserRepository({
      policies: [
        {
          tenantId: "tenant_acme",
          password: { enabled: true },
          emailMagicLink: { enabled: true },
          passkey: { enabled: true }
        }
      ],
      users: [buildActiveUser()]
    });
    const passkeyRepository = new MemoryPasskeyRepository();
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: new TestLoginChallengeRepository(),
      loginChallengeRepository: new TestLoginChallengeRepository(),
      passkeyRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(7),
      userRepository
    });

    const response = await app.request(
      "https://idp.example.test/passkey/acme/enroll/start",
      {
        body: JSON.stringify({ user_id: "user_123" }),
        headers: { "content-type": "application/json" },
        method: "POST"
      }
    );

    expect(response.status).toBe(200);
    const body = await response.json() as { challenge: string; enrollment_session_id: string };
    expect(typeof body.challenge).toBe("string");
    expect(body.challenge.length).toBeGreaterThan(0);
    expect(typeof body.enrollment_session_id).toBe("string");
  });

  it("enrolled passkey can satisfy a login challenge", async () => {
    const loginChallengeToken = "challenge-passkey-login";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge(loginChallengeToken)
    ]);
    const passkeyRepository = new MemoryPasskeyRepository();
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const sessionRepository = new MemoryUserSessionRepository();
    const auditRepository = new MemoryAuditRepository();

    const app = createApp({
      auditRepository,
      authorizationCodeRepository,
      browserSessionRepository: sessionRepository,
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
      passkeyRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(7),
      userRepository: new MemoryUserRepository({
        policies: [
          {
            tenantId: "tenant_acme",
            password: { enabled: true },
            emailMagicLink: { enabled: true },
            passkey: { enabled: true }
          }
        ],
        users: [buildActiveUser()]
      })
    });

    // Start enrollment
    const enrollStart = await app.request(
      "https://idp.example.test/passkey/acme/enroll/start",
      {
        body: JSON.stringify({ user_id: "user_123" }),
        headers: { "content-type": "application/json" },
        method: "POST"
      }
    );
    expect(enrollStart.status).toBe(200);
    const { enrollment_session_id: enrollmentSessionId } = await enrollStart.json() as {
      challenge: string;
      enrollment_session_id: string;
    };

    // Complete enrollment (using test mode: fake credential)
    const credentialId = "test-credential-id-alice";
    const enrollFinish = await app.request(
      "https://idp.example.test/passkey/acme/enroll/finish",
      {
        body: JSON.stringify({
          enrollment_session_id: enrollmentSessionId,
          credential_id: credentialId,
          public_key_cbor: "dGVzdC1wdWJsaWMta2V5", // base64 "test-public-key"
          sign_count: 0
        }),
        headers: { "content-type": "application/json" },
        method: "POST"
      }
    );
    expect(enrollFinish.status).toBe(200);
    expect(passkeyRepository.listCredentials()).toHaveLength(1);

    // Start passkey login assertion
    const loginStart = await app.request(
      "https://idp.example.test/login/acme/passkey/start",
      {
        body: new URLSearchParams({ login_challenge: loginChallengeToken }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    expect(loginStart.status).toBe(200);
    const { assertion_session_id: assertionSessionId } = await loginStart.json() as {
      challenge: string;
      assertion_session_id: string;
    };

    // Complete passkey login
    const loginFinish = await app.request(
      "https://idp.example.test/login/acme/passkey/finish",
      {
        body: JSON.stringify({
          assertion_session_id: assertionSessionId,
          credential_id: credentialId,
          sign_count: 1
        }),
        headers: { "content-type": "application/json" },
        method: "POST"
      }
    );

    expect(loginFinish.status).toBe(302);
    const location = new URL(loginFinish.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe("https://app.acme.test/callback");
    expect(location.searchParams.get("code")).toEqual(expect.any(String));
    expect(loginFinish.headers.get("set-cookie")).toMatch(/^user_session=/);
    expect(sessionRepository.listSessions()).toHaveLength(1);
    expect(authorizationCodeRepository.listAuthorizationCodes()).toHaveLength(1);

    const eventTypes = auditRepository.listEvents().map((e) => e.eventType);
    expect(eventTypes).toContain("user.passkey.enrollment.succeeded");
    expect(eventTypes).toContain("user.passkey.login.succeeded");
  });

  it("passkey login with unknown credential is rejected", async () => {
    const loginChallengeToken = "challenge-passkey-unknown-cred";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge(loginChallengeToken)
    ]);
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      auditRepository,
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
      passkeyRepository: new MemoryPasskeyRepository(),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(7),
      userRepository: new MemoryUserRepository({
        policies: [
          {
            tenantId: "tenant_acme",
            password: { enabled: true },
            emailMagicLink: { enabled: true },
            passkey: { enabled: true }
          }
        ],
        users: [buildActiveUser()]
      })
    });

    // Start passkey login assertion (no credentials enrolled)
    const loginStart = await app.request(
      "https://idp.example.test/login/acme/passkey/start",
      {
        body: new URLSearchParams({ login_challenge: loginChallengeToken }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    expect(loginStart.status).toBe(200);
    const { assertion_session_id: assertionSessionId } = await loginStart.json() as {
      assertion_session_id: string;
      challenge: string;
    };

    const loginFinish = await app.request(
      "https://idp.example.test/login/acme/passkey/finish",
      {
        body: JSON.stringify({
          assertion_session_id: assertionSessionId,
          credential_id: "unknown-credential",
          sign_count: 1
        }),
        headers: { "content-type": "application/json" },
        method: "POST"
      }
    );

    expect(loginFinish.status).toBe(401);
    expect(await loginFinish.json()).toEqual({ error: "invalid_credentials" });
    expect(auditRepository.listEvents().map((e) => e.eventType)).toContain(
      "user.passkey.login.failed"
    );
  });

  it("tenant passkey policy disables enrollment and login when configured off", async () => {
    const loginChallengeToken = "challenge-passkey-policy-off";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge(loginChallengeToken)
    ]);
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
      passkeyRepository: new MemoryPasskeyRepository(),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(7),
      userRepository: new MemoryUserRepository({
        policies: [
          {
            tenantId: "tenant_acme",
            password: { enabled: true },
            emailMagicLink: { enabled: true },
            passkey: { enabled: false }
          }
        ],
        users: [buildActiveUser()]
      })
    });

    const enrollResponse = await app.request(
      "https://idp.example.test/passkey/acme/enroll/start",
      {
        body: JSON.stringify({ user_id: "user_123" }),
        headers: { "content-type": "application/json" },
        method: "POST"
      }
    );
    expect(enrollResponse.status).toBe(403);
    expect(await enrollResponse.json()).toEqual({ error: "passkey_disabled" });

    const loginResponse = await app.request(
      "https://idp.example.test/login/acme/passkey/start",
      {
        body: new URLSearchParams({ login_challenge: loginChallengeToken }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    expect(loginResponse.status).toBe(403);
    expect(await loginResponse.json()).toEqual({ error: "passkey_disabled" });
  });
});
