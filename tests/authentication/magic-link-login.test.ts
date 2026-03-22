import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryUserSessionRepository } from "../../src/adapters/db/memory/memory-user-session-repository";
import { MemoryMagicLinkRepository } from "../../src/adapters/db/memory/memory-magic-link-repository";
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
  },
  {
    id: "tenant_disabled",
    slug: "disabled",
    displayName: "Disabled",
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

const buildChallenge = async ({
  consumedAt = null,
  tenantId = "tenant_acme",
  token
}: {
  consumedAt?: string | null;
  tenantId?: string;
  token: string;
}): Promise<LoginChallenge> => ({
  id: `challenge_${token}`,
  tenantId,
  issuer: `https://idp.example.test/t/${tenantId === "tenant_acme" ? "acme" : "disabled"}`,
  clientId: "client_acme_first_party",
  redirectUri: "https://app.acme.test/callback",
  scope: "openid profile",
  state: "opaque-state",
  codeChallenge: "pkce-challenge",
  codeChallengeMethod: "S256",
  nonce: "nonce_123",
  tokenHash: await sha256Base64Url(token),
  expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  consumedAt,
  authenticatedUserId: null,
  mfaState: "none" as const,
  mfaAttemptCount: 0,
  enrollmentAttemptCount: 0,
  totpEnrollmentSecretEncrypted: null,
  createdAt: new Date().toISOString()
});

const buildUserRepository = () =>
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
        id: "user_123",
        tenantId: "tenant_acme",
        email: "alice@acme.test",
        emailVerified: true,
        username: "alice",
        displayName: "Alice",
        status: "active",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
    ]
  });

describe("magic link login", () => {
  it("existing tenant user can request a magic link", async () => {
    const loginChallengeToken = "challenge-magic-link-request";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: loginChallengeToken })
    ]);
    const magicLinkRepository = new MemoryMagicLinkRepository();
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      auditRepository,
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
      magicLinkRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      userRepository: buildUserRepository()
    });

    const response = await app.request("https://idp.example.test/login/acme/magic-link/request", {
      body: new URLSearchParams({
        email: "alice@acme.test",
        login_challenge: loginChallengeToken
      }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });

    expect(response.status).toBe(200);
    const body = await response.json() as { magic_link_token: string };
    expect(typeof body.magic_link_token).toBe("string");
    expect(body.magic_link_token.length).toBeGreaterThan(0);
    expect(magicLinkRepository.listTokens()).toHaveLength(1);
    expect(auditRepository.listEvents().map((e) => e.eventType)).toContain(
      "user.magic_link.requested"
    );
  });

  it("consuming the magic link creates a session and resumes authorization", async () => {
    const loginChallengeToken = "challenge-magic-link-consume";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: loginChallengeToken })
    ]);
    const magicLinkRepository = new MemoryMagicLinkRepository();
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
      magicLinkRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      userRepository: buildUserRepository()
    });

    // Request magic link
    const requestResponse = await app.request(
      "https://idp.example.test/login/acme/magic-link/request",
      {
        body: new URLSearchParams({
          email: "alice@acme.test",
          login_challenge: loginChallengeToken
        }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    expect(requestResponse.status).toBe(200);
    const { magic_link_token: magicLinkToken } = await requestResponse.json() as { magic_link_token: string };

    // Consume magic link
    const consumeResponse = await app.request(
      "https://idp.example.test/login/acme/magic-link/consume",
      {
        body: new URLSearchParams({ token: magicLinkToken }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );

    expect(consumeResponse.status).toBe(302);
    const location = new URL(consumeResponse.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe("https://app.acme.test/callback");
    expect(location.searchParams.get("state")).toBe("opaque-state");
    expect(location.searchParams.get("code")).toEqual(expect.any(String));
    expect(consumeResponse.headers.get("set-cookie")).toMatch(/^user_session=/);
    expect(sessionRepository.listSessions()).toHaveLength(1);
    expect(authorizationCodeRepository.listAuthorizationCodes()).toHaveLength(1);
    expect(auditRepository.listEvents().map((e) => e.eventType)).toContain(
      "user.magic_link.consumed"
    );
  });

  it("expired or previously consumed magic link is rejected", async () => {
    const loginChallengeToken = "challenge-magic-link-expired";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: loginChallengeToken })
    ]);
    const magicLinkRepository = new MemoryMagicLinkRepository();
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      auditRepository,
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
      magicLinkRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      userRepository: buildUserRepository()
    });

    // Request magic link
    const requestResponse = await app.request(
      "https://idp.example.test/login/acme/magic-link/request",
      {
        body: new URLSearchParams({
          email: "alice@acme.test",
          login_challenge: loginChallengeToken
        }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    const { magic_link_token: magicLinkToken } = await requestResponse.json() as { magic_link_token: string };

    // Expire the token manually
    const tokenRecord = magicLinkRepository.listTokens()[0];
    if (tokenRecord !== undefined) {
      tokenRecord.expiresAt = new Date(Date.now() - 1000).toISOString();
    }

    const consumeResponse = await app.request(
      "https://idp.example.test/login/acme/magic-link/consume",
      {
        body: new URLSearchParams({ token: magicLinkToken }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );

    expect(consumeResponse.status).toBe(400);
    expect(await consumeResponse.json()).toEqual({ error: "invalid_or_expired_token" });
  });

  it("consuming twice is rejected", async () => {
    const loginChallengeToken = "challenge-magic-link-double";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: loginChallengeToken })
    ]);
    const magicLinkRepository = new MemoryMagicLinkRepository();
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
      magicLinkRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      userRepository: buildUserRepository()
    });

    const requestResponse = await app.request(
      "https://idp.example.test/login/acme/magic-link/request",
      {
        body: new URLSearchParams({
          email: "alice@acme.test",
          login_challenge: loginChallengeToken
        }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    const { magic_link_token: magicLinkToken } = await requestResponse.json() as { magic_link_token: string };

    const firstConsume = await app.request(
      "https://idp.example.test/login/acme/magic-link/consume",
      {
        body: new URLSearchParams({ token: magicLinkToken }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    expect(firstConsume.status).toBe(302);

    const secondConsume = await app.request(
      "https://idp.example.test/login/acme/magic-link/consume",
      {
        body: new URLSearchParams({ token: magicLinkToken }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    expect(secondConsume.status).toBe(400);
    expect(await secondConsume.json()).toEqual({ error: "invalid_or_expired_token" });
  });

  it("tenant magic-link policy disables the flow when configured off", async () => {
    const loginChallengeToken = "challenge-magic-link-policy-off";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: loginChallengeToken })
    ]);
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
      magicLinkRepository: new MemoryMagicLinkRepository(),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      userRepository: new MemoryUserRepository({
        policies: [
          {
            tenantId: "tenant_acme",
            password: { enabled: true },
            emailMagicLink: { enabled: false },
            passkey: { enabled: true }
          }
        ],
        users: [
          {
            id: "user_123",
            tenantId: "tenant_acme",
            email: "alice@acme.test",
            emailVerified: true,
            username: "alice",
            displayName: "Alice",
            status: "active",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      })
    });

    const response = await app.request(
      "https://idp.example.test/login/acme/magic-link/request",
      {
        body: new URLSearchParams({
          email: "alice@acme.test",
          login_challenge: loginChallengeToken
        }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "magic_link_login_disabled" });
  });

  it("magic-link request and consume emit audit events", async () => {
    const loginChallengeToken = "challenge-magic-link-audit";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: loginChallengeToken })
    ]);
    const magicLinkRepository = new MemoryMagicLinkRepository();
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      auditRepository,
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
      magicLinkRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      userRepository: buildUserRepository()
    });

    const requestResponse = await app.request(
      "https://idp.example.test/login/acme/magic-link/request",
      {
        body: new URLSearchParams({
          email: "alice@acme.test",
          login_challenge: loginChallengeToken
        }),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST"
      }
    );
    expect(requestResponse.status).toBe(200);
    const { magic_link_token: magicLinkToken } = await requestResponse.json() as { magic_link_token: string };

    await app.request("https://idp.example.test/login/acme/magic-link/consume", {
      body: new URLSearchParams({ token: magicLinkToken }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST"
    });

    const eventTypes = auditRepository.listEvents().map((e) => e.eventType);
    expect(eventTypes).toContain("user.magic_link.requested");
    expect(eventTypes).toContain("user.magic_link.consumed");
  });
});
