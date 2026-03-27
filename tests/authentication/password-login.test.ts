import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryUserSessionRepository } from "../../src/adapters/db/memory/memory-user-session-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { createApp } from "../../src/app/app";
import type { AuthenticationLoginChallengeRepository } from "../../src/domain/authentication/login-challenge-repository";
import type { LoginChallengeRepository } from "../../src/domain/authorization/repository";
import type { LoginChallenge } from "../../src/domain/authorization/types";
import type { Client } from "../../src/domain/clients/types";
import { hashPassword } from "../../src/domain/users/passwords";
import { sha256Base64Url } from "../../src/lib/hash";

class TestLoginChallengeRepository
  implements LoginChallengeRepository, AuthenticationLoginChallengeRepository
{
  private readonly challenges: LoginChallenge[];
  private readonly staleReads: boolean;

  constructor(
    initialChallenges: LoginChallenge[] = [],
    options: {
      staleReads?: boolean;
    } = {}
  ) {
    this.challenges = [...initialChallenges];
    this.staleReads = options.staleReads ?? false;
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
        (challenge) =>
          challenge.tokenHash === tokenHash &&
          (this.staleReads || challenge.consumedAt === null)
      ) ?? null
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
    consentPolicy: "skip",
    clientProfile: "web",
    accessTokenAudience: null
  },
  {
    id: "client_record_acme_consent_required",
    tenantId: "tenant_acme",
    clientId: "client_acme_consent_required",
    clientName: "Acme Consent Required",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.acme.test/consent"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: "hashed-secret",
    trustLevel: "first_party_trusted",
    consentPolicy: "require",
    clientProfile: "web",
    accessTokenAudience: null
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

describe("password login", () => {
  it("valid username/password login consumes the login challenge and redirects back with code", async () => {
    const loginChallengeToken = "challenge-valid-password";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: loginChallengeToken })
    ]);
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const sessionRepository = new MemoryUserSessionRepository();
    const auditRepository = new MemoryAuditRepository();
    const userRepository = new MemoryUserRepository({
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
          email: "user@acme.test",
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
          id: "credential_123",
          tenantId: "tenant_acme",
          userId: "user_123",
          passwordHash: await hashPassword("correct-horse-battery-staple"),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
      ]
    });
    const app = createApp({
      auditRepository,
      authorizationCodeRepository,
      browserSessionRepository: sessionRepository,
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
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

    const response = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken,
        username: "alice",
        password: "correct-horse-battery-staple"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");

    expect(location.origin + location.pathname).toBe("https://app.acme.test/callback");
    expect(location.searchParams.get("state")).toBe("opaque-state");
    expect(location.searchParams.get("code")).toEqual(expect.any(String));
    expect(response.headers.get("set-cookie")).toMatch(/^user_session=/);
    expect(
      loginChallengeRepository.listChallenges().find((challenge) => challenge.id === `challenge_${loginChallengeToken}`)
        ?.consumedAt
    ).not.toBeNull();
    expect(sessionRepository.listSessions()).toHaveLength(1);
    expect(authorizationCodeRepository.listAuthorizationCodes()).toHaveLength(1);
    expect(authorizationCodeRepository.listAuthorizationCodes()[0]).toMatchObject({
      tenantId: "tenant_acme",
      clientId: "client_acme_first_party",
      userId: "user_123",
      redirectUri: "https://app.acme.test/callback",
      codeChallenge: "pkce-challenge",
      codeChallengeMethod: "S256"
    });
    expect(auditRepository.listEvents().map((event) => event.eventType)).toContain(
      "user.password_login.succeeded"
    );
  });

  it("invalid password returns a login failure without leaking tenant state", async () => {
    const loginChallengeToken = "challenge-invalid-password";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: loginChallengeToken })
    ]);
    const auditRepository = new MemoryAuditRepository();
    const userRepository = new MemoryUserRepository({
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
          email: "user@acme.test",
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
          id: "credential_123",
          tenantId: "tenant_acme",
          userId: "user_123",
          passwordHash: await hashPassword("correct-password"),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
      ]
    });
    const app = createApp({
      auditRepository,
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
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

    const response = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken,
        username: "alice",
        password: "wrong-password"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      error: "invalid_credentials"
    });
    expect(auditRepository.listEvents().map((event) => event.eventType)).toContain(
      "user.password_login.failed"
    );
  });

  it("consent-required client does not receive a code after password login resume", async () => {
    const loginChallengeToken = "challenge-consent-required";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      {
        ...(await buildChallenge({ token: loginChallengeToken })),
        clientId: "client_acme_consent_required",
        redirectUri: "https://app.acme.test/consent"
      }
    ]);
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const sessionRepository = new MemoryUserSessionRepository();
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository,
      browserSessionRepository: sessionRepository,
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
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
        users: [
          {
            id: "user_123",
            tenantId: "tenant_acme",
            email: "user@acme.test",
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
            id: "credential_123",
            tenantId: "tenant_acme",
            userId: "user_123",
            passwordHash: await hashPassword("correct-password"),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      })
    });

    const response = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken,
        username: "alice",
        password: "correct-password"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");

    expect(location.origin + location.pathname).toBe("https://app.acme.test/consent");
    expect(location.searchParams.get("error")).toBe("consent_required");
    expect(location.searchParams.get("code")).toBeNull();
    expect(authorizationCodeRepository.listAuthorizationCodes()).toHaveLength(0);
    expect(sessionRepository.listSessions()).toHaveLength(1);
  });

  it("rejects second submit when challenge consume claim is lost", async () => {
    const loginChallengeToken = "challenge-racy-double-submit";
    const loginChallengeRepository = new TestLoginChallengeRepository(
      [await buildChallenge({ token: loginChallengeToken })],
      {
        staleReads: true
      }
    );
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const sessionRepository = new MemoryUserSessionRepository();
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository,
      browserSessionRepository: sessionRepository,
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
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
        users: [
          {
            id: "user_123",
            tenantId: "tenant_acme",
            email: "user@acme.test",
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
            id: "credential_123",
            tenantId: "tenant_acme",
            userId: "user_123",
            passwordHash: await hashPassword("correct-password"),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      })
    });

    const firstResponse = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken,
        username: "alice",
        password: "correct-password"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });
    expect(firstResponse.status).toBe(302);

    const secondResponse = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken,
        username: "alice",
        password: "correct-password"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });

    expect(secondResponse.status).toBe(400);
    expect(await secondResponse.json()).toEqual({
      error: "invalid_request"
    });
    expect(authorizationCodeRepository.listAuthorizationCodes()).toHaveLength(1);
    expect(sessionRepository.listSessions()).toHaveLength(1);
  });

  it("rejects mixed-issuer challenge redemption", async () => {
    const loginChallengeToken = "challenge-wrong-issuer";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      {
        ...(await buildChallenge({ token: loginChallengeToken })),
        issuer: "https://login.acme.test"
      }
    ]);
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
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
        users: [
          {
            id: "user_123",
            tenantId: "tenant_acme",
            email: "user@acme.test",
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
            id: "credential_123",
            tenantId: "tenant_acme",
            userId: "user_123",
            passwordHash: await hashPassword("correct-password"),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      })
    });

    const response = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken,
        username: "alice",
        password: "correct-password"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "invalid_request"
    });
  });

  it("disabled tenant or disabled user is rejected", async () => {
    const disabledUserChallengeToken = "challenge-disabled-user";
    const disabledUserChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: disabledUserChallengeToken })
    ]);
    const appWithDisabledUser = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: disabledUserChallengeRepository,
      loginChallengeRepository: disabledUserChallengeRepository,
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
        users: [
          {
            id: "user_disabled",
            tenantId: "tenant_acme",
            email: "disabled@acme.test",
            emailVerified: true,
            username: "disabled-user",
            displayName: "Disabled User",
            status: "disabled",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ],
        passwordCredentials: [
          {
            id: "credential_disabled",
            tenantId: "tenant_acme",
            userId: "user_disabled",
            passwordHash: await hashPassword("password"),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      })
    });

    const disabledUserResponse = await appWithDisabledUser.request(
      "https://idp.example.test/login/acme/password",
      {
        body: new URLSearchParams({
          login_challenge: disabledUserChallengeToken,
          username: "disabled-user",
          password: "password"
        }),
        headers: {
          "content-type": "application/x-www-form-urlencoded"
        },
        method: "POST"
      }
    );

    expect(disabledUserResponse.status).toBe(401);
    expect(await disabledUserResponse.json()).toEqual({
      error: "invalid_credentials"
    });

    const appWithDisabledTenant = createApp({
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: new TestLoginChallengeRepository(),
      loginChallengeRepository: new TestLoginChallengeRepository(),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(7),
      userRepository: new MemoryUserRepository()
    });

    const disabledTenantResponse = await appWithDisabledTenant.request(
      "https://idp.example.test/t/disabled/login/password",
      {
        body: new URLSearchParams({
          login_challenge: "challenge-disabled-tenant",
          username: "alice",
          password: "password"
        }),
        headers: {
          "content-type": "application/x-www-form-urlencoded"
        },
        method: "POST"
      }
    );

    expect(disabledTenantResponse.status).toBe(404);
  });

  it("tenant password policy disables the flow when configured off", async () => {
    const loginChallengeToken = "challenge-policy-disabled";
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
            password: { enabled: false },
            emailMagicLink: { enabled: true },
            passkey: { enabled: true }
          }
        ]
      })
    });

    const response = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: loginChallengeToken,
        username: "alice",
        password: "password"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: "password_login_disabled"
    });
  });

  it("login success and failure emit audit events", async () => {
    const successChallengeToken = "challenge-audit-success";
    const failureChallengeToken = "challenge-audit-failure";
    const loginChallengeRepository = new TestLoginChallengeRepository([
      await buildChallenge({ token: successChallengeToken }),
      await buildChallenge({ token: failureChallengeToken })
    ]);
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      auditRepository,
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      browserSessionRepository: new MemoryUserSessionRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeLookupRepository: loginChallengeRepository,
      loginChallengeRepository,
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
        users: [
          {
            id: "user_123",
            tenantId: "tenant_acme",
            email: "user@acme.test",
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
            id: "credential_123",
            tenantId: "tenant_acme",
            userId: "user_123",
            passwordHash: await hashPassword("correct-password"),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      })
    });

    const successResponse = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: successChallengeToken,
        username: "alice",
        password: "correct-password"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });
    expect(successResponse.status).toBe(302);

    const failureResponse = await app.request("https://idp.example.test/login/acme/password", {
      body: new URLSearchParams({
        login_challenge: failureChallengeToken,
        username: "alice",
        password: "wrong-password"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      method: "POST"
    });
    expect(failureResponse.status).toBe(401);

    const eventTypes = auditRepository.listEvents().map((event) => event.eventType);

    expect(eventTypes).toContain("user.password_login.succeeded");
    expect(eventTypes).toContain("user.password_login.failed");
  });
});
