import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { AuthenticationLoginChallengeRepository } from "../../src/domain/authentication/login-challenge-repository";
import type { ClientAuthMethodPolicy } from "../../src/domain/clients/types";
import type { LoginChallengeRepository } from "../../src/domain/authorization/repository";
import type { LoginChallenge } from "../../src/domain/authorization/types";
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
    displayName: "Acme Corp",
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

const buildChallenge = async (token: string, tenantId = "tenant_acme"): Promise<LoginChallenge> => ({
  id: `challenge_${token}`,
  tenantId,
  issuer: "https://idp.example.test/t/acme",
  clientId: "client_acme",
  redirectUri: "https://app.acme.test/callback",
  scope: "openid",
  state: "state",
  codeChallenge: "pkce",
  codeChallengeMethod: "S256",
  nonce: null,
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

// The challenge uses clientId: "client_acme" (OAuth string).
// The client record maps that to UUID "client_acme_id" for policy lookups.
const clientRepository = new MemoryClientRepository([
  {
    id: "client_acme_id",
    tenantId: "tenant_acme",
    clientId: "client_acme",
    clientName: "Acme App",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.acme.test/callback"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: null,
    trustLevel: "first_party_trusted",
    consentPolicy: "skip"
  }
]);

const makeApp = (
  challengeRepo: TestLoginChallengeRepository,
  policyRepo: MemoryClientAuthMethodPolicyRepository
) =>
  createApp({
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    auditRepository: new MemoryAuditRepository(),
    tenantRepository,
    userRepository: new MemoryUserRepository({ policies: [] }),
    clientRepository,
    clientAuthMethodPolicyRepository: policyRepo,
    loginChallengeLookupRepository: challengeRepo,
    loginChallengeRepository: challengeRepo
  });

const makePolicy = (
  overrides: Partial<Pick<ClientAuthMethodPolicy, "password" | "emailMagicLink" | "passkey">> = {}
): ClientAuthMethodPolicy => ({
  clientId: "client_acme_id",
  tenantId: "tenant_acme",
  password: { enabled: false, allowRegistration: false },
  emailMagicLink: { enabled: false, allowRegistration: false },
  passkey: { enabled: false, allowRegistration: false },
  google: { enabled: false },
  apple: { enabled: false },
  facebook: { enabled: false },
  wechat: { enabled: false },
  mfaRequired: false,
  ...overrides
});

describe("GET /login/:tenant/challenge-info", () => {
  it("returns 400 when login_challenge is missing", async () => {
    const app = makeApp(
      new TestLoginChallengeRepository(),
      new MemoryClientAuthMethodPolicyRepository()
    );
    const res = await app.request(
      "https://auth.example.test/login/acme/challenge-info"
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: "missing_login_challenge" });
  });

  it("returns 400 when login_challenge token is not found", async () => {
    const app = makeApp(
      new TestLoginChallengeRepository(),
      new MemoryClientAuthMethodPolicyRepository()
    );
    const res = await app.request(
      "https://auth.example.test/login/acme/challenge-info?login_challenge=nonexistent"
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: "invalid_login_challenge" });
  });

  it("returns 404 when tenant slug is unknown", async () => {
    const token = "challenge-unknown-tenant";
    const challengeRepo = new TestLoginChallengeRepository([
      await buildChallenge(token)
    ]);
    const app = makeApp(
      challengeRepo,
      new MemoryClientAuthMethodPolicyRepository()
    );
    const res = await app.request(
      `https://auth.example.test/login/unknown-tenant/challenge-info?login_challenge=${token}`
    );
    expect(res.status).toBe(404);
  });

  it("returns tenant display name and all enabled methods", async () => {
    const token = "challenge-all-methods";
    const challengeRepo = new TestLoginChallengeRepository([
      await buildChallenge(token)
    ]);
    const policyRepo = new MemoryClientAuthMethodPolicyRepository();
    await policyRepo.create(makePolicy({
      password: { enabled: true, allowRegistration: false },
      emailMagicLink: { enabled: true, allowRegistration: false },
      passkey: { enabled: true, allowRegistration: false }
    }));
    const app = makeApp(challengeRepo, policyRepo);
    const res = await app.request(
      `https://auth.example.test/login/acme/challenge-info?login_challenge=${token}`
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      tenant_display_name: string;
      methods: { method: string; allow_registration: boolean }[];
    };
    expect(body.tenant_display_name).toBe("Acme Corp");
    const methodNames = body.methods.map((m) => m.method);
    expect(methodNames).toContain("password");
    expect(methodNames).toContain("magic_link");
    expect(methodNames).toContain("passkey");
  });

  it("returns only password method when only password is enabled", async () => {
    const token = "challenge-password-only";
    const challengeRepo = new TestLoginChallengeRepository([
      await buildChallenge(token)
    ]);
    const policyRepo = new MemoryClientAuthMethodPolicyRepository();
    await policyRepo.create(makePolicy({
      password: { enabled: true, allowRegistration: false }
    }));
    const app = makeApp(challengeRepo, policyRepo);
    const res = await app.request(
      `https://auth.example.test/login/acme/challenge-info?login_challenge=${token}`
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { methods: { method: string; allow_registration: boolean }[] };
    expect(body.methods).toHaveLength(1);
    expect(body.methods[0].method).toBe("password");
  });

  it("returns empty methods when no policy exists for the client", async () => {
    const token = "challenge-no-policy";
    const challengeRepo = new TestLoginChallengeRepository([
      await buildChallenge(token)
    ]);
    const app = makeApp(
      challengeRepo,
      new MemoryClientAuthMethodPolicyRepository()
    );
    const res = await app.request(
      `https://auth.example.test/login/acme/challenge-info?login_challenge=${token}`
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { methods: unknown[] };
    // No policy row → fail-safe deny-all → empty methods array
    expect(body.methods).toEqual([]);
  });

  it("includes allow_registration flag in method objects", async () => {
    const token = "challenge-allow-reg";
    const challengeRepo = new TestLoginChallengeRepository([
      await buildChallenge(token)
    ]);
    const policyRepo = new MemoryClientAuthMethodPolicyRepository();
    await policyRepo.create(makePolicy({
      password: { enabled: true, allowRegistration: true }
    }));
    const app = makeApp(challengeRepo, policyRepo);
    const res = await app.request(
      `https://auth.example.test/login/acme/challenge-info?login_challenge=${token}`
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { methods: { method: string; allow_registration: boolean }[] };
    const passwordMethod = body.methods.find((m) => m.method === "password");
    expect(passwordMethod).toBeDefined();
    expect(passwordMethod?.allow_registration).toBe(true);
  });
});
