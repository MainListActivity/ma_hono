import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { AuthenticationLoginChallengeRepository } from "../../src/domain/authentication/login-challenge-repository";
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
  createdAt: new Date().toISOString()
});

const makeApp = (
  challengeRepo: TestLoginChallengeRepository,
  userRepo: MemoryUserRepository
) =>
  createApp({
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    auditRepository: new MemoryAuditRepository(),
    tenantRepository,
    userRepository: userRepo,
    loginChallengeLookupRepository: challengeRepo,
    loginChallengeRepository: challengeRepo
  });

describe("GET /login/:tenant/challenge-info", () => {
  it("returns 400 when login_challenge is missing", async () => {
    const app = makeApp(
      new TestLoginChallengeRepository(),
      new MemoryUserRepository({ policies: [] })
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
      new MemoryUserRepository({ policies: [] })
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
      new MemoryUserRepository({ policies: [] })
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
    const userRepo = new MemoryUserRepository({
      policies: [
        {
          tenantId: "tenant_acme",
          password: { enabled: true },
          emailMagicLink: { enabled: true },
          passkey: { enabled: true }
        }
      ]
    });
    const app = makeApp(challengeRepo, userRepo);
    const res = await app.request(
      `https://auth.example.test/login/acme/challenge-info?login_challenge=${token}`
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      tenant_display_name: string;
      methods: string[];
    };
    expect(body.tenant_display_name).toBe("Acme Corp");
    expect(body.methods).toContain("password");
    expect(body.methods).toContain("magic_link");
    expect(body.methods).toContain("passkey");
  });

  it("returns only enabled methods when some are disabled", async () => {
    const token = "challenge-password-only";
    const challengeRepo = new TestLoginChallengeRepository([
      await buildChallenge(token)
    ]);
    const userRepo = new MemoryUserRepository({
      policies: [
        {
          tenantId: "tenant_acme",
          password: { enabled: true },
          emailMagicLink: { enabled: false },
          passkey: { enabled: false }
        }
      ]
    });
    const app = makeApp(challengeRepo, userRepo);
    const res = await app.request(
      `https://auth.example.test/login/acme/challenge-info?login_challenge=${token}`
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { methods: string[] };
    expect(body.methods).toEqual(["password"]);
  });

  it("returns all methods when no policy exists for the tenant", async () => {
    const token = "challenge-no-policy";
    const challengeRepo = new TestLoginChallengeRepository([
      await buildChallenge(token)
    ]);
    const userRepo = new MemoryUserRepository({ policies: [] });
    const app = makeApp(challengeRepo, userRepo);
    const res = await app.request(
      `https://auth.example.test/login/acme/challenge-info?login_challenge=${token}`
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { methods: string[] };
    expect(body.methods).toContain("password");
    expect(body.methods).toContain("magic_link");
    expect(body.methods).toContain("passkey");
  });
});
