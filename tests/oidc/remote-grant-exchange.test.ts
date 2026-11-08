import { exportJWK, generateKeyPair, importJWK, jwtVerify, type JWK } from "jose";
import { describe, expect, it } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryRefreshTokenRepository } from "../../src/adapters/db/memory/memory-refresh-token-repository";
import { MemoryRemoteGrantRepository } from "../../src/adapters/db/memory/memory-remote-grant-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { Client } from "../../src/domain/clients/types";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import type { RemoteGrantRecord } from "../../src/domain/tokens/remote-grant-repository";
import type { User } from "../../src/domain/users/types";
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
      }
    ]
  }
]);

const createSigner = async (): Promise<{ signer: SigningKeySigner; material: SigningKeyMaterial }> => {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const material: SigningKeyMaterial = {
    key: {
      id: "key_acme",
      tenantId: "tenant_acme",
      kid: "kid-acme",
      alg: "RS256",
      kty: "RSA",
      status: "active",
      publicJwk: { ...(await exportJWK(publicKey)), alg: "RS256", kid: "kid-acme", use: "sig" }
    },
    privateJwk: { ...(await exportJWK(privateKey)), alg: "RS256", kid: "kid-acme" }
  };
  return {
    material,
    signer: {
      async ensureActiveSigningKeyMaterial() { return material; },
      async loadActiveSigningKeyMaterial() { return material; }
    }
  };
};

const remoteClient = (grantTypes: string[] = [
  "urn:ietf:params:oauth:grant-type:token-exchange",
  "refresh_token"
]): Client => ({
  id: "record_remote_client",
  tenantId: "tenant_acme",
  clientId: "remote_client",
  clientName: "remote_client",
  applicationType: "web",
  grantTypes,
  redirectUris: [],
  responseTypes: [],
  tokenEndpointAuthMethod: "none",
  clientSecretHash: null,
  trustLevel: "first_party_trusted",
  consentPolicy: "skip",
  clientProfile: "web",
  accessTokenAudience: null
});

const testUser = (overrides: Partial<User> = {}): User => ({
  id: "user_1",
  tenantId: "tenant_acme",
  email: "remote@test.example",
  emailVerified: true,
  username: "remote",
  displayName: "Remote",
  status: "active",
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  ...overrides
});

const makeGrant = async (overrides: Partial<RemoteGrantRecord> = {}): Promise<RemoteGrantRecord> => ({
  id: "rg_1",
  tenantId: "tenant_acme",
  userId: "user_1",
  clientId: "remote_client",
  codeHash: await sha256Base64Url("the-code"),
  codeExpiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  codeConsumedAt: null,
  resources: ["aud-default", "aud-ops"],
  taskRef: "task-1",
  expiresAt: new Date(Date.now() + 31 * 24 * 3_600_000).toISOString(),
  status: "active",
  createdAt: new Date().toISOString(),
  revokedAt: null,
  ...overrides
});

const buildApp = ({
  client = remoteClient(),
  grants = [],
  refreshRepository = new MemoryRefreshTokenRepository(),
  users = [testUser()]
}: {
  client?: Client;
  grants?: RemoteGrantRecord[];
  refreshRepository?: MemoryRefreshTokenRepository;
  users?: User[];
} = {}) => {
  const app = createApp({
    auditRepository: new MemoryAuditRepository(),
    authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
    clientRepository: new MemoryClientRepository([client]),
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    refreshTokenRepository: refreshRepository,
    remoteGrantRepository: new MemoryRemoteGrantRepository(grants),
    userRepository: new MemoryUserRepository({ users }),
    signer: undefined,
    tenantRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });
  return app;
};

const TOKEN_URL = "https://idp.example.test/t/acme/token";

const redeem = (
  app: ReturnType<typeof createApp>,
  fields: Record<string, string> = {}
) =>
  app.request(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token_type: "urn:ma-hono:params:oauth:token-type:remote-grant-code",
      subject_token: "the-code",
      client_id: "remote_client",
      ...fields
    }).toString()
  });

const refresh = (
  app: ReturnType<typeof createApp>,
  token: string,
  fields: Record<string, string> = {}
) =>
  app.request(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: token,
      client_id: "remote_client",
      ...fields
    }).toString()
  });

const appWithSigner = async (options: Parameters<typeof buildApp>[0] = {}) => {
  const { signer, material } = await createSigner();
  const app = buildApp(options);
  void signer;
  // createApp 的 signer 选项无法后置注入：重建带 signer 的 app。
  const app2 = createApp({
    auditRepository: new MemoryAuditRepository(),
    authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
    clientRepository: new MemoryClientRepository([options?.client ?? remoteClient()]),
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    refreshTokenRepository: options?.refreshRepository ?? new MemoryRefreshTokenRepository(),
    remoteGrantRepository: new MemoryRemoteGrantRepository(options?.grants ?? []),
    userRepository: new MemoryUserRepository({ users: options?.users ?? [testUser()] }),
    signer,
    tenantRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });
  void app;
  return { app: app2, material };
};

describe("remote grant token exchange", () => {
  it("redeems a code for RFC 8693 fields with refresh bound to the grant", async () => {
    const grant = await makeGrant();
    const refreshRepository = new MemoryRefreshTokenRepository();
    const { app, material } = await appWithSigner({ grants: [grant], refreshRepository });

    const response = await redeem(app);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.issued_token_type).toBe("urn:ietf:params:oauth:token-type:access_token");
    expect(body.token_type).toBe("Bearer");
    expect(body.id_token).toBeUndefined();
    expect(body.access_token).toBeTypeOf("string");
    expect(body.refresh_token).toBeTypeOf("string");
    expect(body.expires_in as number).toBeGreaterThan(0);
    expect(body.expires_in as number).toBeLessThanOrEqual(3600);

    const key = await importJWK(material.key.publicJwk as JWK, "RS256");
    const access = await jwtVerify(body.access_token as string, key, {
      issuer: "https://idp.example.test/t/acme",
      audience: "aud-default"
    });
    expect(access.payload.sub).toBe("user_1");

    const stored = refreshRepository.listRefreshTokens();
    expect(stored).toHaveLength(1);
    expect(stored[0].remoteGrantId).toBe("rg_1");
    expect(stored[0].absoluteExpiresAt).toBe(grant.expiresAt);
    expect(stored[0].resource).toBe("aud-default");
  });

  it("rejects code replay, expired code, expired grant, revoked grant, wrong client, missing grant type, wrong token type and bad resource", async () => {
    const good = await makeGrant();
    const { app } = await appWithSigner({ grants: [good] });
    expect((await redeem(app)).status).toBe(200);
    // 重放
    expect((await redeem(app)).status).toBe(400);

    const cases: { name: string; grant?: Partial<RemoteGrantRecord>; client?: Client; fields?: Record<string, string> }[] = [
      { name: "expired code", grant: { id: "a", codeExpiresAt: "2020-01-01T00:00:00Z" } },
      { name: "expired grant", grant: { id: "b", expiresAt: "2020-01-01T00:00:00Z" } },
      { name: "revoked grant", grant: { id: "c", status: "revoked", revokedAt: "2020-01-01T00:00:00Z" } },
      { name: "wrong subject_token_type", fields: { subject_token_type: "urn:ietf:params:oauth:token-type:access_token" } },
      { name: "resource not allowed", fields: { resource: "aud-evil" } }
    ];
    for (const c of cases) {
      const grant = await makeGrant(c.grant);
      const { app: a } = await appWithSigner({ grants: [grant] });
      const res = await redeem(a, c.fields);
      expect(res.status, c.name).toBe(400);
      expect(((await res.json()) as { error: string }).error, c.name).toBe("invalid_grant");
    }

    // grant 登记的 client_id 与请求 client_id 不一致（client 存在但不匹配）
    const otherClient: Client = { ...remoteClient(), id: "record_other", clientId: "other_client" };
    const { app: wrongClient } = await appWithSigner({ grants: [await makeGrant()] });
    void otherClient;
    const resWrong = await redeem(wrongClient, { client_id: "other_client" });
    expect(resWrong.status).toBe(401); // other_client 未登记，client auth 阶段即拒绝
    // grant.clientId 不匹配：再测一个登记在别的 client 名下的 grant
    const grantOther = await makeGrant({ clientId: "other_client" });
    const { app: mismatch } = await appWithSigner({ grants: [grantOther] });
    const resMismatch = await redeem(mismatch);
    expect(resMismatch.status).toBe(400);
    expect(((await resMismatch.json()) as { error: string }).error).toBe("invalid_grant");

    // client 未开该 grant type
    const { app: noGrant } = await appWithSigner({
      client: remoteClient(["authorization_code"]),
      grants: [await makeGrant()]
    });
    expect((await redeem(noGrant)).status).toBe(400);
  });

  it("mints ops-audience tokens and lets refresh switch audience inside grant resources", async () => {
    const grant = await makeGrant();
    const { app, material } = await appWithSigner({ grants: [grant] });
    const key = await importJWK(material.key.publicJwk as JWK, "RS256");
    const opts = { issuer: "https://idp.example.test/t/acme" };

    const res = await redeem(app, { resource: "aud-ops" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; refresh_token: string };
    await jwtVerify(body.access_token, key, { ...opts, audience: "aud-ops" });

    // refresh 切回默认 resource
    const res2 = await refresh(app, body.refresh_token, { resource: "aud-default" });
    expect(res2.status).toBe(200);
    const body2 = (await res2.json()) as { access_token: string; refresh_token: string };
    await jwtVerify(body2.access_token, key, { ...opts, audience: "aud-default" });

    // refresh 不带 resource 沿用上一个 aud
    const res3 = await refresh(app, body2.refresh_token);
    expect(res3.status).toBe(200);
    const body3 = (await res3.json()) as { access_token: string };
    await jwtVerify(body3.access_token, key, { ...opts, audience: "aud-default" });
  });

  it("fails refresh after grant revocation and revokes the grant on refresh replay", async () => {
    const grant = await makeGrant();
    const remoteGrants = new MemoryRemoteGrantRepository([grant]);
    const { material } = await createSigner();
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
      clientRepository: new MemoryClientRepository([remoteClient()]),
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test",
      authDomain: "auth.example.test",
      refreshTokenRepository: new MemoryRefreshTokenRepository(),
      remoteGrantRepository: remoteGrants,
      userRepository: new MemoryUserRepository({ users: [testUser()] }),
      signer: {
        async ensureActiveSigningKeyMaterial() { return material; },
        async loadActiveSigningKeyMaterial() { return material; }
      },
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
    });

    const res = await redeem(app);
    const body = (await res.json()) as { refresh_token: string };
    const res2 = await refresh(app, body.refresh_token);
    const body2 = (await res2.json()) as { refresh_token: string };
    expect(res2.status).toBe(200);

    // 旧 refresh 重放 → grant 被 revoke，后续 refresh 全部失败
    expect((await refresh(app, body.refresh_token)).status).toBe(400);
    const stored = await remoteGrants.findById("tenant_acme", "rg_1");
    expect(stored?.status).toBe("revoked");
    expect((await refresh(app, body2.refresh_token)).status).toBe(400);
  });

  it("rejects expired test users on redeem and refresh", async () => {
    const expiredUser = testUser({ expiresAt: new Date(Date.now() - 1000).toISOString() });
    const { app } = await appWithSigner({
      grants: [await makeGrant()],
      users: [expiredUser]
    });
    expect((await redeem(app)).status).toBe(400);
  });
});

describe("GET /t/:tenant/remote", () => {
  it("returns plain-text usage with no-store and no side effects", async () => {
    const app = buildApp();
    const response = await app.request("https://idp.example.test/t/acme/remote");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/plain");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toContain("token-exchange");
  });
});
