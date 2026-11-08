import { describe, expect, it } from "vitest";

import { authenticateWithPassword } from "../../src/adapters/auth/local-auth/password-auth-service";
import { requestMagicLink } from "../../src/adapters/auth/local-auth/magic-link-service";
import { startPasskeyEnrollment } from "../../src/adapters/auth/webauthn/webauthn-service";
import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryMagicLinkRepository } from "../../src/adapters/db/memory/memory-magic-link-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryPasskeyRepository } from "../../src/adapters/db/memory/memory-passkey-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { AuthenticationLoginChallengeRepository } from "../../src/domain/authentication/login-challenge-repository";
import type { LoginChallenge } from "../../src/domain/authorization/types";
import type { Tenant } from "../../src/domain/tenants/types";
import { activateUser } from "../../src/domain/users/activate-user";
import { changeUserStatus } from "../../src/domain/users/change-user-status";
import { hashPassword } from "../../src/domain/users/passwords";
import { provisionAgentUser, provisionUser } from "../../src/domain/users/provision-user";
import type { PasswordCredential, User } from "../../src/domain/users/types";
import { sha256Base64Url } from "../../src/lib/hash";

const tenantId = "tenant_ck";
const otherTenantId = "tenant_other";
const issuer = "https://idp.example.test/t/ck";
const timestamp = "2026-01-01T00:00:00.000Z";
const password = "CorrectHorseBatteryStaple!42";

const makeUser = (overrides: Pick<User, "email" | "id"> & Partial<User>): User => ({
  tenantId,
  emailVerified: true,
  username: null,
  displayName: overrides.id,
  status: "active",
  createdAt: timestamp,
  updatedAt: timestamp,
  ...overrides
});

const passwordCredentialFor = async (userId: string): Promise<PasswordCredential> => ({
  id: `cred_${userId}`,
  tenantId,
  userId,
  passwordHash: await hashPassword(password),
  createdAt: timestamp,
  updatedAt: timestamp
});

const buildChallenge = async (token: string): Promise<LoginChallenge> => ({
  id: `challenge_${token}`,
  tenantId,
  issuer,
  clientId: "client_ck_console",
  redirectUri: "https://ck.example.test/callback",
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
  createdAt: timestamp
});

/** 只需要 findByTokenHash 的挑战仓库：登录与 magic link 入口仅依赖它。 */
const challengeRepositoryFor = (challenge: LoginChallenge) =>
  ({
    async findByTokenHash(tokenHash: string) {
      return tokenHash === challenge.tokenHash ? challenge : null;
    },
    async consume() {
      return true;
    }
  }) as unknown as AuthenticationLoginChallengeRepository;

describe("changeUserStatus", () => {
  it("disables an active user and restores it to active when it holds a password", async () => {
    const userRepository = new MemoryUserRepository({
      users: [makeUser({ id: "user_active", email: "active@ck.test" })],
      passwordCredentials: [await passwordCredentialFor("user_active")]
    });

    await expect(
      changeUserStatus({ status: "disabled", tenantId, userId: "user_active", userRepository })
    ).resolves.toMatchObject({ ok: true, previousStatus: "active", user: { status: "disabled" } });

    await expect(
      changeUserStatus({ status: "active", tenantId, userId: "user_active", userRepository })
    ).resolves.toMatchObject({ ok: true, previousStatus: "disabled", user: { status: "active" } });
  });

  it("restores a disabled agent to active without a password", async () => {
    const userRepository = new MemoryUserRepository();
    const { user } = await provisionAgentUser({
      userRepository,
      tenantId,
      email: "runner@ck.test",
      displayName: "Runner"
    });

    await changeUserStatus({ status: "disabled", tenantId, userId: user.id, userRepository });

    await expect(
      changeUserStatus({ status: "active", tenantId, userId: user.id, userRepository })
    ).resolves.toMatchObject({ ok: true, user: { status: "active", kind: "agent" } });
  });

  it("keeps a never-activated user provisioned and refuses a direct jump to active", async () => {
    const userRepository = new MemoryUserRepository();
    const { invitationToken, user } = await provisionUser({
      userRepository,
      tenantId,
      email: "newcomer@ck.test",
      displayName: "Newcomer"
    });

    await expect(
      changeUserStatus({ status: "active", tenantId, userId: user.id, userRepository })
    ).resolves.toEqual({ ok: false, reason: "invalid_state" });

    await changeUserStatus({ status: "disabled", tenantId, userId: user.id, userRepository });

    await expect(
      changeUserStatus({ status: "active", tenantId, userId: user.id, userRepository })
    ).resolves.toMatchObject({ ok: true, previousStatus: "disabled", user: { status: "provisioned" } });

    // 恢复后仍须走原激活流程。
    await expect(
      activateUser({ userRepository, invitationToken, password })
    ).resolves.toMatchObject({ ok: true, user: { status: "active" } });
  });

  it("blocks activation while a provisioned user is disabled", async () => {
    const userRepository = new MemoryUserRepository();
    const { invitationToken, user } = await provisionUser({
      userRepository,
      tenantId,
      email: "paused@ck.test",
      displayName: "Paused"
    });

    await changeUserStatus({ status: "disabled", tenantId, userId: user.id, userRepository });

    await expect(
      activateUser({ userRepository, invitationToken, password })
    ).resolves.toEqual({ ok: false, reason: "user_disabled" });
  });

  it("reports missing users and treats a repeated status as a no-op", async () => {
    const userRepository = new MemoryUserRepository({
      users: [makeUser({ id: "user_repeat", email: "repeat@ck.test" })]
    });

    await expect(
      changeUserStatus({ status: "active", tenantId, userId: "user_missing", userRepository })
    ).resolves.toEqual({ ok: false, reason: "user_not_found" });

    await expect(
      changeUserStatus({ status: "active", tenantId, userId: "user_repeat", userRepository })
    ).resolves.toMatchObject({ ok: true, previousStatus: "active", user: { status: "active" } });
  });

  it("does not find a user that belongs to another tenant", async () => {
    const userRepository = new MemoryUserRepository({
      users: [makeUser({ id: "user_foreign", email: "foreign@other.test", tenantId: otherTenantId })]
    });

    await expect(
      changeUserStatus({ status: "disabled", tenantId, userId: "user_foreign", userRepository })
    ).resolves.toEqual({ ok: false, reason: "user_not_found" });
    expect(userRepository.listUsers()[0]?.status).toBe("active");
  });
});

describe("agent accounts never sign in as a person", () => {
  it("rejects password login for an agent even with a valid password, and still accepts a human", async () => {
    const agent = makeUser({ id: "agent_runner", email: "runner@ck.test", kind: "agent", username: "runner-login" });
    const human = makeUser({ id: "user_human", email: "human@ck.test", kind: "human", username: "human-login" });
    const userRepository = new MemoryUserRepository({
      users: [agent, human],
      passwordCredentials: [
        await passwordCredentialFor(agent.id),
        await passwordCredentialFor(human.id)
      ]
    });
    const token = "agent-password-challenge";

    const agentResult = await authenticateWithPassword({
      issuer,
      loginChallengeRepository: challengeRepositoryFor(await buildChallenge(token)),
      loginChallengeToken: token,
      password,
      tenantId,
      userRepository,
      username: "runner-login"
    });
    expect(agentResult).toEqual({ kind: "rejected", reason: "invalid_credentials" });

    const humanResult = await authenticateWithPassword({
      issuer,
      loginChallengeRepository: challengeRepositoryFor(await buildChallenge(token)),
      loginChallengeToken: token,
      password,
      tenantId,
      userRepository,
      username: "human-login"
    });
    expect(humanResult).toMatchObject({ kind: "authenticated", user: { id: "user_human" } });
  });

  it("does not issue a magic link to an agent email, while a human still gets one", async () => {
    const userRepository = new MemoryUserRepository({
      users: [
        makeUser({ id: "agent_mail", email: "mail-agent@ck.test", kind: "agent" }),
        makeUser({ id: "user_mail", email: "mail-human@ck.test", kind: "human" })
      ]
    });
    const token = "agent-magic-challenge";
    const challenge = await buildChallenge(token);

    const agentResult = await requestMagicLink({
      email: "mail-agent@ck.test",
      issuer,
      loginChallengeRepository: challengeRepositoryFor(challenge),
      loginChallengeToken: token,
      magicLinkRepository: new MemoryMagicLinkRepository(),
      tenantId,
      userRepository
    });
    expect(agentResult).toEqual({ kind: "rejected", reason: "user_not_found" });

    const humanResult = await requestMagicLink({
      email: "mail-human@ck.test",
      issuer,
      loginChallengeRepository: challengeRepositoryFor(challenge),
      loginChallengeToken: token,
      magicLinkRepository: new MemoryMagicLinkRepository(),
      tenantId,
      userRepository
    });
    expect(humanResult).toMatchObject({ kind: "issued", user: { id: "user_mail" } });
  });

  it("does not start passkey enrollment for an agent account", async () => {
    const userRepository = new MemoryUserRepository({
      users: [
        makeUser({ id: "agent_passkey", email: "passkey-agent@ck.test", kind: "agent" }),
        makeUser({ id: "user_passkey", email: "passkey-human@ck.test", kind: "human" })
      ]
    });

    await expect(
      startPasskeyEnrollment({
        passkeyRepository: new MemoryPasskeyRepository(),
        tenantId,
        userId: "agent_passkey",
        userRepository
      })
    ).resolves.toEqual({ kind: "rejected", reason: "user_not_found" });

    await expect(
      startPasskeyEnrollment({
        passkeyRepository: new MemoryPasskeyRepository(),
        tenantId,
        userId: "user_passkey",
        userRepository
      })
    ).resolves.toMatchObject({ kind: "challenge_issued" });
  });
});

const tenantFixture = (id: string, slug: string): Tenant => ({
  id,
  slug,
  displayName: slug.toUpperCase(),
  status: "active",
  issuers: [
    {
      id: `issuer_${slug}`,
      issuerType: "platform_path",
      issuerUrl: `https://idp.example.test/t/${slug}`,
      domain: null,
      isPrimary: true,
      verificationStatus: "verified"
    }
  ]
});

const createFixture = () => {
  const adminRepository = new MemoryAdminRepository({
    adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
  });
  const auditRepository = new MemoryAuditRepository();
  const tenantRepository = new MemoryTenantRepository([
    tenantFixture(tenantId, "ck"),
    tenantFixture(otherTenantId, "other")
  ]);
  const userRepository = new MemoryUserRepository();
  const app = createApp({
    adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
    adminWhitelist: ["admin@example.test"],
    adminRepository,
    auditRepository,
    managementApiToken: "mgmt-token-not-for-provision",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    tenantRepository,
    userRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });

  return { app, auditRepository, userRepository };
};

const loginAsAdmin = async (app: ReturnType<typeof createApp>) => {
  const response = await app.request("https://idp.example.test/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "admin@example.test", password: "bootstrap-secret" })
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { session_token: string }).session_token;
};

const mintPrincipal = async (
  app: ReturnType<typeof createApp>,
  sessionToken: string,
  scopes: string[]
) => {
  const response = await app.request("https://idp.example.test/admin/service-principals", {
    method: "POST",
    headers: {
      authorization: `Bearer ${sessionToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({ label: "users-test", scopes })
  });
  expect(response.status).toBe(201);
  return (await response.json()) as { id: string; token: string };
};

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const jsonBody = (token: string, body: unknown) => ({
  method: "POST",
  headers: { ...bearer(token), "content-type": "application/json" },
  body: JSON.stringify(body)
});

describe("admin user routes: kind and status", () => {
  it("opens an agent account through user.write with no invitation and audits its kind", async () => {
    const { app, auditRepository, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken, ["user.write"]);

    const response = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users`,
      jsonBody(minted.token, { email: "runner@ck.test", display_name: "Runner", kind: "agent" })
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      user: { id: string; kind: string; status: string };
      invitation_token: string | null;
      activation_url: string | null;
    };
    expect(body.user).toMatchObject({ kind: "agent", status: "active" });
    expect(body.invitation_token).toBeNull();
    expect(body.activation_url).toBeNull();
    expect(userRepository.listInvitations()).toEqual([]);

    expect(
      auditRepository.listEvents().find((event) => event.eventType === "user.provisioned")
    ).toMatchObject({
      actorType: "service_principal",
      actorId: minted.id,
      targetId: body.user.id,
      payload: { email: "runner@ck.test", kind: "agent" }
    });
  });

  it("defaults kind to human and keeps the invitation flow", async () => {
    const { app, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken, ["user.provision"]);

    const response = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users`,
      jsonBody(minted.token, { email: "lawyer@ck.test", display_name: "Lawyer" })
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      user: { kind: string; status: string };
      invitation_token: string;
      activation_url: string;
    };
    expect(body.user).toMatchObject({ kind: "human", status: "provisioned" });
    expect(body.invitation_token).toBeTypeOf("string");
    expect(body.activation_url).toContain("token=");
    expect(userRepository.listInvitations()).toHaveLength(1);
  });

  it("rejects an unknown kind without creating a user", async () => {
    const { app, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);

    const response = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users`,
      jsonBody(sessionToken, { email: "robot@ck.test", display_name: "Robot", kind: "robot" })
    );
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_request" });
    expect(userRepository.listUsers()).toHaveLength(0);
  });

  it("filters the user list by kind and reports kind on every row", async () => {
    const { app, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken, ["user.read"]);
    await provisionAgentUser({ userRepository, tenantId, email: "runner@ck.test", displayName: "Runner" });
    await provisionUser({ userRepository, tenantId, email: "human@ck.test", displayName: "Human" });

    const all = await app.request(`https://idp.example.test/admin/tenants/${tenantId}/users`, {
      headers: bearer(minted.token)
    });
    const allBody = (await all.json()) as { users: Array<{ email: string; kind: string }> };
    expect(allBody.users.map((user) => [user.email, user.kind]).sort()).toEqual([
      ["human@ck.test", "human"],
      ["runner@ck.test", "agent"]
    ]);

    const agents = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users?kind=agent`,
      { headers: bearer(minted.token) }
    );
    expect(agents.status).toBe(200);
    await expect(agents.json()).resolves.toMatchObject({
      users: [{ email: "runner@ck.test", kind: "agent", status: "active" }]
    });

    const invalid = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users?kind=robot`,
      { headers: bearer(minted.token) }
    );
    expect(invalid.status).toBe(400);
  });

  it("disables and re-enables a user through user.write and audits each real change", async () => {
    const { app, auditRepository, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken, ["user.write"]);
    const { user } = await provisionAgentUser({
      userRepository,
      tenantId,
      email: "runner@ck.test",
      displayName: "Runner"
    });
    const url = `https://idp.example.test/admin/tenants/${tenantId}/users/${user.id}`;
    const patch = (token: string, body: unknown) => ({
      method: "PATCH",
      headers: { ...bearer(token), "content-type": "application/json" },
      body: JSON.stringify(body)
    });

    const disabled = await app.request(url, patch(minted.token, { status: "disabled" }));
    expect(disabled.status).toBe(200);
    await expect(disabled.json()).resolves.toMatchObject({
      user: { id: user.id, status: "disabled", kind: "agent" }
    });

    const repeated = await app.request(url, patch(minted.token, { status: "disabled" }));
    expect(repeated.status).toBe(200);

    const enabled = await app.request(url, patch(minted.token, { status: "active" }));
    expect(enabled.status).toBe(200);
    await expect(enabled.json()).resolves.toMatchObject({ user: { status: "active" } });

    const changes = auditRepository
      .listEvents()
      .filter((event) => event.eventType === "user.status_changed");
    expect(changes).toHaveLength(2);
    expect(changes[0]).toMatchObject({
      actorType: "service_principal",
      actorId: minted.id,
      targetId: user.id,
      payload: { from: "active", to: "disabled" }
    });
    expect(changes[1]).toMatchObject({ payload: { from: "disabled", to: "active" } });
  });

  it("refuses bad PATCH bodies, kind changes, and jumps that skip activation", async () => {
    const { app, auditRepository, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const { user: agent } = await provisionAgentUser({
      userRepository,
      tenantId,
      email: "runner@ck.test",
      displayName: "Runner"
    });
    const { user: pending } = await provisionUser({
      userRepository,
      tenantId,
      email: "pending@ck.test",
      displayName: "Pending"
    });
    const patch = (body: unknown) => ({
      method: "PATCH",
      headers: { ...bearer(sessionToken), "content-type": "application/json" },
      body: JSON.stringify(body)
    });

    const badStatus = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/${agent.id}`,
      patch({ status: "provisioned" })
    );
    expect(badStatus.status).toBe(400);
    await expect(badStatus.json()).resolves.toEqual({ error: "invalid_request" });

    const kindChange = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/${agent.id}`,
      patch({ status: "active", kind: "human" })
    );
    expect(kindChange.status).toBe(400);
    await expect(kindChange.json()).resolves.toEqual({ error: "kind_immutable" });

    const skipActivation = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/${pending.id}`,
      patch({ status: "active" })
    );
    expect(skipActivation.status).toBe(409);
    await expect(skipActivation.json()).resolves.toEqual({ error: "invalid_state" });
    expect(
      auditRepository.listEvents().find((event) => event.eventType === "user.status_change.failed")
    ).toMatchObject({ payload: { reason: "invalid_state", requested_status: "active" } });

    const missing = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/user_missing`,
      patch({ status: "disabled" })
    );
    expect(missing.status).toBe(404);
    await expect(missing.json()).resolves.toEqual({ error: "user_not_found" });

    expect(userRepository.listUsers().find((user) => user.id === agent.id)?.status).toBe("active");
  });

  it("does not let a tenant path change a user that belongs to another tenant", async () => {
    const { app, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const { user: foreign } = await provisionAgentUser({
      userRepository,
      tenantId: otherTenantId,
      email: "foreign@other.test",
      displayName: "Foreign"
    });

    const response = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/${foreign.id}`,
      {
        method: "PATCH",
        headers: { ...bearer(sessionToken), "content-type": "application/json" },
        body: JSON.stringify({ status: "disabled" })
      }
    );
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({ error: "user_not_found" });
    expect(userRepository.listUsers().find((user) => user.id === foreign.id)?.status).toBe("active");
  });

  it("requires user.write for PATCH and returns 403 for principals that only hold user.provision", async () => {
    const { app, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const minted = await mintPrincipal(app, sessionToken, ["user.provision", "user.read"]);
    const { user } = await provisionAgentUser({
      userRepository,
      tenantId,
      email: "runner@ck.test",
      displayName: "Runner"
    });

    const response = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/${user.id}`,
      {
        method: "PATCH",
        headers: { ...bearer(minted.token), "content-type": "application/json" },
        body: JSON.stringify({ status: "disabled" })
      }
    );
    expect(response.status).toBe(403);
    expect(userRepository.listUsers().find((item) => item.id === user.id)?.status).toBe("active");
  });

  it("accepts user.write for reissue-activation and refuses an agent", async () => {
    const { app, userRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const writer = await mintPrincipal(app, sessionToken, ["user.write"]);
    const reader = await mintPrincipal(app, sessionToken, ["user.read"]);
    const { user: pending } = await provisionUser({
      userRepository,
      tenantId,
      email: "reissue@ck.test",
      displayName: "Reissue"
    });
    const { user: agent } = await provisionAgentUser({
      userRepository,
      tenantId,
      email: "runner@ck.test",
      displayName: "Runner"
    });

    const readerAttempt = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/${pending.id}/reissue-activation`,
      { method: "POST", headers: bearer(reader.token) }
    );
    expect(readerAttempt.status).toBe(403);

    const reissued = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/${pending.id}/reissue-activation`,
      { method: "POST", headers: bearer(writer.token) }
    );
    expect(reissued.status).toBe(200);
    await expect(reissued.json()).resolves.toMatchObject({
      user: { id: pending.id, kind: "human" }
    });

    const agentAttempt = await app.request(
      `https://idp.example.test/admin/tenants/${tenantId}/users/${agent.id}/reissue-activation`,
      { method: "POST", headers: bearer(writer.token) }
    );
    expect(agentAttempt.status).toBe(409);
    await expect(agentAttempt.json()).resolves.toEqual({ error: "invalid_state" });
  });
});
