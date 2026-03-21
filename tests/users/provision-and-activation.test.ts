import { describe, expect, it, vi } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryUserSessionRepository } from "../../src/adapters/db/memory/memory-user-session-repository";
import { createApp } from "../../src/app/app";
import { activateUser } from "../../src/domain/users/activate-user";
import { hashPassword, verifyPassword } from "../../src/domain/users/passwords";
import * as passwords from "../../src/domain/users/passwords";
import { provisionUser } from "../../src/domain/users/provision-user";
import type { PasswordCredential, TenantAuthMethodPolicy } from "../../src/domain/users/types";
import {
  authenticateBrowserSession,
  createBrowserSession
} from "../../src/domain/authentication/session-service";
import { sha256Base64Url } from "../../src/lib/hash";

interface AdminLoginResponse {
  session_token: string;
}

class EventFailingAuditRepository extends MemoryAuditRepository {
  constructor(private readonly failOnEventType: string) {
    super();
  }

  override async record(event: Parameters<MemoryAuditRepository["record"]>[0]): Promise<void> {
    if (event.eventType === this.failOnEventType) {
      throw new Error(`simulated audit failure for ${event.eventType}`);
    }

    await super.record(event);
  }
}

const tenantPolicy: TenantAuthMethodPolicy = {
  tenantId: "tenant_acme",
  password: {
    enabled: true
  },
  emailMagicLink: {
    enabled: true
  },
  passkey: {
    enabled: false
  }
};

const createTenantRepositoryWithAcmeTenant = () =>
  new MemoryTenantRepository([
    {
      id: "tenant_acme",
      slug: "acme",
      displayName: "Acme",
      status: "active",
      issuers: [
        {
          id: "issuer_acme",
          issuerType: "platform_path",
          issuerUrl: "https://idp.example.test/t/acme",
          domain: null,
          isPrimary: true,
          verificationStatus: "verified"
        }
      ]
    }
  ]);

describe("user provisioning and activation domain", () => {
  it("provisions a tenant user, issues an activation invitation, and exposes tenant auth policy reads", async () => {
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const now = new Date("2026-03-21T09:00:00.000Z");

    const result = await provisionUser({
      userRepository: repository,
      tenantId: "tenant_acme",
      email: "new.user@acme.test",
      username: "newuser",
      displayName: "New User",
      now
    });

    expect(result.user).toMatchObject({
      tenantId: "tenant_acme",
      email: "new.user@acme.test",
      username: "newuser",
      displayName: "New User",
      emailVerified: false,
      status: "provisioned"
    });
    expect(result.invitation).toMatchObject({
      tenantId: "tenant_acme",
      userId: result.user.id,
      purpose: "account_activation",
      consumedAt: null,
      createdAt: now.toISOString()
    });
    expect(result.invitation.tokenHash).toBe(await sha256Base64Url(result.invitationToken));
    expect(repository.listUsers()).toHaveLength(1);
    expect(repository.listInvitations()).toHaveLength(1);
    expect(await repository.findAuthMethodPolicyByTenantId("tenant_acme")).toEqual(tenantPolicy);
  });

  it("consumes an activation invitation once, activates the user, and stores a verifiable password hash", async () => {
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const provisionedAt = new Date("2026-03-21T10:00:00.000Z");
    const activationTime = new Date("2026-03-21T10:05:00.000Z");
    const provisioned = await provisionUser({
      userRepository: repository,
      tenantId: "tenant_acme",
      email: "activate.me@acme.test",
      username: "activateme",
      displayName: "Activate Me",
      now: provisionedAt
    });
    const activateUserByInvitationTokenSpy = vi.spyOn(repository, "activateUserByInvitationToken");

    const activated = await activateUser({
      userRepository: repository,
      invitationToken: provisioned.invitationToken,
      password: "CorrectHorseBatteryStaple!42",
      now: activationTime
    });

    expect(activated.ok).toBe(true);
    if (!activated.ok) {
      throw new Error(`unexpected activation failure: ${activated.reason}`);
    }

    expect(activated.user).toMatchObject({
      id: provisioned.user.id,
      status: "active",
      emailVerified: true
    });
    expect(activateUserByInvitationTokenSpy).toHaveBeenCalledTimes(1);
    expect(activateUserByInvitationTokenSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        tokenHash: await sha256Base64Url(provisioned.invitationToken),
        now: activationTime,
        createPasswordHash: expect.any(Function)
      })
    );

    const credential = await repository.findPasswordCredentialByUserId(
      provisioned.user.tenantId,
      provisioned.user.id
    );
    expect(credential).not.toBeNull();
    expect(credential?.passwordHash).not.toBe("CorrectHorseBatteryStaple!42");
    expect(
      await verifyPassword({
        password: "CorrectHorseBatteryStaple!42",
        passwordHash: credential?.passwordHash ?? ""
      })
    ).toBe(true);
    expect(
      await verifyPassword({
        password: "not-the-password",
        passwordHash: credential?.passwordHash ?? ""
      })
    ).toBe(false);

    const storedInvitation = repository.listInvitations()[0];
    expect(storedInvitation?.consumedAt).toBe(activationTime.toISOString());

    const secondAttempt = await activateUser({
      userRepository: repository,
      invitationToken: provisioned.invitationToken,
      password: "AnotherPassword!42",
      now: new Date("2026-03-21T10:06:00.000Z")
    });

    expect(secondAttempt).toEqual({
      ok: false,
      reason: "invitation_already_used"
    });
  });

  it("rejects expired activation invitations", async () => {
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const provisioned = await provisionUser({
      userRepository: repository,
      tenantId: "tenant_acme",
      email: "expired@acme.test",
      username: "expireduser",
      displayName: "Expired User",
      invitationTtlMs: 60_000,
      now: new Date("2026-03-21T11:00:00.000Z")
    });

    const result = await activateUser({
      userRepository: repository,
      invitationToken: provisioned.invitationToken,
      password: "CorrectHorseBatteryStaple!42",
      now: new Date("2026-03-21T11:02:00.000Z")
    });

    expect(result).toEqual({
      ok: false,
      reason: "invitation_expired"
    });
    expect(
      await repository.findPasswordCredentialByUserId(provisioned.user.tenantId, provisioned.user.id)
    ).toBeNull();
    expect((await repository.findUserById(provisioned.user.tenantId, provisioned.user.id))?.status).toBe(
      "provisioned"
    );
  });

  it("rejects activation for disabled users without burning the invitation", async () => {
    const provisionedAt = new Date("2026-03-21T11:15:00.000Z");
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const provisioned = await provisionUser({
      userRepository: repository,
      tenantId: "tenant_acme",
      email: "disabled@acme.test",
      username: "disableduser",
      displayName: "Disabled User",
      now: provisionedAt
    });

    await repository.updateUser({
      ...provisioned.user,
      status: "disabled",
      updatedAt: new Date("2026-03-21T11:16:00.000Z").toISOString()
    });

    await expect(
      activateUser({
        userRepository: repository,
        invitationToken: provisioned.invitationToken,
        password: "CorrectHorseBatteryStaple!42",
        now: new Date("2026-03-21T11:17:00.000Z")
      })
    ).resolves.toEqual({
      ok: false,
      reason: "user_disabled"
    });

    expect(repository.listInvitations()[0]?.consumedAt).toBeNull();
    expect(
      await repository.findPasswordCredentialByUserId(provisioned.user.tenantId, provisioned.user.id)
    ).toBeNull();
  });

  it("does not invoke password hashing work for a rejected activation path", async () => {
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const provisioned = await provisionUser({
      userRepository: repository,
      tenantId: "tenant_acme",
      email: "lazy-hash@acme.test",
      username: "lazyhashuser",
      displayName: "Lazy Hash User",
      now: new Date("2026-03-21T11:18:00.000Z")
    });
    const hashPasswordSpy = vi
      .spyOn(passwords, "hashPassword")
      .mockRejectedValue(new Error("hash should not run"));

    try {
      await repository.updateUser({
        ...provisioned.user,
        status: "disabled",
        updatedAt: new Date("2026-03-21T11:18:30.000Z").toISOString()
      });

      await expect(
        activateUser({
          userRepository: repository,
          invitationToken: provisioned.invitationToken,
          password: "CorrectHorseBatteryStaple!42",
          now: new Date("2026-03-21T11:19:00.000Z")
        })
      ).resolves.toEqual({
        ok: false,
        reason: "user_disabled"
      });

      expect(hashPasswordSpy).not.toHaveBeenCalled();
    } finally {
      hashPasswordSpy.mockRestore();
    }
  });

  it("rejects activation for already-initialized users without overwriting the password or burning the invitation", async () => {
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const provisioned = await provisionUser({
      userRepository: repository,
      tenantId: "tenant_acme",
      email: "initialized@acme.test",
      username: "initializeduser",
      displayName: "Initialized User",
      now: new Date("2026-03-21T11:20:00.000Z")
    });
    const originalCredential: PasswordCredential = {
      id: "pwd_123",
      tenantId: provisioned.user.tenantId,
      userId: provisioned.user.id,
      passwordHash: await hashPassword("OriginalPassword!42"),
      createdAt: new Date("2026-03-21T11:21:00.000Z").toISOString(),
      updatedAt: new Date("2026-03-21T11:21:00.000Z").toISOString()
    };

    await repository.upsertPasswordCredential(originalCredential);

    await expect(
      activateUser({
        userRepository: repository,
        invitationToken: provisioned.invitationToken,
        password: "ReplacementPassword!42",
        now: new Date("2026-03-21T11:22:00.000Z")
      })
    ).resolves.toEqual({
      ok: false,
      reason: "user_already_initialized"
    });

    expect(repository.listInvitations()[0]?.consumedAt).toBeNull();
    expect(await repository.findPasswordCredentialByUserId(provisioned.user.tenantId, provisioned.user.id)).toEqual(
      originalCredential
    );
  });

  it("does not burn the invitation when activation commit fails", async () => {
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy],
      failActivationCommit: true
    });
    const provisioned = await provisionUser({
      userRepository: repository,
      tenantId: "tenant_acme",
      email: "activation-failure@acme.test",
      username: "activationfailure",
      displayName: "Activation Failure",
      now: new Date("2026-03-21T11:25:00.000Z")
    });

    await expect(
      activateUser({
        userRepository: repository,
        invitationToken: provisioned.invitationToken,
        password: "CorrectHorseBatteryStaple!42",
        now: new Date("2026-03-21T11:26:00.000Z")
      })
    ).rejects.toThrow("simulated activation commit failure");

    expect(repository.listInvitations()[0]?.consumedAt).toBeNull();
    expect((await repository.findUserById(provisioned.user.tenantId, provisioned.user.id))?.status).toBe(
      "provisioned"
    );
    expect(
      await repository.findPasswordCredentialByUserId(provisioned.user.tenantId, provisioned.user.id)
    ).toBeNull();
  });

  it("does not strand a provisioned user when invitation creation fails", async () => {
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy],
      failProvisionCommit: true
    });

    await expect(
      provisionUser({
        userRepository: repository,
        tenantId: "tenant_acme",
        email: "provision-failure@acme.test",
        username: "provisionfailure",
        displayName: "Provision Failure",
        now: new Date("2026-03-21T11:27:00.000Z")
      })
    ).rejects.toThrow("simulated provision commit failure");

    expect(repository.listUsers()).toEqual([]);
    expect(repository.listInvitations()).toEqual([]);
  });

  it("models activation as a one-time atomic repository operation", async () => {
    const repository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const provisioned = await provisionUser({
      userRepository: repository,
      tenantId: "tenant_acme",
      email: "atomic@acme.test",
      username: "atomicuser",
      displayName: "Atomic User",
      now: new Date("2026-03-21T11:30:00.000Z")
    });
    const tokenHash = await sha256Base64Url(provisioned.invitationToken);
    const passwordHash = await hashPassword("CorrectHorseBatteryStaple!42");

    await expect(
      repository.activateUserByInvitationToken({
        tokenHash,
        createPasswordHash: vi.fn(async () => passwordHash),
        now: new Date("2026-03-21T11:31:00.000Z")
      })
    ).resolves.toMatchObject({
      kind: "activated",
      user: {
        id: provisioned.user.id,
        status: "active"
      }
    });

    await expect(
      repository.activateUserByInvitationToken({
        tokenHash,
        createPasswordHash: vi.fn(async () => passwordHash),
        now: new Date("2026-03-21T11:32:00.000Z")
      })
    ).resolves.toEqual({
      kind: "already_used"
    });
  });

  it("creates opaque browser sessions and resolves active sessions by token", async () => {
    const repository = new MemoryUserSessionRepository();
    const now = new Date("2026-03-21T12:00:00.000Z");

    const created = await createBrowserSession({
      sessionRepository: repository,
      tenantId: "tenant_acme",
      userId: "user_123",
      now,
      lifetimeMs: 5 * 60 * 1000
    });

    expect(created.sessionToken).toBeTypeOf("string");
    expect(created.session.tokenHash).toBe(await sha256Base64Url(created.sessionToken));
    expect(repository.listSessions()).toHaveLength(1);

    expect(
      await authenticateBrowserSession({
        sessionRepository: repository,
        sessionToken: created.sessionToken,
        now: new Date("2026-03-21T12:03:00.000Z")
      })
    ).toMatchObject({
      id: created.session.id,
      tenantId: "tenant_acme",
      userId: "user_123"
    });

    expect(
      await authenticateBrowserSession({
        sessionRepository: repository,
        sessionToken: created.sessionToken,
        now: new Date("2026-03-21T12:06:00.000Z")
      })
    ).toBeNull();
  });
});

describe("user provisioning and activation routes", () => {
  it("allows an authenticated admin to provision a tenant user and returns invitation token + activation url", async () => {
    const userRepository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const app = createApp({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
      }),
      platformHost: "idp.example.test",
      tenantRepository: createTenantRepositoryWithAcmeTenant(),
      userRepository
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "bootstrap-secret"
      })
    });
    const loginBody = (await loginResponse.json()) as AdminLoginResponse;

    const response = await app.request("https://idp.example.test/admin/tenants/tenant_acme/users", {
      method: "POST",
      headers: {
        authorization: `Bearer ${loginBody.session_token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "invitee@acme.test",
        username: "invitee",
        display_name: "Invited User"
      })
    });

    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      activation_url: string;
      invitation_token: string;
      user: { email: string; status: string; tenant_id: string };
    };

    expect(body.user).toMatchObject({
      tenant_id: "tenant_acme",
      email: "invitee@acme.test",
      status: "provisioned"
    });
    expect(body.invitation_token).toBeTypeOf("string");
    expect(body.activation_url).toContain("/activate-account");
    expect(body.activation_url).toContain(`token=${body.invitation_token}`);
    expect(userRepository.listUsers()).toHaveLength(1);
    expect(userRepository.listInvitations()).toHaveLength(1);
  });

  it("activates a provisioned account, consumes the invitation, and emits audit events", async () => {
    const userRepository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
      }),
      auditRepository,
      platformHost: "idp.example.test",
      tenantRepository: createTenantRepositoryWithAcmeTenant(),
      userRepository
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "bootstrap-secret"
      })
    });
    const loginBody = (await loginResponse.json()) as AdminLoginResponse;

    const provisionResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_acme/users",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${loginBody.session_token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          email: "activate-route@acme.test",
          username: "activateroute",
          display_name: "Activate Route"
        })
      }
    );

    const provisionBody = (await provisionResponse.json()) as { invitation_token: string };

    const activationResponse = await app.request("https://idp.example.test/activate-account", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        invitation_token: provisionBody.invitation_token,
        password: "CorrectHorseBatteryStaple!42"
      })
    });

    expect(activationResponse.status).toBe(200);
    await expect(activationResponse.json()).resolves.toMatchObject({
      user: {
        email_verified: true,
        status: "active"
      }
    });

    const invitations = userRepository.listInvitations();
    expect(invitations).toHaveLength(1);
    expect(invitations[0]?.consumedAt).not.toBeNull();
    expect(auditRepository.listEvents().map((event) => event.eventType)).toEqual([
      "admin.login.succeeded",
      "user.provisioned",
      "user.activation.succeeded"
    ]);
  });

  it("accepts invitation token from the published activation url query format", async () => {
    const userRepository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const app = createApp({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
      }),
      platformHost: "idp.example.test",
      tenantRepository: createTenantRepositoryWithAcmeTenant(),
      userRepository
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "bootstrap-secret"
      })
    });
    const loginBody = (await loginResponse.json()) as AdminLoginResponse;

    const provisionResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_acme/users",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${loginBody.session_token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          email: "activate-url@acme.test",
          username: "activateurl",
          display_name: "Activate Url"
        })
      }
    );
    const provisionBody = (await provisionResponse.json()) as { activation_url: string };

    const activationUrl = new URL(provisionBody.activation_url);
    const activationResponse = await app.request(activationUrl.toString(), {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        password: "CorrectHorseBatteryStaple!42"
      })
    });

    expect(activationResponse.status).toBe(200);
    await expect(activationResponse.json()).resolves.toMatchObject({
      user: {
        status: "active",
        email_verified: true
      }
    });
  });

  it("keeps provisioning response successful when success-audit persistence fails", async () => {
    const userRepository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const app = createApp({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
      }),
      auditRepository: new EventFailingAuditRepository("user.provisioned"),
      platformHost: "idp.example.test",
      tenantRepository: createTenantRepositoryWithAcmeTenant(),
      userRepository
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "bootstrap-secret"
      })
    });
    const loginBody = (await loginResponse.json()) as AdminLoginResponse;

    const response = await app.request("https://idp.example.test/admin/tenants/tenant_acme/users", {
      method: "POST",
      headers: {
        authorization: `Bearer ${loginBody.session_token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "audit-provision@acme.test",
        username: "auditprovision",
        display_name: "Audit Provision"
      })
    });

    expect(response.status).toBe(201);
    expect(userRepository.listUsers()).toHaveLength(1);
  });

  it("keeps activation response successful when success-audit persistence fails", async () => {
    const userRepository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const app = createApp({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
      }),
      auditRepository: new EventFailingAuditRepository("user.activation.succeeded"),
      platformHost: "idp.example.test",
      tenantRepository: createTenantRepositoryWithAcmeTenant(),
      userRepository
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "bootstrap-secret"
      })
    });
    const loginBody = (await loginResponse.json()) as AdminLoginResponse;

    const provisionResponse = await app.request(
      "https://idp.example.test/admin/tenants/tenant_acme/users",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${loginBody.session_token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          email: "audit-activation@acme.test",
          username: "auditactivation",
          display_name: "Audit Activation"
        })
      }
    );
    const provisionBody = (await provisionResponse.json()) as { invitation_token: string };

    const activationResponse = await app.request("https://idp.example.test/activate-account", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        invitation_token: provisionBody.invitation_token,
        password: "CorrectHorseBatteryStaple!42"
      })
    });

    expect(activationResponse.status).toBe(200);
    expect(userRepository.listInvitations()[0]?.consumedAt).not.toBeNull();
  });

  it("returns 404 when provisioning targets a nonexistent tenant id", async () => {
    const userRepository = new MemoryUserRepository({
      policies: [tenantPolicy]
    });
    const app = createApp({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test"],
      adminRepository: new MemoryAdminRepository({
        adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
      }),
      platformHost: "idp.example.test",
      tenantRepository: new MemoryTenantRepository(),
      userRepository
    });

    const loginResponse = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "bootstrap-secret"
      })
    });
    const loginBody = (await loginResponse.json()) as AdminLoginResponse;

    const response = await app.request("https://idp.example.test/admin/tenants/tenant_missing/users", {
      method: "POST",
      headers: {
        authorization: `Bearer ${loginBody.session_token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: "missing-tenant@acme.test",
        username: "missingtenant",
        display_name: "Missing Tenant"
      })
    });

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      error: "tenant_not_found"
    });
    expect(userRepository.listUsers()).toHaveLength(0);
  });

  it("preserves failed activation response when failed-activation audit persistence throws", async () => {
    const app = createApp({
      auditRepository: new EventFailingAuditRepository("user.activation.failed"),
      userRepository: new MemoryUserRepository({
        policies: [tenantPolicy]
      })
    });

    const response = await app.request("https://idp.example.test/activate-account", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        invitation_token: "invalid-token",
        password: "CorrectHorseBatteryStaple!42"
      })
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "invalid_invitation"
    });
  });
});
