import { describe, expect, it, vi } from "vitest";

import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { MemoryUserSessionRepository } from "../../src/adapters/db/memory/memory-user-session-repository";
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
