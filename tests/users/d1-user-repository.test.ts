import { describe, expect, it, vi } from "vitest";

import { D1UserRepository } from "../../src/adapters/db/drizzle/runtime";

const invitationRow = {
  id: "inv_1",
  tenantId: "tenant_acme",
  userId: "user_1",
  tokenHash: "token_hash",
  purpose: "account_activation",
  expiresAt: "2030-01-01T00:00:00.000Z",
  consumedAt: null,
  createdAt: "2026-03-21T00:00:00.000Z"
};

const userRow = {
  id: "user_1",
  tenantId: "tenant_acme",
  email: "user@acme.test",
  emailVerified: false,
  username: "user1",
  displayName: "User One",
  status: "provisioned",
  createdAt: "2026-03-21T00:00:00.000Z",
  updatedAt: "2026-03-21T00:00:00.000Z"
};

const createMockTx = (selectResults: unknown[], insertError: Error) => {
  let selectIndex = 0;

  return {
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => ({
          limit: vi.fn(async () => (selectResults[selectIndex++] as unknown[] | undefined) ?? [])
        }))
      }))
    })),
    update: vi.fn(() => ({
      set: vi.fn(() => ({
        where: vi.fn(async () => undefined)
      }))
    })),
    insert: vi.fn(() => ({
      values: vi.fn(async () => {
        throw insertError;
      })
    }))
  };
};

describe("D1UserRepository activation conflict translation", () => {
  it("returns already_used instead of throwing a raw storage error on conflicting second activation", async () => {
    const tx = createMockTx(
      [
        [invitationRow],
        [userRow],
        [],
        [
          {
            ...invitationRow,
            consumedAt: "2026-03-21T10:01:00.000Z"
          }
        ]
      ],
      new Error("UNIQUE constraint failed: user_password_credentials.user_id")
    );
    const db = {
      transaction: async (callback: (transaction: typeof tx) => Promise<unknown>) => callback(tx)
    };
    const repository = new D1UserRepository(db as never);

    await expect(
      repository.activateUserByInvitationToken({
        tokenHash: "token_hash",
        now: new Date("2026-03-21T10:02:00.000Z"),
        createPasswordHash: async () => "password_hash"
      })
    ).resolves.toEqual({
      kind: "already_used"
    });
  });
});
