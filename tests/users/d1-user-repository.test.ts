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

const makeSelectChain = (result: unknown[]) => ({
  from: vi.fn(() => ({
    where: vi.fn(() => ({
      limit: vi.fn(() => result)
    }))
  }))
});

const makeUpdateChain = () => ({
  set: vi.fn(() => ({
    where: vi.fn(() => undefined)
  }))
});

describe("D1UserRepository activation conflict translation", () => {
  it("returns already_used instead of throwing a raw storage error on conflicting second activation", async () => {
    const insertError = new Error("UNIQUE constraint failed: user_password_credentials.user_id");

    // batch call 1: fetch user + credential (returns user row, no credential)
    const batchReadChain1 = [[userRow], []];
    // batch call 2: write batch — throws insertError
    // batch call 3: re-check reads — invitation is now consumed
    const batchReadChain2 = [
      [{ ...invitationRow, consumedAt: "2026-03-21T10:01:00.000Z" }],
      [{ ...userRow, status: "active" }],
      []
    ];

    let batchCallCount = 0;

    const db = {
      select: vi.fn(() => makeSelectChain([invitationRow])),
      update: vi.fn(() => makeUpdateChain()),
      insert: vi.fn(() => ({
        values: vi.fn(() => ({ _tag: "insert" }))
      })),
      batch: vi.fn(async (stmts: unknown[]) => {
        batchCallCount++;
        if (batchCallCount === 1) {
          // read batch: user + credential
          return batchReadChain1;
        }
        if (batchCallCount === 2) {
          // write batch — simulate constraint error
          void stmts;
          throw insertError;
        }
        // re-check batch
        return batchReadChain2;
      })
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
