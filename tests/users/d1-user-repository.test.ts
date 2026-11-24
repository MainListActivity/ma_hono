import { readFile, readdir } from "node:fs/promises";
import { drizzle } from "drizzle-orm/d1";
import { describe, expect, it, vi } from "vitest";
import { getPlatformProxy, unstable_splitSqlQuery } from "wrangler";

import { D1UserRepository } from "../../src/adapters/db/drizzle/runtime";
import { provisionUser } from "../../src/domain/users/provision-user";
import { sha256Base64Url } from "../../src/lib/hash";

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

it("persists early cancellation, cascades pending invitations, and preserves active users in D1", async () => {
  const platform = await getPlatformProxy<{ DB: D1Database }>({ persist: false });
  try {
    const db = platform.env.DB;
    const migrations = "drizzle/migrations";
    for (const file of (await readdir(migrations)).filter((name) => name.endsWith(".sql")).sort()) {
      const sql = await readFile(`${migrations}/${file}`, "utf8");
      await db.batch(unstable_splitSqlQuery(sql).map((statement) => db.prepare(statement)));
    }
    const tenantId = "tenant_acme";
    await db.prepare("INSERT INTO tenants VALUES (?, 'acme', 'Acme', 'active', 'date', 'date')").bind(tenantId).run();
    const repo = new D1UserRepository(drizzle(db));
    const provision = (email: string, cancellationTokenHash: string) => provisionUser({
      tenantId, email, displayName: "Fixture", cancellationTokenHash, userRepository: repo
    });
    const makeProof = () => sha256Base64Url(crypto.randomUUID());

    const earlyProof = await makeProof();
    expect(await repo.cancelProvisionedUser(tenantId, earlyProof)).toBe("absent");
    await expect(provision("late@example.test", earlyProof)).rejects.toThrow();
    expect(await db.prepare("SELECT COUNT(*) AS n FROM users").first("n")).toBe(0);

    const pendingProof = await makeProof();
    const { user } = await provision("pending@example.test", pendingProof);
    expect(await repo.cancelProvisionedUser(tenantId, pendingProof)).toEqual({ userId: user.id });
    expect(await db.prepare("SELECT COUNT(*) AS n FROM user_invitations WHERE user_id = ?").bind(user.id).first("n")).toBe(0);
    expect(await repo.cancelProvisionedUser(tenantId, pendingProof)).toBe("absent");
    await expect(provision("replayed@example.test", pendingProof)).rejects.toThrow();

    const activeProof = await makeProof();
    const active = await provision("active@example.test", activeProof);
    expect(await repo.activateUserByInvitationToken({
      tokenHash: active.invitation.tokenHash,
      now: new Date(),
      createPasswordHash: async () => "fixture_password_hash"
    })).toMatchObject({ kind: "activated" });
    expect(await repo.cancelProvisionedUser(tenantId, activeProof)).toBe("not_provisioned");
    expect(await db.prepare("SELECT status FROM users WHERE id = ?").bind(active.user.id).first("status")).toBe("active");
  } finally {
    await platform.dispose();
  }
}, 30_000);
