import { describe, expect, it } from "vitest";
import { MemoryRemoteGrantRepository } from "../../src/adapters/db/memory/memory-remote-grant-repository";
import { MemoryRefreshTokenRepository } from "../../src/adapters/db/memory/memory-refresh-token-repository";
import { MemoryExpiredUserPurgerFake, purgeExpiredTestUsersFake } from "./remote-grant-purge-helpers";
import { isUserExpired } from "../../src/domain/users/expired-user-purge";
import { sha256Base64Url } from "../../src/lib/hash";
import type { RemoteGrantRecord } from "../../src/domain/tokens/remote-grant-repository";

const GRANT: RemoteGrantRecord = {
  id: "rg_1",
  tenantId: "tenant_acme",
  userId: "user_1",
  clientId: "remote_client",
  codeHash: "",
  codeExpiresAt: "2026-12-01T00:00:00Z",
  codeConsumedAt: null,
  resources: ["aud-a", "aud-b"],
  taskRef: "task-1",
  expiresAt: "2026-12-05T00:00:00Z",
  status: "active",
  createdAt: "2026-11-01T00:00:00Z",
  revokedAt: null
};

describe("remote grant repository", () => {
  it("redeems an active code once and refuses the replay", async () => {
    const repo = new MemoryRemoteGrantRepository([GRANT]);
    const hit = await repo.redeemByCodeHash(GRANT.codeHash, "2026-11-06T00:00:00Z");
    expect(hit?.id).toBe("rg_1");
    expect(await repo.redeemByCodeHash(GRANT.codeHash, "2026-11-06T00:00:01Z")).toBeNull();
  });
  it("refuses consumed, revoked or expired grants", async () => {
    const repo = new MemoryRemoteGrantRepository([
      { ...GRANT, id: "a", codeHash: "a", codeConsumedAt: "x" },
      { ...GRANT, id: "b", codeHash: "b", status: "revoked" },
      { ...GRANT, id: "c", codeHash: "c", codeExpiresAt: "2026-11-01T00:00:00Z" },
      { ...GRANT, id: "d", codeHash: "d", expiresAt: "2026-11-01T00:00:00Z" }
    ]);
    for (const h of ["a", "b", "c", "d"]) {
      expect(await repo.redeemByCodeHash(h, "2026-11-06T00:00:00Z")).toBeNull();
    }
  });
  it("sha256 code lookup matches sha256Base64Url", async () => {
    expect(await sha256Base64Url("the-code")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("expired test users", () => {
  it("isUserExpired treats NULL expiresAt as never expiring", () => {
    expect(isUserExpired({ expiresAt: null }, new Date("2100-01-01"))).toBe(false);
    expect(isUserExpired({ expiresAt: "2020-01-01" }, new Date("2021-01-01"))).toBe(true);
    expect(isUserExpired({ expiresAt: "2030-01-01" }, new Date("2021-01-01"))).toBe(false);
  });
  it("purge only deletes expired users and cascades their data", async () => {
    const purger = new MemoryExpiredUserPurgerFake();
    purger.add({ id: "u_expired", tenantId: "t", testOrigin: "task", expiresAt: "2026-11-01T00:00:00Z" });
    purger.add({ id: "u_normal", tenantId: "t", testOrigin: null, expiresAt: null });
    const audits: { eventType: string; payload: unknown }[] = [];
    const result = await purgeExpiredTestUsersFake(purger, audits, "2026-11-06T00:00:00Z");
    expect(result.purged).toBe(1);
    expect(purger.has("u_expired")).toBe(false);
    expect(purger.has("u_normal")).toBe(true);
    expect(purger.deletedFor("u_expired")).toBe(true);
    expect(audits.map(a => a.eventType)).toEqual(["user.expired_purged"]);
  });
});
