import { describe, expect, it } from "vitest";

import { D1RefreshTokenRepository } from "../../src/adapters/db/drizzle/runtime";
import type { RefreshTokenRecord } from "../../src/domain/tokens/refresh-token-repository";

const captureInsert = (row: Record<string, unknown>) => ({
  db: {
    insert() {
      return {
        async values(values: unknown) {
          Object.assign(row, values as Record<string, unknown>);
        }
      };
    }
  }
});

const baseRecord: RefreshTokenRecord = {
  id: "rt_1",
  tenantId: "tenant_1",
  issuer: "https://idp.example.test/t/acme",
  clientId: "client_1",
  userId: "user_1",
  scope: "openid",
  resource: "https://auth.example.test",
  authMethod: "password",
  tokenHash: "hash",
  absoluteExpiresAt: "2027-01-01T00:00:00Z",
  consumedAt: null,
  parentTokenId: null,
  remoteGrantId: "rg_123",
  replacedByTokenId: null,
  createdAt: "2026-01-01T00:00:00Z"
};

describe("D1RefreshTokenRepository.create", () => {
  it("persists remoteGrantId on insert", async () => {
    const row: Record<string, unknown> = {};
    const repo = new D1RefreshTokenRepository(captureInsert(row).db as never);
    await repo.create(baseRecord);
    expect(row.remoteGrantId).toBe("rg_123");
  });

  it("writes null remoteGrantId for non-remote tokens", async () => {
    const row: Record<string, unknown> = {};
    const repo = new D1RefreshTokenRepository(captureInsert(row).db as never);
    await repo.create({ ...baseRecord, remoteGrantId: null });
    expect(row.remoteGrantId).toBeNull();
  });
});
