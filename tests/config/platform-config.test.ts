import { describe, it, expect } from "vitest";
import { loadPlatformConfig } from "../../src/config/platform-config";

const makeDb = (rows: Array<{ key: string; value: string }>) => ({
  prepare: (sql: string) => ({
    bind: (..._args: unknown[]) => ({
      all: async () => ({ results: rows })
    }),
    all: async () => ({ results: rows })
  }),
  batch: async (stmts: unknown[]) => stmts.map(() => ({ results: [] }))
}) as unknown as D1Database;

describe("loadPlatformConfig", () => {
  it("returns null when no rows exist", async () => {
    const db = makeDb([]);
    expect(await loadPlatformConfig(db)).toBeNull();
  });

  it("returns null when only some keys exist", async () => {
    const db = makeDb([
      { key: "platform_host", value: "auth.example.com" },
      { key: "admin_whitelist", value: "admin@example.com" }
    ]);
    expect(await loadPlatformConfig(db)).toBeNull();
  });

  it("returns config when all four keys exist", async () => {
    const db = makeDb([
      { key: "admin_bootstrap_password_hash", value: "100000:salt:hash" },
      { key: "admin_whitelist", value: "admin@example.com,ops@example.com" },
      { key: "management_api_token", value: "tok_abc123" },
      { key: "platform_host", value: "auth.example.com" }
    ]);
    const config = await loadPlatformConfig(db);
    expect(config).not.toBeNull();
    expect(config!.platformHost).toBe("auth.example.com");
    expect(config!.managementApiToken).toBe("tok_abc123");
    expect(config!.adminBootstrapPasswordHash).toBe("100000:salt:hash");
    expect(config!.adminWhitelist).toEqual(["admin@example.com", "ops@example.com"]);
  });

  it("trims and filters empty entries in admin_whitelist", async () => {
    const db = makeDb([
      { key: "admin_bootstrap_password_hash", value: "100000:salt:hash" },
      { key: "admin_whitelist", value: " admin@example.com , , ops@example.com " },
      { key: "management_api_token", value: "tok" },
      { key: "platform_host", value: "host.example.com" }
    ]);
    const config = await loadPlatformConfig(db);
    expect(config!.adminWhitelist).toEqual(["admin@example.com", "ops@example.com"]);
  });
});
