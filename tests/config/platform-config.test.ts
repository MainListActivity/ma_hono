import { describe, it, expect } from "vitest";
import {
  loadContentReaderIssuancePolicy,
  loadPlatformConfig
} from "../../src/config/platform-config";

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
      { key: "root_domain", value: "example.com" },
      { key: "admin_whitelist", value: "admin@example.com" }
    ]);
    expect(await loadPlatformConfig(db)).toBeNull();
  });

  it("returns config when all four keys exist", async () => {
    const db = makeDb([
      { key: "admin_bootstrap_password_hash", value: "100000:salt:hash" },
      { key: "admin_whitelist", value: "admin@example.com,ops@example.com" },
      { key: "management_api_token", value: "tok_abc123" },
      { key: "root_domain", value: "example.com" }
    ]);
    const config = await loadPlatformConfig(db);
    expect(config).not.toBeNull();
    expect(config!.rootDomain).toBe("example.com");
    expect(config!.managementApiToken).toBe("tok_abc123");
    expect(config!.adminBootstrapPasswordHash).toBe("100000:salt:hash");
    expect(config!.adminWhitelist).toEqual(["admin@example.com", "ops@example.com"]);
  });

  it("trims and filters empty entries in admin_whitelist", async () => {
    const db = makeDb([
      { key: "admin_bootstrap_password_hash", value: "100000:salt:hash" },
      { key: "admin_whitelist", value: " admin@example.com , , ops@example.com " },
      { key: "management_api_token", value: "tok" },
      { key: "root_domain", value: "example.com" }
    ]);
    const config = await loadPlatformConfig(db);
    expect(config!.adminWhitelist).toEqual(["admin@example.com", "ops@example.com"]);
  });
});

describe("loadContentReaderIssuancePolicy", () => {
  it("returns null when client allowlist is absent", async () => {
    const db = makeDb([{ key: "content_reader_allowed_databases", value: "platform_content" }]);
    expect(await loadContentReaderIssuancePolicy(db)).toBeNull();
  });

  it("loads allowlists and defaults the content database and max ttl", async () => {
    const db = makeDb([
      { key: "content_reader_allowed_client_ids", value: " surreal_ck_web , ops " },
      { key: "content_reader_allowed_tenant_ids", value: "tenant_acme" }
    ]);
    const policy = await loadContentReaderIssuancePolicy(db);
    expect(policy).toEqual({
      allowedClientIds: ["surreal_ck_web", "ops"],
      allowedTenantIds: ["tenant_acme"],
      allowedContentDatabases: ["platform_content"],
      maxTtlSeconds: 15 * 60
    });
  });

  it("returns null for invalid max ttl values", async () => {
    const db = makeDb([
      { key: "content_reader_allowed_client_ids", value: "surreal_ck_web" },
      { key: "content_reader_max_ttl_seconds", value: "0" }
    ]);
    expect(await loadContentReaderIssuancePolicy(db)).toBeNull();
  });
});
