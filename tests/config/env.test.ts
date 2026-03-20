import { describe, expect, it } from "vitest";
import { getTableName } from "drizzle-orm";

import { readRuntimeConfig } from "../../src/config/env";
import {
  adminSessions,
  adminUsers,
  auditEvents,
  oidcClients,
  signingKeys,
  tenantIssuers,
  tenants
} from "../../src/adapters/db/drizzle/schema";

describe("readRuntimeConfig", () => {
  it("reads the required runtime configuration", () => {
    const config = readRuntimeConfig({
      ADMIN_BOOTSTRAP_PASSWORD: "bootstrap-secret",
      ADMIN_WHITELIST: "admin@example.test,ops@example.test",
      MANAGEMENT_API_TOKEN: "manage-acme",
      PLATFORM_HOST: "idp.example.test"
    });

    expect(config).toEqual({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test", "ops@example.test"],
      managementApiToken: "manage-acme",
      platformHost: "idp.example.test"
    });
  });

  it("throws when required configuration is missing", () => {
    expect(() =>
      readRuntimeConfig({
        ADMIN_BOOTSTRAP_PASSWORD: "bootstrap-secret",
        ADMIN_WHITELIST: "admin@example.test",
        MANAGEMENT_API_TOKEN: "manage-acme"
      })
    ).toThrowError(/PLATFORM_HOST/);
  });
});

describe("drizzle schema", () => {
  it("exports the core oidc foundation tables", () => {
    expect(getTableName(tenants)).toBe("tenants");
    expect(getTableName(tenantIssuers)).toBe("tenant_issuers");
    expect(getTableName(oidcClients)).toBe("oidc_clients");
    expect(getTableName(signingKeys)).toBe("signing_keys");
    expect(getTableName(adminUsers)).toBe("admin_users");
    expect(getTableName(adminSessions)).toBe("admin_sessions");
    expect(getTableName(auditEvents)).toBe("audit_events");
  });
});
