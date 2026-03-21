import { describe, expect, it } from "vitest";
import { getTableName } from "drizzle-orm";

import { readRuntimeConfig } from "../../src/config/env";
import { createRuntimeRepositories } from "../../src/adapters/db/drizzle/runtime";
import {
  adminUsers,
  auditEvents,
  oidcClients,
  signingKeys,
  tenantIssuers,
  tenants
} from "../../src/adapters/db/drizzle/schema";

const fakeD1Database = {} as D1Database;
const fakeAdminSessionsKv = {} as KVNamespace;
const fakeRegistrationTokensKv = {} as KVNamespace;
const fakeKeyMaterialBucket = {} as R2Bucket;

describe("readRuntimeConfig", () => {
  it("reads the required runtime configuration", () => {
    const config = readRuntimeConfig({
      ADMIN_BOOTSTRAP_PASSWORD: "bootstrap-secret",
      ADMIN_WHITELIST: "admin@example.test,ops@example.test",
      DB: fakeD1Database,
      ADMIN_SESSIONS_KV: fakeAdminSessionsKv,
      REGISTRATION_TOKENS_KV: fakeRegistrationTokensKv,
      KEY_MATERIAL_R2: fakeKeyMaterialBucket,
      MANAGEMENT_API_TOKEN: "manage-acme",
      PLATFORM_HOST: "idp.example.test"
    });

    expect(config).toEqual({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test", "ops@example.test"],
      adminSessionsKv: fakeAdminSessionsKv,
      db: fakeD1Database,
      keyMaterialBucket: fakeKeyMaterialBucket,
      managementApiToken: "manage-acme",
      platformHost: "idp.example.test",
      registrationTokensKv: fakeRegistrationTokensKv
    });
  });

  it("throws when required configuration is missing", () => {
    expect(() =>
      readRuntimeConfig({
        ADMIN_BOOTSTRAP_PASSWORD: "bootstrap-secret",
        ADMIN_WHITELIST: "admin@example.test",
        DB: fakeD1Database,
        ADMIN_SESSIONS_KV: fakeAdminSessionsKv,
        REGISTRATION_TOKENS_KV: fakeRegistrationTokensKv,
        KEY_MATERIAL_R2: fakeKeyMaterialBucket,
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
    expect(getTableName(auditEvents)).toBe("audit_events");
  });
});

describe("createRuntimeRepositories", () => {
  it("builds concrete runtime repositories from Cloudflare bindings", async () => {
    const repositories = await createRuntimeRepositories({
      adminBootstrapPassword: "bootstrap-secret",
      adminWhitelist: ["admin@example.test"],
      adminSessionsKv: fakeAdminSessionsKv,
      db: fakeD1Database,
      keyMaterialBucket: fakeKeyMaterialBucket,
      managementApiToken: "manage-acme",
      platformHost: "idp.example.test",
      registrationTokensKv: fakeRegistrationTokensKv
    });

    expect(repositories.adminRepository).toBeDefined();
    expect(repositories.auditRepository).toBeDefined();
    expect(repositories.clientRepository).toBeDefined();
    expect(repositories.keyRepository).toBeDefined();
    expect(repositories.keyMaterialStore).toBeDefined();
    expect(repositories.registrationAccessTokenRepository).toBeDefined();
    expect(repositories.tenantRepository).toBeDefined();

    await repositories.close();
  });
});
