import { describe, expect, it } from "vitest";
import { getTableColumns, getTableName } from "drizzle-orm";

import { readRuntimeConfig } from "../../src/config/env";
import { createRuntimeRepositories } from "../../src/adapters/db/drizzle/runtime";
import {
  adminUsers,
  auditEvents,
  authorizationCodes,
  oidcClients,
  emailLoginTokens,
  loginChallenges,
  tenantAuthMethodPolicies,
  signingKeys,
  userInvitations,
  userPasswordCredentials,
  users,
  webauthnCredentials,
  tenantIssuers,
  tenants
} from "../../src/adapters/db/drizzle/schema";

const fakeD1Database = {} as D1Database;
const fakeAdminSessionsKv = {} as KVNamespace;
const fakeUserSessionsKv = {} as KVNamespace;
const fakeRegistrationTokensKv = {} as KVNamespace;
const fakeKeyMaterialBucket = {} as R2Bucket;

describe("readRuntimeConfig", () => {
  it("reads the required runtime configuration", () => {
    const config = readRuntimeConfig({
      ADMIN_BOOTSTRAP_PASSWORD: "bootstrap-secret",
      ADMIN_WHITELIST: "admin@example.test,ops@example.test",
      DB: fakeD1Database,
      ADMIN_SESSIONS_KV: fakeAdminSessionsKv,
      USER_SESSIONS_KV: fakeUserSessionsKv,
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
      userSessionsKv: fakeUserSessionsKv,
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
        USER_SESSIONS_KV: fakeUserSessionsKv,
        REGISTRATION_TOKENS_KV: fakeRegistrationTokensKv,
        KEY_MATERIAL_R2: fakeKeyMaterialBucket,
        MANAGEMENT_API_TOKEN: "manage-acme"
      })
    ).toThrowError(/PLATFORM_HOST/);
  });

  it("throws when the end-user session KV binding is missing", () => {
    expect(() =>
      readRuntimeConfig({
        ADMIN_BOOTSTRAP_PASSWORD: "bootstrap-secret",
        ADMIN_WHITELIST: "admin@example.test",
        DB: fakeD1Database,
        ADMIN_SESSIONS_KV: fakeAdminSessionsKv,
        REGISTRATION_TOKENS_KV: fakeRegistrationTokensKv,
        KEY_MATERIAL_R2: fakeKeyMaterialBucket,
        MANAGEMENT_API_TOKEN: "manage-acme",
        PLATFORM_HOST: "idp.example.test"
      })
    ).toThrowError(/USER_SESSIONS_KV/);
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

  it("exports the idp v1 login and authorization tables", () => {
    expect(getTableName(users)).toBe("users");
    expect(getTableName(userPasswordCredentials)).toBe("user_password_credentials");
    expect(getTableName(webauthnCredentials)).toBe("webauthn_credentials");
    expect(getTableName(tenantAuthMethodPolicies)).toBe("tenant_auth_method_policies");
    expect(getTableName(userInvitations)).toBe("user_invitations");
    expect(getTableName(loginChallenges)).toBe("login_challenges");
    expect(getTableName(authorizationCodes)).toBe("authorization_codes");
    expect(getTableName(emailLoginTokens)).toBe("email_login_tokens");
  });

  it("includes the oidc client trust and consent columns", () => {
    const columns = getTableColumns(oidcClients);

    expect(columns).toHaveProperty("trustLevel");
    expect(columns).toHaveProperty("consentPolicy");
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
      userSessionsKv: fakeUserSessionsKv,
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
