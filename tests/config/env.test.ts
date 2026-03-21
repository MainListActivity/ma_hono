import { describe, expect, it } from "vitest";
import { getTableColumns, getTableName } from "drizzle-orm";
import { getTableConfig } from "drizzle-orm/sqlite-core";

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

const getForeignKeySignatures = (table: Parameters<typeof getTableConfig>[0]) =>
  getTableConfig(table).foreignKeys.map((foreignKey) => {
    const reference = foreignKey.reference();

    return {
      columns: reference.columns.map((column) => column.name),
      foreignColumns: reference.foreignColumns.map((column) => column.name),
      foreignTable: getTableName(reference.foreignTable)
    };
  });

const hasUniqueIndex = (
  table: Parameters<typeof getTableConfig>[0],
  columns: string[]
) =>
  getTableConfig(table).indexes.some(
    (index) =>
      index.config.unique &&
      index.config.columns
        .map((column) => ("name" in column ? column.name : ""))
        .join(",") === columns.join(",")
  );

describe("readRuntimeConfig", () => {
  it("reads the required runtime configuration", () => {
    const config = readRuntimeConfig({
      DB: fakeD1Database,
      ADMIN_SESSIONS_KV: fakeAdminSessionsKv,
      USER_SESSIONS_KV: fakeUserSessionsKv,
      REGISTRATION_TOKENS_KV: fakeRegistrationTokensKv,
      KEY_MATERIAL_R2: fakeKeyMaterialBucket
    });

    expect(config).toEqual({
      adminSessionsKv: fakeAdminSessionsKv,
      db: fakeD1Database,
      keyMaterialBucket: fakeKeyMaterialBucket,
      userSessionsKv: fakeUserSessionsKv,
      registrationTokensKv: fakeRegistrationTokensKv
    });
  });

  it("throws when the D1 database binding is missing", () => {
    expect(() =>
      readRuntimeConfig({
        ADMIN_SESSIONS_KV: fakeAdminSessionsKv,
        USER_SESSIONS_KV: fakeUserSessionsKv,
        REGISTRATION_TOKENS_KV: fakeRegistrationTokensKv,
        KEY_MATERIAL_R2: fakeKeyMaterialBucket
      })
    ).toThrowError(/DB/);
  });

  it("throws when the end-user session KV binding is missing", () => {
    expect(() =>
      readRuntimeConfig({
        DB: fakeD1Database,
        ADMIN_SESSIONS_KV: fakeAdminSessionsKv,
        REGISTRATION_TOKENS_KV: fakeRegistrationTokensKv,
        KEY_MATERIAL_R2: fakeKeyMaterialBucket
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

  it("includes the oidc client trust, consent, and tenant-scoped client lookup shape", () => {
    const columns = getTableColumns(oidcClients);

    expect(columns).toHaveProperty("trustLevel");
    expect(columns).toHaveProperty("consentPolicy");
    expect(hasUniqueIndex(oidcClients, ["tenant_id", "client_id"])).toBe(true);
  });

  it("enforces tenant scoped user and client foreign keys", () => {
    expect(hasUniqueIndex(users, ["tenant_id", "id"])).toBe(true);
    expect(getTableColumns(loginChallenges)).toHaveProperty("nonce");

    expect(getForeignKeySignatures(userPasswordCredentials)).toContainEqual({
      columns: ["tenant_id", "user_id"],
      foreignColumns: ["tenant_id", "id"],
      foreignTable: "users"
    });
    expect(getForeignKeySignatures(webauthnCredentials)).toContainEqual({
      columns: ["tenant_id", "user_id"],
      foreignColumns: ["tenant_id", "id"],
      foreignTable: "users"
    });
    expect(getForeignKeySignatures(userInvitations)).toContainEqual({
      columns: ["tenant_id", "user_id"],
      foreignColumns: ["tenant_id", "id"],
      foreignTable: "users"
    });
    expect(getForeignKeySignatures(authorizationCodes)).toContainEqual({
      columns: ["tenant_id", "user_id"],
      foreignColumns: ["tenant_id", "id"],
      foreignTable: "users"
    });
    expect(getForeignKeySignatures(emailLoginTokens)).toContainEqual({
      columns: ["tenant_id", "user_id"],
      foreignColumns: ["tenant_id", "id"],
      foreignTable: "users"
    });
    expect(getForeignKeySignatures(loginChallenges)).toContainEqual({
      columns: ["tenant_id", "client_id"],
      foreignColumns: ["tenant_id", "client_id"],
      foreignTable: "oidc_clients"
    });
    expect(getForeignKeySignatures(authorizationCodes)).toContainEqual({
      columns: ["tenant_id", "client_id"],
      foreignColumns: ["tenant_id", "client_id"],
      foreignTable: "oidc_clients"
    });
  });
});

describe("createRuntimeRepositories", () => {
  it("builds concrete runtime repositories from Cloudflare bindings", async () => {
    const repositories = await createRuntimeRepositories({
      adminSessionsKv: fakeAdminSessionsKv,
      db: fakeD1Database,
      keyMaterialBucket: fakeKeyMaterialBucket,
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
