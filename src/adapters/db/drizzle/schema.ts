import { sql } from "drizzle-orm";
import {
  foreignKey,
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex
} from "drizzle-orm/sqlite-core";

export const tenants = sqliteTable(
  "tenants",
  {
    id: text("id").primaryKey(),
    slug: text("slug").notNull(),
    displayName: text("display_name").notNull(),
    status: text("status").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    slugUnique: uniqueIndex("tenants_slug_unique").on(table.slug),
    statusIdx: index("tenants_status_idx").on(table.status)
  })
);

export const tenantIssuers = sqliteTable(
  "tenant_issuers",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    issuerType: text("issuer_type").notNull(),
    issuerUrl: text("issuer_url").notNull(),
    domain: text("domain"),
    isPrimary: integer("is_primary", { mode: "boolean" }).notNull(),
    verificationStatus: text("verification_status").notNull(),
    verifiedAt: text("verified_at"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    tenantIdIdx: index("tenant_issuers_tenant_id_idx").on(table.tenantId),
    issuerUrlUnique: uniqueIndex("tenant_issuers_issuer_url_unique").on(table.issuerUrl),
    domainUnique: uniqueIndex("tenant_issuers_domain_unique").on(table.domain)
  })
);

export const oidcClients = sqliteTable(
  "oidc_clients",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    clientId: text("client_id").notNull(),
    clientSecretHash: text("client_secret_hash"),
    clientName: text("client_name").notNull(),
    applicationType: text("application_type").notNull(),
    trustLevel: text("trust_level").notNull().default("first_party_trusted"),
    consentPolicy: text("consent_policy").notNull().default("skip"),
    tokenEndpointAuthMethod: text("token_endpoint_auth_method").notNull(),
    redirectUris: text("redirect_uris", { mode: "json" }).$type<string[]>().notNull(),
    grantTypes: text("grant_types", { mode: "json" }).$type<string[]>().notNull(),
    responseTypes: text("response_types", { mode: "json" }).$type<string[]>().notNull(),
    createdBy: text("created_by"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    tenantIdIdx: index("oidc_clients_tenant_id_idx").on(table.tenantId),
    clientIdUnique: uniqueIndex("oidc_clients_client_id_unique").on(table.clientId),
    tenantClientUnique: uniqueIndex("oidc_clients_tenant_id_client_id_unique").on(
      table.tenantId,
      table.clientId
    )
  })
);

export const signingKeys = sqliteTable(
  "signing_keys",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
    kid: text("kid").notNull(),
    alg: text("alg").notNull(),
    kty: text("kty").notNull(),
    publicJwk: text("public_jwk", { mode: "json" }).$type<Record<string, unknown>>().notNull(),
    privateKeyRef: text("private_key_ref"),
    status: text("status").notNull(),
    activatedAt: text("activated_at"),
    retireAt: text("retire_at"),
    createdAt: text("created_at").notNull()
  },
  (table) => ({
    tenantIdIdx: index("signing_keys_tenant_id_idx").on(table.tenantId),
    kidUnique: uniqueIndex("signing_keys_kid_unique").on(table.kid)
  })
);

export const adminUsers = sqliteTable(
  "admin_users",
  {
    id: text("id").primaryKey(),
    email: text("email").notNull(),
    status: text("status").notNull(),
    createdAt: text("created_at").notNull()
  },
  (table) => ({
    emailUnique: uniqueIndex("admin_users_email_unique").on(table.email)
  })
);

export const auditEvents = sqliteTable(
  "audit_events",
  {
    id: text("id").primaryKey(),
    actorType: text("actor_type").notNull(),
    actorId: text("actor_id"),
    tenantId: text("tenant_id").references(() => tenants.id, { onDelete: "set null" }),
    eventType: text("event_type").notNull(),
    targetType: text("target_type"),
    targetId: text("target_id"),
    payload: text("payload", { mode: "json" }).$type<Record<string, unknown> | null>(),
    occurredAt: text("occurred_at").notNull()
  },
  (table) => ({
    tenantIdIdx: index("audit_events_tenant_id_idx").on(table.tenantId),
    eventTypeIdx: index("audit_events_event_type_idx").on(table.eventType)
  })
);

export const users = sqliteTable(
  "users",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    emailVerified: integer("email_verified", { mode: "boolean" }).notNull(),
    username: text("username"),
    displayName: text("display_name").notNull(),
    status: text("status").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    tenantIdIdx: index("users_tenant_id_idx").on(table.tenantId),
    tenantIdIdUnique: uniqueIndex("users_tenant_id_id_unique").on(table.tenantId, table.id),
    tenantEmailUnique: uniqueIndex("users_tenant_id_email_unique").on(table.tenantId, table.email),
    tenantUsernameUnique: uniqueIndex("users_tenant_id_username_unique").on(table.tenantId, table.username)
  })
);

export const userPasswordCredentials = sqliteTable(
  "user_password_credentials",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    passwordHash: text("password_hash").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    tenantUserFk: foreignKey({
      columns: [table.tenantId, table.userId],
      foreignColumns: [users.tenantId, users.id]
    }).onDelete("cascade"),
    tenantIdIdx: index("user_password_credentials_tenant_id_idx").on(table.tenantId),
    userIdUnique: uniqueIndex("user_password_credentials_user_id_unique").on(table.userId)
  })
);

export const webauthnCredentials = sqliteTable(
  "webauthn_credentials",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    credentialId: text("credential_id").notNull(),
    publicKey: text("public_key").notNull(),
    counter: integer("counter").notNull(),
    transports: text("transports", { mode: "json" }).$type<string[] | null>(),
    deviceType: text("device_type").notNull(),
    backedUp: integer("backed_up", { mode: "boolean" }).notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    tenantUserFk: foreignKey({
      columns: [table.tenantId, table.userId],
      foreignColumns: [users.tenantId, users.id]
    }).onDelete("cascade"),
    tenantIdIdx: index("webauthn_credentials_tenant_id_idx").on(table.tenantId),
    userIdIdx: index("webauthn_credentials_user_id_idx").on(table.userId),
    credentialIdUnique: uniqueIndex("webauthn_credentials_credential_id_unique").on(table.credentialId)
  })
);

export const tenantAuthMethodPolicies = sqliteTable(
  "tenant_auth_method_policies",
  {
    tenantId: text("tenant_id")
      .primaryKey()
      .references(() => tenants.id, { onDelete: "cascade" }),
    passwordEnabled: integer("password_enabled", { mode: "boolean" }).notNull(),
    emailMagicLinkEnabled: integer("email_magic_link_enabled", { mode: "boolean" }).notNull(),
    passkeyEnabled: integer("passkey_enabled", { mode: "boolean" }).notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    passwordEnabledIdx: index("tenant_auth_method_policies_password_enabled_idx").on(
      table.passwordEnabled
    )
  })
);

export const clientAuthMethodPolicies = sqliteTable(
  "client_auth_method_policies",
  {
    clientId: text("client_id")
      .primaryKey()
      .references(() => oidcClients.id, { onDelete: "cascade" }),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    passwordEnabled: integer("password_enabled", { mode: "boolean" }).notNull().default(false),
    passwordAllowRegistration: integer("password_allow_registration", { mode: "boolean" }).notNull().default(false),
    magicLinkEnabled: integer("magic_link_enabled", { mode: "boolean" }).notNull().default(false),
    magicLinkAllowRegistration: integer("magic_link_allow_registration", { mode: "boolean" }).notNull().default(false),
    passkeyEnabled: integer("passkey_enabled", { mode: "boolean" }).notNull().default(false),
    passkeyAllowRegistration: integer("passkey_allow_registration", { mode: "boolean" }).notNull().default(false),
    googleEnabled: integer("google_enabled", { mode: "boolean" }).notNull().default(false),
    appleEnabled: integer("apple_enabled", { mode: "boolean" }).notNull().default(false),
    facebookEnabled: integer("facebook_enabled", { mode: "boolean" }).notNull().default(false),
    wechatEnabled: integer("wechat_enabled", { mode: "boolean" }).notNull().default(false),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull()
  },
  (table) => ({
    tenantIdIdx: index("client_auth_method_policies_tenant_id_idx").on(table.tenantId)
  })
);

export const userInvitations = sqliteTable(
  "user_invitations",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    purpose: text("purpose").notNull(),
    expiresAt: text("expires_at").notNull(),
    consumedAt: text("consumed_at"),
    createdAt: text("created_at").notNull()
  },
  (table) => ({
    tenantUserFk: foreignKey({
      columns: [table.tenantId, table.userId],
      foreignColumns: [users.tenantId, users.id]
    }).onDelete("cascade"),
    tenantIdIdx: index("user_invitations_tenant_id_idx").on(table.tenantId),
    userIdIdx: index("user_invitations_user_id_idx").on(table.userId),
    tokenHashActiveUnique: uniqueIndex("user_invitations_token_hash_active_unique")
      .on(table.tokenHash)
      .where(sql`${table.consumedAt} IS NULL`)
  })
);

export const loginChallenges = sqliteTable(
  "login_challenges",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    issuer: text("issuer").notNull(),
    clientId: text("client_id").notNull(),
    redirectUri: text("redirect_uri").notNull(),
    scope: text("scope").notNull(),
    state: text("state").notNull(),
    codeChallenge: text("code_challenge").notNull(),
    codeChallengeMethod: text("code_challenge_method").notNull(),
    nonce: text("nonce"),
    tokenHash: text("token_hash").notNull(),
    expiresAt: text("expires_at").notNull(),
    consumedAt: text("consumed_at"),
    createdAt: text("created_at").notNull()
  },
  (table) => ({
    tenantClientFk: foreignKey({
      columns: [table.tenantId, table.clientId],
      foreignColumns: [oidcClients.tenantId, oidcClients.clientId]
    }).onDelete("cascade"),
    tenantIdIdx: index("login_challenges_tenant_id_idx").on(table.tenantId),
    tokenHashActiveUnique: uniqueIndex("login_challenges_token_hash_active_unique")
      .on(table.tokenHash)
      .where(sql`${table.consumedAt} IS NULL`)
  })
);

export const authorizationCodes = sqliteTable(
  "authorization_codes",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    issuer: text("issuer").notNull(),
    clientId: text("client_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    redirectUri: text("redirect_uri").notNull(),
    scope: text("scope").notNull(),
    nonce: text("nonce"),
    codeChallenge: text("code_challenge").notNull(),
    codeChallengeMethod: text("code_challenge_method").notNull(),
    tokenHash: text("token_hash").notNull(),
    expiresAt: text("expires_at").notNull(),
    consumedAt: text("consumed_at"),
    createdAt: text("created_at").notNull()
  },
  (table) => ({
    tenantUserFk: foreignKey({
      columns: [table.tenantId, table.userId],
      foreignColumns: [users.tenantId, users.id]
    }).onDelete("cascade"),
    tenantClientFk: foreignKey({
      columns: [table.tenantId, table.clientId],
      foreignColumns: [oidcClients.tenantId, oidcClients.clientId]
    }).onDelete("cascade"),
    tenantIdIdx: index("authorization_codes_tenant_id_idx").on(table.tenantId),
    userIdIdx: index("authorization_codes_user_id_idx").on(table.userId),
    tokenHashActiveUnique: uniqueIndex("authorization_codes_token_hash_active_unique")
      .on(table.tokenHash)
      .where(sql`${table.consumedAt} IS NULL`)
  })
);

export const emailLoginTokens = sqliteTable(
  "email_login_tokens",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    issuer: text("issuer").notNull(),
    tokenHash: text("token_hash").notNull(),
    redirectAfterLogin: text("redirect_after_login").notNull(),
    expiresAt: text("expires_at").notNull(),
    consumedAt: text("consumed_at"),
    createdAt: text("created_at").notNull()
  },
  (table) => ({
    tenantUserFk: foreignKey({
      columns: [table.tenantId, table.userId],
      foreignColumns: [users.tenantId, users.id]
    }).onDelete("cascade"),
    tenantIdIdx: index("email_login_tokens_tenant_id_idx").on(table.tenantId),
    userIdIdx: index("email_login_tokens_user_id_idx").on(table.userId),
    tokenHashActiveUnique: uniqueIndex("email_login_tokens_token_hash_active_unique")
      .on(table.tokenHash)
      .where(sql`${table.consumedAt} IS NULL`)
  })
);

export const platformConfig = sqliteTable("platform_config", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: text("updated_at").notNull()
});
