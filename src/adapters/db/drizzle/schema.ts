import {
  boolean,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar
} from "drizzle-orm/pg-core";

export const tenants = pgTable(
  "tenants",
  {
    id: uuid("id").primaryKey(),
    slug: varchar("slug", { length: 128 }).notNull(),
    displayName: varchar("display_name", { length: 256 }).notNull(),
    status: varchar("status", { length: 32 }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull()
  },
  (table) => ({
    slugUnique: uniqueIndex("tenants_slug_unique").on(table.slug)
  })
);

export const tenantIssuers = pgTable(
  "tenant_issuers",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id").notNull(),
    issuerType: varchar("issuer_type", { length: 32 }).notNull(),
    issuerUrl: text("issuer_url").notNull(),
    domain: varchar("domain", { length: 255 }),
    isPrimary: boolean("is_primary").notNull(),
    verificationStatus: varchar("verification_status", { length: 32 }).notNull(),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull()
  },
  (table) => ({
    issuerUrlUnique: uniqueIndex("tenant_issuers_issuer_url_unique").on(table.issuerUrl),
    domainUnique: uniqueIndex("tenant_issuers_domain_unique").on(table.domain)
  })
);

export const oidcClients = pgTable(
  "oidc_clients",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id").notNull(),
    clientId: varchar("client_id", { length: 255 }).notNull(),
    clientSecretHash: text("client_secret_hash"),
    clientName: varchar("client_name", { length: 255 }).notNull(),
    applicationType: varchar("application_type", { length: 32 }).notNull(),
    tokenEndpointAuthMethod: varchar("token_endpoint_auth_method", { length: 64 }).notNull(),
    redirectUris: jsonb("redirect_uris").notNull(),
    grantTypes: jsonb("grant_types").notNull(),
    responseTypes: jsonb("response_types").notNull(),
    registrationAccessTokenHash: text("registration_access_token_hash").notNull(),
    createdBy: varchar("created_by", { length: 128 }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull()
  },
  (table) => ({
    clientIdUnique: uniqueIndex("oidc_clients_client_id_unique").on(table.clientId)
  })
);

export const signingKeys = pgTable("signing_keys", {
  id: uuid("id").primaryKey(),
  tenantId: uuid("tenant_id"),
  kid: varchar("kid", { length: 255 }).notNull(),
  alg: varchar("alg", { length: 32 }).notNull(),
  kty: varchar("kty", { length: 16 }).notNull(),
  publicJwk: jsonb("public_jwk").notNull(),
  privateKeyRef: text("private_key_ref"),
  status: varchar("status", { length: 32 }).notNull(),
  activatedAt: timestamp("activated_at", { withTimezone: true }),
  retireAt: timestamp("retire_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull()
});

export const adminUsers = pgTable(
  "admin_users",
  {
    id: uuid("id").primaryKey(),
    email: varchar("email", { length: 320 }).notNull(),
    status: varchar("status", { length: 32 }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull()
  },
  (table) => ({
    emailUnique: uniqueIndex("admin_users_email_unique").on(table.email)
  })
);

export const adminSessions = pgTable(
  "admin_sessions",
  {
    id: uuid("id").primaryKey(),
    adminUserId: uuid("admin_user_id").notNull(),
    sessionTokenHash: text("session_token_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull()
  },
  (table) => ({
    sessionTokenHashUnique: uniqueIndex("admin_sessions_token_hash_unique").on(
      table.sessionTokenHash
    )
  })
);

export const auditEvents = pgTable("audit_events", {
  id: uuid("id").primaryKey(),
  actorType: varchar("actor_type", { length: 64 }).notNull(),
  actorId: varchar("actor_id", { length: 255 }),
  tenantId: uuid("tenant_id"),
  eventType: varchar("event_type", { length: 128 }).notNull(),
  targetType: varchar("target_type", { length: 128 }),
  targetId: varchar("target_id", { length: 255 }),
  payload: jsonb("payload"),
  occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull()
});
