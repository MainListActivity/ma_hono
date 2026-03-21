import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

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
    clientIdUnique: uniqueIndex("oidc_clients_client_id_unique").on(table.clientId)
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
