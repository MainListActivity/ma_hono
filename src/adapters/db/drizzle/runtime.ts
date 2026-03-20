import { and, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import type { AuditRepository } from "../../../domain/audit/repository";
import type { AuditEvent } from "../../../domain/audit/types";
import type { AdminRepository } from "../../../domain/admin-auth/repository";
import type { AdminSession, AdminUser } from "../../../domain/admin-auth/types";
import type { ClientRepository } from "../../../domain/clients/repository";
import type { Client } from "../../../domain/clients/types";
import type { KeyRepository } from "../../../domain/keys/repository";
import type { SigningKey } from "../../../domain/keys/types";
import type { RuntimeConfig } from "../../../config/env";
import type { TenantRepository } from "../../../domain/tenants/repository";
import type { Tenant, TenantIssuer } from "../../../domain/tenants/types";
import {
  adminSessions,
  adminUsers,
  auditEvents,
  oidcClients,
  signingKeys,
  tenantIssuers,
  tenants
} from "./schema";

const toTenant = (
  tenantRow: typeof tenants.$inferSelect,
  issuerRows: Array<typeof tenantIssuers.$inferSelect>
): Tenant => ({
  id: tenantRow.id,
  slug: tenantRow.slug,
  displayName: tenantRow.displayName,
  status: tenantRow.status as Tenant["status"],
  issuers: issuerRows.map(
    (issuerRow): TenantIssuer => ({
      id: issuerRow.id,
      issuerType: issuerRow.issuerType as TenantIssuer["issuerType"],
      issuerUrl: issuerRow.issuerUrl,
      domain: issuerRow.domain,
      isPrimary: issuerRow.isPrimary,
      verificationStatus: issuerRow.verificationStatus as TenantIssuer["verificationStatus"]
    })
  )
});

class DrizzleTenantRepository implements TenantRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(tenant: Tenant): Promise<void> {
    const now = new Date();

    await this.db.transaction(async (tx) => {
      await tx.insert(tenants).values({
        id: tenant.id,
        slug: tenant.slug,
        displayName: tenant.displayName,
        status: tenant.status,
        createdAt: now,
        updatedAt: now
      });

      if (tenant.issuers.length > 0) {
        await tx.insert(tenantIssuers).values(
          tenant.issuers.map((issuer) => ({
            id: issuer.id,
            tenantId: tenant.id,
            issuerType: issuer.issuerType,
            issuerUrl: issuer.issuerUrl,
            domain: issuer.domain,
            isPrimary: issuer.isPrimary,
            verificationStatus: issuer.verificationStatus,
            verifiedAt: issuer.verificationStatus === "verified" ? now : null,
            createdAt: now,
            updatedAt: now
          }))
        );
      }
    });
  }

  async findBySlug(slug: string): Promise<Tenant | null> {
    const [tenantRow] = await this.db.select().from(tenants).where(eq(tenants.slug, slug)).limit(1);

    if (tenantRow === undefined) {
      return null;
    }

    const issuerRows = await this.db
      .select()
      .from(tenantIssuers)
      .where(eq(tenantIssuers.tenantId, tenantRow.id));

    return toTenant(tenantRow, issuerRows);
  }

  async findByCustomDomain(domain: string): Promise<Tenant | null> {
    const [issuerRow] = await this.db
      .select()
      .from(tenantIssuers)
      .where(and(eq(tenantIssuers.domain, domain), eq(tenantIssuers.verificationStatus, "verified")))
      .limit(1);

    if (issuerRow === undefined) {
      return null;
    }

    const [tenantRow] = await this.db
      .select()
      .from(tenants)
      .where(eq(tenants.id, issuerRow.tenantId))
      .limit(1);

    if (tenantRow === undefined) {
      return null;
    }

    const issuerRows = await this.db
      .select()
      .from(tenantIssuers)
      .where(eq(tenantIssuers.tenantId, tenantRow.id));

    return toTenant(tenantRow, issuerRows);
  }
}

class DrizzleKeyRepository implements KeyRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async listActiveKeysForTenant(tenantId: string): Promise<SigningKey[]> {
    const rows = await this.db
      .select()
      .from(signingKeys)
      .where(and(eq(signingKeys.tenantId, tenantId), eq(signingKeys.status, "active")));

    return rows.map((row) => ({
      id: row.id,
      tenantId: row.tenantId,
      kid: row.kid,
      alg: row.alg,
      kty: row.kty,
      status: row.status as SigningKey["status"],
      publicJwk: row.publicJwk as SigningKey["publicJwk"]
    }));
  }
}

class DrizzleClientRepository implements ClientRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(client: Client): Promise<void> {
    const now = new Date();

    await this.db.insert(oidcClients).values({
      id: client.id,
      tenantId: client.tenantId,
      clientId: client.clientId,
      clientSecretHash: client.clientSecretHash,
      clientName: client.clientName,
      applicationType: client.applicationType,
      tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
      redirectUris: client.redirectUris,
      grantTypes: client.grantTypes,
      responseTypes: client.responseTypes,
      registrationAccessTokenHash: client.registrationAccessTokenHash,
      createdBy: "dynamic_registration",
      createdAt: now,
      updatedAt: now
    });
  }

  async findByClientId(clientId: string): Promise<Client | null> {
    const [row] = await this.db
      .select()
      .from(oidcClients)
      .where(eq(oidcClients.clientId, clientId))
      .limit(1);

    return row === undefined
      ? null
      : {
          id: row.id,
          tenantId: row.tenantId,
          clientId: row.clientId,
          clientSecretHash: row.clientSecretHash,
          clientName: row.clientName,
          applicationType: row.applicationType as Client["applicationType"],
          grantTypes: row.grantTypes as Client["grantTypes"],
          redirectUris: row.redirectUris as Client["redirectUris"],
          responseTypes: row.responseTypes as Client["responseTypes"],
          tokenEndpointAuthMethod: row.tokenEndpointAuthMethod as Client["tokenEndpointAuthMethod"],
          registrationAccessTokenHash: row.registrationAccessTokenHash
        };
  }
}

class DrizzleAdminRepository implements AdminRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async createSession(session: AdminSession): Promise<void> {
    await this.db.insert(adminSessions).values({
      id: session.id,
      adminUserId: session.adminUserId,
      sessionTokenHash: session.sessionTokenHash,
      expiresAt: new Date(session.expiresAt),
      createdAt: new Date()
    });
  }

  async findSessionByTokenHash(sessionTokenHash: string): Promise<AdminSession | null> {
    const [row] = await this.db
      .select()
      .from(adminSessions)
      .where(eq(adminSessions.sessionTokenHash, sessionTokenHash))
      .limit(1);

    return row === undefined
      ? null
      : {
          id: row.id,
          adminUserId: row.adminUserId,
          sessionTokenHash: row.sessionTokenHash,
          expiresAt: row.expiresAt.toISOString()
        };
  }

  async findUserByEmail(email: string): Promise<AdminUser | null> {
    const [row] = await this.db
      .select()
      .from(adminUsers)
      .where(eq(adminUsers.email, email))
      .limit(1);

    return row === undefined
      ? null
      : {
          id: row.id,
          email: row.email,
          status: row.status as AdminUser["status"]
        };
  }
}

class DrizzleAuditRepository implements AuditRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async record(event: AuditEvent): Promise<void> {
    await this.db.insert(auditEvents).values({
      id: event.id,
      actorType: event.actorType,
      actorId: event.actorId,
      tenantId: event.tenantId,
      eventType: event.eventType,
      targetType: event.targetType,
      targetId: event.targetId,
      payload: event.payload,
      occurredAt: new Date(event.occurredAt)
    });
  }
}

export const createRuntimeRepositories = async (config: RuntimeConfig) => {
  const sql = postgres(config.databaseUrl, {
    max: 1,
    prepare: false
  });
  const db = drizzle(sql, {
    schema: {
      adminSessions,
      adminUsers,
      auditEvents,
      oidcClients,
      signingKeys,
      tenantIssuers,
      tenants
    }
  });

  return {
    adminRepository: new DrizzleAdminRepository(db),
    auditRepository: new DrizzleAuditRepository(db),
    clientRepository: new DrizzleClientRepository(db),
    keyRepository: new DrizzleKeyRepository(db),
    tenantRepository: new DrizzleTenantRepository(db),
    close: async () => {
      await sql.end({ timeout: 1 });
    }
  };
};
