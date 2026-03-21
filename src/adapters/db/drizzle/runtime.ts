import { and, desc, eq, isNull, or } from "drizzle-orm";
import { drizzle } from "drizzle-orm/d1";

import type { AuditRepository } from "../../../domain/audit/repository";
import type { AuditEvent } from "../../../domain/audit/types";
import type { AdminRepository } from "../../../domain/admin-auth/repository";
import type { AdminSession, AdminUser } from "../../../domain/admin-auth/types";
import type { RegistrationAccessTokenRepository } from "../../../domain/clients/registration-access-token-repository";
import type { ClientRepository } from "../../../domain/clients/repository";
import type { Client } from "../../../domain/clients/types";
import type { KeyMaterialStore } from "../../../domain/keys/key-material-store";
import type { KeyRepository } from "../../../domain/keys/repository";
import { createSigningKeySigner } from "../../../domain/keys/signer";
import type { SigningKey, SigningKeyMaterial } from "../../../domain/keys/types";
import type { RuntimeConfig } from "../../../config/env";
import type { TenantRepository } from "../../../domain/tenants/repository";
import type { Tenant, TenantIssuer } from "../../../domain/tenants/types";
import { R2KeyMaterialStore } from "../../r2/r2-key-material-store";
import {
  adminUsers,
  auditEvents,
  authorizationCodes,
  emailLoginTokens,
  loginChallenges,
  oidcClients,
  signingKeys,
  tenantAuthMethodPolicies,
  tenantIssuers,
  tenants,
  userInvitations,
  userPasswordCredentials,
  users,
  webauthnCredentials
} from "./schema";

const adminSessionPrefix = "admin_session:";
const registrationTokenPrefix = "registration_access_token:";
const wait = async (milliseconds: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });

export class D1SigningKeyBootstrapper {
  constructor(
    private readonly db: ReturnType<typeof drizzle>,
    private readonly keyMaterialStore: KeyMaterialStore
  ) {}

  async bootstrapSigningKey(input: {
    alg: string;
    kid: string;
    kty: string;
    privateKeyRef: string;
    publicJwk: SigningKey["publicJwk"];
    privateJwk: SigningKey["publicJwk"];
    tenantId: string | null;
  }): Promise<SigningKeyMaterial> {
    const now = new Date().toISOString();
    const key: SigningKey = {
      id: crypto.randomUUID(),
      tenantId: input.tenantId,
      kid: input.kid,
      alg: input.alg,
      kty: input.kty,
      privateKeyRef: input.privateKeyRef,
      status: "active",
      publicJwk: input.publicJwk
    };

    try {
      await this.db.insert(signingKeys).values({
        id: key.id,
        tenantId: key.tenantId,
        kid: key.kid,
        alg: key.alg,
        kty: key.kty,
        publicJwk: key.publicJwk as Record<string, unknown>,
        privateKeyRef: key.privateKeyRef,
        status: key.status,
        activatedAt: now,
        retireAt: null,
        createdAt: now
      });
    } catch (error) {
      const [existingRow] = await this.db
        .select()
        .from(signingKeys)
        .where(eq(signingKeys.kid, input.kid))
        .limit(1);

      if (existingRow === undefined) {
        throw error;
      }

      const privateJwk = await this.loadPrivateJwk(existingRow.privateKeyRef ?? input.privateKeyRef);

      if (privateJwk === null) {
        throw error;
      }

      return {
        key: {
          id: existingRow.id,
          tenantId: existingRow.tenantId,
          kid: existingRow.kid,
          alg: existingRow.alg,
          kty: existingRow.kty,
          privateKeyRef: existingRow.privateKeyRef,
          status: existingRow.status as SigningKey["status"],
          publicJwk: existingRow.publicJwk as SigningKey["publicJwk"]
        },
        privateJwk
      };
    }

    try {
      await this.keyMaterialStore.put(input.privateKeyRef, JSON.stringify(input.privateJwk));
    } catch (error) {
      await this.db.delete(signingKeys).where(eq(signingKeys.kid, input.kid));
      throw error;
    }

    return {
      key,
      privateJwk: input.privateJwk
    };
  }

  private async loadPrivateJwk(privateKeyRef: string): Promise<SigningKey["publicJwk"] | null> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const privateJwkJson = await this.keyMaterialStore.get(privateKeyRef);

      if (privateJwkJson !== null) {
        return JSON.parse(privateJwkJson) as SigningKey["publicJwk"];
      }

      if (attempt < 2) {
        await wait((attempt + 1) * 10);
      }
    }

    return null;
  }
}

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

class D1TenantRepository implements TenantRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(tenant: Tenant): Promise<void> {
    const now = new Date().toISOString();

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

class D1KeyRepository implements KeyRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async listActiveKeysForTenant(tenantId: string): Promise<SigningKey[]> {
    const rows = await this.db
      .select()
      .from(signingKeys)
      .where(
        and(
          eq(signingKeys.status, "active"),
          or(eq(signingKeys.tenantId, tenantId), isNull(signingKeys.tenantId))
        )
      )
      .orderBy(desc(signingKeys.activatedAt), desc(signingKeys.createdAt));

    return rows.map((row) => ({
      id: row.id,
      tenantId: row.tenantId,
      kid: row.kid,
      alg: row.alg,
      kty: row.kty,
      status: row.status as SigningKey["status"],
      privateKeyRef: row.privateKeyRef,
      publicJwk: row.publicJwk as SigningKey["publicJwk"]
    }));
  }
}

class D1ClientRepository implements ClientRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(client: Client): Promise<void> {
    const now = new Date().toISOString();

    await this.db.insert(oidcClients).values({
      id: client.id,
      tenantId: client.tenantId,
      clientId: client.clientId,
      clientSecretHash: client.clientSecretHash,
      clientName: client.clientName,
      applicationType: client.applicationType,
      trustLevel: "first_party_trusted",
      consentPolicy: "skip",
      tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
      redirectUris: client.redirectUris,
      grantTypes: client.grantTypes,
      responseTypes: client.responseTypes,
      createdBy: "dynamic_registration",
      createdAt: now,
      updatedAt: now
    });
  }

  async deleteByClientId(clientId: string): Promise<void> {
    await this.db.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
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
          tokenEndpointAuthMethod: row.tokenEndpointAuthMethod as Client["tokenEndpointAuthMethod"]
        };
  }
}

class D1KvAdminRepository implements AdminRepository {
  constructor(
    private readonly db: ReturnType<typeof drizzle>,
    private readonly sessionsKv: KVNamespace
  ) {}

  async createSession(session: AdminSession): Promise<void> {
    const expirationTtl = Math.max(
      60,
      Math.ceil((new Date(session.expiresAt).getTime() - Date.now()) / 1000)
    );

    await this.sessionsKv.put(`${adminSessionPrefix}${session.sessionTokenHash}`, JSON.stringify(session), {
      expirationTtl
    });
  }

  async findSessionByTokenHash(sessionTokenHash: string): Promise<AdminSession | null> {
    const raw = await this.sessionsKv.get(`${adminSessionPrefix}${sessionTokenHash}`);

    return raw === null ? null : (JSON.parse(raw) as AdminSession);
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

class D1AuditRepository implements AuditRepository {
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
      occurredAt: event.occurredAt
    });
  }
}

class KvRegistrationAccessTokenRepository
  implements RegistrationAccessTokenRepository
{
  constructor(private readonly kv: KVNamespace) {}

  async deleteByTokenHash(tokenHash: string): Promise<void> {
    await this.kv.delete(`${registrationTokenPrefix}${tokenHash}`);
  }

  async store(record: {
    clientId: string;
    expiresAt: string;
    issuer: string;
    tenantId: string;
    tokenHash: string;
  }): Promise<void> {
    const expirationTtl = Math.max(
      60,
      Math.ceil((new Date(record.expiresAt).getTime() - Date.now()) / 1000)
    );

    await this.kv.put(`${registrationTokenPrefix}${record.tokenHash}`, JSON.stringify(record), {
      expirationTtl
    });
  }
}

export const createRuntimeRepositories = async (config: RuntimeConfig) => {
  const db = drizzle(config.db, {
    schema: {
      adminUsers,
      auditEvents,
      authorizationCodes,
      emailLoginTokens,
      loginChallenges,
      oidcClients,
      signingKeys,
      tenantAuthMethodPolicies,
      tenantIssuers,
      tenants,
      userInvitations,
      userPasswordCredentials,
      users,
      webauthnCredentials
    }
  });
  const keyMaterialStore = new R2KeyMaterialStore(config.keyMaterialBucket);
  const keyRepository = new D1KeyRepository(db);
  const signingKeyBootstrapper = new D1SigningKeyBootstrapper(db, keyMaterialStore);
  const signer = createSigningKeySigner({
    bootstrapSigningKey: signingKeyBootstrapper.bootstrapSigningKey.bind(signingKeyBootstrapper),
    keyMaterialStore,
    keyRepository
  });
  const [existingSigningKey] = await db
    .select({ id: signingKeys.id })
    .from(signingKeys)
    .where(eq(signingKeys.status, "active"))
    .limit(1);

  if (existingSigningKey === undefined) {
    await signer.ensureActiveSigningKeyMaterial(null);
  }

  return {
    adminRepository: new D1KvAdminRepository(db, config.adminSessionsKv),
    auditRepository: new D1AuditRepository(db),
    clientRepository: new D1ClientRepository(db),
    keyMaterialStore,
    keyRepository,
    signer,
    registrationAccessTokenRepository: new KvRegistrationAccessTokenRepository(
      config.registrationTokensKv
    ),
    tenantRepository: new D1TenantRepository(db),
    close: async () => undefined
  };
};
