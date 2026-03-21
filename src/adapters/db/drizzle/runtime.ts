import { and, desc, eq, isNull, or } from "drizzle-orm";
import { drizzle } from "drizzle-orm/d1";

import type { AuditRepository } from "../../../domain/audit/repository";
import type { AuditEvent } from "../../../domain/audit/types";
import type { AdminRepository } from "../../../domain/admin-auth/repository";
import type { AdminSession, AdminUser } from "../../../domain/admin-auth/types";
import type { RegistrationAccessTokenRepository } from "../../../domain/clients/registration-access-token-repository";
import type { ClientRepository } from "../../../domain/clients/repository";
import type { Client } from "../../../domain/clients/types";
import type {
  AuthorizationCodeRepository,
  LoginChallengeRepository
} from "../../../domain/authorization/repository";
import type {
  AuthorizationCode,
  LoginChallenge
} from "../../../domain/authorization/types";
import type { KeyMaterialStore } from "../../../domain/keys/key-material-store";
import type { KeyRepository } from "../../../domain/keys/repository";
import { createSigningKeySigner } from "../../../domain/keys/signer";
import type { SigningKey, SigningKeyMaterial } from "../../../domain/keys/types";
import type { RuntimeConfig } from "../../../config/env";
import type { TenantRepository } from "../../../domain/tenants/repository";
import type { Tenant, TenantIssuer } from "../../../domain/tenants/types";
import type {
  ActivateUserByInvitationTokenInput,
  ActivateUserByInvitationTokenResult,
  CreateProvisionedUserWithInvitationInput,
  UserRepository
} from "../../../domain/users/repository";
import type {
  PasswordCredential,
  TenantAuthMethodPolicy,
  User,
  UserInvitation
} from "../../../domain/users/types";
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

  async findById(id: string): Promise<Tenant | null> {
    const [tenantRow] = await this.db.select().from(tenants).where(eq(tenants.id, id)).limit(1);

    if (tenantRow === undefined) {
      return null;
    }

    const issuerRows = await this.db
      .select()
      .from(tenantIssuers)
      .where(eq(tenantIssuers.tenantId, tenantRow.id));

    return toTenant(tenantRow, issuerRows);
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
      trustLevel: client.trustLevel,
      consentPolicy: client.consentPolicy,
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
          tokenEndpointAuthMethod: row.tokenEndpointAuthMethod as Client["tokenEndpointAuthMethod"],
          trustLevel: row.trustLevel as Client["trustLevel"],
          consentPolicy: row.consentPolicy as Client["consentPolicy"]
        };
  }
}

class D1LoginChallengeRepository implements LoginChallengeRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(challenge: LoginChallenge): Promise<void> {
    await this.db.insert(loginChallenges).values({
      id: challenge.id,
      tenantId: challenge.tenantId,
      issuer: challenge.issuer,
      clientId: challenge.clientId,
      redirectUri: challenge.redirectUri,
      scope: challenge.scope,
      state: challenge.state,
      codeChallenge: challenge.codeChallenge,
      codeChallengeMethod: challenge.codeChallengeMethod,
      nonce: challenge.nonce,
      tokenHash: challenge.tokenHash,
      expiresAt: challenge.expiresAt,
      consumedAt: challenge.consumedAt,
      createdAt: challenge.createdAt
    });
  }
}

class D1AuthorizationCodeRepository implements AuthorizationCodeRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(code: AuthorizationCode): Promise<void> {
    await this.db.insert(authorizationCodes).values({
      id: code.id,
      tenantId: code.tenantId,
      issuer: code.issuer,
      clientId: code.clientId,
      userId: code.userId,
      redirectUri: code.redirectUri,
      scope: code.scope,
      nonce: code.nonce,
      codeChallenge: code.codeChallenge,
      codeChallengeMethod: code.codeChallengeMethod,
      tokenHash: code.tokenHash,
      expiresAt: code.expiresAt,
      consumedAt: code.consumedAt,
      createdAt: code.createdAt
    });
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

const toUser = (row: typeof users.$inferSelect): User => ({
  id: row.id,
  tenantId: row.tenantId,
  email: row.email,
  emailVerified: row.emailVerified,
  username: row.username,
  displayName: row.displayName,
  status: row.status as User["status"],
  createdAt: row.createdAt,
  updatedAt: row.updatedAt
});

const toInvitation = (row: typeof userInvitations.$inferSelect): UserInvitation => ({
  id: row.id,
  tenantId: row.tenantId,
  userId: row.userId,
  tokenHash: row.tokenHash,
  purpose: row.purpose as UserInvitation["purpose"],
  expiresAt: row.expiresAt,
  consumedAt: row.consumedAt,
  createdAt: row.createdAt
});

const toPasswordCredential = (
  row: typeof userPasswordCredentials.$inferSelect
): PasswordCredential => ({
  id: row.id,
  tenantId: row.tenantId,
  userId: row.userId,
  passwordHash: row.passwordHash,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt
});

const isConstraintConflictError = (error: unknown) =>
  error instanceof Error &&
  error.message.toLowerCase().includes("constraint failed");

export class D1UserRepository implements UserRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async activateUserByInvitationToken({
    createPasswordHash,
    now,
    tokenHash
  }: ActivateUserByInvitationTokenInput): Promise<ActivateUserByInvitationTokenResult> {
    return this.db.transaction(async (tx) => {
      const [invitationRow] = await tx
        .select()
        .from(userInvitations)
        .where(eq(userInvitations.tokenHash, tokenHash))
        .limit(1);

      if (invitationRow === undefined) {
        return { kind: "not_found" };
      }

      if (invitationRow.consumedAt !== null) {
        return { kind: "already_used" };
      }

      if (new Date(invitationRow.expiresAt).getTime() <= now.getTime()) {
        return { kind: "expired" };
      }

      const [userRow] = await tx
        .select()
        .from(users)
        .where(and(eq(users.tenantId, invitationRow.tenantId), eq(users.id, invitationRow.userId)))
        .limit(1);

      if (userRow === undefined) {
        return { kind: "not_found" };
      }

      if (userRow.status === "disabled") {
        return { kind: "user_disabled" };
      }

      const [credentialRow] = await tx
        .select()
        .from(userPasswordCredentials)
        .where(
          and(
            eq(userPasswordCredentials.tenantId, invitationRow.tenantId),
            eq(userPasswordCredentials.userId, invitationRow.userId)
          )
        )
        .limit(1);

      if (userRow.status !== "provisioned" || credentialRow !== undefined) {
        return { kind: "already_initialized" };
      }

      try {
        const updatedAt = now.toISOString();
        const passwordHash = await createPasswordHash();
        const credential: PasswordCredential = {
          id: crypto.randomUUID(),
          tenantId: invitationRow.tenantId,
          userId: invitationRow.userId,
          passwordHash,
          createdAt: updatedAt,
          updatedAt
        };

        await tx
          .update(userInvitations)
          .set({ consumedAt: updatedAt })
          .where(eq(userInvitations.id, invitationRow.id));
        await tx
          .update(users)
          .set({
            emailVerified: true,
            status: "active",
            updatedAt
          })
          .where(and(eq(users.tenantId, invitationRow.tenantId), eq(users.id, invitationRow.userId)));
        await tx.insert(userPasswordCredentials).values({
          id: credential.id,
          tenantId: credential.tenantId,
          userId: credential.userId,
          passwordHash: credential.passwordHash,
          createdAt: credential.createdAt,
          updatedAt: credential.updatedAt
        });

        return {
          kind: "activated",
          invitation: {
            ...toInvitation(invitationRow),
            consumedAt: updatedAt
          },
          user: {
            ...toUser(userRow),
            emailVerified: true,
            status: "active",
            updatedAt
          },
          credential
        };
      } catch (error) {
        const [latestInvitationRow] = await tx
          .select()
          .from(userInvitations)
          .where(eq(userInvitations.id, invitationRow.id))
          .limit(1);

        if (latestInvitationRow?.consumedAt !== null && latestInvitationRow !== undefined) {
          return { kind: "already_used" };
        }

        const [latestUserRow] = await tx
          .select()
          .from(users)
          .where(and(eq(users.tenantId, invitationRow.tenantId), eq(users.id, invitationRow.userId)))
          .limit(1);

        if (latestUserRow === undefined) {
          return { kind: "not_found" };
        }

        if (latestUserRow.status === "disabled") {
          return { kind: "user_disabled" };
        }

        const [latestCredentialRow] = await tx
          .select()
          .from(userPasswordCredentials)
          .where(
            and(
              eq(userPasswordCredentials.tenantId, invitationRow.tenantId),
              eq(userPasswordCredentials.userId, invitationRow.userId)
            )
          )
          .limit(1);

        if (latestUserRow.status !== "provisioned" || latestCredentialRow !== undefined) {
          return { kind: "already_initialized" };
        }

        if (isConstraintConflictError(error)) {
          return { kind: "already_initialized" };
        }

        throw error;
      }
    });
  }

  async createProvisionedUserWithInvitation({
    invitation,
    user
  }: CreateProvisionedUserWithInvitationInput): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.insert(users).values({
        id: user.id,
        tenantId: user.tenantId,
        email: user.email,
        emailVerified: user.emailVerified,
        username: user.username,
        displayName: user.displayName,
        status: user.status,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      });
      await tx.insert(userInvitations).values({
        id: invitation.id,
        tenantId: invitation.tenantId,
        userId: invitation.userId,
        tokenHash: invitation.tokenHash,
        purpose: invitation.purpose,
        expiresAt: invitation.expiresAt,
        consumedAt: invitation.consumedAt,
        createdAt: invitation.createdAt
      });
    });
  }

  async findAuthMethodPolicyByTenantId(tenantId: string): Promise<TenantAuthMethodPolicy | null> {
    const [row] = await this.db
      .select()
      .from(tenantAuthMethodPolicies)
      .where(eq(tenantAuthMethodPolicies.tenantId, tenantId))
      .limit(1);

    return row === undefined
      ? null
      : {
          tenantId: row.tenantId,
          password: {
            enabled: row.passwordEnabled
          },
          emailMagicLink: {
            enabled: row.emailMagicLinkEnabled
          },
          passkey: {
            enabled: row.passkeyEnabled
          }
        };
  }

  async findPasswordCredentialByUserId(
    tenantId: string,
    userId: string
  ): Promise<PasswordCredential | null> {
    const [row] = await this.db
      .select()
      .from(userPasswordCredentials)
      .where(and(eq(userPasswordCredentials.tenantId, tenantId), eq(userPasswordCredentials.userId, userId)))
      .limit(1);

    return row === undefined ? null : toPasswordCredential(row);
  }

  async findUserByEmail(tenantId: string, email: string): Promise<User | null> {
    const [row] = await this.db
      .select()
      .from(users)
      .where(and(eq(users.tenantId, tenantId), eq(users.email, email)))
      .limit(1);

    return row === undefined ? null : toUser(row);
  }

  async findUserById(tenantId: string, userId: string): Promise<User | null> {
    const [row] = await this.db
      .select()
      .from(users)
      .where(and(eq(users.tenantId, tenantId), eq(users.id, userId)))
      .limit(1);

    return row === undefined ? null : toUser(row);
  }

  async findUserByUsername(tenantId: string, username: string): Promise<User | null> {
    const [row] = await this.db
      .select()
      .from(users)
      .where(and(eq(users.tenantId, tenantId), eq(users.username, username)))
      .limit(1);

    return row === undefined ? null : toUser(row);
  }

  async updateUser(user: User): Promise<void> {
    await this.db
      .update(users)
      .set({
        email: user.email,
        emailVerified: user.emailVerified,
        username: user.username,
        displayName: user.displayName,
        status: user.status,
        updatedAt: user.updatedAt
      })
      .where(and(eq(users.tenantId, user.tenantId), eq(users.id, user.id)));
  }

  async upsertPasswordCredential(credential: PasswordCredential): Promise<void> {
    await this.db
      .insert(userPasswordCredentials)
      .values({
        id: credential.id,
        tenantId: credential.tenantId,
        userId: credential.userId,
        passwordHash: credential.passwordHash,
        createdAt: credential.createdAt,
        updatedAt: credential.updatedAt
      })
      .onConflictDoUpdate({
        target: userPasswordCredentials.userId,
        set: {
          passwordHash: credential.passwordHash,
          updatedAt: credential.updatedAt
        }
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
    authorizationCodeRepository: new D1AuthorizationCodeRepository(db),
    clientRepository: new D1ClientRepository(db),
    keyMaterialStore,
    keyRepository,
    loginChallengeRepository: new D1LoginChallengeRepository(db),
    userRepository: new D1UserRepository(db),
    signer,
    registrationAccessTokenRepository: new KvRegistrationAccessTokenRepository(
      config.registrationTokensKv
    ),
    tenantRepository: new D1TenantRepository(db),
    close: async () => undefined
  };
};
