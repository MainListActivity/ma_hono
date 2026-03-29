import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/d1";

import type { AuditRepository } from "../../../domain/audit/repository";
import type { AuditEvent } from "../../../domain/audit/types";
import type { AdminRepository } from "../../../domain/admin-auth/repository";
import type { AdminSession, AdminUser } from "../../../domain/admin-auth/types";
import type { RegistrationAccessTokenRepository } from "../../../domain/clients/registration-access-token-repository";
import type { AccessTokenClaimsRepository } from "../../../domain/clients/access-token-claims-repository";
import type { AccessTokenCustomClaim } from "../../../domain/clients/access-token-claims-types";
import type {
  ClientAuthMethodPolicyRepository,
  ClientRepository
} from "../../../domain/clients/repository";
import type {
  Client,
  ClientAuthMethodPolicy
} from "../../../domain/clients/types";
import type {
  AuthorizationCodeRepository,
  LoginChallengeRepository
} from "../../../domain/authorization/repository";
import type { AuthenticationLoginChallengeRepository } from "../../../domain/authentication/login-challenge-repository";
import type {
  AuthorizationCode,
  LoginChallenge
} from "../../../domain/authorization/types";
import type {
  RefreshTokenRecord,
  RefreshTokenRepository
} from "../../../domain/tokens/refresh-token-repository";
import type {
  PasskeyCredential,
  PasskeyRepository
} from "../../../domain/authentication/passkey-repository";
import type { KeyMaterialStore } from "../../../domain/keys/key-material-store";
import type { KeyRepository } from "../../../domain/keys/repository";
import { createSigningKeySigner, type SigningKeySigner } from "../../../domain/keys/signer";
import type { SigningKey, SigningKeyMaterial } from "../../../domain/keys/types";
import type { RuntimeConfig } from "../../../config/env";
import type { TotpCredential, TotpRepository } from "../../../domain/mfa/totp-repository";
import type {
  MfaPasskeyChallenge,
  MfaPasskeyChallengeRepository
} from "../../../domain/mfa/mfa-passkey-challenge-repository";
import type { TenantRepository, TenantUpdateInput } from "../../../domain/tenants/repository";
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
  clientAccessTokenClaims,
  clientAuthMethodPolicies,
  emailLoginTokens,
  loginChallenges,
  oidcClients,
  refreshTokens,
  signingKeys,
  tenantAuthMethodPolicies,
  tenantIssuers,
  tenants,
  userInvitations,
  userPasswordCredentials,
  users,
  webauthnCredentials,
  totpCredentials,
  mfaPasskeyChallenges
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

    const insertTenant = this.db.insert(tenants).values({
      id: tenant.id,
      slug: tenant.slug,
      displayName: tenant.displayName,
      status: tenant.status,
      createdAt: now,
      updatedAt: now
    });

    if (tenant.issuers.length > 0) {
      const insertIssuers = this.db.insert(tenantIssuers).values(
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
      await this.db.batch([insertTenant, insertIssuers]);
    } else {
      await insertTenant;
    }
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

  async list(): Promise<Tenant[]> {
    const tenantRows = await this.db.select().from(tenants);
    if (tenantRows.length === 0) return [];

    const issuerRows = await this.db.select().from(tenantIssuers);

    return tenantRows.map((tenantRow) =>
      toTenant(
        tenantRow,
        issuerRows.filter((r) => r.tenantId === tenantRow.id)
      )
    );
  }

  async update(id: string, input: TenantUpdateInput): Promise<void> {
    const now = new Date().toISOString();

    if (input.displayName !== undefined || input.status !== undefined) {
      await this.db
        .update(tenants)
        .set({
          ...(input.displayName !== undefined ? { displayName: input.displayName } : {}),
          ...(input.status !== undefined ? { status: input.status } : {}),
          updatedAt: now
        })
        .where(eq(tenants.id, id));
    }

    if (input.primaryIssuerUrl !== undefined) {
      await this.db
        .update(tenantIssuers)
        .set({ issuerUrl: input.primaryIssuerUrl, updatedAt: now })
        .where(and(eq(tenantIssuers.tenantId, id), eq(tenantIssuers.isPrimary, true)));
    }
  }

  async delete(id: string): Promise<void> {
    await this.db.delete(tenants).where(eq(tenants.id, id));
  }
}

export class D1KeyRepository implements KeyRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async listActiveKeysForTenant(tenantId: string): Promise<SigningKey[]> {
    const rows = await this.db
      .select()
      .from(signingKeys)
      .where(and(eq(signingKeys.status, "active"), eq(signingKeys.tenantId, tenantId)))
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

  async retireActiveKeysForTenant(tenantId: string, retiredAt: string): Promise<void> {
    await this.db
      .update(signingKeys)
      .set({ status: "retired", retireAt: retiredAt })
      .where(and(eq(signingKeys.status, "active"), eq(signingKeys.tenantId, tenantId)));
  }
}

export const rotateSigningKeysForTenants = async ({
  db,
  signer,
  tenantRepository
}: {
  db: ReturnType<typeof drizzle>;
  signer: SigningKeySigner;
  tenantRepository: TenantRepository;
}) => {
  const retiredAt = new Date().toISOString();

  await db
    .update(signingKeys)
    .set({
      status: "retired",
      retireAt: retiredAt
    })
    .where(eq(signingKeys.status, "active"));

  const allTenants = await tenantRepository.list();

  for (const tenant of allTenants) {
    await signer.ensureActiveSigningKeyMaterial(tenant.id);
  }
};

export const ensureTenantSigningKeys = async ({
  signer,
  tenantRepository
}: {
  signer: SigningKeySigner;
  tenantRepository: TenantRepository;
}) => {
  const allTenants = await tenantRepository.list();

  for (const tenant of allTenants) {
    const existingMaterial = await signer.loadActiveSigningKeyMaterial(tenant.id);

    if (existingMaterial === null) {
      await signer.ensureActiveSigningKeyMaterial(tenant.id);
    }
  }
};

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
      clientProfile: client.clientProfile,
      accessTokenAudience: client.accessTokenAudience,
      tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
      redirectUris: client.redirectUris,
      grantTypes: client.grantTypes,
      responseTypes: client.responseTypes,
      createdBy: "dynamic_registration",
      createdAt: now,
      updatedAt: now
    });
  }

  async update(client: Client): Promise<void> {
    const now = new Date().toISOString();
    await this.db
      .update(oidcClients)
      .set({
        clientName: client.clientName,
        applicationType: client.applicationType,
        clientProfile: client.clientProfile,
        tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
        redirectUris: client.redirectUris,
        grantTypes: client.grantTypes,
        responseTypes: client.responseTypes,
        accessTokenAudience: client.accessTokenAudience,
        updatedAt: now
      })
      .where(eq(oidcClients.clientId, client.clientId));
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
          consentPolicy: row.consentPolicy as Client["consentPolicy"],
          clientProfile: row.clientProfile as Client["clientProfile"],
          accessTokenAudience: row.accessTokenAudience
        };
  }

  async listByTenantId(tenantId: string): Promise<Client[]> {
    const rows = await this.db
      .select()
      .from(oidcClients)
      .where(eq(oidcClients.tenantId, tenantId));

    return rows.map((row) => ({
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
      consentPolicy: row.consentPolicy as Client["consentPolicy"],
      clientProfile: row.clientProfile as Client["clientProfile"],
      accessTokenAudience: row.accessTokenAudience
    }));
  }
}

class D1AccessTokenClaimsRepository implements AccessTokenClaimsRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async createMany(claims: AccessTokenCustomClaim[]): Promise<void> {
    if (claims.length === 0) {
      return;
    }

    await this.db.insert(clientAccessTokenClaims).values(
      claims.map((claim) => ({
        id: claim.id,
        clientId: claim.clientId,
        tenantId: claim.tenantId,
        claimName: claim.claimName,
        sourceType: claim.sourceType,
        fixedValue: claim.fixedValue,
        userField: claim.userField,
        createdAt: claim.createdAt,
        updatedAt: claim.updatedAt
      }))
    );
  }

  async replaceAllForClient(
    clientId: string,
    claims: AccessTokenCustomClaim[]
  ): Promise<void> {
    const deleteOp = this.db
      .delete(clientAccessTokenClaims)
      .where(eq(clientAccessTokenClaims.clientId, clientId));

    if (claims.length === 0) {
      await deleteOp;
      return;
    }

    const insertOp = this.db.insert(clientAccessTokenClaims).values(
      claims.map((claim) => ({
        id: claim.id,
        clientId: claim.clientId,
        tenantId: claim.tenantId,
        claimName: claim.claimName,
        sourceType: claim.sourceType,
        fixedValue: claim.fixedValue,
        userField: claim.userField,
        createdAt: claim.createdAt,
        updatedAt: claim.updatedAt
      }))
    );

    await this.db.batch([deleteOp, insertOp]);
  }

  async listByClientId(clientId: string): Promise<AccessTokenCustomClaim[]> {
    const rows = await this.db
      .select()
      .from(clientAccessTokenClaims)
      .where(eq(clientAccessTokenClaims.clientId, clientId));

    return rows.map((row) => ({
      id: row.id,
      clientId: row.clientId,
      tenantId: row.tenantId,
      claimName: row.claimName,
      sourceType: row.sourceType as AccessTokenCustomClaim["sourceType"],
      fixedValue: row.fixedValue,
      userField: row.userField as AccessTokenCustomClaim["userField"],
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    }));
  }

  async listByClientIdAndTenantId(
    clientId: string,
    tenantId: string
  ): Promise<AccessTokenCustomClaim[]> {
    const rows = await this.db
      .select()
      .from(clientAccessTokenClaims)
      .where(
        and(
          eq(clientAccessTokenClaims.clientId, clientId),
          eq(clientAccessTokenClaims.tenantId, tenantId)
        )
      );

    return rows.map((row) => ({
      id: row.id,
      clientId: row.clientId,
      tenantId: row.tenantId,
      claimName: row.claimName,
      sourceType: row.sourceType as AccessTokenCustomClaim["sourceType"],
      fixedValue: row.fixedValue,
      userField: row.userField as AccessTokenCustomClaim["userField"],
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    }));
  }
}

class D1LoginChallengeRepository
  implements LoginChallengeRepository, AuthenticationLoginChallengeRepository
{
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(challenge: LoginChallenge): Promise<void> {
    await this.db.insert(loginChallenges).values({
      id: challenge.id,
      tenantId: challenge.tenantId,
      issuer: challenge.issuer,
      clientId: challenge.clientId,
      authMethod: challenge.authMethod ?? null,
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

  async consume(challengeId: string, consumedAt: string): Promise<boolean> {
    const [row] = await this.db
      .update(loginChallenges)
      .set({
        consumedAt
      })
      .where(
        and(
          eq(loginChallenges.id, challengeId),
          isNull(loginChallenges.consumedAt)
        )
      )
      .returning({
        id: loginChallenges.id
      });

    return row !== undefined;
  }

  async findByTokenHash(tokenHash: string): Promise<LoginChallenge | null> {
    const [row] = await this.db
      .select()
      .from(loginChallenges)
      .where(
        and(
          eq(loginChallenges.tokenHash, tokenHash),
          isNull(loginChallenges.consumedAt)
        )
      )
      .limit(1);

    if (row === undefined) {
      return null;
    }

    return {
      id: row.id,
      tenantId: row.tenantId,
      issuer: row.issuer,
      clientId: row.clientId,
      authMethod: row.authMethod as LoginChallenge["authMethod"],
      redirectUri: row.redirectUri,
      scope: row.scope,
      state: row.state,
      codeChallenge: row.codeChallenge,
      codeChallengeMethod: row.codeChallengeMethod as LoginChallenge["codeChallengeMethod"],
      nonce: row.nonce,
      tokenHash: row.tokenHash,
      expiresAt: row.expiresAt,
      consumedAt: row.consumedAt,
      authenticatedUserId: row.authenticatedUserId,
      mfaState: row.mfaState as LoginChallenge["mfaState"],
      mfaAttemptCount: row.mfaAttemptCount,
      enrollmentAttemptCount: row.enrollmentAttemptCount,
      totpEnrollmentSecretEncrypted: row.totpEnrollmentSecretEncrypted,
      createdAt: row.createdAt
    };
  }

  async setMfaState(
    challengeId: string,
    authenticatedUserId: string,
    mfaState: LoginChallenge["mfaState"],
    authMethod?: LoginChallenge["authMethod"]
  ): Promise<void> {
    await this.db.update(loginChallenges)
      .set({
        authenticatedUserId,
        mfaState,
        ...(authMethod === undefined ? {} : { authMethod })
      })
      .where(eq(loginChallenges.id, challengeId));
  }

  async incrementMfaAttemptCount(challengeId: string): Promise<number> {
    // Atomic SQL increment — avoids read-then-write race condition under concurrent requests
    await this.db.update(loginChallenges)
      .set({ mfaAttemptCount: sql`${loginChallenges.mfaAttemptCount} + 1` })
      .where(eq(loginChallenges.id, challengeId));
    const [row] = await this.db.select({ count: loginChallenges.mfaAttemptCount })
      .from(loginChallenges).where(eq(loginChallenges.id, challengeId)).limit(1);
    return row?.count ?? 0;
  }

  async incrementEnrollmentAttemptCount(challengeId: string): Promise<number> {
    // Atomic SQL increment — avoids read-then-write race condition under concurrent requests
    await this.db.update(loginChallenges)
      .set({ enrollmentAttemptCount: sql`${loginChallenges.enrollmentAttemptCount} + 1` })
      .where(eq(loginChallenges.id, challengeId));
    const [row] = await this.db.select({ count: loginChallenges.enrollmentAttemptCount })
      .from(loginChallenges).where(eq(loginChallenges.id, challengeId)).limit(1);
    return row?.count ?? 0;
  }

  async satisfyMfa(challengeId: string): Promise<void> {
    await this.db.update(loginChallenges).set({ mfaState: "satisfied" })
      .where(eq(loginChallenges.id, challengeId));
  }

  async setTotpEnrollmentSecret(challengeId: string, secretEncrypted: string): Promise<void> {
    await this.db.update(loginChallenges).set({ totpEnrollmentSecretEncrypted: secretEncrypted })
      .where(eq(loginChallenges.id, challengeId));
  }

  async completeEnrollment(challengeId: string): Promise<void> {
    await this.db.update(loginChallenges)
      .set({ mfaState: "satisfied", totpEnrollmentSecretEncrypted: null })
      .where(eq(loginChallenges.id, challengeId));
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
      authMethod: code.authMethod ?? null,
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

  async findByTokenHash(tokenHash: string): Promise<AuthorizationCode | null> {
    const [row] = await this.db
      .select()
      .from(authorizationCodes)
      .where(
        and(
          eq(authorizationCodes.tokenHash, tokenHash),
          isNull(authorizationCodes.consumedAt)
        )
      )
      .limit(1);

    if (row === undefined) {
      return null;
    }

    return {
      id: row.id,
      tenantId: row.tenantId,
      issuer: row.issuer,
      clientId: row.clientId,
      authMethod: row.authMethod as AuthorizationCode["authMethod"],
      userId: row.userId,
      redirectUri: row.redirectUri,
      scope: row.scope,
      nonce: row.nonce,
      codeChallenge: row.codeChallenge,
      codeChallengeMethod: row.codeChallengeMethod as AuthorizationCode["codeChallengeMethod"],
      tokenHash: row.tokenHash,
      expiresAt: row.expiresAt,
      consumedAt: row.consumedAt,
      createdAt: row.createdAt
    };
  }

  async consumeById(id: string, consumedAt: string): Promise<boolean> {
    const [row] = await this.db
      .update(authorizationCodes)
      .set({
        consumedAt
      })
      .where(
        and(
          eq(authorizationCodes.id, id),
          isNull(authorizationCodes.consumedAt)
        )
      )
      .returning({ id: authorizationCodes.id });

    return row !== undefined;
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

const toClientAuthMethodPolicy = (
  row: typeof clientAuthMethodPolicies.$inferSelect
): ClientAuthMethodPolicy => ({
  clientId: row.clientId,
  tenantId: row.tenantId,
  password: {
    enabled: row.passwordEnabled,
    allowRegistration: row.passwordAllowRegistration,
    tokenTtlSeconds: row.passwordTokenTtlSeconds
  },
  emailMagicLink: {
    enabled: row.magicLinkEnabled,
    allowRegistration: row.magicLinkAllowRegistration,
    tokenTtlSeconds: row.magicLinkTokenTtlSeconds
  },
  passkey: {
    enabled: row.passkeyEnabled,
    allowRegistration: row.passkeyAllowRegistration,
    tokenTtlSeconds: row.passkeyTokenTtlSeconds
  },
  google: { enabled: row.googleEnabled, tokenTtlSeconds: row.googleTokenTtlSeconds },
  apple: { enabled: row.appleEnabled, tokenTtlSeconds: row.appleTokenTtlSeconds },
  facebook: { enabled: row.facebookEnabled, tokenTtlSeconds: row.facebookTokenTtlSeconds },
  wechat: { enabled: row.wechatEnabled, tokenTtlSeconds: row.wechatTokenTtlSeconds },
  mfaRequired: row.mfaRequired
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
    const [invitationRow] = await this.db
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

    const [[userRow], [credentialRow]] = await this.db.batch([
      this.db
        .select()
        .from(users)
        .where(and(eq(users.tenantId, invitationRow.tenantId), eq(users.id, invitationRow.userId)))
        .limit(1),
      this.db
        .select()
        .from(userPasswordCredentials)
        .where(
          and(
            eq(userPasswordCredentials.tenantId, invitationRow.tenantId),
            eq(userPasswordCredentials.userId, invitationRow.userId)
          )
        )
        .limit(1)
    ]);

    if (userRow === undefined) {
      return { kind: "not_found" };
    }

    if (userRow.status === "disabled") {
      return { kind: "user_disabled" };
    }

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

      await this.db.batch([
        this.db
          .update(userInvitations)
          .set({ consumedAt: updatedAt })
          .where(eq(userInvitations.id, invitationRow.id)),
        this.db
          .update(users)
          .set({
            emailVerified: true,
            status: "active",
            updatedAt
          })
          .where(and(eq(users.tenantId, invitationRow.tenantId), eq(users.id, invitationRow.userId))),
        this.db.insert(userPasswordCredentials).values({
          id: credential.id,
          tenantId: credential.tenantId,
          userId: credential.userId,
          passwordHash: credential.passwordHash,
          createdAt: credential.createdAt,
          updatedAt: credential.updatedAt
        })
      ]);

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
      // Re-check state to give a precise error for concurrent activation
      const [[latestInvitationRow], [latestUserRow], [latestCredentialRow]] = await this.db.batch([
        this.db
          .select()
          .from(userInvitations)
          .where(eq(userInvitations.id, invitationRow.id))
          .limit(1),
        this.db
          .select()
          .from(users)
          .where(and(eq(users.tenantId, invitationRow.tenantId), eq(users.id, invitationRow.userId)))
          .limit(1),
        this.db
          .select()
          .from(userPasswordCredentials)
          .where(
            and(
              eq(userPasswordCredentials.tenantId, invitationRow.tenantId),
              eq(userPasswordCredentials.userId, invitationRow.userId)
            )
          )
          .limit(1)
      ]);

      if (latestInvitationRow !== undefined && latestInvitationRow.consumedAt !== null) {
        return { kind: "already_used" };
      }

      if (latestUserRow === undefined) {
        return { kind: "not_found" };
      }

      if (latestUserRow.status === "disabled") {
        return { kind: "user_disabled" };
      }

      if (latestUserRow.status !== "provisioned" || latestCredentialRow !== undefined) {
        return { kind: "already_initialized" };
      }

      if (isConstraintConflictError(error)) {
        return { kind: "already_initialized" };
      }

      throw error;
    }
  }

  async createProvisionedUserWithInvitation({
    invitation,
    user
  }: CreateProvisionedUserWithInvitationInput): Promise<void> {
    await this.db.batch([
      this.db.insert(users).values({
        id: user.id,
        tenantId: user.tenantId,
        email: user.email,
        emailVerified: user.emailVerified,
        username: user.username,
        displayName: user.displayName,
        status: user.status,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }),
      this.db.insert(userInvitations).values({
        id: invitation.id,
        tenantId: invitation.tenantId,
        userId: invitation.userId,
        tokenHash: invitation.tokenHash,
        purpose: invitation.purpose,
        expiresAt: invitation.expiresAt,
        consumedAt: invitation.consumedAt,
        createdAt: invitation.createdAt
      })
    ]);
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

  async listByTenantId(tenantId: string): Promise<User[]> {
    const rows = await this.db
      .select()
      .from(users)
      .where(eq(users.tenantId, tenantId));

    return rows.map((row) => ({
      id: row.id,
      tenantId: row.tenantId,
      email: row.email,
      emailVerified: row.emailVerified,
      username: row.username,
      displayName: row.displayName,
      status: row.status as User["status"],
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    }));
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

class D1ClientAuthMethodPolicyRepository implements ClientAuthMethodPolicyRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(policy: ClientAuthMethodPolicy): Promise<void> {
    const now = new Date().toISOString();
    await this.db.insert(clientAuthMethodPolicies).values({
      clientId: policy.clientId,
      tenantId: policy.tenantId,
      passwordEnabled: policy.password.enabled,
      passwordAllowRegistration: policy.password.allowRegistration,
      passwordTokenTtlSeconds: policy.password.tokenTtlSeconds ?? 3600,
      magicLinkEnabled: policy.emailMagicLink.enabled,
      magicLinkAllowRegistration: policy.emailMagicLink.allowRegistration,
      magicLinkTokenTtlSeconds: policy.emailMagicLink.tokenTtlSeconds ?? 3600,
      passkeyEnabled: policy.passkey.enabled,
      passkeyAllowRegistration: policy.passkey.allowRegistration,
      passkeyTokenTtlSeconds: policy.passkey.tokenTtlSeconds ?? 3600,
      googleEnabled: policy.google.enabled,
      googleTokenTtlSeconds: policy.google.tokenTtlSeconds ?? 3600,
      appleEnabled: policy.apple.enabled,
      appleTokenTtlSeconds: policy.apple.tokenTtlSeconds ?? 3600,
      facebookEnabled: policy.facebook.enabled,
      facebookTokenTtlSeconds: policy.facebook.tokenTtlSeconds ?? 3600,
      wechatEnabled: policy.wechat.enabled,
      wechatTokenTtlSeconds: policy.wechat.tokenTtlSeconds ?? 3600,
      mfaRequired: policy.mfaRequired,
      createdAt: now,
      updatedAt: now
    });
  }

  async findByClientId(clientId: string): Promise<ClientAuthMethodPolicy | null> {
    const [row] = await this.db
      .select()
      .from(clientAuthMethodPolicies)
      .where(eq(clientAuthMethodPolicies.clientId, clientId))
      .limit(1);
    return row === undefined ? null : toClientAuthMethodPolicy(row);
  }

  async update(policy: ClientAuthMethodPolicy): Promise<void> {
    const now = new Date().toISOString();
    await this.db
      .update(clientAuthMethodPolicies)
      .set({
        passwordEnabled: policy.password.enabled,
        passwordAllowRegistration: policy.password.allowRegistration,
        passwordTokenTtlSeconds: policy.password.tokenTtlSeconds ?? 3600,
        magicLinkEnabled: policy.emailMagicLink.enabled,
        magicLinkAllowRegistration: policy.emailMagicLink.allowRegistration,
        magicLinkTokenTtlSeconds: policy.emailMagicLink.tokenTtlSeconds ?? 3600,
        passkeyEnabled: policy.passkey.enabled,
        passkeyAllowRegistration: policy.passkey.allowRegistration,
        passkeyTokenTtlSeconds: policy.passkey.tokenTtlSeconds ?? 3600,
        googleEnabled: policy.google.enabled,
        googleTokenTtlSeconds: policy.google.tokenTtlSeconds ?? 3600,
        appleEnabled: policy.apple.enabled,
        appleTokenTtlSeconds: policy.apple.tokenTtlSeconds ?? 3600,
        facebookEnabled: policy.facebook.enabled,
        facebookTokenTtlSeconds: policy.facebook.tokenTtlSeconds ?? 3600,
        wechatEnabled: policy.wechat.enabled,
        wechatTokenTtlSeconds: policy.wechat.tokenTtlSeconds ?? 3600,
        mfaRequired: policy.mfaRequired,
        updatedAt: now
      })
      .where(eq(clientAuthMethodPolicies.clientId, policy.clientId));
  }
}

class D1RefreshTokenRepository implements RefreshTokenRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(record: RefreshTokenRecord): Promise<void> {
    await this.db.insert(refreshTokens).values({
      id: record.id,
      tenantId: record.tenantId,
      issuer: record.issuer,
      clientId: record.clientId,
      userId: record.userId,
      scope: record.scope,
      authMethod: record.authMethod,
      tokenHash: record.tokenHash,
      absoluteExpiresAt: record.absoluteExpiresAt,
      consumedAt: record.consumedAt,
      parentTokenId: record.parentTokenId,
      replacedByTokenId: record.replacedByTokenId,
      createdAt: record.createdAt
    });
  }

  async findActiveByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const [row] = await this.db
      .select()
      .from(refreshTokens)
      .where(
        and(eq(refreshTokens.tokenHash, tokenHash), isNull(refreshTokens.consumedAt))
      )
      .limit(1);

    if (row === undefined) {
      return null;
    }

    return {
      id: row.id,
      tenantId: row.tenantId,
      issuer: row.issuer,
      clientId: row.clientId,
      userId: row.userId,
      scope: row.scope,
      authMethod: row.authMethod as RefreshTokenRecord["authMethod"],
      tokenHash: row.tokenHash,
      absoluteExpiresAt: row.absoluteExpiresAt,
      consumedAt: row.consumedAt,
      parentTokenId: row.parentTokenId,
      replacedByTokenId: row.replacedByTokenId,
      createdAt: row.createdAt
    };
  }

  async consume(
    id: string,
    consumedAt: string,
    replacedByTokenId: string | null = null
  ): Promise<boolean> {
    const [row] = await this.db
      .update(refreshTokens)
      .set({
        consumedAt,
        replacedByTokenId
      })
      .where(and(eq(refreshTokens.id, id), isNull(refreshTokens.consumedAt)))
      .returning({ id: refreshTokens.id });

    return row !== undefined;
  }
}

export class D1TotpRepository implements TotpRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(credential: TotpCredential): Promise<void> {
    await this.db.insert(totpCredentials).values({
      id: credential.id,
      tenantId: credential.tenantId,
      userId: credential.userId,
      secretEncrypted: credential.secretEncrypted,
      algorithm: credential.algorithm,
      digits: credential.digits,
      period: credential.period,
      lastUsedWindow: credential.lastUsedWindow,
      enrolledAt: credential.enrolledAt,
      createdAt: credential.createdAt
    });
  }

  async findByTenantAndUser(tenantId: string, userId: string): Promise<TotpCredential | null> {
    const [row] = await this.db
      .select()
      .from(totpCredentials)
      .where(
        and(
          eq(totpCredentials.tenantId, tenantId),
          eq(totpCredentials.userId, userId)
        )
      )
      .limit(1);
    if (row === undefined) return null;
    return {
      id: row.id,
      tenantId: row.tenantId,
      userId: row.userId,
      secretEncrypted: row.secretEncrypted,
      algorithm: row.algorithm,
      digits: row.digits,
      period: row.period,
      lastUsedWindow: row.lastUsedWindow,
      enrolledAt: row.enrolledAt,
      createdAt: row.createdAt
    };
  }

  async updateLastUsedWindow(id: string, lastUsedWindow: number): Promise<void> {
    await this.db
      .update(totpCredentials)
      .set({ lastUsedWindow })
      .where(eq(totpCredentials.id, id));
  }
}

export class D1MfaPasskeyChallengeRepository implements MfaPasskeyChallengeRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async create(challenge: MfaPasskeyChallenge): Promise<void> {
    await this.db.insert(mfaPasskeyChallenges).values({
      id: challenge.id,
      tenantId: challenge.tenantId,
      loginChallengeId: challenge.loginChallengeId,
      challengeHash: challenge.challengeHash,
      expiresAt: challenge.expiresAt,
      consumedAt: challenge.consumedAt,
      createdAt: challenge.createdAt
    });
  }

  async consumeByChallengeHash(
    challengeHash: string,
    consumedAt: string,
    now: string
  ): Promise<MfaPasskeyChallenge | null> {
    const result = await this.db
      .update(mfaPasskeyChallenges)
      .set({ consumedAt })
      .where(
        and(
          eq(mfaPasskeyChallenges.challengeHash, challengeHash),
          isNull(mfaPasskeyChallenges.consumedAt),
          sql`${mfaPasskeyChallenges.expiresAt} > ${now}`
        )
      )
      .returning();

    return result[0] === undefined
      ? null
      : {
          id: result[0].id,
          tenantId: result[0].tenantId,
          loginChallengeId: result[0].loginChallengeId,
          challengeHash: result[0].challengeHash,
          expiresAt: result[0].expiresAt,
          consumedAt: result[0].consumedAt,
          createdAt: result[0].createdAt
        };
  }
}

export class D1PasskeyRepository implements PasskeyRepository {
  constructor(private readonly db: ReturnType<typeof drizzle>) {}

  async createEnrollmentSession(): Promise<void> {
    // TODO: Implement passkey enrollment sessions
  }

  async findEnrollmentSessionById(): Promise<null> {
    // TODO: Implement passkey enrollment sessions
    return null;
  }

  async consumeEnrollmentSession(): Promise<false> {
    // TODO: Implement passkey enrollment sessions
    return false;
  }

  async createCredential(credential: PasskeyCredential): Promise<void> {
    await this.db.insert(webauthnCredentials).values({
      id: credential.id,
      tenantId: credential.tenantId,
      userId: credential.userId,
      credentialId: credential.credentialId,
      publicKey: credential.publicKeyCbor,
      counter: credential.signCount,
      transports: null,
      deviceType: "",
      backedUp: false,
      createdAt: credential.createdAt,
      updatedAt: credential.updatedAt
    });
  }

  async findCredentialByCredentialId(tenantId: string, credentialId: string): Promise<PasskeyCredential | null> {
    const [row] = await this.db
      .select()
      .from(webauthnCredentials)
      .where(
        and(
          eq(webauthnCredentials.tenantId, tenantId),
          eq(webauthnCredentials.credentialId, credentialId)
        )
      )
      .limit(1);

    if (row === undefined) return null;
    return {
      id: row.id,
      tenantId: row.tenantId,
      userId: row.userId,
      credentialId: row.credentialId,
      publicKeyCbor: row.publicKey,
      signCount: row.counter,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    };
  }

  async updateCredentialSignCount(id: string, signCount: number): Promise<void> {
    await this.db
      .update(webauthnCredentials)
      .set({ counter: signCount })
      .where(eq(webauthnCredentials.id, id));
  }

  async listCredentialsByUserId(tenantId: string, userId: string): Promise<PasskeyCredential[]> {
    const rows = await this.db
      .select()
      .from(webauthnCredentials)
      .where(
        and(
          eq(webauthnCredentials.tenantId, tenantId),
          eq(webauthnCredentials.userId, userId)
        )
      );

    return rows.map(r => ({
      id: r.id,
      tenantId: r.tenantId,
      userId: r.userId,
      credentialId: r.credentialId,
      publicKeyCbor: r.publicKey,
      signCount: r.counter,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt
    }));
  }

  async createAssertionSession(): Promise<void> {
    // TODO: Implement passkey assertion sessions
  }

  async findAssertionSessionById(): Promise<null> {
    // TODO: Implement passkey assertion sessions
    return null;
  }

  async consumeAssertionSession(): Promise<false> {
    // TODO: Implement passkey assertion sessions
    return false;
  }
}

export const createRuntimeRepositories = async (config: RuntimeConfig) => {
  const db = drizzle(config.db, {
    schema: {
      adminUsers,
      auditEvents,
      authorizationCodes,
      clientAccessTokenClaims,
      clientAuthMethodPolicies,
      emailLoginTokens,
      loginChallenges,
      oidcClients,
      refreshTokens,
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
  const tenantRepository = new D1TenantRepository(db);
  const signingKeyBootstrapper = new D1SigningKeyBootstrapper(db, keyMaterialStore);
  const signer = createSigningKeySigner({
    bootstrapSigningKey: signingKeyBootstrapper.bootstrapSigningKey.bind(signingKeyBootstrapper),
    keyMaterialStore,
    keyRepository
  });

  await ensureTenantSigningKeys({
    signer,
    tenantRepository
  });

  const loginChallengeRepository = new D1LoginChallengeRepository(db);

  return {
    adminRepository: new D1KvAdminRepository(db, config.adminSessionsKv),
    auditRepository: new D1AuditRepository(db),
    authorizationCodeRepository: new D1AuthorizationCodeRepository(db),
    accessTokenClaimsRepository: new D1AccessTokenClaimsRepository(db),
    clientAuthMethodPolicyRepository: new D1ClientAuthMethodPolicyRepository(db),
    clientRepository: new D1ClientRepository(db),
    keyMaterialStore,
    keyRepository,
    loginChallengeRepository,
    authenticationLoginChallengeRepository: loginChallengeRepository,
    userRepository: new D1UserRepository(db),
    signer,
    registrationAccessTokenRepository: new KvRegistrationAccessTokenRepository(
      config.registrationTokensKv
    ),
    refreshTokenRepository: new D1RefreshTokenRepository(db),
    tenantRepository,
    totpRepository: new D1TotpRepository(db),
    mfaPasskeyChallengeRepository: new D1MfaPasskeyChallengeRepository(db),
    close: async () => undefined
  };
};
