import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import { ZodError } from "zod";
import { createLocalJWKSet, jwtVerify } from "jose";

import { authenticateWithPassword } from "../adapters/auth/local-auth/password-auth-service";
import { consumeMagicLink, requestMagicLink } from "../adapters/auth/local-auth/magic-link-service";
import { decryptTotpSecret, encryptTotpSecret } from "../adapters/auth/totp/totp-crypto";
import {
  finishPasskeyEnrollment,
  finishPasskeyLogin,
  startPasskeyEnrollment,
  startPasskeyLogin
} from "../adapters/auth/webauthn/webauthn-service";
import { generateTotpSecret, verifyTotpCode } from "../domain/mfa/totp-service";
import type { MagicLinkRepository } from "../domain/authentication/magic-link-repository";
import type { PasskeyRepository } from "../domain/authentication/passkey-repository";
import type { TotpRepository } from "../domain/mfa/totp-repository";
import type { MfaPasskeyChallengeRepository } from "../domain/mfa/mfa-passkey-challenge-repository";
import type { AuditRepository } from "../domain/audit/repository";
import { authenticateAdminSession, loginAdmin } from "../domain/admin-auth/service";
import type { AdminRepository } from "../domain/admin-auth/repository";
import type { AuthenticationLoginChallengeRepository } from "../domain/authentication/login-challenge-repository";
import type { BrowserSessionRepository } from "../domain/authentication/repository";
import {
  buildBrowserSessionCookie,
  createBrowserSession
} from "../domain/authentication/session-service";
import { authorizeRequest } from "../domain/authorization/authorize-request";
import type {
  AuthorizationCodeRepository,
  LoginChallengeRepository
} from "../domain/authorization/repository";
import type { AuthorizeSession } from "../domain/authorization/types";
import type { AccessTokenClaimsRepository } from "../domain/clients/access-token-claims-repository";
import type { RegistrationAccessTokenRepository } from "../domain/clients/registration-access-token-repository";
import { sha256Base64Url } from "../lib/hash";
import {
  registerClient,
  registerClientFromAdmin
} from "../domain/clients/register-client";
import type { AccessTokenCustomClaim, AccessTokenClaimUserField } from "../domain/clients/access-token-claims-types";
import { adminClientUpdateSchema } from "../domain/clients/admin-registration-schema";
import {
  DEFAULT_TOKEN_TTL_SECONDS,
  type ClientAuthMethodName,
  type ClientAuthMethodPolicy
} from "../domain/clients/types";
import type { ClientAuthMethodPolicyRepository, ClientRepository } from "../domain/clients/repository";
import { buildJwks } from "../domain/keys/jwks";
import type { SigningKeySigner } from "../domain/keys/signer";
import type { KeyRepository } from "../domain/keys/repository";
import type { TenantRepository } from "../domain/tenants/repository";
import { resolveIssuerContext, resolveIssuerContextBySlug } from "../domain/tenants/issuer-resolution";
import type { Tenant } from "../domain/tenants/types";
import { buildDiscoveryMetadata } from "../domain/oidc/discovery";
import { exchangeAuthorizationCode } from "../domain/tokens/token-service";
import type { RefreshTokenRepository } from "../domain/tokens/refresh-token-repository";
import { activateUser } from "../domain/users/activate-user";
import { hashPassword } from "../domain/users/passwords";
import { provisionUser } from "../domain/users/provision-user";
import type { UserRepository } from "../domain/users/repository";

class EmptyTenantRepository implements TenantRepository {
  async create(): Promise<void> {
    return;
  }

  async update(): Promise<void> {
    return;
  }

  async delete(): Promise<void> {
    return;
  }

  async findById(): Promise<null> {
    return null;
  }

  async findBySlug(): Promise<null> {
    return null;
  }

  async findByCustomDomain(): Promise<null> {
    return null;
  }

  async list(): Promise<[]> {
    return [];
  }
}

class EmptyKeyRepository implements KeyRepository {
  async listActiveKeysForTenant(): Promise<[]> {
    return [];
  }
  async retireActiveKeysForTenant(): Promise<void> {
    return;
  }
}

class EmptyClientRepository implements ClientRepository {
  async create(): Promise<void> {
    return;
  }

  async update(): Promise<void> {
    return;
  }

  async deleteByClientId(): Promise<void> {
    return;
  }

  async findByClientId(): Promise<null> {
    return null;
  }

  async listByTenantId(): Promise<[]> {
    return [];
  }
}

class EmptyClientAuthMethodPolicyRepository implements ClientAuthMethodPolicyRepository {
  async create(): Promise<void> { return; }
  async findByClientId(): Promise<null> { return null; }
  async update(): Promise<void> { return; }
}

class EmptyRegistrationAccessTokenRepository implements RegistrationAccessTokenRepository {
  async deleteByTokenHash(): Promise<void> {
    return;
  }

  async store(): Promise<void> {
    return;
  }
}

class EmptyAccessTokenClaimsRepository implements AccessTokenClaimsRepository {
  async createMany(): Promise<void> {
    return;
  }

  async replaceAllForClient(): Promise<void> {
    return;
  }

  async listByClientId(): Promise<AccessTokenCustomClaim[]> {
    return [];
  }

  async listByClientIdAndTenantId(): Promise<AccessTokenCustomClaim[]> {
    return [];
  }
}

class EmptyLoginChallengeRepository implements LoginChallengeRepository {
  async create(): Promise<void> {
    return;
  }
}

class EmptyAuthenticationLoginChallengeRepository
  implements AuthenticationLoginChallengeRepository
{
  async consume(): Promise<false> {
    return false;
  }

  async findByTokenHash(): Promise<null> {
    return null;
  }

  async setMfaState(
    _challengeId: string,
    _authenticatedUserId: string,
    _mfaState: import("../domain/authorization/types").LoginChallenge["mfaState"],
    _authMethod?: import("../domain/authorization/types").LoginChallenge["authMethod"]
  ): Promise<void> {
    return;
  }
  async incrementMfaAttemptCount(): Promise<number> { return 0; }
  async incrementEnrollmentAttemptCount(): Promise<number> { return 0; }
  async satisfyMfa(): Promise<void> { return; }
  async setTotpEnrollmentSecret(): Promise<void> { return; }
  async completeEnrollment(): Promise<void> { return; }
}

class EmptyBrowserSessionRepository implements BrowserSessionRepository {
  async create(): Promise<void> {
    return;
  }

  async findByTokenHash(): Promise<null> {
    return null;
  }
}

class EmptyAuthorizationCodeRepository implements AuthorizationCodeRepository {
  async create(): Promise<void> {
    return;
  }

  async findByTokenHash(): Promise<null> {
    return null;
  }

  async consumeById(): Promise<false> {
    return false;
  }
}

class EmptyRefreshTokenRepository implements RefreshTokenRepository {
  async create(): Promise<void> {
    return;
  }

  async findActiveByTokenHash(): Promise<null> {
    return null;
  }

  async consume(): Promise<false> {
    return false;
  }
}

class EmptyAdminRepository implements AdminRepository {
  async createSession(): Promise<void> {
    return;
  }

  async findSessionByTokenHash(): Promise<null> {
    return null;
  }

  async findUserByEmail(): Promise<null> {
    return null;
  }
}

class EmptyAuditRepository implements AuditRepository {
  async record(): Promise<void> {
    return;
  }
}

class EmptyMagicLinkRepository implements MagicLinkRepository {
  async create(): Promise<void> {
    return;
  }

  async findByTokenHash(): Promise<null> {
    return null;
  }

  async consume(): Promise<false> {
    return false;
  }
}

class EmptyPasskeyRepository implements PasskeyRepository {
  async createEnrollmentSession(): Promise<void> { return; }
  async findEnrollmentSessionById(): Promise<null> { return null; }
  async consumeEnrollmentSession(): Promise<false> { return false; }
  async createCredential(): Promise<void> { return; }
  async findCredentialByCredentialId(): Promise<null> { return null; }
  async updateCredentialSignCount(): Promise<void> { return; }
  async listCredentialsByUserId(): Promise<[]> { return []; }
  async createAssertionSession(): Promise<void> { return; }
  async findAssertionSessionById(): Promise<null> { return null; }
  async consumeAssertionSession(): Promise<false> { return false; }
}

class EmptyTotpRepository implements TotpRepository {
  async create(): Promise<void> { return; }
  async findByTenantAndUser(): Promise<null> { return null; }
  async updateLastUsedWindow(): Promise<void> { return; }
}

class EmptyMfaPasskeyChallengeRepository implements MfaPasskeyChallengeRepository {
  async create(): Promise<void> { return; }
  async consumeByChallengeHash(): Promise<null> { return null; }
}

class EmptyUserRepository implements UserRepository {
  async activateUserByInvitationToken() {
    return {
      kind: "not_found" as const
    };
  }

  async createProvisionedUserWithInvitation(): Promise<void> {
    return;
  }

  async findAuthMethodPolicyByTenantId(): Promise<null> {
    return null;
  }

  async findPasswordCredentialByUserId(): Promise<null> {
    return null;
  }

  async findUserByEmail(): Promise<null> {
    return null;
  }

  async findUserById(): Promise<null> {
    return null;
  }

  async findUserByUsername(): Promise<null> {
    return null;
  }

  async listByTenantId(): Promise<[]> {
    return [];
  }

  async updateUser(): Promise<void> {
    return;
  }

  async upsertPasswordCredential(): Promise<void> {
    return;
  }
}

export interface AppOptions {
  adminBootstrapPasswordHash: string;
  adminWhitelist: string[];
  adminRepository?: AdminRepository;
  auditRepository?: AuditRepository;
  authorizationCodeRepository?: AuthorizationCodeRepository;
  authorizeSessionResolver?: (context: Context) => Promise<AuthorizeSession | null> | AuthorizeSession | null;
  /** Root domain, e.g. "maplayer.top". Used to build login redirect URLs: https://auth.{authDomain}/login/{slug} */
  authDomain: string;
  browserSessionRepository?: BrowserSessionRepository;
  accessTokenClaimsRepository?: AccessTokenClaimsRepository;
  clientAuthMethodPolicyRepository?: ClientAuthMethodPolicyRepository;
  clientRepository?: ClientRepository;
  keyMaterialBucket?: R2Bucket;
  keyRepository?: KeyRepository;
  loginChallengeLookupRepository?: AuthenticationLoginChallengeRepository;
  loginChallengeRepository?: LoginChallengeRepository;
  magicLinkRepository?: MagicLinkRepository;
  managementApiToken: string;
  mfaPasskeyChallengeRepository: MfaPasskeyChallengeRepository;
  passkeyRepository?: PasskeyRepository;
  totpRepository: TotpRepository;
  totpEncryptionKey: Uint8Array;
  /** OIDC protocol hostname, e.g. "o.maplayer.top". Used to resolve issuer context and build issuer URLs. */
  oidcHost: string;
  registrationAccessTokenRepository?: RegistrationAccessTokenRepository;
  refreshTokenRepository?: RefreshTokenRepository;
  signer?: SigningKeySigner;
  tenantRepository?: TenantRepository;
  userRepository?: UserRepository;
}

export const createApp = (options: AppOptions) => {
  const app = new Hono();
  const adminBootstrapPasswordHash = options.adminBootstrapPasswordHash;
  const adminWhitelist = options.adminWhitelist;
  const authDomain = options.authDomain;
  const adminRepository = options.adminRepository ?? new EmptyAdminRepository();
  const auditRepository = options.auditRepository ?? new EmptyAuditRepository();
  const authorizationCodeRepository =
    options.authorizationCodeRepository ?? new EmptyAuthorizationCodeRepository();
  const authorizeSessionResolver = options.authorizeSessionResolver ?? (async () => null);
  const browserSessionRepository =
    options.browserSessionRepository ?? new EmptyBrowserSessionRepository();
  const accessTokenClaimsRepository =
    options.accessTokenClaimsRepository ?? new EmptyAccessTokenClaimsRepository();
  const clientAuthMethodPolicyRepository =
    options.clientAuthMethodPolicyRepository ?? new EmptyClientAuthMethodPolicyRepository();
  const clientRepository = options.clientRepository ?? new EmptyClientRepository();
  const keyMaterialBucket = options.keyMaterialBucket ?? null;
  const keyRepository = options.keyRepository ?? new EmptyKeyRepository();
  const loginChallengeLookupRepository =
    options.loginChallengeLookupRepository ?? new EmptyAuthenticationLoginChallengeRepository();
  const loginChallengeRepository =
    options.loginChallengeRepository ?? new EmptyLoginChallengeRepository();
  const magicLinkRepository = options.magicLinkRepository ?? new EmptyMagicLinkRepository();
  const managementApiToken = options.managementApiToken;
  const mfaPasskeyChallengeRepository = options.mfaPasskeyChallengeRepository;
  const passkeyRepository = options.passkeyRepository ?? new EmptyPasskeyRepository();
  const totpRepository = options.totpRepository;
  const totpEncryptionKey = options.totpEncryptionKey;
  const tenantRepository = options.tenantRepository ?? new EmptyTenantRepository();
  const userRepository = options.userRepository ?? new EmptyUserRepository();
  const signer = options.signer;
  const registrationAccessTokenRepository =
    options.registrationAccessTokenRepository ?? new EmptyRegistrationAccessTokenRepository();
  const refreshTokenRepository =
    options.refreshTokenRepository ?? new EmptyRefreshTokenRepository();
  const oidcHost = options.oidcHost;

  const resolveAllowedCorsOrigin = (origin: string) => {
    try {
      const url = new URL(origin);

      if (url.hostname === "localhost") {
        return origin;
      }

      if (url.hostname === "maplayer.top" || url.hostname.endsWith(".maplayer.top")) {
        return origin;
      }

      return null;
    } catch {
      return null;
    }
  };

  const tokenCors = cors({
    origin: (origin) => resolveAllowedCorsOrigin(origin),
    allowMethods: ["POST", "OPTIONS"],
    allowHeaders: ["Accept", "Authorization", "Content-Type"],
    maxAge: 86400
  });

  app.use("/token", tokenCors);
  app.use("/t/:tenant/token", tokenCors);

  /**
   * Resolves issuer context for login/passkey routes.
   * Platform-path requests arrive on auth.{domain}/login/:tenant — use slug param.
   * Custom-domain requests arrive on the tenant's own domain — use host-based resolution.
   */
  const resolveLoginIssuerContext = async (context: Context) => {
    const slug = context.req.param("tenant");

    if (slug) {
      return resolveIssuerContextBySlug({ slug, oidcHost, tenantRepository });
    }

    return resolveIssuerContext({ requestUrl: context.req.url, oidcHost, tenantRepository });
  };

  const createDefaultClientAuthMethodPolicy = (
    clientId: string,
    tenantId: string
  ): ClientAuthMethodPolicy => ({
    clientId,
    tenantId,
    password: {
      enabled: false,
      allowRegistration: false,
      tokenTtlSeconds: DEFAULT_TOKEN_TTL_SECONDS
    },
    emailMagicLink: {
      enabled: false,
      allowRegistration: false,
      tokenTtlSeconds: DEFAULT_TOKEN_TTL_SECONDS
    },
    passkey: {
      enabled: false,
      allowRegistration: false,
      tokenTtlSeconds: DEFAULT_TOKEN_TTL_SECONDS
    },
    google: { enabled: false, tokenTtlSeconds: DEFAULT_TOKEN_TTL_SECONDS },
    apple: { enabled: false, tokenTtlSeconds: DEFAULT_TOKEN_TTL_SECONDS },
    facebook: { enabled: false, tokenTtlSeconds: DEFAULT_TOKEN_TTL_SECONDS },
    wechat: { enabled: false, tokenTtlSeconds: DEFAULT_TOKEN_TTL_SECONDS },
    mfaRequired: false
  });

  const resolveTokenTtl = (value: unknown, fallback: number) =>
    typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;

  const policyToWire = (policy: ClientAuthMethodPolicy | null | undefined) =>
    policy == null ? null : {
      password: {
        enabled: policy.password.enabled,
        allow_registration: policy.password.allowRegistration,
        token_ttl_seconds: policy.password.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
      },
      magic_link: {
        enabled: policy.emailMagicLink.enabled,
        allow_registration: policy.emailMagicLink.allowRegistration,
        token_ttl_seconds: policy.emailMagicLink.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
      },
      passkey: {
        enabled: policy.passkey.enabled,
        allow_registration: policy.passkey.allowRegistration,
        token_ttl_seconds: policy.passkey.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
      },
      google: {
        enabled: policy.google.enabled,
        token_ttl_seconds: policy.google.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
      },
      apple: {
        enabled: policy.apple.enabled,
        token_ttl_seconds: policy.apple.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
      },
      facebook: {
        enabled: policy.facebook.enabled,
        token_ttl_seconds: policy.facebook.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
      },
      wechat: {
        enabled: policy.wechat.enabled,
        token_ttl_seconds: policy.wechat.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
      },
      mfa_required: policy.mfaRequired
    };

  const handleDiscovery = async (requestUrl: string) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl,
      oidcHost,
      tenantRepository
    });

    return issuerContext === null ? null : buildDiscoveryMetadata(issuerContext);
  };

  const buildClientErrorRedirectUrl = ({
    error,
    errorDescription,
    redirectUri,
    state
  }: {
    error: string;
    errorDescription?: string;
    redirectUri: string;
    state: string | null;
  }) => {
    const redirectUrl = new URL(redirectUri);

    redirectUrl.searchParams.set("error", error);
    if (errorDescription !== undefined) {
      redirectUrl.searchParams.set("error_description", errorDescription);
    }
    if (state !== null) {
      redirectUrl.searchParams.set("state", state);
    }

    return redirectUrl.toString();
  };

  const recordAuthorizeAuditEvent = async ({
    actorId,
    actorType,
    eventType,
    payload,
    targetId,
    tenantId
  }: {
    actorId: string | null;
    actorType: string;
    eventType: "oidc.authorization.deferred" | "oidc.authorization.failed" | "oidc.authorization.succeeded";
    payload: Record<string, unknown> | null;
    targetId: string | null;
    tenantId: string;
  }) =>
    auditRepository.record({
      id: crypto.randomUUID(),
      actorType,
      actorId,
      tenantId,
      eventType,
      targetType: "oidc_client",
      targetId,
      payload,
      occurredAt: new Date().toISOString()
    });

  const recordAuditEventBestEffort = async (event: {
    actorType: string;
    actorId: string | null;
    tenantId: string | null;
    eventType: string;
    targetType: string | null;
    targetId: string | null;
    payload: Record<string, unknown> | null;
  }) => {
    try {
      await auditRepository.record({
        id: crypto.randomUUID(),
        actorType: event.actorType,
        actorId: event.actorId,
        tenantId: event.tenantId,
        eventType: event.eventType,
        targetType: event.targetType,
        targetId: event.targetId,
        payload: event.payload,
        occurredAt: new Date().toISOString()
      });
    } catch {
      return;
    }
  };

  const isProvisionConflictError = (error: unknown) => {
    if (!(error instanceof Error)) {
      return false;
    }

    const message = error.message.toLowerCase();

    return (
      message.includes("already exists") ||
      message.includes("duplicate") ||
      message.includes("unique constraint failed")
    );
  };

  const handleAuthorize = async (context: Context) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl: context.req.url,
      oidcHost,
      tenantRepository
    });

    if (issuerContext === null) {
      return context.notFound();
    }

    const url = new URL(context.req.url);
    const resolvedSession = await authorizeSessionResolver(context);
    const session =
      resolvedSession !== null && resolvedSession.tenantId !== issuerContext.tenant.id
        ? null
        : resolvedSession;
    const result = await authorizeRequest({
      authorizationCodeRepository,
      clientRepository,
      issuerContext,
      loginChallengeRepository,
      request: {
        clientId: url.searchParams.get("client_id") ?? "",
        redirectUri: url.searchParams.get("redirect_uri") ?? "",
        responseType: url.searchParams.get("response_type") ?? "",
        scope: url.searchParams.get("scope") ?? "",
        state: url.searchParams.get("state"),
        nonce: url.searchParams.get("nonce"),
        codeChallenge: url.searchParams.get("code_challenge"),
        codeChallengeMethod: url.searchParams.get("code_challenge_method")
      },
      session
    });

    if (result.kind === "error") {
      await recordAuthorizeAuditEvent({
        actorType: session === null ? "anonymous" : "end_user",
        actorId: session?.userId ?? null,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.failed",
        targetId: result.clientId,
        payload: {
          client_id: result.clientId,
          reason: result.error,
          redirect_uri: result.redirectUri
        }
      });

      if (result.shouldRedirect && result.redirectUri !== null) {
        return context.redirect(
          buildClientErrorRedirectUrl({
            error: result.error,
            errorDescription: result.errorDescription,
            redirectUri: result.redirectUri,
            state: result.state
          }),
          302
        );
      }

      return context.json(
        result.errorDescription === undefined
          ? { error: result.error }
          : { error: result.error, error_description: result.errorDescription },
        400
      );
    }

    if (result.kind === "login_required") {
      const loginUrl =
        issuerContext.source === "custom_domain"
          ? new URL(`https://${issuerContext.requestHost}/login`)
          : new URL(`https://${authDomain}/login/${issuerContext.tenant.slug}`);

      loginUrl.searchParams.set("login_challenge", result.loginChallengeToken);

      return context.redirect(loginUrl.toString(), 302);
    }

    if (result.kind === "consent_required") {
      await recordAuthorizeAuditEvent({
        actorType: session === null ? "anonymous" : "end_user",
        actorId: session?.userId ?? null,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.deferred",
        targetId: result.request.clientId,
        payload: {
          client_id: result.request.clientId,
          reason: "consent_required",
          redirect_uri: result.request.redirectUri
        }
      });

      return context.redirect(
        buildClientErrorRedirectUrl({
          error: "consent_required",
          redirectUri: result.request.redirectUri,
          state: result.request.state
        }),
        302
      );
    }

    await recordAuthorizeAuditEvent({
      actorType: "end_user",
      actorId: result.session.userId,
      tenantId: issuerContext.tenant.id,
      eventType: "oidc.authorization.succeeded",
      targetId: result.request.clientId,
      payload: {
        user_id: result.session.userId,
        redirect_uri: result.request.redirectUri
      }
    });

    const redirectUrl = new URL(result.request.redirectUri);

    redirectUrl.searchParams.set("code", result.code);
    if (result.request.state !== null) {
      redirectUrl.searchParams.set("state", result.request.state);
    }

    return context.redirect(redirectUrl.toString(), 302);
  };

  const handleLoginEntry = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    return context.json(
      {
        error: "login_not_implemented",
        issuer: issuerContext.issuer,
        login_challenge: context.req.query("login_challenge") ?? null
      },
      501
    );
  };

  const handleChallengeInfo = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    const loginChallengeToken = context.req.query("login_challenge");
    if (!loginChallengeToken) {
      return context.json({ error: "missing_login_challenge" }, 400);
    }

    const { sha256Base64Url } = await import("../lib/hash");
    const tokenHash = await sha256Base64Url(loginChallengeToken);
    const challenge = await loginChallengeLookupRepository.findByTokenHash(tokenHash);

    if (challenge === null) {
      return context.json({ error: "invalid_login_challenge" }, 400);
    }

    // Look up client policy using the oidcClients.id (UUID) from the challenge's clientId (OAuth string)
    const client = await clientRepository.findByClientId(challenge.clientId);
    const policy = client !== null
      ? await clientAuthMethodPolicyRepository.findByClientId(client.id)
      : null;

    const methods: { method: string; allow_registration: boolean }[] = [];

    if (policy !== null) {
      if (policy.password.enabled) {
        methods.push({ method: "password", allow_registration: policy.password.allowRegistration });
      }
      if (policy.emailMagicLink.enabled) {
        methods.push({ method: "magic_link", allow_registration: policy.emailMagicLink.allowRegistration });
      }
      if (policy.passkey.enabled) {
        methods.push({ method: "passkey", allow_registration: policy.passkey.allowRegistration });
      }
    }
    // If policy is null (no row), return empty methods array (fail-safe: deny all)

    return context.json({
      tenant_display_name: issuerContext.tenant.displayName,
      methods
    });
  };

  const mfaCheckAfterFirstFactor = async ({
    authMethod,
    challenge,
    user,
  }: {
    authMethod: ClientAuthMethodName;
    challenge: import("../domain/authorization/types").LoginChallenge;
    user: { id: string; tenantId: string };
  }): Promise<{
    mfaRequired: false;
  } | {
    mfaRequired: true;
    mfaState: "pending_totp" | "pending_passkey_step_up" | "pending_enrollment";
    hasTotpFallback: boolean;
  }> => {
    const client = await clientRepository.findByClientId(challenge.clientId);
    const policy = client !== null
      ? await clientAuthMethodPolicyRepository.findByClientId(client.id)
      : null;

    if (policy === null || !policy.mfaRequired) {
      return { mfaRequired: false };
    }

    const hasTotpCred = (await totpRepository.findByTenantAndUser(
      challenge.tenantId,
      user.id
    )) !== null;
    const passkeyCreds = await passkeyRepository.listCredentialsByUserId(
      challenge.tenantId,
      user.id
    );
    const hasPasskeyCred = passkeyCreds.length > 0;

    let mfaState: "pending_totp" | "pending_passkey_step_up" | "pending_enrollment";
    let hasTotpFallback = false;

    if (hasPasskeyCred && hasTotpCred) {
      mfaState = "pending_passkey_step_up";
      hasTotpFallback = true;
    } else if (hasPasskeyCred) {
      mfaState = "pending_passkey_step_up";
    } else if (hasTotpCred) {
      mfaState = "pending_totp";
    } else {
      mfaState = "pending_enrollment";
    }

    await loginChallengeLookupRepository.setMfaState(
      challenge.id,
      user.id,
      mfaState,
      authMethod
    );

    return { mfaRequired: true, mfaState, hasTotpFallback };
  };

  const handlePasswordLogin = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    let formData: FormData;
    try {
      formData = await context.req.formData();
    } catch {
      return context.json(
        {
          error: "invalid_request"
        },
        400
      );
    }

    const loginChallengeToken = String(formData.get("login_challenge") ?? "");

    const result = await authenticateWithPassword({
      loginChallengeRepository: loginChallengeLookupRepository,
      loginChallengeToken,
      issuer: issuerContext.issuer,
      password: String(formData.get("password") ?? ""),
      tenantId: issuerContext.tenant.id,
      userRepository,
      username: String(formData.get("username") ?? "")
    });

    if (result.kind === "rejected") {
      const status =
        result.reason === "password_login_disabled"
          ? 403
          : result.reason === "invalid_login_challenge"
            ? 400
            : 401;
      const error =
        result.reason === "password_login_disabled"
          ? "password_login_disabled"
          : result.reason === "invalid_login_challenge"
            ? "invalid_request"
            : "invalid_credentials";

      await recordAuditEventBestEffort({
        actorType: "anonymous",
        actorId: null,
        tenantId: issuerContext.tenant.id,
        eventType: "user.password_login.failed",
        targetType: "user",
        targetId: null,
        payload: {
          reason: result.reason
        }
      });

      return context.json(
        {
          error
        },
        status
      );
    }

    const mfaCheck = await mfaCheckAfterFirstFactor({
      authMethod: "password",
      challenge: result.challenge,
      user: result.user
    });

    if (mfaCheck.mfaRequired) {
      return context.json(
        {
          mfa_state: mfaCheck.mfaState,
          login_challenge: loginChallengeToken,
          ...(mfaCheck.hasTotpFallback ? { has_totp_fallback: true } : {})
        },
        200
      );
    }

    const consumeSucceeded = await loginChallengeLookupRepository.consume(
      result.challenge.id,
      new Date().toISOString()
    );

    if (!consumeSucceeded) {
      await recordAuditEventBestEffort({
        actorType: "anonymous",
        actorId: null,
        tenantId: issuerContext.tenant.id,
        eventType: "user.password_login.failed",
        targetType: "user",
        targetId: null,
        payload: { reason: "invalid_login_challenge" }
      });
      return context.json({ error: "invalid_request" }, 400);
    }

    const { session, sessionToken } = await createBrowserSession({
      sessionRepository: browserSessionRepository,
      tenantId: result.user.tenantId,
      userId: result.user.id
    });

    await recordAuditEventBestEffort({
      actorType: "end_user",
      actorId: result.user.id,
      tenantId: issuerContext.tenant.id,
      eventType: "user.password_login.succeeded",
      targetType: "user",
      targetId: result.user.id,
      payload: {
        client_id: result.challenge.clientId
      }
    });

    context.header(
      "Set-Cookie",
      buildBrowserSessionCookie({
        expiresAt: session.expiresAt,
        secure: new URL(issuerContext.issuer).protocol === "https:",
        sessionToken
      })
    );

    const authorizationResult = await authorizeRequest({
      authMethod: "password",
      authorizationCodeRepository,
      clientRepository,
      issuerContext,
      loginChallengeRepository,
      request: {
        clientId: result.challenge.clientId,
        redirectUri: result.challenge.redirectUri,
        responseType: "code",
        scope: result.challenge.scope,
        state: result.challenge.state.length === 0 ? null : result.challenge.state,
        nonce: result.challenge.nonce,
        codeChallenge: result.challenge.codeChallenge,
        codeChallengeMethod: result.challenge.codeChallengeMethod
      },
      session: {
        userId: result.user.id,
        tenantId: result.user.tenantId
      }
    });

    if (authorizationResult.kind === "error") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: result.user.id,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.failed",
        targetId: authorizationResult.clientId,
        payload: {
          client_id: authorizationResult.clientId,
          reason: authorizationResult.error,
          redirect_uri: authorizationResult.redirectUri
        }
      });

      if (authorizationResult.shouldRedirect && authorizationResult.redirectUri !== null) {
        return context.json(
          {
            redirect_uri: buildClientErrorRedirectUrl({
              error: authorizationResult.error,
              errorDescription: authorizationResult.errorDescription,
              redirectUri: authorizationResult.redirectUri,
              state: authorizationResult.state
            })
          },
          200
        );
      }

      return context.json(
        authorizationResult.errorDescription === undefined
          ? { error: authorizationResult.error }
          : {
              error: authorizationResult.error,
              error_description: authorizationResult.errorDescription
            },
        400
      );
    }

    if (authorizationResult.kind === "consent_required") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: result.user.id,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.deferred",
        targetId: authorizationResult.request.clientId,
        payload: {
          client_id: authorizationResult.request.clientId,
          reason: "consent_required",
          redirect_uri: authorizationResult.request.redirectUri
        }
      });

      return context.json(
        {
          redirect_uri: buildClientErrorRedirectUrl({
            error: "consent_required",
            redirectUri: authorizationResult.request.redirectUri,
            state: authorizationResult.request.state
          })
        },
        200
      );
    }

    if (authorizationResult.kind !== "authorization_granted") {
      return context.json(
        {
          error: "invalid_request"
        },
        400
      );
    }

    await recordAuthorizeAuditEvent({
      actorType: "end_user",
      actorId: authorizationResult.session.userId,
      tenantId: issuerContext.tenant.id,
      eventType: "oidc.authorization.succeeded",
      targetId: authorizationResult.request.clientId,
      payload: {
        user_id: authorizationResult.session.userId,
        redirect_uri: authorizationResult.request.redirectUri
      }
    });

    const redirectUrl = new URL(authorizationResult.request.redirectUri);

    redirectUrl.searchParams.set("code", authorizationResult.code);
    if (authorizationResult.request.state !== null) {
      redirectUrl.searchParams.set("state", authorizationResult.request.state);
    }

    return context.json({ redirect_uri: redirectUrl.toString() }, 200);
  };

  const handleMagicLinkRequest = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    let formData: FormData;
    try {
      formData = await context.req.formData();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const result = await requestMagicLink({
      email: String(formData.get("email") ?? ""),
      issuer: issuerContext.issuer,
      loginChallengeRepository: loginChallengeLookupRepository,
      loginChallengeToken: String(formData.get("login_challenge") ?? ""),
      magicLinkRepository,
      tenantId: issuerContext.tenant.id,
      userRepository
    });

    if (result.kind === "rejected") {
      if (result.reason === "magic_link_login_disabled") {
        return context.json({ error: "magic_link_login_disabled" }, 403);
      }

      // For user_not_found and invalid_login_challenge we return 400 to avoid leaking info
      return context.json({ error: "invalid_request" }, 400);
    }

    await recordAuditEventBestEffort({
      actorType: "end_user",
      actorId: result.user.id,
      tenantId: issuerContext.tenant.id,
      eventType: "user.magic_link.requested",
      targetType: "user",
      targetId: result.user.id,
      payload: { client_id: result.challenge.clientId }
    });

    return context.json({ magic_link_token: result.token }, 200);
  };

  const handleMagicLinkConsume = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    let formData: FormData;
    try {
      formData = await context.req.formData();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const loginChallengeToken = String(formData.get("login_challenge") ?? "");

    const result = await consumeMagicLink({
      loginChallengeRepository: loginChallengeLookupRepository,
      magicLinkRepository,
      token: String(formData.get("token") ?? ""),
      userRepository
    });

    if (result.kind === "rejected") {
      return context.json({ error: result.reason }, 400);
    }

    const mfaCheckMl = await mfaCheckAfterFirstFactor({
      authMethod: "magic_link",
      challenge: result.challenge,
      user: result.user
    });

    if (mfaCheckMl.mfaRequired) {
      return context.json(
        {
          mfa_state: mfaCheckMl.mfaState,
          login_challenge: loginChallengeToken,
          ...(mfaCheckMl.hasTotpFallback ? { has_totp_fallback: true } : {})
        },
        200
      );
    }

    const consumeSucceeded = await loginChallengeLookupRepository.consume(
      result.challenge.id,
      new Date().toISOString()
    );

    if (!consumeSucceeded) {
      await recordAuditEventBestEffort({
        actorType: "anonymous",
        actorId: null,
        tenantId: issuerContext.tenant.id,
        eventType: "user.magic_link.login.failed",
        targetType: "user",
        targetId: null,
        payload: { reason: "invalid_login_challenge" }
      });
      return context.json({ error: "invalid_request" }, 400);
    }

    const { session, sessionToken } = await createBrowserSession({
      sessionRepository: browserSessionRepository,
      tenantId: result.user.tenantId,
      userId: result.user.id
    });

    await recordAuditEventBestEffort({
      actorType: "end_user",
      actorId: result.user.id,
      tenantId: issuerContext.tenant.id,
      eventType: "user.magic_link.consumed",
      targetType: "user",
      targetId: result.user.id,
      payload: { client_id: result.challenge.clientId }
    });

    context.header(
      "Set-Cookie",
      buildBrowserSessionCookie({
        expiresAt: session.expiresAt,
        secure: new URL(issuerContext.issuer).protocol === "https:",
        sessionToken
      })
    );

    const authorizationResult = await authorizeRequest({
      authMethod: "magic_link",
      authorizationCodeRepository,
      clientRepository,
      issuerContext,
      loginChallengeRepository,
      request: {
        clientId: result.challenge.clientId,
        redirectUri: result.challenge.redirectUri,
        responseType: "code",
        scope: result.challenge.scope,
        state: result.challenge.state.length === 0 ? null : result.challenge.state,
        nonce: result.challenge.nonce,
        codeChallenge: result.challenge.codeChallenge,
        codeChallengeMethod: result.challenge.codeChallengeMethod
      },
      session: {
        userId: result.user.id,
        tenantId: result.user.tenantId
      }
    });

    if (authorizationResult.kind === "error") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: result.user.id,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.failed",
        targetId: authorizationResult.clientId,
        payload: {
          client_id: authorizationResult.clientId,
          reason: authorizationResult.error,
          redirect_uri: authorizationResult.redirectUri
        }
      });

      if (authorizationResult.shouldRedirect && authorizationResult.redirectUri !== null) {
        return context.json(
          {
            redirect_uri: buildClientErrorRedirectUrl({
              error: authorizationResult.error,
              errorDescription: authorizationResult.errorDescription,
              redirectUri: authorizationResult.redirectUri,
              state: authorizationResult.state
            })
          },
          200
        );
      }

      return context.json({ error: authorizationResult.error }, 400);
    }

    if (authorizationResult.kind === "consent_required") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: result.user.id,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.deferred",
        targetId: authorizationResult.request.clientId,
        payload: {
          client_id: authorizationResult.request.clientId,
          reason: "consent_required",
          redirect_uri: authorizationResult.request.redirectUri
        }
      });

      return context.json(
        {
          redirect_uri: buildClientErrorRedirectUrl({
            error: "consent_required",
            redirectUri: authorizationResult.request.redirectUri,
            state: authorizationResult.request.state
          })
        },
        200
      );
    }

    if (authorizationResult.kind !== "authorization_granted") {
      return context.json({ error: "invalid_request" }, 400);
    }

    await recordAuthorizeAuditEvent({
      actorType: "end_user",
      actorId: authorizationResult.session.userId,
      tenantId: issuerContext.tenant.id,
      eventType: "oidc.authorization.succeeded",
      targetId: authorizationResult.request.clientId,
      payload: {
        user_id: authorizationResult.session.userId,
        redirect_uri: authorizationResult.request.redirectUri
      }
    });

    const redirectUrl = new URL(authorizationResult.request.redirectUri);
    redirectUrl.searchParams.set("code", authorizationResult.code);
    if (authorizationResult.request.state !== null) {
      redirectUrl.searchParams.set("state", authorizationResult.request.state);
    }

    return context.json({ redirect_uri: redirectUrl.toString() }, 200);
  };

  const handlePasskeyEnrollStart = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    let payload: { user_id?: string };
    try {
      payload = await context.req.json<{ user_id?: string }>();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const result = await startPasskeyEnrollment({
      passkeyRepository,
      tenantId: issuerContext.tenant.id,
      userId: payload.user_id ?? "",
      userRepository
    });

    if (result.kind === "rejected") {
      if (result.reason === "passkey_disabled") {
        return context.json({ error: "passkey_disabled" }, 403);
      }
      return context.json({ error: "user_not_found" }, 404);
    }

    return context.json({
      challenge: result.challenge,
      enrollment_session_id: result.enrollmentSessionId
    });
  };

  const handlePasskeyEnrollFinish = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    let payload: {
      enrollment_session_id?: string;
      credential_id?: string;
      public_key_cbor?: string;
      sign_count?: number;
    };
    try {
      payload = await context.req.json();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const result = await finishPasskeyEnrollment({
      credentialId: payload.credential_id ?? "",
      enrollmentSessionId: payload.enrollment_session_id ?? "",
      passkeyRepository,
      publicKeyCbor: payload.public_key_cbor ?? "",
      signCount: payload.sign_count ?? 0
    });

    if (result.kind === "rejected") {
      if (result.reason === "duplicate_credential") {
        return context.json({ error: "duplicate_credential" }, 409);
      }
      return context.json({ error: "invalid_session" }, 400);
    }

    await recordAuditEventBestEffort({
      actorType: "end_user",
      actorId: null,
      tenantId: issuerContext.tenant.id,
      eventType: "user.passkey.enrollment.succeeded",
      targetType: "user",
      targetId: null,
      payload: { credential_id: payload.credential_id }
    });

    return context.json({ enrolled: true });
  };

  const handlePasskeyLoginStart = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    let formData: FormData;
    try {
      formData = await context.req.formData();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const result = await startPasskeyLogin({
      issuer: issuerContext.issuer,
      loginChallengeRepository: loginChallengeLookupRepository,
      loginChallengeToken: String(formData.get("login_challenge") ?? ""),
      passkeyRepository,
      tenantId: issuerContext.tenant.id,
      userRepository
    });

    if (result.kind === "rejected") {
      if (result.reason === "passkey_disabled") {
        return context.json({ error: "passkey_disabled" }, 403);
      }
      return context.json({ error: "invalid_request" }, 400);
    }

    return context.json({
      challenge: result.challenge,
      assertion_session_id: result.assertionSessionId
    });
  };

  const handlePasskeyLoginFinish = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);

    if (issuerContext === null) {
      return context.notFound();
    }

    let payload: {
      assertion_session_id?: string;
      credential_id?: string;
      sign_count?: number;
      login_challenge?: string;
    };
    try {
      payload = await context.req.json();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const loginChallengeToken = String(payload.login_challenge ?? "");

    const result = await finishPasskeyLogin({
      assertionSessionId: payload.assertion_session_id ?? "",
      credentialId: payload.credential_id ?? "",
      loginChallengeRepository: loginChallengeLookupRepository,
      passkeyRepository,
      signCount: payload.sign_count ?? 0,
      userRepository
    });

    if (result.kind === "rejected") {
      await recordAuditEventBestEffort({
        actorType: "anonymous",
        actorId: null,
        tenantId: issuerContext.tenant.id,
        eventType: "user.passkey.login.failed",
        targetType: "user",
        targetId: null,
        payload: { reason: result.reason }
      });

      const status = result.reason === "invalid_credentials" ? 401 : 400;
      return context.json({ error: result.reason }, status);
    }

    const mfaCheckPk = await mfaCheckAfterFirstFactor({
      authMethod: "passkey",
      challenge: result.challenge,
      user: result.user
    });

    if (mfaCheckPk.mfaRequired) {
      return context.json(
        {
          mfa_state: mfaCheckPk.mfaState,
          login_challenge: loginChallengeToken,
          ...(mfaCheckPk.hasTotpFallback ? { has_totp_fallback: true } : {})
        },
        200
      );
    }

    const consumeSucceeded = await loginChallengeLookupRepository.consume(
      result.challenge.id,
      new Date().toISOString()
    );

    if (!consumeSucceeded) {
      await recordAuditEventBestEffort({
        actorType: "anonymous",
        actorId: null,
        tenantId: issuerContext.tenant.id,
        eventType: "user.passkey.login.failed",
        targetType: "user",
        targetId: null,
        payload: { reason: "invalid_login_challenge" }
      });
      return context.json({ error: "invalid_request" }, 400);
    }

    const { session, sessionToken } = await createBrowserSession({
      sessionRepository: browserSessionRepository,
      tenantId: result.user.tenantId,
      userId: result.user.id
    });

    await recordAuditEventBestEffort({
      actorType: "end_user",
      actorId: result.user.id,
      tenantId: issuerContext.tenant.id,
      eventType: "user.passkey.login.succeeded",
      targetType: "user",
      targetId: result.user.id,
      payload: { client_id: result.challenge.clientId }
    });

    context.header(
      "Set-Cookie",
      buildBrowserSessionCookie({
        expiresAt: session.expiresAt,
        secure: new URL(issuerContext.issuer).protocol === "https:",
        sessionToken
      })
    );

    const authorizationResult = await authorizeRequest({
      authMethod: "passkey",
      authorizationCodeRepository,
      clientRepository,
      issuerContext,
      loginChallengeRepository,
      request: {
        clientId: result.challenge.clientId,
        redirectUri: result.challenge.redirectUri,
        responseType: "code",
        scope: result.challenge.scope,
        state: result.challenge.state.length === 0 ? null : result.challenge.state,
        nonce: result.challenge.nonce,
        codeChallenge: result.challenge.codeChallenge,
        codeChallengeMethod: result.challenge.codeChallengeMethod
      },
      session: {
        userId: result.user.id,
        tenantId: result.user.tenantId
      }
    });

    if (authorizationResult.kind === "error") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: result.user.id,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.failed",
        targetId: authorizationResult.clientId,
        payload: {
          client_id: authorizationResult.clientId,
          reason: authorizationResult.error,
          redirect_uri: authorizationResult.redirectUri
        }
      });

      if (authorizationResult.shouldRedirect && authorizationResult.redirectUri !== null) {
        return context.json(
          {
            redirect_uri: buildClientErrorRedirectUrl({
              error: authorizationResult.error,
              errorDescription: authorizationResult.errorDescription,
              redirectUri: authorizationResult.redirectUri,
              state: authorizationResult.state
            })
          },
          200
        );
      }

      return context.json({ error: authorizationResult.error }, 400);
    }

    if (authorizationResult.kind === "consent_required") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: result.user.id,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.deferred",
        targetId: authorizationResult.request.clientId,
        payload: {
          client_id: authorizationResult.request.clientId,
          reason: "consent_required",
          redirect_uri: authorizationResult.request.redirectUri
        }
      });

      return context.json(
        {
          redirect_uri: buildClientErrorRedirectUrl({
            error: "consent_required",
            redirectUri: authorizationResult.request.redirectUri,
            state: authorizationResult.request.state
          })
        },
        200
      );
    }

    if (authorizationResult.kind !== "authorization_granted") {
      return context.json({ error: "invalid_request" }, 400);
    }

    await recordAuthorizeAuditEvent({
      actorType: "end_user",
      actorId: authorizationResult.session.userId,
      tenantId: issuerContext.tenant.id,
      eventType: "oidc.authorization.succeeded",
      targetId: authorizationResult.request.clientId,
      payload: {
        user_id: authorizationResult.session.userId,
        redirect_uri: authorizationResult.request.redirectUri
      }
    });

    const redirectUrl = new URL(authorizationResult.request.redirectUri);
    redirectUrl.searchParams.set("code", authorizationResult.code);
    if (authorizationResult.request.state !== null) {
      redirectUrl.searchParams.set("state", authorizationResult.request.state);
    }

    return context.json({ redirect_uri: redirectUrl.toString() }, 200);
  };

  // Shared helper called after any MFA step succeeds.
  // Consumes the login challenge, creates a browser session, sets the cookie,
  // runs authorizeRequest, and redirects to the callback with code+state.
  const handlePostMfaSuccess = async (
    context: Context,
    issuerContext: import("../domain/tenants/types").ResolvedIssuerContext,
    challenge: import("../domain/authorization/types").LoginChallenge,
    userId: string
  ): Promise<Response> => {
    const consumed = await loginChallengeLookupRepository.consume(challenge.id, new Date().toISOString());
    if (!consumed) {
      return context.json({ error: "invalid_request" }, 400);
    }

    const { session, sessionToken } = await createBrowserSession({
      sessionRepository: browserSessionRepository,
      tenantId: challenge.tenantId,
      userId
    });

    context.header(
      "Set-Cookie",
      buildBrowserSessionCookie({
        expiresAt: session.expiresAt,
        secure: new URL(issuerContext.issuer).protocol === "https:",
        sessionToken
      })
    );

    const authorizationResult = await authorizeRequest({
      authMethod: challenge.authMethod ?? null,
      authorizationCodeRepository,
      clientRepository,
      issuerContext,
      loginChallengeRepository,
      request: {
        clientId: challenge.clientId,
        redirectUri: challenge.redirectUri,
        responseType: "code",
        scope: challenge.scope,
        state: challenge.state.length === 0 ? null : challenge.state,
        nonce: challenge.nonce,
        codeChallenge: challenge.codeChallenge,
        codeChallengeMethod: challenge.codeChallengeMethod
      },
      session: { userId, tenantId: challenge.tenantId }
    });

    if (authorizationResult.kind === "error") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: userId,
        tenantId: challenge.tenantId,
        eventType: "oidc.authorization.failed",
        targetId: authorizationResult.clientId,
        payload: {
          client_id: authorizationResult.clientId,
          reason: authorizationResult.error,
          redirect_uri: authorizationResult.redirectUri
        }
      });

      if (authorizationResult.shouldRedirect && authorizationResult.redirectUri !== null) {
        return context.json(
          {
            redirect_uri: buildClientErrorRedirectUrl({
              error: authorizationResult.error,
              errorDescription: authorizationResult.errorDescription,
              redirectUri: authorizationResult.redirectUri,
              state: authorizationResult.state
            })
          },
          200
        );
      }

      return context.json({ error: authorizationResult.error }, 400);
    }

    if (authorizationResult.kind === "consent_required") {
      return context.json(
        {
          redirect_uri: buildClientErrorRedirectUrl({
            error: "consent_required",
            redirectUri: authorizationResult.request.redirectUri,
            state: authorizationResult.request.state
          })
        },
        200
      );
    }

    if (authorizationResult.kind !== "authorization_granted") {
      return context.json({ error: "invalid_request" }, 400);
    }

    await recordAuthorizeAuditEvent({
      actorType: "end_user",
      actorId: userId,
      tenantId: challenge.tenantId,
      eventType: "oidc.authorization.succeeded",
      targetId: authorizationResult.request.clientId,
      payload: {
        user_id: userId,
        redirect_uri: authorizationResult.request.redirectUri
      }
    });

    const redirectUrl = new URL(authorizationResult.request.redirectUri);
    redirectUrl.searchParams.set("code", authorizationResult.code);
    if (authorizationResult.request.state !== null) {
      redirectUrl.searchParams.set("state", authorizationResult.request.state);
    }

    return context.json({ redirect_uri: redirectUrl.toString() }, 200);
  };

  const handleMfaTotpVerify = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);
    if (issuerContext === null) return context.notFound();

    let payload: { login_challenge?: string; code?: string };
    try { payload = await context.req.json(); } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const token = (payload.login_challenge ?? "").trim();
    const code = (payload.code ?? "").trim();
    if (!token || !code) return context.json({ error: "invalid_request" }, 400);

    const challenge = await loginChallengeLookupRepository.findByTokenHash(
      await sha256Base64Url(token)
    );

    if (challenge === null || challenge.tenantId !== issuerContext.tenant.id) {
      return context.json({ error: "invalid_request" }, 400);
    }
    if (challenge.mfaState !== "pending_totp" || challenge.authenticatedUserId === null) {
      return context.json({ error: "invalid_mfa_state" }, 400);
    }

    const totpCred = await totpRepository.findByTenantAndUser(
      challenge.tenantId, challenge.authenticatedUserId
    );
    if (totpCred === null) return context.json({ error: "totp_not_enrolled" }, 400);

    const secret = await decryptTotpSecret(totpCred.secretEncrypted, totpEncryptionKey);
    const result = await verifyTotpCode({ secret, code, lastUsedWindow: totpCred.lastUsedWindow });

    if (result.kind !== "valid") {
      const newCount = await loginChallengeLookupRepository.incrementMfaAttemptCount(challenge.id);
      if (newCount >= 5) {
        await loginChallengeLookupRepository.consume(challenge.id, new Date().toISOString());
        await recordAuditEventBestEffort({
          actorType: "user", actorId: challenge.authenticatedUserId,
          tenantId: challenge.tenantId, eventType: "mfa.challenge.invalidated",
          targetType: "login_challenge", targetId: challenge.id, payload: null
        });
        return context.json({ error: "challenge_invalidated" }, 401);
      }
      await recordAuditEventBestEffort({
        actorType: "user", actorId: challenge.authenticatedUserId,
        tenantId: challenge.tenantId, eventType: "mfa.totp.failed",
        targetType: "login_challenge", targetId: challenge.id, payload: null
      });
      return context.json({
        error: result.kind === "replay" ? "replay" : "invalid_code",
        remaining_attempts: 5 - newCount
      }, 401);
    }

    await totpRepository.updateLastUsedWindow(totpCred.id, result.windowIndex);
    await loginChallengeLookupRepository.satisfyMfa(challenge.id);
    await recordAuditEventBestEffort({
      actorType: "user", actorId: challenge.authenticatedUserId,
      tenantId: challenge.tenantId, eventType: "mfa.totp.verified",
      targetType: "login_challenge", targetId: challenge.id, payload: null
    });

    return handlePostMfaSuccess(context, issuerContext, challenge, challenge.authenticatedUserId);
  };

  const handleMfaPasskeyStart = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);
    if (issuerContext === null) return context.notFound();

    let payload: { login_challenge?: string };
    try { payload = await context.req.json(); } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const token = (payload.login_challenge ?? "").trim();
    if (!token) return context.json({ error: "invalid_request" }, 400);

    const challenge = await loginChallengeLookupRepository.findByTokenHash(
      await sha256Base64Url(token)
    );

    if (challenge === null || challenge.tenantId !== issuerContext.tenant.id) {
      return context.json({ error: "invalid_request" }, 400);
    }
    if (challenge.mfaState !== "pending_passkey_step_up" || challenge.authenticatedUserId === null) {
      return context.json({ error: "invalid_mfa_state" }, 400);
    }

    const credentials = await passkeyRepository.listCredentialsByUserId(
      challenge.tenantId, challenge.authenticatedUserId
    );

    const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
    const nonce = btoa(String.fromCharCode(...nonceBytes))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const challengeHash = await sha256Base64Url(nonce);
    const now = new Date();

    await mfaPasskeyChallengeRepository.create({
      id: crypto.randomUUID(),
      tenantId: challenge.tenantId,
      loginChallengeId: challenge.id,
      challengeHash,
      expiresAt: new Date(now.getTime() + 5 * 60 * 1000).toISOString(),
      consumedAt: null,
      createdAt: now.toISOString()
    });

    return context.json({
      challenge: nonce,
      allowed_credentials: credentials.map(c => c.credentialId)
    });
  };

  const handleMfaPasskeyFinish = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);
    if (issuerContext === null) return context.notFound();

    let payload: {
      login_challenge?: string;
      challenge_hash?: string;
      challenge?: string;
      credential_id?: string;
      response?: {
        authenticator_data?: string;
        client_data_json?: string;
        signature?: string;
      };
    };
    try { payload = await context.req.json(); } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const token = (payload.login_challenge ?? "").trim();
    const challengeHash = (payload.challenge_hash ?? "").trim();
    const challengeNonce = (payload.challenge ?? "").trim();
    const credentialId = (payload.credential_id ?? "").trim();
    if (!token || !challengeHash || !challengeNonce || !credentialId) {
      return context.json({ error: "invalid_request" }, 400);
    }

    const challenge = await loginChallengeLookupRepository.findByTokenHash(
      await sha256Base64Url(token)
    );

    if (challenge === null || challenge.tenantId !== issuerContext.tenant.id) {
      return context.json({ error: "invalid_request" }, 400);
    }
    if (challenge.mfaState !== "pending_passkey_step_up" || challenge.authenticatedUserId === null) {
      return context.json({ error: "invalid_mfa_state" }, 400);
    }

    const now = new Date().toISOString();
    const mfaChallenge = await mfaPasskeyChallengeRepository.consumeByChallengeHash(
      challengeHash, now, now
    );
    if (mfaChallenge === null) {
      return context.json({ error: "invalid_request" }, 400);
    }

    const credential = await passkeyRepository.findCredentialByCredentialId(
      challenge.tenantId, credentialId
    );
    if (credential === null) {
      const newCount = await loginChallengeLookupRepository.incrementMfaAttemptCount(challenge.id);
      if (newCount >= 5) {
        await loginChallengeLookupRepository.consume(challenge.id, new Date().toISOString());
        await recordAuditEventBestEffort({
          actorType: "user", actorId: challenge.authenticatedUserId,
          tenantId: challenge.tenantId, eventType: "mfa.challenge.invalidated",
          targetType: "login_challenge", targetId: challenge.id, payload: null
        });
        return context.json({ error: "challenge_invalidated" }, 401);
      }
      return context.json({ error: "credential_not_found", remaining_attempts: 5 - newCount }, 400);
    }

    // Attempt to verify the WebAuthn assertion using @simplewebauthn/server
    let verificationSucceeded = false;
    try {
      const { verifyAuthenticationResponse } = await import("@simplewebauthn/server");
      const authResponse = payload.response ?? {};
      const verificationResult = await verifyAuthenticationResponse({
        response: {
          id: credentialId,
          rawId: credentialId,
          type: "public-key",
          response: {
            authenticatorData: authResponse.authenticator_data ?? "",
            clientDataJSON: authResponse.client_data_json ?? "",
            signature: authResponse.signature ?? ""
          }
        } as Parameters<typeof verifyAuthenticationResponse>[0]["response"],
        expectedChallenge: challengeNonce,
        expectedOrigin: new URL(issuerContext.issuer).origin,
        expectedRPID: new URL(issuerContext.issuer).hostname,
        credential: {
          id: credentialId,
          publicKey: Uint8Array.from(
            atob(credential.publicKeyCbor.replace(/-/g, "+").replace(/_/g, "/")),
            c => c.charCodeAt(0)
          ),
          counter: credential.signCount,
          transports: undefined
        }
      });
      verificationSucceeded = verificationResult.verified;
    } catch {
      verificationSucceeded = false;
    }

    if (!verificationSucceeded) {
      const newCount = await loginChallengeLookupRepository.incrementMfaAttemptCount(challenge.id);
      if (newCount >= 5) {
        await loginChallengeLookupRepository.consume(challenge.id, new Date().toISOString());
        await recordAuditEventBestEffort({
          actorType: "user", actorId: challenge.authenticatedUserId,
          tenantId: challenge.tenantId, eventType: "mfa.challenge.invalidated",
          targetType: "login_challenge", targetId: challenge.id, payload: null
        });
        return context.json({ error: "challenge_invalidated" }, 401);
      }
      await recordAuditEventBestEffort({
        actorType: "user", actorId: challenge.authenticatedUserId,
        tenantId: challenge.tenantId, eventType: "mfa.passkey_stepup.failed",
        targetType: "login_challenge", targetId: challenge.id, payload: null
      });
      return context.json({ error: "passkey_verification_failed", remaining_attempts: 5 - newCount }, 401);
    }

    await loginChallengeLookupRepository.satisfyMfa(challenge.id);
    await recordAuditEventBestEffort({
      actorType: "user", actorId: challenge.authenticatedUserId,
      tenantId: challenge.tenantId, eventType: "mfa.passkey_stepup.verified",
      targetType: "login_challenge", targetId: challenge.id, payload: null
    });

    return handlePostMfaSuccess(context, issuerContext, challenge, challenge.authenticatedUserId);
  };

  const handleMfaTotpEnrollStart = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);
    if (issuerContext === null) return context.notFound();

    let payload: { login_challenge?: string };
    try { payload = await context.req.json(); } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const token = (payload.login_challenge ?? "").trim();
    if (!token) return context.json({ error: "invalid_request" }, 400);

    const challenge = await loginChallengeLookupRepository.findByTokenHash(
      await sha256Base64Url(token)
    );

    if (challenge === null || challenge.tenantId !== issuerContext.tenant.id) {
      return context.json({ error: "invalid_request" }, 400);
    }
    if (challenge.mfaState !== "pending_enrollment" || challenge.authenticatedUserId === null) {
      return context.json({ error: "invalid_mfa_state" }, 400);
    }

    const rawSecret = generateTotpSecret();
    const secretEncrypted = await encryptTotpSecret(rawSecret, totpEncryptionKey);

    await loginChallengeLookupRepository.setTotpEnrollmentSecret(challenge.id, secretEncrypted);

    const user = await userRepository.findUserById(challenge.tenantId, challenge.authenticatedUserId);
    const userEmail = user?.email ?? challenge.authenticatedUserId;
    const issuerLabel = encodeURIComponent(issuerContext.tenant.displayName);
    const accountLabel = encodeURIComponent(userEmail);
    const provisioningUri = `otpauth://totp/${issuerLabel}:${accountLabel}?secret=${rawSecret}&issuer=${issuerLabel}&algorithm=SHA1&digits=6&period=30`;

    return context.json({ provisioning_uri: provisioningUri, secret: rawSecret });
  };

  const handleMfaTotpEnrollFinish = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);
    if (issuerContext === null) return context.notFound();

    let payload: { login_challenge?: string; code?: string };
    try { payload = await context.req.json(); } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const token = (payload.login_challenge ?? "").trim();
    const code = (payload.code ?? "").trim();
    if (!token || !code) return context.json({ error: "invalid_request" }, 400);

    const challenge = await loginChallengeLookupRepository.findByTokenHash(
      await sha256Base64Url(token)
    );

    if (challenge === null || challenge.tenantId !== issuerContext.tenant.id) {
      return context.json({ error: "invalid_request" }, 400);
    }
    if (
      challenge.mfaState !== "pending_enrollment" ||
      challenge.authenticatedUserId === null ||
      challenge.totpEnrollmentSecretEncrypted === null
    ) {
      return context.json({ error: "invalid_mfa_state" }, 400);
    }

    const secret = await decryptTotpSecret(
      challenge.totpEnrollmentSecretEncrypted, totpEncryptionKey
    );
    const result = await verifyTotpCode({ secret, code, lastUsedWindow: 0 });

    if (result.kind !== "valid") {
      const newCount = await loginChallengeLookupRepository.incrementEnrollmentAttemptCount(challenge.id);
      if (newCount >= 5) {
        await loginChallengeLookupRepository.consume(challenge.id, new Date().toISOString());
        await recordAuditEventBestEffort({
          actorType: "user", actorId: challenge.authenticatedUserId,
          tenantId: challenge.tenantId, eventType: "mfa.enrollment.invalidated",
          targetType: "login_challenge", targetId: challenge.id, payload: null
        });
        return context.json({ error: "challenge_invalidated" }, 401);
      }
      return context.json({ error: "invalid_code", remaining_attempts: 5 - newCount }, 401);
    }

    // Create TOTP credential
    const now = new Date().toISOString();
    try {
      await totpRepository.create({
        id: crypto.randomUUID(),
        tenantId: challenge.tenantId,
        userId: challenge.authenticatedUserId,
        secretEncrypted: challenge.totpEnrollmentSecretEncrypted,
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        lastUsedWindow: result.windowIndex,
        enrolledAt: now,
        createdAt: now
      });
    } catch (err) {
      if (isProvisionConflictError(err)) {
        // Duplicate enrollment — already enrolled, treat as success
        return context.json({ mfa_enrolled: true }, 200);
      }
      throw err;
    }

    await loginChallengeLookupRepository.completeEnrollment(challenge.id);
    await recordAuditEventBestEffort({
      actorType: "user", actorId: challenge.authenticatedUserId,
      tenantId: challenge.tenantId, eventType: "mfa.totp.enrolled",
      targetType: "login_challenge", targetId: challenge.id, payload: null
    });

    return handlePostMfaSuccess(context, issuerContext, challenge, challenge.authenticatedUserId);
  };

  const handleMfaSwitchToTotp = async (context: Context) => {
    const issuerContext = await resolveLoginIssuerContext(context);
    if (issuerContext === null) return context.notFound();

    let payload: { login_challenge?: string };
    try { payload = await context.req.json(); } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const token = (payload.login_challenge ?? "").trim();
    if (!token) return context.json({ error: "invalid_request" }, 400);

    const challenge = await loginChallengeLookupRepository.findByTokenHash(
      await sha256Base64Url(token)
    );

    if (challenge === null || challenge.tenantId !== issuerContext.tenant.id) {
      return context.json({ error: "invalid_request" }, 400);
    }
    if (challenge.mfaState !== "pending_passkey_step_up") {
      return context.json({ error: "invalid_mfa_state" }, 400);
    }
    if (challenge.authenticatedUserId === null) {
      return context.json({ error: "invalid_request" }, 400);
    }

    const totpCred = await totpRepository.findByTenantAndUser(
      challenge.tenantId, challenge.authenticatedUserId
    );
    if (totpCred === null) {
      return context.json({ error: "totp_not_enrolled" }, 400);
    }

    await loginChallengeLookupRepository.setMfaState(
      challenge.id,
      challenge.authenticatedUserId,
      "pending_totp",
      challenge.authMethod ?? undefined
    );
    return context.json({ mfa_state: "pending_totp" }, 200);
  };

  const handlePlaceholderEndpoint = async (context: Context) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl: context.req.url,
      oidcHost,
      tenantRepository
    });

    return issuerContext === null ? context.notFound() : context.json({ error: "not_implemented" }, 501);
  };

  const handleToken = async (context: Context) => {
    const setTokenResponseHeaders = ({
      includeBasicWwwAuthenticate
    }: {
      includeBasicWwwAuthenticate?: boolean;
    } = {}) => {
      context.header("Cache-Control", "no-store");
      context.header("Pragma", "no-cache");

      if (includeBasicWwwAuthenticate) {
        context.header("WWW-Authenticate", 'Basic realm="token", error="invalid_client"');
      }
    };

    const issuerContext = await resolveIssuerContext({
      requestUrl: context.req.url,
      oidcHost,
      tenantRepository
    });

    if (issuerContext === null) {
      return context.notFound();
    }

    let formData: FormData;
    try {
      formData = await context.req.formData();
    } catch {
      const error = {
        error: "invalid_request" as const
      };

      await recordAuditEventBestEffort({
        actorType: "oidc_client",
        actorId: null,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.token.exchange.failed",
        targetType: "oidc_client",
        targetId: null,
        payload: {
          reason: error.error
        }
      });

      setTokenResponseHeaders();
      return context.json(error, 400);
    }

    const result = await exchangeAuthorizationCode({
      authorizationCodeRepository,
      accessTokenClaimsRepository,
      clientAuthMethodPolicyRepository,
      clientRepository,
      issuerContext,
      refreshTokenRepository,
      request: {
        authorizationHeader: context.req.header("authorization"),
        grantType: String(formData.get("grant_type") ?? ""),
        code: String(formData.get("code") ?? ""),
        refreshToken: formData.get("refresh_token")?.toString() ?? null,
        redirectUri: String(formData.get("redirect_uri") ?? ""),
        codeVerifier: String(formData.get("code_verifier") ?? ""),
        requestedClientId: formData.get("client_id")?.toString() ?? null,
        requestedClientSecret: formData.get("client_secret")?.toString() ?? null
      },
      signer,
      userRepository
    });

    if (result.kind === "error") {
      await recordAuditEventBestEffort({
        actorType: "oidc_client",
        actorId: result.clientId,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.token.exchange.failed",
        targetType: "oidc_client",
        targetId: result.clientId,
        payload: {
          reason: result.error
        }
      });

      const attemptedBasicAuthentication = context.req
        .header("authorization")
        ?.match(/^basic\s+/iu) !== null;

      setTokenResponseHeaders({
        includeBasicWwwAuthenticate:
          result.error === "invalid_client" && attemptedBasicAuthentication === true
      });
      return context.json(
        {
          error: result.error
        },
        result.status
      );
    }

    await recordAuditEventBestEffort({
      actorType: "oidc_client",
      actorId: result.clientId,
      tenantId: result.tenantId,
      eventType: "oidc.token.exchange.succeeded",
      targetType: "oidc_client",
      targetId: result.clientId,
      payload: {
        user_id: result.userId
      }
    });

    setTokenResponseHeaders();
    return context.json(result.response, 200);
  };

  app.get("/.well-known/openid-configuration", async (context) => {
    const metadata = await handleDiscovery(context.req.url);

    return metadata === null ? context.notFound() : context.json(metadata);
  });

  app.get("/t/:tenant/.well-known/openid-configuration", async (context) => {
    const metadata = await handleDiscovery(context.req.url);

    return metadata === null ? context.notFound() : context.json(metadata);
  });

  app.get("/jwks.json", async (context) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl: context.req.url,
      oidcHost,
      tenantRepository
    });

    if (issuerContext === null) {
      return context.notFound();
    }

    return context.json(await buildJwks(keyRepository, issuerContext.tenant.id));
  });

  app.get("/t/:tenant/jwks.json", async (context) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl: context.req.url,
      oidcHost,
      tenantRepository
    });

    if (issuerContext === null) {
      return context.notFound();
    }

    return context.json(await buildJwks(keyRepository, issuerContext.tenant.id));
  });

  // Custom-domain issuer login routes (host = tenant custom domain)
  app.get("/login", handleLoginEntry);
  app.get("/login/challenge-info", handleChallengeInfo);
  app.post("/login/password", handlePasswordLogin);
  app.post("/login/magic-link/request", handleMagicLinkRequest);
  app.post("/login/magic-link/consume", handleMagicLinkConsume);
  app.post("/passkey/enroll/start", handlePasskeyEnrollStart);
  app.post("/passkey/enroll/finish", handlePasskeyEnrollFinish);
  app.post("/login/passkey/start", handlePasskeyLoginStart);
  app.post("/login/passkey/finish", handlePasskeyLoginFinish);

  // Platform-path login routes (host = auth.{domain}, path = /login/:tenant/*)
  app.get("/login/:tenant", handleLoginEntry);
  app.get("/login/:tenant/challenge-info", handleChallengeInfo);
  app.post("/login/:tenant/password", handlePasswordLogin);
  app.post("/login/:tenant/magic-link/request", handleMagicLinkRequest);
  app.post("/login/:tenant/magic-link/consume", handleMagicLinkConsume);
  app.post("/passkey/:tenant/enroll/start", handlePasskeyEnrollStart);
  app.post("/passkey/:tenant/enroll/finish", handlePasskeyEnrollFinish);
  app.post("/login/:tenant/passkey/start", handlePasskeyLoginStart);
  app.post("/login/:tenant/passkey/finish", handlePasskeyLoginFinish);

  // MFA endpoints (platform-path: /api/login/:tenant/mfa/*)
  app.post("/api/login/:tenant/mfa/totp/verify", handleMfaTotpVerify);
  app.post("/api/login/:tenant/mfa/passkey/start", handleMfaPasskeyStart);
  app.post("/api/login/:tenant/mfa/passkey/finish", handleMfaPasskeyFinish);
  app.post("/api/login/:tenant/mfa/switch-to-totp", handleMfaSwitchToTotp);
  app.post("/api/login/:tenant/mfa/totp/enroll/start", handleMfaTotpEnrollStart);
  app.post("/api/login/:tenant/mfa/totp/enroll/finish", handleMfaTotpEnrollFinish);

  // MFA endpoints (custom-domain: /mfa/*)
  app.post("/mfa/totp/verify", handleMfaTotpVerify);
  app.post("/mfa/passkey/start", handleMfaPasskeyStart);
  app.post("/mfa/passkey/finish", handleMfaPasskeyFinish);
  app.post("/mfa/switch-to-totp", handleMfaSwitchToTotp);
  app.post("/mfa/totp/enroll/start", handleMfaTotpEnrollStart);
  app.post("/mfa/totp/enroll/finish", handleMfaTotpEnrollFinish);

  // OIDC protocol routes (host = o.{domain})
  app.get("/authorize", handleAuthorize);
  app.get("/t/:tenant/authorize", handleAuthorize);
  app.post("/token", handleToken);
  app.post("/t/:tenant/token", handleToken);

  const handleDynamicClientRegistration = async (
    authorizationHeader: string | undefined,
    requestUrl: string,
    payload: unknown
  ) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl,
      oidcHost,
      tenantRepository
    });

    if (issuerContext === null) {
      return { status: 404 as const };
    }

    if (authorizationHeader !== `Bearer ${managementApiToken}`) {
      return { status: 401 as const };
    }

    try {
      const result = await registerClient({
        clientRepository,
        input: payload,
        issuerContext
      });
      const tokenHash = await sha256Base64Url(result.registrationAccessToken);

      try {
        await registrationAccessTokenRepository.store({
          clientId: result.client.clientId,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          issuer: issuerContext.issuer,
          tenantId: issuerContext.tenant.id,
          tokenHash
        });

        await auditRepository.record({
          id: crypto.randomUUID(),
          actorType: "management_token",
          actorId: "initial_access_token",
          tenantId: issuerContext.tenant.id,
          eventType: "oidc.client.registered",
          targetType: "oidc_client",
          targetId: result.client.clientId,
          payload: {
            application_type: result.client.applicationType,
            client_name: result.client.clientName
          },
          occurredAt: new Date().toISOString()
        });
      } catch (error) {
        await Promise.allSettled([
          clientRepository.deleteByClientId(result.client.clientId),
          registrationAccessTokenRepository.deleteByTokenHash(tokenHash)
        ]);
        throw error;
      }

      return {
        status: 201 as const,
        body: {
          client_id: result.client.clientId,
          client_secret: result.clientSecret,
          registration_access_token: result.registrationAccessToken,
          registration_client_uri: `${issuerContext.issuer}/connect/register/${result.client.clientId}`,
          client_name: result.client.clientName,
          redirect_uris: result.client.redirectUris,
          application_type: result.client.applicationType,
          token_endpoint_auth_method: result.client.tokenEndpointAuthMethod,
          grant_types: result.client.grantTypes,
          response_types: result.client.responseTypes
        }
      };
    } catch (error) {
      if (error instanceof ZodError) {
        return {
          status: 400 as const,
          body: {
            error: "invalid_client_metadata",
            issues: error.issues
          }
        };
      }

      throw error;
    }
  };

  app.post("/connect/register", async (context) => {
    const result = await handleDynamicClientRegistration(
      context.req.header("authorization"),
      context.req.url,
      await context.req.json()
    );

    if (result.status === 404) {
      return context.notFound();
    }

    return context.json(result.body ?? { error: "unauthorized" }, result.status);
  });

  app.post("/t/:tenant/connect/register", async (context) => {
    const result = await handleDynamicClientRegistration(
      context.req.header("authorization"),
      context.req.url,
      await context.req.json()
    );

    if (result.status === 404) {
      return context.notFound();
    }

    return context.json(result.body ?? { error: "unauthorized" }, result.status);
  });

  app.post("/t/:tenant/register", async (context) => {
    const issuerContext = await resolveIssuerContextBySlug({
      slug: context.req.param("tenant"),
      oidcHost,
      tenantRepository
    });
    if (issuerContext === null) {
      return context.notFound();
    }

    let payload: { login_challenge?: string; email?: string; username?: string; password?: string };
    try {
      payload = await context.req.json();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const loginChallengeToken = (payload.login_challenge ?? "").trim();
    if (!loginChallengeToken) {
      return context.json({ error: "invalid_request" }, 400);
    }

    const tokenHash = await sha256Base64Url(loginChallengeToken);
    const challenge = await loginChallengeLookupRepository.findByTokenHash(tokenHash);

    if (challenge === null || challenge.consumedAt !== null) {
      return context.json({ error: "invalid_login_challenge" }, 400);
    }
    if (challenge.tenantId !== issuerContext.tenant.id) {
      return context.json({ error: "invalid_login_challenge" }, 400);
    }

    // Look up client policy — registration must be allowed
    const client = await clientRepository.findByClientId(challenge.clientId);
    const policy =
      client !== null ? await clientAuthMethodPolicyRepository.findByClientId(client.id) : null;

    if (policy === null || !policy.password.allowRegistration) {
      return context.json({ error: "registration_not_allowed" }, 403);
    }

    // Validate input
    const email = (payload.email ?? "").trim().toLowerCase();
    const username = (payload.username ?? "").trim() || null;
    const password = payload.password ?? "";

    if (!email.includes("@") || password.length < 8) {
      return context.json({ error: "invalid_request" }, 400);
    }

    // Check for duplicate email
    const existing = await userRepository.findUserByEmail(issuerContext.tenant.id, email);
    if (existing !== null) {
      return context.json({ error: "email_already_exists" }, 409);
    }

    const now = new Date().toISOString();
    const newUser = {
      id: crypto.randomUUID(),
      tenantId: issuerContext.tenant.id,
      email,
      emailVerified: false,
      username,
      displayName: username ?? email.split("@")[0],
      status: "active" as const,
      createdAt: now,
      updatedAt: now
    };

    const passwordHash = await hashPassword(password);

    const credential = {
      id: crypto.randomUUID(),
      tenantId: issuerContext.tenant.id,
      userId: newUser.id,
      passwordHash,
      createdAt: now,
      updatedAt: now
    };

    // Consume the login challenge before creating the user to prevent replay attacks
    const challengeConsumed = await loginChallengeLookupRepository.consume(challenge.id, now);
    if (!challengeConsumed) {
      return context.json({ error: "invalid_login_challenge" }, 400);
    }

    // Create user with immediately-consumed invitation (for D1 batch atomicity)
    await userRepository.createProvisionedUserWithInvitation({
      user: newUser,
      invitation: {
        id: crypto.randomUUID(),
        tenantId: issuerContext.tenant.id,
        userId: newUser.id,
        tokenHash: crypto.randomUUID(), // placeholder — never used
        purpose: "account_activation",
        expiresAt: new Date(Date.now() + 1000).toISOString(), // immediately expired
        consumedAt: now, // mark consumed immediately
        createdAt: now
      }
    });
    await userRepository.upsertPasswordCredential(credential);

    const { session, sessionToken } = await createBrowserSession({
      sessionRepository: browserSessionRepository,
      tenantId: newUser.tenantId,
      userId: newUser.id
    });

    await recordAuditEventBestEffort({
      actorType: "end_user",
      actorId: newUser.id,
      tenantId: issuerContext.tenant.id,
      eventType: "user.self_registration.succeeded",
      targetType: "user",
      targetId: newUser.id,
      payload: { client_id: challenge.clientId }
    });

    context.header(
      "Set-Cookie",
      buildBrowserSessionCookie({
        expiresAt: session.expiresAt,
        secure: new URL(issuerContext.issuer).protocol === "https:",
        sessionToken
      })
    );

    const authorizationResult = await authorizeRequest({
      authMethod: "password",
      authorizationCodeRepository,
      clientRepository,
      issuerContext,
      loginChallengeRepository,
      request: {
        clientId: challenge.clientId,
        redirectUri: challenge.redirectUri,
        responseType: "code",
        scope: challenge.scope,
        state: challenge.state.length === 0 ? null : challenge.state,
        nonce: challenge.nonce,
        codeChallenge: challenge.codeChallenge,
        codeChallengeMethod: challenge.codeChallengeMethod
      },
      session: { userId: newUser.id, tenantId: newUser.tenantId }
    });

    if (authorizationResult.kind === "error") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: newUser.id,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.failed",
        targetId: authorizationResult.clientId,
        payload: {
          client_id: authorizationResult.clientId,
          reason: authorizationResult.error,
          redirect_uri: authorizationResult.redirectUri
        }
      });

      if (authorizationResult.shouldRedirect && authorizationResult.redirectUri !== null) {
        return context.json(
          {
            redirect_uri: buildClientErrorRedirectUrl({
              error: authorizationResult.error,
              errorDescription: authorizationResult.errorDescription,
              redirectUri: authorizationResult.redirectUri,
              state: authorizationResult.state
            })
          },
          200
        );
      }

      return context.json(
        authorizationResult.errorDescription === undefined
          ? { error: authorizationResult.error }
          : {
              error: authorizationResult.error,
              error_description: authorizationResult.errorDescription
            },
        400
      );
    }

    if (authorizationResult.kind === "consent_required") {
      await recordAuthorizeAuditEvent({
        actorType: "end_user",
        actorId: newUser.id,
        tenantId: issuerContext.tenant.id,
        eventType: "oidc.authorization.deferred",
        targetId: authorizationResult.request.clientId,
        payload: {
          client_id: authorizationResult.request.clientId,
          reason: "consent_required",
          redirect_uri: authorizationResult.request.redirectUri
        }
      });

      return context.json(
        {
          redirect_uri: buildClientErrorRedirectUrl({
            error: "consent_required",
            redirectUri: authorizationResult.request.redirectUri,
            state: authorizationResult.request.state
          })
        },
        200
      );
    }

    if (authorizationResult.kind !== "authorization_granted") {
      return context.json({ error: "authorization_failed" }, 500);
    }

    await recordAuthorizeAuditEvent({
      actorType: "end_user",
      actorId: newUser.id,
      tenantId: issuerContext.tenant.id,
      eventType: "oidc.authorization.succeeded",
      targetId: authorizationResult.request.clientId,
      payload: {
        user_id: newUser.id,
        redirect_uri: authorizationResult.request.redirectUri
      }
    });

    const redirectUrl = new URL(authorizationResult.request.redirectUri);
    redirectUrl.searchParams.set("code", authorizationResult.code);
    if (authorizationResult.request.state !== null) {
      redirectUrl.searchParams.set("state", authorizationResult.request.state);
    }
    return context.json({ redirect_uri: redirectUrl.toString() }, 200);
  });

  const tenantToWire = (tenant: Tenant) => ({
    id: tenant.id,
    slug: tenant.slug,
    display_name: tenant.displayName,
    status: tenant.status,
    issuer: tenant.issuers.find((i) => i.isPrimary)?.issuerUrl ?? null
  });

  app.post("/admin/login", async (context) => {
    const payload = await context.req.json<{ email?: string; password?: string }>();
    const result = await loginAdmin({
      adminBootstrapPasswordHash,
      adminWhitelist,
      adminRepository,
      email: payload.email ?? "",
      password: payload.password ?? ""
    });

    if (!result.ok) {
      await auditRepository.record({
        id: crypto.randomUUID(),
        actorType: "admin_login_attempt",
        actorId: payload.email ?? null,
        tenantId: null,
        eventType: "admin.login.failed",
        targetType: "admin_user",
        targetId: payload.email ?? null,
        payload: null,
        occurredAt: new Date().toISOString()
      });
      return context.json({ error: result.reason }, result.reason === "forbidden" ? 403 : 401);
    }

    await auditRepository.record({
      id: crypto.randomUUID(),
      actorType: "admin_user",
      actorId: result.user.id,
      tenantId: null,
      eventType: "admin.login.succeeded",
      targetType: "admin_user",
      targetId: result.user.id,
      payload: {
        email: result.user.email
      },
      occurredAt: new Date().toISOString()
    });

    return context.json({
      email: result.user.email,
      session_token: result.sessionToken
    });
  });

  app.post("/admin/tenants", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });

    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }

    const payload = await context.req.json<{ display_name?: string; slug?: string }>();
    const slug = payload.slug?.trim() ?? "";
    const displayName = payload.display_name?.trim() ?? "";

    if (slug.length === 0 || displayName.length === 0) {
      return context.json({ error: "invalid_request" }, 400);
    }

    if ((await tenantRepository.findBySlug(slug)) !== null) {
      return context.json({ error: "conflict" }, 409);
    }

    const tenantId = crypto.randomUUID();
    await tenantRepository.create({
      id: tenantId,
      slug,
      displayName,
      status: "active",
      issuers: [
        {
          id: crypto.randomUUID(),
          issuerType: "platform_path",
          issuerUrl: `https://${oidcHost}/t/${slug}`,
          domain: null,
          isPrimary: true,
          verificationStatus: "verified"
        }
      ]
    });

    await auditRepository.record({
      id: crypto.randomUUID(),
      actorType: "admin_user",
      actorId: session.adminUserId,
      tenantId,
      eventType: "tenant.created",
      targetType: "tenant",
      targetId: tenantId,
      payload: {
        slug
      },
      occurredAt: new Date().toISOString()
    });

    return context.json(
      {
        id: tenantId,
        slug,
        display_name: displayName,
        issuer: `https://${oidcHost}/t/${slug}`
      },
      201
    );
  });

  app.post("/admin/tenants/:tenantId/users", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });

    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }

    const tenantId = context.req.param("tenantId");
    const payload = await context.req.json<{
      display_name?: string;
      email?: string;
      username?: string | null;
    }>();
    const email = payload.email?.trim() ?? "";
    const displayName = payload.display_name?.trim() ?? "";
    const username = payload.username?.trim();

    if (email.length === 0 || displayName.length === 0) {
      return context.json({ error: "invalid_request" }, 400);
    }

    if ((await tenantRepository.findById(tenantId)) === null) {
      return context.json({ error: "tenant_not_found" }, 404);
    }

    let result: Awaited<ReturnType<typeof provisionUser>>;

    try {
      result = await provisionUser({
        userRepository,
        tenantId,
        email,
        username,
        displayName
      });
    } catch (error) {
      await recordAuditEventBestEffort({
        actorType: "admin_user",
        actorId: session.adminUserId,
        tenantId,
        eventType: "user.provision.failed",
        targetType: "user",
        targetId: null,
        payload: {
          error: error instanceof Error ? error.message : "unknown_error",
          email
        }
      });

      return context.json({ error: isProvisionConflictError(error) ? "conflict" : "internal_error" }, isProvisionConflictError(error) ? 409 : 500);
    }

    const activationUrl = new URL("/activate-account", context.req.url);

    activationUrl.searchParams.set("token", result.invitationToken);

    await recordAuditEventBestEffort({
      actorType: "admin_user",
      actorId: session.adminUserId,
      tenantId,
      eventType: "user.provisioned",
      targetType: "user",
      targetId: result.user.id,
      payload: {
        email: result.user.email
      }
    });

    return context.json(
      {
        user: {
          id: result.user.id,
          tenant_id: result.user.tenantId,
          email: result.user.email,
          username: result.user.username,
          display_name: result.user.displayName,
          status: result.user.status,
          email_verified: result.user.emailVerified
        },
        invitation_token: result.invitationToken,
        activation_url: activationUrl.toString()
      },
      201
    );
  });

  app.get("/admin/tenants", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const allTenants = await tenantRepository.list();
    return context.json({ tenants: allTenants.map(tenantToWire) });
  });

  app.get("/admin/tenants/:tenantId", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) {
      return context.notFound();
    }
    return context.json(tenantToWire(tenant));
  });

  app.patch("/admin/tenants/:tenantId", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) {
      return context.notFound();
    }
    const payload = await context.req.json<{
      display_name?: string;
      status?: string;
      primary_issuer_url?: string;
    }>();
    const input: import("../domain/tenants/repository").TenantUpdateInput = {};
    if (payload.display_name !== undefined) {
      const v = payload.display_name.trim();
      if (v.length === 0) return context.json({ error: "invalid_request" }, 400);
      input.displayName = v;
    }
    if (payload.status !== undefined) {
      if (payload.status !== "active" && payload.status !== "disabled") {
        return context.json({ error: "invalid_request" }, 400);
      }
      input.status = payload.status;
    }
    if (payload.primary_issuer_url !== undefined) {
      const v = payload.primary_issuer_url.trim();
      if (v.length === 0) return context.json({ error: "invalid_request" }, 400);
      input.primaryIssuerUrl = v;
    }
    await tenantRepository.update(tenantId, input);
    const updated = await tenantRepository.findById(tenantId);
    return context.json(tenantToWire(updated!));
  });

  app.post("/admin/tenants/:tenantId/keys/rotate", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    if (signer === undefined) {
      return context.json({ error: "key_rotation_unavailable" }, 503);
    }
    const tenantId = context.req.param("tenantId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) {
      return context.notFound();
    }
    const rotatedAt = new Date().toISOString();
    try {
      await keyRepository.retireActiveKeysForTenant(tenantId, rotatedAt);
      const material = await signer.ensureActiveSigningKeyMaterial(tenantId);
      await auditRepository.record({
        id: crypto.randomUUID(),
        actorType: "admin_user",
        actorId: session.adminUserId,
        tenantId,
        eventType: "signing_key.rotated",
        targetType: "signing_key",
        targetId: material.key.kid,
        payload: { alg: material.key.alg, rotated_at: rotatedAt },
        occurredAt: rotatedAt
      });
      return context.json({ kid: material.key.kid, alg: material.key.alg, rotated_at: rotatedAt }, 200);
    } catch {
      return context.json({ error: "key_rotation_failed" }, 500);
    }
  });

  app.delete("/admin/tenants/:tenantId", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) {
      return context.notFound();
    }
    await tenantRepository.delete(tenantId);
    await recordAuditEventBestEffort({
      actorType: "admin_user",
      actorId: session.adminUserId,
      tenantId: null,
      eventType: "tenant.deleted",
      targetType: "tenant",
      targetId: tenantId,
      payload: { slug: tenant.slug }
    });
    return context.json({ deleted: true });
  });

  app.get("/admin/tenants/:tenantId/users", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) {
      return context.notFound();
    }
    const userList = await userRepository.listByTenantId(tenantId);
    return context.json({
      users: userList.map((u) => ({
        id: u.id,
        email: u.email,
        display_name: u.displayName,
        status: u.status
      }))
    });
  });

  app.get("/admin/tenants/:tenantId/clients", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) {
      return context.notFound();
    }
    const clients = await clientRepository.listByTenantId(tenantId);

    // Fetch policies for all clients in parallel
    const [policies, claimLists] = await Promise.all([
      Promise.all(
        clients.map((c) => clientAuthMethodPolicyRepository.findByClientId(c.id))
      ),
      Promise.all(
        clients.map((c) => accessTokenClaimsRepository.listByClientId(c.id))
      )
    ]);

    return context.json({
      clients: clients.map((c, i) => ({
        id: c.id,
        client_id: c.clientId,
        client_name: c.clientName,
        application_type: c.applicationType,
        client_profile: c.clientProfile,
        access_token_audience: c.accessTokenAudience,
        access_token_custom_claims_count: claimLists[i]?.length ?? 0,
        redirect_uris: c.redirectUris,
        grant_types: c.grantTypes,
        response_types: c.responseTypes,
        token_endpoint_auth_method: c.tokenEndpointAuthMethod,
        trust_level: c.trustLevel,
        consent_policy: c.consentPolicy,
        auth_method_policy: policyToWire(policies[i])
      }))
    });
  });

  app.get("/admin/tenants/:tenantId/clients/:clientId", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const clientId = context.req.param("clientId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) return context.notFound();

    const client = await clientRepository.findByClientId(clientId);
    if (client === null || client.tenantId !== tenantId) return context.notFound();

    let policy = await clientAuthMethodPolicyRepository.findByClientId(client.id);
    const claims = await accessTokenClaimsRepository.listByClientId(client.id);
    if (policy === null) {
      // Synthesize and persist default all-disabled policy on first access (handles pre-migration clients)
      policy = createDefaultClientAuthMethodPolicy(client.id, client.tenantId);
      await clientAuthMethodPolicyRepository.create(policy);
    }

    return context.json({
      id: client.id,
      client_id: client.clientId,
      client_name: client.clientName,
      application_type: client.applicationType,
      client_profile: client.clientProfile,
      access_token_audience: client.accessTokenAudience,
      access_token_custom_claims_count: claims.length,
      access_token_custom_claims: claims.map((c) => ({
        claim_name: c.claimName,
        source_type: c.sourceType,
        fixed_value: c.fixedValue,
        user_field: c.userField
      })),
      redirect_uris: client.redirectUris,
      grant_types: client.grantTypes,
      response_types: client.responseTypes,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      trust_level: client.trustLevel,
      consent_policy: client.consentPolicy,
      auth_method_policy: policyToWire(policy)
    });
  });

  app.patch("/admin/tenants/:tenantId/clients/:clientId/auth-method-policy", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const clientId = context.req.param("clientId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) return context.notFound();

    const client = await clientRepository.findByClientId(clientId);
    if (client === null || client.tenantId !== tenantId) return context.notFound();

    const existingOrNull = await clientAuthMethodPolicyRepository.findByClientId(client.id);
    const existing =
      existingOrNull ?? createDefaultClientAuthMethodPolicy(client.id, client.tenantId);

    let body: Record<string, unknown>;
    try {
      body = await context.req.json();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    // Partial merge — only override fields that are present in the body
    const pw = typeof body.password === "object" && body.password !== null
      ? body.password as Record<string, unknown> : {};
    const ml = typeof body.magic_link === "object" && body.magic_link !== null
      ? body.magic_link as Record<string, unknown> : {};
    const pk = typeof body.passkey === "object" && body.passkey !== null
      ? body.passkey as Record<string, unknown> : {};
    const go = typeof body.google === "object" && body.google !== null
      ? body.google as Record<string, unknown> : {};
    const ap = typeof body.apple === "object" && body.apple !== null
      ? body.apple as Record<string, unknown> : {};
    const fb = typeof body.facebook === "object" && body.facebook !== null
      ? body.facebook as Record<string, unknown> : {};
    const wc = typeof body.wechat === "object" && body.wechat !== null
      ? body.wechat as Record<string, unknown> : {};

    const merged: ClientAuthMethodPolicy = {
      clientId: existing.clientId,
      tenantId: existing.tenantId,
      password: {
        enabled: typeof pw.enabled === "boolean" ? pw.enabled : existing.password.enabled,
        allowRegistration: typeof pw.allow_registration === "boolean"
          ? pw.allow_registration : existing.password.allowRegistration,
        tokenTtlSeconds: resolveTokenTtl(
          pw.token_ttl_seconds,
          existing.password.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
        )
      },
      emailMagicLink: {
        enabled: typeof ml.enabled === "boolean" ? ml.enabled : existing.emailMagicLink.enabled,
        allowRegistration: typeof ml.allow_registration === "boolean"
          ? ml.allow_registration : existing.emailMagicLink.allowRegistration,
        tokenTtlSeconds: resolveTokenTtl(
          ml.token_ttl_seconds,
          existing.emailMagicLink.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
        )
      },
      passkey: {
        enabled: typeof pk.enabled === "boolean" ? pk.enabled : existing.passkey.enabled,
        allowRegistration: typeof pk.allow_registration === "boolean"
          ? pk.allow_registration : existing.passkey.allowRegistration,
        tokenTtlSeconds: resolveTokenTtl(
          pk.token_ttl_seconds,
          existing.passkey.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
        )
      },
      google: {
        enabled: typeof go.enabled === "boolean" ? go.enabled : existing.google.enabled,
        tokenTtlSeconds: resolveTokenTtl(
          go.token_ttl_seconds,
          existing.google.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
        )
      },
      apple: {
        enabled: typeof ap.enabled === "boolean" ? ap.enabled : existing.apple.enabled,
        tokenTtlSeconds: resolveTokenTtl(
          ap.token_ttl_seconds,
          existing.apple.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
        )
      },
      facebook: {
        enabled: typeof fb.enabled === "boolean" ? fb.enabled : existing.facebook.enabled,
        tokenTtlSeconds: resolveTokenTtl(
          fb.token_ttl_seconds,
          existing.facebook.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
        )
      },
      wechat: {
        enabled: typeof wc.enabled === "boolean" ? wc.enabled : existing.wechat.enabled,
        tokenTtlSeconds: resolveTokenTtl(
          wc.token_ttl_seconds,
          existing.wechat.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS
        )
      },
      mfaRequired: typeof body.mfa_required === "boolean" ? body.mfa_required : existing.mfaRequired
    };

    if (existingOrNull === null) {
      await clientAuthMethodPolicyRepository.create(merged);
    } else {
      await clientAuthMethodPolicyRepository.update(merged);
    }

    await auditRepository.record({
      id: crypto.randomUUID(),
      actorType: "admin_user",
      actorId: session.adminUserId,
      tenantId,
      eventType: "oidc.client.auth_method_policy.updated",
      targetType: "oidc_client",
      targetId: client.clientId,
      payload: policyToWire(merged),
      occurredAt: new Date().toISOString()
    });

    return context.json({ auth_method_policy: policyToWire(merged) });
  });

  app.post("/admin/tenants/:tenantId/clients", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) {
      return context.notFound();
    }
    const issuerContext = await resolveIssuerContextBySlug({
      slug: tenant.slug,
      oidcHost,
      tenantRepository
    });
    if (issuerContext === null) {
      return context.json({ error: "issuer_not_found" }, 422);
    }
    let payload: unknown;
    try {
      payload = await context.req.json();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }
    try {
      const result = await registerClientFromAdmin({
        accessTokenClaimsRepository,
        clientRepository,
        input: payload,
        issuerContext
      });
      const tokenHash = await sha256Base64Url(result.registrationAccessToken);
      try {
        await registrationAccessTokenRepository.store({
          clientId: result.client.clientId,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          issuer: issuerContext.issuer,
          tenantId,
          tokenHash
        });
        // Create default all-disabled auth method policy
        await clientAuthMethodPolicyRepository.create(
          createDefaultClientAuthMethodPolicy(result.client.id, result.client.tenantId)
        );
        await auditRepository.record({
          id: crypto.randomUUID(),
          actorType: "admin_user",
          actorId: session.adminUserId,
          tenantId,
          eventType: "oidc.client.registered",
          targetType: "oidc_client",
          targetId: result.client.clientId,
          payload: {
            application_type: result.client.applicationType,
            client_name: result.client.clientName,
            client_profile: result.client.clientProfile,
            access_token_audience: result.client.accessTokenAudience
          },
          occurredAt: new Date().toISOString()
        });
      } catch (error) {
        await Promise.allSettled([
          clientRepository.deleteByClientId(result.client.clientId),
          registrationAccessTokenRepository.deleteByTokenHash(tokenHash)
        ]);
        throw error;
      }
      return context.json(
        {
          client_id: result.client.clientId,
          client_secret: result.clientSecret,
          client_name: result.client.clientName,
          redirect_uris: result.client.redirectUris,
          application_type: result.client.applicationType,
          token_endpoint_auth_method: result.client.tokenEndpointAuthMethod,
          grant_types: result.client.grantTypes,
          response_types: result.client.responseTypes,
          trust_level: result.client.trustLevel,
          consent_policy: result.client.consentPolicy,
          client_profile: result.client.clientProfile,
          access_token_audience: result.client.accessTokenAudience
        },
        201
      );
    } catch (error) {
      if (error instanceof ZodError) {
        return context.json({ error: "invalid_client_metadata", issues: error.issues }, 400);
      }
      throw error;
    }
  });

  app.delete("/admin/tenants/:tenantId/clients/:clientId", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const clientId = context.req.param("clientId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) return context.notFound();

    const client = await clientRepository.findByClientId(clientId);
    if (client === null || client.tenantId !== tenantId) return context.notFound();

    // Cascade deletes in DB handle client_access_token_claims and client_auth_method_policies
    await clientRepository.deleteByClientId(clientId);

    await auditRepository.record({
      id: crypto.randomUUID(),
      actorType: "admin_user",
      actorId: session.adminUserId,
      tenantId,
      eventType: "oidc.client.deleted",
      targetType: "oidc_client",
      targetId: clientId,
      payload: { client_name: client.clientName },
      occurredAt: new Date().toISOString()
    });

    return context.json({ deleted: true });
  });

  app.patch("/admin/tenants/:tenantId/clients/:clientId", async (context) => {
    const session = await authenticateAdminSession({
      adminRepository,
      authorizationHeader: context.req.header("authorization")
    });
    if (session === null) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const tenantId = context.req.param("tenantId");
    const clientId = context.req.param("clientId");
    const tenant = await tenantRepository.findById(tenantId);
    if (tenant === null) return context.notFound();

    const client = await clientRepository.findByClientId(clientId);
    if (client === null || client.tenantId !== tenantId) return context.notFound();

    let body: unknown;
    try {
      body = await context.req.json();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    try {
      const parsed = adminClientUpdateSchema.parse(body);

      // Apply updates to client fields
      const updated = { ...client };
      if (parsed.client_name !== undefined) updated.clientName = parsed.client_name;
      if (parsed.client_profile !== undefined) updated.clientProfile = parsed.client_profile;
      if (parsed.application_type !== undefined) updated.applicationType = parsed.application_type;
      if (parsed.token_endpoint_auth_method !== undefined) {
        updated.tokenEndpointAuthMethod = parsed.token_endpoint_auth_method;
      }
      if (parsed.redirect_uris !== undefined) updated.redirectUris = parsed.redirect_uris;
      if (parsed.access_token_audience !== undefined) {
        updated.accessTokenAudience = parsed.access_token_audience;
      }

      // Validate SPA audience requirement after merge
      if (updated.clientProfile === "spa" && !updated.accessTokenAudience) {
        return context.json(
          { error: "invalid_client_metadata", message: "SPA clients require an access_token_audience" },
          400
        );
      }

      await clientRepository.update(updated);

      // Replace custom claims if provided
      if (parsed.access_token_custom_claims !== undefined) {
        const now = new Date().toISOString();
        const newClaims: AccessTokenCustomClaim[] = parsed.access_token_custom_claims.map(
          (c) => ({
            id: crypto.randomUUID(),
            clientId: client.id,
            tenantId,
            claimName: c.claim_name,
            sourceType: c.source_type,
            fixedValue: c.source_type === "fixed" ? (c.fixed_value ?? null) : null,
            userField:
              c.source_type === "user_field"
                ? ((c.user_field ?? null) as AccessTokenClaimUserField | null)
                : null,
            createdAt: now,
            updatedAt: now
          })
        );
        await accessTokenClaimsRepository.replaceAllForClient(client.id, newClaims);
      }

      const claims = await accessTokenClaimsRepository.listByClientId(client.id);
      const policy = await clientAuthMethodPolicyRepository.findByClientId(client.id);

      await auditRepository.record({
        id: crypto.randomUUID(),
        actorType: "admin_user",
        actorId: session.adminUserId,
        tenantId,
        eventType: "oidc.client.updated",
        targetType: "oidc_client",
        targetId: clientId,
        payload: parsed,
        occurredAt: new Date().toISOString()
      });

      return context.json({
        id: updated.id,
        client_id: updated.clientId,
        client_name: updated.clientName,
        application_type: updated.applicationType,
        client_profile: updated.clientProfile,
        access_token_audience: updated.accessTokenAudience,
        access_token_custom_claims_count: claims.length,
        redirect_uris: updated.redirectUris,
        grant_types: updated.grantTypes,
        response_types: updated.responseTypes,
        token_endpoint_auth_method: updated.tokenEndpointAuthMethod,
        trust_level: updated.trustLevel,
        consent_policy: updated.consentPolicy,
        auth_method_policy: policyToWire(policy)
      });
    } catch (error) {
      if (error instanceof ZodError) {
        return context.json({ error: "invalid_client_metadata", issues: error.issues }, 400);
      }
      throw error;
    }
  });

  // ---------------------------------------------------------------------------
  // POST /db/execTemplate
  // Reads a SQL template from R2, substitutes parameters (token context
  // overrides caller-supplied params), and executes it against SurrealDB.
  // ---------------------------------------------------------------------------
  app.post("/db/execTemplate", async (context) => {
    // 1. Resolve tenant: x-mp-tenant header (slug) or parse Bearer token
    const tenantSlug = context.req.header("x-mp-tenant")?.trim() ?? null;
    const authorizationHeader = context.req.header("authorization") ?? "";

    let issuerContext: Awaited<ReturnType<typeof resolveIssuerContextBySlug>> | null = null;

    if (tenantSlug !== null && tenantSlug.length > 0) {
      issuerContext = await resolveIssuerContextBySlug({
        slug: tenantSlug,
        oidcHost,
        tenantRepository
      });
    } else {
      // Try to derive tenant from the Bearer token's issuer claim
      const bearerMatch = authorizationHeader.match(/^Bearer\s+(.+)$/i);
      if (bearerMatch) {
        try {
          // Decode header/payload without verification first to extract issuer
          const [, payloadB64] = bearerMatch[1].split(".");
          const payloadJson = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
          const iss: string = payloadJson.iss ?? "";
          // issuer looks like https://o.{domain}/t/{slug} — extract slug
          const slugFromIss = iss.split("/t/")[1]?.split("/")[0] ?? null;
          if (slugFromIss) {
            issuerContext = await resolveIssuerContextBySlug({
              slug: slugFromIss,
              oidcHost,
              tenantRepository
            });
          }
        } catch {
          // fall through — issuerContext stays null
        }
      }
    }

    if (issuerContext === null) {
      return context.json({ error: "tenant_not_found" }, 404);
    }

    // 2. Validate Bearer token against tenant JWKS
    const bearerTokenMatch = authorizationHeader.match(/^Bearer\s+(.+)$/i);
    if (!bearerTokenMatch) {
      return context.json({ error: "unauthorized" }, 401);
    }
    const rawToken = bearerTokenMatch[1];

    let tokenClaims: Record<string, unknown> = {};
    try {
      const jwks = await buildJwks(keyRepository, issuerContext.tenant.id);
      if (jwks.keys.length === 0) {
        return context.json({ error: "no_signing_keys" }, 503);
      }
      const keySet = createLocalJWKSet(jwks as Parameters<typeof createLocalJWKSet>[0]);
      const { payload } = await jwtVerify(rawToken, keySet, {
        issuer: issuerContext.issuer
      });
      tokenClaims = payload as Record<string, unknown>;
    } catch {
      return context.json({ error: "invalid_token" }, 401);
    }

    // 3. Parse request body
    let body: { id?: unknown; params?: unknown };
    try {
      body = await context.req.json();
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }

    const templateId = typeof body.id === "string" ? body.id.trim() : "";
    if (templateId.length === 0) {
      return context.json({ error: "missing_template_id" }, 400);
    }

    const callerParams: Record<string, unknown> =
      body.params !== null && typeof body.params === "object" && !Array.isArray(body.params)
        ? (body.params as Record<string, unknown>)
        : {};

    // 4. Load SQL template from R2
    if (keyMaterialBucket === null) {
      return context.json({ error: "storage_not_configured" }, 503);
    }

    const templateKey = `db-templates/${templateId}.sql`;
    const templateObject = await keyMaterialBucket.get(templateKey);
    if (templateObject === null) {
      return context.json({ error: "template_not_found" }, 404);
    }
    const templateSql = await templateObject.text();

    // 5. Load SurrealDB credentials from R2
    const credsKey = "db-config/surrealdb.json";
    const credsObject = await keyMaterialBucket.get(credsKey);
    if (credsObject === null) {
      return context.json({ error: "db_credentials_not_configured" }, 503);
    }
    let dbCreds: { url: string; username: string; password: string; ns?: string; db?: string };
    try {
      dbCreds = await credsObject.json<typeof dbCreds>();
    } catch {
      return context.json({ error: "db_credentials_invalid" }, 503);
    }

    // 6. Merge params: token context fields override caller-supplied params
    // Map well-known JWT claims to parameter names
    const tokenContext: Record<string, unknown> = {};
    if (typeof tokenClaims.sub === "string") tokenContext["sub"] = tokenClaims.sub;
    if (typeof tokenClaims.email === "string") tokenContext["email"] = tokenClaims.email;
    // Copy any extra non-reserved claims from the token
    const reservedClaims = new Set(["iss", "aud", "exp", "iat", "nbf", "jti", "nonce"]);
    for (const [k, v] of Object.entries(tokenClaims)) {
      if (!reservedClaims.has(k)) {
        tokenContext[k] = v;
      }
    }
    // Token claims override caller-provided params with the same name
    const mergedParams: Record<string, unknown> = { ...callerParams, ...tokenContext };

    // 7. Substitute $param placeholders in the SQL template
    // Parameters in SurrealDB SQL use $name syntax — we pass them as query vars
    // We also do a simple string substitution for non-SurrealDB contexts
    // For SurrealDB we pass params via the query string (age=value style)
    // Build the endpoint URL with query params for simple scalar values
    const queryUrl = new URL(dbCreds.url);
    for (const [k, v] of Object.entries(mergedParams)) {
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
        queryUrl.searchParams.set(k, String(v));
      }
    }

    // 8. Execute against SurrealDB
    const basicCredential = btoa(`${dbCreds.username}:${dbCreds.password}`);
    let surrealResponse: Response;
    try {
      surrealResponse = await fetch(queryUrl.toString(), {
        method: "POST",
        headers: {
          "Authorization": `Basic ${basicCredential}`,
          "Surreal-NS": dbCreds.ns ?? "main",
          "Surreal-DB": dbCreds.db ?? "docs",
          "Accept": "application/json",
          "Content-Type": "text/plain"
        },
        body: templateSql
      });
    } catch (err) {
      return context.json({ error: "db_request_failed" }, 502);
    }

    if (!surrealResponse.ok && surrealResponse.status >= 500) {
      return context.json({ error: "db_error", status: surrealResponse.status }, 502);
    }

    let result: unknown;
    try {
      result = await surrealResponse.json();
    } catch {
      const text = await surrealResponse.text();
      return context.json({ error: "db_response_invalid", body: text }, 502);
    }

    return context.json({ result }, surrealResponse.ok ? 200 : 400);
  });

  app.post("/activate-account", async (context) => {
    const payload = await context.req.json<{
      invitation_token?: string;
      password?: string;
    }>();
    const invitationTokenFromBody = payload.invitation_token?.trim() ?? "";
    const invitationTokenFromQuery = new URL(context.req.url).searchParams.get("token")?.trim() ?? "";
    const invitationToken =
      invitationTokenFromBody.length > 0 ? invitationTokenFromBody : invitationTokenFromQuery;
    const password = payload.password ?? "";

    if (invitationToken.length === 0 || password.length === 0) {
      return context.json({ error: "invalid_request" }, 400);
    }

    const result = await activateUser({
      userRepository,
      invitationToken,
      password
    });

    if (!result.ok) {
      await recordAuditEventBestEffort({
        actorType: "anonymous",
        actorId: null,
        tenantId: null,
        eventType: "user.activation.failed",
        targetType: "activation_invitation",
        targetId: null,
        payload: {
          reason: result.reason
        }
      });

      if (result.reason === "invalid_invitation" || result.reason === "invitation_expired") {
        return context.json({ error: result.reason }, 400);
      }

      if (result.reason === "invitation_already_used" || result.reason === "user_already_initialized") {
        return context.json({ error: result.reason }, 409);
      }

      return context.json({ error: result.reason }, 403);
    }

    await recordAuditEventBestEffort({
      actorType: "end_user",
      actorId: result.user.id,
      tenantId: result.user.tenantId,
      eventType: "user.activation.succeeded",
      targetType: "user",
      targetId: result.user.id,
      payload: null
    });

    return context.json({
      user: {
        id: result.user.id,
        tenant_id: result.user.tenantId,
        email: result.user.email,
        username: result.user.username,
        display_name: result.user.displayName,
        status: result.user.status,
        email_verified: result.user.emailVerified
      }
    });
  });

  return app;
};
