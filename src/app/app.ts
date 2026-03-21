import { Hono, type Context } from "hono";
import { ZodError } from "zod";

import { authenticateWithPassword } from "../adapters/auth/local-auth/password-auth-service";
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
import type { RegistrationAccessTokenRepository } from "../domain/clients/registration-access-token-repository";
import { sha256Base64Url } from "../lib/hash";
import { registerClient } from "../domain/clients/register-client";
import type { ClientRepository } from "../domain/clients/repository";
import { buildJwks } from "../domain/keys/jwks";
import type { SigningKeySigner } from "../domain/keys/signer";
import type { KeyRepository } from "../domain/keys/repository";
import type { TenantRepository } from "../domain/tenants/repository";
import { resolveIssuerContext } from "../domain/tenants/issuer-resolution";
import { buildDiscoveryMetadata } from "../domain/oidc/discovery";
import { exchangeAuthorizationCode } from "../domain/tokens/token-service";
import { activateUser } from "../domain/users/activate-user";
import { provisionUser } from "../domain/users/provision-user";
import type { UserRepository } from "../domain/users/repository";

class EmptyTenantRepository implements TenantRepository {
  async create(): Promise<void> {
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
}

class EmptyKeyRepository implements KeyRepository {
  async listActiveKeysForTenant(): Promise<[]> {
    return [];
  }
}

class EmptyClientRepository implements ClientRepository {
  async create(): Promise<void> {
    return;
  }

  async deleteByClientId(): Promise<void> {
    return;
  }

  async findByClientId(): Promise<null> {
    return null;
  }
}

class EmptyRegistrationAccessTokenRepository implements RegistrationAccessTokenRepository {
  async deleteByTokenHash(): Promise<void> {
    return;
  }

  async store(): Promise<void> {
    return;
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

  async updateUser(): Promise<void> {
    return;
  }

  async upsertPasswordCredential(): Promise<void> {
    return;
  }
}

export interface AppOptions {
  adminBootstrapPassword?: string;
  adminWhitelist?: string[];
  adminRepository?: AdminRepository;
  auditRepository?: AuditRepository;
  authorizationCodeRepository?: AuthorizationCodeRepository;
  authorizeSessionResolver?: (context: Context) => Promise<AuthorizeSession | null> | AuthorizeSession | null;
  browserSessionRepository?: BrowserSessionRepository;
  clientRepository?: ClientRepository;
  keyRepository?: KeyRepository;
  loginChallengeLookupRepository?: AuthenticationLoginChallengeRepository;
  loginChallengeRepository?: LoginChallengeRepository;
  managementApiToken?: string;
  platformHost?: string;
  registrationAccessTokenRepository?: RegistrationAccessTokenRepository;
  signer?: SigningKeySigner;
  tenantRepository?: TenantRepository;
  userRepository?: UserRepository;
}

export const createApp = (options: AppOptions = {}) => {
  const app = new Hono();
  const adminBootstrapPassword = options.adminBootstrapPassword ?? "";
  const adminWhitelist = options.adminWhitelist ?? [];
  const adminRepository = options.adminRepository ?? new EmptyAdminRepository();
  const auditRepository = options.auditRepository ?? new EmptyAuditRepository();
  const authorizationCodeRepository =
    options.authorizationCodeRepository ?? new EmptyAuthorizationCodeRepository();
  const authorizeSessionResolver = options.authorizeSessionResolver ?? (async () => null);
  const browserSessionRepository =
    options.browserSessionRepository ?? new EmptyBrowserSessionRepository();
  const clientRepository = options.clientRepository ?? new EmptyClientRepository();
  const keyRepository = options.keyRepository ?? new EmptyKeyRepository();
  const loginChallengeLookupRepository =
    options.loginChallengeLookupRepository ?? new EmptyAuthenticationLoginChallengeRepository();
  const loginChallengeRepository =
    options.loginChallengeRepository ?? new EmptyLoginChallengeRepository();
  const managementApiToken = options.managementApiToken ?? "";
  const tenantRepository = options.tenantRepository ?? new EmptyTenantRepository();
  const userRepository = options.userRepository ?? new EmptyUserRepository();
  const signer = options.signer;
  const registrationAccessTokenRepository =
    options.registrationAccessTokenRepository ?? new EmptyRegistrationAccessTokenRepository();
  const platformHost = options.platformHost ?? "localhost";

  const handleDiscovery = async (requestUrl: string) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl,
      platformHost,
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

  const createOpaqueToken = () => crypto.randomUUID().replaceAll("-", "");
  const authorizationCodeLifetimeMs = 5 * 60 * 1000;

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
      platformHost,
      tenantRepository
    });

    if (issuerContext === null) {
      return context.notFound();
    }

    const url = new URL(context.req.url);
    const session = await authorizeSessionResolver(context);
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
      const loginUrl = new URL(`${issuerContext.issuer}/login`);

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
    const issuerContext = await resolveIssuerContext({
      requestUrl: context.req.url,
      platformHost,
      tenantRepository
    });

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

  const handlePasswordLogin = async (context: Context) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl: context.req.url,
      platformHost,
      tenantRepository
    });

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

    const result = await authenticateWithPassword({
      loginChallengeRepository: loginChallengeLookupRepository,
      loginChallengeToken: String(formData.get("login_challenge") ?? ""),
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

    const { session, sessionToken } = await createBrowserSession({
      sessionRepository: browserSessionRepository,
      tenantId: result.user.tenantId,
      userId: result.user.id
    });
    const authorizationCodeToken = createOpaqueToken();

    await authorizationCodeRepository.create({
      id: crypto.randomUUID(),
      tenantId: result.challenge.tenantId,
      issuer: result.challenge.issuer,
      clientId: result.challenge.clientId,
      userId: result.user.id,
      redirectUri: result.challenge.redirectUri,
      scope: result.challenge.scope,
      nonce: result.challenge.nonce,
      codeChallenge: result.challenge.codeChallenge,
      codeChallengeMethod: result.challenge.codeChallengeMethod,
      tokenHash: await sha256Base64Url(authorizationCodeToken),
      expiresAt: new Date(Date.now() + authorizationCodeLifetimeMs).toISOString(),
      consumedAt: null,
      createdAt: new Date().toISOString()
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

    const redirectUrl = new URL(result.challenge.redirectUri);

    redirectUrl.searchParams.set("code", authorizationCodeToken);
    if (result.challenge.state.length > 0) {
      redirectUrl.searchParams.set("state", result.challenge.state);
    }

    context.header(
      "Set-Cookie",
      buildBrowserSessionCookie({
        expiresAt: session.expiresAt,
        secure: new URL(issuerContext.issuer).protocol === "https:",
        sessionToken
      })
    );

    return context.redirect(redirectUrl.toString(), 302);
  };

  const handlePlaceholderEndpoint = async (context: Context) => {
    const issuerContext = await resolveIssuerContext({
      requestUrl: context.req.url,
      platformHost,
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
      platformHost,
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
      clientRepository,
      issuerContext,
      request: {
        authorizationHeader: context.req.header("authorization"),
        grantType: String(formData.get("grant_type") ?? ""),
        code: String(formData.get("code") ?? ""),
        redirectUri: String(formData.get("redirect_uri") ?? ""),
        codeVerifier: String(formData.get("code_verifier") ?? ""),
        requestedClientId: formData.get("client_id")?.toString() ?? null,
        requestedClientSecret: formData.get("client_secret")?.toString() ?? null
      },
      signer
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
      platformHost,
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
      platformHost,
      tenantRepository
    });

    if (issuerContext === null) {
      return context.notFound();
    }

    return context.json(await buildJwks(keyRepository, issuerContext.tenant.id));
  });

  app.get("/login", handleLoginEntry);
  app.get("/t/:tenant/login", handleLoginEntry);
  app.post("/login/password", handlePasswordLogin);
  app.post("/t/:tenant/login/password", handlePasswordLogin);
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
      platformHost,
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

  app.post("/admin/login", async (context) => {
    const payload = await context.req.json<{ email?: string; password?: string }>();
    const result = await loginAdmin({
      adminBootstrapPassword,
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
          issuerUrl: `https://${platformHost}/t/${slug}`,
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
        issuer: `https://${platformHost}/t/${slug}`
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
