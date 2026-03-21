import { Hono } from "hono";
import { ZodError } from "zod";

import type { AuditRepository } from "../domain/audit/repository";
import { authenticateAdminSession, loginAdmin } from "../domain/admin-auth/service";
import type { AdminRepository } from "../domain/admin-auth/repository";
import type { RegistrationAccessTokenRepository } from "../domain/clients/registration-access-token-repository";
import { sha256Base64Url } from "../lib/hash";
import { registerClient } from "../domain/clients/register-client";
import type { ClientRepository } from "../domain/clients/repository";
import { buildJwks } from "../domain/keys/jwks";
import type { KeyRepository } from "../domain/keys/repository";
import type { TenantRepository } from "../domain/tenants/repository";
import { resolveIssuerContext } from "../domain/tenants/issuer-resolution";
import { buildDiscoveryMetadata } from "../domain/oidc/discovery";

class EmptyTenantRepository implements TenantRepository {
  async create(): Promise<void> {
    return;
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

export interface AppOptions {
  adminBootstrapPassword?: string;
  adminWhitelist?: string[];
  adminRepository?: AdminRepository;
  auditRepository?: AuditRepository;
  clientRepository?: ClientRepository;
  keyRepository?: KeyRepository;
  managementApiToken?: string;
  platformHost?: string;
  registrationAccessTokenRepository?: RegistrationAccessTokenRepository;
  tenantRepository?: TenantRepository;
}

export const createApp = (options: AppOptions = {}) => {
  const app = new Hono();
  const adminBootstrapPassword = options.adminBootstrapPassword ?? "";
  const adminWhitelist = options.adminWhitelist ?? [];
  const adminRepository = options.adminRepository ?? new EmptyAdminRepository();
  const auditRepository = options.auditRepository ?? new EmptyAuditRepository();
  const clientRepository = options.clientRepository ?? new EmptyClientRepository();
  const keyRepository = options.keyRepository ?? new EmptyKeyRepository();
  const managementApiToken = options.managementApiToken ?? "";
  const tenantRepository = options.tenantRepository ?? new EmptyTenantRepository();
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

  return app;
};
