import { Hono } from "hono";
import { ZodError } from "zod";

import { registerClient } from "../domain/clients/register-client";
import type { ClientRepository } from "../domain/clients/repository";
import { buildJwks } from "../domain/keys/jwks";
import type { KeyRepository } from "../domain/keys/repository";
import type { TenantRepository } from "../domain/tenants/repository";
import { resolveIssuerContext } from "../domain/tenants/issuer-resolution";
import { buildDiscoveryMetadata } from "../domain/oidc/discovery";

class EmptyTenantRepository implements TenantRepository {
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

  async findByClientId(): Promise<null> {
    return null;
  }
}

export interface AppOptions {
  clientRepository?: ClientRepository;
  keyRepository?: KeyRepository;
  managementApiToken?: string;
  platformHost?: string;
  tenantRepository?: TenantRepository;
}

export const createApp = (options: AppOptions = {}) => {
  const app = new Hono();
  const clientRepository = options.clientRepository ?? new EmptyClientRepository();
  const keyRepository = options.keyRepository ?? new EmptyKeyRepository();
  const managementApiToken = options.managementApiToken ?? "";
  const tenantRepository = options.tenantRepository ?? new EmptyTenantRepository();
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

  return app;
};
