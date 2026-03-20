import { Hono } from "hono";

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

export interface AppOptions {
  platformHost?: string;
  tenantRepository?: TenantRepository;
}

export const createApp = (options: AppOptions = {}) => {
  const app = new Hono();
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

  return app;
};
