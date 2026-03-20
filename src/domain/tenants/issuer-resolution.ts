import type { TenantRepository } from "./repository";
import type { IssuerType, ResolvedIssuerContext, Tenant, TenantIssuer } from "./types";

interface ResolveIssuerContextInput {
  requestUrl: string;
  platformHost: string;
  tenantRepository: TenantRepository;
}

const findIssuerByType = (tenant: Tenant, issuerType: IssuerType) =>
  tenant.issuers.find((issuer) => issuer.issuerType === issuerType) ?? null;

const toResolvedContext = (
  tenant: Tenant,
  issuer: TenantIssuer,
  requestHost: string
): ResolvedIssuerContext => ({
  tenant,
  issuer: issuer.issuerUrl,
  issuerPathPrefix: issuer.issuerType === "platform_path" ? `/t/${tenant.slug}` : "",
  source: issuer.issuerType,
  requestHost
});

export const resolveIssuerContext = async ({
  requestUrl,
  platformHost,
  tenantRepository
}: ResolveIssuerContextInput): Promise<ResolvedIssuerContext | null> => {
  const url = new URL(requestUrl);
  const requestHost = url.host;

  const customDomainTenant = await tenantRepository.findByCustomDomain(requestHost);

  if (customDomainTenant !== null) {
    const customDomainIssuer = findIssuerByType(customDomainTenant, "custom_domain");

    if (customDomainIssuer !== null) {
      return toResolvedContext(customDomainTenant, customDomainIssuer, requestHost);
    }
  }

  if (requestHost !== platformHost) {
    return null;
  }

  const match = url.pathname.match(/^\/t\/([^/]+)(?:\/|$)/);

  if (match === null) {
    return null;
  }

  const tenant = await tenantRepository.findBySlug(match[1]);

  if (tenant === null) {
    return null;
  }

  const platformIssuer = findIssuerByType(tenant, "platform_path");

  return platformIssuer === null ? null : toResolvedContext(tenant, platformIssuer, requestHost);
};
