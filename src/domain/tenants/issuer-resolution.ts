import type { TenantRepository } from "./repository";
import type { IssuerType, ResolvedIssuerContext, Tenant, TenantIssuer } from "./types";

interface ResolveIssuerContextInput {
  requestUrl: string;
  platformHost: string;
  tenantRepository: TenantRepository;
}

const isActiveTenant = (tenant: Tenant) => tenant.status === "active";

const normalizeHost = (value: string) => {
  const normalized = value.trim().toLowerCase();

  if (normalized.includes("://")) {
    return new URL(normalized).hostname.toLowerCase();
  }

  const bracketedIpv6Match = normalized.match(/^\[([^\]]+)\](?::\d+)?$/);

  if (bracketedIpv6Match !== null) {
    return bracketedIpv6Match[1];
  }

  return (normalized.match(/:/g)?.length ?? 0) === 1 ? normalized.split(":")[0] : normalized;
};

const findIssuerByType = (tenant: Tenant, issuerType: IssuerType) =>
  tenant.issuers.find((issuer) => issuer.issuerType === issuerType) ?? null;

const findCustomDomainIssuer = (tenant: Tenant, requestHost: string) =>
  tenant.issuers.find(
    (issuer) =>
      issuer.issuerType === "custom_domain" &&
      issuer.domain === requestHost &&
      issuer.verificationStatus === "verified"
  ) ?? null;

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
  const requestHost = normalizeHost(url.hostname);
  const normalizedPlatformHost = normalizeHost(platformHost);

  const customDomainTenant = await tenantRepository.findByCustomDomain(requestHost);

  if (customDomainTenant !== null && isActiveTenant(customDomainTenant)) {
    if (url.pathname.startsWith("/t/")) {
      return null;
    }

    const customDomainIssuer = findCustomDomainIssuer(customDomainTenant, requestHost);

    if (customDomainIssuer !== null) {
      return toResolvedContext(customDomainTenant, customDomainIssuer, requestHost);
    }
  }

  if (requestHost !== normalizedPlatformHost) {
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

  if (!isActiveTenant(tenant)) {
    return null;
  }

  const platformIssuer = findIssuerByType(tenant, "platform_path");

  return platformIssuer === null ? null : toResolvedContext(tenant, platformIssuer, requestHost);
};
