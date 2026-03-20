import type { TenantRepository } from "../../../domain/tenants/repository";
import type { Tenant } from "../../../domain/tenants/types";

export class MemoryTenantRepository implements TenantRepository {
  constructor(private readonly tenants: Tenant[]) {}

  async findBySlug(slug: string): Promise<Tenant | null> {
    return this.tenants.find((tenant) => tenant.slug === slug) ?? null;
  }

  async findByCustomDomain(domain: string): Promise<Tenant | null> {
    return (
      this.tenants.find((tenant) =>
        tenant.issuers.some(
          (issuer) =>
            issuer.issuerType === "custom_domain" &&
            issuer.domain === domain &&
            issuer.verificationStatus === "verified"
        )
      ) ?? null
    );
  }
}
