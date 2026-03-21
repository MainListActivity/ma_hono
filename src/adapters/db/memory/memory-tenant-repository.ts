import type { TenantRepository } from "../../../domain/tenants/repository";
import type { Tenant } from "../../../domain/tenants/types";

export class MemoryTenantRepository implements TenantRepository {
  constructor(private readonly tenants: Tenant[] = []) {}

  async create(tenant: Tenant): Promise<void> {
    this.tenants.push(tenant);
  }

  async findById(id: string): Promise<Tenant | null> {
    return this.tenants.find((tenant) => tenant.id === id) ?? null;
  }

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

  async list(): Promise<Tenant[]> {
    return [...this.tenants];
  }
}
