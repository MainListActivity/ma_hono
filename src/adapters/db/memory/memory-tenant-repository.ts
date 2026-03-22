import type { TenantRepository, TenantUpdateInput } from "../../../domain/tenants/repository";
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

  async update(id: string, input: TenantUpdateInput): Promise<void> {
    const tenant = this.tenants.find((t) => t.id === id);
    if (!tenant) return;
    if (input.displayName !== undefined) tenant.displayName = input.displayName;
    if (input.status !== undefined) tenant.status = input.status;
    if (input.primaryIssuerUrl !== undefined) {
      const primary = tenant.issuers.find((i) => i.isPrimary);
      if (primary) primary.issuerUrl = input.primaryIssuerUrl;
    }
  }

  async delete(id: string): Promise<void> {
    const idx = this.tenants.findIndex((t) => t.id === id);
    if (idx !== -1) this.tenants.splice(idx, 1);
  }
}
