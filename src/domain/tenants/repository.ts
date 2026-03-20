import type { Tenant } from "./types";

export interface TenantRepository {
  create(tenant: Tenant): Promise<void>;
  findBySlug(slug: string): Promise<Tenant | null>;
  findByCustomDomain(domain: string): Promise<Tenant | null>;
}
