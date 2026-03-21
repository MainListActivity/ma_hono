import type { Tenant } from "./types";

export interface TenantRepository {
  create(tenant: Tenant): Promise<void>;
  findById(id: string): Promise<Tenant | null>;
  findBySlug(slug: string): Promise<Tenant | null>;
  findByCustomDomain(domain: string): Promise<Tenant | null>;
  list(): Promise<Tenant[]>;
}
