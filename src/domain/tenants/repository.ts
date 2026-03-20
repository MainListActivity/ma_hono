import type { Tenant } from "./types";

export interface TenantRepository {
  findBySlug(slug: string): Promise<Tenant | null>;
  findByCustomDomain(domain: string): Promise<Tenant | null>;
}
