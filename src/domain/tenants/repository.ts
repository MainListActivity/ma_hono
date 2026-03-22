import type { Tenant } from "./types";

export interface TenantUpdateInput {
  displayName?: string;
  status?: Tenant["status"];
  /** Replace the primary platform-path issuer URL */
  primaryIssuerUrl?: string;
}

export interface TenantRepository {
  create(tenant: Tenant): Promise<void>;
  update(id: string, input: TenantUpdateInput): Promise<void>;
  delete(id: string): Promise<void>;
  findById(id: string): Promise<Tenant | null>;
  findBySlug(slug: string): Promise<Tenant | null>;
  findByCustomDomain(domain: string): Promise<Tenant | null>;
  list(): Promise<Tenant[]>;
}
