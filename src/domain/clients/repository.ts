import type { Client } from "./types";

export interface ClientRepository {
  create(client: Client): Promise<void>;
  deleteByClientId(clientId: string): Promise<void>;
  findByClientId(clientId: string): Promise<Client | null>;
  listByTenantId(tenantId: string): Promise<Client[]>;
}
