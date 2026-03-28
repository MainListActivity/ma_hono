import type { Client, ClientAuthMethodPolicy } from "./types";

export interface ClientRepository {
  create(client: Client): Promise<void>;
  update(client: Client): Promise<void>;
  deleteByClientId(clientId: string): Promise<void>;
  findByClientId(clientId: string): Promise<Client | null>;
  listByTenantId(tenantId: string): Promise<Client[]>;
}

export interface ClientAuthMethodPolicyRepository {
  // clientId is oidc_clients.id (UUID), not the OAuth client_id string
  create(policy: ClientAuthMethodPolicy): Promise<void>;
  findByClientId(clientId: string): Promise<ClientAuthMethodPolicy | null>;
  update(policy: ClientAuthMethodPolicy): Promise<void>;
}
