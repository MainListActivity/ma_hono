import type { ClientRepository } from "../../../domain/clients/repository";
import type { Client } from "../../../domain/clients/types";

export class MemoryClientRepository implements ClientRepository {
  private clients: Client[];

  constructor(initialClients: Client[] = []) {
    this.clients = [...initialClients];
  }

  async create(client: Client): Promise<void> {
    this.clients.push(client);
  }

  async update(client: Client): Promise<void> {
    const index = this.clients.findIndex((c) => c.clientId === client.clientId);
    if (index !== -1) {
      this.clients[index] = client;
    }
  }

  async deleteByClientId(clientId: string): Promise<void> {
    this.clients = this.clients.filter((client) => client.clientId !== clientId);
  }

  async findByClientId(clientId: string): Promise<Client | null> {
    return this.clients.find((client) => client.clientId === clientId) ?? null;
  }

  listClients(): Client[] {
    return [...this.clients];
  }

  async listByTenantId(tenantId: string): Promise<Client[]> {
    return this.clients.filter((client) => client.tenantId === tenantId);
  }
}
