import type { ClientRepository } from "../../../domain/clients/repository";
import type { Client } from "../../../domain/clients/types";

export class MemoryClientRepository implements ClientRepository {
  private readonly clients: Client[];

  constructor(initialClients: Client[] = []) {
    this.clients = [...initialClients];
  }

  async create(client: Client): Promise<void> {
    this.clients.push(client);
  }

  async findByClientId(clientId: string): Promise<Client | null> {
    return this.clients.find((client) => client.clientId === clientId) ?? null;
  }
}
