import type { Client } from "./types";

export interface ClientRepository {
  create(client: Client): Promise<void>;
  findByClientId(clientId: string): Promise<Client | null>;
}
