import type { ClientAuthMethodPolicyRepository } from "../../../domain/clients/repository";
import type { ClientAuthMethodPolicy } from "../../../domain/clients/types";

export class MemoryClientAuthMethodPolicyRepository
  implements ClientAuthMethodPolicyRepository
{
  private policies: ClientAuthMethodPolicy[] = [];

  async create(policy: ClientAuthMethodPolicy): Promise<void> {
    this.policies.push({ ...policy });
  }

  async findByClientId(clientId: string): Promise<ClientAuthMethodPolicy | null> {
    return this.policies.find((p) => p.clientId === clientId) ?? null;
  }

  async update(policy: ClientAuthMethodPolicy): Promise<void> {
    const idx = this.policies.findIndex((p) => p.clientId === policy.clientId);
    if (idx !== -1) {
      this.policies[idx] = { ...policy };
    }
  }
}
