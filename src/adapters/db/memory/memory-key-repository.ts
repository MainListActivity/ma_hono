import type { KeyRepository } from "../../../domain/keys/repository";
import type { SigningKey } from "../../../domain/keys/types";

export class MemoryKeyRepository implements KeyRepository {
  constructor(private readonly keys: SigningKey[]) {}

  async listActiveKeysForTenant(tenantId: string): Promise<SigningKey[]> {
    return this.keys.filter((key) => key.tenantId === tenantId && key.status === "active");
  }

  async retireActiveKeysForTenant(tenantId: string, retiredAt: string): Promise<void> {
    for (const key of this.keys) {
      if (key.tenantId === tenantId && key.status === "active") {
        key.status = "retired";
      }
    }
  }
}
