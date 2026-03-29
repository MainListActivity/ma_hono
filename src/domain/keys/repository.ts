import type { SigningKey } from "./types";

export interface KeyRepository {
  listActiveKeysForTenant(tenantId: string): Promise<SigningKey[]>;
  retireActiveKeysForTenant(tenantId: string, retiredAt: string): Promise<void>;
}
