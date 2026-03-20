import type { SigningKey } from "./types";

export interface KeyRepository {
  listActiveKeysForTenant(tenantId: string): Promise<SigningKey[]>;
}
