import type { KeyRepository } from "./repository";
import type { JwksResponse } from "./types";

export const buildJwks = async (
  keyRepository: KeyRepository,
  tenantId: string
): Promise<JwksResponse> => {
  const keys = await keyRepository.listActiveKeysForTenant(tenantId);

  return {
    keys: keys.map((key) => key.publicJwk)
  };
};
