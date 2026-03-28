import type { AccessTokenCustomClaim } from "./access-token-claims-types";

export interface AccessTokenClaimsRepository {
  createMany(claims: AccessTokenCustomClaim[]): Promise<void>;
  replaceAllForClient(
    clientId: string,
    claims: AccessTokenCustomClaim[]
  ): Promise<void>;
  listByClientId(clientId: string): Promise<AccessTokenCustomClaim[]>;
  listByClientIdAndTenantId(
    clientId: string,
    tenantId: string
  ): Promise<AccessTokenCustomClaim[]>;
}
