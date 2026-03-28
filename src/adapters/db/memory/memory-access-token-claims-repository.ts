import type { AccessTokenClaimsRepository } from "../../../domain/clients/access-token-claims-repository";
import type { AccessTokenCustomClaim } from "../../../domain/clients/access-token-claims-types";

export class MemoryAccessTokenClaimsRepository
  implements AccessTokenClaimsRepository
{
  private claims: AccessTokenCustomClaim[] = [];

  async createMany(claims: AccessTokenCustomClaim[]): Promise<void> {
    this.claims.push(...claims);
  }

  async replaceAllForClient(
    clientId: string,
    claims: AccessTokenCustomClaim[]
  ): Promise<void> {
    this.claims = this.claims.filter((claim) => claim.clientId !== clientId);
    this.claims.push(...claims);
  }

  async listByClientId(clientId: string): Promise<AccessTokenCustomClaim[]> {
    return this.claims.filter((claim) => claim.clientId === clientId);
  }

  async listByClientIdAndTenantId(
    clientId: string,
    tenantId: string
  ): Promise<AccessTokenCustomClaim[]> {
    return this.claims.filter(
      (claim) => claim.clientId === clientId && claim.tenantId === tenantId
    );
  }
}
