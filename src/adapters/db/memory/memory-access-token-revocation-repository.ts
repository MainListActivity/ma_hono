import type {
  AccessTokenRevocationRecord,
  AccessTokenRevocationRepository
} from "../../../domain/tokens/access-token-revocation-repository";

export class MemoryAccessTokenRevocationRepository
  implements AccessTokenRevocationRepository
{
  private readonly records = new Map<string, AccessTokenRevocationRecord>();

  async revoke(record: AccessTokenRevocationRecord): Promise<void> {
    this.records.set(record.tokenHash, { ...record });
  }

  async isRevoked(tokenHash: string): Promise<boolean> {
    return this.records.has(tokenHash);
  }
}
