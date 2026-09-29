import type {
  RegistrationAccessTokenRecord,
  RegistrationAccessTokenRepository
} from "../../../domain/clients/registration-access-token-repository";

export class MemoryRegistrationAccessTokenRepository
  implements RegistrationAccessTokenRepository
{
  private records: RegistrationAccessTokenRecord[];

  constructor(initialRecords: RegistrationAccessTokenRecord[] = []) {
    this.records = [...initialRecords];
  }

  async store(record: RegistrationAccessTokenRecord): Promise<void> {
    this.records.push(record);
  }

  async deleteByTokenHash(tokenHash: string): Promise<void> {
    this.records = this.records.filter((record) => record.tokenHash !== tokenHash);
  }

  async findByTokenHash(tokenHash: string): Promise<RegistrationAccessTokenRecord | null> {
    const record = this.records.find((candidate) => candidate.tokenHash === tokenHash);
    if (record === undefined) return null;
    if (new Date(record.expiresAt).getTime() <= Date.now()) {
      this.records = this.records.filter((candidate) => candidate.tokenHash !== tokenHash);
      return null;
    }
    return record;
  }

  listTokens(): RegistrationAccessTokenRecord[] {
    return [...this.records];
  }
}
