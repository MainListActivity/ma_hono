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

  listTokens(): RegistrationAccessTokenRecord[] {
    return [...this.records];
  }
}
