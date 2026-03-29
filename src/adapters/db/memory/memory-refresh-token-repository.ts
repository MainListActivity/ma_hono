import type {
  RefreshTokenRecord,
  RefreshTokenRepository
} from "../../../domain/tokens/refresh-token-repository";

export class MemoryRefreshTokenRepository implements RefreshTokenRepository {
  private readonly records: RefreshTokenRecord[];

  constructor(initialRecords: RefreshTokenRecord[] = []) {
    this.records = [...initialRecords];
  }

  async create(record: RefreshTokenRecord): Promise<void> {
    this.records.push({ ...record });
  }

  async findActiveByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const match = this.records.find(
      (record) => record.tokenHash === tokenHash && record.consumedAt === null
    );

    return match === undefined ? null : { ...match };
  }

  async consume(
    id: string,
    consumedAt: string,
    replacedByTokenId: string | null = null
  ): Promise<boolean> {
    const match = this.records.find(
      (record) => record.id === id && record.consumedAt === null
    );

    if (match === undefined) {
      return false;
    }

    match.consumedAt = consumedAt;
    match.replacedByTokenId = replacedByTokenId;
    return true;
  }

  listRefreshTokens(): RefreshTokenRecord[] {
    return [...this.records];
  }
}
