import type {
  RemoteGrantRecord,
  RemoteGrantRepository
} from "../../../domain/tokens/remote-grant-repository";

export class MemoryRemoteGrantRepository implements RemoteGrantRepository {
  private readonly records: RemoteGrantRecord[];

  constructor(initialRecords: RemoteGrantRecord[] = []) {
    this.records = [...initialRecords];
  }

  async redeemByCodeHash(codeHash: string, nowIso: string): Promise<RemoteGrantRecord | null> {
    const now = Date.parse(nowIso);
    const match = this.records.find(
      (record) =>
        record.codeHash === codeHash &&
        record.codeConsumedAt === null &&
        record.status === "active" &&
        Date.parse(record.codeExpiresAt) > now &&
        Date.parse(record.expiresAt) > now
    );

    if (match === undefined) return null;
    match.codeConsumedAt = nowIso;
    return { ...match };
  }

  async findById(tenantId: string, id: string): Promise<RemoteGrantRecord | null> {
    const match = this.records.find(
      (record) => record.tenantId === tenantId && record.id === id
    );
    return match === undefined ? null : { ...match };
  }

  async revoke(tenantId: string, id: string, revokedAt: string): Promise<boolean> {
    const match = this.records.find(
      (record) => record.tenantId === tenantId && record.id === id && record.status !== "revoked"
    );
    if (match === undefined) return false;
    match.status = "revoked";
    match.revokedAt = revokedAt;
    return true;
  }

  listRemoteGrants(): RemoteGrantRecord[] {
    return [...this.records];
  }
}
