import type { TotpCredential, TotpRepository } from "../../../domain/mfa/totp-repository";

export class MemoryTotpRepository implements TotpRepository {
  private readonly credentials: TotpCredential[] = [];

  async create(credential: TotpCredential): Promise<void> {
    const existing = this.credentials.findIndex(
      (c) => c.tenantId === credential.tenantId && c.userId === credential.userId
    );
    if (existing !== -1) {
      // Unique constraint violation — throw to match D1 behavior
      throw new Error("UNIQUE constraint failed: totp_credentials.tenant_id, totp_credentials.user_id");
    }
    this.credentials.push({ ...credential });
  }

  async findByTenantAndUser(tenantId: string, userId: string): Promise<TotpCredential | null> {
    return this.credentials.find((c) => c.tenantId === tenantId && c.userId === userId) ?? null;
  }

  async updateLastUsedWindow(id: string, lastUsedWindow: number): Promise<void> {
    const cred = this.credentials.find((c) => c.id === id);
    if (cred !== undefined) {
      cred.lastUsedWindow = lastUsedWindow;
    }
  }
}
