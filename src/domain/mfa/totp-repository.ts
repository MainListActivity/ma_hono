export interface TotpCredential {
  id: string;
  tenantId: string;
  userId: string;
  secretEncrypted: string;
  algorithm: string;
  digits: number;
  period: number;
  lastUsedWindow: number;
  enrolledAt: string;
  createdAt: string;
}

export interface TotpRepository {
  create(credential: TotpCredential): Promise<void>;
  findByTenantAndUser(tenantId: string, userId: string): Promise<TotpCredential | null>;
  updateLastUsedWindow(id: string, lastUsedWindow: number): Promise<void>;
}
