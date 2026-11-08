export type RemoteGrantStatus = "active" | "revoked";

export interface RemoteGrantRecord {
  id: string;
  tenantId: string;
  userId: string;
  clientId: string;
  codeHash: string;
  codeExpiresAt: string;
  codeConsumedAt: string | null;
  resources: string[];
  taskRef: string | null;
  expiresAt: string;
  status: RemoteGrantStatus;
  createdAt: string;
  revokedAt: string | null;
}

export interface RemoteGrantRepository {
  /** Atomic single-statement consume: matches the hash, unconsumed, active and unexpired. */
  redeemByCodeHash(codeHash: string, nowIso: string): Promise<RemoteGrantRecord | null>;
  findById(tenantId: string, id: string): Promise<RemoteGrantRecord | null>;
  revoke(tenantId: string, id: string, revokedAt: string): Promise<boolean>;
}
