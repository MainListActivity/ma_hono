import type { ClientAuthMethodName } from "../clients/types";

export interface RefreshTokenRecord {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  userId: string;
  scope: string;
  resource?: string | null;
  authMethod: ClientAuthMethodName | null;
  tokenHash: string;
  absoluteExpiresAt: string;
  remoteGrantId?: string | null;
  consumedAt: string | null;
  parentTokenId: string | null;
  replacedByTokenId: string | null;
  createdAt: string;
}

export interface RefreshTokenRepository {
  create(record: RefreshTokenRecord): Promise<void>;
  findActiveByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  /** Includes consumed rows — needed for remote-grant refresh replay detection. */
  findAnyByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  consume(
    id: string,
    consumedAt: string,
    replacedByTokenId?: string | null
  ): Promise<boolean>;
}
