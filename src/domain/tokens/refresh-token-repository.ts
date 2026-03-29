import type { ClientAuthMethodName } from "../clients/types";

export interface RefreshTokenRecord {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  userId: string;
  scope: string;
  authMethod: ClientAuthMethodName | null;
  tokenHash: string;
  absoluteExpiresAt: string;
  consumedAt: string | null;
  parentTokenId: string | null;
  replacedByTokenId: string | null;
  createdAt: string;
}

export interface RefreshTokenRepository {
  create(record: RefreshTokenRecord): Promise<void>;
  findActiveByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  consume(
    id: string,
    consumedAt: string,
    replacedByTokenId?: string | null
  ): Promise<boolean>;
}
