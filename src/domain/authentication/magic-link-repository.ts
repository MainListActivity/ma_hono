export interface MagicLinkToken {
  id: string;
  tenantId: string;
  userId: string;
  loginChallengeTokenHash: string;
  tokenHash: string;
  expiresAt: string;
  consumedAt: string | null;
  createdAt: string;
}

export interface MagicLinkRepository {
  create(token: MagicLinkToken): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<MagicLinkToken | null>;
  consume(id: string, consumedAt: string): Promise<boolean>;
}
