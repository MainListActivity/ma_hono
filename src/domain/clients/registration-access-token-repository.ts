export interface RegistrationAccessTokenRecord {
  clientId: string;
  expiresAt: string;
  issuer: string;
  tenantId: string;
  tokenHash: string;
}

export interface RegistrationAccessTokenRepository {
  deleteByTokenHash(tokenHash: string): Promise<void>;
  store(record: RegistrationAccessTokenRecord): Promise<void>;
}
