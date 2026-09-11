export interface AccessTokenRevocationRecord {
  id: string;
  tenantId: string;
  clientId: string;
  tokenHash: string;
  expiresAt: string;
  revokedAt: string;
}

/**
 * Keeps only a hash of a revoked JWT. Resource servers use introspection for
 * this check, so an RFC 7009 revocation takes effect before JWT expiry.
 */
export interface AccessTokenRevocationRepository {
  revoke(record: AccessTokenRevocationRecord): Promise<void>;
  isRevoked(tokenHash: string): Promise<boolean>;
}
