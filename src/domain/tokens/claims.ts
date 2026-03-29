interface BaseTokenClaimsInput {
  audience: string;
  issuer: string;
  nowSeconds: number;
  scope: string;
  userId: string;
}

export interface IdTokenClaims extends Record<string, unknown> {
  aud: string;
  exp: number;
  iat: number;
  iss: string;
  jti?: string;
  nonce?: string;
  sub: string;
}

export interface AccessTokenClaims extends Record<string, unknown> {
  aud: string;
  client_id: string;
  exp: number;
  iat: number;
  iss: string;
  jti?: string;
  scope: string;
  sub: string;
}

export const buildIdTokenClaims = ({
  audience,
  issuer,
  nonce,
  nowSeconds,
  tokenId,
  ttlSeconds = 5 * 60,
  userId
}: BaseTokenClaimsInput & {
  nonce: string | null;
  tokenId?: string;
  ttlSeconds?: number;
}): IdTokenClaims => ({
  iss: issuer,
  sub: userId,
  aud: audience,
  iat: nowSeconds,
  exp: nowSeconds + ttlSeconds,
  ...(tokenId === undefined ? {} : { jti: tokenId }),
  ...(nonce === null ? {} : { nonce })
});

export const buildAccessTokenClaims = ({
  audience,
  clientId,
  extraClaims,
  issuer,
  nowSeconds,
  scope,
  tokenId,
  ttlSeconds = 60 * 60,
  userId
}: BaseTokenClaimsInput & {
  clientId: string;
  extraClaims?: Record<string, unknown>;
  tokenId?: string;
  ttlSeconds?: number;
}): AccessTokenClaims => ({
  ...extraClaims,
  iss: issuer,
  sub: userId,
  aud: audience,
  client_id: clientId,
  iat: nowSeconds,
  exp: nowSeconds + ttlSeconds,
  ...(tokenId === undefined ? {} : { jti: tokenId }),
  scope
});
