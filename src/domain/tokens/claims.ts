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
  nonce?: string;
  sub: string;
}

export interface AccessTokenClaims extends Record<string, unknown> {
  aud: string;
  client_id: string;
  exp: number;
  iat: number;
  iss: string;
  scope: string;
  sub: string;
}

export const buildIdTokenClaims = ({
  audience,
  issuer,
  nonce,
  nowSeconds,
  userId
}: BaseTokenClaimsInput & { nonce: string | null }): IdTokenClaims => ({
  iss: issuer,
  sub: userId,
  aud: audience,
  iat: nowSeconds,
  exp: nowSeconds + 5 * 60,
  ...(nonce === null ? {} : { nonce })
});

export const buildAccessTokenClaims = ({
  audience,
  clientId,
  extraClaims,
  issuer,
  nowSeconds,
  scope,
  userId
}: BaseTokenClaimsInput & {
  clientId: string;
  extraClaims?: Record<string, unknown>;
}): AccessTokenClaims => ({
  iss: issuer,
  sub: userId,
  aud: audience,
  client_id: clientId,
  iat: nowSeconds,
  exp: nowSeconds + 60 * 60,
  scope,
  ...extraClaims
});
