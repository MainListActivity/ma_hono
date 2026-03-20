import type { JWK } from "jose";

export type SigningKeyStatus = "active" | "retired";

export interface SigningKey {
  id: string;
  tenantId: string | null;
  kid: string;
  alg: string;
  kty: string;
  status: SigningKeyStatus;
  publicJwk: JWK;
}

export interface JwksResponse {
  keys: JWK[];
}
