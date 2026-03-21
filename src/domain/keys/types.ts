import type { JWK } from "jose";

export type SigningKeyStatus = "active" | "retired";

export interface SigningKey {
  id: string;
  tenantId: string | null;
  kid: string;
  alg: string;
  kty: string;
  status: SigningKeyStatus;
  privateKeyRef?: string | null;
  publicJwk: JWK;
}

export interface SigningKeyMaterial {
  key: SigningKey;
  privateJwk: JWK;
}

export interface JwksResponse {
  keys: JWK[];
}
