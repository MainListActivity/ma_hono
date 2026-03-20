import { exportJWK, generateKeyPair, type JWK } from "jose";

export interface DevKeyMaterial {
  publicJwk: JWK;
}

export const generateDevEs256PublicJwk = async (): Promise<DevKeyMaterial> => {
  const { publicKey } = await generateKeyPair("ES256");

  return {
    publicJwk: await exportJWK(publicKey)
  };
};
