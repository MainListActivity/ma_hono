import { exportJWK, generateKeyPair, type JWK } from "jose";

export interface DevKeyMaterial {
  publicJwk: JWK;
}

export const generateDevRs256PublicJwk = async (): Promise<DevKeyMaterial> => {
  const { publicKey } = await generateKeyPair("RS256");

  return {
    publicJwk: await exportJWK(publicKey)
  };
};
