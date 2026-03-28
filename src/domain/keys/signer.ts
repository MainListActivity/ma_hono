import { exportJWK, generateKeyPair, type JWK } from "jose";

import type { KeyMaterialStore } from "./key-material-store";
import type { KeyRepository } from "./repository";
import type { SigningKey, SigningKeyMaterial } from "./types";

export interface SigningKeyBootstrapInput {
  tenantId: string;
  kid: string;
  alg: string;
  kty: string;
  privateKeyRef: string;
  publicJwk: JWK;
  privateJwk: JWK;
}

export interface SigningKeyBootstrapper {
  bootstrapSigningKey(input: SigningKeyBootstrapInput): Promise<SigningKeyMaterial>;
}

export interface SigningKeySigner {
  loadActiveSigningKeyMaterial(tenantId: string): Promise<SigningKeyMaterial | null>;
  ensureActiveSigningKeyMaterial(tenantId: string): Promise<SigningKeyMaterial>;
}

const signingKeyPrefix = "signing-keys";

const createBootstrapKeyId = (tenantId: string) => `bootstrap-${tenantId}-rs256`;

const createPrivateKeyRef = (tenantId: string, kid: string) =>
  `${signingKeyPrefix}/${tenantId}/${kid}.json`;

const normalizePublicJwk = (jwk: JWK, kid: string): JWK => ({
  ...jwk,
  alg: "RS256",
  kid,
  use: "sig"
});

const normalizePrivateJwk = (jwk: JWK, kid: string): JWK => ({
  ...jwk,
  alg: "RS256",
  kid
});

const parseJwk = (value: string): JWK => JSON.parse(value) as JWK;

const loadSigningKeyMaterial = async (
  key: SigningKey,
  keyMaterialStore: KeyMaterialStore
): Promise<SigningKeyMaterial | null> => {
  if (key.privateKeyRef === undefined || key.privateKeyRef === null) {
    return null;
  }

  const privateJwkJson = await keyMaterialStore.get(key.privateKeyRef);

  if (privateJwkJson === null) {
    return null;
  }

  return {
    key,
    privateJwk: parseJwk(privateJwkJson)
  };
};

export const createSigningKeySigner = ({
  bootstrapSigningKey,
  keyMaterialStore,
  keyRepository
}: {
  bootstrapSigningKey?: SigningKeyBootstrapper["bootstrapSigningKey"];
  keyMaterialStore: KeyMaterialStore;
  keyRepository: KeyRepository;
}): SigningKeySigner => {
  const inFlightBootstraps = new Map<string, Promise<SigningKeyMaterial>>();

  const loadActiveSigningKeyMaterial = async (
    tenantId: string
  ): Promise<SigningKeyMaterial | null> => {
    const activeKeys = await keyRepository.listActiveKeysForTenant(tenantId);

    if (activeKeys.length === 0) {
      return null;
    }

    for (const key of activeKeys) {
      const material = await loadSigningKeyMaterial(key, keyMaterialStore);

      if (material !== null) {
        return material;
      }
    }

    throw new Error(`Active signing key metadata exists for ${tenantId} but private material is missing`);
  };

  const bootstrapKeyMaterial = async (
    tenantId: string
  ): Promise<SigningKeyMaterial> => {
    if (bootstrapSigningKey === undefined) {
      throw new Error(`No active signing key material is available for ${tenantId}`);
    }

    const { publicKey, privateKey } = await generateKeyPair("RS256", {
      extractable: true
    });
    const kid = createBootstrapKeyId(tenantId);
    const privateKeyRef = createPrivateKeyRef(tenantId, kid);
    const publicJwk = normalizePublicJwk(await exportJWK(publicKey), kid);
    const privateJwk = normalizePrivateJwk(await exportJWK(privateKey), kid);

    return await bootstrapSigningKey({
      tenantId,
      kid,
      alg: "RS256",
      kty: "RSA",
      privateKeyRef,
      publicJwk,
      privateJwk
    });
  };

  const ensureActiveSigningKeyMaterial = async (
    tenantId: string
  ): Promise<SigningKeyMaterial> => {
    const existingMaterial = await loadActiveSigningKeyMaterial(tenantId);

    if (existingMaterial !== null) {
      return existingMaterial;
    }

    const inFlightBootstrap = inFlightBootstraps.get(tenantId);

    if (inFlightBootstrap !== undefined) {
      return inFlightBootstrap;
    }

    const bootstrapPromise = bootstrapKeyMaterial(tenantId).finally(() => {
      inFlightBootstraps.delete(tenantId);
    });

    inFlightBootstraps.set(tenantId, bootstrapPromise);

    return bootstrapPromise;
  };

  return {
    ensureActiveSigningKeyMaterial,
    loadActiveSigningKeyMaterial
  };
};
