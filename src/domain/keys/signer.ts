import { exportJWK, generateKeyPair, type JWK } from "jose";

import type { KeyMaterialStore } from "./key-material-store";
import type { KeyRepository } from "./repository";
import type { SigningKey, SigningKeyMaterial } from "./types";

export interface SigningKeyBootstrapInput {
  tenantId: string | null;
  kid: string;
  alg: string;
  kty: string;
  privateKeyRef: string;
  publicJwk: JWK;
}

export interface SigningKeyBootstrapper {
  bootstrapSigningKey(input: SigningKeyBootstrapInput): Promise<SigningKey>;
}

export interface SigningKeySigner {
  loadActiveSigningKeyMaterial(tenantId: string): Promise<SigningKeyMaterial | null>;
  ensureActiveSigningKeyMaterial(tenantId: string | null): Promise<SigningKeyMaterial>;
}

const signingKeyPrefix = "signing-keys";

const createPrivateKeyRef = (tenantId: string | null, kid: string) =>
  `${signingKeyPrefix}/${tenantId ?? "global"}/${kid}.json`;

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

  const ensureActiveSigningKeyMaterial = async (
    tenantId: string | null
  ): Promise<SigningKeyMaterial> => {
    const existingMaterial = await loadActiveSigningKeyMaterial(tenantId ?? "");

    if (existingMaterial !== null) {
      return existingMaterial;
    }

    if (bootstrapSigningKey === undefined) {
      throw new Error(`No active signing key material is available for ${tenantId ?? "the global issuer"}`);
    }

    const { publicKey, privateKey } = await generateKeyPair("ES256", {
      extractable: true
    });
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    const kid = crypto.randomUUID();
    const privateKeyRef = createPrivateKeyRef(tenantId, kid);

    await keyMaterialStore.put(privateKeyRef, JSON.stringify(privateJwk));

    const key = await bootstrapSigningKey({
      tenantId,
      kid,
      alg: "ES256",
      kty: "EC",
      privateKeyRef,
      publicJwk
    });

    return {
      key: key.privateKeyRef === undefined || key.privateKeyRef === null ? { ...key, privateKeyRef } : key,
      privateJwk
    };
  };

  return {
    ensureActiveSigningKeyMaterial,
    loadActiveSigningKeyMaterial
  };
};
