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
  privateJwk: JWK;
}

export interface SigningKeyBootstrapper {
  bootstrapSigningKey(input: SigningKeyBootstrapInput): Promise<SigningKeyMaterial>;
}

export interface SigningKeySigner {
  loadActiveSigningKeyMaterial(tenantId: string): Promise<SigningKeyMaterial | null>;
  ensureActiveSigningKeyMaterial(tenantId: string | null): Promise<SigningKeyMaterial>;
}

const signingKeyPrefix = "signing-keys";

const createBootstrapKeyId = (tenantId: string | null) =>
  `bootstrap-${tenantId ?? "global"}-es256`;

const createPrivateKeyRef = (tenantId: string | null, kid: string) =>
  `${signingKeyPrefix}/${tenantId ?? "global"}/${kid}.json`;

const normalizePublicJwk = (jwk: JWK, kid: string): JWK => ({
  ...jwk,
  alg: "ES256",
  kid,
  use: "sig"
});

const normalizePrivateJwk = (jwk: JWK, kid: string): JWK => ({
  ...jwk,
  alg: "ES256",
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
    tenantId: string | null
  ): Promise<SigningKeyMaterial> => {
    if (bootstrapSigningKey === undefined) {
      throw new Error(`No active signing key material is available for ${tenantId ?? "the global issuer"}`);
    }

    const { publicKey, privateKey } = await generateKeyPair("ES256", {
      extractable: true
    });
    const kid = createBootstrapKeyId(tenantId);
    const privateKeyRef = createPrivateKeyRef(tenantId, kid);
    const publicJwk = normalizePublicJwk(await exportJWK(publicKey), kid);
    const privateJwk = normalizePrivateJwk(await exportJWK(privateKey), kid);

    return await bootstrapSigningKey({
      tenantId,
      kid,
      alg: "ES256",
      kty: "EC",
      privateKeyRef,
      publicJwk,
      privateJwk
    });
  };

  const ensureActiveSigningKeyMaterial = async (
    tenantId: string | null
  ): Promise<SigningKeyMaterial> => {
    const lookupTenantId = tenantId ?? "";
    const existingMaterial = await loadActiveSigningKeyMaterial(lookupTenantId);

    if (existingMaterial !== null) {
      return existingMaterial;
    }

    const bootstrapKeyId = tenantId ?? "__global__";
    const inFlightBootstrap = inFlightBootstraps.get(bootstrapKeyId);

    if (inFlightBootstrap !== undefined) {
      return inFlightBootstrap;
    }

    const bootstrapPromise = bootstrapKeyMaterial(tenantId).finally(() => {
      inFlightBootstraps.delete(bootstrapKeyId);
    });

    inFlightBootstraps.set(bootstrapKeyId, bootstrapPromise);

    return bootstrapPromise;
  };

  return {
    ensureActiveSigningKeyMaterial,
    loadActiveSigningKeyMaterial
  };
};
