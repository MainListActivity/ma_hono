import { describe, expect, it } from "vitest";

import { MemoryKeyRepository } from "../../src/adapters/db/memory/memory-key-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { createApp } from "../../src/app/app";
import { D1KeyRepository, D1SigningKeyBootstrapper } from "../../src/adapters/db/drizzle/runtime";
import { createSigningKeySigner } from "../../src/domain/keys/signer";
import type { KeyMaterialStore } from "../../src/domain/keys/key-material-store";
import type { KeyRepository } from "../../src/domain/keys/repository";
import type { SigningKey, SigningKeyMaterial } from "../../src/domain/keys/types";

interface JwksResponse {
  keys: Array<Record<string, unknown>>;
}

const tenantRepository = new MemoryTenantRepository([
  {
    id: "tenant_acme",
    slug: "acme",
    displayName: "Acme",
    status: "active",
    issuers: [
      {
        id: "issuer_platform_acme",
        issuerType: "platform_path",
        issuerUrl: "https://idp.example.test/t/acme",
        domain: null,
        isPrimary: true,
        verificationStatus: "verified"
      },
      {
        id: "issuer_custom_acme",
        issuerType: "custom_domain",
        issuerUrl: "https://login.acme.test",
        domain: "login.acme.test",
        isPrimary: false,
        verificationStatus: "verified"
      }
    ]
  }
]);

const keyRepository = new MemoryKeyRepository([
  {
    id: "key_active_acme",
    tenantId: "tenant_acme",
    kid: "kid-active",
    alg: "RS256",
    kty: "RSA",
    status: "active",
    publicJwk: {
      kid: "kid-active",
      kty: "RSA",
      alg: "RS256",
      use: "sig",
      n: "sXch0M8WtfzT1p1p1v9gZyJ3VG5X5M8uB1e9dJ6s2WjzW6O7rN7U2kQ7XQe8n0JdE3cH8pN5vK4zM3sT2uP1qQ",
      e: "AQAB"
    }
  },
  {
    id: "key_inactive_acme",
    tenantId: "tenant_acme",
    kid: "kid-inactive",
    alg: "RS256",
    kty: "RSA",
    status: "retired",
    publicJwk: {
      kid: "kid-inactive",
      kty: "RSA",
      alg: "RS256",
      use: "sig",
      n: "uQ7z4Kj1Qm2Gd4Pf6Lk9Vb2Ws3Hx7Nt5Yp8Rc1Mn4Ta6Yz9Le3Hc2Vq8Nb5Jd7Fs0Xr4Cu6Dp1Mw9Kt2Lp5Q",
      e: "AQAB"
    }
  }
]);

const createMemoryKeyMaterialStore = (initial: Record<string, string> = {}): KeyMaterialStore => {
  const records = new Map(Object.entries(initial));

  return {
    async get(key: string) {
      return records.get(key) ?? null;
    },
    async put(key: string, value: string) {
      records.set(key, value);
    }
  };
};

describe("OIDC JWKS", () => {
  it("returns only active public keys for a platform-path issuer", async () => {
    const app = createApp({
      keyRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
    });

    const response = await app.request("https://idp.example.test/t/acme/jwks.json");

    expect(response.status).toBe(200);
    const body = (await response.json()) as JwksResponse;

    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]).toMatchObject({
      kid: "kid-active",
      kty: "RSA",
      alg: "RS256",
      use: "sig"
    });
    expect(body.keys[0]).not.toHaveProperty("d");
  });

  it("returns issuer-context keys for a custom-domain issuer", async () => {
    const app = createApp({
      keyRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
    });

    const response = await app.request("https://login.acme.test/jwks.json");

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      keys: [expect.objectContaining({ kid: "kid-active" })]
    });
  });

  it("returns 404 when the jwks issuer cannot be resolved", async () => {
    const app = createApp({
      keyRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      oidcHost: "idp.example.test", authDomain: "auth.example.test",
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0)
    });

    const response = await app.request("https://idp.example.test/t/missing/jwks.json");

    expect(response.status).toBe(404);
  });

  it("loads active signing key material from D1 metadata and R2 private material", async () => {
    const privateJwk = {
      kty: "RSA",
      n: "sXch0M8WtfzT1p1p1v9gZyJ3VG5X5M8uB1e9dJ6s2WjzW6O7rN7U2kQ7XQe8n0JdE3cH8pN5vK4zM3sT2uP1qQ",
      e: "AQAB",
      d: "Yf7J3mN9pQ2sV5tX8wC1eR4yU7iO0pL3kN6bH9dF2gJ5mQ8rT1vW4xY7zA0cD3fG6hJ9kL2mN5pQ8rT1vW4xY"
    };
    const tenantKey: SigningKey = {
      id: "key_active_acme",
      tenantId: "tenant_acme",
      kid: "kid-active",
      alg: "RS256",
      kty: "RSA",
      status: "active",
      privateKeyRef: "signing-keys/tenant_acme/kid-active.json",
      publicJwk: {
        kid: "kid-active",
        kty: "RSA",
        alg: "RS256",
        use: "sig",
        n: privateJwk.n,
        e: privateJwk.e
      }
    };
    const keyRepositoryWithPrivateKey: KeyRepository = {
      async listActiveKeysForTenant(tenantId: string) {
        return tenantId === "tenant_acme" ? [tenantKey] : [];
      },
      async retireActiveKeysForTenant() {}
    };
    const keyMaterialStore = createMemoryKeyMaterialStore({
      "signing-keys/tenant_acme/kid-active.json": JSON.stringify(privateJwk)
    });

    const signer = createSigningKeySigner({
      keyMaterialStore,
      keyRepository: keyRepositoryWithPrivateKey
    });

    await expect(signer.loadActiveSigningKeyMaterial("tenant_acme")).resolves.toEqual({
      key: tenantKey,
      privateJwk
    });
  });

  it("bootstraps active signing key material when no active key exists", async () => {
    const keyMaterialStore = createMemoryKeyMaterialStore();
    const bootstrapCalls: Array<{
      kid: string;
      privateKeyRef: string;
      tenantId: string | null;
    }> = [];
    const signer = createSigningKeySigner({
      keyMaterialStore,
      keyRepository: {
        async listActiveKeysForTenant() {
          return [];
        },
        async retireActiveKeysForTenant() {}
      },
      bootstrapSigningKey: async (input) => {
        bootstrapCalls.push({
          kid: input.kid,
          privateKeyRef: input.privateKeyRef,
          tenantId: input.tenantId
        });

        await keyMaterialStore.put(input.privateKeyRef, JSON.stringify(input.privateJwk));

        return {
          key: {
            id: "key_bootstrap_acme",
            tenantId: input.tenantId,
            kid: input.kid,
            alg: input.alg,
            kty: input.kty,
            status: "active",
            privateKeyRef: input.privateKeyRef,
            publicJwk: input.publicJwk
          },
          privateJwk: input.privateJwk
        };
      }
    });

    const material = await signer.ensureActiveSigningKeyMaterial("tenant_acme");

    expect(material.key.status).toBe("active");
    expect(material.key.tenantId).toBe("tenant_acme");
    expect(material.key.privateKeyRef).toContain("signing-keys/tenant_acme/");
    expect(material.key.publicJwk).toMatchObject({
      kid: material.key.kid,
      alg: "RS256",
      use: "sig"
    });
    expect(material.privateJwk).toMatchObject({
      kty: "RSA"
    });
    expect(bootstrapCalls).toHaveLength(1);
    expect(bootstrapCalls[0]).toMatchObject({
      tenantId: "tenant_acme"
    });
    await expect(
      keyMaterialStore.get(material.key.privateKeyRef as string)
    ).resolves.toContain('"kty":"RSA"');
  });

  it("recovers from a duplicate D1 bootstrap insert by loading the existing private material", async () => {
    const privateJwk = {
      kty: "EC",
      crv: "P-256",
      x: "existing-x",
      y: "existing-y",
      d: "existing-private"
    };
    const existingKey: SigningKey = {
      id: "key_existing_bootstrap",
      tenantId: "tenant_acme",
      kid: "bootstrap-tenant_acme-rs256",
      alg: "RS256",
      kty: "RSA",
      status: "active",
      privateKeyRef: "signing-keys/tenant_acme/bootstrap-tenant_acme-rs256.json",
      publicJwk: {
        kid: "bootstrap-tenant_acme-rs256",
        kty: "RSA",
        alg: "RS256",
        use: "sig",
        n: "existing-n",
        e: "AQAB"
      }
    };
    const keyMaterialStore = createMemoryKeyMaterialStore({
      [existingKey.privateKeyRef as string]: JSON.stringify(privateJwk)
    });
    let insertCalls = 0;
    const fakeDb = {
      insert: () => ({
        values: async () => {
          insertCalls++;
          throw new Error("SQLITE_CONSTRAINT: UNIQUE constraint failed: signing_keys.kid_unique");
        }
      }),
      select: () => ({
        from: () => ({
          where: () => ({
            limit: async () => [
              {
                id: existingKey.id,
                tenantId: existingKey.tenantId,
                kid: existingKey.kid,
                alg: existingKey.alg,
                kty: existingKey.kty,
                privateKeyRef: existingKey.privateKeyRef,
                status: existingKey.status,
                publicJwk: existingKey.publicJwk
              }
            ]
          })
        })
      }),
      delete: () => ({
        where: async () => undefined
      })
    } as never;

    const bootstrapper = new D1SigningKeyBootstrapper(fakeDb, keyMaterialStore);

    const material = await bootstrapper.bootstrapSigningKey({
      tenantId: "tenant_acme",
      kid: existingKey.kid,
      alg: "RS256",
      kty: "RSA",
      privateKeyRef: existingKey.privateKeyRef as string,
      publicJwk: existingKey.publicJwk,
      privateJwk
    });

    expect(insertCalls).toBe(1);
    expect(material.key).toMatchObject(existingKey);
    expect(material.privateJwk).toEqual(privateJwk);
    await expect(keyMaterialStore.get(existingKey.privateKeyRef as string)).resolves.toBe(
      JSON.stringify(privateJwk)
    );
  });

  it("does not leave orphaned private material when bootstrap fails", async () => {
    const keyMaterialStore = createMemoryKeyMaterialStore();
    let capturedPrivateKeyRef: string | null = null;
    const signer = createSigningKeySigner({
      keyMaterialStore,
      keyRepository: {
        async listActiveKeysForTenant() {
          return [];
        },
        async retireActiveKeysForTenant() {}
      },
      bootstrapSigningKey: async (input) => {
        capturedPrivateKeyRef = input.privateKeyRef;
        throw new Error("bootstrap failed");
      }
    });

    await expect(signer.ensureActiveSigningKeyMaterial("tenant_acme")).rejects.toThrowError(
      /bootstrap failed/
    );
    expect(capturedPrivateKeyRef).not.toBeNull();
    if (capturedPrivateKeyRef === null) {
      throw new Error("expected bootstrap to capture a private key ref");
    }

    await expect(keyMaterialStore.get(capturedPrivateKeyRef)).resolves.toBeNull();
  });

  it("does not include global active keys when listing a tenant's signing keys", async () => {
    const fakeDb = {
      select: () => ({
        from: () => ({
          where: () => ({
            orderBy: async () => [
              {
                id: "key_tenant_acme",
                tenantId: "tenant_acme",
                kid: "kid-tenant-acme",
                alg: "RS256",
                kty: "RSA",
                status: "active",
                privateKeyRef: "signing-keys/tenant_acme/kid-tenant-acme.json",
                publicJwk: {
                  kid: "kid-tenant-acme",
                  kty: "RSA",
                  alg: "RS256",
                  use: "sig",
                  n: "tenant-n",
                  e: "AQAB"
                }
              }
            ]
          })
        })
      })
    } as never;

    const repository = new D1KeyRepository(fakeDb);

    await expect(repository.listActiveKeysForTenant("tenant_acme")).resolves.toEqual([
      expect.objectContaining({
        tenantId: "tenant_acme",
        kid: "kid-tenant-acme",
        alg: "RS256"
      })
    ]);
  });
});
