import { describe, expect, it } from "vitest";

import { MemoryKeyRepository } from "../../src/adapters/db/memory/memory-key-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { createApp } from "../../src/app/app";
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
    alg: "ES256",
    kty: "EC",
    status: "active",
    publicJwk: {
      kid: "kid-active",
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
      use: "sig",
      x: "f83OJ3D2xF4xT5cU6d1b6q8L6o-l7Yx31xHn0SI7g0Y",
      y: "x_FEzRu9pG2bGS7dUdr9YzQKQwe4S4n1lWv1q5rE6E8"
    }
  },
  {
    id: "key_inactive_acme",
    tenantId: "tenant_acme",
    kid: "kid-inactive",
    alg: "ES256",
    kty: "EC",
    status: "retired",
    publicJwk: {
      kid: "kid-inactive",
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
      use: "sig",
      x: "4B2YVZxjzG5b1W3oJ6iQf0WQkXxwA7s1W8vM3v7F8I0",
      y: "7lP3zM7Q6Lq2iA9gH9hT1qT9mWk4xA5bD1rJ6qS2pLQ"
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
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://idp.example.test/t/acme/jwks.json");

    expect(response.status).toBe(200);
    const body = (await response.json()) as JwksResponse;

    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]).toMatchObject({
      kid: "kid-active",
      kty: "EC",
      alg: "ES256",
      use: "sig"
    });
    expect(body.keys[0]).not.toHaveProperty("d");
  });

  it("returns issuer-context keys for a custom-domain issuer", async () => {
    const app = createApp({
      keyRepository,
      platformHost: "idp.example.test",
      tenantRepository
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
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request("https://idp.example.test/t/missing/jwks.json");

    expect(response.status).toBe(404);
  });

  it("loads active signing key material from D1 metadata and R2 private material", async () => {
    const privateJwk = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF4xT5cU6d1b6q8L6o-l7Yx31xHn0SI7g0Y",
      y: "x_FEzRu9pG2bGS7dUdr9YzQKQwe4S4n1lWv1q5rE6E8",
      d: "n0SI7g0Yf83OJ3D2xF4xT5cU6d1b6q8L6o-l7Yx31xH"
    };
    const tenantKey: SigningKey = {
      id: "key_active_acme",
      tenantId: "tenant_acme",
      kid: "kid-active",
      alg: "ES256",
      kty: "EC",
      status: "active",
      privateKeyRef: "signing-keys/tenant_acme/kid-active.json",
      publicJwk: {
        kid: "kid-active",
        kty: "EC",
        crv: "P-256",
        alg: "ES256",
        use: "sig",
        x: privateJwk.x,
        y: privateJwk.y
      }
    };
    const keyRepositoryWithPrivateKey: KeyRepository = {
      async listActiveKeysForTenant(tenantId: string) {
        return tenantId === "tenant_acme" ? [tenantKey] : [];
      }
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
        }
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
      alg: "ES256",
      use: "sig"
    });
    expect(material.privateJwk).toMatchObject({
      kty: "EC",
      crv: "P-256"
    });
    expect(bootstrapCalls).toHaveLength(1);
    expect(bootstrapCalls[0]).toMatchObject({
      tenantId: "tenant_acme"
    });
    await expect(
      keyMaterialStore.get(material.key.privateKeyRef as string)
    ).resolves.toContain('"kty":"EC"');
  });

  it("does not mint duplicate signing keys when bootstrap is already in flight", async () => {
    const activeKeys: SigningKey[] = [];
    let resolveBootstrap: ((value: SigningKeyMaterial) => void) | null = null;
    const bootstrapStarted: Array<string> = [];
    const keyMaterialStore = createMemoryKeyMaterialStore();

    const signer = createSigningKeySigner({
      keyMaterialStore,
      keyRepository: {
        async listActiveKeysForTenant(tenantId: string) {
          return activeKeys.filter((key) => key.tenantId === tenantId && key.status === "active");
        }
      },
      bootstrapSigningKey: async (input) => {
        bootstrapStarted.push(input.kid);

        const key: SigningKey = {
          id: "key_bootstrap_concurrent",
          tenantId: input.tenantId,
          kid: input.kid,
          alg: input.alg,
          kty: input.kty,
          status: "active",
          privateKeyRef: input.privateKeyRef,
          publicJwk: input.publicJwk
        };

        activeKeys.push(key);

        return await new Promise<SigningKeyMaterial>((resolve) => {
          resolveBootstrap = resolve;
        });
      }
    });

    const first = signer.ensureActiveSigningKeyMaterial("tenant_acme");
    const second = signer.ensureActiveSigningKeyMaterial("tenant_acme");

    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(bootstrapStarted).toHaveLength(1);

    if (resolveBootstrap === null) {
      throw new Error("bootstrap promise was not captured");
    }

    const bootstrapResolver: (value: SigningKeyMaterial) => void = resolveBootstrap;

    bootstrapResolver({
      key: activeKeys[0],
      privateJwk: {
        kty: "EC",
        crv: "P-256",
        d: "concurrent-private",
        x: "concurrent-x",
        y: "concurrent-y"
      }
    });

    await expect(first).resolves.toHaveProperty("key.kid", activeKeys[0]?.kid);
    await expect(second).resolves.toHaveProperty("key.kid", activeKeys[0]?.kid);
  });

  it("does not leave orphaned private material when bootstrap fails", async () => {
    const keyMaterialStore = createMemoryKeyMaterialStore();
    let capturedPrivateKeyRef: string | null = null;
    const signer = createSigningKeySigner({
      keyMaterialStore,
      keyRepository: {
        async listActiveKeysForTenant() {
          return [];
        }
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
});
