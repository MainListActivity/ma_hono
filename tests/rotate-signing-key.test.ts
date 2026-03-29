// tests/rotate-signing-key.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SigningKeySigner } from "../src/domain/keys/signer";

// Minimal in-memory stand-in for the D1 drizzle instance
// We test the logic by verifying what the signer receives and what the DB receives.

describe("rotateSigningKeyForTenant", () => {
  it("retires active keys for the tenant and bootstraps a new one", async () => {
    const updatedRows: { tenantId: string; status: string }[] = [];

    // Fake drizzle db that captures UPDATE calls
    const fakeDb = {
      update: () => ({
        set: (values: { status: string; retireAt: string }) => ({
          where: (condition: unknown) => {
            // Record what was updated — condition is opaque, so we just record the set values
            updatedRows.push({ tenantId: "tenant-abc", status: values.status });
            return Promise.resolve();
          }
        })
      })
    } as unknown as Parameters<typeof import("../src/adapters/db/drizzle/runtime").rotateSigningKeyForTenant>[0]["db"];

    let bootstrappedForTenant: string | null = null;
    const fakeSigner: SigningKeySigner = {
      ensureActiveSigningKeyMaterial: async (tenantId: string) => {
        bootstrappedForTenant = tenantId;
        return {
          key: {
            id: "new-key-id",
            tenantId,
            kid: `bootstrap-${tenantId}-rs256`,
            alg: "RS256",
            kty: "RSA",
            status: "active",
            publicJwk: { kty: "RSA", use: "sig", alg: "RS256", kid: `bootstrap-${tenantId}-rs256` }
          },
          privateJwk: { kty: "RSA", alg: "RS256", kid: `bootstrap-${tenantId}-rs256` }
        };
      },
      loadActiveSigningKeyMaterial: async () => null
    };

    const { rotateSigningKeyForTenant } = await import(
      "../src/adapters/db/drizzle/runtime"
    );

    const result = await rotateSigningKeyForTenant({
      db: fakeDb,
      signer: fakeSigner,
      tenantId: "tenant-abc"
    });

    expect(updatedRows).toHaveLength(1);
    expect(updatedRows[0].status).toBe("retired");

    expect(bootstrappedForTenant).toBe("tenant-abc");

    expect(result.kid).toBe("bootstrap-tenant-abc-rs256");
    expect(result.alg).toBe("RS256");
    expect(result.rotated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});
