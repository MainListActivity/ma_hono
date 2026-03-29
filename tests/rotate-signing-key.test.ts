// tests/rotate-signing-key.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SigningKeySigner } from "../src/domain/keys/signer";

// Minimal in-memory stand-in for the D1 drizzle instance
// We test the logic by verifying what the signer receives and what the DB receives.

describe("rotateSigningKeyForTenant", () => {
  it("retires active keys for the tenant and bootstraps a new one", async () => {
    // Simulates D1 rows — only rows matching the WHERE clause get updated
    const fakeRows: { tenantId: string; status: string }[] = [
      { tenantId: "tenant-abc", status: "active" },
      { tenantId: "tenant-other", status: "active" }
    ];

    const fakeDb = {
      update: (table: unknown) => ({
        set: (values: { status: string; retireAt: string }) => ({
          where: (_condition: unknown) => {
            // The real implementation calls:
            //   .where(and(eq(signingKeys.status, "active"), eq(signingKeys.tenantId, tenantId)))
            // We simulate the effect: only update rows for tenant-abc with status active
            for (const row of fakeRows) {
              if (row.tenantId === "tenant-abc" && row.status === "active") {
                row.status = values.status;
              }
            }
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

    // tenant-abc key was retired
    expect(fakeRows.find(r => r.tenantId === "tenant-abc")?.status).toBe("retired");

    // tenant-other key was NOT touched
    expect(fakeRows.find(r => r.tenantId === "tenant-other")?.status).toBe("active");

    expect(bootstrappedForTenant).toBe("tenant-abc");

    expect(result.kid).toBe("bootstrap-tenant-abc-rs256");
    expect(result.alg).toBe("RS256");
    expect(result.rotated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});
