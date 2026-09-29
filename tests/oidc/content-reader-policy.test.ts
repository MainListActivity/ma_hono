import { describe, expect, it } from "vitest";

import {
  computeContentReaderTtlSeconds,
  createContentReaderIssuancePolicy,
  isContentReaderIssuanceAllowed,
  mergeContentReaderClaims
} from "../../src/domain/tokens/content-reader-policy";

describe("content_reader issuance policy", () => {
  it("creates a normalized allowlist policy", () => {
    const policy = createContentReaderIssuancePolicy({
      allowedClientIds: [" app-client ", "app-client", "ops-client"],
      allowedTenantIds: ["tenant_acme"],
      allowedContentDatabases: ["platform_content"],
      maxTtlSeconds: 600
    });

    expect(policy.allowedClientIds).toEqual(["app-client", "ops-client"]);
    expect(policy.allowedTenantIds).toEqual(["tenant_acme"]);
    expect(policy.allowedContentDatabases).toEqual(["platform_content"]);
    expect(policy.maxTtlSeconds).toBe(600);
  });

  it("rejects empty client or database allowlists", () => {
    expect(() =>
      createContentReaderIssuancePolicy({
        allowedClientIds: [],
        allowedContentDatabases: ["platform_content"]
      })
    ).toThrow(/client_id/);

    expect(() =>
      createContentReaderIssuancePolicy({
        allowedClientIds: ["app-client"],
        allowedContentDatabases: []
      })
    ).toThrow(/database/);
  });

  it("gates issuance by client and optional tenant allowlists", () => {
    const policy = createContentReaderIssuancePolicy({
      allowedClientIds: ["app-client"],
      allowedTenantIds: ["tenant_acme"],
      allowedContentDatabases: ["platform_content"]
    });

    expect(
      isContentReaderIssuanceAllowed({
        clientId: "app-client",
        policy,
        tenantId: "tenant_acme"
      })
    ).toBe(true);
    expect(
      isContentReaderIssuanceAllowed({
        clientId: "other-client",
        policy,
        tenantId: "tenant_acme"
      })
    ).toBe(false);
    expect(
      isContentReaderIssuanceAllowed({
        clientId: "app-client",
        policy,
        tenantId: "tenant_beta"
      })
    ).toBe(false);
    expect(
      isContentReaderIssuanceAllowed({
        clientId: "app-client",
        policy: null,
        tenantId: "tenant_acme"
      })
    ).toBe(false);
  });

  it("computes ttl as the min of subject remainder, lease, and server max", () => {
    expect(
      computeContentReaderTtlSeconds({
        nowSeconds: 1_000,
        subjectExpiresAt: 1_000 + 1_800,
        leaseEndSeconds: 1_000 + 300,
        maxTtlSeconds: 900
      })
    ).toEqual({ ok: true, ttlSeconds: 300 });

    expect(
      computeContentReaderTtlSeconds({
        nowSeconds: 1_000,
        subjectExpiresAt: 1_000 + 120,
        leaseEndSeconds: 1_000 + 300,
        maxTtlSeconds: 900
      })
    ).toEqual({ ok: true, ttlSeconds: 120 });

    expect(
      computeContentReaderTtlSeconds({
        nowSeconds: 1_000,
        subjectExpiresAt: 1_000 + 1_800,
        leaseEndSeconds: 1_000 + 1_200,
        maxTtlSeconds: 900
      })
    ).toEqual({ ok: true, ttlSeconds: 900 });
  });

  it("rejects expired or non-positive lifetime inputs", () => {
    expect(
      computeContentReaderTtlSeconds({
        nowSeconds: 1_000,
        subjectExpiresAt: 999,
        leaseEndSeconds: 1_500,
        maxTtlSeconds: 900
      })
    ).toEqual({ ok: false });

    expect(
      computeContentReaderTtlSeconds({
        nowSeconds: 1_000,
        subjectExpiresAt: 1_500,
        leaseEndSeconds: 1_000,
        maxTtlSeconds: 900
      })
    ).toEqual({ ok: false });

    expect(
      computeContentReaderTtlSeconds({
        nowSeconds: 1_000,
        subjectExpiresAt: 1_500.5,
        leaseEndSeconds: 1_800,
        maxTtlSeconds: 900
      })
    ).toEqual({ ok: false });
  });

  it("lets content claims win over configured purpose-boundary keys", () => {
    expect(
      mergeContentReaderClaims({
        configuredClaims: {
          ac: "admin",
          db: "ws_alpha",
          RL: ["Owner"],
          email: "alice@example.com",
          can_create_workspace: true
        },
        contentClaims: {
          ac: "content_reader",
          db: "platform_content",
          workspace_id: "ws_alpha",
          entitlement_revision: "rev_1"
        }
      })
    ).toEqual({
      email: "alice@example.com",
      can_create_workspace: true,
      ac: "content_reader",
      db: "platform_content",
      workspace_id: "ws_alpha",
      entitlement_revision: "rev_1"
    });
  });
});
