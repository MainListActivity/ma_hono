import { describe, expect, it } from "vitest";

import type { AccessTokenCustomClaim } from "../../src/domain/clients/access-token-claims-types";
import { resolveCustomClaims } from "../../src/domain/clients/resolve-custom-claims";
import type { User } from "../../src/domain/users/types";

const baseUser: User = {
  id: "user_1",
  tenantId: "tenant_1",
  email: "alice@example.com",
  emailVerified: true,
  username: "alice",
  displayName: "Alice Smith",
  status: "active",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z"
};

const makeClaim = (
  overrides: Partial<AccessTokenCustomClaim>
): AccessTokenCustomClaim => ({
  id: "claim_1",
  clientId: "client_1",
  tenantId: "tenant_1",
  claimName: "custom",
  sourceType: "fixed",
  fixedValue: null,
  userField: null,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  ...overrides
});

describe("resolveCustomClaims", () => {
  it("resolves fixed claims", () => {
    const claims = [
      makeClaim({ claimName: "ns", sourceType: "fixed", fixedValue: "my_ns" })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ ns: "my_ns" });
  });

  it("resolves user_field id", () => {
    const claims = [
      makeClaim({ claimName: "uid", sourceType: "user_field", userField: "id" })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ uid: "user_1" });
  });

  it("resolves user_field email", () => {
    const claims = [
      makeClaim({
        claimName: "user_email",
        sourceType: "user_field",
        userField: "email"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ user_email: "alice@example.com" });
  });

  it("resolves user_field email_verified", () => {
    const claims = [
      makeClaim({
        claimName: "ev",
        sourceType: "user_field",
        userField: "email_verified"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ ev: true });
  });

  it("resolves user_field username", () => {
    const claims = [
      makeClaim({
        claimName: "uname",
        sourceType: "user_field",
        userField: "username"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ uname: "alice" });
  });

  it("resolves user_field display_name", () => {
    const claims = [
      makeClaim({
        claimName: "name",
        sourceType: "user_field",
        userField: "display_name"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ name: "Alice Smith" });
  });

  it("omits user_field claim when value is null", () => {
    const user = { ...baseUser, username: null };
    const claims = [
      makeClaim({
        claimName: "uname",
        sourceType: "user_field",
        userField: "username"
      })
    ];

    const result = resolveCustomClaims(claims, user);

    expect(result).toEqual({});
  });

  it("resolves multiple claims", () => {
    const claims = [
      makeClaim({
        id: "c1",
        claimName: "ns",
        sourceType: "fixed",
        fixedValue: "my_ns"
      }),
      makeClaim({
        id: "c2",
        claimName: "user_email",
        sourceType: "user_field",
        userField: "email"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ ns: "my_ns", user_email: "alice@example.com" });
  });

  it("returns empty object when no claims", () => {
    const result = resolveCustomClaims([], baseUser);

    expect(result).toEqual({});
  });
});
