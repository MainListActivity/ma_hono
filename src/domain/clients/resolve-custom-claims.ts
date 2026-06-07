import type { User } from "../users/types";
import type { AccessTokenCustomClaim } from "./access-token-claims-types";
import {
  fetchClaimHook,
  type ClaimHookConfig,
  type ClaimHookFetcher
} from "./claim-hook-client";

const customClaimNameAliases = new Map([
  ["https://surrealdb.com/db", "db"],
  ["https://surrealdb.com/ac", "ac"],
  ["https://surrealdb.com/email", "email"]
]);

const resolveUserField = (
  user: User,
  field: string
): string | boolean | null => {
  switch (field) {
    case "id":
      return user.id;
    case "email":
      return user.email;
    case "email_verified":
      return user.emailVerified;
    case "username":
      return user.username;
    case "display_name":
      return user.displayName;
    default:
      return null;
  }
};

const normalizeCustomClaimName = (claimName: string): string =>
  customClaimNameAliases.get(claimName) ?? claimName;

export interface ResolveCustomClaimsHookDeps {
  config: ClaimHookConfig;
  /** Override for tests; defaults to the network fetcher. */
  fetcher?: ClaimHookFetcher;
}

/**
 * Resolve a client's custom claim configs into a flat claim map.
 *
 * - `fixed` / `user_field` sources resolve synchronously off the user record.
 * - `hook` sources call the external hook **at most once** (deduped here), then
 *   map `hookField` → `claimName` off the single returned object. If the hook is
 *   unconfigured (no `hookDeps`) or returns no value for a field, that claim is
 *   simply omitted.
 */
export const resolveCustomClaims = async (
  claims: AccessTokenCustomClaim[],
  user: User,
  hookDeps?: ResolveCustomClaimsHookDeps
): Promise<Record<string, unknown>> => {
  const result: Record<string, unknown> = {};

  const hasHookClaim = claims.some((claim) => claim.sourceType === "hook");
  let hookResult: Record<string, unknown> | null = null;

  if (hasHookClaim && hookDeps !== undefined) {
    const fetcher = hookDeps.fetcher ?? fetchClaimHook;
    hookResult = await fetcher(hookDeps.config, {
      subject: user.id,
      email: user.email
    });
  }

  for (const claim of claims) {
    const claimName = normalizeCustomClaimName(claim.claimName);

    if (claim.sourceType === "fixed") {
      if (claim.fixedValue !== null) {
        result[claimName] = claim.fixedValue;
      }
      continue;
    }

    if (claim.sourceType === "user_field" && claim.userField !== null) {
      const value = resolveUserField(user, claim.userField);

      if (value !== null && value !== "") {
        result[claimName] = value;
      }
      continue;
    }

    if (claim.sourceType === "hook" && claim.hookField !== null && hookResult !== null) {
      const value = hookResult[claim.hookField];

      if (value !== undefined && value !== null && value !== "") {
        result[claimName] = value;
      }
    }
  }

  return result;
};
