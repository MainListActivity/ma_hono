import type { AccessTokenCustomClaim } from "./access-token-claims-types";

/**
 * True when `text` is valid JSON and not `null`. A null value would be
 * indistinguishable from "no claim", so it is rejected at admin write time.
 */
export const isValidJsonClaimValue = (text: string): boolean => {
  try {
    return JSON.parse(text) !== null;
  } catch {
    return false;
  }
};

/**
 * The value a fixed claim contributes to a token. `json` claims store JSON text
 * (for example `["Editor"]`) and are emitted as the parsed value; `string` claims
 * are emitted verbatim. Admin writes are validated, so a parse failure here means
 * stored data was corrupted. It throws instead of silently dropping the claim.
 */
export const resolveFixedClaimValue = (claim: AccessTokenCustomClaim): unknown => {
  if (claim.fixedValue === null || claim.valueType !== "json") {
    return claim.fixedValue;
  }

  return JSON.parse(claim.fixedValue);
};
