export type AccessTokenClaimSourceType = "fixed" | "user_field" | "hook";

export type AccessTokenClaimUserField =
  | "id"
  | "email"
  | "email_verified"
  | "username"
  | "display_name";

export const ALLOWED_USER_FIELDS: AccessTokenClaimUserField[] = [
  "id",
  "email",
  "email_verified",
  "username",
  "display_name"
];

export const RESERVED_CLAIM_NAMES = new Set([
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  "scope",
  "client_id",
  "nonce",
  "act",
  "task"
]);

/** "json": fixedValue is JSON text, emitted as the parsed value (e.g. an array). */
export type AccessTokenClaimValueType = "string" | "json";

export interface AccessTokenCustomClaim {
  id: string;
  clientId: string;
  tenantId: string;
  claimName: string;
  sourceType: AccessTokenClaimSourceType;
  fixedValue: string | null;
  /** Absent means "string". */
  valueType?: AccessTokenClaimValueType;
  userField: AccessTokenClaimUserField | null;
  hookField: string | null;
  createdAt: string;
  updatedAt: string;
}
