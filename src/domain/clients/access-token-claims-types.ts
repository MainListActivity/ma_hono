export type AccessTokenClaimSourceType = "fixed" | "user_field";

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
  "nonce"
]);

export interface AccessTokenCustomClaim {
  id: string;
  clientId: string;
  tenantId: string;
  claimName: string;
  sourceType: AccessTokenClaimSourceType;
  fixedValue: string | null;
  userField: AccessTokenClaimUserField | null;
  createdAt: string;
  updatedAt: string;
}
