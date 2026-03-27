import type { User } from "../users/types";
import type { AccessTokenCustomClaim } from "./access-token-claims-types";

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

export const resolveCustomClaims = (
  claims: AccessTokenCustomClaim[],
  user: User
): Record<string, unknown> => {
  const result: Record<string, unknown> = {};

  for (const claim of claims) {
    if (claim.sourceType === "fixed") {
      if (claim.fixedValue !== null) {
        result[claim.claimName] = claim.fixedValue;
      }
      continue;
    }

    if (claim.sourceType === "user_field" && claim.userField !== null) {
      const value = resolveUserField(user, claim.userField);

      if (value !== null && value !== "") {
        result[claim.claimName] = value;
      }
    }
  }

  return result;
};
