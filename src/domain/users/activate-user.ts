import { sha256Base64Url } from "../../lib/hash";
import { hashPassword } from "./passwords";
import type { UserRepository } from "./repository";
import type { User } from "./types";

export type ActivateUserResult =
  | {
      ok: true;
      user: User;
    }
  | {
      ok: false;
      reason:
        | "invalid_invitation"
        | "invitation_already_used"
        | "invitation_expired"
        | "user_already_initialized"
        | "user_disabled";
    };

export const activateUser = async ({
  invitationToken,
  now = new Date(),
  password,
  userRepository
}: {
  invitationToken: string;
  now?: Date;
  password: string;
  userRepository: UserRepository;
}): Promise<ActivateUserResult> => {
  const activated = await userRepository.activateUserByInvitationToken({
    createPasswordHash: () => hashPassword(password),
    tokenHash: await sha256Base64Url(invitationToken),
    now
  });

  if (activated.kind === "not_found") {
    return {
      ok: false,
      reason: "invalid_invitation"
    };
  }

  if (activated.kind === "already_used") {
    return {
      ok: false,
      reason: "invitation_already_used"
    };
  }

  if (activated.kind === "expired") {
    return {
      ok: false,
      reason: "invitation_expired"
    };
  }

  if (activated.kind === "user_disabled") {
    return {
      ok: false,
      reason: "user_disabled"
    };
  }

  if (activated.kind === "already_initialized") {
    return {
      ok: false,
      reason: "user_already_initialized"
    };
  }

  return {
    ok: true,
    user: activated.user
  };
};
