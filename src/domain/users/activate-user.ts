import { sha256Base64Url } from "../../lib/hash";
import { hashPassword } from "./passwords";
import type { UserRepository } from "./repository";
import type { PasswordCredential, User } from "./types";

export type ActivateUserResult =
  | {
      ok: true;
      user: User;
    }
  | {
      ok: false;
      reason: "invalid_invitation" | "invitation_already_used" | "invitation_expired";
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
  const consumedInvitation = await userRepository.consumeInvitationByTokenHash({
    tokenHash: await sha256Base64Url(invitationToken),
    now
  });

  if (consumedInvitation.kind === "not_found") {
    return {
      ok: false,
      reason: "invalid_invitation"
    };
  }

  if (consumedInvitation.kind === "already_used") {
    return {
      ok: false,
      reason: "invitation_already_used"
    };
  }

  if (consumedInvitation.kind === "expired") {
    return {
      ok: false,
      reason: "invitation_expired"
    };
  }

  const { invitation } = consumedInvitation;

  const user = await userRepository.findUserById(invitation.tenantId, invitation.userId);

  if (user === null) {
    return {
      ok: false,
      reason: "invalid_invitation"
    };
  }

  const updatedAt = now.toISOString();
  const activatedUser: User = {
    ...user,
    emailVerified: true,
    status: "active",
    updatedAt
  };
  const existingCredential = await userRepository.findPasswordCredentialByUserId(
    user.tenantId,
    user.id
  );
  const credential: PasswordCredential = {
    id: existingCredential?.id ?? crypto.randomUUID(),
    tenantId: user.tenantId,
    userId: user.id,
    passwordHash: await hashPassword(password),
    createdAt: existingCredential?.createdAt ?? updatedAt,
    updatedAt
  };

  await userRepository.upsertPasswordCredential(credential);
  await userRepository.updateUser(activatedUser);

  return {
    ok: true,
    user: activatedUser
  };
};
