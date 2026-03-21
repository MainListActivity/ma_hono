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
  const invitation = await userRepository.findInvitationByTokenHash(
    await sha256Base64Url(invitationToken)
  );

  if (invitation === null) {
    return {
      ok: false,
      reason: "invalid_invitation"
    };
  }

  if (invitation.consumedAt !== null) {
    return {
      ok: false,
      reason: "invitation_already_used"
    };
  }

  if (new Date(invitation.expiresAt).getTime() <= now.getTime()) {
    return {
      ok: false,
      reason: "invitation_expired"
    };
  }

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
  await userRepository.updateInvitation({
    ...invitation,
    consumedAt: updatedAt
  });

  return {
    ok: true,
    user: activatedUser
  };
};
