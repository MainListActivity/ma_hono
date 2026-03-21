import { sha256Base64Url } from "../../lib/hash";
import type { UserRepository } from "./repository";
import type { User, UserInvitation } from "./types";

const defaultInvitationTtlMs = 24 * 60 * 60 * 1000;

const createOpaqueToken = () => crypto.randomUUID().replaceAll("-", "");

const normalizeEmail = (email: string) => email.trim().toLowerCase();

const normalizeUsername = (username: string | null | undefined) => {
  if (username === undefined || username === null) {
    return null;
  }

  const normalized = username.trim().toLowerCase();

  return normalized.length > 0 ? normalized : null;
};

export const provisionUser = async ({
  displayName,
  email,
  invitationTtlMs = defaultInvitationTtlMs,
  now = new Date(),
  tenantId,
  userRepository,
  username
}: {
  displayName: string;
  email: string;
  invitationTtlMs?: number;
  now?: Date;
  tenantId: string;
  userRepository: UserRepository;
  username?: string | null;
}): Promise<{
  invitation: UserInvitation;
  invitationToken: string;
  user: User;
}> => {
  const createdAt = now.toISOString();
  const user: User = {
    id: crypto.randomUUID(),
    tenantId,
    email: normalizeEmail(email),
    emailVerified: false,
    username: normalizeUsername(username),
    displayName: displayName.trim(),
    status: "provisioned",
    createdAt,
    updatedAt: createdAt
  };
  const invitationToken = createOpaqueToken();
  const invitation: UserInvitation = {
    id: crypto.randomUUID(),
    tenantId,
    userId: user.id,
    tokenHash: await sha256Base64Url(invitationToken),
    purpose: "account_activation",
    expiresAt: new Date(now.getTime() + invitationTtlMs).toISOString(),
    consumedAt: null,
    createdAt
  };

  await userRepository.createProvisionedUserWithInvitation({
    invitation,
    user
  });

  return {
    invitation,
    invitationToken,
    user
  };
};
