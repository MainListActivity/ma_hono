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
    kind: "human",
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

/**
 * 开设 agent 账号：机器身份，没有密码与激活邀请，开户即 active。
 * agent 不能作为人登录（密码、magic link、passkey 均拒绝），令牌只能经换发获得。
 */
export const provisionAgentUser = async ({
  displayName,
  email,
  now = new Date(),
  tenantId,
  userRepository,
  username
}: {
  displayName: string;
  email: string;
  now?: Date;
  tenantId: string;
  userRepository: UserRepository;
  username?: string | null;
}): Promise<{ user: User }> => {
  const createdAt = now.toISOString();
  const user: User = {
    id: crypto.randomUUID(),
    tenantId,
    email: normalizeEmail(email),
    emailVerified: false,
    username: normalizeUsername(username),
    displayName: displayName.trim(),
    status: "active",
    kind: "agent",
    createdAt,
    updatedAt: createdAt
  };

  await userRepository.createAgentUser({ user });

  return { user };
};

export type ReissueUserActivationResult =
  | {
      ok: true;
      invitation: UserInvitation;
      invitationToken: string;
      user: User;
    }
  | {
      ok: false;
      reason: "user_not_found" | "user_not_provisioned";
    };

export const reissueUserActivation = async ({
  invitationTtlMs = defaultInvitationTtlMs,
  now = new Date(),
  tenantId,
  userId,
  userRepository
}: {
  invitationTtlMs?: number;
  now?: Date;
  tenantId: string;
  userId: string;
  userRepository: UserRepository;
}): Promise<ReissueUserActivationResult> => {
  const invitationToken = createOpaqueToken();
  const createdAt = now.toISOString();
  const invitation: UserInvitation = {
    id: crypto.randomUUID(),
    tenantId,
    userId,
    tokenHash: await sha256Base64Url(invitationToken),
    purpose: "account_activation",
    expiresAt: new Date(now.getTime() + invitationTtlMs).toISOString(),
    consumedAt: null,
    createdAt
  };

  const result = await userRepository.reissueActivationInvitation({
    invitation,
    now,
    tenantId,
    userId
  });

  if (result.kind === "not_found") {
    return { ok: false, reason: "user_not_found" };
  }

  if (result.kind === "not_provisioned") {
    return { ok: false, reason: "user_not_provisioned" };
  }

  return {
    ok: true,
    invitation,
    invitationToken,
    user: result.user
  };
};
