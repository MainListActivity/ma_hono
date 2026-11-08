import type { UserRepository } from "./repository";
import type { User, UserStatus } from "./types";

export type ChangeableUserStatus = "active" | "disabled";

export type ChangeUserStatusResult =
  | {
      ok: true;
      previousStatus: UserStatus;
      user: User;
    }
  | {
      ok: false;
      reason: "user_not_found" | "invalid_state";
    };

/**
 * 启用 / 停用用户。
 *
 * - 停用：active 或 provisioned 均可置为 disabled；disabled 时激活与登录都被拒绝。
 * - 启用：只从 disabled 恢复。agent 或已有密码凭据的用户回到 active；
 *   否则回到 provisioned，保留激活流程，避免绕过激活邀请。
 * - provisioned 不能直接置为 active，必须走激活流程。
 * - 目标状态与当前相同时视为幂等成功，不写库。
 */
export const changeUserStatus = async ({
  now = new Date(),
  status,
  tenantId,
  userId,
  userRepository
}: {
  now?: Date;
  status: ChangeableUserStatus;
  tenantId: string;
  userId: string;
  userRepository: UserRepository;
}): Promise<ChangeUserStatusResult> => {
  const user = await userRepository.findUserById(tenantId, userId);

  if (user === null) {
    return { ok: false, reason: "user_not_found" };
  }

  if (user.status === status) {
    return { ok: true, previousStatus: user.status, user };
  }

  let nextStatus: UserStatus;

  if (status === "disabled") {
    nextStatus = "disabled";
  } else if (user.status === "disabled") {
    const hasPasswordCredential =
      user.kind !== "agent" &&
      (await userRepository.findPasswordCredentialByUserId(tenantId, userId)) !== null;

    nextStatus =
      user.kind === "agent" || hasPasswordCredential ? "active" : "provisioned";
  } else {
    return { ok: false, reason: "invalid_state" };
  }

  const updated: User = {
    ...user,
    status: nextStatus,
    updatedAt: now.toISOString()
  };

  await userRepository.updateUser(updated);

  return { ok: true, previousStatus: user.status, user: updated };
};
