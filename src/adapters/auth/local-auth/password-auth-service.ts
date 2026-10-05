import type { AuthenticationLoginChallengeRepository } from "../../../domain/authentication/login-challenge-repository";
import type { UserRepository } from "../../../domain/users/repository";
import type { LoginChallenge } from "../../../domain/authorization/types";
import type { User } from "../../../domain/users/types";
import { verifyPassword } from "../../../domain/users/passwords";
import { sha256Base64Url } from "../../../lib/hash";
import { isLoginChallengeActive } from "../../../domain/authentication/login-challenge";

export type PasswordLoginFailureReason =
  | "invalid_credentials"
  | "invalid_login_challenge"
  | "password_login_disabled";

export type PasswordLoginResult =
  | {
      kind: "authenticated";
      challenge: LoginChallenge;
      user: User;
    }
  | {
      kind: "rejected";
      reason: PasswordLoginFailureReason;
    };

export const authenticateWithPassword = async ({
  loginChallengeRepository,
  loginChallengeToken,
  now = new Date(),
  password,
  issuer,
  tenantId,
  userRepository,
  username
}: {
  loginChallengeRepository: AuthenticationLoginChallengeRepository;
  loginChallengeToken: string;
  now?: Date;
  password: string;
  issuer: string;
  tenantId: string;
  userRepository: UserRepository;
  username: string;
}): Promise<PasswordLoginResult> => {
  const normalizedChallengeToken = loginChallengeToken.trim();
  const normalizedUsername = username.trim();

  if (
    normalizedChallengeToken.length === 0 ||
    normalizedUsername.length === 0 ||
    password.length === 0
  ) {
    return {
      kind: "rejected",
      reason: "invalid_credentials"
    };
  }

  const challenge = await loginChallengeRepository.findByTokenHash(
    await sha256Base64Url(normalizedChallengeToken)
  );

  if (
    challenge === null ||
    challenge.issuer !== issuer ||
    challenge.tenantId !== tenantId ||
    !isLoginChallengeActive(challenge, now)
  ) {
    return {
      kind: "rejected",
      reason: "invalid_login_challenge"
    };
  }

  const policy = await userRepository.findAuthMethodPolicyByTenantId(tenantId);

  if (policy !== null && !policy.password.enabled) {
    return {
      kind: "rejected",
      reason: "password_login_disabled"
    };
  }

  // 登录框文案是「用户名或邮箱」：按 username 精确匹配；未命中且标识符形似
  // 邮箱时按 email 兜底（email 落库统一小写，users(tenant_id,email) 唯一索引）。
  const user =
    (await userRepository.findUserByUsername(tenantId, normalizedUsername)) ??
    (normalizedUsername.includes("@")
      ? await userRepository.findUserByEmail(tenantId, normalizedUsername.toLowerCase())
      : null);

  if (user === null || user.status !== "active") {
    return {
      kind: "rejected",
      reason: "invalid_credentials"
    };
  }

  const credential = await userRepository.findPasswordCredentialByUserId(tenantId, user.id);

  if (credential === null) {
    return {
      kind: "rejected",
      reason: "invalid_credentials"
    };
  }

  if (
    !(await verifyPassword({
      password,
      passwordHash: credential.passwordHash
    }))
  ) {
    return {
      kind: "rejected",
      reason: "invalid_credentials"
    };
  }

  return {
    kind: "authenticated",
    challenge,
    user
  };
};
