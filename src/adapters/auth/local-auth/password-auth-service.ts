import type { AuthenticationLoginChallengeRepository } from "../../../domain/authentication/login-challenge-repository";
import type { UserRepository } from "../../../domain/users/repository";
import type { LoginChallenge } from "../../../domain/authorization/types";
import type { User } from "../../../domain/users/types";
import { verifyPassword } from "../../../domain/users/passwords";
import { sha256Base64Url } from "../../../lib/hash";

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
    new Date(challenge.expiresAt).getTime() <= now.getTime()
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

  const user = await userRepository.findUserByUsername(tenantId, normalizedUsername);

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

  const consumeSucceeded = await loginChallengeRepository.consume(
    challenge.id,
    now.toISOString()
  );

  if (!consumeSucceeded) {
    return {
      kind: "rejected",
      reason: "invalid_login_challenge"
    };
  }

  return {
    kind: "authenticated",
    challenge,
    user
  };
};
