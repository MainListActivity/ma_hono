import type { AuthenticationLoginChallengeRepository } from "../../../domain/authentication/login-challenge-repository";
import type { MagicLinkRepository } from "../../../domain/authentication/magic-link-repository";
import type { LoginChallenge } from "../../../domain/authorization/types";
import type { User } from "../../../domain/users/types";
import type { UserRepository } from "../../../domain/users/repository";
import { sha256Base64Url } from "../../../lib/hash";

export type MagicLinkRequestResult =
  | {
      kind: "issued";
      token: string;
      user: User;
      challenge: LoginChallenge;
    }
  | {
      kind: "rejected";
      reason: "magic_link_login_disabled" | "user_not_found" | "invalid_login_challenge";
    };

export type MagicLinkConsumeResult =
  | {
      kind: "authenticated";
      user: User;
      challenge: LoginChallenge;
    }
  | {
      kind: "rejected";
      reason: "invalid_or_expired_token";
    };

export const requestMagicLink = async ({
  email,
  issuer,
  loginChallengeRepository,
  loginChallengeToken,
  magicLinkRepository,
  now = new Date(),
  tenantId,
  userRepository
}: {
  email: string;
  issuer: string;
  loginChallengeRepository: AuthenticationLoginChallengeRepository;
  loginChallengeToken: string;
  magicLinkRepository: MagicLinkRepository;
  now?: Date;
  tenantId: string;
  userRepository: UserRepository;
}): Promise<MagicLinkRequestResult> => {
  const policy = await userRepository.findAuthMethodPolicyByTenantId(tenantId);

  if (policy !== null && !policy.emailMagicLink.enabled) {
    return { kind: "rejected", reason: "magic_link_login_disabled" };
  }

  const normalizedChallengeToken = loginChallengeToken.trim();
  const loginChallengeTokenHash = await sha256Base64Url(normalizedChallengeToken);
  const challenge = await loginChallengeRepository.findByTokenHash(loginChallengeTokenHash);

  if (
    challenge === null ||
    challenge.issuer !== issuer ||
    challenge.tenantId !== tenantId ||
    new Date(challenge.expiresAt).getTime() <= now.getTime()
  ) {
    return { kind: "rejected", reason: "invalid_login_challenge" };
  }

  const user = await userRepository.findUserByEmail(tenantId, email.trim());

  if (user === null || user.status !== "active") {
    return { kind: "rejected", reason: "user_not_found" };
  }

  const token = crypto.randomUUID();
  const tokenHash = await sha256Base64Url(token);
  const expiresAt = new Date(now.getTime() + 15 * 60 * 1000).toISOString();
  const createdAt = now.toISOString();

  await magicLinkRepository.create({
    id: crypto.randomUUID(),
    tenantId,
    userId: user.id,
    loginChallengeTokenHash,
    tokenHash,
    expiresAt,
    consumedAt: null,
    createdAt
  });

  return { kind: "issued", token, user, challenge };
};

export const consumeMagicLink = async ({
  loginChallengeRepository,
  magicLinkRepository,
  now = new Date(),
  token,
  userRepository
}: {
  loginChallengeRepository: AuthenticationLoginChallengeRepository;
  magicLinkRepository: MagicLinkRepository;
  now?: Date;
  token: string;
  userRepository: UserRepository;
}): Promise<MagicLinkConsumeResult> => {
  const normalizedToken = token.trim();

  if (normalizedToken.length === 0) {
    return { kind: "rejected", reason: "invalid_or_expired_token" };
  }

  const tokenHash = await sha256Base64Url(normalizedToken);
  const magicLinkRecord = await magicLinkRepository.findByTokenHash(tokenHash);

  if (
    magicLinkRecord === null ||
    new Date(magicLinkRecord.expiresAt).getTime() <= now.getTime()
  ) {
    return { kind: "rejected", reason: "invalid_or_expired_token" };
  }

  const challenge = await loginChallengeRepository.findByTokenHash(
    magicLinkRecord.loginChallengeTokenHash
  );

  if (challenge === null) {
    return { kind: "rejected", reason: "invalid_or_expired_token" };
  }

  const consumed = await magicLinkRepository.consume(magicLinkRecord.id, now.toISOString());

  if (!consumed) {
    return { kind: "rejected", reason: "invalid_or_expired_token" };
  }

  const consumedChallenge = await loginChallengeRepository.consume(
    challenge.id,
    now.toISOString()
  );

  if (!consumedChallenge) {
    return { kind: "rejected", reason: "invalid_or_expired_token" };
  }

  const user = await userRepository.findUserById(magicLinkRecord.tenantId, magicLinkRecord.userId);

  if (user === null || user.status !== "active") {
    return { kind: "rejected", reason: "invalid_or_expired_token" };
  }

  return { kind: "authenticated", user, challenge };
};
