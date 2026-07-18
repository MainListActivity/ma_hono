import type { LoginChallenge } from "../authorization/types";
import type { AuthenticationLoginChallengeRepository } from "./login-challenge-repository";
import { sha256Base64Url } from "../../lib/hash";

export const isLoginChallengeActive = (
  challenge: LoginChallenge,
  now: Date = new Date()
): boolean =>
  challenge.consumedAt === null &&
  new Date(challenge.expiresAt).getTime() > now.getTime();

export const findActiveLoginChallengeForTenant = async ({
  loginChallengeRepository,
  tenantId,
  token,
  now = new Date()
}: {
  loginChallengeRepository: AuthenticationLoginChallengeRepository;
  tenantId: string;
  token: string;
  now?: Date;
}): Promise<LoginChallenge | null> => {
  const normalizedToken = token.trim();
  if (normalizedToken.length === 0) return null;

  const challenge = await loginChallengeRepository.findByTokenHash(
    await sha256Base64Url(normalizedToken)
  );

  return challenge !== null &&
    challenge.tenantId === tenantId &&
    isLoginChallengeActive(challenge, now)
    ? challenge
    : null;
};
