import type { LoginChallenge } from "../authorization/types";

export const isLoginChallengeActive = (
  challenge: LoginChallenge,
  now: Date = new Date()
): boolean =>
  challenge.consumedAt === null &&
  new Date(challenge.expiresAt).getTime() > now.getTime();
