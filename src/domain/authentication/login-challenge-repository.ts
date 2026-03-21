import type { LoginChallenge } from "../authorization/types";

export interface AuthenticationLoginChallengeRepository {
  consume(challengeId: string, consumedAt: string): Promise<boolean>;
  findByTokenHash(tokenHash: string): Promise<LoginChallenge | null>;
}
