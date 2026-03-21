import type { LoginChallenge } from "../authorization/types";

export interface AuthenticationLoginChallengeRepository {
  consume(challengeId: string, consumedAt: string): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<LoginChallenge | null>;
}
