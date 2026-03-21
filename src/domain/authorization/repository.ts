import type { AuthorizationCode, LoginChallenge } from "./types";

export interface LoginChallengeRepository {
  create(challenge: LoginChallenge): Promise<void>;
}

export interface AuthorizationCodeRepository {
  create(code: AuthorizationCode): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<AuthorizationCode | null>;
  consumeById(id: string, consumedAt: string): Promise<boolean>;
}
