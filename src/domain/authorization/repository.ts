import type { AuthorizationCode, LoginChallenge } from "./types";

export interface LoginChallengeRepository {
  create(challenge: LoginChallenge): Promise<void>;
}

export interface AuthorizationCodeRepository {
  create(code: AuthorizationCode): Promise<void>;
}
