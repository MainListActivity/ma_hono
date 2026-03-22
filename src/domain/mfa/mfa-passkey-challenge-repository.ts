export interface MfaPasskeyChallenge {
  id: string;
  tenantId: string;
  loginChallengeId: string;
  challengeHash: string;
  expiresAt: string;
  consumedAt: string | null;
  createdAt: string;
}

export interface MfaPasskeyChallengeRepository {
  create(challenge: MfaPasskeyChallenge): Promise<void>;
  /** Returns null if not found, expired, or already consumed */
  consumeByChallengeHash(challengeHash: string, consumedAt: string, now: string): Promise<MfaPasskeyChallenge | null>;
}
