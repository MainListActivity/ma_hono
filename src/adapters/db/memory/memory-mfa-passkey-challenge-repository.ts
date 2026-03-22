import type {
  MfaPasskeyChallenge,
  MfaPasskeyChallengeRepository
} from "../../../domain/mfa/mfa-passkey-challenge-repository";

export class MemoryMfaPasskeyChallengeRepository implements MfaPasskeyChallengeRepository {
  private readonly challenges: MfaPasskeyChallenge[] = [];

  async create(challenge: MfaPasskeyChallenge): Promise<void> {
    this.challenges.push({ ...challenge });
  }

  async consumeByChallengeHash(
    challengeHash: string,
    consumedAt: string,
    now: string
  ): Promise<MfaPasskeyChallenge | null> {
    const challenge = this.challenges.find(
      (c) =>
        c.challengeHash === challengeHash &&
        c.consumedAt === null &&
        c.expiresAt > now
    );
    if (challenge === undefined) return null;
    challenge.consumedAt = consumedAt;
    return { ...challenge };
  }
}
