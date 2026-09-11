import type {
  ConsentChallenge,
  ConsentChallengeRepository
} from "../../../domain/authorization/consent-repository";

export class MemoryConsentChallengeRepository implements ConsentChallengeRepository {
  private readonly challenges: ConsentChallenge[];

  constructor(initialChallenges: ConsentChallenge[] = []) {
    this.challenges = initialChallenges.map((challenge) => ({ ...challenge }));
  }

  async create(challenge: ConsentChallenge): Promise<void> {
    this.challenges.push({ ...challenge });
  }

  async findActiveByTokenHash(tokenHash: string): Promise<ConsentChallenge | null> {
    const match = this.challenges.find(
      (challenge) =>
        challenge.tokenHash === tokenHash &&
        challenge.consumedAt === null &&
        new Date(challenge.expiresAt).getTime() > Date.now()
    );

    return match === undefined ? null : { ...match };
  }

  async consumeById(id: string, consumedAt: string): Promise<boolean> {
    const match = this.challenges.find(
      (challenge) =>
        challenge.id === id &&
        challenge.consumedAt === null &&
        new Date(challenge.expiresAt).getTime() > new Date(consumedAt).getTime()
    );

    if (match === undefined) {
      return false;
    }

    match.consumedAt = consumedAt;
    return true;
  }

  listChallenges(): ConsentChallenge[] {
    return this.challenges.map((challenge) => ({ ...challenge }));
  }
}

