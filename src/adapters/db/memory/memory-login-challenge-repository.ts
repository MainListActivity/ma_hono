import type { LoginChallengeRepository } from "../../../domain/authorization/repository";
import type { LoginChallenge } from "../../../domain/authorization/types";

export class MemoryLoginChallengeRepository implements LoginChallengeRepository {
  private readonly challenges: LoginChallenge[];

  constructor(initialChallenges: LoginChallenge[] = []) {
    this.challenges = [...initialChallenges];
  }

  async create(challenge: LoginChallenge): Promise<void> {
    this.challenges.push(challenge);
  }

  listChallenges(): LoginChallenge[] {
    return [...this.challenges];
  }
}
