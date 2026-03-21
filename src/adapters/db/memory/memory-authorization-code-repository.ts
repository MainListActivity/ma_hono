import type { AuthorizationCodeRepository } from "../../../domain/authorization/repository";
import type { AuthorizationCode } from "../../../domain/authorization/types";

export class MemoryAuthorizationCodeRepository implements AuthorizationCodeRepository {
  private readonly authorizationCodes: AuthorizationCode[];

  constructor(initialAuthorizationCodes: AuthorizationCode[] = []) {
    this.authorizationCodes = [...initialAuthorizationCodes];
  }

  async create(code: AuthorizationCode): Promise<void> {
    this.authorizationCodes.push(code);
  }

  async findByTokenHash(tokenHash: string): Promise<AuthorizationCode | null> {
    const match = this.authorizationCodes.find(
      (code) => code.tokenHash === tokenHash && code.consumedAt === null
    );

    if (match === undefined) {
      return null;
    }

    return {
      ...match
    };
  }

  async consumeById(id: string, consumedAt: string): Promise<boolean> {
    const match = this.authorizationCodes.find((code) => code.id === id && code.consumedAt === null);

    if (match === undefined) {
      return false;
    }

    match.consumedAt = consumedAt;

    return true;
  }

  listAuthorizationCodes(): AuthorizationCode[] {
    return [...this.authorizationCodes];
  }
}
