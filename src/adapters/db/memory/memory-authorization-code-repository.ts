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

  async consumeByTokenHash(
    tokenHash: string,
    consumedAt: string
  ): Promise<AuthorizationCode | null> {
    const match = this.authorizationCodes.find(
      (code) => code.tokenHash === tokenHash && code.consumedAt === null
    );

    if (match === undefined) {
      return null;
    }

    match.consumedAt = consumedAt;

    return {
      ...match
    };
  }

  listAuthorizationCodes(): AuthorizationCode[] {
    return [...this.authorizationCodes];
  }
}
