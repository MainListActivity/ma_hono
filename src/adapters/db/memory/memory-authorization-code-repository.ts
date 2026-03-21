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

  listAuthorizationCodes(): AuthorizationCode[] {
    return [...this.authorizationCodes];
  }
}
