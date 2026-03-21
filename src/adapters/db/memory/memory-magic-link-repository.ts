import type { MagicLinkToken, MagicLinkRepository } from "../../../domain/authentication/magic-link-repository";


export class MemoryMagicLinkRepository implements MagicLinkRepository {
  private readonly tokens: MagicLinkToken[];

  constructor(initialTokens: MagicLinkToken[] = []) {
    this.tokens = [...initialTokens];
  }

  async create(token: MagicLinkToken): Promise<void> {
    this.tokens.push(token);
  }

  async findByTokenHash(tokenHash: string): Promise<MagicLinkToken | null> {
    return (
      this.tokens.find(
        (t) => t.tokenHash === tokenHash && t.consumedAt === null
      ) ?? null
    );
  }

  async consume(id: string, consumedAt: string): Promise<boolean> {
    const token = this.tokens.find((t) => t.id === id && t.consumedAt === null);

    if (token !== undefined) {
      token.consumedAt = consumedAt;
      return true;
    }

    return false;
  }

  listTokens(): MagicLinkToken[] {
    return this.tokens;
  }
}
