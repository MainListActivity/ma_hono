import type { BrowserSessionRepository } from "../../../domain/authentication/repository";
import type { BrowserSession } from "../../../domain/authentication/types";

export class MemoryUserSessionRepository implements BrowserSessionRepository {
  private readonly sessions: BrowserSession[];

  constructor(initialSessions: BrowserSession[] = []) {
    this.sessions = [...initialSessions];
  }

  async create(session: BrowserSession): Promise<void> {
    this.sessions.push(session);
  }

  async findByTokenHash(tokenHash: string): Promise<BrowserSession | null> {
    return this.sessions.find((session) => session.tokenHash === tokenHash) ?? null;
  }

  listSessions(): BrowserSession[] {
    return [...this.sessions];
  }
}
