import type { BrowserSession } from "./types";

export interface BrowserSessionRepository {
  create(session: BrowserSession): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<BrowserSession | null>;
}
