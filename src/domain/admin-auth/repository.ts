import type { AdminSession, AdminUser } from "./types";

export interface AdminRepository {
  createSession(session: AdminSession): Promise<void>;
  findSessionByTokenHash(sessionTokenHash: string): Promise<AdminSession | null>;
  findUserByEmail(email: string): Promise<AdminUser | null>;
}
