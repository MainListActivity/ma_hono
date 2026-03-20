import type { AdminRepository } from "../../../domain/admin-auth/repository";
import type { AdminSession, AdminUser } from "../../../domain/admin-auth/types";

export class MemoryAdminRepository implements AdminRepository {
  private readonly adminUsers: AdminUser[];
  private readonly sessions: AdminSession[];

  constructor({
    adminUsers = [],
    sessions = []
  }: {
    adminUsers?: AdminUser[];
    sessions?: AdminSession[];
  } = {}) {
    this.adminUsers = [...adminUsers];
    this.sessions = [...sessions];
  }

  async createSession(session: AdminSession): Promise<void> {
    this.sessions.push(session);
  }

  async findSessionByTokenHash(sessionTokenHash: string): Promise<AdminSession | null> {
    return this.sessions.find((session) => session.sessionTokenHash === sessionTokenHash) ?? null;
  }

  async findUserByEmail(email: string): Promise<AdminUser | null> {
    return this.adminUsers.find((adminUser) => adminUser.email === email) ?? null;
  }
}
