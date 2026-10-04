import type { AdminRepository } from "../../../domain/admin-auth/repository";
import type {
  AdminServicePrincipal,
  AdminSession,
  AdminUser
} from "../../../domain/admin-auth/types";

export class MemoryAdminRepository implements AdminRepository {
  private readonly adminUsers: AdminUser[];
  private readonly sessions: AdminSession[];
  private readonly servicePrincipals: AdminServicePrincipal[];

  constructor({
    adminUsers = [],
    sessions = [],
    servicePrincipals = []
  }: {
    adminUsers?: AdminUser[];
    sessions?: AdminSession[];
    servicePrincipals?: AdminServicePrincipal[];
  } = {}) {
    this.adminUsers = [...adminUsers];
    this.sessions = [...sessions];
    this.servicePrincipals = [...servicePrincipals];
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

  async createServicePrincipal(principal: AdminServicePrincipal): Promise<void> {
    this.servicePrincipals.push(principal);
  }

  async findServicePrincipalByTokenHash(
    tokenHash: string
  ): Promise<AdminServicePrincipal | null> {
    return this.servicePrincipals.find((principal) => principal.tokenHash === tokenHash) ?? null;
  }

  async findServicePrincipalById(id: string): Promise<AdminServicePrincipal | null> {
    return this.servicePrincipals.find((principal) => principal.id === id) ?? null;
  }

  async listServicePrincipals(): Promise<AdminServicePrincipal[]> {
    return [...this.servicePrincipals];
  }

  async revokeServicePrincipal(
    id: string,
    revokedAt: string
  ): Promise<AdminServicePrincipal | null> {
    const principal = this.servicePrincipals.find((entry) => entry.id === id) ?? null;
    if (principal === null) {
      return null;
    }

    principal.status = "revoked";
    principal.revokedAt = revokedAt;
    return principal;
  }

  /** Test helper: expose stored principals including token hashes. */
  listServicePrincipalsRaw(): AdminServicePrincipal[] {
    return [...this.servicePrincipals];
  }
}
