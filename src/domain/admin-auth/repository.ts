import type { AdminServicePrincipal, AdminSession, AdminUser } from "./types";

export interface AdminRepository {
  createSession(session: AdminSession): Promise<void>;
  findSessionByTokenHash(sessionTokenHash: string): Promise<AdminSession | null>;
  findUserByEmail(email: string): Promise<AdminUser | null>;
  createServicePrincipal(principal: AdminServicePrincipal): Promise<void>;
  findServicePrincipalByTokenHash(tokenHash: string): Promise<AdminServicePrincipal | null>;
  findServicePrincipalById(id: string): Promise<AdminServicePrincipal | null>;
  listServicePrincipals(): Promise<AdminServicePrincipal[]>;
  revokeServicePrincipal(id: string, revokedAt: string): Promise<AdminServicePrincipal | null>;
}
