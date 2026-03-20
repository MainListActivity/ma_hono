export type AdminUserStatus = "active" | "disabled";

export interface AdminUser {
  id: string;
  email: string;
  status: AdminUserStatus;
}

export interface AdminSession {
  id: string;
  adminUserId: string;
  sessionTokenHash: string;
  expiresAt: string;
}
