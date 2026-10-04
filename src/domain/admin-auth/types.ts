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

export type ServicePrincipalStatus = "active" | "revoked";

export type ServicePrincipalScope = "tenant.read" | "user.read" | "user.provision";

export const SERVICE_PRINCIPAL_SCOPES: readonly ServicePrincipalScope[] = [
  "tenant.read",
  "user.read",
  "user.provision"
] as const;

export interface AdminServicePrincipal {
  id: string;
  label: string;
  tokenHash: string;
  scopes: ServicePrincipalScope[];
  status: ServicePrincipalStatus;
  createdAt: string;
  revokedAt: string | null;
  createdBy: string;
}

export type AdminAuthorization =
  | { kind: "session"; session: AdminSession }
  | { kind: "service_principal"; principal: AdminServicePrincipal };
