export type UserStatus = "provisioned" | "active" | "disabled";

export interface User {
  id: string;
  tenantId: string;
  email: string;
  emailVerified: boolean;
  username: string | null;
  displayName: string;
  status: UserStatus;
  createdAt: string;
  updatedAt: string;
}

export interface PasswordCredential {
  id: string;
  tenantId: string;
  userId: string;
  passwordHash: string;
  createdAt: string;
  updatedAt: string;
}

export type UserInvitationPurpose = "account_activation";

export interface UserInvitation {
  id: string;
  tenantId: string;
  userId: string;
  tokenHash: string;
  purpose: UserInvitationPurpose;
  expiresAt: string;
  consumedAt: string | null;
  createdAt: string;
}

export interface TenantAuthMethodToggle {
  enabled: boolean;
}

export interface TenantAuthMethodPolicy {
  tenantId: string;
  password: TenantAuthMethodToggle;
  emailMagicLink: TenantAuthMethodToggle;
  passkey: TenantAuthMethodToggle;
}
