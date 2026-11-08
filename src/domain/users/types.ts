export type UserStatus = "provisioned" | "active" | "disabled";

/** "agent" accounts are machine identities; they never sign in as a person. */
export type UserKind = "human" | "agent";

export interface User {
  id: string;
  tenantId: string;
  email: string;
  emailVerified: boolean;
  username: string | null;
  displayName: string;
  status: UserStatus;
  /** ISO datetime; 非 NULL 即测试账号，到期后不可用并被清理。 */
  expiresAt?: string | null;
  testOrigin?: string | null;
  /** Absent means "human" (legacy rows). */
  kind?: UserKind;
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
