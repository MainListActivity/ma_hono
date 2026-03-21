import type {
  PasswordCredential,
  TenantAuthMethodPolicy,
  User,
  UserInvitation
} from "./types";

export interface UserRepository {
  createInvitation(invitation: UserInvitation): Promise<void>;
  createUser(user: User): Promise<void>;
  findAuthMethodPolicyByTenantId(tenantId: string): Promise<TenantAuthMethodPolicy | null>;
  findInvitationByTokenHash(tokenHash: string): Promise<UserInvitation | null>;
  findPasswordCredentialByUserId(
    tenantId: string,
    userId: string
  ): Promise<PasswordCredential | null>;
  findUserByEmail(tenantId: string, email: string): Promise<User | null>;
  findUserById(tenantId: string, userId: string): Promise<User | null>;
  findUserByUsername(tenantId: string, username: string): Promise<User | null>;
  updateInvitation(invitation: UserInvitation): Promise<void>;
  updateUser(user: User): Promise<void>;
  upsertPasswordCredential(credential: PasswordCredential): Promise<void>;
}
