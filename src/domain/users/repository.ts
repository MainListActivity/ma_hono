import type {
  PasswordCredential,
  TenantAuthMethodPolicy,
  User,
  UserInvitation
} from "./types";

export interface CreateProvisionedUserWithInvitationInput {
  invitation: UserInvitation;
  user: User;
}

export interface ActivateUserByInvitationTokenInput {
  createPasswordHash: () => Promise<string>;
  tokenHash: string;
  now: Date;
}

export type ActivateUserByInvitationTokenResult =
  | {
      kind: "activated";
      credential: PasswordCredential;
      invitation: UserInvitation;
      user: User;
    }
  | {
      kind: "not_found";
    }
  | {
      kind: "already_used";
    }
  | {
      kind: "expired";
    }
  | {
      kind: "user_disabled";
    }
  | {
      kind: "already_initialized";
    };

export interface UserRepository {
  activateUserByInvitationToken(
    input: ActivateUserByInvitationTokenInput
  ): Promise<ActivateUserByInvitationTokenResult>;
  createProvisionedUserWithInvitation(input: CreateProvisionedUserWithInvitationInput): Promise<void>;
  findAuthMethodPolicyByTenantId(tenantId: string): Promise<TenantAuthMethodPolicy | null>;
  findPasswordCredentialByUserId(
    tenantId: string,
    userId: string
  ): Promise<PasswordCredential | null>;
  findUserByEmail(tenantId: string, email: string): Promise<User | null>;
  findUserById(tenantId: string, userId: string): Promise<User | null>;
  findUserByUsername(tenantId: string, username: string): Promise<User | null>;
  listByTenantId(tenantId: string): Promise<User[]>;
  updateUser(user: User): Promise<void>;
  upsertPasswordCredential(credential: PasswordCredential): Promise<void>;
}
