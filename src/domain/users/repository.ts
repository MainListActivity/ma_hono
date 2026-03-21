import type {
  PasswordCredential,
  TenantAuthMethodPolicy,
  User,
  UserInvitation
} from "./types";

export interface ConsumeInvitationByTokenHashInput {
  tokenHash: string;
  now: Date;
}

export type ConsumeInvitationByTokenHashResult =
  | {
      kind: "consumed";
      invitation: UserInvitation;
    }
  | {
      kind: "not_found";
    }
  | {
      kind: "already_used";
    }
  | {
      kind: "expired";
    };

export interface UserRepository {
  consumeInvitationByTokenHash(
    input: ConsumeInvitationByTokenHashInput
  ): Promise<ConsumeInvitationByTokenHashResult>;
  createInvitation(invitation: UserInvitation): Promise<void>;
  createUser(user: User): Promise<void>;
  findAuthMethodPolicyByTenantId(tenantId: string): Promise<TenantAuthMethodPolicy | null>;
  findPasswordCredentialByUserId(
    tenantId: string,
    userId: string
  ): Promise<PasswordCredential | null>;
  findUserByEmail(tenantId: string, email: string): Promise<User | null>;
  findUserById(tenantId: string, userId: string): Promise<User | null>;
  findUserByUsername(tenantId: string, username: string): Promise<User | null>;
  updateUser(user: User): Promise<void>;
  upsertPasswordCredential(credential: PasswordCredential): Promise<void>;
}
