import type {
  ConsumeInvitationByTokenHashInput,
  ConsumeInvitationByTokenHashResult,
  UserRepository
} from "../../../domain/users/repository";
import type {
  PasswordCredential,
  TenantAuthMethodPolicy,
  User,
  UserInvitation
} from "../../../domain/users/types";

export class MemoryUserRepository implements UserRepository {
  private readonly invitations: UserInvitation[];
  private readonly passwordCredentials: PasswordCredential[];
  private readonly policies: TenantAuthMethodPolicy[];
  private readonly users: User[];

  constructor({
    invitations = [],
    passwordCredentials = [],
    policies = [],
    users = []
  }: {
    invitations?: UserInvitation[];
    passwordCredentials?: PasswordCredential[];
    policies?: TenantAuthMethodPolicy[];
    users?: User[];
  } = {}) {
    this.invitations = [...invitations];
    this.passwordCredentials = [...passwordCredentials];
    this.policies = [...policies];
    this.users = [...users];
  }

  async createInvitation(invitation: UserInvitation): Promise<void> {
    this.invitations.push(invitation);
  }

  async consumeInvitationByTokenHash({
    now,
    tokenHash
  }: ConsumeInvitationByTokenHashInput): Promise<ConsumeInvitationByTokenHashResult> {
    const index = this.invitations.findIndex((invitation) => invitation.tokenHash === tokenHash);

    if (index === -1) {
      return {
        kind: "not_found"
      };
    }

    const invitation = this.invitations[index];

    if (invitation === undefined) {
      return {
        kind: "not_found"
      };
    }

    if (invitation.consumedAt !== null) {
      return {
        kind: "already_used"
      };
    }

    if (new Date(invitation.expiresAt).getTime() <= now.getTime()) {
      return {
        kind: "expired"
      };
    }

    const consumedInvitation: UserInvitation = {
      ...invitation,
      consumedAt: now.toISOString()
    };

    this.invitations[index] = consumedInvitation;

    return {
      kind: "consumed",
      invitation: consumedInvitation
    };
  }

  async createUser(user: User): Promise<void> {
    if (this.users.some((storedUser) => storedUser.tenantId === user.tenantId && storedUser.email === user.email)) {
      throw new Error(`user email already exists for tenant: ${user.tenantId}`);
    }

    if (
      user.username !== null &&
      this.users.some(
        (storedUser) => storedUser.tenantId === user.tenantId && storedUser.username === user.username
      )
    ) {
      throw new Error(`username already exists for tenant: ${user.tenantId}`);
    }

    this.users.push(user);
  }

  async findAuthMethodPolicyByTenantId(tenantId: string): Promise<TenantAuthMethodPolicy | null> {
    return this.policies.find((policy) => policy.tenantId === tenantId) ?? null;
  }

  async findPasswordCredentialByUserId(
    tenantId: string,
    userId: string
  ): Promise<PasswordCredential | null> {
    return (
      this.passwordCredentials.find(
        (credential) => credential.tenantId === tenantId && credential.userId === userId
      ) ?? null
    );
  }

  async findUserByEmail(tenantId: string, email: string): Promise<User | null> {
    return this.users.find((user) => user.tenantId === tenantId && user.email === email) ?? null;
  }

  async findUserById(tenantId: string, userId: string): Promise<User | null> {
    return this.users.find((user) => user.tenantId === tenantId && user.id === userId) ?? null;
  }

  async findUserByUsername(tenantId: string, username: string): Promise<User | null> {
    return this.users.find((user) => user.tenantId === tenantId && user.username === username) ?? null;
  }

  listInvitations(): UserInvitation[] {
    return [...this.invitations];
  }

  listUsers(): User[] {
    return [...this.users];
  }

  async updateUser(user: User): Promise<void> {
    const index = this.users.findIndex(
      (storedUser) => storedUser.tenantId === user.tenantId && storedUser.id === user.id
    );

    if (index === -1) {
      throw new Error(`user not found: ${user.id}`);
    }

    this.users[index] = user;
  }

  async upsertPasswordCredential(credential: PasswordCredential): Promise<void> {
    const index = this.passwordCredentials.findIndex(
      (storedCredential) =>
        storedCredential.tenantId === credential.tenantId && storedCredential.userId === credential.userId
    );

    if (index === -1) {
      this.passwordCredentials.push(credential);
      return;
    }

    this.passwordCredentials[index] = credential;
  }
}
