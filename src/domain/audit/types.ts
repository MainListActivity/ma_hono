export type AuditEventType =
  | "admin.login.failed"
  | "admin.login.succeeded"
  | "user.magic_link.consumed"
  | "user.magic_link.requested"
  | "user.password_login.failed"
  | "user.password_login.succeeded"
  | "user.passkey.enrollment.failed"
  | "user.passkey.enrollment.succeeded"
  | "user.passkey.login.failed"
  | "user.passkey.login.succeeded"
  | "oidc.authorization.deferred"
  | "oidc.authorization.failed"
  | "oidc.authorization.succeeded"
  | "oidc.token.exchange.failed"
  | "oidc.token.exchange.succeeded"
  | "oidc.client.registered"
  | "oidc.client.token_profile.updated"
  | "tenant.created"
  | "user.activation.failed"
  | "user.activation.succeeded"
  | "user.provision.failed"
  | "user.provisioned"
  | (string & {});

export interface AuditEvent {
  id: string;
  actorType: string;
  actorId: string | null;
  tenantId: string | null;
  eventType: AuditEventType;
  targetType: string | null;
  targetId: string | null;
  payload: Record<string, unknown> | null;
  occurredAt: string;
}
