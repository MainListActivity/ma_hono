export type AuditEventType =
  | "admin.login.failed"
  | "admin.login.succeeded"
  | "oidc.authorization.deferred"
  | "oidc.authorization.failed"
  | "oidc.authorization.succeeded"
  | "oidc.token.exchange.failed"
  | "oidc.token.exchange.succeeded"
  | "oidc.client.registered"
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
