export type AuditEventType =
  | "admin.login.failed"
  | "admin.login.succeeded"
  | "oidc.authorization.failed"
  | "oidc.authorization.succeeded"
  | "oidc.client.registered"
  | "tenant.created"
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
