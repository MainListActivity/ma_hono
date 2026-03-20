export interface AuditEvent {
  id: string;
  actorType: string;
  actorId: string | null;
  tenantId: string | null;
  eventType: string;
  targetType: string | null;
  targetId: string | null;
  payload: Record<string, unknown> | null;
  occurredAt: string;
}
