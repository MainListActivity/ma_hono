import type { AuditRepository } from "../../../domain/audit/repository";
import type { AuditEvent } from "../../../domain/audit/types";

export class MemoryAuditRepository implements AuditRepository {
  private readonly events: AuditEvent[];

  constructor(initialEvents: AuditEvent[] = []) {
    this.events = [...initialEvents];
  }

  async record(event: AuditEvent): Promise<void> {
    this.events.push(event);
  }

  listEvents(): AuditEvent[] {
    return [...this.events];
  }
}
