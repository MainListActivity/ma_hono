import type { AuditEvent } from "./types";

export interface AuditRepository {
  record(event: AuditEvent): Promise<void>;
}
