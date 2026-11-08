import type { ExpiredUserPurger } from "../../src/domain/users/expired-user-purge";

export class MemoryExpiredUserPurgerFake implements ExpiredUserPurger {
  private users: { id: string; tenantId: string; testOrigin: string | null; expiresAt: string | null }[] = [];
  private deleted = new Set<string>();

  add(u: { id: string; tenantId: string; testOrigin: string | null; expiresAt: string | null }) { this.users.push(u); }
  has(id: string) { return this.users.some(u => u.id === id); }
  deletedFor(id: string) { return this.deleted.has(id); }

  async listExpiredUserIds(nowIso: string, limit: number) {
    return this.users
      .filter(u => u.expiresAt != null && Date.parse(u.expiresAt) <= Date.parse(nowIso))
      .slice(0, limit)
      .map(u => ({ id: u.id, tenantId: u.tenantId, testOrigin: u.testOrigin }));
  }
  async deleteUserCascade(_t: string, userId: string) {
    this.users = this.users.filter(u => u.id !== userId);
    this.deleted.add(userId);
  }
}

export async function purgeExpiredTestUsersFake(
  purger: ExpiredUserPurger,
  audits: { eventType: string; payload: unknown }[],
  nowIso: string
) {
  const { purgeExpiredTestUsers } = await import("../../src/domain/users/expired-user-purge");
  return purgeExpiredTestUsers({
    auditRepository: { record: async (e) => { audits.push({ eventType: e.eventType, payload: e.payload }); } },
    purger,
    now: new Date(nowIso)
  });
}
