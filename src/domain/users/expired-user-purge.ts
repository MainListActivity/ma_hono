import type { AuditRepository } from "../audit/repository";

/** 到期测试账号清理端口：列出并级联删除。 */
export interface ExpiredUserPurger {
  listExpiredUserIds(nowIso: string, limit: number): Promise<{ id: string; tenantId: string; testOrigin: string | null }[]>;
  deleteUserCascade(tenantId: string, userId: string): Promise<void>;
}

export const PURGE_BATCH_LIMIT = 200;

/** expires_at 非空且已到期的用户视为不可用（等价于被禁用，但不泄露原因）。 */
export const isUserExpired = (
  user: { expiresAt?: string | null },
  now: Date
): boolean => user.expiresAt != null && Date.parse(user.expiresAt) <= now.getTime();


export const purgeExpiredTestUsers = async ({
  auditRepository,
  now = new Date(),
  purger
}: {
  auditRepository: AuditRepository;
  now?: Date;
  purger: ExpiredUserPurger;
}): Promise<{ purged: number; failed: number }> => {
  const nowIso = now.toISOString();
  const expired = await purger.listExpiredUserIds(nowIso, PURGE_BATCH_LIMIT);
  let purged = 0;
  let failed = 0;

  for (const user of expired) {
    try {
      await purger.deleteUserCascade(user.tenantId, user.id);
      purged += 1;
    } catch (error) {
      failed += 1;
      console.error("[remote-grant] failed to purge expired test user", {
        userId: user.id,
        message: error instanceof Error ? error.message : String(error)
      });
    }

    try {
      await auditRepository.record({
        id: crypto.randomUUID(),
        actorType: "system",
        actorId: null,
        tenantId: user.tenantId,
        eventType: "user.expired_purged",
        targetType: "user",
        targetId: user.id,
        payload: {
          user_id: user.id,
          test_origin: user.testOrigin,
          ...(failed > 0 ? { failed: true } : {})
        },
        occurredAt: nowIso
      });
    } catch {
      // 审计失败不阻塞清理。
    }
  }

  return { purged, failed };
};
