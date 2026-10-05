// fake-d1.mjs —— 测试用 D1 假件：从环境变量 FAKE_D1_STATE 指定的 JSON 文件
// 读写 admin_service_principals / audit_events，仅覆盖 bootstrap 脚本用到的
// 四类语句（SELECT active / INSERT principal / INSERT audit / UPDATE revoke）。
// 输出 wrangler d1 execute --remote --json 的形状：[{ success, results }].
import { readFileSync, writeFileSync } from "node:fs";

const statePath = process.env.FAKE_D1_STATE;
const sql = process.argv[2] ?? "";
const state = JSON.parse(readFileSync(statePath, "utf8"));
state.admin_service_principals ??= [];
state.audit_events ??= [];

const sqlValues = (text) => {
  const m = text.match(/VALUES\s*\((.*)\)\s*;?\s*$/is);
  if (!m) return [];
  const tokens = [];
  const re = /'((?:[^']|'')*)'|NULL/g;
  let match;
  while ((match = re.exec(m[1])) !== null) {
    tokens.push(match[1] === undefined ? null : match[1].replaceAll("''", "'"));
  }
  return tokens;
};

const emit = (results) => {
  process.stdout.write(JSON.stringify([{ success: true, results, meta: {} }]));
};

if (/SELECT .* FROM admin_service_principals WHERE status='active'/i.test(sql)) {
  emit(state.admin_service_principals.filter((p) => p.status === "active")
    .map((p) => ({ id: p.id, label: p.label, created_by: p.created_by })));
} else if (/INSERT INTO admin_service_principals/i.test(sql)) {
  const [id, label, token_hash, scopes, status, created_at, , created_by] = sqlValues(sql);
  state.admin_service_principals.push({ id, label, token_hash, scopes, status, created_at, revoked_at: null, created_by });
  emit([]);
} else if (/INSERT INTO audit_events/i.test(sql)) {
  const [id, actor_type, actor_id, , event_type, target_type, target_id, payload, occurred_at] = sqlValues(sql);
  state.audit_events.push({ id, actor_type, actor_id, event_type, target_type, target_id, payload, occurred_at });
  emit([]);
} else if (/UPDATE admin_service_principals SET status='revoked'/i.test(sql)) {
  const id = sql.match(/WHERE id='([^']+)'/i)?.[1];
  const revokedAt = sql.match(/revoked_at='([^']+)'/i)?.[1] ?? null;
  for (const p of state.admin_service_principals) {
    if (p.id === id) {
      p.status = "revoked";
      p.revoked_at = revokedAt;
    }
  }
  emit([]);
} else {
  process.stdout.write(JSON.stringify([{ success: false, error: `unsupported SQL: ${sql}` }]));
  process.exit(1);
}

writeFileSync(statePath, JSON.stringify(state));
