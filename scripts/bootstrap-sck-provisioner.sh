#!/usr/bin/env bash
# bootstrap-sck-provisioner.sh
# 幂等保证 IdP 里存在一个 active 的 provision service principal（默认 label
# `sck-provisioner`），并把 token 注入消费侧 surreal_ck 的生产环境 secret
# `ORIGIN_ENV_IDP_PROVISION_TOKEN`。
#
# 信任根 = 部署通道本身：本脚本挂在 deploy.yml 迁移之后运行，wrangler 已持
# D1 operator 级权限，不要求人工签发。日常轮换不走这里——轮换用 ops broker
# 的 ops_idp_provision_rotate（吊销旧→签新→注入产品密封仓→双探针），密封仓
# 取值优先于本脚本维护的 env 兜底。
#
# 语义：
#   - 存在任何 active principal → 跳过（不新增、不触碰既有凭证）。
#   - 无 active 且 SCK_REPO_TOKEN 未配置 → 告警跳过，部署不失败；
#     配置后下次部署自动补建。
#   - 无 active 且注入通道可用 → mint + 写 D1（只存 sha256）+ gh secret set；
#     注入失败立即补偿吊销刚建的 principal，保持「active ⇒ token 已送达」。
#
# 环境变量：
#   CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID  wrangler D1 访问（deploy 同款）
#   SCK_REPO_TOKEN        可写 surreal_ck secrets 的 GitHub token（缺省则只读检查）
#   D1_NAME               默认 ma-hono
#   SCK_REPO              默认 MainListActivity/surreal_ck
#   SCK_ENV               默认 production
#   PROVISION_LABEL       默认 sck-provisioner

set -euo pipefail
set +x

D1_NAME="${D1_NAME:-ma-hono}"
SCK_REPO="${SCK_REPO:-MainListActivity/surreal_ck}"
SCK_ENV="${SCK_ENV:-production}"
PROVISION_LABEL="${PROVISION_LABEL:-sck-provisioner}"
SECRET_NAME="ORIGIN_ENV_IDP_PROVISION_TOKEN"
SCOPES_JSON='["tenant.read","user.read","user.provision"]'
ACTOR="deploy:ma_hono-pipeline"

log() { echo "[bootstrap] $*"; }

TOKEN=""
cleanup() { TOKEN=""; }
trap cleanup EXIT

d1() {
  pnpm exec wrangler d1 execute "$D1_NAME" --remote --json --command "$1"
}

if [ -z "${CLOUDFLARE_API_TOKEN:-}" ] || [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
  log "缺少 CLOUDFLARE_API_TOKEN/CLOUDFLARE_ACCOUNT_ID，跳过 bootstrap"
  exit 0
fi

# --- 1. active principal 盘点（任何 label 都算，避免凭证繁殖） ---
RESP=$(d1 "SELECT id, label, created_by FROM admin_service_principals WHERE status='active'") || {
  log "[error] 查询 admin_service_principals 失败（迁移 0014 未应用？）"
  exit 1
}
if ! jq -e '.[0].success == true' <<<"$RESP" >/dev/null 2>&1; then
  log "[error] D1 查询未成功：$(jq -rc '.[0].error // .[0]' <<<"$RESP" 2>/dev/null || echo "$RESP" | head -c 300)"
  exit 1
fi
ACTIVE_COUNT=$(jq '[.[0].results[]?] | length' <<<"$RESP")
if [ "$ACTIVE_COUNT" -gt 0 ]; then
  log "已有 ${ACTIVE_COUNT} 个 active principal（$(jq -rc '[.[0].results[].id] | join(", ")' <<<"$RESP")），跳过"
  exit 0
fi

# --- 2. 需要 mint：先确认注入通道，避免建出无法送达的凭证 ---
if [ -z "${SCK_REPO_TOKEN:-}" ]; then
  log "[warn] 无 active principal 但 SCK_REPO_TOKEN 未配置，跳过 mint"
  log "       为 ${SCK_REPO} 配置该 secret 后下次部署自动补建；"
  log "       或用 ops_idp_provision_rotate 走密封仓通道。"
  exit 0
fi

# --- 3. mint（与 mintServicePrincipalToken 同构：32B base64url，只存 sha256） ---
CREDS=$(node -e '
  const c = require("crypto");
  const token = c.randomBytes(32).toString("base64url");
  console.log(JSON.stringify({
    token,
    hash: c.createHash("sha256").update(token).digest("base64url"),
    id: c.randomUUID(),
    auditId: c.randomUUID(),
    now: new Date().toISOString()
  }));
')
ID=$(jq -r .id <<<"$CREDS")
HASH=$(jq -r .hash <<<"$CREDS")
NOW=$(jq -r .now <<<"$CREDS")
AUDIT_ID=$(jq -r .auditId <<<"$CREDS")
TOKEN=$(jq -r .token <<<"$CREDS")
CREDS=""

# --- 4. 写 principal 行 + 审计（明文从不进 SQL，只写 hash） ---
d1 "INSERT INTO admin_service_principals (id, label, token_hash, scopes, status, created_at, revoked_at, created_by) VALUES ('${ID}', '${PROVISION_LABEL}', '${HASH}', '${SCOPES_JSON}', 'active', '${NOW}', NULL, '${ACTOR}')" >/dev/null
d1 "INSERT INTO audit_events (id, actor_type, actor_id, tenant_id, event_type, target_type, target_id, payload, occurred_at) VALUES ('${AUDIT_ID}', 'management_token', '${ACTOR}', NULL, 'admin.service_principal.minted', 'service_principal', '${ID}', '{\"label\":\"${PROVISION_LABEL}\",\"scopes\":${SCOPES_JSON},\"via\":\"deploy-pipeline\"}', '${NOW}')" >/dev/null \
  || log "[warn] 审计行写入失败（不阻断；principal ${ID} 已建）"
log "已创建 principal ${ID}（label=${PROVISION_LABEL}）"

# --- 5. 注入消费侧 env secret（stdin 传递，值不回显） ---
if printf '%s' "$TOKEN" | GH_TOKEN="$SCK_REPO_TOKEN" gh secret set "$SECRET_NAME" --repo "$SCK_REPO" --env "$SCK_ENV" 2>/dev/null; then
  log "已注入 ${SCK_REPO}/${SCK_ENV} ${SECRET_NAME}"
else
  log "[error] gh secret set 失败，补偿吊销 ${ID}"
  d1 "UPDATE admin_service_principals SET status='revoked', revoked_at='$(date -u +%Y-%m-%dT%H:%M:%S.000Z)' WHERE id='${ID}'" >/dev/null || true
  exit 1
fi
