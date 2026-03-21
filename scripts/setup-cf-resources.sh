#!/usr/bin/env bash
# setup-cf-resources.sh
# 幂等地创建 Cloudflare 资源（D1、KV、R2），并将真实 ID 写入 wrangler.jsonc。
# 本地和 CI 通用，CI 需设置 CLOUDFLARE_API_TOKEN 环境变量。
set -euo pipefail

API_TOKEN_TMP="${CLOUDFLARE_API_TOKEN:-}"
ACCOUNT_ID_TMP="${CLOUDFLARE_ACCOUNT_ID:-}"
echo "=== Cloudflare Credentials ==="
echo "CLOUDFLARE_API_TOKEN 前3位: ${API_TOKEN_TMP:0:3}"
echo "CLOUDFLARE_ACCOUNT_ID 前3位: ${ACCOUNT_ID_TMP:0:3}"
echo "=============================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRANGLER_FILE="$SCRIPT_DIR/../wrangler.jsonc"

WORKER_NAME="ma-auth"
D1_NAME="ma-hono"
KV_NAMES=("ADMIN_SESSIONS_KV" "USER_SESSIONS_KV" "REGISTRATION_TOKENS_KV")

# --- D1 ---
echo "[D1] 查找或创建 $D1_NAME ..."
DATABASE_ID=$(npx wrangler d1 list --json 2>/dev/null | jq -r ".[] | select(.name==\"$D1_NAME\") | .uuid // empty")
if [ -z "$DATABASE_ID" ]; then
  echo "[D1] 不存在，创建中..."
  npx wrangler d1 create "$D1_NAME" > /dev/null
  DATABASE_ID=$(npx wrangler d1 list --json | jq -r ".[] | select(.name==\"$D1_NAME\") | .uuid")
fi
echo "[D1] DATABASE_ID=$DATABASE_ID"

# --- KV ---
declare -A KV_IDS
for KV_NAME in "${KV_NAMES[@]}"; do
  echo "[KV] 查找或创建 $KV_NAME ..."
  KV_ID=$(npx wrangler kv namespace list 2>/dev/null | jq -r ".[] | select(.title==\"$KV_NAME\") | .id // empty")
  if [ -z "$KV_ID" ]; then
    echo "[KV] 不存在，创建中..."
    npx wrangler kv namespace create "$KV_NAME" > /dev/null
    KV_ID=$(npx wrangler kv namespace list | jq -r ".[] | select(.title==\"$KV_NAME\") | .id")
  fi
  KV_IDS[$KV_NAME]=$KV_ID
  echo "[KV] ${KV_NAME}_ID=$KV_ID"
done

# --- 更新 wrangler.jsonc ---
echo "[config] 写入真实 ID 到 wrangler.jsonc ..."
sed -i.bak \
  -e "s|\"database_id\": \"[^\"]*\"|\"database_id\": \"$DATABASE_ID\"|" \
  -e "s|\"id\": \"replace-with-admin-sessions-kv-id\"|\"id\": \"${KV_IDS[ADMIN_SESSIONS_KV]}\"|" \
  -e "s|\"id\": \"replace-with-user-sessions-kv-id\"|\"id\": \"${KV_IDS[USER_SESSIONS_KV]}\"|" \
  -e "s|\"id\": \"replace-with-registration-tokens-kv-id\"|\"id\": \"${KV_IDS[REGISTRATION_TOKENS_KV]}\"|" \
  "$WRANGLER_FILE"
rm -f "${WRANGLER_FILE}.bak"
echo "[config] 完成，wrangler.jsonc 已更新"

# --- Apply D1 migrations ---
echo "[D1] Applying migrations ..."
npx wrangler d1 migrations apply "$D1_NAME" --remote
echo "[D1] Migrations applied"

npx wrangler deploy
