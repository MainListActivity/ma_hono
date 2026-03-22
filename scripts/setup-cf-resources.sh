#!/usr/bin/env bash
# setup-cf-resources.sh
# 幂等地创建 Cloudflare 资源（D1、KV、R2、Pages、Worker 路由），并将真实 ID 写入 wrangler.jsonc。
# 本地和 CI 通用，CI 需设置 CLOUDFLARE_API_TOKEN 和 CLOUDFLARE_ACCOUNT_ID 环境变量。
#
# 部署拓扑：
#   auth.{ROOT_DOMAIN}        → Cloudflare Pages（admin + 租户登录 SPA）
#   auth.{ROOT_DOMAIN}/api/*  → Worker 路由（覆盖 Pages，处理所有 Hono API）
#   o.{ROOT_DOMAIN}/*         → Worker 路由（OIDC 协议端点专用子域名）
#
# ROOT_DOMAIN 优先级：
#   1. 环境变量 ROOT_DOMAIN（GitHub Actions variable 或本地设置）
#   2. Cloudflare 账号下的第一个已激活 Zone 的域名

set -euo pipefail

API_TOKEN_TMP="${CLOUDFLARE_API_TOKEN:-}"
ACCOUNT_ID_TMP="${CLOUDFLARE_ACCOUNT_ID:-}"
echo "=== Cloudflare Credentials ==="
echo "CLOUDFLARE_API_TOKEN 前3位: ${API_TOKEN_TMP:0:3}"
echo "CLOUDFLARE_ACCOUNT_ID 前3位: ${ACCOUNT_ID_TMP:0:3}"
echo "=============================="

if [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
  echo "[error] CLOUDFLARE_ACCOUNT_ID 未设置" >&2
  exit 1
fi
if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  echo "[error] CLOUDFLARE_API_TOKEN 未设置" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRANGLER_FILE="$SCRIPT_DIR/../wrangler.jsonc"

WORKER_NAME="ma-auth"
PAGES_PROJECT="ma-hono-admin"
D1_NAME="ma-hono"
KV_NAMES=("ADMIN_SESSIONS_KV" "USER_SESSIONS_KV" "REGISTRATION_TOKENS_KV")

# --- 解析 ROOT_DOMAIN ---
echo "[domain] 解析根域名 ..."
if [ -n "${ROOT_DOMAIN:-}" ]; then
  echo "[domain] 使用环境变量 ROOT_DOMAIN=$ROOT_DOMAIN"
else
  echo "[domain] ROOT_DOMAIN 未设置，从 Cloudflare 账号获取第一个已激活 Zone ..."
  ROOT_DOMAIN=$(curl -s \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    "https://api.cloudflare.com/client/v4/zones?account.id=$CLOUDFLARE_ACCOUNT_ID&status=active&per_page=1" \
    | jq -r '.result[0].name // empty')
  if [ -z "$ROOT_DOMAIN" ]; then
    echo "[error] 无法从 Cloudflare 获取域名，请手动设置 ROOT_DOMAIN 环境变量" >&2
    exit 1
  fi
  echo "[domain] 自动检测到 ROOT_DOMAIN=$ROOT_DOMAIN"
fi

AUTH_DOMAIN="auth.${ROOT_DOMAIN}"
OIDC_DOMAIN="o.${ROOT_DOMAIN}"
echo "[domain] AUTH_DOMAIN=$AUTH_DOMAIN"
echo "[domain] OIDC_DOMAIN=$OIDC_DOMAIN"

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

# --- 更新 wrangler.jsonc 中的 Worker 路由域名占位符 ---
echo "[config] 更新 wrangler.jsonc 路由域名占位符 ..."
sed -i.bak \
  -e "s|auth\.REPLACE_WITH_ROOT_DOMAIN|${AUTH_DOMAIN}|g" \
  -e "s|o\.REPLACE_WITH_ROOT_DOMAIN|${OIDC_DOMAIN}|g" \
  -e "s|REPLACE_WITH_ROOT_DOMAIN|${ROOT_DOMAIN}|g" \
  "$WRANGLER_FILE"
rm -f "${WRANGLER_FILE}.bak"
echo "[config] 路由域名已更新为 AUTH_DOMAIN=${AUTH_DOMAIN}, OIDC_DOMAIN=${OIDC_DOMAIN}"

# --- Apply D1 migrations ---
echo "[D1] Applying migrations ..."
npx wrangler d1 migrations apply "$D1_NAME" --remote
echo "[D1] Migrations applied"

# --- Deploy Worker ---
echo "[Worker] 部署 Worker ..."
npx wrangler deploy
echo "[Worker] 部署完成"

# --- 配置 Worker 路由 ---
# Worker 路由让 auth.{domain}/api/* 和 o.{domain}/* 优先于 Pages
echo "[routes] 配置 Worker 路由 ..."

CF_API="https://api.cloudflare.com/client/v4"

# 获取 ROOT_DOMAIN 对应的 Zone ID
ZONE_ID=$(curl -s \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones?name=$ROOT_DOMAIN&account.id=$CLOUDFLARE_ACCOUNT_ID" \
  | jq -r '.result[0].id // empty')

if [ -z "$ZONE_ID" ]; then
  echo "[warn] 未找到 $ROOT_DOMAIN 对应的 Zone，跳过路由配置。请确保域名已托管在此 Cloudflare 账号下。"
else
  echo "[routes] Zone ID=$ZONE_ID"

  # 获取已部署 Worker 的 script name（即 WORKER_NAME）
  configure_worker_route() {
    local PATTERN="$1"
    local DESCRIPTION="$2"
    echo "[routes] 配置路由: $PATTERN ..."
    # 检查是否已存在
    EXISTING=$(curl -s \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      "$CF_API/zones/$ZONE_ID/workers/routes" \
      | jq -r ".result[] | select(.pattern==\"$PATTERN\") | .id // empty")
    if [ -z "$EXISTING" ]; then
      RESULT=$(curl -s -X POST \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"pattern\": \"$PATTERN\", \"script\": \"$WORKER_NAME\"}" \
        "$CF_API/zones/$ZONE_ID/workers/routes")
      SUCCESS=$(echo "$RESULT" | jq -r '.success')
      if [ "$SUCCESS" = "true" ]; then
        echo "[routes] $DESCRIPTION 路由已创建: $PATTERN"
      else
        echo "[warn] $DESCRIPTION 路由创建失败: $(echo "$RESULT" | jq -r '.errors')"
      fi
    else
      echo "[routes] $DESCRIPTION 路由已存在: $PATTERN (id=$EXISTING)"
    fi
  }

  configure_worker_route "${AUTH_DOMAIN}/api/*" "API (auth subdomain)"
  configure_worker_route "${OIDC_DOMAIN}/*" "OIDC protocol (o subdomain)"
fi

# --- 创建或更新 Cloudflare Pages 项目 ---
echo "[Pages] 检查 Pages 项目 $PAGES_PROJECT ..."
PAGES_EXISTS=$(curl -s \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "$CF_API/accounts/$CLOUDFLARE_ACCOUNT_ID/pages/projects/$PAGES_PROJECT" \
  | jq -r '.result.name // empty')

if [ -z "$PAGES_EXISTS" ]; then
  echo "[Pages] 项目不存在，创建 $PAGES_PROJECT ..."
  curl -s -X POST \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"$PAGES_PROJECT\",
      \"production_branch\": \"main\",
      \"build_config\": {
        \"build_command\": \"pnpm build\",
        \"destination_dir\": \"dist\",
        \"root_dir\": \"admin\"
      }
    }" \
    "$CF_API/accounts/$CLOUDFLARE_ACCOUNT_ID/pages/projects" > /dev/null
  echo "[Pages] 项目已创建"
else
  echo "[Pages] 项目已存在: $PAGES_PROJECT"
fi

# --- 配置 Pages 自定义域名 ---
if [ -n "$ZONE_ID" ]; then
  echo "[Pages] 检查自定义域名 $AUTH_DOMAIN ..."
  DOMAIN_EXISTS=$(curl -s \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    "$CF_API/accounts/$CLOUDFLARE_ACCOUNT_ID/pages/projects/$PAGES_PROJECT/domains" \
    | jq -r ".result[] | select(.name==\"$AUTH_DOMAIN\") | .name // empty")

  if [ -z "$DOMAIN_EXISTS" ]; then
    echo "[Pages] 添加自定义域名 $AUTH_DOMAIN ..."
    DOMAIN_RESULT=$(curl -s -X POST \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"name\": \"$AUTH_DOMAIN\"}" \
      "$CF_API/accounts/$CLOUDFLARE_ACCOUNT_ID/pages/projects/$PAGES_PROJECT/domains")
    DOMAIN_SUCCESS=$(echo "$DOMAIN_RESULT" | jq -r '.success')
    if [ "$DOMAIN_SUCCESS" = "true" ]; then
      echo "[Pages] 自定义域名已添加: $AUTH_DOMAIN"
    else
      echo "[warn] 自定义域名添加失败: $(echo "$DOMAIN_RESULT" | jq -r '.errors')"
    fi
  else
    echo "[Pages] 自定义域名已存在: $AUTH_DOMAIN"
  fi
fi

echo ""
echo "=== 部署完成 ==="
echo "  Pages SPA (admin + 租户登录): https://$AUTH_DOMAIN"
echo "  Worker API:                    https://$AUTH_DOMAIN/api/*"
echo "  Worker OIDC 协议:              https://$OIDC_DOMAIN/t/{tenant}/*"
echo ""
echo "  首次访问后，请完成 Setup Wizard 配置平台参数。"
echo "  Setup Wizard 完成后将重定向至 https://$AUTH_DOMAIN/"
