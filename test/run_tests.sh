#!/usr/bin/env bash
# test/run_tests.sh — openresty-base 功能验证脚本
# 用法：bash test/run_tests.sh [image]
# 默认镜像：ghcr.io/yorkane/openresty-base:latest

set -euo pipefail

IMAGE="${1:-ghcr.io/yorkane/openresty-base:latest}"
CONTAINER="or-test-$$"
PORT=8080
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0

# ── 颜色 ──────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓ PASS${NC}  $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}  ✗ FAIL${NC}  $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${CYAN}▶ $1${NC}"; }

# ── 启动容器 ──────────────────────────────────────────────────────────
cleanup() {
    docker rm -f "$CONTAINER" &>/dev/null || true
}
trap cleanup EXIT

info "Pulling / using image: $IMAGE"
docker pull "$IMAGE" --quiet

info "Starting container $CONTAINER on port $PORT ..."
docker run -d --name "$CONTAINER" \
    --platform linux/amd64 \
    -p "${PORT}:8080" \
    -v "${REPO_DIR}:/repo" \
    "$IMAGE" \
    openresty -g "daemon off;" -c /repo/test/conf/nginx.conf

# 等 nginx 就绪
sleep 2

BASE="http://localhost:${PORT}"

# ── 辅助函数 ──────────────────────────────────────────────────────────
assert_contains() {
    local desc="$1" url="$2" expect="$3"
    local body
    body=$(curl -sf "$url" 2>&1) || { fail "$desc (curl error)"; return; }
    if echo "$body" | grep -q "$expect"; then
        ok "$desc"
    else
        fail "$desc (expected '$expect', got: ${body:0:120})"
    fi
}

assert_http_status() {
    local desc="$1" method="$2" url="$3" expect_code="$4"
    shift 4
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$@" "$url")
    if [[ "$code" == "$expect_code" ]]; then
        ok "$desc (HTTP $code)"
    else
        fail "$desc (expected HTTP $expect_code, got $code)"
    fi
}

# ── 测试用例 ──────────────────────────────────────────────────────────
echo ""
info "=== 1. Lua 基础 ==="
assert_contains "lua content_by_lua_block"  "$BASE/hello" "hello from lua"
assert_contains "ngx_lua_version exposed"   "$BASE/hello" "ngx_lua_version="

echo ""
info "=== 2. cjson 内置库 ==="
assert_contains "cjson encode"              "$BASE/json"  '"status":"ok"'

echo ""
info "=== 3. resty.core 及常用 resty 库 ==="
assert_contains "resty.core"                "$BASE/core"  "resty.core: OK"
assert_contains "ngx.re"                    "$BASE/core"  "ngx.re: OK"
assert_contains "resty.lrucache"            "$BASE/core"  "resty.lrucache: OK"

echo ""
info "=== 4. LuaJIT FFI ==="
assert_contains "ffi load"                  "$BASE/ffi"   "ffi: OK"
assert_contains "ffi.arch amd64"            "$BASE/ffi"   "arch: x64"

echo ""
info "=== 5. FancyIndex 目录浏览 ==="
assert_contains "fancyindex HTML response"  "$BASE/files/"  "a.txt"
assert_contains "fancyindex table tag"      "$BASE/files/"  "<table"

echo ""
info "=== 6. WebDAV — OPTIONS ==="
assert_http_status "WebDAV OPTIONS 200"     OPTIONS "$BASE/dav/" 200

echo ""
info "=== 6. WebDAV — PUT 上传文件 ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: text/plain" --data "hello webdav" \
    "$BASE/dav/hello.txt")
if [[ "$code" == "201" || "$code" == "204" ]]; then
    ok "WebDAV PUT (HTTP $code)"
else
    fail "WebDAV PUT expected 201/204, got $code"
fi

echo ""
info "=== 6. WebDAV — PROPFIND ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -H "Depth: 1" "$BASE/dav/")
if [[ "$code" == "207" ]]; then
    ok "WebDAV PROPFIND (HTTP 207 Multi-Status)"
else
    fail "WebDAV PROPFIND expected 207, got $code"
fi

echo ""
info "=== 7. nginx error log (should be empty / warn only) ==="
ERR_LOG="${REPO_DIR}/test/logs/error.log"
if [[ -f "$ERR_LOG" ]]; then
    ERRORS=$(grep -c "\[error\]" "$ERR_LOG" || true)
    if [[ "$ERRORS" -eq 0 ]]; then
        ok "No [error] lines in error.log"
    else
        fail "Found $ERRORS [error] lines in error.log:"
        grep "\[error\]" "$ERR_LOG" | head -5
    fi
else
    ok "error.log not created (no warnings)"
fi

echo ""
info "=== 8. JWT / SSO 公共库 (resty.jwt + resty.noco_auth) ==="
assert_contains "resty.jwt 可用"            "$BASE/jwt"  "resty.jwt: OK"
assert_contains "resty.noco_auth 可用"      "$BASE/jwt"  "resty.noco_auth: OK"
assert_contains "HS256 签发并验证"          "$BASE/jwt"  "sign/verify: OK"
assert_contains "错误密钥应拒绝"            "$BASE/jwt"  "bad secret: rejected"
assert_contains "APISIX 格式 JWT 验证"      "$BASE/jwt"  "apisix-style token: OK"
assert_contains "noco_uid 3段解析"          "$BASE/jwt"  "noco_uid: authed/kate"

echo ""
info "=== 9. SSO authorize 自动跳转 ==="
# 9.1 无 cookie → 302 → signin_url
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/auth")
if [[ "$code" == "302" ]]; then
    ok "无 cookie → 302"
else
    fail "无 cookie 应 302，got $code"
fi
loc=$(curl -s -o /dev/null -w "%{redirect_url}" "$BASE/auth")
if [[ "$loc" == *"/login"* ]]; then
    ok "跳转 signin_url ($loc)"
else
    fail "应跳转 /login，got $loc"
fi

# 9.2 过期 token + noco_uid → 302 → sso_renew_url?url=...
b64url() { echo -n "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='; }
hs256() { echo -n "$1" | openssl dgst -sha256 -hmac "sso_key" -binary | base64 -w0 | tr '+/' '-_' | tr -d '='; }
EXPIRED_HDR=$(b64url '{"alg":"HS256","typ":"JWT"}')
EXPIRED_PAY=$(b64url '{"uid":1,"uname":"t","exp":1}')
EXPIRED_TOKEN="${EXPIRED_HDR}.${EXPIRED_PAY}.$(hs256 "${EXPIRED_HDR}.${EXPIRED_PAY}")"
code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Cookie: sso_ck=${EXPIRED_TOKEN}; noco_uid=req1-08170000" "$BASE/auth")
if [[ "$code" == "302" ]]; then
    ok "过期 token + noco_uid → 302"
else
    fail "过期 token 应 302，got $code"
fi
loc=$(curl -s -o /dev/null -w "%{redirect_url}" \
    -H "Cookie: sso_ck=${EXPIRED_TOKEN}; noco_uid=req1-08170000" "$BASE/auth")
if [[ "$loc" == *"/renew?url="* ]]; then
    ok "跳转 sso_renew_url 带回跳 ($loc)"
else
    fail "应跳转 /renew?url=，got $loc"
fi

# 9.3 有效 token → 200
VALID_HDR=$(b64url '{"alg":"HS256","typ":"JWT"}')
VALID_PAY=$(b64url "{\"uid\":7,\"uname\":\"bob\",\"exp\":$(date +%s)+3600}")
VALID_TOKEN="${VALID_HDR}.${VALID_PAY}.$(hs256 "${VALID_HDR}.${VALID_PAY}")"
body=$(curl -s -H "Cookie: sso_ck=${VALID_TOKEN}" "$BASE/auth")
if echo "$body" | grep -q "authorized uid=7"; then
    ok "有效 token 放行"
else
    fail "有效 token 应放行，got: $body"
fi

# ── 汇总 ──────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────"
TOTAL=$((PASS + FAIL))
echo -e "Results: ${GREEN}${PASS} passed${NC} / ${RED}${FAIL} failed${NC} / ${TOTAL} total"
echo "────────────────────────────────────────"

[[ "$FAIL" -eq 0 ]]
