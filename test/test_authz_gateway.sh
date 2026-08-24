#!/usr/bin/env bash
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${OPENRESTY_TEST_IMAGE:-ghcr.io/yorkane/openresty-base:latest}
CONTAINER_NAME="authz-gateway-test-$$"
TMP_DIR=$(mktemp -d)
PASS=0
MOCK_PID=""
NOCO_PID=""
WS_PID=""

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

HTTP_PORT=$(free_port)
HTTPS_PORT=$(free_port)
UPSTREAM_PORT=$(free_port)
NOCO_PORT=$(free_port)
WS_PORT=$(free_port)
DYNAMIC_HOST="${UPSTREAM_PORT}-dynamic.test.example"
POLICY_OBJECT="/${UPSTREAM_PORT}/*"

cleanup() {
    docker exec "$CONTAINER_NAME" chmod -R a+rwx /data >/dev/null 2>&1 || true
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    if [[ -n "$MOCK_PID" ]]; then kill "$MOCK_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "$NOCO_PID" ]]; then kill "$NOCO_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "$WS_PID" ]]; then kill "$WS_PID" >/dev/null 2>&1 || true; fi
    rm -rf "$TMP_DIR" || true
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    [[ -f "$TMP_DIR/body" ]] && cat "$TMP_DIR/body" >&2 || true
    [[ -f "$TMP_DIR/nocobase.log" ]] && tail -n 40 "$TMP_DIR/nocobase.log" >&2 || true
    docker logs "$CONTAINER_NAME" 2>&1 | tail -n 100 >&2 || true
    exit 1
}

pass() {
    PASS=$((PASS + 1))
    printf 'PASS: %s\n' "$1"
}

assert_eq() {
    local name=$1 actual=$2 expected=$3
    [[ "$actual" == "$expected" ]] || fail "$name (expected '$expected', got '$actual')"
    pass "$name"
}

assert_contains() {
    local name=$1 actual=$2 expected=$3
    [[ "$actual" == *"$expected"* ]] || fail "$name (missing '$expected')"
    pass "$name"
}

assert_not_contains() {
    local name=$1 actual=$2 unexpected=$3
    [[ "$actual" != *"$unexpected"* ]] || fail "$name (unexpected '$unexpected')"
    pass "$name"
}

assert_json() {
    local name=$1 filter=$2 expected=$3 actual
    actual=$(jq -er "$filter" "$TMP_DIR/body") || fail "$name (invalid JSON or filter)"
    assert_eq "$name" "$actual" "$expected"
}

python3 "$REPO_DIR/test/mock_http.py" "$UPSTREAM_PORT" >"$TMP_DIR/mock.log" 2>&1 &
MOCK_PID=$!
python3 "$REPO_DIR/test/mock_nocobase.py" "$NOCO_PORT" \
    "http://admin.test.example:$HTTP_PORT/_authz/oauth/callback" >"$TMP_DIR/nocobase.log" 2>&1 &
NOCO_PID=$!
python3 "$REPO_DIR/test/mock_websocket.py" "$WS_PORT" >"$TMP_DIR/websocket.log" 2>&1 &
WS_PID=$!
for _ in $(seq 1 30); do
    curl -fsS --max-time 1 "http://127.0.0.1:$UPSTREAM_PORT/" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -fsS --max-time 2 "http://127.0.0.1:$UPSTREAM_PORT/" >/dev/null || fail "mock upstream did not start"
MOCK_BODY=$(curl -fsS --max-time 2 "http://127.0.0.1:$UPSTREAM_PORT/")
for _ in $(seq 1 30); do
    STATUS=$(curl -sS --max-time 1 -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:$NOCO_PORT/api/auth:check" 2>/dev/null || true)
    [[ "$STATUS" == "401" ]] && break
    sleep 0.1
done
[[ "$STATUS" == "401" ]] || fail "mock NocoBase did not start"

OPENRESTY_BUILD_ARGS=$(docker run --rm "$IMAGE" openresty -V 2>&1)
assert_contains "OpenResty includes Brotli module" "$OPENRESTY_BUILD_ARGS" "--add-module=/tmp/ngx_brotli"
docker run --rm "$IMAGE" sh -c \
    'test -s /usr/local/openresty/nginx/html/admin/api.js.br' \
    || fail "image does not contain Brotli static sidecar"
pass "admin assets have Brotli static sidecars"
docker run --rm "$IMAGE" sh -c \
    'test -s /usr/local/openresty/site/lualib/resty/mlcache.lua' \
    || fail "image does not contain vendored lua-resty-mlcache"
pass "lua-resty-mlcache is vendored in the image"

SERVER_TEMPLATE=$(cat "$REPO_DIR/conf/server.conf.template")
assert_eq "HTTP and HTTPS share server template" \
    "$(grep -c 'include server.conf.template;' "$REPO_DIR/conf/nginx.conf.template")" "2"
assert_contains "WebSocket origin host forwarding" "$SERVER_TEMPLATE" \
    'proxy_set_header X-Forwarded-Host  $authz_forwarded_host;'
assert_contains "upstream Host uses local proxy target" "$SERVER_TEMPLATE" \
    'proxy_set_header Host              $proxy_host;'
assert_not_contains "upstream Host does not expose public domain" "$SERVER_TEMPLATE" \
    'proxy_set_header Host              $host;'
assert_contains "WebSocket buffering disabled" "$SERVER_TEMPLATE" 'proxy_buffering off;'
assert_contains "WebSocket idle timeout extended" "$SERVER_TEMPLATE" 'proxy_read_timeout 3600s;'
AUTHZ_INIT_SOURCE=$(cat "$REPO_DIR/lualib/resty/authz/init.lua")
assert_contains "gateway always uses HTTP upstream" "$AUTHZ_INIT_SOURCE" \
    'ngx.var.authz_target = "http://127.0.0.1:" .. port'
assert_not_contains "gateway does not derive upstream scheme from listener" "$AUTHZ_INIT_SOURCE" \
    'ngx.var.scheme .. "://127.0.0.1:" .. port'
NGINX_TEMPLATE=$(cat "$REPO_DIR/conf/nginx.conf.template")
assert_contains "database cache shared dictionary configured" "$NGINX_TEMPLATE" \
    'lua_shared_dict authz_db_cache 10m;'

cat >"$TMP_DIR/nocobase.env" <<EOF
AUTHZ_HOST_URL=http://admin.test.example:$HTTP_PORT
AUTHZ_NOCO_URL=http://127.0.0.1:$NOCO_PORT
AUTHZ_NOCO_API_KEY=registration-api-key
AUTHZ_NOCO_OAUTH_ENABLED=false
AUTHZ_NOCO_OAUTH_CLIENT_ID=noco-client
AUTHZ_NOCO_OAUTH_CLIENT_SECRET=noco-secret
EOF
python3 "$REPO_DIR/scripts/register_nocobase_oauth.py" \
    --allow-http --env-file "$TMP_DIR/nocobase.env" >/dev/null || fail "NocoBase OAuth registration failed"
assert_eq "NocoBase OAuth registration enables provider" \
    "$(grep '^AUTHZ_NOCO_OAUTH_ENABLED=' "$TMP_DIR/nocobase.env")" "AUTHZ_NOCO_OAUTH_ENABLED=true"
assert_eq "NocoBase OAuth registration writes exact callback" \
    "$(grep '^AUTHZ_NOCO_OAUTH_REDIRECT_URI=' "$TMP_DIR/nocobase.env")" \
    "AUTHZ_NOCO_OAUTH_REDIRECT_URI=http://admin.test.example:$HTTP_PORT/_authz/oauth/callback"
python3 "$REPO_DIR/scripts/register_nocobase_oauth.py" \
    --allow-http --env-file "$TMP_DIR/nocobase.env" >/dev/null || fail "NocoBase OAuth registration is not idempotent"
pass "NocoBase OAuth registration reuses existing client"

mkdir -p "$TMP_DIR/data/authz"
python3 - "$TMP_DIR/data/authz/authz.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("""CREATE TABLE users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    roles TEXT NOT NULL DEFAULT 'user',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
)""")
connection.execute("""CREATE TABLE sessions(
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL
)""")
connection.execute("""CREATE TABLE remote_users(
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    roles TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    synced_at INTEGER NOT NULL,
    PRIMARY KEY(provider, subject)
)""")
connection.execute("""INSERT INTO remote_users
    (provider, subject, username, roles, enabled, synced_at)
    VALUES ('legacy', 'legacy-subject', 'legacy_remote', 'viewer', 1, 1)
""")
connection.execute("""CREATE TABLE policies(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ptype TEXT NOT NULL,
    v0 TEXT NOT NULL,
    v1 TEXT NOT NULL DEFAULT '*',
    v2 TEXT NOT NULL DEFAULT '*',
    UNIQUE(ptype, v0, v1, v2)
)""")
connection.execute("""INSERT INTO policies(ptype, v0, v1, v2)
    VALUES ('p', 'legacy_user', '/2999/*', 'GET')
""")
connection.commit()
connection.close()
PY
docker run -d \
    --name "$CONTAINER_NAME" \
    --network host \
    -e NGINX_WORKER_PROCESSES=1 \
    -e AUTHZ_HTTP_PORT="$HTTP_PORT" \
    -e AUTHZ_HTTPS_PORT="$HTTPS_PORT" \
    -e AUTHZ_COOKIE_DOMAIN=.test.example \
    -e AUTHZ_ADMIN_PASSWORD=admin123 \
    -e AUTHZ_DB_CACHE_TTL=30 \
    -e AUTHZ_DB_CACHE_LRU_SIZE=500 \
    -e AUTHZ_PORT_MIN=1000 \
    -e AUTHZ_PORT_MAX=65535 \
    -e AUTHZ_DISCOVERY_PORTS="$UPSTREAM_PORT,$WS_PORT" \
    -e AUTHZ_NOCO_ENABLED=true \
    -e AUTHZ_NOCO_URL="http://127.0.0.1:$NOCO_PORT" \
    -e AUTHZ_NOCO_ALLOW_HTTP=true \
    -e AUTHZ_NOCO_ROLE_MAP='member=user,operator=staff,root=admin' \
    -e AUTHZ_NOCO_OAUTH_ENABLED=true \
    -e AUTHZ_NOCO_OAUTH_CLIENT_ID=noco-client \
    -e AUTHZ_NOCO_OAUTH_CLIENT_SECRET=noco-secret \
    -e AUTHZ_NOCO_OAUTH_REDIRECT_URI="http://admin.test.example:$HTTP_PORT/_authz/oauth/callback" \
    -e AUTHZ_OAUTH_ENABLED=true \
    -e AUTHZ_OAUTH_PROVIDER=testid \
    -e 'AUTHZ_OAUTH_TITLE=Test Identity' \
    -e AUTHZ_OAUTH_CLIENT_ID=test-client \
    -e AUTHZ_OAUTH_CLIENT_SECRET=test-secret \
    -e AUTHZ_OAUTH_AUTHORIZE_URL="http://127.0.0.1:$NOCO_PORT/oauth/authorize" \
    -e AUTHZ_OAUTH_TOKEN_URL="http://127.0.0.1:$NOCO_PORT/oauth/token" \
    -e AUTHZ_OAUTH_USERINFO_URL="http://127.0.0.1:$NOCO_PORT/oauth/userinfo" \
    -e AUTHZ_OAUTH_REDIRECT_URI="http://admin.test.example:$HTTP_PORT/_authz/oauth/callback" \
    -e AUTHZ_OAUTH_ROLE_MAP='employees=staff' \
    -e AUTHZ_OAUTH_ALLOW_HTTP=true \
    -e AUTHZ_DINGTALK_ENABLED=true \
    -e AUTHZ_DINGTALK_CLIENT_ID=ding-client \
    -e AUTHZ_DINGTALK_CLIENT_SECRET=ding-secret \
    -e AUTHZ_DINGTALK_REDIRECT_URI="http://admin.test.example:$HTTP_PORT/_authz/oauth/callback" \
    -e AUTHZ_DINGTALK_AUTHORIZE_URL="http://127.0.0.1:$NOCO_PORT/dingtalk/authorize" \
    -e AUTHZ_DINGTALK_TOKEN_URL="http://127.0.0.1:$NOCO_PORT/dingtalk/token" \
    -e AUTHZ_DINGTALK_USERINFO_URL="http://127.0.0.1:$NOCO_PORT/dingtalk/userinfo" \
    -e AUTHZ_WECHAT_ENABLED=true \
    -e AUTHZ_WECHAT_APP_ID=wechat-app \
    -e AUTHZ_WECHAT_APP_SECRET=wechat-secret \
    -e AUTHZ_WECHAT_REDIRECT_URI="http://admin.test.example:$HTTP_PORT/_authz/oauth/callback" \
    -e AUTHZ_WECHAT_AUTHORIZE_URL="http://127.0.0.1:$NOCO_PORT/wechat/authorize" \
    -e AUTHZ_WECHAT_TOKEN_URL="http://127.0.0.1:$NOCO_PORT/wechat/token" \
    -e AUTHZ_WECHAT_USERINFO_URL="http://127.0.0.1:$NOCO_PORT/wechat/userinfo" \
    -v "$TMP_DIR/data:/data" \
    -v "$REPO_DIR/admin:/usr/local/openresty/nginx/html/admin:ro" \
    -v "$REPO_DIR/conf/nginx.conf.template:/usr/local/openresty/nginx/conf/nginx.conf.template:ro" \
    -v "$REPO_DIR/conf/server.conf.template:/usr/local/openresty/nginx/conf/server.conf.template:ro" \
    -v "$REPO_DIR/lualib:/usr/local/openresty/site/lualib:ro" \
    "$IMAGE" >/dev/null

for _ in $(seq 1 80); do
    STATUS=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/_api_/authz/v1/session" 2>/dev/null || true)
    [[ "$STATUS" == "401" ]] && break
    sleep 0.1
done
[[ "$STATUS" == "401" ]] || fail "gateway did not become ready"
MIGRATED_SOURCE=$(python3 - "$TMP_DIR/data/authz/authz.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
columns = {row[1] for row in connection.execute("PRAGMA table_info(sessions)")}
print("yes" if "source" in columns else "no")
connection.close()
PY
)
assert_eq "legacy sessions schema migrated" "$MIGRATED_SOURCE" "yes"
REMOTE_MIGRATION=$(python3 - "$TMP_DIR/data/authz/authz.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
columns = {row[1] for row in connection.execute("PRAGMA table_info(remote_users)")}
unique_indexes = [row[1] for row in connection.execute("PRAGMA index_list(remote_users)") if row[2]]
unique_columns = [tuple(item[2] for item in connection.execute(f"PRAGMA index_info({index})"))
                  for index in unique_indexes]
valid = {"remote_roles", "roles_overridden", "created_at", "last_login_at", "updated_at"}.issubset(columns)
valid = valid and ("provider", "username") in unique_columns and ("username",) not in unique_columns
legacy = connection.execute("""SELECT created_at, last_login_at, updated_at
    FROM remote_users WHERE provider = 'legacy'""").fetchone()
valid = valid and legacy == (1, 1, 1)
print("yes" if valid else "no")
connection.close()
PY
)
assert_eq "remote identity and timestamps migrated" "$REMOTE_MIGRATION" "yes"
USER_TIMESTAMP_MIGRATION=$(python3 - "$TMP_DIR/data/authz/authz.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
row = connection.execute("SELECT created_at, last_login_at, updated_at FROM users WHERE username = 'admin'").fetchone()
valid = {"created_at", "last_login_at", "updated_at"}.issubset(columns)
valid = valid and row and row[0] > 0 and row[1] is None and row[2] == row[0]
print("yes" if valid else "no")
connection.close()
PY
)
assert_eq "local user timestamps migrated and seeded" "$USER_TIMESTAMP_MIGRATION" "yes"
LEGACY_POLICY=$(python3 - "$TMP_DIR/data/authz/authz.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
row = connection.execute("SELECT v0 FROM policies WHERE v1 = '/2999/*'").fetchone()
print(row[0] if row else "missing")
connection.close()
PY
)
assert_eq "legacy user policy migrated to local identity" "$LEGACY_POLICY" "user:local:legacy_user"

cookie_header() {
    awk '
        !/^#/ && NF >= 7 {
            value = $6 "=" $7
            cookies = cookies (cookies == "" ? "" : "; ") value
            next
        }
        !/^#/ && /^[^=[:space:]]+=/ {
            cookies = cookies (cookies == "" ? "" : "; ") $0
        }
        END { print cookies }
    ' "$1"
}

save_session_cookie() {
    local headers=$1 cookie=$2 token
    token=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie:/ { line=$0; sub(/^[^:]+:[[:space:]]*/, "", line); sub(/;.*/, "", line); if (line ~ /^authz_session=/) { sub(/^authz_session=/, "", line); print line; exit } }' "$headers")
    [[ "$token" =~ ^[A-Fa-f0-9]{64}$ ]] || fail "response did not set a valid session cookie"
    printf 'authz_session=%s' "$token" > "$cookie"
}

request() {
    local method=$1 host=$2 path=$3 cookie=${4:-} csrf=${5:-} data=${6:-}
    local args=(--silent --show-error --max-time 5 --request "$method" --resolve "$host:$HTTP_PORT:127.0.0.1" -H 'Accept: application/json' -D "$TMP_DIR/headers" -o "$TMP_DIR/body" -w '%{http_code}')
    [[ -n "$cookie" ]] && args+=(-H "Cookie: $(cookie_header "$cookie")")
    [[ -n "$csrf" ]] && args+=(-H "X-CSRF-Token: $csrf")
    if [[ -n "$data" ]]; then args+=(-H 'Content-Type: application/json' --data "$data"); fi
    STATUS=$(curl "${args[@]}" "http://$host:$HTTP_PORT$path")
    BODY=$(<"$TMP_DIR/body")
    CONTENT_TYPE=$(awk 'BEGIN { IGNORECASE=1 } /^Content-Type:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); value=$0 } END { print value }' "$TMP_DIR/headers")
}

login() {
    local host=$1 username=$2 password=$3 cookie=$4 source=${5:-local} expect_session=${6:-true}
    rm -f "$cookie"
    STATUS=$(curl -sS --max-time 5 --resolve "$host:$HTTP_PORT:127.0.0.1" -D "$TMP_DIR/login-headers" -o /dev/null -w '%{http_code}' \
        -X POST "http://$host:$HTTP_PORT/_authz/login" \
        --data-urlencode "username=$username" --data-urlencode "password=$password" \
        --data-urlencode "source=$source")
    assert_eq "login $username from $source" "$STATUS" "302"
    if [[ "$expect_session" == "true" ]]; then
        save_session_cookie "$TMP_DIR/login-headers" "$cookie"
    else
        if awk 'BEGIN { IGNORECASE=1; found=0 } /^Set-Cookie:[[:space:]]*authz_session=/ { found=1 } END { exit found ? 0 : 1 }' "$TMP_DIR/login-headers"; then
            fail "rejected login unexpectedly set a session cookie"
        fi
        printf '' > "$cookie"
    fi
}

ADMIN_HOST=admin.test.example
ADMIN_COOKIE="$TMP_DIR/admin.cookie"
BOB_COOKIE="$TMP_DIR/bob.cookie"
DYNAMIC_COOKIE="$TMP_DIR/dynamic.cookie"
APP_COOKIE="$TMP_DIR/app.cookie"
REMOTE_COOKIE="$TMP_DIR/remote.cookie"
REMOTE_DYNAMIC_COOKIE="$TMP_DIR/remote-dynamic.cookie"
SHADOW_COOKIE="$TMP_DIR/shadow.cookie"
SHADOW_DYNAMIC_COOKIE="$TMP_DIR/shadow-dynamic.cookie"
OAUTH_COOKIE="$TMP_DIR/oauth.cookie"
NOCO_OAUTH_COOKIE="$TMP_DIR/noco-oauth.cookie"
NOCO_OAUTH_SECOND_COOKIE="$TMP_DIR/noco-oauth-second.cookie"
NOCO_BAD_ISSUER_COOKIE="$TMP_DIR/noco-bad-issuer.cookie"
DINGTALK_COOKIE="$TMP_DIR/dingtalk.cookie"
WECHAT_COOKIE="$TMP_DIR/wechat.cookie"

request GET "$ADMIN_HOST" /_api_/authz/v1/session
assert_eq "unauthenticated API status" "$STATUS" "401"
assert_eq "unauthenticated API JSON type" "$CONTENT_TYPE" "application/json; charset=UTF-8"
assert_json "unauthenticated API error" '.error.code' "unauthenticated"
request GET "$ADMIN_HOST" /_radmin_/
assert_eq "unauthenticated admin UI redirects" "$STATUS" "302"

login "$ADMIN_HOST" admin admin123 "$ADMIN_COOKIE"
HTTP_LOGIN_COOKIE=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/^[^;]+/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/login-headers")
assert_not_contains "HTTP session cookie is not Secure" "$HTTP_LOGIN_COOKIE" "; Secure"
for _ in $(seq 1 20); do
    request GET "$ADMIN_HOST" /_api_/authz/v1/session "$ADMIN_COOKIE"
    [[ "$STATUS" == "200" ]] && break
    sleep 0.05
done
assert_eq "session becomes available after login" "$STATUS" "200"

request GET "$ADMIN_HOST" /_radmin_/ "$ADMIN_COOKIE"
assert_eq "authenticated admin UI" "$STATUS" "200"
assert_contains "admin UI loads shell" "$BODY" "app-frame"
assert_contains "admin UI assembles menu with SSI" "$BODY" "id=\"admin-menu\""
assert_not_contains "admin SSI menu has no inline style" "$BODY" "<style>"
assert_not_contains "admin UI does not iframe menu" "$BODY" "menu-frame"
assert_contains "admin shell is not cached" "$(cat "$TMP_DIR/headers")" "Cache-Control: no-store"
request GET "$ADMIN_HOST" '/_radmin_/app.css?v=6' "$ADMIN_COOKIE"
assert_eq "admin shared CSS asset" "$STATUS" "200"
assert_contains "shared CSS contains SSI menu styles" "$BODY" "#admin-menu .menu-shell"
assert_contains "shared CSS contains mini drawer styles" "$BODY" ".admin-drawer-mini #admin-menu"
request GET "$ADMIN_HOST" '/_radmin_/api.js?v=7' "$ADMIN_COOKIE"
assert_eq "admin API client asset" "$STATUS" "200"
assert_contains "admin client uses new API root" "$BODY" "/_api_/authz/v1"
assert_contains "admin API errors expose status" "$BODY" "error.status = response.status"
assert_contains "binding API supports edit" "$BODY" "values.action === 'edit'"
STATIC_STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -H 'Accept-Encoding: gzip' -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" -D "$TMP_DIR/static-headers" \
    -o /dev/null -w '%{http_code}' "http://$ADMIN_HOST:$HTTP_PORT/_radmin_/api.js?v=7")
assert_eq "admin static asset status" "$STATIC_STATUS" "200"
assert_eq "admin static asset gzip encoding" \
    "$(awk 'BEGIN { IGNORECASE=1 } /^Content-Encoding:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/static-headers")" "gzip"
BR_STATIC_STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -H 'Accept-Encoding: br' -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" -D "$TMP_DIR/br-static-headers" \
    -o /dev/null -w '%{http_code}' "http://$ADMIN_HOST:$HTTP_PORT/_radmin_/api.js?v=7")
assert_eq "admin static asset Brotli status" "$BR_STATIC_STATUS" "200"
assert_eq "admin static asset Brotli encoding" \
    "$(awk 'BEGIN { IGNORECASE=1 } /^Content-Encoding:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/br-static-headers")" "br"
assert_contains "admin static asset permanent cache" \
    "$(awk 'BEGIN { IGNORECASE=1 } /^Cache-Control:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/static-headers")" "max-age=315360000"
assert_contains "admin static asset expires max" \
    "$(awk 'BEGIN { IGNORECASE=1 } /^Expires:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/static-headers")" "2037"
request GET "$ADMIN_HOST" /_radmin_/app.js "$ADMIN_COOKIE"
assert_contains "admin redirect is limited to API 401" "$BODY" "error?.status === 401"
assert_contains "authorization menu is admin gated" "$BODY" "if (isAdmin.value)"
assert_contains "menu reads admin status from session" "$BODY" "isAdmin.value = Boolean(session.admin)"
assert_contains "menu loads local applications" "$BODY" "window.adminApi.applications"
assert_contains "menu refreshes local applications" "$BODY" "setInterval(loadApplications, 30000)"
assert_contains "built-in app URLs are versioned" "$BODY" "apps/authorization.html?v=7"
request GET "$ADMIN_HOST" /_radmin_/apps/users.html "$ADMIN_COOKIE"
assert_contains "user roles use controlled multi-select" "$BODY" 'multiple use-chips emit-value map-options'
assert_contains "user role fallback catalog" "$BODY" "['admin', 'staff', 'user', 'viewer']"
assert_contains "remote users share user table" "$BODY" "data.remote_users"
assert_contains "remote roles can be restored" "$BODY" "restoreRemoteRoles"
assert_contains "all identities use enabled state toggle" "$BODY" 'v-if="isAdmin" :model-value="props.row.enabled === 1"'
assert_contains "remote identities can be enabled or disabled" "$BODY" "window.adminApi.saveRemoteUser"
assert_contains "only enabled and disabled status labels are shown" "$BODY" "t.enabled : t.disabled"
assert_contains "user table shows last login time" "$BODY" "name: 'last_login_at'"
assert_contains "user table shows updated time" "$BODY" "name: 'updated_at'"
assert_contains "user timestamps include seconds" "$BODY" "second: '2-digit'"
assert_contains "profile page loads current session first" "$BODY" "const current = await window.adminApi.session()"
assert_contains "non-admin profile uses only session identity" "$BODY" "if (!current.admin)"
request GET "$ADMIN_HOST" /_radmin_/apps/authorization.html "$ADMIN_COOKIE"
assert_contains "admin application HTML is not cached" "$(cat "$TMP_DIR/headers")" "Cache-Control: no-store"
assert_contains "policy subject uses select options" "$BODY" 'policySubjectOptions'
assert_contains "policy object uses binding options" "$BODY" 'policyObjectOptions'
assert_contains "policy HTTP method uses select options" "$BODY" ':options="httpActions"'
assert_contains "policy HTTP method supports multi-select" "$BODY" 'multiple use-chips emit-value map-options :options="httpActions"'
assert_contains "policy methods include CONNECT" "$BODY" "'CONNECT'"
assert_contains "policy methods include TRACE" "$BODY" "'TRACE'"
assert_contains "binding page supports editing" "$BODY" "openEditBinding"
assert_contains "binding form supports saving" "$BODY" "saveBindingForm"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$ADMIN_COOKIE"
assert_eq "session API" "$STATUS" "200"
assert_json "session username" '.data.username' "admin"
assert_json "session canonical identity" '.data.identity' "user:local:admin"
assert_json "session admin flag" '.data.admin | tostring' "true"
assert_json "session exposes creation time" '.data.created_at > 0 | tostring' "true"
assert_json "session exposes last login time" '.data.last_login_at > 0 | tostring' "true"
assert_json "session exposes updated time" '.data.updated_at > 0 | tostring' "true"
CSRF=$(jq -er '.data.csrf' "$TMP_DIR/body")
request GET "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE"
assert_eq "applications API" "$STATUS" "200"
assert_json "applications API returns a list" '.data | type' "array"
assert_json "applications API discovers local HTTP service" ".data | map(select(.port == $UPSTREAM_PORT)) | length" "1"

request GET "$ADMIN_HOST" '/_authz/login?next=/_radmin_/'
assert_eq "login page with OAuth provider" "$STATUS" "200"
assert_contains "login page disables browser cache" "$(cat "$TMP_DIR/headers")" "Cache-Control: no-store"
assert_contains "OAuth provider login button" "$BODY" "Test Identity"
assert_contains "password login exposes identity source" "$BODY" 'name="source"'
assert_contains "login card doubles desktop width" "$BODY" 'width:min(720px'
assert_contains "login page uses two columns" "$BODY" 'grid-template-columns:1fr 1fr'
assert_contains "associated logins use two-column grid" "$BODY" 'grid-template-columns:repeat(2,minmax(0,1fr))'
assert_contains "NocoBase OAuth branded entry" "$BODY" 'class="oauth brand-nocobase"'
assert_contains "Google branded entry remains visible" "$BODY" 'class="oauth brand-google disabled"'
assert_contains "DingTalk branded entry" "$BODY" 'class="oauth brand-dingtalk"'
assert_contains "WeChat branded entry" "$BODY" 'class="oauth brand-wechat"'
assert_contains "OAuth buttons expose brand icons" "$BODY" 'class="brand-icon"'
assert_not_contains "OAuth buttons remove action wording" "$BODY" "使用 NocoBase 登录"
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/headers" -o /dev/null -w '%{http_code}' -X POST \
    "http://$ADMIN_HOST:$HTTP_PORT/_authz/login" \
    --data-urlencode 'username=invalid-user' --data-urlencode 'password=invalid-password' \
    --data-urlencode 'source=local' --data-urlencode 'next=/_radmin_/')
assert_eq "invalid login redirects" "$STATUS" "302"
LOGIN_ERROR_LOCATION=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")
request GET "$ADMIN_HOST" "$LOGIN_ERROR_LOCATION"
assert_contains "login error is decoded UTF-8" "$BODY" "用户名或密码错误"
assert_contains "login return path is decoded" "$BODY" 'name="next" value="/_radmin_/"'
if [[ "$BODY" == *'%E7%94%A8%E6%88%B7'* ]]; then fail "login error must not expose percent encoding"; fi
pass "login error hides percent encoding"
request GET "$ADMIN_HOST" '/_authz/oauth/start?provider=testid&next=/_radmin_/'
assert_eq "OAuth start redirects to provider" "$STATUS" "302"
OAUTH_AUTHORIZE_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")
assert_contains "OAuth start uses PKCE" "$OAUTH_AUTHORIZE_URL" "code_challenge_method=S256"
OAUTH_CALLBACK_URL=$(curl -sS --max-time 5 -D - -o /dev/null "$OAUTH_AUTHORIZE_URL" | awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }')
OAUTH_CALLBACK_PATH=$(python3 - "$OAUTH_CALLBACK_URL" <<'PY'
import sys
from urllib.parse import urlsplit

value = urlsplit(sys.argv[1])
print(value.path + ("?" + value.query if value.query else ""))
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/headers" -o /dev/null -w '%{http_code}' \
    "http://$ADMIN_HOST:$HTTP_PORT$OAUTH_CALLBACK_PATH")
assert_eq "OAuth callback creates local session" "$STATUS" "302"
save_session_cookie "$TMP_DIR/headers" "$OAUTH_COOKIE"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$OAUTH_COOKIE"
assert_eq "OAuth session API" "$STATUS" "200"
assert_json "OAuth session source" '.data.source' "testid"
assert_json "OAuth canonical identity" '.data.identity' "user:testid:oauth.user@example.test"
assert_json "OAuth userinfo username" '.data.username' "oauth.user@example.test"
assert_json "OAuth claim maps local role" '.data.roles | join(",")' "staff"
OAUTH_TOKEN_ATTEMPTS=$(curl -fsS --max-time 5 \
    "http://127.0.0.1:$NOCO_PORT/test/oauth-token-attempts" | jq -r '.attempts')
assert_eq "OAuth retries first transport failure" "$OAUTH_TOKEN_ATTEMPTS" "2"
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -o /dev/null -w '%{http_code}' "http://$ADMIN_HOST:$HTTP_PORT$OAUTH_CALLBACK_PATH")
assert_eq "OAuth callback replay is rejected" "$STATUS" "302"
request GET "$ADMIN_HOST" /_api_/authz/v1/session
assert_eq "replayed OAuth callback creates no session" "$STATUS" "401"

request GET "$ADMIN_HOST" '/_authz/oauth/start?provider=nocobase&next=/_radmin_/'
assert_eq "NocoBase OAuth start redirects to provider" "$STATUS" "302"
assert_contains "NocoBase OAuth start disables browser cache" "$(cat "$TMP_DIR/headers")" "Cache-Control: no-store"
NOCO_OAUTH_AUTHORIZE_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")
assert_contains "NocoBase OAuth uses PKCE" "$NOCO_OAUTH_AUTHORIZE_URL" "code_challenge_method=S256"
assert_contains "NocoBase OAuth requests API scope" "$NOCO_OAUTH_AUTHORIZE_URL" "api"
assert_not_contains "NocoBase OAuth omits obsolete resource" "$NOCO_OAUTH_AUTHORIZE_URL" "resource="
NOCO_OAUTH_CALLBACK_URL=$(curl -sS --max-time 5 -D - -o /dev/null "$NOCO_OAUTH_AUTHORIZE_URL" | awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }')
assert_contains "NocoBase OAuth callback includes issuer" "$NOCO_OAUTH_CALLBACK_URL" "iss="
NOCO_OAUTH_CALLBACK_PATH=$(python3 - "$NOCO_OAUTH_CALLBACK_URL" <<'PY'
import sys
from urllib.parse import urlsplit
value = urlsplit(sys.argv[1])
print(value.path + "?" + value.query)
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/headers" -o /dev/null -w '%{http_code}' \
    "http://$ADMIN_HOST:$HTTP_PORT$NOCO_OAUTH_CALLBACK_PATH")
assert_eq "NocoBase OAuth callback creates session" "$STATUS" "302"
assert_contains "NocoBase OAuth callback disables browser cache" "$(cat "$TMP_DIR/headers")" "Cache-Control: no-store"
save_session_cookie "$TMP_DIR/headers" "$NOCO_OAUTH_COOKIE"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$NOCO_OAUTH_COOKIE"
assert_eq "NocoBase OAuth session API" "$STATUS" "200"
assert_json "NocoBase OAuth shares source" '.data.source' "nocobase"
assert_json "NocoBase OAuth username" '.data.username' "remote_user"
assert_json "NocoBase OAuth uses local default role" '.data.roles | join(",")' "viewer"

request GET "$ADMIN_HOST" '/_authz/oauth/start?provider=nocobase&next=/_radmin_/'
assert_eq "second NocoBase OAuth start" "$STATUS" "302"
NOCO_SECOND_AUTHORIZE_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")
NOCO_SECOND_CALLBACK_URL=$(curl -sS --max-time 5 -D - -o /dev/null "$NOCO_SECOND_AUTHORIZE_URL" | awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }')
NOCO_SECOND_CALLBACK_PATH=$(python3 - "$NOCO_SECOND_CALLBACK_URL" <<'PY'
import sys
from urllib.parse import urlsplit
value = urlsplit(sys.argv[1])
print(value.path + "?" + value.query)
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/headers" -o /dev/null -w '%{http_code}' \
    "http://$ADMIN_HOST:$HTTP_PORT$NOCO_SECOND_CALLBACK_PATH")
assert_eq "second NocoBase OAuth callback succeeds" "$STATUS" "302"
assert_eq "second NocoBase OAuth skips stale login error" \
    "$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")" \
    "/_radmin_/"
save_session_cookie "$TMP_DIR/headers" "$NOCO_OAUTH_SECOND_COOKIE"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$NOCO_OAUTH_SECOND_COOKIE"
assert_eq "second NocoBase OAuth creates session" "$STATUS" "200"
assert_json "second NocoBase OAuth keeps source" '.data.source' "nocobase"

request GET "$ADMIN_HOST" '/_authz/oauth/start?provider=nocobase&next=/_radmin_/'
NOCO_BAD_ISSUER_AUTHORIZE_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")
NOCO_BAD_ISSUER_CALLBACK_URL=$(curl -sS --max-time 5 -D - -o /dev/null "$NOCO_BAD_ISSUER_AUTHORIZE_URL" | awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }')
NOCO_BAD_ISSUER_CALLBACK_PATH=$(python3 - "$NOCO_BAD_ISSUER_CALLBACK_URL" <<'PY'
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit

value = urlsplit(sys.argv[1])
query = dict(parse_qsl(value.query, keep_blank_values=True))
query["iss"] = "https://attacker.example/api"
print(value.path + "?" + urlencode(query))
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -c "$NOCO_BAD_ISSUER_COOKIE" -o /dev/null -w '%{http_code}' \
    "http://$ADMIN_HOST:$HTTP_PORT$NOCO_BAD_ISSUER_CALLBACK_PATH")
assert_eq "NocoBase OAuth rejects mismatched issuer" "$STATUS" "302"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$NOCO_BAD_ISSUER_COOKIE"
assert_eq "mismatched NocoBase issuer creates no session" "$STATUS" "401"

request GET "$ADMIN_HOST" '/_authz/oauth/start?provider=dingtalk&next=/_radmin_/'
assert_eq "DingTalk start redirects to provider" "$STATUS" "302"
DINGTALK_AUTHORIZE_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")
assert_contains "DingTalk authorization scope" "$DINGTALK_AUTHORIZE_URL" "scope=openid"
DINGTALK_CALLBACK_URL=$(curl -sS --max-time 5 -D - -o /dev/null "$DINGTALK_AUTHORIZE_URL" | awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }')
DINGTALK_CALLBACK_PATH=$(python3 - "$DINGTALK_CALLBACK_URL" <<'PY'
import sys
from urllib.parse import urlsplit
value = urlsplit(sys.argv[1])
print(value.path + "?" + value.query)
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/headers" -o /dev/null -w '%{http_code}' \
    "http://$ADMIN_HOST:$HTTP_PORT$DINGTALK_CALLBACK_PATH")
assert_eq "DingTalk callback creates session" "$STATUS" "302"
save_session_cookie "$TMP_DIR/headers" "$DINGTALK_COOKIE"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$DINGTALK_COOKIE"
assert_json "DingTalk session source" '.data.source' "dingtalk"
assert_json "DingTalk missing email uses stable username" '.data.username | startswith("dingtalk_") | tostring' "true"
assert_json "DingTalk default role" '.data.roles | join(",")' "viewer"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$DINGTALK_COOKIE"
assert_eq "remote viewer authorization API denied" "$STATUS" "403"

request GET "$ADMIN_HOST" '/_authz/oauth/start?provider=wechat&next=/_radmin_/'
assert_eq "WeChat start redirects to provider" "$STATUS" "302"
WECHAT_AUTHORIZE_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")
assert_contains "WeChat website login scope" "$WECHAT_AUTHORIZE_URL" "scope=snsapi_login"
assert_contains "WeChat authorization fragment" "$WECHAT_AUTHORIZE_URL" "#wechat_redirect"
WECHAT_CALLBACK_URL=$(curl -sS --max-time 5 -D - -o /dev/null "$WECHAT_AUTHORIZE_URL" | awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }')
WECHAT_CALLBACK_PATH=$(python3 - "$WECHAT_CALLBACK_URL" <<'PY'
import sys
from urllib.parse import urlsplit
value = urlsplit(sys.argv[1])
print(value.path + "?" + value.query)
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/headers" -o /dev/null -w '%{http_code}' \
    "http://$ADMIN_HOST:$HTTP_PORT$WECHAT_CALLBACK_PATH")
assert_eq "WeChat callback creates session" "$STATUS" "302"
save_session_cookie "$TMP_DIR/headers" "$WECHAT_COOKIE"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$WECHAT_COOKIE"
assert_json "WeChat session source" '.data.source' "wechat"
assert_json "WeChat identity uses stable username" '.data.username | startswith("wechat_") | tostring' "true"
assert_json "WeChat default role" '.data.roles | join(",")' "viewer"

request GET "$ADMIN_HOST" /_authz/api/users "$ADMIN_COOKIE"
assert_eq "legacy data API retired" "$STATUS" "410"
assert_contains "legacy data API move hint" "$BODY" "/_api_/authz/v1"
request POST "$ADMIN_HOST" /_authz/users/save "$ADMIN_COOKIE" "$CSRF" '{}'
assert_eq "legacy save API retired" "$STATUS" "410"

request GET "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE"
assert_eq "users API" "$STATUS" "200"
assert_json "seeded admin user" '.data.users[0].username' "admin"
assert_json "fixed role catalog" '.data.available_roles | join(",")' "admin,staff,user,viewer"

request POST "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE" "" '{"username":"bob","password":"bob123456","roles":"user"}'
assert_eq "mutation without CSRF" "$STATUS" "403"
assert_json "CSRF error code" '.error.code' "csrf_failed"

request POST "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE" "$CSRF" '{bad-json'
assert_eq "invalid JSON body" "$STATUS" "400"
assert_json "invalid JSON error code" '.error.code' "invalid_body"

request POST "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE" "$CSRF" '{"username":"invalid-role","password":"password123","roles":["auditor"]}'
assert_eq "unknown user role rejected" "$STATUS" "422"

request POST "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE" "$CSRF" '{"username":"bob","password":"bob123456","roles":["user"]}'
assert_eq "create user" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE"
BOB_ID=$(jq -er '.data.users[] | select(.username == "bob") | .id' "$TMP_DIR/body")
[[ -n "$BOB_ID" ]] || fail "created user not found"
pass "created user appears in list"
assert_json "cached user list starts with original role" '.data.users[] | select(.username == "bob") | .roles' "user"
assert_json "new user exposes nullable last login field" '.data.users[] | select(.username == "bob") | has("last_login_at") | tostring' "true"
assert_json "new user has no login time before first login" '.data.users[] | select(.username == "bob") | .last_login_at == null | tostring' "true"
assert_json "columns after null remain readable" '.data.users[] | select(.username == "bob") | .updated_at == .created_at | tostring' "true"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/users/$BOB_ID" "$ADMIN_COOKIE" "$CSRF" '{"roles":["staff","user"]}'
assert_eq "update user roles" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE"
assert_json "cached user list invalidates after write" '.data.users[] | select(.username == "bob") | .roles' "staff,user"
request PUT "$ADMIN_HOST" "/_api_/authz/v1/users/$BOB_ID/password" "$ADMIN_COOKIE" "$CSRF" '{"password":"bob654321"}'
assert_eq "reset user password" "$STATUS" "200"

login "$ADMIN_HOST" bob bob654321 "$BOB_COOKIE"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$BOB_COOKIE"
assert_eq "non-admin can read own session profile" "$STATUS" "200"
assert_json "non-admin own identity" '.data.identity' "user:local:bob"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "$BOB_COOKIE"
assert_eq "non-admin users API denied" "$STATUS" "403"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$BOB_COOKIE"
assert_eq "non-admin authorization API denied" "$STATUS" "403"

login "$DYNAMIC_HOST" bob bob654321 "$DYNAMIC_COOKIE"
request GET "$DYNAMIC_HOST" / "$DYNAMIC_COOKIE"
assert_eq "default deny for ordinary user" "$STATUS" "403"

login "$ADMIN_HOST" remote@example.test remote123 "$REMOTE_COOKIE" nocobase
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_COOKIE"
assert_eq "remote NocoBase session" "$STATUS" "200"
assert_json "remote session source" '.data.source' "nocobase"
assert_json "remote username comes from NocoBase" '.data.username' "remote_user"
assert_json "remote canonical identity" '.data.identity' "user:nocobase:remote_user"
assert_json "remote roles map to local catalog" '.data.roles | join(",")' "staff,user"
REMOTE_CSRF=$(jq -er '.data.csrf' "$TMP_DIR/body")
request PUT "$ADMIN_HOST" /_api_/authz/v1/me/password "$REMOTE_COOKIE" "$REMOTE_CSRF" '{"old_password":"remote123","new_password":"changed123"}'
assert_eq "remote password changes stay in NocoBase" "$STATUS" "409"

request GET "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE"
assert_json "remote user appears in management" '.data.remote_users[] | select(.username == "remote_user") | .provider' "nocobase"
assert_json "remote identity exposes one-way record time" '.data.remote_users[] | select(.username == "remote_user") | .recorded_at > 0 | tostring' "true"
assert_json "remote identity hides legacy sync field" '.data.remote_users[] | select(.username == "remote_user") | .synced_at == null | tostring' "true"
assert_json "remote user exposes creation time" '.data.remote_users[] | select(.username == "remote_user") | .created_at > 0 | tostring' "true"
assert_json "remote user exposes last login time" '.data.remote_users[] | select(.username == "remote_user") | .last_login_at > 0 | tostring' "true"
assert_json "remote user exposes updated time" '.data.remote_users[] | select(.username == "remote_user") | .updated_at > 0 | tostring' "true"
assert_json "local management row exposes canonical identity" '.data.users[] | select(.username == "bob") | .identity' "user:local:bob"
assert_json "local user exposes creation time" '.data.users[] | select(.username == "bob") | .created_at > 0 | tostring' "true"
assert_json "local user exposes last login time" '.data.users[] | select(.username == "bob") | .last_login_at > 0 | tostring' "true"
assert_json "local user exposes updated time" '.data.users[] | select(.username == "bob") | .updated_at > 0 | tostring' "true"
assert_json "remote management row exposes canonical identity" '.data.remote_users[] | select(.username == "remote_user") | .identity' "user:nocobase:remote_user"
assert_json "recorded remote roles are exposed" '.data.remote_users[] | select(.username == "remote_user") | .remote_roles' "staff,user"
request PATCH "$ADMIN_HOST" /_api_/authz/v1/remote-users/nocobase "$ADMIN_COOKIE" "$CSRF" '{"subject":"42","roles":["viewer"]}'
assert_eq "admin overrides remote roles" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_COOKIE"
assert_json "remote session sees role override immediately" '.data.roles | join(",")' "viewer"
login "$ADMIN_HOST" remote@example.test remote123 "$REMOTE_COOKIE" nocobase
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_COOKIE"
assert_json "remote login preserves local role override" '.data.roles | join(",")' "viewer"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE"
assert_json "remote override flag is visible" '.data.remote_users[] | select(.username == "remote_user") | .roles_overridden | tostring' "1"
assert_json "next login refreshes recorded remote roles" '.data.remote_users[] | select(.username == "remote_user") | .remote_roles' "staff,user"
request PATCH "$ADMIN_HOST" /_api_/authz/v1/remote-users/nocobase "$ADMIN_COOKIE" "$CSRF" '{"subject":"42","use_remote_roles":true}'
assert_eq "admin restores recorded remote roles" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_COOKIE"
assert_json "restored remote roles apply immediately" '.data.roles | join(",")' "staff,user"

request PATCH "$ADMIN_HOST" /_api_/authz/v1/remote-users/nocobase "$ADMIN_COOKIE" "$CSRF" '{"subject":"42","enabled":false}'
assert_eq "admin disables remote identity" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_COOKIE"
assert_eq "disabled remote identity session revoked" "$STATUS" "401"
login "$ADMIN_HOST" remote@example.test remote123 "$REMOTE_COOKIE" nocobase false
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_COOKIE"
assert_eq "disabled remote identity cannot sign in again" "$STATUS" "401"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE"
assert_json "remote authentication preserves disabled state" '.data.remote_users[] | select(.provider == "nocobase" and .subject == "42") | .enabled | tostring' "0"
request PATCH "$ADMIN_HOST" /_api_/authz/v1/remote-users/nocobase "$ADMIN_COOKIE" "$CSRF" '{"subject":"42","enabled":true}'
assert_eq "admin enables remote identity" "$STATUS" "200"
login "$ADMIN_HOST" remote@example.test remote123 "$REMOTE_COOKIE" nocobase
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_COOKIE"
assert_eq "enabled remote identity can sign in" "$STATUS" "200"

login "$ADMIN_HOST" shadow@example.test remote123 "$SHADOW_COOKIE" nocobase
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$SHADOW_COOKIE"
assert_eq "same username from NocoBase gets a session" "$STATUS" "200"
assert_json "same username keeps remote source" '.data.source' "nocobase"
assert_json "same username keeps remote canonical identity" '.data.identity' "user:nocobase:bob"
assert_json "same username keeps source-specific roles" '.data.roles | join(",")' "viewer"
login "$DYNAMIC_HOST" shadow@example.test remote123 "$SHADOW_DYNAMIC_COOKIE" nocobase
request GET "$DYNAMIC_HOST" / "$SHADOW_DYNAMIC_COOKIE"
assert_eq "remote same-name identity denied before direct policy" "$STATUS" "403"

request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"user:nocobase:bob\",\"v1\":\"$POLICY_OBJECT\",\"v2\":[\"GET\"],\"eft\":\"allow\"}"
assert_eq "create source-specific user policy" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
SOURCE_POLICY_ID=$(jq -er --arg object "$POLICY_OBJECT" '.data.policies[] | select(.v0 == "user:nocobase:bob" and .v1 == $object) | .id' "$TMP_DIR/body")
request GET "$DYNAMIC_HOST" / "$SHADOW_DYNAMIC_COOKIE"
assert_eq "direct policy authorizes matching remote identity" "$STATUS" "200"
request GET "$DYNAMIC_HOST" / "$DYNAMIC_COOKIE"
assert_eq "direct remote policy does not authorize local same-name identity" "$STATUS" "403"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/policies/$SOURCE_POLICY_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "delete source-specific user policy" "$STATUS" "200"

request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:user\",\"v1\":\"$POLICY_OBJECT\",\"v2\":[\"POST\",\"GET\"],\"eft\":\"allow\"}"
assert_eq "create access policy" "$STATUS" "201"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:user\",\"v1\":\"$POLICY_OBJECT\",\"v2\":[\"GET\",\"BREW\"],\"eft\":\"allow\"}"
assert_eq "unknown HTTP method rejected" "$STATUS" "422"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:auditor\",\"v1\":\"$POLICY_OBJECT\",\"v2\":\"GET\",\"eft\":\"allow\"}"
assert_eq "unknown policy role rejected" "$STATUS" "422"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_eq "authorization API" "$STATUS" "200"
assert_json "minimum dynamic port clamped" '.data.port_min | tostring' "2000"
assert_json "local user policy identity option" '.data.policy_users[] | select(.username == "admin" and .source == "local") | .identity' "user:local:admin"
assert_json "policy role options" '.data.policy_roles | index("user") != null | tostring' "true"
assert_json "policy role catalog" '.data.policy_roles | join(",")' "admin,staff,user,viewer"
assert_json "remote identity is a policy subject" '.data.policy_users[] | select(.username == "remote_user" and .source == "nocobase") | .identity' "user:nocobase:remote_user"
assert_json "local same-name identity is listed separately" '.data.policy_users[] | select(.username == "bob" and .source == "local") | .identity' "user:local:bob"
assert_json "remote same-name identity is listed separately" '.data.policy_users[] | select(.username == "bob" and .source == "nocobase") | .identity' "user:nocobase:bob"
assert_json "HTTP method catalog includes CONNECT" '.data.http_methods | index("CONNECT") != null | tostring' "true"
assert_json "HTTP method catalog includes TRACE" '.data.http_methods | index("TRACE") != null | tostring' "true"
assert_json "multi-method policy normalized" ".data.policies[] | select(.v0 == \"role:user\" and .v1 == \"$POLICY_OBJECT\") | .action" "GET,POST"
POLICY_ID=$(jq -er --arg object "$POLICY_OBJECT" '.data.policies[] | select(.v0 == "role:user" and .v1 == $object) | .id' "$TMP_DIR/body")

request GET "$DYNAMIC_HOST" / "$DYNAMIC_COOKIE"
assert_eq "dynamic port allowed by policy" "$STATUS" "200"
assert_eq "dynamic proxy body" "$BODY" "$MOCK_BODY"
request GET "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE"
assert_json "HTTP service discovery finds mock port" ".data[] | select(.port == $UPSTREAM_PORT and .source == \"127.0.0.1\") | .port | tostring" "$UPSTREAM_PORT"
request POST "$DYNAMIC_HOST" / "$DYNAMIC_COOKIE"
assert_eq "second selected method allowed" "$STATUS" "200"
assert_eq "multi-method proxy body" "$BODY" "$MOCK_BODY"
request GET "$DYNAMIC_HOST" /identity "$DYNAMIC_COOKIE"
assert_json "upstream receives raw username" '.user' "bob"
assert_json "upstream receives identity source" '.source' "local"
assert_json "upstream receives canonical identity" '.identity' "user:local:bob"
assert_json "upstream receives local target Host" '.host' "127.0.0.1:$UPSTREAM_PORT"
login "$DYNAMIC_HOST" remote@example.test remote123 "$REMOTE_DYNAMIC_COOKIE" nocobase
request GET "$DYNAMIC_HOST" / "$REMOTE_DYNAMIC_COOKIE"
assert_eq "mapped remote role authorizes application" "$STATUS" "200"

request DELETE "$ADMIN_HOST" /_api_/authz/v1/remote-users/nocobase "$ADMIN_COOKIE" "$CSRF" '{"subject":"42"}'
assert_eq "admin deletes recorded remote identity" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_DYNAMIC_COOKIE"
assert_eq "deleting remote identity revokes sessions" "$STATUS" "401"
login "$ADMIN_HOST" remote@example.test remote123 "$REMOTE_COOKIE" nocobase
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$REMOTE_COOKIE"
assert_eq "deleted remote identity is recreated by authentication" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE"
assert_json "recreated remote identity starts enabled" '.data.remote_users[] | select(.provider == "nocobase" and .subject == "42") | .enabled | tostring' "1"

request POST "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"fixed.test.example\",\"port\":$UPSTREAM_PORT,\"enabled\":true,\"note\":\"test\"}"
assert_eq "create application" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
APP_ID=$(jq -er '.data.bindings[] | select(.domain == "fixed.test.example") | .id' "$TMP_DIR/body")
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"edited.test.example\",\"port\":$NOCO_PORT,\"enabled\":true,\"note\":\"edited\"}"
assert_eq "edit binding fields" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_json "edited binding domain" '.data.bindings[] | select(.domain == "edited.test.example") | .domain' "edited.test.example"
assert_json "edited binding port" '.data.bindings[] | select(.domain == "edited.test.example") | .port | tostring' "$NOCO_PORT"
assert_json "edited binding note" '.data.bindings[] | select(.domain == "edited.test.example") | .note' "edited"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" "{\"port\":1999}"
assert_eq "edit binding rejects port below minimum" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"fixed.test.example\",\"port\":$UPSTREAM_PORT,\"enabled\":true,\"note\":\"test\"}"
assert_eq "restore edited binding" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
APP_ID=$(jq -er '.data.bindings[] | select(.domain == "fixed.test.example") | .id' "$TMP_DIR/body")
login fixed.test.example bob bob654321 "$APP_COOKIE"
request GET fixed.test.example / "$APP_COOKIE"
assert_eq "fixed application proxy" "$STATUS" "200"

STATUS=$(curl -skS --max-time 5 --resolve "fixed.test.example:$HTTPS_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$APP_COOKIE")" -o "$TMP_DIR/https-proxy-body" -w '%{http_code}' \
    "https://fixed.test.example:$HTTPS_PORT/")
assert_eq "HTTPS gateway proxies to HTTP upstream" "$STATUS" "200"
assert_eq "HTTPS HTTP-upstream proxy body" "$(<"$TMP_DIR/https-proxy-body")" "$MOCK_BODY"

request POST "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"ws-fixed.test.example\",\"port\":$WS_PORT,\"enabled\":true,\"websocket\":false,\"note\":\"websocket default test\"}"
assert_eq "create WebSocket application" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_json "WebSocket compatibility field is stored" '.data.bindings[] | select(.domain == "ws-fixed.test.example") | .websocket | tostring' "0"
WS_STATUS=$(curl -sS --max-time 5 --http1.1 --resolve "ws-fixed.test.example:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" -D "$TMP_DIR/websocket-headers" -o "$TMP_DIR/websocket-body" -w '%{http_code}' \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    "http://ws-fixed.test.example:$HTTP_PORT/" || true)
assert_eq "WebSocket handshake through default binding" "$WS_STATUS" "101"
assert_contains "WebSocket upgrade response" "$(cat "$TMP_DIR/websocket-headers")" "101 Switching Protocols"
WS_STATUS=$(curl -skS --max-time 5 --http1.1 --resolve "ws-fixed.test.example:$HTTPS_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" -D "$TMP_DIR/https-websocket-headers" -o /dev/null -w '%{http_code}' \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    "https://ws-fixed.test.example:$HTTPS_PORT/" || true)
assert_eq "HTTPS default WebSocket proxy" "$WS_STATUS" "101"
assert_contains "HTTPS WebSocket upgrade response" \
    "$(cat "$TMP_DIR/https-websocket-headers")" "101 Switching Protocols"

request POST "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"ws-fixed.test.example\",\"port\":$WS_PORT,\"enabled\":true}"
assert_eq "duplicate domain binding rejected clearly" "$STATUS" "409"
assert_json "duplicate domain binding error" '.error.code' "request_failed"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"enabled":false}'
assert_eq "disable application" "$STATUS" "200"
request GET fixed.test.example / "$APP_COOKIE"
assert_eq "disabled application no longer resolves" "$STATUS" "404"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"enabled":true}'
assert_eq "enable application" "$STATUS" "200"

request DELETE "$ADMIN_HOST" "/_api_/authz/v1/policies/$POLICY_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "delete access policy" "$STATUS" "200"
request GET "$DYNAMIC_HOST" / "$DYNAMIC_COOKIE"
assert_eq "policy deletion invalidates cache" "$STATUS" "403"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/users/$BOB_ID" "$ADMIN_COOKIE" "$CSRF" '{"enabled":false}'
assert_eq "disable user" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$BOB_COOKIE"
assert_eq "disabled user session revoked" "$STATUS" "401"
login "$ADMIN_HOST" bob bob654321 "$BOB_COOKIE" local false
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$BOB_COOKIE"
assert_eq "disabled local user cannot sign in again" "$STATUS" "401"

request PATCH "$ADMIN_HOST" /_api_/authz/v1/users/1 "$ADMIN_COOKIE" "$CSRF" '{"enabled":false}'
assert_eq "built-in admin cannot be disabled" "$STATUS" "409"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/users/$BOB_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "delete user" "$STATUS" "200"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "delete application" "$STATUS" "200"

request GET "$ADMIN_HOST" /_api_/authz/v1/missing "$ADMIN_COOKIE"
assert_eq "unknown API status" "$STATUS" "404"
assert_eq "unknown API JSON type" "$CONTENT_TYPE" "application/json; charset=UTF-8"
assert_json "unknown API error" '.error.code' "http_404"

request DELETE "$ADMIN_HOST" /_api_/authz/v1/session "$ADMIN_COOKIE" "$CSRF"
assert_eq "logout API" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$ADMIN_COOKIE"
assert_eq "logged-out session rejected" "$STATUS" "401"

STATUS=$(curl -skS --max-time 5 --resolve "$ADMIN_HOST:$HTTPS_PORT:127.0.0.1" \
    -D "$TMP_DIR/secure-headers" -o /dev/null -w '%{http_code}' \
    -X POST "https://$ADMIN_HOST:$HTTPS_PORT/_authz/login" \
    --data-urlencode 'username=admin' --data-urlencode 'password=admin123')
assert_eq "HTTPS login succeeds" "$STATUS" "302"
SECURE_COOKIE=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie:/ { print }' "$TMP_DIR/secure-headers")
assert_contains "HTTPS session cookie is Secure" "$SECURE_COOKIE" "; Secure"
assert_contains "session cookie uses root domain" "$SECURE_COOKIE" "; Domain=.test.example"

STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -H 'X-Forwarded-Proto: https' -D "$TMP_DIR/forwarded-secure-headers" \
    -o /dev/null -w '%{http_code}' -X POST "http://$ADMIN_HOST:$HTTP_PORT/_authz/login" \
    --data-urlencode 'username=admin' --data-urlencode 'password=admin123')
assert_eq "forwarded HTTPS login succeeds" "$STATUS" "302"
FORWARDED_SECURE_COOKIE=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie:/ { print }' "$TMP_DIR/forwarded-secure-headers")
assert_contains "forwarded HTTPS cookie is Secure" "$FORWARDED_SECURE_COOKIE" "; Secure"

for _ in $(seq 1 10); do
    STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
        -o /dev/null -w '%{http_code}' -X POST "http://$ADMIN_HOST:$HTTP_PORT/_authz/login" \
        --data-urlencode 'username=missing' --data-urlencode 'password=incorrect')
    [[ "$STATUS" == "302" ]] || fail "failed login before limit (got $STATUS)"
done
STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -o /dev/null -w '%{http_code}' -X POST "http://$ADMIN_HOST:$HTTP_PORT/_authz/login" \
    --data-urlencode 'username=missing' --data-urlencode 'password=incorrect')
assert_eq "login attempts are rate limited" "$STATUS" "429"

printf '\nAll %d authz gateway checks passed.\n' "$PASS"
