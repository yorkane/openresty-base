#!/usr/bin/env bash
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${OPENRESTY_TEST_IMAGE:-ghcr.io/yorkane/openresty-base:latest}
CONTAINER_NAME="authz-gateway-test-$$"
RELAY_CONTAINER_NAME=""
TMP_DIR=$(mktemp -d)
PASS=0
MOCK_PID=""
REMOTE_PID=""
NOCO_PID=""
WS_PID=""
TLS_PID=""

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
TLS_PORT=$(free_port)
RELAY_HTTP_PORT=$(free_port)
RELAY_HTTPS_PORT=$(free_port)
REMOTE_PORT=$(free_port)
REMOTE_IP=$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("192.0.2.1", 9))
    print(s.getsockname()[0])
finally:
    s.close()
PY
)
[[ "$REMOTE_IP" != 127.* ]] || { printf 'FAIL: no non-loopback IPv4 address available\n' >&2; exit 1; }
DYNAMIC_HOST="${UPSTREAM_PORT}-dynamic.test.example"
POLICY_OBJECT="/${UPSTREAM_PORT}/*"

cleanup() {
    docker exec "$CONTAINER_NAME" chmod -R a+rwx /data >/dev/null 2>&1 || true
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    if [[ -n "$RELAY_CONTAINER_NAME" ]]; then
        docker exec "$RELAY_CONTAINER_NAME" chmod -R a+rwx /data >/dev/null 2>&1 || true
        docker rm -f "$RELAY_CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    if [[ -n "$MOCK_PID" ]]; then kill "$MOCK_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "$REMOTE_PID" ]]; then kill "$REMOTE_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "$NOCO_PID" ]]; then kill "$NOCO_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "$WS_PID" ]]; then kill "$WS_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "$TLS_PID" ]]; then kill "$TLS_PID" >/dev/null 2>&1 || true; fi
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

TLS_CERT="$TMP_DIR/mock-upstream-cert.pem"
TLS_KEY="$TMP_DIR/mock-upstream-key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS_KEY" -out "$TLS_CERT" \
    -days 1 -subj '/CN=127.0.0.1' >/dev/null 2>&1 || fail "unable to create TLS mock certificate"
RELAY_SECRET=$(openssl rand -hex 32)
RELAY_BUSINESS_NAME="business1"
HUB_HOST="hub.test.example"
RELAY_HOST="relay2.test.example"

python3 "$REPO_DIR/test/mock_http.py" "$UPSTREAM_PORT" >"$TMP_DIR/mock.log" 2>&1 &
MOCK_PID=$!
python3 "$REPO_DIR/test/mock_http.py" "$REMOTE_PORT" 0.0.0.0 hello-from-remote-ip >"$TMP_DIR/remote.log" 2>&1 &
REMOTE_PID=$!
python3 "$REPO_DIR/test/mock_nocobase.py" "$NOCO_PORT" \
    "http://admin.test.example:$HTTP_PORT/_authz/oauth/callback" >"$TMP_DIR/nocobase.log" 2>&1 &
NOCO_PID=$!
python3 "$REPO_DIR/test/mock_websocket.py" "$WS_PORT" >"$TMP_DIR/websocket.log" 2>&1 &
WS_PID=$!
python3 "$REPO_DIR/test/mock_https.py" "$TLS_PORT" "$TLS_CERT" "$TLS_KEY" >"$TMP_DIR/https-mock.log" 2>&1 &
TLS_PID=$!
for _ in $(seq 1 30); do
    curl -kfsS --max-time 1 "https://127.0.0.1:$TLS_PORT/" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -kfsS --max-time 2 "https://127.0.0.1:$TLS_PORT/" >/dev/null \
    || fail "mock HTTPS upstream did not start"
for _ in $(seq 1 30); do
    curl -fsS --max-time 1 "http://127.0.0.1:$UPSTREAM_PORT/" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -fsS --max-time 2 "http://127.0.0.1:$UPSTREAM_PORT/" >/dev/null || fail "mock upstream did not start"
MOCK_BODY=$(curl -fsS --max-time 2 "http://127.0.0.1:$UPSTREAM_PORT/")
for _ in $(seq 1 30); do
    curl -fsS --max-time 1 "http://$REMOTE_IP:$REMOTE_PORT/" >/dev/null 2>&1 && break
    sleep 0.1
done
REMOTE_BODY=$(curl -fsS --max-time 2 "http://$REMOTE_IP:$REMOTE_PORT/") || fail "remote IP mock upstream did not start"
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
    "$(grep -c 'include server.conf;' "$REPO_DIR/conf/nginx.conf.template")" "2"
ENTRYPOINT_SOURCE=$(cat "$REPO_DIR/docker-entrypoint.sh")
assert_contains "entrypoint renders shared server configuration" "$ENTRYPOINT_SOURCE" \
    'render_template "$SERVER_TEMPLATE_FILE" "$NGINX_CONF_DIR/server.conf"'
assert_contains "WebSocket origin host forwarding" "$SERVER_TEMPLATE" \
    'proxy_set_header X-Forwarded-Host  $authz_proxy_forwarded_host;'
assert_contains "upstream Host preserves external request host" "$SERVER_TEMPLATE" \
    'proxy_set_header Host              $authz_upstream_host;'
assert_contains "binding controls forwarded protocol" "$SERVER_TEMPLATE" \
    'proxy_set_header X-Forwarded-Proto $authz_forwarded_proto;'
assert_contains "binding controls forwarded port" "$SERVER_TEMPLATE" \
    'proxy_set_header X-Forwarded-Port  $authz_forwarded_port;'
assert_contains "binding controls upstream Origin" "$SERVER_TEMPLATE" \
    'proxy_set_header Origin            $authz_origin;'
assert_not_contains "upstream Host does not use internal proxy target" "$SERVER_TEMPLATE" \
    'proxy_set_header Host              $proxy_host;'
assert_contains "WebSocket buffering disabled" "$SERVER_TEMPLATE" 'proxy_buffering off;'
assert_contains "WebSocket idle timeout extended" "$SERVER_TEMPLATE" 'proxy_read_timeout 3600s;'
assert_contains "API key is stripped before proxying" "$SERVER_TEMPLATE" \
    'proxy_set_header X-Authz-Key       "";'
AUTHZ_INIT_SOURCE=$(cat "$REPO_DIR/lualib/resty/authz/init.lua")
assert_contains "gateway chooses configured upstream scheme" "$AUTHZ_INIT_SOURCE" \
    'local scheme = binding and binding.upstream_scheme or "http"'
assert_not_contains "gateway does not derive upstream scheme from listener" "$AUTHZ_INIT_SOURCE" \
    'ngx.var.scheme .. "://"'
assert_contains "gateway supports upstream SSL verification" "$SERVER_TEMPLATE" \
    'proxy_ssl_verify on;'
assert_contains "gateway has private insecure HTTPS proxy location" "$SERVER_TEMPLATE" \
    'location @authz_proxy_insecure {'
assert_contains "gateway configures upstream SNI" "$SERVER_TEMPLATE" \
    'proxy_ssl_name $authz_upstream_ssl_name;'
assert_contains "gateway configures upstream CA bundle" "$SERVER_TEMPLATE" \
    'proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;'
assert_contains "gateway preserves query when rewriting upstream path" "$AUTHZ_INIT_SOURCE" \
    'local query = ngx.var.args'
NGINX_TEMPLATE=$(cat "$REPO_DIR/conf/nginx.conf.template")
assert_contains "database cache shared dictionary configured" "$NGINX_TEMPLATE" \
    'lua_shared_dict authz_db_cache 10m;'
USERS_SOURCE=$(cat "$REPO_DIR/admin/apps/users.html")
assert_contains "password form asks for confirmation" "$USERS_SOURCE" 'passwordForm.newpw_confirm'
assert_contains "password form validates confirmation" "$USERS_SOURCE" 'matchingPassword'
SERVICE_SOURCE=$(cat "$REPO_DIR/lualib/resty/authz/api/service.lua")
assert_contains "password API validates confirmation" "$SERVICE_SOURCE" '两次输入的新密码不一致'

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
connection.execute("""CREATE TABLE bindings(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    port INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    websocket INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    menu_name TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
)""")
connection.execute("""INSERT INTO bindings(domain, port, enabled, created_at)
    VALUES ('legacy.test.example', 2998, 0, 1)
""")
connection.execute("""CREATE TABLE api_keys(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'api' CHECK(role = 'api'),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
)""")
connection.commit()
connection.close()
PY
mkdir -p "$TMP_DIR/templates"
cp "$REPO_DIR/conf/nginx.conf.template" "$TMP_DIR/templates/nginx.conf.template"
{
    printf '# runtime-template-v1\n'
    cat "$REPO_DIR/conf/server.conf.template"
} > "$TMP_DIR/templates/server.conf.template"
docker run -d \
    --name "$CONTAINER_NAME" \
    --network host \
    -e NGINX_WORKER_PROCESSES=1 \
    -e AUTHZ_HTTP_PORT="$HTTP_PORT" \
    -e AUTHZ_HTTPS_PORT="$HTTPS_PORT" \
    -e "AUTHZ_HOST_URL=http://admin.test.example:$HTTP_PORT" \
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
    -e "AUTHZ_OAUTH_RELAY_SECRET=$RELAY_SECRET" \
    -e "AUTHZ_OAUTH_RELAY_CLIENTS=$RELAY_BUSINESS_NAME|http://relay2.test.example:$RELAY_HTTP_PORT/_authz/oauth/callback" \
    -e OPENRESTY_TEMPLATE_DIR=/etc/openresty/templates \
    -v "$TMP_DIR/data:/data" \
    -v "$REPO_DIR/admin:/usr/local/openresty/nginx/html/admin:ro" \
    -v "$TMP_DIR/templates:/etc/openresty/templates:ro" \
    -v "$REPO_DIR/docker-entrypoint.sh:/docker-entrypoint.sh:ro" \
    -v "$REPO_DIR/lualib:/usr/local/openresty/site/lualib:ro" \
    "$IMAGE" >/dev/null

for _ in $(seq 1 80); do
    STATUS=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/_api_/authz/v1/session" 2>/dev/null || true)
    [[ "$STATUS" == "401" ]] && break
    sleep 0.1
done
[[ "$STATUS" == "401" ]] || fail "gateway did not become ready"
docker exec "$CONTAINER_NAME" grep -q '^# runtime-template-v1$' \
    /usr/local/openresty/nginx/conf/server.conf || fail "entrypoint did not render mounted server template"
pass "entrypoint renders mounted server template"

{
    printf '# runtime-template-v2\n'
    cat "$REPO_DIR/conf/server.conf.template"
} > "$TMP_DIR/templates/server.conf.template.next"
mv "$TMP_DIR/templates/server.conf.template.next" "$TMP_DIR/templates/server.conf.template"
docker restart "$CONTAINER_NAME" >/dev/null
for _ in $(seq 1 80); do
    STATUS=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/_api_/authz/v1/session" 2>/dev/null || true)
    [[ "$STATUS" == "401" ]] && break
    sleep 0.1
done
[[ "$STATUS" == "401" ]] || fail "gateway did not become ready after runtime template change"
docker exec "$CONTAINER_NAME" grep -q '^# runtime-template-v2$' \
    /usr/local/openresty/nginx/conf/server.conf || fail "server template was not re-rendered after restart"
pass "server template changes apply without rebuilding the image"
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
BINDING_TARGET_MIGRATION=$(python3 - "$TMP_DIR/data/authz/authz.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
columns = {row[1] for row in connection.execute("PRAGMA table_info(bindings)")}
expected = {"target_ip", "upstream_host", "forwarded_host", "forwarded_proto",
            "forwarded_port", "origin_mode", "custom_origin", "simulate_local", "local_ip",
            "upstream_scheme", "upstream_ssl_verify", "upstream_path"}
row = connection.execute("""SELECT target_ip, upstream_host, forwarded_host, forwarded_proto,
    forwarded_port, origin_mode, custom_origin, simulate_local, local_ip,
    upstream_scheme, upstream_ssl_verify, upstream_path
    FROM bindings WHERE domain = 'legacy.test.example'""").fetchone()
defaults = ("127.0.0.1", "", "", "", 0, "auto", "", 0, "127.0.0.1", "http", 1, "")
print("yes" if expected.issubset(columns) and row == defaults else "no")
connection.close()
PY
)
assert_eq "legacy bindings receive safe proxy defaults" "$BINDING_TARGET_MIGRATION" "yes"
API_KEY_SCHEMA=$(python3 - "$TMP_DIR/data/authz/authz.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
columns = {row[1] for row in connection.execute("PRAGMA table_info(api_keys)")}
schema = connection.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'api_keys'").fetchone()[0]
policy = connection.execute("""SELECT 1 FROM policies
    WHERE ptype = 'p' AND v0 = 'role:api' AND v1 = '/*' AND v2 = '*'""").fetchone()
valid = columns == {"id", "name", "token_hash", "role", "enabled", "created_at", "updated_at"}
print("yes" if valid and policy and "CHECK" not in schema.upper() else "no")
connection.close()
PY
)
assert_eq "API key schema and api role policy seeded" "$API_KEY_SCHEMA" "yes"
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
    local method=$1 host=$2 path=$3 cookie=${4:-} csrf=${5:-} data=${6:-} api_key=${7:-}
    local args=(--silent --show-error --max-time 5 --request "$method" --resolve "$host:$HTTP_PORT:127.0.0.1" -H 'Accept: application/json' -D "$TMP_DIR/headers" -o "$TMP_DIR/body" -w '%{http_code}')
    [[ -n "$cookie" ]] && args+=(-H "Cookie: $(cookie_header "$cookie")")
    [[ -n "$csrf" ]] && args+=(-H "X-CSRF-Token: $csrf")
    [[ -n "$api_key" ]] && args+=(-H "x-authz-key: $api_key")
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
SECOND_BASE_HOST=app-m.w.wtvdev.com
ADMIN_COOKIE="$TMP_DIR/admin.cookie"
SECOND_BASE_COOKIE="$TMP_DIR/second-base.cookie"
BOB_COOKIE="$TMP_DIR/bob.cookie"
DYNAMIC_COOKIE="$TMP_DIR/dynamic.cookie"
APP_COOKIE="$TMP_DIR/app.cookie"
REMOTE_COOKIE="$TMP_DIR/remote.cookie"
REMOTE_DYNAMIC_COOKIE="$TMP_DIR/remote-dynamic.cookie"
SHADOW_COOKIE="$TMP_DIR/shadow.cookie"
SHADOW_DYNAMIC_COOKIE="$TMP_DIR/shadow-dynamic.cookie"
RESET_COOKIE="$TMP_DIR/reset.cookie"
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
request GET "$ADMIN_HOST" /_radmin_
assert_eq "admin URL without slash redirects" "$STATUS" "301"
ADMIN_SLASH_LOCATION=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/headers")
assert_eq "admin slash redirect stays relative" "$ADMIN_SLASH_LOCATION" "/_radmin_/"

login "$ADMIN_HOST" admin admin123 "$ADMIN_COOKIE"
HTTP_LOGIN_COOKIE=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/^[^;]+/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/login-headers")
assert_not_contains "HTTP session cookie is not Secure" "$HTTP_LOGIN_COOKIE" "; Secure"
LOGIN_COOKIES=$(cat "$TMP_DIR/login-headers")
assert_contains "cookie domain derives from request host" "$LOGIN_COOKIES" "; Domain=.test.example"
assert_contains "login clears legacy host-only session cookie" "$LOGIN_COOKIES" "authz_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
assert_contains "login clears deeper legacy domain cookie" "$LOGIN_COOKIES" "; Domain=.admin.test.example"

login "$SECOND_BASE_HOST" admin admin123 "$SECOND_BASE_COOKIE"
SECOND_BASE_ACTIVE_COOKIE=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie:/ { sub(/\r$/, ""); print; exit }' "$TMP_DIR/login-headers")
SECOND_BASE_COOKIES=$(cat "$TMP_DIR/login-headers")
assert_contains "second base domain uses its request-scoped cookie parent" "$SECOND_BASE_ACTIVE_COOKIE" "; Domain=.w.wtvdev.com"
assert_not_contains "configured fallback does not override another base domain" "$SECOND_BASE_ACTIVE_COOKIE" "; Domain=.test.example"
assert_contains "second base login clears its deeper legacy domain" "$SECOND_BASE_COOKIES" "; Domain=.app-m.w.wtvdev.com"
assert_contains "second base login clears its broader legacy parent" "$SECOND_BASE_COOKIES" "; Domain=.wtvdev.com"
for _ in $(seq 1 20); do
    request GET "$ADMIN_HOST" /_api_/authz/v1/session "$ADMIN_COOKIE"
    [[ "$STATUS" == "200" ]] && break
    sleep 0.05
done
assert_eq "session becomes available after login" "$STATUS" "200"

DUPLICATE_STATUS=$(curl -sS --max-time 5 --resolve "$ADMIN_HOST:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: authz_session=0000000000000000000000000000000000000000000000000000000000000000; $(cookie_header "$ADMIN_COOKIE")" \
    -D "$TMP_DIR/duplicate-cookie-headers" -o "$TMP_DIR/duplicate-cookie-body" -w '%{http_code}' \
    "http://$ADMIN_HOST:$HTTP_PORT/_api_/authz/v1/session")
assert_eq "duplicate session cookies select the valid session" "$DUPLICATE_STATUS" "200"
DUPLICATE_COOKIES=$(cat "$TMP_DIR/duplicate-cookie-headers")
assert_contains "duplicate session cookies are normalized to root domain" "$DUPLICATE_COOKIES" "; Domain=.test.example"
assert_contains "duplicate session cleanup expires host-only cookie" "$DUPLICATE_COOKIES" "authz_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
assert_contains "duplicate session cleanup expires deeper domain" "$DUPLICATE_COOKIES" "; Domain=.admin.test.example"

request GET "$ADMIN_HOST" /_radmin_/ "$ADMIN_COOKIE"
assert_eq "authenticated admin UI" "$STATUS" "200"
assert_contains "admin UI loads shell" "$BODY" "app-frame"
assert_contains "admin UI assembles menu with SSI" "$BODY" "id=\"admin-menu\""
assert_not_contains "admin SSI menu has no inline style" "$BODY" "<style>"
assert_not_contains "admin UI does not iframe menu" "$BODY" "menu-frame"
assert_contains "menu shows application address on hover" "$BODY" '<q-tooltip v-if="item.address"'
assert_contains "menu renders binding note below label" "$BODY" '<span v-if="item.note" class="menu-item-note">{{ item.note }}</span>'
assert_not_contains "admin shell has no no-store HTTP header" "$(cat "$TMP_DIR/headers")" "Cache-Control: no-store"
assert_contains "admin shell declares browser no-cache" "$BODY" 'http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"'
assert_contains "admin shell declares no-cache pragma" "$BODY" 'http-equiv="Pragma" content="no-cache"'
assert_contains "admin shell declares expired HTML" "$BODY" 'http-equiv="Expires" content="0"'
request GET "$ADMIN_HOST" '/_radmin_/app.css?v=6' "$ADMIN_COOKIE"
assert_eq "admin shared CSS asset" "$STATUS" "200"
assert_contains "shared CSS contains SSI menu styles" "$BODY" "#admin-menu .menu-shell"
assert_contains "shared CSS contains mini drawer styles" "$BODY" ".admin-drawer-mini #admin-menu"
request GET "$ADMIN_HOST" '/_radmin_/api.js?v=7' "$ADMIN_COOKIE"
assert_eq "admin API client asset" "$STATUS" "200"
assert_contains "admin client uses new API root" "$BODY" "/_api_/authz/v1"
assert_contains "admin API errors expose status" "$BODY" "error.status = response.status"
assert_contains "binding API supports edit" "$BODY" "values.action === 'edit'"
assert_contains "policy API supports edit" "$BODY" 'mutation('\''PATCH'\'', `/policies/${values.id}`'
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
request GET "$ADMIN_HOST" '/_radmin_/app.js?v=9' "$ADMIN_COOKIE"
assert_contains "admin redirect is limited to API 401" "$BODY" "error?.status === 401"
assert_contains "menu separates application label and note" "$BODY" "application.label || application.menu_name || application.domain"
assert_contains "menu sends application address to tooltip" "$BODY" "address: appUrl"
assert_contains "menu keeps binding notes below label" "$BODY" "note: application.binding ? application.note : ''"
assert_contains "authorization menu is admin gated" "$BODY" "if (isAdmin.value)"
assert_contains "menu reads admin status from session" "$BODY" "isAdmin.value = Boolean(session.admin)"
assert_contains "menu loads local applications" "$BODY" "window.adminApi.applications"
assert_contains "menu refreshes local applications" "$BODY" "setInterval(loadApplications, 30000)"
assert_contains "menu supports Ctrl or Command click" "$BODY" 'event?.ctrlKey || event?.metaKey'
assert_contains "menu opens Ctrl click in a new window" "$BODY" "window.open(item.app, '_blank', 'noopener,noreferrer')"
assert_contains "built-in app URLs are versioned" "$BODY" "apps/authorization.html?v=14"
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
assert_not_contains "admin application has no no-store HTTP header" "$(cat "$TMP_DIR/headers")" "Cache-Control: no-store"
assert_contains "admin application declares browser no-cache" "$BODY" 'http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"'
assert_not_contains "policy form hides the policy type switch" "$BODY" 'v-model="policyForm.ptype"'
assert_not_contains "policy form removes role assignment" "$BODY" 'roleAssignment'
assert_contains "policy form always submits P policies" "$BODY" "reactive({ ptype: 'p'"
assert_contains "policy subject uses select options" "$BODY" 'policySubjectOptions'
assert_contains "policy object uses binding options" "$BODY" 'policyObjectOptions'
assert_not_contains "policy object does not allow text input" "$BODY" 'v-model="policyForm.objectTarget" dark dense outlined use-input'
assert_not_contains "policy object does not create typed targets" "$BODY" '@new-value="addPolicyObjectTarget"'
assert_contains "policy object exposes an editable path" "$BODY" 'v-model.trim="policyForm.objectPath"'
assert_contains "policy object combines binding and path" "$BODY" 'v1: policyObjectValue.value'
assert_contains "policy selector retains existing direct ports" "$BODY" 'value: `port:${port}`'
assert_contains "policy selector identifies an exact binding" "$BODY" 'value: `binding:${binding.id}`'
assert_contains "policy submission includes the selected binding ID" "$BODY" 'values.binding_id = selected.bindingId'
assert_contains "policy table displays binding target details" "$BODY" 'class="policy-object-target"'
assert_contains "policy table marks shared port bindings" "$BODY" "props.row.object_kind === 'shared'"
assert_contains "policy table exposes an edit action" "$BODY" '@click="openEditPolicy(props.row)"'
assert_contains "policy edit action is limited to P policies" "$BODY" "isAdmin && props.row.ptype === 'p'"
assert_contains "policy edit dialog prefills existing values" "$BODY" 'function openEditPolicy (policy)'
assert_contains "policy HTTP method uses select options" "$BODY" ':options="httpActions"'
assert_contains "policy HTTP method supports multi-select" "$BODY" 'multiple use-chips emit-value map-options :options="httpActions"'
assert_contains "policy effect exposes allow radio" "$BODY" 'v-model="policyForm.eft" val="allow"'
assert_contains "policy effect exposes deny radio" "$BODY" 'v-model="policyForm.eft" val="deny"'
assert_contains "policy methods include CONNECT" "$BODY" "'CONNECT'"
assert_contains "policy methods include TRACE" "$BODY" "'TRACE'"
assert_contains "binding page supports editing" "$BODY" "openEditBinding"
assert_contains "binding form supports saving" "$BODY" "saveBindingForm"
assert_contains "binding form defaults to local target IP" "$BODY" "target_ip: '127.0.0.1'"
assert_contains "binding table displays target IP" "$BODY" 'body-cell-target_ip'
assert_contains "binding form exposes upstream Host" "$BODY" 'bindingForm.upstream_host'
assert_contains "binding form exposes forwarded Host" "$BODY" 'bindingForm.forwarded_host'
assert_contains "binding form exposes Origin policy" "$BODY" 'bindingForm.origin_mode'
assert_contains "binding form supports local request simulation" "$BODY" 'bindingForm.simulate_local'
assert_contains "binding form exposes upstream scheme" "$BODY" 'bindingForm.upstream_scheme'
assert_contains "binding form exposes upstream SSL verification" "$BODY" 'bindingForm.upstream_ssl_verify'
assert_contains "binding form exposes upstream path rewrite" "$BODY" 'bindingForm.upstream_path'
assert_contains "binding form keeps proxy settings compact" "$BODY" 'q-expansion-item v-model="bindingAdvancedOpen"'
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

request GET "$ADMIN_HOST" /_api_/authz/v1/api-keys
assert_eq "API key management requires a session" "$STATUS" "401"
request POST "$ADMIN_HOST" /_api_/authz/v1/api-keys "$ADMIN_COOKIE" "$CSRF" '{"name":"agent-test"}'
assert_eq "admin creates an API key" "$STATUS" "201"
API_KEY_ID=$(jq -er '.data.id' "$TMP_DIR/body")
API_KEY_TOKEN=$(jq -er '.data.token' "$TMP_DIR/body")
jq '.data.token = "[REDACTED]"' "$TMP_DIR/body" >"$TMP_DIR/body-redacted"
mv "$TMP_DIR/body-redacted" "$TMP_DIR/body"
BODY=$(<"$TMP_DIR/body")
[[ "$API_KEY_TOKEN" =~ ^ak_[a-f0-9]{64}$ ]] || fail "created API key has an invalid format"
pass "raw API key is returned once with a stable format"
assert_json "API key defaults to the api role" '.data.role' "api"

request GET "$ADMIN_HOST" /_api_/authz/v1/api-keys "$ADMIN_COOKIE"
assert_eq "admin lists API keys" "$STATUS" "200"
assert_json "API key list never returns raw token" '.data[0] | has("token") | tostring' "false"
assert_json "API key list never returns token hash" '.data[0] | has("token_hash") | tostring' "false"
request POST "$ADMIN_HOST" /_api_/authz/v1/api-keys "$ADMIN_COOKIE" "$CSRF" \
    '{"name":"invalid-role-agent","role":"root"}'
assert_eq "unsupported API key role is rejected" "$STATUS" "422"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "" "" "" "$API_KEY_TOKEN"
assert_eq "API key reads its service identity" "$STATUS" "200"
assert_json "API key session identifies machine authentication" '.data.auth_type' "api_key"
assert_json "API key session exposes assigned role" '.data.roles | join(",")' "api"
assert_json "api role is not admin" '.data.admin | tostring' "false"
request DELETE "$ADMIN_HOST" /_api_/authz/v1/session "" "" "" "$API_KEY_TOKEN"
assert_eq "API key cannot perform browser logout" "$STATUS" "403"
request GET "$ADMIN_HOST" /_api_/authz/v1/applications "" "" "" "$API_KEY_TOKEN"
assert_eq "API role can read application entries" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "" "" "" "$API_KEY_TOKEN"
assert_eq "API role cannot manage users or roles" "$STATUS" "403"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "" "" '{"ptype":"p","v0":"role:api","v1":"/*","v2":"*"}' "$API_KEY_TOKEN"
assert_eq "API role cannot modify core authorization" "$STATUS" "403"
request GET "$ADMIN_HOST" /_api_/authz/v1/api-keys "" "" "" "$API_KEY_TOKEN"
assert_eq "API role cannot manage API keys" "$STATUS" "403"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$ADMIN_COOKIE" "" "" "ak_invalid"
assert_eq "invalid API key never falls back to an admin cookie" "$STATUS" "401"

request POST "$ADMIN_HOST" /_api_/authz/v1/applications "" "" \
    "{\"domain\":\"agent.test.example\",\"port\":$UPSTREAM_PORT,\"menu_name\":\"Agent test\"}" "$API_KEY_TOKEN"
assert_eq "API role creates a domain binding without CSRF" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
API_BINDING_ID=$(jq -er '.data.bindings[] | select(.domain == "agent.test.example") | .id' "$TMP_DIR/body")
request GET agent.test.example /identity "" "" "" "$API_KEY_TOKEN"
assert_eq "API key accesses a proxied HTTP service" "$STATUS" "200"
assert_json "upstream receives API key display name" '.user' "agent-test"
assert_json "upstream receives API key source" '.source' "api-key"
assert_json "upstream receives API key principal" ".identity" "api-key:$API_KEY_ID"
assert_json "raw API key is stripped from upstream" '.authz_key == null | tostring' "true"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" \
    "{\"ptype\":\"p\",\"v0\":\"role:api\",\"v1\":\"/$UPSTREAM_PORT/blocked\",\"v2\":\"GET\",\"eft\":\"deny\"}"
assert_eq "admin can constrain the API role with a deny policy" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
API_DENY_POLICY_ID=$(jq -er --arg object "/$UPSTREAM_PORT/blocked" \
    '.data.policies[] | select(.v0 == "role:api" and .v1 == $object) | .id' "$TMP_DIR/body")
request GET agent.test.example /blocked "" "" "" "$API_KEY_TOKEN"
assert_eq "API key obeys role:api Casbin deny policy" "$STATUS" "403"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/policies/$API_DENY_POLICY_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "admin removes the API role deny policy" "$STATUS" "200"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$API_BINDING_ID" "" "" \
    '{"menu_name":"forbidden"}' "$API_KEY_TOKEN"
assert_eq "API role cannot modify an existing binding" "$STATUS" "403"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$API_KEY_ID" "$ADMIN_COOKIE" "$CSRF" '{"role":"viewer"}'
assert_eq "admin changes an API key role" "$STATUS" "200"
request GET agent.test.example / "" "" "" "$API_KEY_TOKEN"
assert_eq "viewer API key loses api proxy permission immediately" "$STATUS" "403"
request POST "$ADMIN_HOST" /_api_/authz/v1/applications "" "" \
    "{\"domain\":\"viewer-denied.test.example\",\"port\":$UPSTREAM_PORT}" "$API_KEY_TOKEN"
assert_eq "viewer API key cannot create a binding" "$STATUS" "403"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$API_KEY_ID" "$ADMIN_COOKIE" "$CSRF" '{"role":"api"}'
assert_eq "admin restores the API key role" "$STATUS" "200"
request GET agent.test.example / "" "" "" "$API_KEY_TOKEN"
assert_eq "restored api role invalidates proxy authorization cache" "$STATUS" "200"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$API_KEY_ID" "$ADMIN_COOKIE" "$CSRF" '{"enabled":false}'
assert_eq "admin disables an API key" "$STATUS" "200"
request GET agent.test.example /identity "" "" "" "$API_KEY_TOKEN"
assert_eq "disabled API key is rejected immediately" "$STATUS" "401"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$API_KEY_ID" "$ADMIN_COOKIE" "$CSRF" '{"enabled":true}'
assert_eq "admin re-enables an API key" "$STATUS" "200"
request GET agent.test.example / "" "" "" "$API_KEY_TOKEN"
assert_eq "re-enabled API key invalidates authorization cache" "$STATUS" "200"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$API_KEY_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "admin deletes an API key" "$STATUS" "200"
request GET agent.test.example / "" "" "" "$API_KEY_TOKEN"
assert_eq "deleted API key is rejected immediately" "$STATUS" "401"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/applications/$API_BINDING_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "admin removes the API-created binding" "$STATUS" "200"
unset API_KEY_TOKEN

request POST "$ADMIN_HOST" /_api_/authz/v1/api-keys "$ADMIN_COOKIE" "$CSRF" \
    '{"name":"admin-agent","role":"admin"}'
assert_eq "admin creates an admin-role API key" "$STATUS" "201"
ADMIN_API_KEY_ID=$(jq -er '.data.id' "$TMP_DIR/body")
ADMIN_API_KEY_TOKEN=$(jq -er '.data.token' "$TMP_DIR/body")
jq '.data.token = "[REDACTED]"' "$TMP_DIR/body" >"$TMP_DIR/body-redacted"
mv "$TMP_DIR/body-redacted" "$TMP_DIR/body"
BODY=$(<"$TMP_DIR/body")
[[ "$ADMIN_API_KEY_TOKEN" =~ ^ak_[a-f0-9]{64}$ ]] || fail "created admin API key has an invalid format"
pass "admin-role API key is returned once"

request GET "$ADMIN_HOST" /_api_/authz/v1/session "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key reads its identity" "$STATUS" "200"
assert_json "admin API key exposes admin role" '.data.roles | join(",")' "admin"
assert_json "admin API key exposes admin capability" '.data.admin | tostring' "true"
assert_json "admin API key uses canonical service principal" ".data.identity" "api-key:$ADMIN_API_KEY_ID"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key reads user management" "$STATUS" "200"
request POST "$ADMIN_HOST" /_api_/authz/v1/users "" "" \
    '{"username":"api-managed","password":"password123","roles":["user"]}' "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key creates a user without CSRF" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "" "" "" "$ADMIN_API_KEY_TOKEN"
API_MANAGED_USER_ID=$(jq -er '.data.users[] | select(.username == "api-managed") | .id' "$TMP_DIR/body")
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/users/$API_MANAGED_USER_ID" "" "" \
    '{"roles":["viewer"]}' "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key updates a user" "$STATUS" "200"
request PUT "$ADMIN_HOST" "/_api_/authz/v1/users/$API_MANAGED_USER_ID/password" "" "" \
    '{"password":"password456"}' "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key resets a user password" "$STATUS" "200"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/users/$API_MANAGED_USER_ID" "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key deletes a user" "$STATUS" "200"

request POST "$ADMIN_HOST" /_api_/authz/v1/applications "" "" \
    "{\"domain\":\"admin-agent.test.example\",\"port\":$UPSTREAM_PORT}" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key creates a binding" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key reads core authorization" "$STATUS" "200"
ADMIN_API_BINDING_ID=$(jq -er '.data.bindings[] | select(.domain == "admin-agent.test.example") | .id' "$TMP_DIR/body")
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$ADMIN_API_BINDING_ID" "" "" \
    '{"menu_name":"Admin agent"}' "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key updates a binding" "$STATUS" "200"
request GET admin-agent.test.example /identity "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key accesses proxy targets through role:admin" "$STATUS" "200"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "" "" \
    "{\"ptype\":\"p\",\"v0\":\"role:viewer\",\"v1\":\"/$UPSTREAM_PORT/admin-agent\",\"v2\":\"GET\",\"eft\":\"allow\"}" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key creates an authorization policy" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "" "" "" "$ADMIN_API_KEY_TOKEN"
ADMIN_API_POLICY_ID=$(jq -er --arg object "/$UPSTREAM_PORT/admin-agent" \
    '.data.policies[] | select(.v0 == "role:viewer" and .v1 == $object) | .id' "$TMP_DIR/body")
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/policies/$ADMIN_API_POLICY_ID" "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key deletes an authorization policy" "$STATUS" "200"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/applications/$ADMIN_API_BINDING_ID" "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key deletes a binding" "$STATUS" "200"

request POST "$ADMIN_HOST" /_api_/authz/v1/api-keys "" "" \
    '{"name":"viewer-agent","role":"viewer"}' "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key creates another role-scoped key" "$STATUS" "201"
VIEWER_API_KEY_ID=$(jq -er '.data.id' "$TMP_DIR/body")
VIEWER_API_KEY_TOKEN=$(jq -er '.data.token' "$TMP_DIR/body")
jq '.data.token = "[REDACTED]"' "$TMP_DIR/body" >"$TMP_DIR/body-redacted"
mv "$TMP_DIR/body-redacted" "$TMP_DIR/body"
BODY=$(<"$TMP_DIR/body")
request GET "$ADMIN_HOST" /_api_/authz/v1/session "" "" "" "$VIEWER_API_KEY_TOKEN"
assert_json "viewer API key receives viewer role" '.data.roles | join(",")' "viewer"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "" "" "" "$VIEWER_API_KEY_TOKEN"
assert_eq "viewer API key cannot use admin APIs" "$STATUS" "403"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$VIEWER_API_KEY_ID" "" "" \
    '{"role":"user"}' "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key changes another key role" "$STATUS" "200"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$VIEWER_API_KEY_ID" "" "" \
    '{"role":"root"}' "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key cannot assign an unknown role" "$STATUS" "422"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "" "" "" "$VIEWER_API_KEY_TOKEN"
assert_json "API key role update is immediately visible" '.data.roles | join(",")' "user"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$VIEWER_API_KEY_ID" "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key deletes another key" "$STATUS" "200"
unset VIEWER_API_KEY_TOKEN

request PUT "$ADMIN_HOST" /_api_/authz/v1/me/password "" "" \
    '{"old_password":"ignored","new_password":"ignored"}' "$ADMIN_API_KEY_TOKEN"
assert_eq "API key cannot use personal password endpoint" "$STATUS" "403"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/api-keys/$ADMIN_API_KEY_ID" "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "admin API key can revoke itself" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "" "" "" "$ADMIN_API_KEY_TOKEN"
assert_eq "self-revoked admin API key is rejected" "$STATUS" "401"
unset ADMIN_API_KEY_TOKEN

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
request POST "$ADMIN_HOST" /_api_/authz/v1/users "$ADMIN_COOKIE" "$CSRF" '{"username":"api-human","password":"password123","roles":["api"]}'
assert_eq "api role cannot be assigned to a human user" "$STATUS" "422"

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
BOB_CSRF=$(jq -er '.data.csrf' "$TMP_DIR/body")
login "$DYNAMIC_HOST" bob bob654321 "$DYNAMIC_COOKIE"
request PUT "$ADMIN_HOST" /_api_/authz/v1/me/password "$BOB_COOKIE" "$BOB_CSRF" \
    '{"oldpw":"bob654321","newpw":"changed123","newpw_confirm":"different123"}'
assert_eq "mismatched password confirmation rejected" "$STATUS" "422"
assert_json "password mismatch error" '.error.message' "两次输入的新密码不一致"
request PUT "$ADMIN_HOST" /_api_/authz/v1/me/password "$BOB_COOKIE" "$BOB_CSRF" \
    '{"oldpw":"bob654321","newpw":"changed123","newpw_confirm":"changed123"}'
assert_eq "password change succeeds with matching confirmation" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$BOB_COOKIE"
assert_eq "password change invalidates current session" "$STATUS" "401"
request GET "$DYNAMIC_HOST" /_api_/authz/v1/session "$DYNAMIC_COOKIE"
assert_eq "password change invalidates other sessions" "$STATUS" "401"
login "$ADMIN_HOST" bob changed123 "$BOB_COOKIE"
request GET "$ADMIN_HOST" /_api_/authz/v1/users "$BOB_COOKIE"
assert_eq "non-admin users API denied" "$STATUS" "403"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$BOB_COOKIE"
assert_eq "non-admin authorization API denied" "$STATUS" "403"

login "$DYNAMIC_HOST" bob changed123 "$DYNAMIC_COOKIE"
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
CUSTOM_PATH_OBJECT="/$UPSTREAM_PORT/api/*"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:viewer\",\"v1\":\"$CUSTOM_PATH_OBJECT\",\"v2\":[\"GET\"],\"eft\":\"allow\"}"
assert_eq "create access policy with an editable binding path" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_json "custom binding path is stored as the final policy object" ".data.policies[] | select(.v0 == \"role:viewer\" and .v1 == \"$CUSTOM_PATH_OBJECT\") | .v1" "$CUSTOM_PATH_OBJECT"
CUSTOM_PATH_POLICY_ID=$(jq -er --arg object "$CUSTOM_PATH_OBJECT" '.data.policies[] | select(.v0 == "role:viewer" and .v1 == $object) | .id' "$TMP_DIR/body")
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/policies/$CUSTOM_PATH_POLICY_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "delete custom binding path policy" "$STATUS" "200"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:user\",\"v1\":\"$POLICY_OBJECT\",\"v2\":[\"GET\",\"BREW\"],\"eft\":\"allow\"}"
assert_eq "unknown HTTP method rejected" "$STATUS" "422"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:auditor\",\"v1\":\"$POLICY_OBJECT\",\"v2\":\"GET\",\"eft\":\"allow\"}"
assert_eq "unknown policy role rejected" "$STATUS" "422"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" '{"ptype":"p","v0":"role:user","v1":"/not-a-port/public/*","v2":"GET","eft":"allow"}'
assert_eq "malformed policy object is rejected" "$STATUS" "422"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_eq "authorization API" "$STATUS" "200"
assert_json "minimum dynamic port clamped" '.data.port_min | tostring' "2000"
assert_json "local user policy identity option" '.data.policy_users[] | select(.username == "admin" and .source == "local") | .identity' "user:local:admin"
assert_json "policy role options" '.data.policy_roles | index("user") != null | tostring' "true"
assert_json "policy role catalog includes service api role" '.data.policy_roles | join(",")' "admin,staff,user,viewer,api"
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
assert_json "upstream receives external dynamic Host" '.host' "$DYNAMIC_HOST:$HTTP_PORT"
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

request POST "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"invalid-target.test.example\",\"target_ip\":\"http://127.0.0.1\",\"port\":$UPSTREAM_PORT}"
assert_eq "binding rejects a URL as target IP" "$STATUS" "422"
request POST "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"fixed.test.example\",\"port\":$UPSTREAM_PORT,\"enabled\":true,\"note\":\"test\"}"
assert_eq "create application" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE"
assert_json "binding application keeps its menu label" '.data[] | select(.domain == "fixed.test.example") | .label' "fixed.test.example"
assert_json "binding application exposes its note" '.data[] | select(.domain == "fixed.test.example") | .note' "test"
assert_json "binding application is marked explicit" '.data[] | select(.domain == "fixed.test.example") | .binding | tostring' "true"
request GET "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE"
assert_json "applications API exposes target IP" '.data[] | select(.domain == "fixed.test.example") | .target_ip' "127.0.0.1"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
APP_ID=$(jq -er '.data.bindings[] | select(.domain == "fixed.test.example") | .id' "$TMP_DIR/body")
assert_json "binding defaults to the local target IP" '.data.bindings[] | select(.domain == "fixed.test.example") | .target_ip' "127.0.0.1"
assert_json "binding defaults to request Host forwarding" '.data.bindings[] | select(.domain == "fixed.test.example") | .upstream_host' ""
assert_json "binding defaults to automatic Origin handling" '.data.bindings[] | select(.domain == "fixed.test.example") | .origin_mode' "auto"
assert_json "binding defaults to normal client identity" '.data.bindings[] | select(.domain == "fixed.test.example") | .simulate_local | tostring' "0"
assert_json "binding defaults to HTTP upstream" '.data.bindings[] | select(.domain == "fixed.test.example") | .upstream_scheme' "http"
assert_json "binding defaults to SSL verification" '.data.bindings[] | select(.domain == "fixed.test.example") | .upstream_ssl_verify | tostring' "1"
assert_json "binding defaults to original upstream path" '.data.bindings[] | select(.domain == "fixed.test.example") | .upstream_path' ""
assert_json "existing port policy is associated with its binding" ".data.policies[] | select(.v0 == \"role:user\" and .v1 == \"$POLICY_OBJECT\") | .object_kind" "binding"
assert_json "associated policy exposes the binding domain" ".data.policies[] | select(.v0 == \"role:user\" and .v1 == \"$POLICY_OBJECT\") | .binding_matches[0].domain" "fixed.test.example"
assert_json "associated policy exposes the binding target" ".data.policies[] | select(.v0 == \"role:user\" and .v1 == \"$POLICY_OBJECT\") | .binding_matches[0].target_ip" "127.0.0.1"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:viewer\",\"v1\":\"/$REMOTE_PORT/public/*\",\"binding_id\":$APP_ID,\"v2\":\"GET\",\"eft\":\"allow\"}"
assert_eq "policy binding and object port mismatch is rejected" "$STATUS" "422"
BOUND_PATH_OBJECT="/$UPSTREAM_PORT/public/*"
request POST "$ADMIN_HOST" /_api_/authz/v1/policies "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:viewer\",\"v1\":\"$BOUND_PATH_OBJECT\",\"binding_id\":$APP_ID,\"v2\":\"GET\",\"eft\":\"allow\"}"
assert_eq "create policy for the selected binding" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_json "selected binding policy keeps its path" ".data.policies[] | select(.v0 == \"role:viewer\" and .v1 == \"$BOUND_PATH_OBJECT\") | .object_path" "/public/*"
assert_json "selected binding policy resolves to one binding" ".data.policies[] | select(.v0 == \"role:viewer\" and .v1 == \"$BOUND_PATH_OBJECT\") | .binding_matches | length | tostring" "1"
assert_json "selected binding policy exposes target address" ".data.policies[] | select(.v0 == \"role:viewer\" and .v1 == \"$BOUND_PATH_OBJECT\") | .binding_matches[0] | \"\(.target_ip):\(.port)\"" "127.0.0.1:$UPSTREAM_PORT"
BOUND_PATH_POLICY_ID=$(jq -er --arg object "$BOUND_PATH_OBJECT" '.data.policies[] | select(.v0 == "role:viewer" and .v1 == $object) | .id' "$TMP_DIR/body")
UPDATED_BOUND_PATH_OBJECT="/$UPSTREAM_PORT/private/*"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/policies/$BOUND_PATH_POLICY_ID" "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:viewer\",\"v1\":\"$UPDATED_BOUND_PATH_OBJECT\",\"binding_id\":$APP_ID,\"v2\":[\"PATCH\",\"POST\"],\"eft\":\"deny\"}"
assert_eq "update selected binding policy" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_json "updated policy stores the new path" ".data.policies[] | select(.id == $BOUND_PATH_POLICY_ID) | .v1" "$UPDATED_BOUND_PATH_OBJECT"
assert_json "updated policy normalizes methods" ".data.policies[] | select(.id == $BOUND_PATH_POLICY_ID) | .action" "POST,PATCH"
assert_json "updated policy stores deny effect" ".data.policies[] | select(.id == $BOUND_PATH_POLICY_ID) | .effect" "deny"
assert_json "updated policy retains binding details" ".data.policies[] | select(.id == $BOUND_PATH_POLICY_ID) | .binding_matches[0].domain" "fixed.test.example"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/policies/$BOUND_PATH_POLICY_ID" "$ADMIN_COOKIE" "$CSRF" "{\"ptype\":\"p\",\"v0\":\"role:viewer\",\"v1\":\"/$REMOTE_PORT/private/*\",\"binding_id\":$APP_ID,\"v2\":\"GET\",\"eft\":\"allow\"}"
assert_eq "policy edit rejects binding and port mismatch" "$STATUS" "422"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_json "rejected policy edit preserves previous object" ".data.policies[] | select(.id == $BOUND_PATH_POLICY_ID) | .v1" "$UPDATED_BOUND_PATH_OBJECT"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/policies/$BOUND_PATH_POLICY_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "delete selected binding policy" "$STATUS" "200"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"edited.test.example\",\"target_ip\":\"$REMOTE_IP\",\"port\":$REMOTE_PORT,\"enabled\":true,\"note\":\"edited\"}"
assert_eq "edit binding fields" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
assert_json "edited binding domain" '.data.bindings[] | select(.domain == "edited.test.example") | .domain' "edited.test.example"
assert_json "edited binding target IP" '.data.bindings[] | select(.domain == "edited.test.example") | .target_ip' "$REMOTE_IP"
assert_json "edited binding port" '.data.bindings[] | select(.domain == "edited.test.example") | .port | tostring' "$REMOTE_PORT"
assert_json "edited binding note" '.data.bindings[] | select(.domain == "edited.test.example") | .note' "edited"
request GET edited.test.example / "$ADMIN_COOKIE"
assert_eq "binding proxies another IP" "$STATUS" "200"
assert_eq "remote IP proxy body" "$BODY" "$REMOTE_BODY"
request GET edited.test.example /identity "$ADMIN_COOKIE"
assert_json "remote upstream receives external binding Host" '.host' "edited.test.example:$HTTP_PORT"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"target_ip":"999.1.1.1"}'
assert_eq "edit binding rejects invalid target IP" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" "{\"port\":1999}"
assert_eq "edit binding rejects port below minimum" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" "{\"domain\":\"fixed.test.example\",\"target_ip\":\"127.0.0.1\",\"port\":$UPSTREAM_PORT,\"enabled\":true,\"note\":\"test\"}"
assert_eq "restore edited binding" "$STATUS" "200"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
APP_ID=$(jq -er '.data.bindings[] | select(.domain == "fixed.test.example") | .id' "$TMP_DIR/body")

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_path":"/backend"}'
assert_eq "save upstream path rewrite" "$STATUS" "200"
request GET fixed.test.example '/path-probe?check=1' "$ADMIN_COOKIE"
assert_eq "upstream path rewrite reaches service" "$STATUS" "200"
assert_eq "upstream path rewrite replaces path and keeps query" "$BODY" "/backend?check=1"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_host":null,"forwarded_host":null,"forwarded_proto":null,"forwarded_port":null,"origin_mode":null,"custom_origin":null,"simulate_local":null,"local_ip":null,"upstream_path":null}'
assert_eq "binding accepts null as an automatic proxy value" "$STATUS" "200"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_host":"http://bad.example"}'
assert_eq "binding rejects URL syntax in upstream Host" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_host":"safe.example\nX-Bad: yes"}'
assert_eq "binding rejects header injection in upstream Host" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"forwarded_proto":"ftp"}'
assert_eq "binding rejects unsupported forwarded protocol" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_scheme":"ftp"}'
assert_eq "binding rejects unsupported upstream scheme" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_path":"https://backend.example"}'
assert_eq "binding rejects URL as upstream path rewrite" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"forwarded_port":70000}'
assert_eq "binding rejects invalid forwarded port" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"origin_mode":"custom","custom_origin":""}'
assert_eq "custom Origin mode requires a value" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"origin_mode":"custom","custom_origin":"https://public.example/path"}'
assert_eq "binding rejects Origin paths" "$STATUS" "422"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"simulate_local":true,"local_ip":"local-machine"}'
assert_eq "local simulation rejects invalid source IP" "$STATUS" "422"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_host":"app.internal:2078","forwarded_host":"public.example:99","forwarded_proto":"https","forwarded_port":99,"origin_mode":"custom","custom_origin":"https://public.example:99","simulate_local":false,"upstream_path":""}'
assert_eq "save custom proxy headers" "$STATUS" "200"
request GET fixed.test.example /identity "$ADMIN_COOKIE"
assert_eq "custom proxy request reaches upstream" "$STATUS" "200"
assert_json "custom upstream Host reaches service" '.host' "app.internal:2078"
assert_json "custom forwarded Host reaches service" '.forwarded_host' "public.example:99"
assert_json "custom forwarded protocol reaches service" '.forwarded_proto' "https"
assert_json "custom forwarded port reaches service" '.forwarded_port' "99"
assert_json "custom Origin reaches service" '.origin' "https://public.example:99"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_host":"","forwarded_host":"","forwarded_proto":"","forwarded_port":0,"origin_mode":"auto","custom_origin":"","simulate_local":true,"local_ip":"192.168.50.10"}'
assert_eq "enable local request simulation" "$STATUS" "200"
STATUS=$(curl -sS --max-time 5 --resolve "fixed.test.example:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" \
    -H "Origin: http://fixed.test.example:$HTTP_PORT" \
    -o "$TMP_DIR/body" -w '%{http_code}' "http://fixed.test.example:$HTTP_PORT/identity")
assert_eq "local simulation request reaches upstream" "$STATUS" "200"
assert_json "local simulation uses target Host" '.host' "127.0.0.1:$UPSTREAM_PORT"
assert_json "local simulation uses target forwarded Host" '.forwarded_host' "127.0.0.1:$UPSTREAM_PORT"
assert_json "local simulation reports HTTP upstream protocol" '.forwarded_proto' "http"
assert_json "local simulation reports target port" '.forwarded_port' "$UPSTREAM_PORT"
assert_json "local simulation rewrites Origin" '.origin' "http://127.0.0.1:$UPSTREAM_PORT"
assert_json "local simulation replaces real IP" '.real_ip' "192.168.50.10"
assert_json "local simulation replaces forwarded chain" '.forwarded_for' "192.168.50.10"
assert_json "local simulation removes standard Forwarded" '.forwarded == null | tostring' "true"

request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_host":"","forwarded_host":"","forwarded_proto":"","forwarded_port":0,"origin_mode":"auto","custom_origin":"","simulate_local":false,"local_ip":"127.0.0.1"}'
assert_eq "restore default proxy behavior" "$STATUS" "200"
login fixed.test.example bob changed123 "$APP_COOKIE"
request GET fixed.test.example / "$APP_COOKIE"
assert_eq "fixed application proxy" "$STATUS" "200"

STATUS=$(curl -sS --max-time 5 --resolve "fixed.test.example:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" \
    -H "Origin: http://fixed.test.example:$HTTP_PORT" \
    -H 'Content-Type: application/json' \
    --data '{"cwd":"/tmp"}' \
    -o "$TMP_DIR/trusted-origin-body" -w '%{http_code}' \
    "http://fixed.test.example:$HTTP_PORT/trusted-origin")
assert_eq "same-origin POST survives reverse proxy host forwarding" "$STATUS" "200"
assert_eq "same-origin POST reaches upstream unchanged" \
    "$(jq -r '.origin' "$TMP_DIR/trusted-origin-body")" "http://fixed.test.example:$HTTP_PORT"
STATUS=$(curl -sS --max-time 5 --resolve "fixed.test.example:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" \
    -H 'Origin: http://fixed.test.example:99' \
    -H 'Content-Type: application/json' \
    --data '{"cwd":"/tmp"}' \
    -o "$TMP_DIR/public-port-origin-body" -w '%{http_code}' \
    "http://fixed.test.example:$HTTP_PORT/trusted-origin")
assert_eq "same-host public Origin port survives outer proxy port mapping" "$STATUS" "200"
assert_eq "upstream Host restores the same-host public Origin port" \
    "$(jq -r '.expected_origin' "$TMP_DIR/public-port-origin-body")" "http://fixed.test.example:99"
STATUS=$(curl -sS --max-time 5 --resolve "fixed.test.example:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" \
    -H 'Origin: https://cross-origin.test' \
    -H 'Content-Type: application/json' \
    --data '{"cwd":"/tmp"}' \
    -o "$TMP_DIR/untrusted-origin-body" -w '%{http_code}' \
    "http://fixed.test.example:$HTTP_PORT/trusted-origin")
assert_eq "cross-origin POST remains rejected by upstream" "$STATUS" "403"

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

request POST "$ADMIN_HOST" /_api_/authz/v1/applications "$ADMIN_COOKIE" "$CSRF" \
    "{\"domain\":\"https-fixed.test.example\",\"target_ip\":\"127.0.0.1\",\"port\":$TLS_PORT,\"upstream_scheme\":\"https\",\"upstream_ssl_verify\":false}"
assert_eq "create HTTPS upstream binding" "$STATUS" "201"
request GET "$ADMIN_HOST" /_api_/authz/v1/authorization "$ADMIN_COOKIE"
HTTPS_APP_ID=$(jq -er '.data.bindings[] | select(.domain == "https-fixed.test.example") | .id' "$TMP_DIR/body")
assert_json "HTTPS binding stores upstream scheme" '.data.bindings[] | select(.domain == "https-fixed.test.example") | .upstream_scheme' "https"
assert_json "HTTPS binding can ignore SSL verification" '.data.bindings[] | select(.domain == "https-fixed.test.example") | .upstream_ssl_verify | tostring' "0"
request GET https-fixed.test.example / "$ADMIN_COOKIE"
assert_eq "HTTPS upstream works with ignored certificate" "$STATUS" "200"
assert_eq "HTTPS upstream response body" "$BODY" "/"
request PATCH "$ADMIN_HOST" "/_api_/authz/v1/applications/$HTTPS_APP_ID" "$ADMIN_COOKIE" "$CSRF" '{"upstream_ssl_verify":true}'
assert_eq "enable HTTPS upstream SSL verification" "$STATUS" "200"
request GET https-fixed.test.example / "$ADMIN_COOKIE"
assert_eq "self-signed HTTPS upstream is rejected when verification is enabled" "$STATUS" "502"
request DELETE "$ADMIN_HOST" "/_api_/authz/v1/applications/$HTTPS_APP_ID" "$ADMIN_COOKIE" "$CSRF"
assert_eq "delete HTTPS upstream binding" "$STATUS" "200"

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
login "$ADMIN_HOST" bob changed123 "$BOB_COOKIE" local false
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
LOGOUT_COOKIES=$(cat "$TMP_DIR/headers")
assert_contains "logout clears configured root-domain cookie" "$LOGOUT_COOKIES" "; Domain=.test.example"
assert_contains "logout clears host-only cookie" "$LOGOUT_COOKIES" "authz_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
assert_contains "logout clears deeper legacy domain cookie" "$LOGOUT_COOKIES" "; Domain=.admin.test.example"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$ADMIN_COOKIE"
assert_eq "logged-out session rejected" "$STATUS" "401"

RESET_OUTPUT=$(docker exec "$CONTAINER_NAME" env AUTHZ_ADMIN_PASSWORD=reset123 admin_password_reset)
assert_contains "admin password reset command runs" "$RESET_OUTPUT" "admin password reset from AUTHZ_ADMIN_PASSWORD"
sleep 1
login "$ADMIN_HOST" admin reset123 "$RESET_COOKIE"
request GET "$ADMIN_HOST" /_api_/authz/v1/session "$RESET_COOKIE"
assert_eq "reset admin password is immediately usable" "$STATUS" "200"
docker exec "$CONTAINER_NAME" env AUTHZ_ADMIN_PASSWORD=admin123 admin_password_reset >/dev/null
sleep 1
login "$ADMIN_HOST" admin admin123 "$ADMIN_COOKIE"

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

# ── 多实例 OAuth 两级中继: 业务实例 → 认证实例(中枢) → 身份提供方 → 中枢 → 业务实例 ──
RELAY_CONTAINER_NAME="authz-gateway-relay-test-$$"
mkdir -p "$TMP_DIR/relay-data/authz"
docker run -d \
    --name "$RELAY_CONTAINER_NAME" \
    --network host \
    -e NGINX_WORKER_PROCESSES=1 \
    -e AUTHZ_HTTP_PORT="$RELAY_HTTP_PORT" \
    -e AUTHZ_HTTPS_PORT="$RELAY_HTTPS_PORT" \
    -e "AUTHZ_HOST_URL=http://relay2.test.example:$RELAY_HTTP_PORT" \
    -e AUTHZ_ADMIN_PASSWORD=admin123 \
    -e AUTHZ_PORT_MIN=1000 \
    -e AUTHZ_PORT_MAX=65535 \
    -e "AUTHZ_OAUTH_RELAY_SECRET=$RELAY_SECRET" \
    -e "AUTHZ_OAUTH_RELAY_NAME=$RELAY_BUSINESS_NAME" \
    -e "AUTHZ_OAUTH_HUB_URL=http://$HUB_HOST:$HTTP_PORT" \
    -e "AUTHZ_OAUTH_HUB_PROVIDERS=testid:Test Identity" \
    -e AUTHZ_OAUTH_RELAY_ALLOW_HTTP=true \
    -e AUTHZ_OAUTH_ALLOW_HTTP=true \
    -e OPENRESTY_TEMPLATE_DIR=/etc/openresty/templates \
    -v "$TMP_DIR/relay-data:/data" \
    -v "$REPO_DIR/admin:/usr/local/openresty/nginx/html/admin:ro" \
    -v "$TMP_DIR/templates:/etc/openresty/templates:ro" \
    -v "$REPO_DIR/docker-entrypoint.sh:/docker-entrypoint.sh:ro" \
    -v "$REPO_DIR/lualib:/usr/local/openresty/site/lualib:ro" \
    "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
    STATUS=$(curl -sS --max-time 2 --resolve "$RELAY_HOST:$RELAY_HTTP_PORT:127.0.0.1" \
        -o /dev/null -w '%{http_code}' "http://$RELAY_HOST:$RELAY_HTTP_PORT/_authz/login" 2>/dev/null || true)
    [[ "$STATUS" == "200" ]] && break
    sleep 0.5
done
[[ "$STATUS" == "200" ]] || fail "relay business instance did not become ready"
pass "relay business instance is ready"

# 业务实例登录页展示中枢提供的身份提供方(本地未配置任何 provider)
RELAY_LOGIN_BODY=$(curl -sS --max-time 5 --resolve "$RELAY_HOST:$RELAY_HTTP_PORT:127.0.0.1" \
    "http://$RELAY_HOST:$RELAY_HTTP_PORT/_authz/login")
assert_contains "relay login lists hub provider" "$RELAY_LOGIN_BODY" "Test Identity"

# 1) 业务实例发起认证: 跳转认证实例中继入口, 携带 relay 名与 next 路径
STATUS=$(curl -sS --max-time 5 --resolve "$RELAY_HOST:$RELAY_HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/relay-start-headers" -o /dev/null -w '%{http_code}' \
    "http://$RELAY_HOST:$RELAY_HTTP_PORT/_authz/oauth/start?provider=testid&next=/app1/dashboard")
assert_eq "relay start redirects to hub" "$STATUS" "302"
RELAY_START_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/relay-start-headers")
assert_contains "relay start targets hub relay endpoint" "$RELAY_START_URL" "/_authz/oauth/relay/start"
assert_contains "relay start carries relay name" "$RELAY_START_URL" "relay=business1"
assert_contains "relay start carries next path" "$RELAY_START_URL" "next=%2Fapp1%2Fdashboard"

# 2) 认证实例接收中继请求后跳转真实身份提供方 (authorize), 回调固定为中枢地址
STATUS=$(curl -sS --max-time 5 --resolve "$HUB_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/hub-headers" -o /dev/null -w '%{http_code}' "$RELAY_START_URL")
assert_eq "hub relay start redirects to provider" "$STATUS" "302"
RELAY_AUTHORIZE_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/hub-headers")
assert_contains "hub relay authorize uses hub callback" "$RELAY_AUTHORIZE_URL" "admin.test.example"

# 3) 身份提供方授权后跳回认证实例的 callback (携带原始 state)
RELAY_PROVIDER_CALLBACK_URL=$(curl -sS --max-time 5 -D - -o /dev/null "$RELAY_AUTHORIZE_URL" | awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }')
RELAY_PROVIDER_CALLBACK_PATH=$(python3 - "$RELAY_PROVIDER_CALLBACK_URL" <<'PY'
import sys
from urllib.parse import urlsplit
value = urlsplit(sys.argv[1])
print(value.path + ("?" + value.query if value.query else ""))
PY
)

# 4) 认证实例完成一级认证, 签发断言并跳回业务实例的 callback
STATUS=$(curl -sS --max-time 5 --resolve "$HUB_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/hub-callback-headers" -o /dev/null -w '%{http_code}' \
    "http://$HUB_HOST:$HTTP_PORT$RELAY_PROVIDER_CALLBACK_PATH")
assert_eq "hub callback issues relay assertion" "$STATUS" "302"
RELAY_BACK_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/hub-callback-headers")
assert_contains "relay assertion targets business instance" "$RELAY_BACK_URL" "relay2.test.example:${RELAY_HTTP_PORT}/_authz/oauth/callback"
assert_contains "relay assertion carries token" "$RELAY_BACK_URL" "assertion="

# 5) 业务实例验证断言、同步远程身份并创建本机会话, 跳回最初 next 路径
RELAY_BACK_PATH=$(python3 - "$RELAY_BACK_URL" <<'PY'
import sys
from urllib.parse import urlsplit
value = urlsplit(sys.argv[1])
print(value.path + ("?" + value.query if value.query else ""))
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$RELAY_HOST:$RELAY_HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/relay-callback-headers" -o /dev/null -w '%{http_code}' \
    "http://$RELAY_HOST:$RELAY_HTTP_PORT$RELAY_BACK_PATH")
assert_eq "business callback creates session" "$STATUS" "302"
RELAY_FINAL_NEXT=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/relay-callback-headers")
assert_eq "business callback returns to original next path" "$RELAY_FINAL_NEXT" "/app1/dashboard"
save_session_cookie "$TMP_DIR/relay-callback-headers" "$TMP_DIR/relay.cookie"
RELAY_SESSION=$(curl -sS --max-time 5 --resolve "$RELAY_HOST:$RELAY_HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cat "$TMP_DIR/relay.cookie")" \
    "http://$RELAY_HOST:$RELAY_HTTP_PORT/_api_/authz/v1/session")
assert_json_value() {
    local name=$1 filter=$2 expected=$3 payload=$4 actual
    actual=$(jq -er "$filter" <<<"$payload") || fail "$name (invalid JSON or filter)"
    assert_eq "$name" "$actual" "$expected"
}
assert_json_value "relay session source" '.data.source' "testid" "$RELAY_SESSION"
assert_json_value "relay session identity" '.data.identity' "user:testid:oauth.user@example.test" "$RELAY_SESSION"
assert_json_value "relay session synced roles" '.data.roles | join(",")' "staff" "$RELAY_SESSION"

# 6) 断言令牌不可重放: 二次提交同一断言不创建会话且跳回登录错误页
STATUS=$(curl -sS --max-time 5 --resolve "$RELAY_HOST:$RELAY_HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/relay-replay-headers" -o /dev/null -w '%{http_code}' \
    "http://$RELAY_HOST:$RELAY_HTTP_PORT$RELAY_BACK_PATH")
assert_eq "relay assertion replay is rejected" "$STATUS" "302"
RELAY_REPLAY_LOCATION=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/relay-replay-headers")
assert_contains "relay replay redirects to login error" "$RELAY_REPLAY_LOCATION" "/_authz/login?err="

# 7) 断言令牌被篡改后签名校验失败, 且不回退 Cookie 会话
TAMPERED_PATH=$(python3 - "$RELAY_BACK_URL" <<'PY'
import sys
from urllib.parse import urlsplit, parse_qsl, urlencode
value = urlsplit(sys.argv[1])
query = dict(parse_qsl(value.query, keep_blank_values=True))
assertion = query.get("assertion", "")
query["assertion"] = assertion[:-2] + ("AA" if not assertion.endswith("AA") else "BB")
print(value.path + "?" + urlencode(query))
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$RELAY_HOST:$RELAY_HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/relay-tamper-headers" -o /dev/null -w '%{http_code}' \
    "http://$RELAY_HOST:$RELAY_HTTP_PORT$TAMPERED_PATH")
assert_eq "tampered relay assertion is rejected" "$STATUS" "302"
TAMPERED_LOCATION=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/relay-tamper-headers")
assert_contains "tampered assertion redirects to login error" "$TAMPERED_LOCATION" "/_authz/login?err="

# 8) 未在白名单中的中继名称被认证实例拒绝 (不回退本机会话创建)
STATUS=$(curl -sS --max-time 5 --resolve "$HUB_HOST:$HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/relay-unknown-headers" -o /dev/null -w '%{http_code}' \
    "http://$HUB_HOST:$HTTP_PORT/_authz/oauth/relay/start?provider=testid&relay=intruder&next=/_radmin_/")
assert_eq "unknown relay client rejected" "$STATUS" "302"
UNKNOWN_RELAY_LOCATION=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/relay-unknown-headers")
assert_contains "unknown relay client redirects to login error" "$UNKNOWN_RELAY_LOCATION" "/_authz/login?err="

# 9) 业务实例已同步远程身份快照 (单向记录, 不依赖中枢数据库)
RELAY_REMOTE_COUNT=$(python3 - "$TMP_DIR/relay-data/authz/authz.db" <<'PY'
import sqlite3
import sys
connection = sqlite3.connect(sys.argv[1])
count = connection.execute(
    "SELECT COUNT(*) FROM remote_users WHERE provider = 'testid'").fetchone()[0]
print(count)
connection.close()
PY
)
assert_eq "business instance records remote identity" "$RELAY_REMOTE_COUNT" "1"

# 10) SSO 快捷路径: 认证实例已有远程会话时不再跳转身份提供方, 直接签发断言跳回业务实例
HUB_SESSION_COOKIE="$TMP_DIR/hub-session.cookie"
save_session_cookie "$TMP_DIR/hub-callback-headers" "$HUB_SESSION_COOKIE"
STATUS=$(curl -sS --max-time 5 --resolve "$HUB_HOST:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$HUB_SESSION_COOKIE")" \
    -D "$TMP_DIR/hub-sso-headers" -o /dev/null -w '%{http_code}' \
    "http://$HUB_HOST:$HTTP_PORT/_authz/oauth/relay/start?provider=testid&relay=$RELAY_BUSINESS_NAME&next=%2Fapp2%2Fhome")
assert_eq "hub SSO skips provider" "$STATUS" "302"
HUB_SSO_URL=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/hub-sso-headers")
assert_contains "hub SSO targets business callback" "$HUB_SSO_URL" "relay2.test.example:${RELAY_HTTP_PORT}/_authz/oauth/callback"
assert_contains "hub SSO carries assertion" "$HUB_SSO_URL" "assertion="

HUB_SSO_PATH=$(python3 - "$HUB_SSO_URL" <<'PY'
import sys
from urllib.parse import urlsplit
value = urlsplit(sys.argv[1])
print(value.path + ("?" + value.query if value.query else ""))
PY
)
STATUS=$(curl -sS --max-time 5 --resolve "$RELAY_HOST:$RELAY_HTTP_PORT:127.0.0.1" \
    -D "$TMP_DIR/relay-sso-headers" -o /dev/null -w '%{http_code}' \
    "http://$RELAY_HOST:$RELAY_HTTP_PORT$HUB_SSO_PATH")
assert_eq "hub SSO assertion creates business session" "$STATUS" "302"
HUB_SSO_NEXT=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/relay-sso-headers")
assert_eq "hub SSO returns to requested next path" "$HUB_SSO_NEXT" "/app2/home"

# 11) 认证实例的本地账号会话不参与跨实例中继, 仍走正常提供方流程
STATUS=$(curl -sS --max-time 5 --resolve "$HUB_HOST:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$ADMIN_COOKIE")" \
    -D "$TMP_DIR/hub-local-headers" -o /dev/null -w '%{http_code}' \
    "http://$HUB_HOST:$HTTP_PORT/_authz/oauth/relay/start?provider=testid&relay=$RELAY_BUSINESS_NAME&next=/_radmin_/")
assert_eq "hub local session still uses provider flow" "$STATUS" "302"
HUB_LOCAL_LOCATION=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/hub-local-headers")
assert_contains "hub local session redirects to provider authorize" "$HUB_LOCAL_LOCATION" "/oauth/authorize"

# 12) 会话来源与请求 provider 不一致时不走 SSO 快捷路径, 进入正常授权流程
STATUS=$(curl -sS --max-time 5 --resolve "$HUB_HOST:$HTTP_PORT:127.0.0.1" \
    -H "Cookie: $(cookie_header "$HUB_SESSION_COOKIE")" \
    -D "$TMP_DIR/hub-mismatch-headers" -o /dev/null -w '%{http_code}' \
    "http://$HUB_HOST:$HTTP_PORT/_authz/oauth/relay/start?provider=dingtalk&relay=$RELAY_BUSINESS_NAME&next=/_radmin_/")
assert_eq "hub provider mismatch uses provider flow" "$STATUS" "302"
HUB_MISMATCH_LOCATION=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$TMP_DIR/hub-mismatch-headers")
assert_contains "hub mismatch redirects to dingtalk authorize" "$HUB_MISMATCH_LOCATION" "dingtalk/authorize"

printf '\nAll %d authz gateway checks passed.\n' "$PASS"
