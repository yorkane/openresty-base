#!/bin/sh
# openresty-base gateway entrypoint
# 1. 生成自签默认证书 (如缺失)
# 2. envsubst 渲染 nginx.conf
# 3. 启动 openresty

set -e

HTTP_PORT="${AUTHZ_HTTP_PORT:-6080}"
HTTPS_PORT="${AUTHZ_HTTPS_PORT:-6443}"
WORKER_PROCESSES="${NGINX_WORKER_PROCESSES:-4}"
CERT_DIR="${AUTHZ_CERT_DIR:-/data/certs}"
DB_PATH="${AUTHZ_DB_PATH:-/data/authz/authz.db}"
DNS_RESOLVER="${AUTHZ_DNS_RESOLVER:-$(awk '/^nameserver[[:space:]]+/ { print $2; exit }' /etc/resolv.conf)}"
DNS_RESOLVER="${DNS_RESOLVER:-1.1.1.1}"
CERT_FILE="$CERT_DIR/default.crt"
CERT_KEY="$CERT_DIR/default.key"

OPENSSL_BIN="/usr/local/openresty/openssl3/bin/openssl"
OPENSSL_CONF_FILE="/usr/local/openresty/nginx/conf/openssl.cnf"
NGINX_CONF_DIR="/usr/local/openresty/nginx/conf"

mkdir -p "$(dirname "$DB_PATH")" "$CERT_DIR" /var/log/openresty

# ── 自签默认证书 (10 年, SAN: DNS:*) ─────────────────────────────
if [ ! -s "$CERT_FILE" ] || [ ! -s "$CERT_KEY" ]; then
    echo "==> generating default self-signed certificate ..."
    OPENSSL_CONF="$OPENSSL_CONF_FILE" "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_KEY" -out "$CERT_FILE" \
        -days 3650 \
        -subj "/CN=openresty-gateway" \
        -addext "subjectAltName=DNS:*" >/dev/null 2>&1
fi

# ── 渲染 nginx.conf ─────────────────────────────────────────────
export HTTP_PORT HTTPS_PORT WORKER_PROCESSES CERT_FILE CERT_KEY DNS_RESOLVER
envsubst '${HTTP_PORT} ${HTTPS_PORT} ${WORKER_PROCESSES} ${CERT_FILE} ${CERT_KEY} ${DNS_RESOLVER}' \
    < "$NGINX_CONF_DIR/nginx.conf.template" \
    > "$NGINX_CONF_DIR/nginx.conf"

echo "==> starting openresty gateway (http:$HTTP_PORT https:$HTTPS_PORT)"

exec "$@"
