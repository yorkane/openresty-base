#!/bin/bash
# openresty-base authz gateway 功能测试矩阵 (幂等: 开头清理状态)
# 前置: 网关容器 authz-gw 运行中 (--network host), mock http:3456 https:4567
GW_HOST=127.0.0.1
PASS=0; FAIL=0

check() { # check <名称> <期望> <实际>
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "PASS | $1 | $3";
  else FAIL=$((FAIL+1)); echo "FAIL | $1 | 期望=$2 实际=$3"; fi
}

# ── 状态清理 (上次运行残留) + 重启等待就绪 ──────────────────────
timeout 10 docker exec authz-gw sqlite3 /data/authz/authz.db "
DELETE FROM bindings;
DELETE FROM policies WHERE v0='bob' OR (ptype='p' AND v0='role:user');
DELETE FROM users WHERE username='bob';
DELETE FROM sessions;" >/dev/null 2>&1
docker restart authz-gw >/dev/null 2>&1
for i in $(seq 1 30); do
  code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "Host: 3456-wait.com" http://$GW_HOST:6080/ 2>/dev/null)
  [ "$code" = "302" ] && break
  sleep 2
done

# 在指定域名下登录, cookie 存到 $4
login_at() { # login_at <host> <user> <pass> <cookiefile> [port] [scheme]
  local host=$1 user=$2 pass=$3 ck=$4 port=${5:-6080} scheme=${6:-http}
  local kflag=""; [ "$scheme" = "https" ] && kflag="-k"
  rm -f "$ck"
  curl -s -m 5 $kflag -c "$ck" --resolve "$host:$port:$GW_HOST" \
    -X POST "$scheme://$host:$port/_authz/login" \
    -d "username=$user&password=$pass" -o /dev/null
}
gget() { # gget <host> <path> <cookiefile> [port] [scheme] [extra curl args...]
  local host=$1 path=$2 ck=$3 port=${4:-6080} scheme=${5:-http}; shift 5
  local kflag=""; [ "$scheme" = "https" ] && kflag="-k"
  curl -s -m 5 $kflag -b "$ck" --resolve "$host:$port:$GW_HOST" "$scheme://$host:$port$path" "$@"
}
gcode() { # gcode <host> <path> <cookiefile> [port] [scheme]
  local host=$1 path=$2 ck=$3 port=${4:-6080} scheme=${5:-http}
  local kflag=""; [ "$scheme" = "https" ] && kflag="-k"
  curl -s -m 5 $kflag -b "$ck" --resolve "$host:$port:$GW_HOST" "$scheme://$host:$port$path" -o /dev/null -w "%{http_code}"
}
gpost() { # gpost <host> <path> <cookiefile> <curl args...>
  local host=$1 path=$2 ck=$3; shift 3
  curl -s -m 5 -b "$ck" --resolve "$host:6080:$GW_HOST" \
    -X POST "http://$host:6080$path" "$@"
}

echo "═══ A. 未认证访问 ═══"
loc=$(curl -s -m 5 --resolve 3456-t1.example.com:6080:$GW_HOST "http://3456-t1.example.com:6080/" -o /dev/null -w "%{redirect_url}")
case "$loc" in */_authz/login*) check "数字前缀未登录→重定向登录页" ok ok;; *) check "数字前缀未登录→重定向登录页" ok "$loc";; esac

echo "═══ B. 端口解析规则 (未登录, 通过302/404区分) ═══"
for p in 2000 20000 9999; do
  code=$(curl -s -m 5 -H "Host: ${p}-x.com" "http://$GW_HOST:6080/" -o /dev/null -w "%{http_code}")
  check "端口$p 在范围内→需登录(302)" 302 "$code"
done
for p in 1999 20001 80 443; do
  code=$(curl -s -m 5 -H "Host: ${p}-x.com" "http://$GW_HOST:6080/" -o /dev/null -w "%{http_code}")
  check "端口$p 范围外→404" 404 "$code"
done
code=$(curl -s -m 5 -H "Host: unbound.test.example" "http://$GW_HOST:6080/" -o /dev/null -w "%{http_code}")
check "无前缀域名且无绑定→404" 404 "$code"

echo "═══ C. 认证流程 ═══"
code=$(curl -s -m 5 -X POST "http://$GW_HOST:6080/_authz/login" -d "username=admin&password=wrong" -o /dev/null -w "%{http_code}")
check "错误密码→302回登录页" 302 "$code"
login_at c.example.com admin admin123 /tmp/ck-c.txt
grep -q authz_session /tmp/ck-c.txt && check "正确登录获得会话cookie" yes yes || check "正确登录获得会话cookie" yes no

echo "═══ D. 已认证动态代理 ═══"
login_at 3456-d.example.com admin admin123 /tmp/ckd.txt
body=$(gget 3456-d.example.com / /tmp/ckd.txt)
check "代理到本机3456(http入口)" "hello-from-port-3456" "$body"
login_at 4567-d.example.com admin admin123 /tmp/ckd2.txt 6443 https
body=$(gget 4567-d.example.com / /tmp/ckd2.txt 6443 https)
check "代理到本机4567(https入口→https上游)" "hello-from-port-3456" "$body"
login_at 3456-a.b.c.example.com admin admin123 /tmp/ckd3.txt
body=$(gget 3456-a.b.c.example.com /index.html /tmp/ckd3.txt)
check "多级子域名代理" "hello-from-port-3456" "$body"

echo "═══ E. 控制台与绑定管理 ═══"
CK=/tmp/ck-e.txt
login_at e.example.com admin admin123 $CK
csrf=$(gget e.example.com /_authz/ $CK | grep -o "name='_csrf' value='[a-f0-9]*'" | head -1 | grep -o "[a-f0-9]\{32\}")
[ -n "$csrf" ] && check "获取CSRF token" yes yes || check "获取CSRF token" yes no

code=$(gpost e.example.com /_authz/bindings/save $CK \
  -d "_csrf=$csrf&action=create&domain=nas.example.com&port=3456&note=test&enabled=on" \
  -o /dev/null -w "%{http_code}")
check "创建绑定→302回控制台" 302 "$code"
login_at nas.example.com admin admin123 /tmp/ck-nas.txt
body=$(gget nas.example.com / /tmp/ck-nas.txt)
check "绑定域名生效→代理3456" "hello-from-port-3456" "$body"

code=$(gpost e.example.com /_authz/bindings/save $CK \
  -d "action=create&domain=evil.example.com&port=3456" -o /dev/null -w "%{http_code}")
check "无CSRF写操作→403" 403 "$code"

echo "═══ F. 用户管理与策略授权 ═══"
gpost e.example.com /_authz/users/save $CK \
  -d "_csrf=$csrf&action=create&username=bob&password=bob123456&roles=user" -o /dev/null
login_at f.example.com bob bob123456 /tmp/ck-bob.txt
grep -q authz_session /tmp/ck-bob.txt && check "新用户bob可登录" yes yes || check "新用户bob可登录" yes no

login_at 3456-fb.example.com bob bob123456 /tmp/ck-bob2.txt
body=$(gget 3456-fb.example.com / /tmp/ck-bob2.txt)
check "bob(role:user默认策略)可访问" "hello-from-port-3456" "$body"

code=$(gpost f.example.com /_authz/users/save /tmp/ck-bob.txt \
  -d "_csrf=x&action=create&username=hack&password=hack123" -o /dev/null -w "%{http_code}")
check "bob伪造CSRF访问用户管理→403" 403 "$code"

# 删除 role:user 全局策略 → bob 被拒
pid=$(timeout 10 docker exec authz-gw sqlite3 /data/authz/authz.db \
  "SELECT id FROM policies WHERE v0='role:user' AND ptype='p' AND v1='/*'" 2>/dev/null)
if [ -n "$pid" ]; then
  gpost e.example.com /_authz/policies/save $CK -d "_csrf=$csrf&action=del&id=$pid" -o /dev/null
  sleep 1
  code=$(gcode 3456-fb.example.com / /tmp/ck-bob2.txt)
  check "删除role:user策略后bob→403" 403 "$code"
  gpost e.example.com /_authz/policies/save $CK \
    -d "_csrf=$csrf&action=add&ptype=p&v0=role:user&v1=/*&v2=*&eft=allow" -o /dev/null
  sleep 1
  code=$(gcode 3456-fb.example.com / /tmp/ck-bob2.txt)
  check "恢复role:user策略后bob→200" 200 "$code"
else
  echo "SKIP | role:user 策略查询 (sqlite3 cli 不可用)"
fi

# deny 策略: bob 禁止 GET /3456/*
gpost e.example.com /_authz/policies/save $CK \
  -d "_csrf=$csrf&action=add&ptype=p&v0=bob&v1=/3456/*&v2=GET&eft=deny" -o /dev/null
sleep 1
code=$(gcode 3456-fb.example.com / /tmp/ck-bob2.txt)
check "deny策略生效(bob→403)" 403 "$code"
code=$(gcode 3456-d.example.com / /tmp/ckd.txt)
check "deny不影响admin" 200 "$code"

echo "═══ G. 会话安全 ═══"
code=$(curl -s -m 5 -H "Cookie: authz_session=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" -H "Host: 3456-x.com" "http://$GW_HOST:6080/" -o /dev/null -w "%{http_code}")
check "伪造cookie→302登录" 302 "$code"

echo ""
echo "════════ 结果: PASS=$PASS FAIL=$FAIL ════════"
