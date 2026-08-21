# openresty-base 设计文档 (design.md)

> 本文档面向后续维护 agent。修改代码前请先阅读本文档了解架构与约束。

## 1. 项目定位

定制 OpenResty Alpine Docker 镜像，双职能：

1. **基础镜像**：源码编译的 OpenResty（最新 lua-nginx-module master）+ WebDAV/FancyIndex + JWT/SSO 库
2. **Authz Gateway**（默认运行模式）：动态端口反向代理 + 本地认证授权

## 2. 总体架构

```
                    ┌──────────────────────────────────────┐
 Browser ──http──▶  │ :6080 ──▶ access_by_lua(resty.authz) │──▶ http://127.0.0.1:<port>
 Browser ──https─▶  │ :6443 ──▶   认证→casbin→解析目标端口  │──▶ https://127.0.0.1:<port>
                    │            │                         │    (自签证书, verify off)
                    │   /_authz/* → app.lua 管理界面       │
                    │            │                         │
                    │   SQLite /data/authz/authz.db ◀─────│
                    │   (users/sessions/policies/bindings) │
                    └──────────────────────────────────────┘
```

## 3. 目录结构与模块职责

```
Dockerfile                  单阶段构建; RUNDEPS 含 sqlite-libs; ENTRYPOINT 化
docker-entrypoint.sh        ① 自签证书生成(缺失时) ② envsubst 渲染 nginx.conf ③ exec "$@"
conf/nginx.conf.template    网关主配置模板 (${HTTP_PORT} 等占位符, envsubst 只替换白名单变量)
conf/openssl.cnf            最小 openssl 配置(镜像内 openssl 无默认 cnf)
lualib/resty/hmac.lua       resty.hmac 兼容垫片(OpenSSL 3.x), 供 resty.jwt 使用
lualib/resty/noco_auth.lua  APISIX noco_sso_auth 的 sso_ck Cookie 验证封装
lualib/resty/authz/         ★ Authz Gateway 核心
  init.lua                  入口: init()(init_by_lua) + access()(access_by_lua)
  app.lua                   管理界面路由分发 + HTML 渲染 (/_authz/*)
  db.lua                    SQLite FFI 封装 + schema + seed
  casbin.lua                mini-casbin 执行器 (p/g 行, deny 优先)
  session.lua               服务端会话 CRUD + cookie 读写
  util.lua                  密码哈希(HMAC-SHA256 迭代5000次)/随机token/HTML转义
test/run_tests.sh           基础镜像功能测试(7项, 不依赖 authz)
test/test_authz_gateway.sh  Gateway 测试矩阵(26项断言, 幂等: 开头清库重启)
docs/sso-jwt-auth.md        SSO 集成指南
```

### 模块依赖关系

```
nginx.conf.template
  init_by_lua  → authz.init() ─→ db.init() [master建schema+seed后close]
  access_by_lua → authz.access() ─→ db.open(懒加载,每worker) → resolve_port → session → casbin.enforce
  content_by_lua(/_authz) → app.handle() ─→ 同上 + HTML 渲染
```

## 4. 数据模型 (SQLite)

| 表 | 关键列 | 说明 |
|----|--------|------|
| users | username(UNIQUE), password_hash, salt, roles(逗号分隔), enabled | 角色: admin/user |
| sessions | token(PK, 32B随机hex), username, csrf, expires_at | 服务端会话, TTL 默认7天 |
| policies | ptype('p'/'g'), v0, v1, v2, UNIQUE(ptype,v0,v1,v2) | casbin 策略行 |
| bindings | domain(UNIQUE), port, enabled, note | 显式域名绑定 |

**policies 编码约定**：
- `p` 行: v0=主体(user或role:x), v1=对象"/<port><path模式>", v2=HTTP方法或`*`
  - deny 编码在 v2 尾部: `"GET|deny"`（表无独立 eft 列）
- `g` 行: v0=用户名, v1=role:xxx；v2 固定 `-`
- seed 默认: `p,role:admin,/*,*` 与 `p,role:user,/*,*` 均 allow

**密码哈希**: `hex = to_hex(H(salt,...H(salt,H(salt,password))))`, H=HMAC-SHA256(key=salt), 迭代5000次。
Python 等价验证: `hmac.new(salt.encode(), prev, hashlib.sha256).digest()`。

## 5. 请求处理流程 (authz.access())

```
Host 解析 (ngx.var.host 已 lowercase 无端口):
  1. bindings 精确匹配 (enabled=1) → port
  2. 正则 ^(\d{1,5})- 且 port ∈ [PORT_MIN,PORT_MAX] → port   ← 数字前缀免配置
  3. 否则 → 404 页面
会话认证: cookie authz_session → sessions 表查 token (过期即删)
  失败 → 302 /_authz/login?next=<request_uri>
Casbin 授权: enforce(username, "/<port><uri>", HTTP_METHOD)
  deny优先/fail-closed → 失败返回 403 页面
设置 ngx.var.authz_target = <entry_scheme>://127.0.0.1:<port>  → proxy_pass
     ngx.var.authz_user   = username                 → X-Authz-User 头
```

**上游协议由入口决定**: 6080→http 上游, 6443→https 上游（proxy_ssl_verify off）。

## 6. 缓存一致性

- `lua_shared_dict authz_cache` 存 `rev` 计数器
- 管理界面任何写操作调用 `bump_rev()` (dict:incr)
- 每个 worker 维护 `{rev, enforcer, bindings}` 本地缓存, rev 变化时全量重载
- 直接改数据库不会触发失效（必须走管理界面或重启）

## 7. 安全设计

| 机制 | 实现 |
|------|------|
| 会话 | 服务端存储, cookie 仅 32B 随机 hex, HttpOnly+SameSite=Lax |
| CSRF | 所有 POST 校验 `_csrf` == session.csrf (登录除外) |
| 密码 | 盐+HMAC-SHA256 迭代5000, 常量时间比较 |
| 注入 | SQL 全部参数化绑定; HTML 输出经 escape_html |
| fail-closed | casbin 无匹配策略 → 拒绝; DB 不可用 → 报错不绕过 |
| 改密 | 删除该用户其他所有会话 |
| next 参数 | 仅接受以 `/` 开头且非 `//` 的路径 |

## 8. 关键实现约束 / 踩坑记录 ⚠

后续维护必读：

1. **Lua 模式不支持 `(组)?`、`(组)+`、`{n,m}` 量词** — 一律用 `ngx.re.match`(PCRE)
2. **LuaJIT FFI**: 必须显式 `ffi.load("libsqlite3.so.0")`（Alpine 运行包无 `.so` 软链,
   且 libsqlite3 不在 nginx 全局符号表）
3. **位运算**: 不要用 `|`/`~`（依赖 LUA52COMPAT 编译选项）, 用算术替代
4. **SQLite 并发**: WAL + busy_timeout=5000; master 进程 init 后必须 close,
   worker 各自懒加载重开（fd 跨 fork 共享会导致状态错乱）
5. **nginx worker 用户**: 模板中 `user root;` 是必须的, 否则 worker(nobody) 无权写挂载卷中的 db
6. **envsubst 只认 `${VAR}`**, 模板不要用 `@@VAR@@`; nginx 自身的 `$host` 等变量靠
   白名单(SHELL-FORMAT)保护不被替换
7. **镜像内 openssl CLI 无默认 cnf** → 必须 `OPENSSL_CONF=conf/openssl.cnf`
8. **cookie 与域名绑定**: 测试时同一会话必须访问同一 Host（curl 自定义 Host 头会干扰
   cookie 匹配, 用 `--resolve` 而非 `-H "Host:"`）
9. **app.lua 中 local 函数有顺序依赖**（如 is_admin 调 user_roles）, 调整位置需注意
10. **docker exec 在容器启动早期可能挂起**, entrypoint 的 apk 重试循环期间网关不可达

## 9. 构建与发布

- GitHub Actions (.github/workflows/build.yml): push main / 每周一 UTC 02:00 / 手动触发
- 推送 ghcr.io/yorkane/openresty-base 与 docker.io/yorkane/openresty-base
- Tag: latest / `<openresty版本>` / `<版本>-<日期>`
- 本地构建: `docker build -t openresty-base:local .`（约15-30分钟, 单层 RUN）

## 10. 测试

```bash
# 基础镜像功能 (7项, 任意环境)
bash test/run_tests.sh [image]

# Authz Gateway 矩阵 (26项, 需要 --network host 容器 + mock 上游)
docker run -d --name authz-gw --network host -v /tmp/authz-data:/data \
  -v $PWD/lualib/resty/authz:/usr/local/openresty/lualib/resty/authz:ro \
  ... ghcr.io/yorkane/openresty-base:latest ...
# mock: http:3456 (python -m http.server), https:4567 (ssl 包装)
bash test/test_authz_gateway.sh
```

测试矩阵覆盖: 端口范围边界(1999/2000/20000/20001/80/443)、未认证重定向、错误密码、
http/https 双入口代理、多级子域名、绑定 CRUD、CSRF 拒绝、用户创建/登录、
策略删除/恢复/deny 热更新、伪造 cookie。

## 11. 后续演进方向 (未实现)

- NocoBase/APISIX SSO 对接: resty.noco_auth 已内置, 可在 access() 中加外部身份源分支
- 绑定级匿名访问开关 (bindings.auth_required 列)
- HTTPS 入口按 SNI 动态选择证书 (目前单一默认证书)
- 管理界面访问日志/审计页
- arm64 构建
