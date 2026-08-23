# openresty-base 设计文档 (design.md)

> 本文保留核心设计说明。当前维护入口、测试基线、部署流程和前端规则以
> [docs/maintenance-handbook.md](docs/maintenance-handbook.md) 与 `AGENTS.MD` 为准。

## 1. 项目定位

定制 OpenResty Alpine Docker 镜像，双职能：

1. **基础镜像**：源码编译的 OpenResty（最新 lua-nginx-module master）+ WebDAV/FancyIndex + JWT/HTTP 库
2. **Authz Gateway**（默认运行模式）：动态端口反向代理 + 本地会话认证授权 + 可选 NocoBase 身份源

## 2. 总体架构

```
                    ┌──────────────────────────────────────┐
 Browser ──http──▶  │ :6080 ──▶ access_by_lua(resty.authz) │──▶ http://127.0.0.1:<port>
 Browser ──https─▶  │ :6443 ──▶   认证→casbin→解析目标端口  │──▶ https://127.0.0.1:<port>
                    │            │                         │    (自签证书, verify off)
                    │   /_authz/* → 登录/OAuth/旧接口410   │
                    │   /_api_/*  → klib.router JSON API   │
                    │   /_radmin_ → 会话保护的静态管理端   │
                    │            │                         │
                    │   SQLite /data/authz/authz.db ◀─────│
                    │ (local/remote users, sessions, ACL) │
                    └──────────────────────────────────────┘
```

## 3. 目录结构与模块职责

```
Dockerfile                  多阶段构建; 内置 lua-resty-http/CA/sqlite-libs/SSI/ngx_brotli
docker-entrypoint.sh        ① 自签证书生成(缺失时) ② envsubst 渲染 nginx.conf ③ exec "$@"
conf/nginx.conf.template    网关主配置模板 (${HTTP_PORT} 等占位符, envsubst 只替换白名单变量)
conf/openssl.cnf            最小 openssl 配置(镜像内 openssl 无默认 cnf)
lualib/resty/hmac.lua       resty.hmac 兼容垫片(OpenSSL 3.x), 供通用 resty.jwt 使用
lualib/resty/authz/         ★ Authz Gateway 核心
  init.lua                  入口: init()(init_by_lua) + access()(access_by_lua)
  app.lua                   登录/OAuth 路由 + 旧接口退役响应 (/_authz/*)
  api/router.lua            /_api_/authz/v1 代码注册式 API Router
  api/guard.lua             session/admin/CSRF guard
  api/service.lua           用户、应用绑定与策略业务服务
  db.lua                    SQLite FFI 封装 + schema + seed
  casbin.lua                mini-casbin 执行器 (p/g 行, deny 优先)
  session.lua               服务端会话 CRUD + cookie 读写
  nocobase.lua              NocoBase signIn/check + 本地角色映射 + 远程身份快照
  oauth.lua                 OAuth2/OIDC + Google 授权码、PKCE、userinfo
  remote.lua                远程身份单向记录与本地角色覆盖
  util.lua                  密码哈希(HMAC-SHA256 迭代5000次)/随机token/HTML转义
test/run_tests.sh           基础镜像功能测试(17项断言, 不依赖 authz)
test/test_authz_gateway.sh  Gateway/API 隔离测试矩阵
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
| users | username(UNIQUE), password_hash, salt, roles, enabled, created_at, last_login_at, updated_at | 本地用户；认证状态仅启用/未启用，时间为 Unix 秒 |
| remote_users | provider+subject(PK), UNIQUE(provider,username), roles, remote_roles, roles_overridden, enabled, synced_at, created_at, last_login_at, updated_at | 单向身份记录；`synced_at` 为兼容存储列，API 输出 `recorded_at`；不保存密码/token |
| sessions | token(PK, 32B随机hex), username, source, csrf, expires_at | 本机服务端会话, TTL 默认7天 |
| policies | ptype('p'/'g'), v0, v1, v2, UNIQUE(ptype,v0,v1,v2) | casbin 策略行 |
| bindings | domain(UNIQUE), port, enabled, note | 显式域名绑定 |

**policies 编码约定**：
- `p` 行: v0=主体(`user:<source>:<username>`或`role:x`), v1=对象"/<port><path模式>", v2=HTTP方法或`*`
  - deny 编码在 v2 尾部: `"GET|deny"`（表无独立 eft 列）
- `g` 行: v0=`user:<source>:<username>`, v1=role:xxx；v2 固定 `-`
- seed 默认: 仅 `p,role:admin,/*,*` allow，其他角色默认拒绝

**密码哈希**: `hex = to_hex(H(salt,...H(salt,H(salt,password))))`, H=HMAC-SHA256(key=salt), 迭代5000次。
Python 等价验证: `hmac.new(salt.encode(), prev, hashlib.sha256).digest()`。

## 5. 请求处理流程 (authz.access())

```
Host 解析 (ngx.var.host 已 lowercase 无端口):
  1. bindings 精确匹配 (enabled=1) → port
  2. 正则 ^(\d{1,5})- 且 port ∈ [PORT_MIN,PORT_MAX] → port   ← 数字前缀免配置
  3. 否则 → 404 页面
会话认证: cookie authz_session → sessions 表查 token/source (过期即删)
  local 会话必须命中 enabled 本地用户
  任意远程 provider 会话必须命中对应来源的 enabled 本地记录；后续登录记录不得覆盖管理员设置的启用状态
  失败 → 302 /_authz/login?next=<request_uri>
规范主体: principal = "user:" .. source .. ":" .. username
Casbin 授权: enforce(principal, "/<port><uri>", HTTP_METHOD)
  deny优先/fail-closed → 失败返回 403 页面
设置 ngx.var.authz_target = <entry_scheme>://127.0.0.1:<port>  → proxy_pass
     ngx.var.authz_user   = username                 → X-Authz-User 头
     ngx.var.authz_source = source                   → X-Authz-Source 头
     ngx.var.authz_identity = principal              → X-Authz-Identity 头
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
| CSRF | 管理修改 API 校验 `X-CSRF-Token` == session.csrf（登录除外） |
| 密码 | 盐+HMAC-SHA256 迭代5000, 常量时间比较 |
| 注入 | SQL 全部参数化绑定; HTML 输出经 escape_html |
| fail-closed | casbin 无匹配策略 → 拒绝; DB 不可用 → 报错不绕过 |
| 改密 | 删除该用户其他所有会话 |
| next 参数 | 仅接受以 `/` 开头且非 `//` 的路径 |
| 远程认证 | 默认关闭；登录时显式选择来源；HTTPS 证书校验；密码/JWT 不落库 |
| OAuth/OIDC | Authorization Code + PKCE；一次性 state；NocoBase 校验 issuer 并使用 Basic Client 认证；access token 不落库 |
| 身份隔离 | 用户名与来源组成身份；同名多来源的会话、角色与直授权互不影响 |
| 管理边界 | 仅 admin 可读取用户列表、应用和 Casbin 策略；非管理员只读取自身会话资料 |
| 远程密码 | NocoBase、Google、钉钉、微信等远程身份不能在本机修改密码 |
| 远程生命周期 | 登录记录不覆盖本机启用状态；仅管理员删除记录后，下次认证才按新身份重新创建 |

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
- 镜像发布和部署默认优先使用 GitHub Actions 产出的 GHCR 镜像；本地构建仅用于调试、验证或 CI 不可用时的回退。
- 本地构建使用 Docker CLI `buildx`：`docker buildx build --load --build-arg RESTY_J=${RESTY_J:-8} -t openresty-base:local .`。
  Dockerfile 将 Brotli 源码下载、OpenResty builder 和 runtime 分层；源码层、BuildKit 缓存和并行编译可复用。
  GitHub Actions 通过 `docker/setup-buildx-action` 与 `type=gha,mode=max` 保持同一构建路径。

## 10. 测试

```bash
# Router/ctxvar 真实 OpenResty 回归
OPENRESTY_TEST_IMAGE=openresty-base:nocobase-test bash test/test_klib_router_ctxvar.sh

# Authz Gateway/API/OAuth/代理隔离矩阵
OPENRESTY_TEST_IMAGE=openresty-base:nocobase-test bash test/test_authz_gateway.sh

# 基础镜像功能
bash test/run_tests.sh openresty-base:nocobase-test
```

测试矩阵覆盖: Router、端口解析、未认证重定向、本地用户、NocoBase mock 登录与角色查询、
OAuth state/PKCE/callback、同名多来源身份隔离、旧身份策略迁移、远端角色记录与本地覆盖、
来源级直授权、上游身份头、远程改密拒绝、绑定 CRUD、CSRF、Casbin 多方法授权和缓存失效。
