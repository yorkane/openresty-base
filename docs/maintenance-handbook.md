# OpenResty Authz Gateway 维护手册

> 面向后续维护 Agent。本文记录截至 2026-08-25 已验证的系统设计、开发约束、测试基线与部署方式。
> 修改前先读根目录 `AGENTS.MD`；涉及身份源时再读 `docs/sso-jwt-auth.md`。

## 1. 系统定位与入口

本仓库同时提供 OpenResty 基础镜像和轻量级 Authz Gateway。Gateway 负责：

- 将数字前缀域名或显式域名绑定解析到本机端口；
- 本地账户、NocoBase 密码认证及 OAuth/OIDC 关联登录；
- SQLite 服务端会话、来源感知身份和 mini-Casbin 授权；
- Vue 3 + Quasar UMD 静态管理界面。

稳定入口约定：

| 路径 | 职责 |
|---|---|
| `/_radmin_/` | 唯一 Admin UI 入口；不要恢复 `/admin/` |
| `/_authz/login` | 密码登录页和提交端点 |
| `/_authz/oauth/start` | OAuth 登录发起 |
| `/_authz/oauth/callback` | 所有 OAuth Provider 共用回调 |
| `/_api_/authz/v1/*` | 管理端 JSON API |
| `/_authz/api/*`、`*/save` | 已退役，返回 410 和迁移提示 |
| 其他路径 | 认证、授权后代理到本机应用 |

公网实例曾使用 `https://6080-241.ws.example.com:99/_radmin_/` 映射本机 6080。部署地址可能变化，
维护时以反向代理配置和 `docker inspect` 为准，不把该域名写入通用业务逻辑。

## 2. 请求架构

```text
Browser
  ├─ /_authz/*       -> resty.authz.app
  ├─ /_api_/*        -> klib.router("/_api_") -> authz API guard/service
  ├─ /_radmin_/*     -> 会话保护后的静态 Quasar UMD 文件
  └─ /*              -> resty.authz.access
                         -> 解析端口
                         -> 读取会话
                         -> mini-Casbin enforce
                         -> proxy_pass 127.0.0.1:<port>
```

两个网关入口使用相同控制面：

- HTTP 入口默认 6080，代理 `http://127.0.0.1:<port>`；
- HTTPS 入口默认 6443，在网关终止 TLS 后代理 `http://127.0.0.1:<port>`；
- 目标端口优先取启用的精确域名绑定，否则解析 `<port>-任意域名`；显式绑定记录包含 `menu_name` 和 `websocket` 配置；
- 可代理端口下限强制不小于 2000；目标为网关自身端口时返回 508；
- 上游收到 `X-Authz-User`、`X-Authz-Source`、`X-Authz-Identity`。
- 只要请求带有 `Upgrade: websocket`，所有已解析的动态代理目标都会转发升级头；同时通过 `X-Forwarded-Host` 转发外部 Origin Host，并关闭缓冲、延长读写超时。`bindings.websocket` 保留为历史兼容字段，不再阻断升级请求。

Admin 菜单应用列表不依赖 `bindings` 表：`/_api_/authz/v1/applications` 读取 `/proc/net/tcp` 和
`/proc/net/tcp6` 的监听端口，在 `AUTHZ_PORT_MIN/MAX` 范围内排除网关端口，再向 `127.0.0.1` 发送
短超时 `HEAD /`；只有返回 HTTP 状态行的端口才会列出。结果按 worker 缓存，默认 30 秒；容器需要使用
host 网络或其他方式让目标服务位于网关容器的 `127.0.0.1` 网络命名空间内。

## 3. 代码职责

| 路径 | 责任 |
|---|---|
| `conf/nginx.conf.template` | 全局配置、HTTP/HTTPS listener 与 TLS；两个 server 都 include 公共片段 |
| `conf/server.conf.template` | HTTP/HTTPS 共用的控制面 location、Admin 静态资源和动态代理配置 |
| `lualib/resty/authz/init.lua` | 环境配置、初始化、端口解析、缓存和 access 阶段 |
| `lualib/resty/authz/app.lua` | 登录、OAuth 跳转、旧接口 410；不承载管理业务 API |
| `lualib/resty/authz/api/router.lua` | `/_api_/authz/v1` 代码注册式路由 |
| `lualib/resty/authz/api/guard.lua` | 会话、admin、CSRF guard 和统一错误结构 |
| `lualib/resty/authz/api/service.lua` | 用户、远程身份、绑定和策略业务规则 |
| `lualib/resty/authz/db.lua` | SQLite FFI 数据层、schema、迁移、seed 和查询缓存 |
| `lualib/resty/mlcache.lua` | vendored lua-resty-mlcache 分层缓存实现 |
| `lualib/resty/authz/session.lua` | 服务端会话与 Cookie |
| `lualib/resty/authz/identity.lua` | 来源感知身份键 |
| `lualib/resty/authz/remote.lua` | 远程身份单向记录、本地启用状态和角色覆盖 |
| `lualib/resty/authz/nocobase.lua` | NocoBase 用户名密码认证 |
| `lualib/resty/authz/oauth.lua` | OAuth Code + PKCE、token/userinfo、身份记录 |
| `lualib/resty/authz/discovery.lua` | 读取本机监听端口并用短超时 HTTP HEAD 发现本地服务 |
| `admin/` | 无构建步骤的 Vue 3 + Quasar UMD Admin UI |
| `lualib/klib/` | 项目代码注册式 Router 和请求上下文框架 |

`lualib` 在镜像构建时整体复制到 `/usr/local/openresty/site/lualib`，开发部署也必须整体挂载。
只挂载 `lualib/resty/authz` 会漏掉 `klib.router`、模板等依赖，导致镜像与挂载行为不一致。

`db.lua` 的查询使用 `resty.mlcache`：worker 内 L1 LRU、共享字典 L2 和 SQLite 回调 L3。缓存默认
使用 `authz_db_cache` 共享字典，TTL 由 `AUTHZ_DB_CACHE_TTL` 控制，L1 容量由
`AUTHZ_DB_CACHE_LRU_SIZE` 控制。每次成功执行 `db.exec()` 都递增 `authz_cache:db_rev`，查询键包含
该 revision，因此管理 API 的写入会让所有 worker 使用新查询键，不需要 IPC 广播。直接改 SQLite
不会触发 revision；生产变更必须走管理 API 或重启网关。

## 4. 数据和身份模型

SQLite 默认位于 `/data/authz/authz.db`，`/data` 必须持久化。

| 表 | 关键约束 |
|---|---|
| `users` | 本地用户名唯一；角色、启用状态、密码摘要及创建/最近登录/修改时间 |
| `remote_users` | 主键 `(provider, subject)`；唯一 `(provider, username)`；创建/最近登录/修改时间 |
| `sessions` | token、username、source、csrf、expires_at |
| `policies` | `ptype/v0/v1/v2` 唯一；存 p/g 规则 |
| `bindings` | domain 唯一；port、enabled、websocket、note、menu_name |

`remote_users.synced_at` 是保留的内部存储列名；管理 API 只输出语义明确的 `recorded_at`，避免把
单向身份记录误解为双向同步协议。

本地和远程用户统一使用 Unix 秒级时间戳：`created_at` 保持首次创建时间，`last_login_at` 在成功
认证后更新，`updated_at` 在角色、启用状态、密码或远程身份记录变化时更新。管理端显示到秒。

身份不能只按用户名判断。规范主体是：

```text
user:<source>:<username>
user:local:kate
user:nocobase:kate
user:dingtalk:kate
```

同名不同来源必须保留独立角色、启用状态、会话和用户直授权。人类角色目录固定为
`admin`、`staff`、`user`、`viewer`；服务主体另有不可分配给用户的 `api` 角色：

- `admin` 可访问用户、应用绑定和 Casbin 管理 API；
- `api-key:<id>` 固定继承 `role:api`，只能新建绑定并请求代理目标；
- `api` 不能修改/删除绑定，不能管理用户、角色、策略、API Key 或核心认证；
- 非 admin 只能读取自身 session/profile；
- 默认仅 `role:admin` 拥有 `/*`，其他角色默认拒绝；
- viewer 不得看到 Authorization/Casbin 数据；
- 远程用户不能在本机修改密码。

所有用户只有启用和未启用两种认证状态。后续登录记录不得重新启用已被本机管理员禁用的身份。
管理员删除远程快照时，同时删除其会话和直接策略；下次远程认证会以新身份快照重新创建并默认启用。

远程角色单向记录规则：

1. 成功认证记录最近的 `remote_roles`；
2. 无本地覆盖时写入本机有效 `roles`；
3. `roles_overridden=1` 时保留本地有效角色；
4. 管理员可执行“恢复记录角色”清除覆盖；
5. 任何变更必须 bump `authz_cache` revision。

## 5. API 与授权规则

API Router 根固定为 `/_api_`，业务路径注册为 `/authz/v1/...`。不要依赖 Nginx location 自动剥离 URI。

所有 API table 响应使用：

```text
Content-Type: application/json; charset=UTF-8
成功: {"data": ...}
失败: {"error":{"code":"...","message":"..."}}
```

约定状态码：无会话 401、无权限或 CSRF 失败 403、不存在 404、请求格式错误 400、业务校验
422、冲突 409。所有修改请求使用 JSON body，并从 session API 取得 CSRF，通过
`X-CSRF-Token` 发送；仅登录 POST 和 API Key 新建 binding 不要求 CSRF。稳定接口清单、请求体与
Agent 调用契约见 [核心 API](core-api.md)。

API Key 安全约束：

- Header 固定为 `x-authz-key: ak_<64 hex>`，显式无效 Key 不得回退浏览器 Cookie；
- 数据库 `api_keys` 只保存 SHA-256 摘要，明文只在创建响应中出现一次；
- Key 固定使用 `api` 角色，不提供角色修改或角色创建接口；
- 代理前必须通过 `proxy_set_header X-Authz-Key ""` 清除凭据；
- Key 启用、禁用、删除和策略变更都必须 bump cache revision，并有跨 worker HTTP 回归。

策略规则：

- `p`: `v0` 为 `user:<source>:<username>` 或 `role:<role>`；
- `v1` 为 `/<port><path-pattern>`，全局为 `/*`；
- `v2` 支持标准 HTTP 方法多选，数据库中以逗号保存；`*` 表示全部；
- deny 通过 `v2` 的 `|deny` 后缀编码，deny 优先；
- `g`: 将来源感知用户主体分配给固定角色。

管理端可选 HTTP 方法目录包括 `GET/HEAD/POST/PUT/DELETE/OPTIONS/PATCH/CONNECT/TRACE` 和 `*`。
注意 `klib.router` 自身只注册 GET、HEAD、POST、PUT、DELETE、OPTIONS、PATCH；CONNECT/TRACE 是代理
授权策略动作，不用于管理 API 路由注册。

## 6. OAuth 与 NocoBase

通用 OAuth 流程使用 Authorization Code、一次性 state 和 PKCE S256。access token 只在回调请求
期间使用，不写入 SQLite、日志或 Cookie。公网 token/userinfo 传输失败自动重试一次，默认
connect/send/read timeout 为 10/10/15 秒；HTTP 非 2xx 不重试。

NocoBase 有两种登录方式：

- 密码认证：`POST /api/auth:signIn`，随后 `GET /api/auth:check` 获取用户名与角色；
- OAuth：与密码认证共用 `nocobase` 来源和本地角色覆盖。

NocoBase OAuth 的 `/api/idpOAuth/me` 只提供标准身份 claim，不使用 Basic 登录专用的
`/api/auth:check` 查询角色；首次角色来自 `AUTHZ_NOCO_OAUTH_DEFAULT_ROLES`，后续只由本机管理。

生产 NocoBase 为 2.2 时必须遵守：

- issuer 为 `<AUTHZ_NOCO_URL>/api`；
- authorize/token/userinfo 为 `/api/idpOAuth/authorize|token|me`；
- scope 为 `openid profile email api`；
- 回调必须精确校验 RFC 9207 `iss`；
- token 使用 `client_secret_basic`，并同时携带 PKCE verifier；
- 公网 Client 通过 `oidcStates:create` collection API 一次性注册，不安装 NocoBase 插件；
- NocoBase Client 注册 API Key 不注入运行容器，配置以 `docs/thirdparty-oauth-login.md` 为准；它与
  Authz Gateway 的 `x-authz-key` 应用凭据不是同一种密钥。

同一 Client ID、Secret 和回调 URI 必须同时注入 NocoBase 与网关。环境变量改变必须重建容器，
普通 `docker restart` 不会改变容器环境。详细配置见 `docs/sso-jwt-auth.md`。

其他 Provider：

- DingTalk 使用 `authCode` 回调和专用 token/userinfo 请求头；
- Google 要求 verified email；
- 微信使用网站应用 `snsapi_login`，不是公众号或小程序流程；
- 未完整配置的 Provider 必须继续显示“待配置”，但不能发起残缺授权流程。

## 7. Admin UI 规则

技术栈固定为 Vue 3 Browser Global + Quasar UMD，无用户明确要求时不加入 Node、Vite 或 Vue Router。
生产页面只加载 `admin/vendor/quasar-umd.js` 和 `admin/vendor/quasar-umd.css` 两个框架 bundle；其中已包含
Vue、Quasar、zh-CN/en-US、MDI v7、Roboto 和图标字体。

页面结构：

```text
index.html + app.js + app.css
  ├─ SSI include: menu.html（同一 Vue 壳内的菜单片段）
  └─ 右侧 iframe:
       ├─ apps/users.html
       └─ apps/authorization.html
共享: api.js、i18n.js、app-page.css、vendor/*
```

必须保持以下 UI 契约：

- 暗色 Pollux/Linear 风格，低对比边框、柔和紫色强调、10-16px 圆角；
- 保留大型统计卡片，但压缩页首空白，不恢复冗余大标题；
- 无顶部菜单栏；仅右侧应用使用无边框 iframe，左侧菜单由 SSI 直接组装；
- 左栏展开 220px、收起 40px；收起时图标仍可见、左对齐且状态切换图标正确；
- Logout 和语言切换在左下角；窄栏下图标/文字可换行；
- 字号使用适配规则，正文不可因桌面布局而缩小到难以阅读；
- `app.js` 只允许白名单右侧页面，所有 `postMessage` 校验同源和发送窗口；
- 页面 API 统一放 `api.js`；右侧应用页面的 Vue 初始化与页面业务 JS 内联在 HTML 底部；
- 危险操作必须确认，网络请求必须展示 Loading 和可见错误。

i18n 默认完整支持 `zh-CN` 和 `en-US`：

- 词典集中在 `admin/i18n.js`；
- 偏好键为 `localStorage.admin_locale`；
- 通过同源 `postMessage` 和 storage event 同步壳及右侧应用 iframe；菜单属于同一壳文档；
- 标题、列名、按钮、Tooltip、Dialog、Notify、校验和空状态不能残留单语言硬编码。

## 8. klib 框架规则

`AGENTS.MD` 是详细规范，以下是不可破坏的框架契约：

- 每个 APP 一个主 Router，模块级创建；请求期间不注册或 merge；
- Router `root_entry` 必须匹配原始 URI 前缀；
- 所有 `register()` 第三个错误值必须检查；
- 所有 `merge()` 返回值必须检查；成功为 `true, route_count`，失败为 `nil, error`；
- merge 在注册前整体预检，失败不能产生半注册状态；
- table 响应为 JSON Content-Type；
- 默认错误处理不回显请求头，生产 API 仍需安装通用 404/500 handler，避免输出内部堆栈；
- handler 签名为 `function(params, env, req)`；API body 优先使用 `req.get_body(env)`；
- `req.get_body()` 只接受 JSON object 或 form；不支持的 Content-Type 必须失败；
- 子 Router merge 仍不会复制 template，模板路由保持在主 Router 或显式渲染；
- 暂不使用损坏的 `add_access()`，也不无 seed 调用 timer `ctxvar`。

## 9. 测试策略

涉及 `ngx`、请求阶段、Router、session、Cookie、OAuth 或代理行为，必须在真实 OpenResty 容器中测试，
不能只运行系统 Lua。

推荐顺序：

```bash
git diff --check

OPENRESTY_TEST_IMAGE=openresty-base:nocobase-test \
  bash test/test_klib_router_ctxvar.sh

OPENRESTY_TEST_IMAGE=openresty-base:nocobase-test \
  bash test/test_authz_gateway.sh

bash test/run_tests.sh openresty-base:nocobase-test
```

三组测试职责：

| 脚本 | 覆盖 |
|---|---|
| `test/test_klib_router_ctxvar.sh` | Router/ctxvar、JSON、错误脱敏、merge 返回与原子性 |
| `test/test_authz_gateway.sh` | 登录、API、CSRF、身份隔离、远端记录、OAuth、动态代理和 HTTPS Cookie |
| `test/run_tests.sh` | 镜像基础库、WebDAV、FancyIndex、JWT/旧 SSO 兼容 |

截至本文更新，最近基线为 Router 99、Authz 270、基础镜像 17，共 386 项/断言。数量不是固定契约；
任何行为变更必须增加或调整能验证真实 HTTP 结果的断言。

OAuth 测试使用 `test/mock_nocobase.py`，不得连接生产账号或把真实 token 写入测试输出。测试至少覆盖
PKCE、resource、回调 issuer、state 一次性、角色映射、同名来源隔离和禁用状态保持。

## 10. 部署与挂载

推荐 Compose；要代理宿主机 `127.0.0.1:<port>` 时使用 host network。必须持久化/挂载：

```text
宿主机 data/   -> /data
宿主机 admin/  -> /usr/local/openresty/nginx/html/admin:ro
宿主机 lualib/ -> /usr/local/openresty/site/lualib:ro
```

这使 Lua 和前端修改无需重建镜像。部署操作区分：

- 只改挂载代码/静态资源：`openresty -t` 后重启或 reload；
- 镜像部署修改 `conf/nginx.conf.template` 或 `conf/server.conf.template`：重新构建并重建容器；主模板由 entrypoint 执行 `envsubst`，公共 server 模板由两个 listener 直接 include；
- 开发时若显式挂载两个模板：主模板变化需要重启容器重新渲染，只有公共 server 模板变化时可先 `openresty -t` 再 reload；
- 改环境变量、网络、挂载、镜像：重建容器；
- 改数据库 schema：先备份 `/data/authz/authz.db`，不得先热更新挂载 Lua；必须重启或重建容器，让 `init_by_lua` 的幂等迁移在 worker 接收流量前完成；
- 改 vendor：重新生成 manifest 和哈希，不在页面恢复 CDN 依赖。

生产检查模板：

```bash
docker inspect <container> --format '{{.Config.Image}} {{.HostConfig.NetworkMode}}'
docker inspect <container> --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
docker exec <container> openresty -t
docker restart --time 2 <container>
curl -fsS http://127.0.0.1:6080/_authz/login >/dev/null
```

不要默认容器名。历史实例用过 `authz-gw`，Compose 默认名是 `openresty-gateway`。

日常重建优先使用仓库脚本：

```bash
bash scripts/restart_gateway.sh          # 使用当前镜像，应用新的 .env
bash scripts/restart_gateway.sh --build  # 按当前 Docker 架构重建镜像后部署
```

脚本会拒绝非 `host` 网络，执行 `openresty -t`，并检查登录页、session API、Admin 入口和 HTTPS 登录页。
`.env`、网络、挂载和镜像变化都要重建容器；仅执行 `docker restart` 不会更新容器创建时的环境变量。
主配置或公共 `server.conf.template` 变化必须 `--build`；`admin/` 和 `lualib/` 是挂载目录，修改它们通常无需重新构建镜像。

### 10.1 本次代理排障经验

1. 先确认上游服务本身：`curl -i http://127.0.0.1:2077/` 返回 `200` 才说明本机 code-server HTTP 服务正常；本机 HTTPS 失败不代表网关故障。
2. 再确认网关入口：`6443` 对外提供 HTTPS，但上游仍是 HTTP，不能设置上游 TLS 参数。
3. 未登录时，绑定已解析但返回 `302` 到 `/_authz/login` 是预期认证结果；它证明请求已经进入认证链路。
4. WebSocket 默认全局开启；不同前缀可以共用同一端口，但同一最终域名重复创建返回 `409`。验证时只需携带 `Upgrade: websocket`，不依赖绑定记录中的旧 `websocket` 值。
5. 管理菜单优先使用已配置绑定的 `menu-name`，其次是绑定域名；没有绑定时才使用自动发现的 `local:<port>`。

## 11. 已解决故障与防回归点

- Admin UI 统一使用 `/_radmin_/`，不要恢复 `/admin/`；旧路径曾与认证跳转和 Cookie 问题混杂。
- 登录错误 query 必须通过 `ngx.req.get_uri_args()` 解码，不能直接渲染 `ngx.var.arg_err` 的百分号编码。
- 登录页和 OAuth 的 start/callback 响应必须使用 `Cache-Control: no-store`，避免浏览器回退或 302 缓存重现旧错误。
- 右侧 iframe 必须占满壳的剩余空间；修改 drawer 时同时验证右侧内容可见。
- 40px mini drawer 下，菜单、收缩按钮、Logout、语言按钮必须分别验证“可见”和“可点击”。
- `klib.router` JSON Content-Type、默认错误请求头脱敏、`merge()` 返回/原子性均有真实回归，不能退回旧行为。
- 整体挂载 `lualib`，避免镜像内有 `klib`、挂载后却缺失的差异。
- `db.lua` 的缓存查询键包含 `authz_cache:db_rev`；管理 API 写入会 bump revision 并让所有 worker 使用新查询键。
  直接改 SQLite 不会触发 revision，必须走 service/API，或重启进程。
- 反向代理终止 TLS 时正确传递 `X-Forwarded-Proto`，或设置 `AUTHZ_COOKIE_SECURE=true`。
- `/_radmin_/` 静态资源默认启用 Brotli/Gzip，Brotli 动态等级 5、Gzip 等级 5；镜像构建为资源生成 Brotli 等级 11 的 `.br` 侧车文件，并通过 `brotli_static on` 优先提供。
- Admin 入口启用 SSI，个性化壳输出 `Cache-Control: no-store`；普通静态资源通过 `expires max` 输出长期缓存头。
- Dockerfile 使用 Buildx 多阶段构建，`RESTY_J` 默认 8；源码下载单独缓存，GitHub Actions 使用 GHA cache。不要退回 `DOCKER_BUILDKIT=0`。
- 发布或部署镜像时优先使用 GitHub Actions 推送到 GHCR 的镜像；只有调试 Dockerfile、验证未发布改动或 CI 不可用时才本地构建。
- Docker Desktop for Mac 必须开启 Host Networking；否则容器内的 `127.0.0.1` 不代表宿主机端口，自动发现和代理测试都会产生误导性结果。

## 12. 维护交付清单

- [ ] 未改变稳定入口和 API 根路径；
- [ ] 身份始终按来源 + 用户名处理；
- [ ] 非 admin 无法读取用户列表和授权策略；
- [ ] 远程禁用状态不会被后续登录记录重新启用；
- [ ] Router register/merge 错误全部检查；
- [ ] 新增 API 有真实 OpenResty HTTP 测试；
- [ ] Admin UI 中英文、移动宽度、mini drawer、SSI 菜单和右侧 iframe 都验证；
- [ ] 没有记录密码、Cookie、Client Secret、Authorization 或 access token；
- [ ] `git diff --check` 和相关三组测试通过；
- [ ] 生产先 `openresty -t`，再部署，并验证登录页、session API 和一个受保护应用。
