# openresty-base

定制 OpenResty Alpine Docker 镜像，在官方源码编译基础上额外集成：

- [lua-nginx-module](https://github.com/openresty/lua-nginx-module) — master 分支最新版本（替换 OpenResty 内置捆绑版）
- [nginx-dav-ext-module](https://github.com/arut/nginx-dav-ext-module) — WebDAV PROPFIND / OPTIONS / LOCK / UNLOCK 支持
- [ngx-fancyindex](https://github.com/aperezdc/ngx-fancyindex) — 美化目录索引
- [lua-resty-jwt](https://github.com/api7/lua-resty-jwt) — JWT 签发/验证（APISIX 同款 api7 fork，含 `resty.noco_auth` SSO 对接封装）
- **Authz Gateway** — 动态端口代理 + 本地认证授权（SQLite + mini-casbin + 管理界面）

## Authz Gateway（动态端口代理 + 认证授权）

镜像默认以网关模式启动，两个入口：

| 入口 | 上游 | 说明 |
|------|------|------|
| `6080` (http) | `http://127.0.0.1:<port>` | 代理本机 http 服务 |
| `6443` (https) | `https://127.0.0.1:<port>` | 自签默认证书，代理本机 https 服务 |

### 域名 → 端口解析规则

1. **数字前缀子域名**（免配置）：`3000-任意域名` → 本机 `3000` 端口，
   支持多级子域名（`3000-a.b.c.example.com`），端口范围默认 `2000-20000`
2. **显式绑定**：管理界面配置固定域名映射（存 SQLite）
3. 其余域名 → 404

所有代理流量需登录 + Casbin 策略授权；后端收到 `X-Authz-User` 头。

### 管理界面

访问任意入口的 `/_authz/`：

- 登录 / 登出（服务端会话，HttpOnly Cookie，CSRF 防护）
- 域名绑定管理（增删/启停）
- Casbin 策略编辑（p 授权行 / g 角色分配，deny 优先，fail-closed）
- 用户管理（创建/禁用/删除/重置密码/角色分配）
- 修改密码

首次启动自动 seed：`admin / admin123`（务必尽快改密）与默认策略
（`role:admin`、`role:user` 对 `/*` 全放行）。

### 快速使用

```bash
docker run -d --name gw --network host \
  -v /data/gw:/data \
  -e AUTHZ_ADMIN_PASSWORD=your-secret \
  ghcr.io/yorkane/openresty-base:latest
# 浏览器打开 http://<host>:6080/_authz/ 登录
# 代理本机 3000 端口: http://3000-myhost.example.com:6080/
```

### 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `AUTHZ_DB_PATH` | `/data/authz/authz.db` | SQLite 路径（用户/会话/策略/绑定） |
| `AUTHZ_ADMIN_PASSWORD` | `admin123` | 首次 seed 的 admin 密码 |
| `AUTHZ_PORT_MIN` / `AUTHZ_PORT_MAX` | `2000` / `20000` | 数字前缀端口范围 |
| `AUTHZ_HTTP_PORT` / `AUTHZ_HTTPS_PORT` | `6080` / `6443` | 入口端口 |
| `AUTHZ_CERT_DIR` | `/data/certs` | 自签证书目录（10 年有效） |
| `AUTHZ_SESSION_TTL` | `604800` | 会话有效期（秒） |

### 数据持久化

挂载 `/data` 即可：`/data/authz/authz.db`（全部状态）+ `/data/certs/`（证书）。

### 功能测试

```bash
# 需要: 容器 authz-gw (--network host) 运行中 + 本机 mock 端口 3456(http)/4567(https)
bash test/test_authz_gateway.sh   # 26 项断言
```

## JWT / SSO 集成

镜像内置 `resty.jwt`、`resty.hmac`（OpenSSL 3.x 兼容适配）与 `resty.noco_auth`，
可直接验证 [APISIX noco_sso_auth](../../docs/noco_sso_auth.md) 签发的
`sso_ck` JWT Cookie，实现 OpenResty 代理与 APISIX SSO 无缝对接。

```nginx
location / {
    access_by_lua_block {
        local noco = require "resty.noco_auth"
        local user, err = noco.verify_request("sso_key")
        if not user then return ngx.exit(ngx.HTTP_UNAUTHORIZED) end
        ngx.ctx.sso_user = user
    }
    proxy_pass http://backend;
}
```

完整指南见 [docs/sso-jwt-auth.md](docs/sso-jwt-auth.md)。

## 镜像地址

| Registry | 地址 |
|----------|------|
| GitHub Container Registry | `ghcr.io/yorkane/openresty-base` |
| Docker Hub | `yorkane/openresty-base` |

## 快速使用

```bash
docker pull ghcr.io/yorkane/openresty-base:latest
# 或
docker pull yorkane/openresty-base:latest
```

## Tag 规则

| Tag | 说明 |
|-----|------|
| `latest` | 最新构建 |
| `1.31.1.1` | OpenResty 版本号 |
| `1.31.1.1-20260315` | OpenResty 版本 + 构建日期 |

## 组件版本

| 组件 | 版本策略 |
|------|---------|
| Alpine | 3.23.5 |
| OpenResty | 自动检测官网最新稳定版 |
| LuaJIT | OpenResty 捆绑版（2.1.ROLLING） |
| lua-nginx-module | GitHub `master` 分支最新 commit |
| stream-lua-nginx-module | GitHub `master` 分支最新 commit |
| lua-resty-core | GitHub `master` 分支最新 commit |
| lua-resty-jwt | api7 fork v0.2.6（APISIX 同款） |
| nginx-dav-ext-module | GitHub `master` 分支最新 commit |
| ngx-fancyindex | 最新 Release tag |
| LuaRocks | 3.13.0 |
| OpenSSL | 3.5.7 (patch base 3.5.5) |
| PCRE2 | 10.47 |

## 镜像特性

- **基础镜像**：`alpine:3.23`，最终镜像约 **~75 MB**
- **单层构建**：所有编译步骤合并为一个 `RUN`，编译工具链在构建完成后完全清除
- **二进制精简**：`strip` nginx / luajit / openssl / pcre2 / *.so，去掉调试符号
- **运行时依赖最小化**：仅保留必要的 so 和 Alpine 包
- **动态模块**：geoip、image_filter、xslt 以动态 `.so` 形式保留
- **OpenSSL 独立编译**：作为共享库安装到 `/usr/local/openresty/openssl3`，并应用 OpenResty 官方补丁（`sess_set_get_cb_yield`）
- **PCRE2 独立编译**：作为共享库安装到 `/usr/local/openresty/pcre2`，启用 JIT
- **去掉 RDS / Mail POP3/IMAP/SMTP**：与官方 alpine 镜像保持一致

## 本地构建

```bash
docker build -t openresty-base:local .
```

## 本地测试

```bash
# 运行完整功能测试（需要 Docker + curl）
bash test/run_tests.sh

# 指定自定义镜像
bash test/run_tests.sh ghcr.io/yorkane/openresty-base:1.31.1.1
```

测试覆盖以下功能点：

| # | 测试项 | 验证内容 |
|---|--------|---------|
| 1 | Lua 基础 | `content_by_lua_block`，`ngx_lua_version` |
| 2 | cjson | 内置 `cjson.encode` |
| 3 | resty 库 | `resty.core` / `ngx.re` / `resty.lrucache` / `resty.string` / `resty.md5` |
| 4 | LuaJIT FFI | `ffi.arch`、`ffi.os` |
| 5 | FancyIndex | 目录浏览 HTML 响应 |
| 6 | WebDAV | OPTIONS → Allow 头、PUT 201、PROPFIND 207 |
| 7 | Error log | 确认无 `[error]` 行 |

## 自动构建

GitHub Actions 每周一 UTC 02:00 自动检测最新版本并构建，推送到 GHCR 和 Docker Hub。  
也可在仓库 **Actions → Build and Publish → Run workflow** 手动触发（支持指定 OpenResty 版本和强制重建）。

## 平台支持

| 平台 | 支持 |
|------|------|
| `linux/amd64` | ✅ |
| `linux/arm64` | ❌（暂未支持） |

## 配置 Secrets

使用 Docker Hub 推送前，需在仓库 **Settings → Secrets and variables → Actions** 中添加：

| Secret 名称 | 说明 |
|-------------|------|
| `DOCKERHUB_USERNAME` | Docker Hub 用户名（`yorkane`） |
| `DOCKERHUB_TOKEN` | Docker Hub Access Token |

GHCR 推送使用内置 `GITHUB_TOKEN`，无需额外配置。

## 目录结构

```
.
├── Dockerfile                  # 单阶段 Alpine 构建
├── README.md
├── docker-entrypoint.sh        # 证书生成 + conf 渲染 + 启动
├── docs/
│   └── sso-jwt-auth.md         # NocoBase SSO (JWT) 集成指南
├── lualib/
│   └── resty/
│       ├── hmac.lua            # resty.hmac 适配器（基于捆绑 resty.openssl.hmac）
│       ├── noco_auth.lua       # resty.noco_auth SSO Cookie 认证库
│       └── authz/              # Authz Gateway (动态端口代理+认证)
│           ├── init.lua        # 入口: 配置/端口解析/认证授权
│           ├── app.lua         # 管理界面 (登录/绑定/策略/用户)
│           ├── db.lua          # SQLite FFI 封装 + schema
│           ├── casbin.lua      # mini-casbin (p/g, deny优先)
│           ├── session.lua     # 服务端会话
│           └── util.lua        # 密码哈希/随机token/HTML转义
├── conf/
│   ├── nginx.conf.template     # 网关 nginx 配置模板
│   └── openssl.cnf             # 最小 openssl 配置(自签证书用)
└── test/
    ├── run_tests.sh            # 基础功能测试脚本
    ├── test_authz_gateway.sh   # Authz Gateway 测试矩阵 (26项)
    ├── conf/
    │   └── nginx.conf          # 测试用 nginx 配置
    ├── html/                   # FancyIndex 测试文件
    ├── dav/                    # WebDAV 上传目录（运行时生成）
    └── logs/                   # nginx 日志（运行时生成）
```
