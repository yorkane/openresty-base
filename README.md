# openresty-base

定制 OpenResty Alpine Docker 镜像，在官方源码编译基础上额外集成：

- [lua-nginx-module](https://github.com/openresty/lua-nginx-module) — master 分支最新版本（替换 OpenResty 内置捆绑版）
- [nginx-dav-ext-module](https://github.com/arut/nginx-dav-ext-module) — WebDAV PROPFIND / OPTIONS / LOCK / UNLOCK 支持
- [ngx-fancyindex](https://github.com/aperezdc/ngx-fancyindex) — 美化目录索引
- [lua-resty-jwt](https://github.com/api7/lua-resty-jwt) — JWT 签发/验证（APISIX 同款 api7 fork，含 `resty.noco_auth` SSO 对接封装）

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
├── docs/
│   └── sso-jwt-auth.md         # NocoBase SSO (JWT) 集成指南
├── lualib/
│   └── resty/
│       ├── hmac.lua            # resty.hmac 适配器（基于捆绑 resty.openssl.hmac）
│       └── noco_auth.lua       # resty.noco_auth SSO Cookie 认证库
└── test/
    ├── run_tests.sh            # 功能测试脚本
    ├── conf/
    │   └── nginx.conf          # 测试用 nginx 配置
    ├── html/                   # FancyIndex 测试文件
    ├── dav/                    # WebDAV 上传目录（运行时生成）
    └── logs/                   # nginx 日志（运行时生成）
```
