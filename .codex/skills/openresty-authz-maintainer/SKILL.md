---
name: openresty-authz-maintainer
description: 维护本仓库的 OpenResty Authz Gateway、klib Router、Vue 3 + Quasar UMD 管理端、身份认证授权、真实容器测试和挂载式部署。用于修改或排查本项目，不用于通用 OpenResty 教程。
---

# OpenResty Authz Maintainer

维护当前仓库时，先读取：

1. `AGENTS.MD`：klib Router、ctxvar 和真实 OpenResty 约束；
2. `docs/maintenance-handbook.md`：系统架构、身份模型、UI、测试和部署知识；
3. 涉及 NocoBase/OAuth 时读取 `docs/sso-jwt-auth.md`；
4. 涉及 Admin UI 时检查 `admin/vendor/manifest.json`、SSI 入口和现有 i18n 实现。

## 工作原则

- 先查看 `git status`，保留用户已有修改；只做任务需要的最小改动。
- 以代码和真实 HTTP 回归为准；发现文档与实现冲突时，先验证，再同步修正文档。
- 涉及 `ngx`、请求阶段、worker 生命周期、Cookie、Router、代理或 OAuth 时，必须用真实 OpenResty 容器验证。
- 不记录或输出密码、Cookie、Client Secret、Authorization header、access token 或完整敏感请求体。
- 外部身份源注册、凭据轮换和生产容器重建属于外部状态修改；没有明确授权和访问入口时只准备代码与步骤。

## 稳定架构

- Admin UI 入口仅为 `/_radmin_/`；不要引入 `/admin/`。
- 登录/OAuth 保持在 `/_authz/*`，管理 API 保持在 `/_api_/authz/v1/*`。
- 旧 `/_authz/api/*` 和 `*/save` 保持 410，不恢复双栈 API。
- API 使用一个模块级 `klib.router("/_api_")`；路由代码注册，禁止请求期注册或数据库动态路由。
- 身份键固定为 `user:<source>:<username>`；同名不同来源必须完全隔离。
- 本地角色目录固定为 `admin/staff/user/viewer`，默认拒绝，只有 admin 默认拥有 `/*`。
- 管理写操作必须经过 service 并 bump cache revision；不要绕过 API 直接改库作为功能实现。
- `lualib/resty/authz/db.lua` 是 SQLite 数据层，查询必须使用 vendored `resty.mlcache`；成功 `exec()`
  必须 bump `authz_cache:db_rev`，查询键必须包含 revision，保证多 worker 写后读到新数据。
- `lualib/resty/mlcache.lua` 必须随 `lualib/` 整体复制和挂载；不引入网络运行时依赖，不使用未经验证的
  CDN 版本。直接 SQLite 写入不会触发数据库缓存失效。
- 外部身份只在成功登录时单向记录到本机；禁止回写身份源或同步外部网关路由、用户、角色和策略。

## 后端与框架规则

- 所有 Router `register()` 第三个错误值必须断言。
- 所有 `merge()` 返回值必须检查；失败不能留下部分路由。
- table 响应必须为 `application/json; charset=UTF-8`。
- 生产 API 安装稳定的 404/500 JSON handler，不暴露请求头、token 或内部堆栈。
- API handler 使用 `params/env/req`，JSON/form body 使用 `req.get_body(env)`。
- guard 顺序保持会话、admin、CSRF，再进入 service；修改请求使用 `X-CSRF-Token`。
- `lualib` 作为整体复制和整体挂载，不能只部署 `resty/authz` 子目录。
- NocoBase 2.2 OAuth 以 `docs/thirdparty-oauth-login.md` 为准：公网 Client 通过
  `oidcStates:create` 一次性注册，运行时使用 Code + PKCE、`client_secret_basic` 和严格 `iss` 校验；
  禁止恢复 `app:` 静态 Client、NocoBase 本地插件或 `resource` 参数方案。

## 前端规则

- 使用 Vue 3 Browser Global + Quasar UMD；除非用户明确要求，不加入 Node、Vite、Vue Router 或额外状态库。
- 框架资源只引用 `vendor/quasar-umd.js` 和 `vendor/quasar-umd.css`；保持 MDI v7 与中英文语言包。
- `api.js` 保持独立；右侧应用页的 Vue 初始化和页面业务 JS 内联在各自 HTML 底部。
- 保持无顶部菜单、SSI 组装左菜单 + 右应用 iframe、无 iframe 边框；drawer 展开 220px、收起 40px。
- mini drawer 下逐项验证菜单、切换、Logout 和语言按钮可见；不要只测试点击区域。
- i18n 完整覆盖 zh-CN/en-US，并通过 `admin_locale`、同源 postMessage 和 storage event 在壳与右侧应用页面间同步。
- 延续 Linear/Pollux 暗色、低对比边框、柔和紫色、10-16px 圆角和可读的响应式字号。
- 网络操作展示 Loading/错误，删除、禁用、覆盖和恢复操作需要确认。
- `/_radmin_/` 精确入口必须启用 SSI 并输出 `Cache-Control: no-store`；菜单是 `menu.html` SSI 片段，不能恢复菜单 iframe。
- 菜单应用列表通过 `resty.authz.discovery` 探测网关本机 `127.0.0.1` 的 HTTP 服务，仅扫描配置端口范围、排除网关端口，并使用短超时缓存结果；不要恢复仅依赖 `bindings` 表的菜单发现。
- Dockerfile 必须保留 `--with-http_ssi_module` 和 `ngx_brotli`；Brotli 动态等级 5，静态资源构建时生成等级 11 的 `.br`，由 `brotli_static` 提供。
- `conf/nginx.conf.template` 只维护全局配置、HTTP/HTTPS listener 和 TLS；两个 server 必须共同 include `conf/server.conf.template`，控制面 location 与代理参数只在公共片段维护。

## 验证顺序

先运行最相关测试，再运行完整基线：

```bash
git diff --check
OPENRESTY_TEST_IMAGE=openresty-base:nocobase-test bash test/test_klib_router_ctxvar.sh
OPENRESTY_TEST_IMAGE=openresty-base:nocobase-test bash test/test_authz_gateway.sh
bash test/run_tests.sh openresty-base:nocobase-test
```

镜像发布和部署优先使用 GitHub Actions 构建并推送的 GHCR 镜像；仅在调试 Dockerfile、验证未发布改动或 CI 不可用时本地构建。
本地构建需要 Docker CLI `buildx`，可使用 `docker buildx build --load` 或 `docker compose build`，不要设置
`DOCKER_BUILDKIT=0` 退回 legacy builder。普通代码修改优先复用 BuildKit 缓存；只有变更 OpenResty
版本、编译参数或原生模块时才触发完整编译。
新增行为必须增加可观察的 HTTP 断言，不能只匹配源代码字符串。

## 部署规则

- 开发/生产挂载保持：`data -> /data`、`admin -> nginx/html/admin:ro`、`lualib -> site/lualib:ro`。
- 修改挂载代码前后执行 `docker exec <container> openresty -t`；环境变量、网络或挂载改变必须重建容器。
- 不假设容器名，先用 `docker ps` 和 `docker inspect` 确认镜像、network mode、mounts 和环境变量状态。
- 部署后至少验证登录页、session API、`/_radmin_/`、SSI 菜单、一个右侧应用 iframe 页面和一个受保护代理目标。
- OAuth 上线还需验证 Provider authorize 跳转、callback、来源、角色和禁用状态，不以“按钮可见”代替成功登录验证。
