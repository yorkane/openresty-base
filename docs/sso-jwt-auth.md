# openresty-base × NocoBase SSO (JWT) 集成指南

本镜像已将 `lua-resty-jwt`（APISIX 同款 api7 fork）及其依赖集成到
`/usr/local/openresty/lualib/resty/` 公共库，并提供 `resty.noco_auth`
封装，使基于本镜像的 OpenResty 代理配置可以直接验证
APISIX [noco_sso_auth](../../docs/noco_sso_auth.md) 方案签发的
`sso_ck` JWT Cookie，实现无缝对接。

## 集成内容

| 模块 | 来源 | 路径 |
|------|------|------|
| `resty.jwt` | [api7-lua-resty-jwt](https://github.com/api7/lua-resty-jwt) v0.2.6（APISIX 同款） | `/usr/local/openresty/lualib/resty/jwt.lua` |
| `resty.jwt-validators` | 同上 | `.../resty/jwt-validators.lua` |
| `resty.evp` | 同上（RSA/EC 验签支持） | `.../resty/evp.lua` |
| `resty.hmac` | 本项目适配器（基于捆绑 `resty.openssl.hmac`） | `.../resty/hmac.lua` |
| `resty.noco_auth` | 本项目封装（SSO Cookie 认证） | `.../resty/noco_auth.lua` |

> `resty.hmac` 兼容 lua-resty-hmac-ffi API（`hmac:new(key, hmac.ALGOS.SHA256):final(msg)`，
> 默认返回 raw 二进制摘要，符合 RFC 7518），底层改用 OpenSSL 3.x 兼容的
> `HMAC_CTX_new`，避免旧版 `HMAC_CTX_init` 在 OpenSSL 3.5 中已移除的问题。
> 底层 `resty.openssl.cipher` / `resty.openssl.hmac` 由 OpenResty 捆绑的
> `lua-resty-openssl` 提供，无需额外安装。

## 与 APISIX noco_sso_auth 的对接约定

APISIX 登录流程签发的 Cookie：

| Cookie | 格式 | 说明 |
|--------|------|------|
| `sso_ck` | JWT（HS256，密钥 `sso_key`） | payload 含 `{ uid, uname, exp }` |
| `noco_uid` | `<reqid>-<MMDDHHmmss>`（2 段=有会话） | 登录后 |
| `noco_uid` | `<reqid>-<MMDDHHmmss>-<uname>`（3 段=已认证） | SSO 续签后 |

## 快速使用

### 1. 全站保护（access_by_lua + 自动跳转，推荐）

```nginx
http {
    # init 阶段注入 SSO 配置（signin / sso_renew URL 等）
    init_by_lua_block {
        local noco = require "resty.noco_auth"
        noco.setup({
            sso_key       = "sso_key",                       -- APISIX 侧 sso_key
            signin_url    = "https://noco.w.wtvdev.com/api/auth:signIn",  -- 登录端点
            sso_renew_url = "https://noco.w.wtvdev.com/_sso_renew",       -- 续期端点
        })
    }

    server {
        listen 80;
        server_name app.example.com;

        location / {
            access_by_lua_block {
                local noco = require "resty.noco_auth"
                local user = noco.authorize()   -- 内部自动处理跳转
                if not user then
                    return  -- 已 302 到 signin / sso_renew，无需再 exit
                end
                ngx.ctx.sso_user = user
            }

            proxy_pass http://backend_upstream;
        }
    }
}
```

`authorize()` 自动鉴权流程：

| 场景 | 行为 |
|------|------|
| `sso_ck` 有效 | 放行，返回 `payload {uid, uname, exp}` |
| 无任何会话 Cookie | 302 → `signin_url`（登录） |
| `sso_ck` 缺失/过期/失效，但存在 `noco_uid` 会话 | 302 → `sso_renew_url?url=<当前URI>`（续期后自动回跳） |
| 过期/失效且无 `noco_uid` | 302 → `signin_url` |

> `sso_renew_url` 会携带 `url=<当前请求URI>`（URL 编码）回跳参数，
> 与 APISIX noco_sso_auth 的 `sso_renew?url=xxx → 302 redirect` 行为一致。

### 2. 调用级配置（不经 setup，直接传参）

```nginx
location / {
    access_by_lua_block {
        local noco = require "resty.noco_auth"
        local user = noco.authorize("sso_key", {
            signin_url    = "/login",   -- 覆盖默认
            sso_renew_url = "/renew",
        })
        if not user then return end
        ngx.ctx.sso_user = user
    }
    proxy_pass http://backend;
}
```

### 3. 仅保护指定 location（手动 401）

```nginx
location /admin/ {
    access_by_lua_block {
        local noco = require "resty.noco_auth"
        local user, err = noco.verify_request("sso_key")
        if not user then
            return ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
        -- 可再叠加 noco_uid 三段的强认证校验：
        local _, noco_info = noco.authenticate("sso_key")
        if not noco_info or noco_info.state ~= "authed" then
            return ngx.exit(ngx.HTTP_FORBIDDEN)  -- 已登录但未完成跨域 SSO
        end
        ngx.ctx.sso_user = user
    }
    proxy_pass http://backend_upstream;
}
```

### 3. 把用户信息透传给后端（X-User 头）

```nginx
location /api/ {
    access_by_lua_block {
        local noco = require "resty.noco_auth"
        local user, err = noco.verify_request("sso_key")
        if not user then
            return ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
        ngx.req.set_header("X-SSO-UID", user.uid)
        ngx.req.set_header("X-SSO-UNAME", user.uname)
        ngx.req.set_header("X-SSO-EXP", user.exp)
    }
    proxy_pass http://backend_upstream;
}
```

## API 参考

### `resty.noco_auth`

| 函数 | 说明 |
|------|------|
| `setup(opts)` | 注入模块级配置（建议 `init_by_lua_block` 调用一次） |
| `authorize(secret?, opts?)` | **推荐**：验证 `sso_ck`；失败时自动 302 跳转（无会话→`signin_url`，有会话但 cookie 失效→`sso_renew_url?url=`）。`secret` 可省略（用 setup 注入的 `sso_key`），也支持 `authorize({...})` 形式 |
| `verify_request(secret, opts?)` | 读取当前请求的 `sso_ck` Cookie 并验证，返回 `payload` 或 `nil, err` |
| `verify_token(secret, token, opts?)` | 验证给定 JWT 字符串（无需请求上下文） |
| `authenticate(secret, opts?)` | 验证 `sso_ck` 并解析 `noco_uid`，返回 `payload, noco_info, err` |
| `parse_noco_uid(cookie_value)` | 解析 `noco_uid`，返回 `{ req_id, ts, uname, state }`，state 为 `session`(2段)/`authed`(3段) |
| `get_cookie(cookie_header, name)` | 从 Cookie 头字符串提取指定 cookie 值 |
| `get_uid(secret, opts?)` / `get_uname(secret, opts?)` | 快速取当前用户 uid / uname |
| `build_url(target, return_url, opts?)` | 拼接带 `url=` 回跳参数的跳转地址 |
| `redirect(target, opts?)` | 302 跳转（`opts.redirect_code` 可覆盖状态码） |
| `sign(secret, payload, opts?)` | 签发 HS256 JWT（可选，用于自建 sso_renew 服务） |

**`setup()` / 调用级 `opts` 可配置项**（调用级优先）：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `sso_key` | nil | sso_ck JWT 的 HMAC 密钥（对应 APISIX 侧 `sso_key`） |
| `signin_url` | `/api/auth:signIn` | 无会话时 302 跳转的登录端点 |
| `sso_renew_url` | `/_sso_renew` | cookie 失效时 302 跳转的续期端点 |
| `cookie_name` | `sso_ck` | sso JWT cookie 名 |
| `leeway` | 60 | exp 时钟偏差容忍（秒） |
| `return_url_param` | `url` | sso_renew 回跳参数名 |
| `signin_append_url` | false | 是否给 signin_url 也追加回跳参数 |
| `redirect_code` | 302 | 跳转状态码 |

### `resty.jwt`（原汁原味）

```lua
local jwt = require "resty.jwt"
local ok_obj = jwt:verify("sso_key", token)
if ok_obj.verified then ... end

local token = jwt:sign("sso_key", {
    header  = { typ = "JWT", alg = "HS256" },
    payload = { uid = 3, uname = "kate", exp = os.time() + 3600 },
})
```

### `resty.hmac`

```lua
local hmac = require "resty.hmac"
local mac  = hmac:new("sso_key", hmac.ALGOS.SHA256)
local raw  = mac:final("hello")      -- raw 摘要（默认）
local hex  = mac:final("hello", true) -- hex 摘要
```

## 签发侧（可选）：镜像内自建 sso_renew

如果不想依赖 APISIX 的 `/_sso_renew`，可用本镜像签发相同格式的 Cookie：

```nginx
location /_sso_renew {
    content_by_lua_block {
        local noco = require "resty.noco_auth"
        local exp  = ngx.time() + 24 * 3600
        local token, err = noco.sign("sso_key", { uid = 3, uname = "kate", exp = exp })
        if not token then
            return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end
        local cookie = "sso_ck=" .. token .. "; Path=/; HttpOnly; Max-Age=86400"
        ngx.header["Set-Cookie"] = cookie
        ngx.say("ok")
    }
}
```

## 验证与调试

```bash
# 进入容器内直接验证
docker run --rm ghcr.io/yorkane/openresty-base:latest sh -c '
  echo "dofile(\"/tmp/check.lua\")" > /tmp/check.lua  # 见下
'

# 容器内一行验证（resty CLI 需要 perl，用 openresty -e 即可）
docker run --rm ghcr.io/yorkane/openresty-base:latest openresty -e '
  local noco = require "resty.noco_auth"
  -- 与 APISIX 互操作的 HS256 验证
'
```

模块列表自检：

```lua
local mods = { "resty.jwt", "resty.jwt-validators", "resty.hmac", "resty.noco_auth", "resty.openssl.hmac" }
for _, m in ipairs(mods) do
    local ok, err = pcall(require, m)
    ngx.say(m, " => ", ok and "OK" or tostring(err))
end
```

## 常见问题

| 问题 | 说明 |
|------|------|
| `jwt verify failed: signature mismatch` | 密钥不一致，或 token 被篡改；确认 `sso_key` 与 APISIX 配置一致 |
| `sso token expired` | `exp` 已过（默认容忍 60s 时钟偏差，可调 `leeway`） |
| 401 on 无 Cookie | 预期行为；需先经 APISIX 登录拿到 `sso_ck` |
| 是否需要额外安装依赖 | 不需要；全部随镜像内置，`lua_package_path` 默认已覆盖 `lualib` |
