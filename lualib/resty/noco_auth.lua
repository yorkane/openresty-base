-- resty.noco_auth
--
-- 与 APISIX noco_sso_auth 方案无缝对接的 OpenResty 侧 SSO 认证库。
--
-- 背景：APISIX 通过 serverless-pre-function 在登录后签发两个 Cookie：
--   sso_ck  = JWT (HS256, sso_key)，payload 含 { uid, uname, exp }
--   noco_uid = <reqid>-<MMDDHHmmss>[-<uname>]
--     2 段 = 已有 NocoBase 会话；3 段 = 已完成跨域 SSO 认证
--
-- 本模块直接放入镜像 /usr/local/openresty/lualib/resty/ 公共库，
-- 代理配置里 require "resty.noco_auth" 即可验证上述 Cookie。
--
-- 用法一（手动验证）：
--   local noco = require "resty.noco_auth"
--   local user, err = noco.verify_request("sso_key")
--   if not user then return ngx.exit(ngx.HTTP_UNAUTHORIZED) end
--   ngx.ctx.sso_user = user
--
-- 用法二（全自动：无 cookie → 302 signin_url 登录；
--           过期/失效但有会话 → 302 sso_renew_url 续期）：
--   init_by_lua_block {
--       local noco = require "resty.noco_auth"
--       noco.setup({
--           sso_key       = "sso_key",
--           signin_url    = "https://noco.w.wtvdev.com/api/auth:signIn",
--           sso_renew_url = "https://noco.w.wtvdev.com/_sso_renew",
--       })
--   }
--   server {
--       location / {
--           access_by_lua_block {
--               local noco = require "resty.noco_auth"
--               local user = noco.authorize()   -- 内部自动 302 跳转
--               if not user then return end
--               ngx.ctx.sso_user = user
--           }
--           proxy_pass http://backend;
--       }
--   }

local jwt = require "resty.jwt"

local _M = { _VERSION = "0.2.0" }

local tonumber = tonumber
local tostring = tostring
local type = type
local pairs = pairs
local setmetatable = setmetatable

-- ── 模块级默认配置（可用 setup() 覆盖，也可在每次调用时传 opts）──────
_M.config = {
    -- sso_ck JWT 的 HMAC 密钥（对应 APISIX 侧配置的 sso_key）
    sso_key       = nil,
    -- 登录端点：无任何会话 Cookie 时 302 跳转至此
    signin_url    = "/api/auth:signIn",
    -- 续期端点：sso_ck 过期/失效但存在 noco_uid 会话时 302 跳转至此，
    -- 自动追加 ?url=<当前请求URI>，APISIX 侧续期成功后 302 回跳
    sso_renew_url = "/_sso_renew",
    -- sso_ck cookie 名
    cookie_name   = "sso_ck",
    -- exp 容忍时钟偏差（秒）
    leeway        = 60,
    -- sso_renew 回跳参数名
    return_url_param = "url",
    -- 是否给 signin_url 也追加 return url（默认 false，signin 通常是 POST 接口）
    signin_append_url = false,
    -- 跳转状态码（302）
    redirect_code = ngx.HTTP_MOVED_TEMPORARILY,
}

-- 注入配置（建议在 init_by_lua_block 中调用一次）
-- @param opts 与 _M.config 同构的 table
function _M.setup(opts)
    opts = opts or {}
    for k, v in pairs(opts) do
        _M.config[k] = v
    end
    return _M.config
end

-- 合并 opts 与模块级配置（调用级 opts 优先）
function _M._resolve_opts(opts)
    local merged = {}
    for k, v in pairs(_M.config) do
        merged[k] = v
    end
    if opts then
        for k, v in pairs(opts) do
            merged[k] = v
        end
    end
    return merged
end

-- ── 跳转辅助 ────────────────────────────────────────────────────────
-- 构造带 return url 的跳转地址
-- @param target 目标 URL/路径
-- @param return_url 回跳地址（通常为当前请求 URI）
-- @param opts
-- @return 拼接后的 URL 字符串
function _M.build_url(target, return_url, opts)
    opts = opts or {}
    if not return_url or return_url == "" then
        return target
    end
    local sep = target:find("?") and "&" or "?"
    return target .. sep .. (opts.return_url_param or "url") .. "="
        .. ngx.escape_uri(return_url)
end

-- 302 跳转（终止当前请求）
function _M.redirect(target, opts)
    opts = opts or {}
    return ngx.redirect(target, opts.redirect_code or ngx.HTTP_MOVED_TEMPORARILY)
end

-- ── noco_uid 解析 ──────────────────────────────────────────────────
-- 输入 "reqid-MMDDHHmmss"（2 段）或 "reqid-MMDDHHmmss-uname"（3 段）
-- 返回 { req_id, ts, uname, state = "session"|"authed" }
-- 失败返回 nil, err
function _M.parse_noco_uid(cookie_value)
    if not cookie_value or cookie_value == "" then
        return nil, "no noco_uid cookie"
    end
    local parts = {}
    for seg in tostring(cookie_value):gmatch("[^-]+") do
        parts[#parts + 1] = seg
    end
    if #parts < 2 then
        return nil, "invalid noco_uid: " .. tostring(cookie_value)
    end
    local info = {
        req_id = parts[1],
        ts = parts[2],
        uname = nil,
        state = "session",
    }
    if #parts >= 3 then
        info.uname = table.concat(parts, "-", 3)
        info.state = "authed"
    end
    return info
end

-- 从 Cookie 请求头字符串中提取指定 cookie 的值
-- 兼容 APISIX 侧的 cookie 处理（分号分隔，key=value）
function _M.get_cookie(cookie_header, name)
    if not cookie_header then
        return nil
    end
    local target = name .. "="
    for part in tostring(cookie_header):gmatch("[^;]+") do
        part = part:gsub("^%s+", "")
        if part:sub(1, #target) == target then
            return part:sub(#target + 1)
        end
    end
    return nil
end

-- ── JWT 验证 ───────────────────────────────────────────────────────
-- 验证 sso_ck token（HS256）
-- @param secret sso_key
-- @param token  JWT 字符串
-- @param opts   { leeway=60, require_uid=false, require_exp=true }
-- @return payload (table) 或 nil, err
function _M.verify_token(secret, token, opts)
    opts = opts or {}
    if type(secret) ~= "string" or secret == "" then
        return nil, "empty sso secret"
    end
    if not token or token == "" then
        return nil, "missing sso token"
    end
    local jwt_obj = jwt:verify(secret, token)
    if not jwt_obj.verified then
        return nil, "jwt verify failed: " .. tostring(jwt_obj.reason)
    end
    local payload = jwt_obj.payload
    if type(payload) ~= "table" then
        return nil, "jwt payload missing"
    end
    -- exp 校验（resty.jwt 本身不校验 claim）
    if opts.require_exp ~= false then
        local exp = tonumber(payload.exp)
        if exp and exp + (opts.leeway or 60) < ngx.time() then
            return nil, "sso token expired"
        end
    end
    if opts.require_uid and not payload.uid then
        return nil, "sso payload missing uid"
    end
    return payload
end

-- 从当前请求的 Cookie 中读取并验证 sso_ck
-- @param secret sso_key
-- @param opts   { cookie_name="sso_ck", leeway=60, require_uid=false }
-- @return payload 或 nil, err
function _M.verify_request(secret, opts)
    opts = opts or {}
    local cookie_name = opts.cookie_name or "sso_ck"
    -- 优先用 nginx 变量 $cookie_xxx（openresty 自动解析）
    local token = ngx.var["cookie_" .. cookie_name]
    if not token then
        token = _M.get_cookie(ngx.var.http_cookie, cookie_name)
    end
    return _M.verify_token(secret, token, opts)
end-- ── 便捷封装 ───────────────────────────────────────────────────────
-- 验证 sso_ck 并同时返回 noco_uid 解析结果
-- @return payload, noco_info, err
function _M.authenticate(secret, opts)
    opts = _M._resolve_opts(opts)
    local payload, err = _M.verify_request(secret, opts)
    if not payload then
        return nil, nil, err
    end
    local noco_info = _M.parse_noco_uid(
        _M.get_cookie(ngx.var.http_cookie, "noco_uid"))
    return payload, noco_info
end

-- ── 全自动鉴权（推荐）：验证失败时自动 302 跳转 ─────────────────────
-- 流程：
--   1. sso_ck 有效           → 返回 payload（放行）
--   2. 无任何会话 Cookie      → 302 跳转 signin_url 登录
--   3. sso_ck 缺失/过期/失效，
--      但存在 noco_uid 会话  → 302 跳转 sso_renew_url?url=<当前URI> 续期
--
-- @param secret sso_key（可省略，使用 setup() 注入的 sso_key）
-- @param opts   调用级覆盖项（signin_url / sso_renew_url / cookie_name 等）
-- @return payload（成功）；失败时已执行 302 跳转并返回 nil, nil, err
function _M.authorize(secret, opts)
    if type(secret) == "table" then
        opts = secret          -- 允许 authorize({ ... }) 形式
        secret = nil
    end
    opts = _M._resolve_opts(opts)
    secret = secret or opts.sso_key
    if not secret or secret == "" then
        return nil, nil, "no sso_key configured (setup({ sso_key = ... }) or authorize(secret))"
    end

    local payload, err = _M.verify_request(secret, opts)
    if payload then
        return payload
    end

    -- 区分场景：是否有 noco_uid 会话 Cookie
    local noco_info = _M.parse_noco_uid(
        _M.get_cookie(ngx.var.http_cookie, "noco_uid"))
    local return_url = opts.return_url or ngx.var.request_uri

    if noco_info then
        -- 有会话：sso_ck 缺失/过期/失效 → 跳 sso_renew 续期（带回跳）
        local target = _M.build_url(opts.sso_renew_url, return_url, opts)
        ngx.log(ngx.INFO, "noco_auth: sso_ck invalid (", tostring(err),
            "), redirect to renew: ", target)
        _M.redirect(target, opts)
        return nil, nil, err
    end

    -- 完全无会话：跳 signin 登录
    local target = opts.signin_url
    if opts.signin_append_url then
        target = _M.build_url(target, return_url, opts)
    end
    ngx.log(ngx.INFO, "noco_auth: no session cookie, redirect to signin: ", target)
    _M.redirect(target, opts)
    return nil, nil, err
end

-- 直接取当前用户 uid（失败返回 nil, err）
function _M.get_uid(secret, opts)
    local payload, err = _M.verify_request(secret, opts)
    if not payload then
        return nil, err
    end
    return payload.uid
end

-- 直接取当前用户名（失败返回 nil, err）
function _M.get_uname(secret, opts)
    local payload, err = _M.verify_request(secret, opts)
    if not payload then
        return nil, err
    end
    return payload.uname
end

-- ── 签发（可选，供自定义 sso_renew 服务使用）────────────────────────
-- 签发 HS256 JWT，payload 需含 { uid, uname, exp }
-- @return token 或 nil, err
function _M.sign(secret, payload, opts)
    opts = opts or {}
    local jwt_obj = {
        header = { typ = "JWT", alg = opts.alg or "HS256" },
        payload = payload,
    }
    local token, err = jwt:sign(secret, jwt_obj)
    if not token then
        return nil, tostring(err)
    end
    return token
end

return _M
