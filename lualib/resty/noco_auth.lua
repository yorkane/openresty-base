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
-- 用法：
--   local noco = require "resty.noco_auth"
--   local user, err = noco.verify_request("sso_key")
--   if not user then return ngx.exit(ngx.HTTP_UNAUTHORIZED) end
--   ngx.ctx.sso_user = user

local jwt = require "resty.jwt"

local _M = { _VERSION = "0.1.0" }

local tonumber = tonumber
local tostring = tostring
local type = type
local setmetatable = setmetatable

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
    local pattern = "(^|;%s*)" .. name .. "=([^;]*)"
    local _, _, value = tostring(cookie_header):find(pattern)
    if value then
        return value
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
end

-- ── 便捷封装 ───────────────────────────────────────────────────────
-- 验证 sso_ck 并同时返回 noco_uid 解析结果
-- @return payload, noco_info, err
function _M.authenticate(secret, opts)
    opts = opts or {}
    local payload, err = _M.verify_request(secret, opts)
    if not payload then
        return nil, nil, err
    end
    local noco_info = _M.parse_noco_uid(
        _M.get_cookie(ngx.var.http_cookie, "noco_uid"))
    return payload, noco_info
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
