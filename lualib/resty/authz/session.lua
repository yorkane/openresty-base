-- resty.authz.session
-- 服务端会话: SQLite 存储, Cookie 只携带随机 token

local db = require "resty.authz.db"
local identity = require "resty.authz.identity"
local util = require "resty.authz.util"

local _M = {}
_M.cookie_name = "authz_session"
_M.ttl = 7 * 86400 -- 7 天
_M.secure = false

local function secure_flag()
    local forwarded = tostring(ngx.var.http_x_forwarded_proto or ""):lower()
    local first_forwarded = forwarded:match("^%s*([^,;]+)")
    local forwarded_https = first_forwarded and first_forwarded:match("^https%s*$") ~= nil
    return (_M.secure or ngx.var.https == "on" or forwarded_https) and "; Secure" or ""
end

-- 创建本机会话，username + source 共同标识身份
function _M.create(username, source)
    source = identity.source(source)
    local principal = source and identity.key(source, username)
    if not principal then
        return nil, "invalid session identity"
    end
    source, username = identity.parse(principal)
    local token = util.random_token(32)
    local csrf = util.random_token(16)
    local ok, err = db.exec(
        "INSERT INTO sessions(token, username, source, csrf, expires_at) VALUES(?,?,?,?,?)",
        token, username, source, csrf, os.time() + _M.ttl)
    if not ok then return nil, err end
    return token
end

-- 按 cookie token 取会话, 过期返回 nil (顺带清理)
function _M.get(token)
    if not token or #token < 16 or #token > 128 then return nil end
    local rows = db.query(
        "SELECT username, source, csrf, expires_at FROM sessions WHERE token = ?", token)
    local s = rows and rows[1]
    if not s then return nil end
    if s.expires_at < os.time() then
        db.exec("DELETE FROM sessions WHERE token = ?", token)
        return nil
    end
    if s.source == "local" then
        local users = db.query(
            "SELECT id FROM users WHERE username = ? AND enabled = 1", s.username)
        if not users or not users[1] then return nil end
    else
        local remote_users = db.query([[SELECT subject FROM remote_users
            WHERE provider = ? AND username = ? AND enabled = 1]], s.source, s.username)
        if not remote_users or not remote_users[1] then return nil end
    end
    return s
end

function _M.delete(token)
    return db.exec("DELETE FROM sessions WHERE token = ?", token)
end

function _M.delete_all_for(username, source)
    return db.exec("DELETE FROM sessions WHERE username = ? AND source = ?",
        username, identity.source(source) or "local")
end

-- 从请求头解析 cookie token
function _M.get_request_token()
    local cookie = ngx.var.http_cookie
    if not cookie then return nil end
    local m = ngx.re.match(cookie, "(?:^|;\\s*)" .. _M.cookie_name .. "=([A-Za-z0-9]+)")
    return m and m[1] or nil
end

-- 设置/清除 Set-Cookie 头
function _M.set_cookie(token)
    ngx.header["Set-Cookie"] = _M.cookie_name .. "=" .. token ..
        "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" .. tostring(_M.ttl) .. secure_flag()
end

function _M.clear_cookie()
    ngx.header["Set-Cookie"] = _M.cookie_name .. "=" ..
        "; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" .. secure_flag()
end

return _M
