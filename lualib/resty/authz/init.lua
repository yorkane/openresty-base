-- resty.authz
-- 网关入口: 动态端口代理 (数字前缀子域名 / SQLite 域名绑定) + 登录认证 + Casbin 授权
--
-- 用法:
--   init_by_lua_block { require("resty.authz").init() }
--   location / {
--     set $authz_target "";
--     access_by_lua_block { require("resty.authz").access() }
--     proxy_pass $authz_target;
--   }
--
-- 环境变量:
--   AUTHZ_DB_PATH          默认 /data/authz/authz.db
--   AUTHZ_ADMIN_PASSWORD   首次 seed 的 admin 密码, 默认 admin123
--   AUTHZ_PORT_MIN/MAX     数字前缀允许的端口范围, 默认 2000-20000
--   AUTHZ_SESSION_TTL      会话有效期秒, 默认 604800

local db = require "resty.authz.db"
local session = require "resty.authz.session"
local casbin_mod = require "resty.authz.casbin"

local _M = {}
_M.config = {}

-- ────────────────────────────────────────────────────────────────
-- 初始化 (init_by_lua, master 进程)
-- ────────────────────────────────────────────────────────────────

function _M.init()
    local c = _M.config
    c.db_path = os.getenv("AUTHZ_DB_PATH") or "/data/authz/authz.db"
    c.admin_password = os.getenv("AUTHZ_ADMIN_PASSWORD") or "admin123"
    c.port_min = tonumber(os.getenv("AUTHZ_PORT_MIN")) or 2000
    c.port_max = tonumber(os.getenv("AUTHZ_PORT_MAX")) or 20000
    c.cache_dict = "authz_cache"

    local ttl = tonumber(os.getenv("AUTHZ_SESSION_TTL"))
    if ttl then session.ttl = ttl end

    -- master 中建 schema/seed 后关闭连接; worker 各自懒加载重开
    db.init(c)
    db.close()

    ngx.log(ngx.NOTICE, "authz: initialized (db=" .. c.db_path ..
        ", port range " .. c.port_min .. "-" .. c.port_max .. ")")
end

-- ────────────────────────────────────────────────────────────────
-- 缓存: shared dict rev 计数器, worker 本地按 rev 失效
-- ────────────────────────────────────────────────────────────────

local cache = {
    rev = -1,
    enforcer = nil,        -- casbin enforcer
    bindings = nil,        -- { [domain_lower] = {port=..., enabled=...} }
}

local function current_rev()
    local dict = ngx.shared[_M.config.cache_dict]
    if not dict then return 0 end
    return dict:get("rev") or 0
end

local function load_policies()
    local rows = db.query("SELECT ptype, v0, v1, v2 FROM policies") or {}
    local lines = {}
    for _, r in ipairs(rows) do
        if r.ptype == "p" then
            -- v2 可能带 "|deny" 后缀 (管理页 deny 编码)
            local act, eft = r.v2:match("^([^|]+)|(.+)$")
            if act then
                lines[#lines + 1] = "p, " .. r.v0 .. ", " .. r.v1 .. ", " .. act .. ", " .. eft
            else
                lines[#lines + 1] = "p, " .. r.v0 .. ", " .. r.v1 .. ", " .. r.v2
            end
        elseif r.ptype == "g" then
            lines[#lines + 1] = "g, " .. r.v0 .. ", " .. r.v1
        end
    end
    return lines
end

local function load_bindings()
    local rows = db.query("SELECT domain, port, enabled FROM bindings") or {}
    local map = {}
    for _, b in ipairs(rows) do
        map[b.domain] = { port = b.port, enabled = b.enabled }
    end
    return map
end

local function ensure_cache()
    local rev = current_rev()
    if cache.rev == rev and cache.enforcer then return end
    local users = db.query("SELECT username, roles FROM users WHERE enabled = 1") or {}
    local lines = load_policies()
    for _, u in ipairs(users) do
        for role in u.roles:gmatch("[^,%s]+") do
            lines[#lines + 1] = "g, " .. u.username .. ", role:" .. role
        end
    end
    cache.enforcer = casbin_mod.new_enforcer(lines)
    cache.bindings = load_bindings()
    cache.rev = rev
end

-- ────────────────────────────────────────────────────────────────
-- 目标解析: 显式绑定 > 数字前缀 > 404
-- 返回 port 或 nil, err_html
-- ────────────────────────────────────────────────────────────────

local function resolve_port(host)
    ensure_cache()
    -- 1. 显式绑定 (精确匹配, 已 lowercase)
    local b = host and cache.bindings[host]
    if b and b.enabled == 1 then return b.port end

    -- 2. 数字前缀: <port>-<任意多级域名>
    if host then
        local m = ngx.re.match(host, [[^(\d{1,5})-]])
        if m then
            local port = tonumber(m[1])
            if port and port >= _M.config.port_min and port <= _M.config.port_max then
                return port
            end
        end
    end
    return nil
end

local function serve_404(host)
    ngx.status = ngx.HTTP_NOT_FOUND
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say([[<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>404</title><style>body{font-family:sans-serif;background:#f4f6f8;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center}.box h1{font-size:64px;margin:0;color:#94a3b8}</style></head>
<body><div class="box"><h1>404</h1><p>未找到 <b>]] ..
        (host or "") .. [[</b> 对应的服务</p>
<p style="color:#888">用法: <code>&lt;端口&gt;-任意域名</code> 访问本机对应端口<br>
或 <a href="/_authz/">登录控制台</a> 配置域名绑定</p></div></body></html>]])
    return ngx.exit(ngx.HTTP_OK)
end

-- ────────────────────────────────────────────────────────────────
-- access 阶段入口
-- ────────────────────────────────────────────────────────────────

function _M.access()
    db.open(_M.config.db_path)

    local host = ngx.var.host -- 已 lowercase, 不含端口
    local port = resolve_port(host)
    if not port then
        return serve_404(host)
    end

    -- 会话认证
    local token = session.get_request_token()
    local s = token and session.get(token) or nil
    if not s then
        local next_url = ngx.var.request_uri or "/"
        ngx.status = ngx.HTTP_MOVED_TEMPORARILY
        ngx.header["Location"] = "/_authz/login?next=" .. ngx.escape_uri(next_url)
        return ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
    end

    -- Casbin 授权: obj = "/<port><uri>", act = HTTP method
    ensure_cache()
    local obj = "/" .. port .. (ngx.var.uri or "")
    if not cache.enforcer:enforce(s.username, obj, ngx.req.get_method()) then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html; charset=utf-8"
        ngx.say("<html><body style='font-family:sans-serif;text-align:center;padding-top:80px'>" ..
            "<h1>403</h1><p>用户 <b>" .. s.username ..
            "</b> 无权访问 <code>" .. obj .. "</code></p>" ..
            "<p><a href='/_authz/'>控制台</a></p></body></html>")
        return ngx.exit(ngx.HTTP_OK)
    end

    -- 传递给 proxy_pass 与后端
    ngx.var.authz_user = s.username
    ngx.var.authz_target = ngx.var.scheme .. "://127.0.0.1:" .. port
end

return _M
