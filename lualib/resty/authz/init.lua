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
--   AUTHZ_NOCO_ENABLED     是否允许 NocoBase 远程认证, 默认关闭
--   AUTHZ_NOCO_URL         NocoBase 站点根地址

local db = require "resty.authz.db"
local identity = require "resty.authz.identity"
local session = require "resty.authz.session"
local casbin_mod = require "resty.authz.casbin"

local _M = {}
_M.config = {}

local function env_bool(name, default)
    local value = os.getenv(name)
    if value == nil or value == "" then return default end
    value = value:lower()
    return value == "1" or value == "true" or value == "yes" or value == "on"
end

local function parse_roles(value, default)
    local allowed = { admin = true, staff = true, user = true, viewer = true }
    local roles, selected = {}, {}
    for role in tostring(value or default or "viewer"):gmatch("[^,%s]+") do
        role = role:lower()
        if allowed[role] then selected[role] = true end
    end
    for _, role in ipairs({ "admin", "staff", "user", "viewer" }) do
        if selected[role] then roles[#roles + 1] = role end
    end
    if #roles == 0 then roles[1] = "viewer" end
    return roles
end

local function parse_role_map(value)
    local allowed = { admin = true, staff = true, user = true, viewer = true }
    local map = {}
    for entry in tostring(value or ""):gmatch("[^,;]+") do
        local source, target = entry:match("^%s*([%w_.-]+)%s*=%s*([%w_.-]+)%s*$")
        if source and allowed[target:lower()] then map[source:lower()] = target:lower() end
    end
    return map
end

local function validate_oauth_provider(provider, allow_http)
    if provider.client_id == "" or provider.redirect_uri == "" then
        error("OAuth provider " .. provider.id .. " requires client id and redirect URI")
    end
    if provider.token_auth_method == "client_secret_basic" and provider.client_secret == "" then
        error("OAuth provider " .. provider.id .. " requires client secret")
    end
    local fields = { "authorize_url", "token_url", "userinfo_url", "redirect_uri" }
    if provider.issuer then fields[#fields + 1] = "issuer" end
    for _, field in ipairs(fields) do
        local value = provider[field]
        local scheme = value:match("^(https?)://")
        if not scheme or value:find("[#]", 1) or (scheme ~= "https" and not allow_http) then
            error("OAuth provider " .. provider.id .. " has invalid " .. field)
        end
    end
end

-- ────────────────────────────────────────────────────────────────
-- 初始化 (init_by_lua, master 进程)
-- ────────────────────────────────────────────────────────────────

function _M.init()
    local c = _M.config
    c.db_path = os.getenv("AUTHZ_DB_PATH") or "/data/authz/authz.db"
    c.admin_password = os.getenv("AUTHZ_ADMIN_PASSWORD") or "admin123"
    c.port_min = math.max(2000, tonumber(os.getenv("AUTHZ_PORT_MIN")) or 2000)
    c.port_max = math.min(65535, tonumber(os.getenv("AUTHZ_PORT_MAX")) or 20000)
    if c.port_max < c.port_min then c.port_max = c.port_min end
    c.http_port = tonumber(os.getenv("AUTHZ_HTTP_PORT")) or 6080
    c.https_port = tonumber(os.getenv("AUTHZ_HTTPS_PORT")) or 6443
    c.discovery_ttl = math.max(5, tonumber(os.getenv("AUTHZ_DISCOVERY_TTL")) or 30)
    c.discovery_connect_timeout = math.max(20, tonumber(os.getenv("AUTHZ_DISCOVERY_CONNECT_TIMEOUT_MS")) or 100)
    c.discovery_read_timeout = math.max(20, tonumber(os.getenv("AUTHZ_DISCOVERY_READ_TIMEOUT_MS")) or 200)
    c.db_cache_ttl = math.max(1, tonumber(os.getenv("AUTHZ_DB_CACHE_TTL")) or 30)
    c.db_cache_lru_size = math.max(50, tonumber(os.getenv("AUTHZ_DB_CACHE_LRU_SIZE")) or 500)
    c.cache_dict = "authz_cache"
    c.login_limit_dict = "authz_login_limit"
    c.login_attempts = math.max(1, tonumber(os.getenv("AUTHZ_LOGIN_ATTEMPTS")) or 10)
    c.login_window = math.max(1, tonumber(os.getenv("AUTHZ_LOGIN_WINDOW")) or 60)
    session.secure = env_bool("AUTHZ_COOKIE_SECURE", false)
    session.cookie_domain = tostring(os.getenv("AUTHZ_COOKIE_DOMAIN") or "")
    c.noco_enabled = env_bool("AUTHZ_NOCO_ENABLED", false)
    c.noco_oauth_enabled = env_bool("AUTHZ_NOCO_OAUTH_ENABLED", false)
    c.noco_base_url = tostring(os.getenv("AUTHZ_NOCO_URL") or ""):gsub("/+$", "")
    c.noco_role_map = os.getenv("AUTHZ_NOCO_ROLE_MAP") or ""
    c.noco_connect_timeout = tonumber(os.getenv("AUTHZ_NOCO_CONNECT_TIMEOUT_MS")) or 3000
    c.noco_send_timeout = tonumber(os.getenv("AUTHZ_NOCO_SEND_TIMEOUT_MS")) or 5000
    c.noco_read_timeout = tonumber(os.getenv("AUTHZ_NOCO_READ_TIMEOUT_MS")) or 5000
    c.noco_max_body_size = tonumber(os.getenv("AUTHZ_NOCO_MAX_BODY_SIZE")) or 1048576
    if c.noco_enabled or c.noco_oauth_enabled then
        local scheme = c.noco_base_url:match("^(https?)://")
        if not scheme or c.noco_base_url:find("[?#]") then
            error("NocoBase authentication requires a valid AUTHZ_NOCO_URL")
        end
        if scheme ~= "https" and not env_bool("AUTHZ_NOCO_ALLOW_HTTP", false) then
            error("AUTHZ_NOCO_URL must use https unless AUTHZ_NOCO_ALLOW_HTTP is enabled")
        end
    end

    c.oauth_state_dict = "authz_oauth_state"
    c.oauth_state_ttl = math.max(60, tonumber(os.getenv("AUTHZ_OAUTH_STATE_TTL")) or 600)
    c.oauth_connect_timeout = tonumber(os.getenv("AUTHZ_OAUTH_CONNECT_TIMEOUT_MS")) or 10000
    c.oauth_send_timeout = tonumber(os.getenv("AUTHZ_OAUTH_SEND_TIMEOUT_MS")) or 10000
    c.oauth_read_timeout = tonumber(os.getenv("AUTHZ_OAUTH_READ_TIMEOUT_MS")) or 15000
    c.oauth_max_body_size = tonumber(os.getenv("AUTHZ_OAUTH_MAX_BODY_SIZE")) or 1048576
    c.oauth_providers = {}
    local oauth_allow_http = env_bool("AUTHZ_OAUTH_ALLOW_HTTP", false)
    if c.noco_oauth_enabled then
        local nocobase_oauth = {
            id = "nocobase",
            kind = "nocobase",
            title = os.getenv("AUTHZ_NOCO_OAUTH_TITLE") or "NocoBase",
            client_id = os.getenv("AUTHZ_NOCO_OAUTH_CLIENT_ID") or "",
            client_secret = os.getenv("AUTHZ_NOCO_OAUTH_CLIENT_SECRET") or "",
            authorize_url = c.noco_base_url .. "/api/idpOAuth/authorize",
            token_url = c.noco_base_url .. "/api/idpOAuth/token",
            userinfo_url = c.noco_base_url .. "/api/idpOAuth/me",
            issuer = c.noco_base_url .. "/api",
            redirect_uri = os.getenv("AUTHZ_NOCO_OAUTH_REDIRECT_URI") or "",
            scope = "openid profile email api",
            subject_claim = "sub",
            username_claim = "preferred_username",
            role_claim = "roles",
            role_map = parse_role_map(c.noco_role_map),
            default_roles = parse_roles(os.getenv("AUTHZ_NOCO_OAUTH_DEFAULT_ROLES"), "viewer"),
            require_verified_email = false,
            use_pkce = true,
            token_auth_method = "client_secret_basic",
        }
        validate_oauth_provider(nocobase_oauth, oauth_allow_http)
        c.oauth_providers[#c.oauth_providers + 1] = nocobase_oauth
    end
    if env_bool("AUTHZ_GOOGLE_ENABLED", false) then
        local google = {
            id = "google",
            kind = "standard",
            title = os.getenv("AUTHZ_GOOGLE_TITLE") or "Google",
            client_id = os.getenv("AUTHZ_GOOGLE_CLIENT_ID") or "",
            client_secret = os.getenv("AUTHZ_GOOGLE_CLIENT_SECRET") or "",
            authorize_url = "https://accounts.google.com/o/oauth2/v2/auth",
            token_url = "https://oauth2.googleapis.com/token",
            userinfo_url = "https://openidconnect.googleapis.com/v1/userinfo",
            redirect_uri = os.getenv("AUTHZ_GOOGLE_REDIRECT_URI") or "",
            scope = "openid email profile",
            subject_claim = "sub",
            username_claim = "email",
            role_claim = "roles",
            role_map = {},
            default_roles = parse_roles(os.getenv("AUTHZ_GOOGLE_DEFAULT_ROLES"), "viewer"),
            access_type = "online",
            prompt = "select_account",
            require_verified_email = true,
            use_pkce = true,
        }
        validate_oauth_provider(google, false)
        c.oauth_providers[#c.oauth_providers + 1] = google
    end
    if env_bool("AUTHZ_DINGTALK_ENABLED", false) then
        local dingtalk = {
            id = "dingtalk",
            kind = "dingtalk",
            title = os.getenv("AUTHZ_DINGTALK_TITLE") or "钉钉",
            client_id = os.getenv("AUTHZ_DINGTALK_CLIENT_ID") or "",
            client_secret = os.getenv("AUTHZ_DINGTALK_CLIENT_SECRET") or "",
            authorize_url = os.getenv("AUTHZ_DINGTALK_AUTHORIZE_URL") or
                "https://login.dingtalk.com/oauth2/auth",
            token_url = os.getenv("AUTHZ_DINGTALK_TOKEN_URL") or
                "https://api.dingtalk.com/v1.0/oauth2/userAccessToken",
            userinfo_url = os.getenv("AUTHZ_DINGTALK_USERINFO_URL") or
                "https://api.dingtalk.com/v1.0/contact/users/me",
            redirect_uri = os.getenv("AUTHZ_DINGTALK_REDIRECT_URI") or "",
            scope = os.getenv("AUTHZ_DINGTALK_SCOPE") or "openid",
            subject_claim = "unionId",
            username_claim = "email",
            role_claim = "roles",
            role_map = {},
            default_roles = parse_roles(os.getenv("AUTHZ_DINGTALK_DEFAULT_ROLES"), "viewer"),
            prompt = "consent",
            require_verified_email = false,
            use_pkce = false,
        }
        validate_oauth_provider(dingtalk, oauth_allow_http)
        c.oauth_providers[#c.oauth_providers + 1] = dingtalk
    end
    if env_bool("AUTHZ_WECHAT_ENABLED", false) then
        local wechat = {
            id = "wechat",
            kind = "wechat",
            title = os.getenv("AUTHZ_WECHAT_TITLE") or "微信",
            client_id = os.getenv("AUTHZ_WECHAT_APP_ID") or "",
            client_secret = os.getenv("AUTHZ_WECHAT_APP_SECRET") or "",
            authorize_url = os.getenv("AUTHZ_WECHAT_AUTHORIZE_URL") or
                "https://open.weixin.qq.com/connect/qrconnect",
            token_url = os.getenv("AUTHZ_WECHAT_TOKEN_URL") or
                "https://api.weixin.qq.com/sns/oauth2/access_token",
            userinfo_url = os.getenv("AUTHZ_WECHAT_USERINFO_URL") or
                "https://api.weixin.qq.com/sns/userinfo",
            redirect_uri = os.getenv("AUTHZ_WECHAT_REDIRECT_URI") or "",
            scope = "snsapi_login",
            subject_claim = "unionid",
            username_claim = "email",
            role_claim = "roles",
            role_map = {},
            default_roles = parse_roles(os.getenv("AUTHZ_WECHAT_DEFAULT_ROLES"), "viewer"),
            require_verified_email = false,
            use_pkce = false,
        }
        validate_oauth_provider(wechat, oauth_allow_http)
        c.oauth_providers[#c.oauth_providers + 1] = wechat
    end
    if env_bool("AUTHZ_OAUTH_ENABLED", false) then
        local provider_id = tostring(os.getenv("AUTHZ_OAUTH_PROVIDER") or "oauth"):lower()
        if not provider_id:match("^[a-z0-9_.-]+$") or provider_id == "local" or
            provider_id == "nocobase" or provider_id == "google" or
            provider_id == "dingtalk" or provider_id == "wechat" then
            error("AUTHZ_OAUTH_PROVIDER is invalid or reserved")
        end
        local provider = {
            id = provider_id,
            kind = "standard",
            title = os.getenv("AUTHZ_OAUTH_TITLE") or "OAuth",
            client_id = os.getenv("AUTHZ_OAUTH_CLIENT_ID") or "",
            client_secret = os.getenv("AUTHZ_OAUTH_CLIENT_SECRET") or "",
            authorize_url = os.getenv("AUTHZ_OAUTH_AUTHORIZE_URL") or "",
            token_url = os.getenv("AUTHZ_OAUTH_TOKEN_URL") or "",
            userinfo_url = os.getenv("AUTHZ_OAUTH_USERINFO_URL") or "",
            redirect_uri = os.getenv("AUTHZ_OAUTH_REDIRECT_URI") or "",
            scope = os.getenv("AUTHZ_OAUTH_SCOPE") or "openid email profile",
            subject_claim = os.getenv("AUTHZ_OAUTH_SUBJECT_CLAIM") or "sub",
            username_claim = os.getenv("AUTHZ_OAUTH_USERNAME_CLAIM") or "email",
            role_claim = os.getenv("AUTHZ_OAUTH_ROLE_CLAIM") or "roles",
            role_map = parse_role_map(os.getenv("AUTHZ_OAUTH_ROLE_MAP")),
            default_roles = parse_roles(os.getenv("AUTHZ_OAUTH_DEFAULT_ROLES"), "viewer"),
            require_verified_email = env_bool("AUTHZ_OAUTH_REQUIRE_VERIFIED_EMAIL", false),
            use_pkce = true,
        }
        validate_oauth_provider(provider, oauth_allow_http)
        c.oauth_providers[#c.oauth_providers + 1] = provider
    end

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
            local actions, eft = r.v2:match("^([^|]+)|(.+)$")
            actions = actions or r.v2
            for act in actions:gmatch("[^,]+") do
                local line = "p, " .. r.v0 .. ", " .. r.v1 .. ", " .. act
                if eft then line = line .. ", " .. eft end
                lines[#lines + 1] = line
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
        local principal = assert(identity.key("local", u.username))
        for role in u.roles:gmatch("[^,%s]+") do
            lines[#lines + 1] = "g, " .. principal .. ", role:" .. role
        end
    end
    local remote_users = db.query([[SELECT provider, username, roles FROM remote_users
        WHERE enabled = 1]]) or {}
    for _, u in ipairs(remote_users) do
        local principal = assert(identity.key(u.provider, u.username))
        for role in u.roles:gmatch("[^,%s]+") do
            lines[#lines + 1] = "g, " .. principal .. ", role:" .. role
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

    if tonumber(ngx.var.server_port) == port then
        ngx.status = 508
        ngx.header.content_type = "text/html; charset=utf-8"
        ngx.say([[<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>508 Loop Detected</title></head><body style="font-family:sans-serif;text-align:center;padding-top:80px">
<h1>508</h1><p>目标端口 ]] .. port .. [[ 是网关自身监听端口，已阻止循环代理。</p>
<p>管理界面请访问 <code>/_radmin_/</code>。</p></body></html>]])
        return ngx.exit(508)
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
    local principal = identity.key(s.source, s.username)
    if not principal or not cache.enforcer:enforce(principal, obj, ngx.req.get_method()) then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html; charset=utf-8"
        ngx.say("<html><body style='font-family:sans-serif;text-align:center;padding-top:80px'>" ..
            "<h1>403</h1><p>身份 <b>" .. (principal or "invalid") ..
            "</b> 无权访问 <code>" .. obj .. "</code></p>" ..
            "<p><a href='/_authz/'>控制台</a></p></body></html>")
        return ngx.exit(ngx.HTTP_OK)
    end

    -- 传递给 proxy_pass 与后端
    ngx.var.authz_user = s.username
    ngx.var.authz_source = s.source
    ngx.var.authz_identity = principal
    ngx.var.authz_target = ngx.var.scheme .. "://127.0.0.1:" .. port
end

return _M
