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
local api_key = require "resty.authz.api_key"
local session = require "resty.authz.session"
local casbin_mod = require "resty.authz.casbin"
local target = require "resty.authz.target"

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
    c.discovery_ports = tostring(os.getenv("AUTHZ_DISCOVERY_PORTS") or "")
    c.db_cache_ttl = math.max(1, tonumber(os.getenv("AUTHZ_DB_CACHE_TTL")) or 30)
    c.db_cache_lru_size = math.max(50, tonumber(os.getenv("AUTHZ_DB_CACHE_LRU_SIZE")) or 500)
    c.cache_dict = "authz_cache"
    c.login_limit_dict = "authz_login_limit"
    c.login_attempts = math.max(1, tonumber(os.getenv("AUTHZ_LOGIN_ATTEMPTS")) or 10)
    c.login_window = math.max(1, tonumber(os.getenv("AUTHZ_LOGIN_WINDOW")) or 60)
    session.secure = env_bool("AUTHZ_COOKIE_SECURE", false)
    session.configure_cookie_domain(os.getenv("AUTHZ_COOKIE_DOMAIN"), os.getenv("AUTHZ_HOST_URL"))

    -- 共享会话 (Redis): 各实例把登录会话同步到公共 Redis, 切换域名不丢登录。
    -- Casbin 策略/绑定/角色仍在各实例本地管理, 不做同步。
    c.session_shared = env_bool("AUTHZ_SESSION_SHARED", false)
    local redis_url = tostring(os.getenv("AUTHZ_SESSION_REDIS_URL") or ""):gsub("%s+", "")
    if c.session_shared then
        local redis_host, redis_port_text = redis_url:match("^redis://([^:/]+):?(%d*)$")
        if not redis_host then
            error("AUTHZ_SESSION_SHARED requires AUTHZ_SESSION_REDIS_URL=redis://<host>[:<port>]")
        end
        session.redis.host = redis_host
        local redis_port = redis_port_text ~= "" and tonumber(redis_port_text) or 6379
        if not redis_port or redis_port < 1 or redis_port > 65535 then
            error("AUTHZ_SESSION_REDIS_URL port must be 1-65535")
        end
        session.redis.port = redis_port
        session.redis.password = tostring(os.getenv("AUTHZ_SESSION_REDIS_PASSWORD") or "")
        session.redis.db = tonumber(os.getenv("AUTHZ_SESSION_REDIS_DB")) or 0
        session.redis.prefix = tostring(os.getenv("AUTHZ_SESSION_REDIS_PREFIX") or "authz")
        session.redis.connect_timeout = tonumber(os.getenv("AUTHZ_SESSION_REDIS_CONNECT_TIMEOUT_MS")) or 2000
        session.redis.read_timeout = tonumber(os.getenv("AUTHZ_SESSION_REDIS_READ_TIMEOUT_MS")) or 2000
        session.shared_enabled = true
        ngx.log(ngx.NOTICE, "authz: shared session mode enabled (redis://" ..
            session.redis.host .. ":" .. session.redis.port .. ")")
    end
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
    -- 多实例 OAuth 中继: 认证实例(中枢)与身份提供方通信并签发断言, 业务实例验证断言后同步身份。
    c.oauth_relay_secret = tostring(os.getenv("AUTHZ_OAUTH_RELAY_SECRET") or "")
    c.oauth_relay_ttl = math.max(60, tonumber(os.getenv("AUTHZ_OAUTH_RELAY_TTL")) or 300)
    c.oauth_hub_url = tostring(os.getenv("AUTHZ_OAUTH_HUB_URL") or ""):gsub("/+$", "")
    c.oauth_relay_name = tostring(os.getenv("AUTHZ_OAUTH_RELAY_NAME") or ""):lower()
    c.oauth_hub_providers = {}
    for entry in tostring(os.getenv("AUTHZ_OAUTH_HUB_PROVIDERS") or ""):gmatch("[^,]+") do
        entry = entry:gsub("^%s+", ""):gsub("%s+$", "")
        if entry ~= "" then
            local id, title = entry:match("^([a-zA-Z0-9_.-]+):(.+)$")
            if not id then
                id, title = entry, ""
            end
            id = id:lower()
            title = title:gsub("^%s+", ""):gsub("%s+$", "")
            if not id:match("^[a-z0-9_.-]+$") or #id > 64 or #title > 128 then
                error("invalid AUTHZ_OAUTH_HUB_PROVIDERS entry: " .. entry)
            end
            c.oauth_hub_providers[#c.oauth_hub_providers + 1] = { id = id, title = title }
        end
    end
    local relay_clients, relay_clients_err = require("resty.authz.relay")
        .parse_clients(os.getenv("AUTHZ_OAUTH_RELAY_CLIENTS"))
    if not relay_clients then error(relay_clients_err) end
    c.oauth_relay_clients = relay_clients
    if c.oauth_hub_url ~= "" then
        local scheme = c.oauth_hub_url:match("^(https?)://")
        if not scheme or c.oauth_hub_url:find("[?#%s]") then
            error("AUTHZ_OAUTH_HUB_URL must be a valid absolute URL")
        end
        if scheme ~= "https" and not env_bool("AUTHZ_OAUTH_RELAY_ALLOW_HTTP", false) then
            error("AUTHZ_OAUTH_HUB_URL must use https unless AUTHZ_OAUTH_RELAY_ALLOW_HTTP is enabled")
        end
        if c.oauth_relay_secret == "" or c.oauth_relay_name == "" or
            not c.oauth_relay_name:match("^[a-z0-9_.-]+$") then
            error("OAuth relay clients require AUTHZ_OAUTH_RELAY_SECRET and a valid AUTHZ_OAUTH_RELAY_NAME")
        end
    end
    if next(c.oauth_relay_clients) and c.oauth_relay_secret == "" then
        error("AUTHZ_OAUTH_RELAY_CLIENTS requires AUTHZ_OAUTH_RELAY_SECRET")
    end
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
    bindings = nil,        -- { [domain_lower] = {target_ip=..., port=..., enabled=...} }
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
    local rows = db.query([[SELECT domain, target_ip, port, enabled, websocket,
        upstream_host, forwarded_host, forwarded_proto, forwarded_port, origin_mode,
        custom_origin, simulate_local, local_ip, upstream_scheme, upstream_ssl_verify,
        upstream_path FROM bindings]]) or {}
    local map = {}
    for _, b in ipairs(rows) do
        map[b.domain] = {
            target_ip = target.normalize_ip(b.target_ip) or "127.0.0.1",
            port = b.port,
            enabled = b.enabled,
            websocket = b.websocket == 1,
            upstream_host = target.normalize_authority(b.upstream_host, true) or "",
            forwarded_host = target.normalize_authority(b.forwarded_host, true) or "",
            forwarded_proto = (b.forwarded_proto == "http" or b.forwarded_proto == "https")
                and b.forwarded_proto or "",
            forwarded_port = tonumber(b.forwarded_port) or 0,
            origin_mode = ({ auto = true, preserve = true, rewrite = true,
                remove = true, custom = true })[b.origin_mode] and b.origin_mode or "auto",
            custom_origin = target.normalize_origin(b.custom_origin, true) or "",
            simulate_local = tonumber(b.simulate_local) == 1,
            local_ip = target.normalize_ip(b.local_ip) or "127.0.0.1",
            upstream_scheme = b.upstream_scheme == "https" and "https" or "http",
            upstream_ssl_verify = tonumber(b.upstream_ssl_verify) ~= 0,
            upstream_path = target.normalize_upstream_path(b.upstream_path) or "",
        }
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
    local api_keys = db.query("SELECT id, role FROM api_keys WHERE enabled = 1") or {}
    for _, key in ipairs(api_keys) do
        local principal = api_key.principal(key.id)
        local role = api_key.valid_role(key.role)
        if principal and role then
            lines[#lines + 1] = "g, " .. principal .. ", role:" .. role
        end
    end
    cache.enforcer = casbin_mod.new_enforcer(lines)
    cache.bindings = load_bindings()
    cache.rev = rev
end

-- ────────────────────────────────────────────────────────────────
-- 目标解析: 显式绑定 > 数字前缀 > 404
-- 返回 port、WebSocket 兼容值、target_ip、显式绑定，或 nil
-- ────────────────────────────────────────────────────────────────

local function resolve_target(host)
    ensure_cache()
    -- 1. 显式绑定 (精确匹配, 已 lowercase)
    local b = host and cache.bindings[host]
    if b and b.enabled == 1 then return b.port, b.websocket, b.target_ip, b end

    -- 2. 数字前缀: <port>-<任意多级域名>
    if host then
        local m = ngx.re.match(host, [[^(\d{1,5})-]])
        if m then
            local port = tonumber(m[1])
            if port and port >= _M.config.port_min and port <= _M.config.port_max then
                return port, false, "127.0.0.1", nil
            end
        end
    end
    return nil
end

local function authority_port(authority)
    authority = tostring(authority or "")
    return tonumber(authority:match("^%[[^%]]+%]:(%d+)$") or authority:match("^[^:]+:(%d+)$"))
end

local function request_forwarded_for()
    local existing = tostring(ngx.var.http_x_forwarded_for or "")
    local remote = tostring(ngx.var.remote_addr or "")
    if existing == "" then return remote end
    if remote == "" then return existing end
    return existing .. ", " .. remote
end

local function apply_proxy_headers(binding, target_ip, port)
    binding = binding or {}
    local target_authority = target.url_host(target_ip) .. ":" .. tostring(port)
    local request_host = target.normalize_authority(ngx.var.authz_forwarded_host, true)
    if not request_host or request_host == "" then
        request_host = target.normalize_authority(ngx.var.http_host, true)
    end
    if not request_host or request_host == "" then request_host = target_authority end

    local simulate_local = binding.simulate_local == true
    local upstream_host = binding.upstream_host or ""
    if upstream_host == "" then
        upstream_host = simulate_local and target_authority or request_host
    end
    local forwarded_host = binding.forwarded_host or ""
    if forwarded_host == "" then forwarded_host = upstream_host end

    local forwarded_proto = binding.forwarded_proto or ""
    if forwarded_proto == "" then
        forwarded_proto = simulate_local and "http" or tostring(ngx.var.scheme or "http")
    end
    local forwarded_port = tonumber(binding.forwarded_port) or 0
    if forwarded_port < 1 or forwarded_port > 65535 then
        forwarded_port = authority_port(forwarded_host) or
            (simulate_local and port or (forwarded_proto == "https" and 443 or 80))
    end

    local incoming_origin = tostring(ngx.var.http_origin or "")
    local origin_mode = binding.origin_mode or "auto"
    local origin
    if origin_mode == "remove" then
        origin = ""
    elseif origin_mode == "custom" then
        origin = binding.custom_origin or ""
    elseif origin_mode == "rewrite" or (origin_mode == "auto" and simulate_local) then
        origin = incoming_origin ~= "" and (forwarded_proto .. "://" .. forwarded_host) or ""
    else
        origin = incoming_origin
    end

    ngx.var.authz_upstream_host = upstream_host
    ngx.var.authz_proxy_forwarded_host = forwarded_host
    ngx.var.authz_forwarded_proto = forwarded_proto
    ngx.var.authz_forwarded_port = tostring(forwarded_port)
    ngx.var.authz_origin = origin
    if simulate_local then
        ngx.var.authz_real_ip = binding.local_ip or "127.0.0.1"
        ngx.var.authz_forwarded_for = binding.local_ip or "127.0.0.1"
        ngx.var.authz_forwarded = ""
    else
        ngx.var.authz_real_ip = tostring(ngx.var.remote_addr or "")
        ngx.var.authz_forwarded_for = request_forwarded_for()
        ngx.var.authz_forwarded = tostring(ngx.var.http_forwarded or "")
    end
end

local function upstream_path(binding)
    local request_path = tostring(ngx.var.uri or "/")
    local rewrite = binding and binding.upstream_path or ""
    if rewrite == "" then return request_path end
    return rewrite
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
    local port, websocket, target_ip, binding = resolve_target(host)
    if not port then
        return serve_404(host)
    end

    local server_ip = target.normalize_ip(ngx.var.server_addr)
    if tonumber(ngx.var.server_port) == port and
        (target.is_loopback(target_ip) or (server_ip and server_ip == target_ip)) then
        ngx.status = 508
        ngx.header.content_type = "text/html; charset=utf-8"
        ngx.say([[<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>508 Loop Detected</title></head><body style="font-family:sans-serif;text-align:center;padding-top:80px">
<h1>508</h1><p>目标 ]] .. target_ip .. ":" .. port .. [[ 是网关自身监听地址，已阻止循环代理。</p>
<p>管理界面请访问 <code>/_radmin_/</code>。</p></body></html>]])
        return ngx.exit(508)
    end

    -- x-authz-key 优先于浏览器会话；显式提交无效 Key 时禁止回退 Cookie。
    local key_presented, current = api_key.authenticate_request()
    local machine_request = key_presented
    if not key_presented then
        local token = session.get_request_token()
        current = token and session.get(token) or nil
    end
    if not current then
        if machine_request then
            ngx.status = ngx.HTTP_UNAUTHORIZED
            ngx.header.content_type = "application/json; charset=UTF-8"
            ngx.say('{"error":{"code":"invalid_api_key","message":"API key is invalid or disabled"}}')
            return ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
        local next_url = ngx.var.request_uri or "/"
        ngx.status = ngx.HTTP_MOVED_TEMPORARILY
        ngx.header["Location"] = "/_authz/login?next=" .. ngx.escape_uri(next_url)
        return ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
    end

    -- Casbin 授权: obj = "/<port><uri>", act = HTTP method
    ensure_cache()
    local obj = "/" .. port .. (ngx.var.uri or "")
    local principal = machine_request and current.identity or identity.key(current.source, current.username)
    if not principal or not cache.enforcer:enforce(principal, obj, ngx.req.get_method()) then
        ngx.status = ngx.HTTP_FORBIDDEN
        if machine_request then
            ngx.header.content_type = "application/json; charset=UTF-8"
            ngx.say('{"error":{"code":"forbidden","message":"API role is not allowed to access this target"}}')
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
        ngx.header.content_type = "text/html; charset=utf-8"
        ngx.say("<html><body style='font-family:sans-serif;text-align:center;padding-top:80px'>" ..
            "<h1>403</h1><p>身份 <b>" .. (principal or "invalid") ..
            "</b> 无权访问 <code>" .. obj .. "</code></p>" ..
            "<p><a href='/_authz/'>控制台</a></p></body></html>")
        return ngx.exit(ngx.HTTP_OK)
    end

    -- 传递给 proxy_pass 与后端
    ngx.var.authz_user = current.username
    ngx.var.authz_source = current.source
    ngx.var.authz_identity = principal
    -- The gateway may terminate TLS for the client while forwarding to either
    -- an HTTP or HTTPS upstream selected by the binding.
    local scheme = binding and binding.upstream_scheme or "http"
    local query = ngx.var.args
    local query_suffix = query and query ~= "" and "?" .. query or ""
    ngx.var.authz_target = scheme .. "://" .. target.url_host(target_ip) .. ":" .. port ..
        upstream_path(binding) .. query_suffix
    local ssl_host = binding and binding.upstream_host ~= "" and
        target.authority_host(binding.upstream_host)
    ssl_host = ssl_host or target.authority_host(target.url_host(target_ip)) or target.url_host(target_ip)
    ngx.var.authz_upstream_ssl_name = ssl_host
    apply_proxy_headers(binding, target_ip, port)
    local requested_upgrade = tostring(ngx.var.http_upgrade or "")
    -- WebSocket 代理默认对所有已解析目标开启；bindings.websocket 仅保留
    -- 为历史配置兼容，不再作为升级请求的阻断条件。
    local websocket_request = requested_upgrade:lower() == "websocket"
    ngx.var.authz_websocket = websocket_request and "1" or "0"
    ngx.var.authz_upgrade = websocket_request and requested_upgrade or ""
    ngx.var.authz_connection = websocket_request and "upgrade" or ""

    -- proxy_ssl_verify only accepts a literal on/off in nginx.  Keep the
    -- normal location fail-closed and use a private named location when a
    -- binding explicitly opts out of HTTPS certificate verification.
    if scheme == "https" and binding and binding.upstream_ssl_verify == false then
        return ngx.exec("@authz_proxy_insecure")
    end
end

return _M
