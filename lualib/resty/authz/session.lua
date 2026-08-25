-- resty.authz.session
-- 服务端会话: SQLite 存储, Cookie 只携带随机 token

local db = require "resty.authz.db"
local identity = require "resty.authz.identity"
local util = require "resty.authz.util"

local _M = {}
_M.cookie_name = "authz_session"
_M.ttl = 7 * 86400 -- 7 天
_M.secure = false
_M.cookie_domain = ""
_M.cookie_domains = {}

local function normalize_domain(value)
    local domain = tostring(value or ""):lower()
        :gsub("^%s+", ""):gsub("%s+$", ""):gsub("^%.*", ""):gsub("%.$", "")
    if domain == "" or #domain > 253 or not domain:find("%.") or
        not domain:match("^[a-z0-9][a-z0-9.-]*[a-z0-9]$") or
        domain:find("..", 1, true) then
        return ""
    end
    for label in domain:gmatch("[^.]+") do
        if #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" then return "" end
    end
    return "." .. domain
end

local function host_from_url(value)
    local authority = tostring(value or ""):match("^https?://([^/%?#]+)")
    if not authority then return "" end
    if authority:sub(1, 1) == "[" then return "" end
    return authority:gsub(":%d+$", ""):lower()
end

local function label_count(domain)
    local count = 0
    for _ in tostring(domain or ""):gsub("^%.", ""):gmatch("[^.]+") do count = count + 1 end
    return count
end

local function domain_matches_host(domain, host)
    domain = tostring(domain or ""):gsub("^%.", "")
    return domain ~= "" and (host == domain or host:sub(-#domain - 1) == "." .. domain)
end

local function domain_from_host(host)
    host = tostring(host or ""):lower():gsub("%.$", "")
    if host == "" or host:match("^%d+%.%d+%.%d+%.%d+$") or host:find(":", 1, true) then
        return ""
    end
    local normalized = normalize_domain(host)
    if normalized == "" then return "" end
    local labels = {}
    for label in host:gmatch("[^.]+") do labels[#labels + 1] = label end
    if #labels == 2 then return normalized end
    return normalize_domain(table.concat(labels, ".", 2))
end

function _M.default_cookie_domain(host_url)
    return domain_from_host(host_from_url(host_url))
end

function _M.configure_cookie_domain(value, host_url)
    local domains, seen = {}, {}
    for candidate in tostring(value or ""):gmatch("[^,;%s]+") do
        local domain = normalize_domain(candidate)
        if domain ~= "" and not seen[domain] then
            seen[domain] = true
            domains[#domains + 1] = domain
        end
    end
    if #domains == 0 then
        local fallback = _M.default_cookie_domain(host_url)
        if fallback ~= "" then domains[1] = fallback end
    end
    _M.cookie_domains = domains
    _M.cookie_domain = domains[1] or ""
    return _M.cookie_domain
end

local function current_cookie_domain()
    local host = tostring(ngx.var.host or ""):lower():gsub("%.$", "")
    local derived = domain_from_host(host)
    local selected, selected_labels = "", 0
    for _, configured in ipairs(_M.cookie_domains or {}) do
        local labels = label_count(configured)
        if domain_matches_host(configured, host) and labels > selected_labels then
            selected, selected_labels = configured, labels
        end
    end
    if selected ~= "" and selected_labels >= label_count(derived) then return selected end
    if derived ~= "" then return derived end
    return selected ~= "" and selected or normalize_domain(_M.cookie_domain)
end

local function secure_flag()
    local forwarded = tostring(ngx.var.http_x_forwarded_proto or ""):lower()
    local first_forwarded = forwarded:match("^%s*([^,;]+)")
    local forwarded_https = first_forwarded and first_forwarded:match("^https%s*$") ~= nil
    return (_M.secure or ngx.var.https == "on" or forwarded_https) and "; Secure" or ""
end

local function cookie_line(value, max_age, domain)
    local line = _M.cookie_name .. "=" .. tostring(value or "") ..
        "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" .. tostring(max_age)
    if domain and domain ~= "" then line = line .. "; Domain=" .. domain end
    return line .. secure_flag()
end

local function legacy_cookie_domains(desired_domain)
    local domains, seen = {}, {}
    local desired = normalize_domain(desired_domain):gsub("^%.", "")
    local host = tostring(ngx.var.host or ""):lower():gsub("%.$", "")
    local function add(domain)
        domain = normalize_domain(domain)
        if domain ~= "" and domain:gsub("^%.", "") ~= desired and not seen[domain] then
            seen[domain] = true
            domains[#domains + 1] = domain
        end
    end

    if host ~= "" and host:match("^[a-z0-9][a-z0-9.-]*[a-z0-9]$") then
        if desired ~= "" and (host == desired or host:sub(-#desired - 1) == "." .. desired) then
            local cursor = host
            while cursor ~= desired do
                add(cursor)
                cursor = cursor:match("^[^.]+%.(.+)$") or desired
            end
        else
            add(host)
        end
    end

    local parent = desired
    while parent ~= "" do
        parent = parent:match("^[^.]+%.(.+)$") or ""
        if parent ~= "" and parent:find("%.") then add(parent) else break end
    end
    return domains
end

local function cleanup_cookie_lines(include_desired, include_host_only, desired_domain)
    local lines = {}
    if include_host_only then lines[#lines + 1] = cookie_line("", 0, "") end
    local desired = normalize_domain(desired_domain)
    if include_desired and desired ~= "" then
        lines[#lines + 1] = cookie_line("", 0, desired)
    end
    for _, domain in ipairs(legacy_cookie_domains(desired)) do
        lines[#lines + 1] = cookie_line("", 0, domain)
    end
    return lines
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
    local tokens, occurrences, seen = {}, 0, {}
    for pair in cookie:gmatch("[^;]+") do
        local name, token = pair:match("^%s*([^=]+)=([A-Za-z0-9]+)%s*$")
        if name == _M.cookie_name then
            occurrences = occurrences + 1
            if not seen[token] then
                seen[token] = true
                tokens[#tokens + 1] = token
            end
        end
    end
    if #tokens == 0 then return nil end

    local selected, latest_expiry
    for _, token in ipairs(tokens) do
        local current = _M.get(token)
        if current and (not latest_expiry or tonumber(current.expires_at) >= latest_expiry) then
            selected = token
            latest_expiry = tonumber(current.expires_at)
        end
    end
    selected = selected or tokens[1]
    if occurrences > 1 and latest_expiry then _M.set_cookie(selected) end
    return selected
end

-- 设置/清除 Set-Cookie 头
function _M.set_cookie(token)
    local desired = current_cookie_domain()
    local lines = { cookie_line(token, _M.ttl, desired) }
    for _, line in ipairs(cleanup_cookie_lines(false, desired ~= "", desired)) do lines[#lines + 1] = line end
    ngx.header["Set-Cookie"] = lines
end

function _M.clear_cookie()
    local desired = current_cookie_domain()
    ngx.header["Set-Cookie"] = cleanup_cookie_lines(true, true, desired)
end

return _M
