local authz = require "resty.authz"
local api_key = require "resty.authz.api_key"
local cjson = require "cjson.safe"
local db = require "resty.authz.db"
local identity_key = require "resty.authz.identity"
local session = require "resty.authz.session"
local util = require "resty.authz.util"
local discovery = require "resty.authz.discovery"
local target = require "resty.authz.target"

local _M = {}

local HUMAN_ROLE_CATALOG = { "admin", "staff", "user", "viewer" }
local POLICY_ROLE_CATALOG = { "admin", "staff", "user", "viewer", "api" }
local HUMAN_ROLE_SET = {}
local POLICY_ROLE_SET = {}
for _, role in ipairs(HUMAN_ROLE_CATALOG) do HUMAN_ROLE_SET[role] = true end
for _, role in ipairs(POLICY_ROLE_CATALOG) do POLICY_ROLE_SET[role] = true end

local HTTP_METHODS = {
    "*", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"
}
local HTTP_METHOD_SET = {}
for _, method in ipairs(HTTP_METHODS) do HTTP_METHOD_SET[method] = true end

local BINDING_PROXY_FIELDS = {
    "upstream_host", "forwarded_host", "forwarded_proto", "forwarded_port",
    "origin_mode", "custom_origin", "simulate_local", "local_ip", "upstream_scheme",
    "upstream_ssl_verify", "upstream_path",
}
local FORWARDED_PROTO_SET = { [""] = true, http = true, https = true }
local UPSTREAM_SCHEME_SET = { http = true, https = true }
local ORIGIN_MODE_SET = {
    auto = true, preserve = true, rewrite = true, remove = true, custom = true,
}

local function normalize_http_methods(value)
    local input = type(value) == "table" and value or { tostring(value or "*") }
    local selected = {}
    for _, item in ipairs(input) do
        for method in tostring(item):gmatch("[^,%s]+") do
            method = method:upper()
            if not HTTP_METHOD_SET[method] then
                return nil, "动作必须是标准 HTTP 方法或 *"
            end
            if method == "*" then return "*" end
            selected[method] = true
        end
    end
    local methods = {}
    for _, method in ipairs(HTTP_METHODS) do
        if method ~= "*" and selected[method] then methods[#methods + 1] = method end
    end
    if #methods == 0 then return nil, "至少选择一个 HTTP 方法" end
    return table.concat(methods, ",")
end

local function parse_policy_object(value)
    local object = tostring(value or ""):gsub("%s+", "")
    if object == "" then object = "/*" end
    if #object > 512 or object:find(",", 1, true) or object:find("|", 1, true) or
        object:find("%c") then
        return nil, "对象格式不合法"
    end
    if object == "/*" then
        return { value = object, kind = "global", path = "/*" }
    end
    local port_value, path = object:match("^/(%d+)(/.*)$")
    local port = tonumber(port_value)
    if not port or port < authz.config.port_min or port > authz.config.port_max then
        return nil, "对象必须使用 /<端口><路径> 格式，且端口在允许范围内"
    end
    return { value = "/" .. tostring(port) .. path, kind = "port", port = port, path = path }
end

local function bump_rev()
    local dict = ngx.shared[authz.config.cache_dict]
    if dict then dict:incr("rev", 1, 0) end
end

local function db_error(message, err)
    return nil, message .. ": " .. tostring(err or "database error"), 500
end

local function user_by_id(id)
    local rows = db.query([[SELECT id, username, roles, enabled, created_at, last_login_at, updated_at
        FROM users WHERE id = ?]], id)
    return rows and rows[1]
end

local function remote_user(provider, subject)
    local rows = db.query([[SELECT provider, subject, username, roles, remote_roles,
        roles_overridden, enabled, synced_at, created_at, last_login_at, updated_at FROM remote_users
        WHERE provider = ? AND subject = ?]], provider, subject)
    return rows and rows[1]
end

local function normalize_roles(value)
    local input = type(value) == "table" and value or { tostring(value or "user") }
    local roles, seen = {}, {}
    for _, item in ipairs(input) do
        for role in tostring(item):gmatch("[^,%s]+") do
            role = role:lower()
            if not HUMAN_ROLE_SET[role] then
                return nil, "角色仅支持 admin、staff、user、viewer"
            end
            if not seen[role] then
                seen[role] = true
                roles[#roles + 1] = role
            end
        end
    end
    if #roles == 0 then roles[1] = "user" end
    table.sort(roles)
    return table.concat(roles, ",")
end

function _M.roles_for(identity)
    if type(identity) == "table" and identity.kind == "api_key" then
        local role = api_key.valid_role(identity.role)
        return role and { role } or {}
    end
    local username = type(identity) == "table" and identity.username or identity
    local source = type(identity) == "table" and identity.source or "local"
    local rows
    if source ~= "local" then
        rows = db.query([[SELECT roles FROM remote_users
            WHERE provider = ? AND username = ? AND enabled = 1]], source, username)
    else
        rows = db.query("SELECT roles FROM users WHERE username = ? AND enabled = 1", username)
    end
    if not rows or not rows[1] then return {} end
    local roles = {}
    for role in rows[1].roles:gmatch("[^,%s]+") do roles[#roles + 1] = role end
    return roles
end

function _M.has_any_role(identity, allowed)
    local role_set = {}
    for _, role in ipairs(type(allowed) == "table" and allowed or { allowed }) do
        role_set[tostring(role)] = true
    end
    for _, role in ipairs(_M.roles_for(identity)) do
        if role_set[role] then return true end
    end
    return false
end

function _M.is_admin(s)
    if not s then return false end
    for _, role in ipairs(_M.roles_for(s)) do
        if role == "admin" then return true end
    end
    return false
end

function _M.session_payload(s)
    if s.kind == "api_key" then
        return {
            authenticated = true,
            auth_type = "api_key",
            api_key_id = s.id,
            username = s.username,
            source = s.source,
            identity = s.identity,
            roles = _M.roles_for(s),
            admin = _M.is_admin(s),
            created_at = s.created_at,
            last_login_at = cjson.null,
            updated_at = s.updated_at,
        }
    end
    local timestamps
    if s.source == "local" then
        timestamps = db.query([[SELECT created_at, last_login_at, updated_at FROM users
            WHERE username = ?]], s.username)
    else
        timestamps = db.query([[SELECT created_at, last_login_at, updated_at FROM remote_users
            WHERE provider = ? AND username = ?]], s.source, s.username)
    end
    timestamps = timestamps and timestamps[1] or {}
    return {
        authenticated = true,
        username = s.username,
        source = s.source,
        identity = identity_key.key(s.source, s.username),
        roles = _M.roles_for(s),
        admin = _M.is_admin(s),
        csrf = s.csrf,
        created_at = timestamps.created_at,
        last_login_at = timestamps.last_login_at or cjson.null,
        updated_at = timestamps.updated_at,
    }
end

local function principal_for(s)
    if s.kind == "api_key" then return s.identity end
    return identity_key.key(s.source, s.username)
end

function _M.list_users(s)
    local users = db.query(
        [[SELECT id, username, roles, enabled, created_at, last_login_at, updated_at
            FROM users ORDER BY id]]) or {}
    local remote_users = db.query([[SELECT provider, subject, username, roles, remote_roles,
        roles_overridden, enabled, synced_at, created_at, last_login_at, updated_at
        FROM remote_users r ORDER BY username, provider]]) or {}
    for _, user in ipairs(users) do
        user.source = "local"
        user.identity = identity_key.key("local", user.username)
        user.last_login_at = user.last_login_at or cjson.null
    end
    for _, user in ipairs(remote_users) do
        user.source = user.provider
        user.identity = identity_key.key(user.provider, user.username)
        user.recorded_at = user.synced_at
        user.synced_at = nil
        user.last_login_at = user.last_login_at or cjson.null
    end
    return {
        username = s.username,
        source = s.source,
        identity = principal_for(s),
        roles = _M.roles_for(s),
        admin = true,
        csrf = s.csrf,
        available_roles = HUMAN_ROLE_CATALOG,
        users = users,
        remote_users = remote_users
    }
end

function _M.authorization(s)
    local bindings = db.query("SELECT * FROM bindings ORDER BY domain") or {}
    local bindings_by_port = {}
    for _, binding in ipairs(bindings) do
        local port = tonumber(binding.port)
        bindings_by_port[port] = bindings_by_port[port] or {}
        bindings_by_port[port][#bindings_by_port[port] + 1] = {
            id = binding.id,
            domain = binding.domain,
            target_ip = binding.target_ip,
            port = binding.port,
            menu_name = binding.menu_name,
            enabled = binding.enabled,
        }
    end
    local policies = db.query("SELECT * FROM policies ORDER BY ptype, v0, id") or {}
    for _, policy in ipairs(policies) do
        local action, effect = tostring(policy.v2 or ""), "allow"
        if action:sub(-5) == "|deny" then
            action = action:sub(1, -6)
            effect = "deny"
        end
        policy.action = action
        policy.effect = effect
        local source, username = identity_key.parse(policy.v0)
        policy.subject_label = source and (username .. " · " .. source) or policy.v0
        if policy.ptype == "p" then
            local object = parse_policy_object(policy.v1)
            if object then
                policy.object_kind = object.kind
                policy.object_port = object.port or cjson.null
                policy.object_path = object.path
                policy.binding_matches = object.port and (bindings_by_port[object.port] or {}) or {}
                if object.port then
                    if #policy.binding_matches == 1 then
                        policy.object_kind = "binding"
                    elseif #policy.binding_matches > 1 then
                        policy.object_kind = "shared"
                    else
                        policy.object_kind = "unbound"
                    end
                end
            else
                policy.object_kind = "invalid"
                policy.object_port = cjson.null
                policy.object_path = policy.v1
                policy.binding_matches = {}
            end
        end
    end
    local admin = _M.is_admin(s)
    local policy_users = {}
    if admin then
        local users = db.query("SELECT username FROM users WHERE enabled = 1 ORDER BY username") or {}
        for _, user in ipairs(users) do
            policy_users[#policy_users + 1] = {
                username = user.username,
                source = "local",
                identity = identity_key.key("local", user.username),
            }
        end
        local remote_users = db.query([[SELECT provider, username FROM remote_users
            WHERE enabled = 1 ORDER BY username, provider]]) or {}
        for _, user in ipairs(remote_users) do
            policy_users[#policy_users + 1] = {
                username = user.username,
                source = user.provider,
                identity = identity_key.key(user.provider, user.username),
            }
        end
    end
    return {
        username = s.username,
        source = s.source,
        identity = principal_for(s),
        roles = _M.roles_for(s),
        admin = admin,
        csrf = s.csrf,
        bindings = bindings,
        policies = policies,
        policy_users = policy_users,
        policy_roles = POLICY_ROLE_CATALOG,
        http_methods = HTTP_METHODS,
        port_min = authz.config.port_min,
        port_max = authz.config.port_max
    }
end

function _M.applications()
    local applications = db.query([[SELECT id, domain, target_ip, port, note, menu_name, websocket,
        upstream_host, forwarded_host, forwarded_proto, forwarded_port, origin_mode,
        custom_origin, simulate_local, local_ip, upstream_scheme, upstream_ssl_verify,
        upstream_path
        FROM bindings WHERE enabled = 1 ORDER BY domain]]) or {}
    local known_ports = {}
    for _, application in ipairs(applications) do
        known_ports[tonumber(application.port)] = true
        application.label = application.menu_name ~= "" and application.menu_name or application.domain
        application.binding = true
    end
    for _, application in ipairs(discovery.list(authz.config)) do
        if not known_ports[tonumber(application.port)] then
            application.label = "local:" .. tostring(application.port)
            application.binding = false
            applications[#applications + 1] = application
        end
    end
    table.sort(applications, function(left, right)
        if tonumber(left.port) == tonumber(right.port) then
            return tostring(left.domain or "") < tostring(right.domain or "")
        end
        return tonumber(left.port) < tonumber(right.port)
    end)
    return applications
end

function _M.create_user(data)
    local username = tostring(data.username or ""):lower():gsub("%s+", "")
    local password = tostring(data.password or "")
    if not ngx.re.match(username, [[^[a-z0-9_-]{2,32}$]]) then
        return nil, "用户名格式不合法", 422
    end
    if #password < 6 then return nil, "密码至少 6 位", 422 end
    local roles, role_err = normalize_roles(data.roles)
    if not roles then return nil, role_err, 422 end
    local salt = util.random_token(16)
    local hash, hash_err = util.hash_password(password, salt)
    if not hash then return nil, tostring(hash_err), 500 end
    local now = os.time()
    local ok, err = db.exec(
        [[INSERT INTO users(username, password_hash, salt, roles, enabled, created_at, updated_at)
            VALUES(?,?,?,?,1,?,?)]],
        username, hash, salt, roles, now, now)
    if not ok then return db_error("创建用户失败", err) end
    bump_rev()
    return { message = "用户已创建" }, nil, 201
end

function _M.update_user(id, data)
    local user = user_by_id(id)
    if not user then return nil, "用户不存在", 404 end
    local now = os.time()
    if data.enabled ~= nil then
        local enabled = data.enabled == true or data.enabled == 1
        if user.username == "admin" and not enabled then
            return nil, "不能禁用内置管理员", 409
        end
        local ok, err = db.exec("UPDATE users SET enabled = ?, updated_at = ? WHERE id = ?",
            enabled and 1 or 0, now, id)
        if not ok then return db_error("更新用户状态失败", err) end
        if not enabled then session.delete_all_for(user.username, "local") end
    end
    if data.roles ~= nil then
        if user.username == "admin" then return nil, "不能修改内置管理员角色", 409 end
        local roles, role_err = normalize_roles(data.roles)
        if not roles then return nil, role_err, 422 end
        local ok, err = db.exec("UPDATE users SET roles = ?, updated_at = ? WHERE id = ?", roles, now, id)
        if not ok then return db_error("更新角色失败", err) end
    end
    bump_rev()
    return { message = "用户已更新" }
end

function _M.update_remote_user(provider, subject, data)
    provider = tostring(provider or ""):lower()
    subject = tostring(subject or "")
    if not provider:match("^[a-z0-9_.-]+$") or subject == "" then
        return nil, "远程身份格式不合法", 422
    end
    local user = remote_user(provider, subject)
    if not user then return nil, "远程用户不存在", 404 end
    local now = os.time()

    local roles
    local overridden
    local has_role_update = false
    if data.use_remote_roles == true then
        roles = user.remote_roles
        overridden = 0
        has_role_update = true
    elseif data.roles ~= nil then
        local role_err
        roles, role_err = normalize_roles(data.roles)
        if not roles then return nil, role_err, 422 end
        overridden = 1
        has_role_update = true
    end
    if data.enabled == nil and not has_role_update then
        return nil, "没有可更新字段", 422
    end

    if data.enabled ~= nil then
        local enabled = data.enabled == true or data.enabled == 1
        local ok, err = db.exec([[UPDATE remote_users SET enabled = ?, updated_at = ?
            WHERE provider = ? AND subject = ?]], enabled and 1 or 0, now, provider, subject)
        if not ok then return db_error("更新远程用户状态失败", err) end
        if not enabled then session.delete_all_for(user.username, provider) end
    end
    if has_role_update then
        local ok, err = db.exec([[UPDATE remote_users SET roles = ?, roles_overridden = ?, updated_at = ?
            WHERE provider = ? AND subject = ?]], roles, overridden, now, provider, subject)
        if not ok then return db_error("更新远程用户角色失败", err) end
    end
    bump_rev()
    return {
        message = has_role_update and
            (overridden == 1 and "远程用户角色已覆盖" or "已恢复上游角色") or
            "远程用户状态已更新",
        roles = has_role_update and roles or user.roles,
        roles_overridden = has_role_update and overridden or user.roles_overridden,
    }
end

function _M.delete_user(id)
    local user = user_by_id(id)
    if not user then return nil, "用户不存在", 404 end
    if user.username == "admin" then return nil, "不能删除内置管理员", 409 end
    local ok, err = db.exec("DELETE FROM users WHERE id = ?", id)
    if not ok then return db_error("删除用户失败", err) end
    session.delete_all_for(user.username, "local")
    db.exec("DELETE FROM policies WHERE v0 = ?", identity_key.key("local", user.username))
    bump_rev()
    return { message = "用户已删除" }
end

function _M.delete_remote_user(provider, subject)
    provider = tostring(provider or ""):lower()
    subject = tostring(subject or "")
    if not provider:match("^[a-z0-9_.-]+$") or subject == "" then
        return nil, "远程身份格式不合法", 422
    end
    local user = remote_user(provider, subject)
    if not user then return nil, "远程用户不存在", 404 end
    local ok, err = db.exec(
        "DELETE FROM remote_users WHERE provider = ? AND subject = ?", provider, subject)
    if not ok then return db_error("删除远程用户失败", err) end
    session.delete_all_for(user.username, provider)
    db.exec("DELETE FROM policies WHERE v0 = ?", identity_key.key(provider, user.username))
    bump_rev()
    return { message = "远程用户已删除" }
end

function _M.reset_password(id, data)
    local user = user_by_id(id)
    if not user then return nil, "用户不存在", 404 end
    local password = tostring(data.password or data.newpw or "")
    if #password < 6 then return nil, "密码至少 6 位", 422 end
    local salt = util.random_token(16)
    local hash, hash_err = util.hash_password(password, salt)
    if not hash then return nil, tostring(hash_err), 500 end
    local ok, err = db.exec([[UPDATE users SET password_hash = ?, salt = ?, updated_at = ?
        WHERE id = ?]], hash, salt, os.time(), id)
    if not ok then return db_error("重置密码失败", err) end
    session.delete_all_for(user.username, "local")
    return { message = "密码已重置" }
end

function _M.change_password(s, _, data)
    if s.source ~= "local" then
        return nil, "远程用户请在 NocoBase 修改密码", 409
    end
    local old_password = tostring(data.old_password or data.oldpw or "")
    local new_password = tostring(data.new_password or data.newpw or "")
    local confirm_password = tostring(data.new_password_confirm or data.newpw_confirm or "")
    local rows = db.query("SELECT password_hash, salt FROM users WHERE username = ?", s.username)
    local user = rows and rows[1]
    if not user or not util.verify_password(old_password, user.salt, user.password_hash) then
        return nil, "当前密码错误", 422
    end
    if #new_password < 6 then return nil, "新密码至少 6 位", 422 end
    if confirm_password ~= "" and confirm_password ~= new_password then
        return nil, "两次输入的新密码不一致", 422
    end
    local salt = util.random_token(16)
    local hash, hash_err = util.hash_password(new_password, salt)
    if not hash then return nil, tostring(hash_err), 500 end
    local ok, err = db.exec(
        "UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE username = ?",
        hash, salt, os.time(), s.username)
    if not ok then return db_error("修改密码失败", err) end
    session.delete_all_for(s.username, "local")
    return { message = "密码已修改" }
end

local function valid_host(domain)
    return ngx.re.match(domain,
        [[^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$]]) ~= nil
end

local function valid_domain_prefix(prefix)
    return ngx.re.match(prefix, [[^[a-z0-9]([a-z0-9-]*[a-z0-9])?$]]) ~= nil
end

local function instance_base_host()
    local host = tostring(ngx.var.host or ""):lower()
    host = host:gsub("^a%-", ""):gsub("^%d+%-", "")
    return host
end

local function normalize_binding_domain(value)
    local domain = tostring(value or ""):lower():gsub("%s+", ""):gsub(":%d+$", "")
    if valid_host(domain) then return domain end
    if not valid_domain_prefix(domain) then return nil end
    local generated = domain .. "-" .. instance_base_host()
    return valid_host(generated) and generated or nil
end

local function normalize_binding_proxy(data)
    local function optional(value, default)
        if value == nil or value == cjson.null then return default end
        return value
    end

    local upstream_host = target.normalize_authority(optional(data.upstream_host, ""), true)
    if upstream_host == nil then return nil, "上游 Host 格式不合法" end

    local forwarded_host = target.normalize_authority(optional(data.forwarded_host, ""), true)
    if forwarded_host == nil then return nil, "Forwarded Host 格式不合法" end

    local forwarded_proto = tostring(optional(data.forwarded_proto, "")):lower()
        :gsub("^%s+", ""):gsub("%s+$", "")
    if not FORWARDED_PROTO_SET[forwarded_proto] then
        return nil, "Forwarded Proto 仅支持自动、http 或 https"
    end

    local forwarded_port = optional(data.forwarded_port, "")
    if forwarded_port == "" then
        forwarded_port = 0
    else
        forwarded_port = tonumber(forwarded_port)
        if forwarded_port == 0 then
            forwarded_port = 0
        elseif not forwarded_port or forwarded_port % 1 ~= 0 or
            forwarded_port < 1 or forwarded_port > 65535 then
            return nil, "Forwarded Port 必须是 1-65535，留空表示自动"
        end
    end

    local origin_mode = tostring(optional(data.origin_mode, "auto")):lower()
        :gsub("^%s+", ""):gsub("%s+$", "")
    if not ORIGIN_MODE_SET[origin_mode] then return nil, "Origin 处理模式不受支持" end
    local custom_origin = target.normalize_origin(optional(data.custom_origin, ""), true)
    if custom_origin == nil then return nil, "自定义 Origin 必须是合法的 http(s) Origin" end
    if origin_mode == "custom" and custom_origin == "" then
        return nil, "自定义 Origin 模式必须填写 Origin"
    end

    local local_ip = target.normalize_ip(optional(data.local_ip, "127.0.0.1"))
    if not local_ip then return nil, "模拟本机 IP 必须是合法的 IPv4 或 IPv6 地址" end

    local upstream_scheme = tostring(optional(data.upstream_scheme, "http")):lower()
        :gsub("^%s+", ""):gsub("%s+$", "")
    if not UPSTREAM_SCHEME_SET[upstream_scheme] then
        return nil, "上游协议仅支持 http 或 https"
    end

    local upstream_path = target.normalize_upstream_path(optional(data.upstream_path, ""))
    if upstream_path == nil then
        return nil, "上游改写路径必须是合法路径，不能包含查询参数、片段、连续斜杠或 .."
    end

    local ssl_verify = optional(data.upstream_ssl_verify, true)
    if type(ssl_verify) == "string" then
        ssl_verify = ssl_verify:lower():gsub("^%s+", ""):gsub("%s+$", "")
    end

    return {
        upstream_host = upstream_host,
        forwarded_host = forwarded_host,
        forwarded_proto = forwarded_proto,
        forwarded_port = forwarded_port,
        origin_mode = origin_mode,
        custom_origin = custom_origin,
        simulate_local = (data.simulate_local == true or data.simulate_local == 1) and 1 or 0,
        local_ip = local_ip,
        upstream_scheme = upstream_scheme,
        upstream_ssl_verify = (ssl_verify == false or ssl_verify == 0 or ssl_verify == "0" or ssl_verify == "false") and 0 or 1,
        upstream_path = upstream_path,
    }
end

local function proxy_fields_present(data)
    for _, field in ipairs(BINDING_PROXY_FIELDS) do
        if data[field] ~= nil then return true end
    end
    return false
end

function _M.create_application(data)
    local domain = normalize_binding_domain(data.domain)
    local target_ip = target.normalize_ip(data.target_ip == nil and "127.0.0.1" or data.target_ip)
    local port = tonumber(data.port)
    if not domain then return nil, "请输入最后一级域名前缀，例如 name1", 422 end
    if not target_ip then return nil, "目标 IP 必须是合法的 IPv4 或 IPv6 地址", 422 end
    if not port or port < authz.config.port_min or port > authz.config.port_max then
        return nil, "端口必须在 " .. authz.config.port_min .. "-" .. authz.config.port_max, 422
    end
    local proxy, proxy_err = normalize_binding_proxy(data)
    if not proxy then return nil, proxy_err, 422 end
    local note = tostring(data.note or "")
    local menu_name = tostring(data.menu_name or "")
    if #note > 256 then return nil, "备注不能超过 256 个字符", 422 end
    if #menu_name > 128 then return nil, "菜单名称不能超过 128 个字符", 422 end
    local existing = db.query("SELECT id FROM bindings WHERE domain = ?", domain)
    if existing and existing[1] then
        return nil, "域名绑定已存在: " .. domain, 409
    end
    local ok, err = db.exec([[INSERT INTO bindings(
        domain, target_ip, port, enabled, websocket, note, menu_name,
        upstream_host, forwarded_host, forwarded_proto, forwarded_port,
        origin_mode, custom_origin, simulate_local, local_ip,
        upstream_scheme, upstream_ssl_verify, upstream_path, created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)]],
        domain, target_ip, port, data.enabled == false and 0 or 1,
        data.websocket == true and 1 or 0, note, menu_name,
        proxy.upstream_host, proxy.forwarded_host, proxy.forwarded_proto,
        proxy.forwarded_port, proxy.origin_mode, proxy.custom_origin,
        proxy.simulate_local, proxy.local_ip, proxy.upstream_scheme,
        proxy.upstream_ssl_verify, proxy.upstream_path, os.time())
    if not ok then return db_error("创建应用失败", err) end
    bump_rev()
    return { message = "应用已创建" }, nil, 201
end

local function valid_api_key_name(value)
    local name = tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", "")
    if not ngx.re.match(name, [[^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$]], "jo") then
        return nil
    end
    return name
end

local function api_key_by_id(id)
    local rows = db.query([[SELECT id, name, role, enabled, created_at, updated_at
        FROM api_keys WHERE id = ?]], id)
    return rows and rows[1]
end

function _M.list_api_keys()
    return db.query([[SELECT id, name, role, enabled, created_at, updated_at
        FROM api_keys ORDER BY id]]) or {}
end

function _M.create_api_key(data)
    local name = valid_api_key_name(data.name)
    if not name then return nil, "名称需为 2-64 位字母、数字、点、下划线或连字符", 422 end
    local duplicate = db.query("SELECT id FROM api_keys WHERE name = ?", name)
    if duplicate and duplicate[1] then return nil, "API Key 名称已存在", 409 end
    local role = api_key.valid_role(data.role or "api")
    if not role then return nil, "API Key 角色仅支持 admin、staff、user、viewer、api", 422 end

    local random_part = util.random_token(32)
    if not random_part then return nil, "生成 API Key 失败", 500 end
    local token = "ak_" .. random_part
    local token_hash, hash_err = util.sha256_hex(token)
    if not token_hash then return nil, tostring(hash_err), 500 end
    local now = os.time()
    local ok, err = db.exec([[INSERT INTO api_keys
        (name, token_hash, role, enabled, created_at, updated_at)
        VALUES(?, ?, ?, 1, ?, ?)]], name, token_hash, role, now, now)
    if not ok then return db_error("创建 API Key 失败", err) end
    local rows = db.query([[SELECT id, name, role, enabled, created_at, updated_at
        FROM api_keys WHERE token_hash = ?]], token_hash)
    local created = rows and rows[1]
    if not created then return nil, "创建 API Key 后读取失败", 500 end
    bump_rev()
    return {
        id = created.id,
        name = created.name,
        role = created.role,
        enabled = created.enabled,
        created_at = created.created_at,
        updated_at = created.updated_at,
        token = token,
    }, nil, 201
end

function _M.update_api_key(id, data)
    id = tonumber(id)
    local current = id and api_key_by_id(id)
    if not current then return nil, "API Key 不存在", 404 end
    local fields, values = {}, {}
    if data.name ~= nil then
        local name = valid_api_key_name(data.name)
        if not name then return nil, "名称需为 2-64 位字母、数字、点、下划线或连字符", 422 end
        local duplicate = db.query("SELECT id FROM api_keys WHERE name = ? AND id != ?", name, id)
        if duplicate and duplicate[1] then return nil, "API Key 名称已存在", 409 end
        fields[#fields + 1] = "name = ?"
        values[#values + 1] = name
    end
    if data.enabled ~= nil then
        fields[#fields + 1] = "enabled = ?"
        values[#values + 1] = (data.enabled == true or data.enabled == 1) and 1 or 0
    end
    if data.role ~= nil then
        local role = api_key.valid_role(data.role)
        if not role then return nil, "API Key 角色仅支持 admin、staff、user、viewer、api", 422 end
        fields[#fields + 1] = "role = ?"
        values[#values + 1] = role
    end
    if #fields == 0 then return nil, "没有可更新字段", 422 end
    fields[#fields + 1] = "updated_at = ?"
    values[#values + 1] = os.time()
    values[#values + 1] = id
    local ok, err = db.exec("UPDATE api_keys SET " .. table.concat(fields, ", ") .. " WHERE id = ?",
        unpack(values))
    if not ok then return db_error("更新 API Key 失败", err) end
    bump_rev()
    return api_key_by_id(id)
end

function _M.delete_api_key(id)
    id = tonumber(id)
    if not id or not api_key_by_id(id) then return nil, "API Key 不存在", 404 end
    local ok, err = db.exec("DELETE FROM api_keys WHERE id = ?", id)
    if not ok then return db_error("删除 API Key 失败", err) end
    bump_rev()
    return { message = "API Key 已删除" }
end

function _M.update_application(id, data)
    local rows = db.query("SELECT * FROM bindings WHERE id = ?", id)
    if not rows or not rows[1] then return nil, "应用不存在", 404 end
    local current = rows[1]
    local fields, values = {}, {}
    if data.domain ~= nil then
        local domain = normalize_binding_domain(data.domain)
        if not domain then return nil, "请输入最后一级域名前缀，例如 name1", 422 end
        local duplicate = db.query("SELECT id FROM bindings WHERE domain = ? AND id != ?", domain, id)
        if duplicate and duplicate[1] then return nil, "域名已存在", 409 end
        fields[#fields + 1] = "domain = ?"
        values[#values + 1] = domain
    end
    if data.port ~= nil then
        local port = tonumber(data.port)
        if not port or port < authz.config.port_min or port > authz.config.port_max then
            return nil, "端口必须在 " .. authz.config.port_min .. "-" .. authz.config.port_max, 422
        end
        fields[#fields + 1] = "port = ?"
        values[#values + 1] = port
    end
    if data.target_ip ~= nil then
        local target_ip = target.normalize_ip(data.target_ip)
        if not target_ip then return nil, "目标 IP 必须是合法的 IPv4 或 IPv6 地址", 422 end
        fields[#fields + 1] = "target_ip = ?"
        values[#values + 1] = target_ip
    end
    if data.note ~= nil then
        local note = tostring(data.note)
        if #note > 256 then return nil, "备注不能超过 256 个字符", 422 end
        fields[#fields + 1] = "note = ?"
        values[#values + 1] = note
    end
    if data.menu_name ~= nil then
        local menu_name = tostring(data.menu_name)
        if #menu_name > 128 then return nil, "菜单名称不能超过 128 个字符", 422 end
        fields[#fields + 1] = "menu_name = ?"
        values[#values + 1] = menu_name
    end
    if data.enabled ~= nil then
        fields[#fields + 1] = "enabled = ?"
        values[#values + 1] = (data.enabled == true or data.enabled == 1) and 1 or 0
    end
    if data.websocket ~= nil then
        fields[#fields + 1] = "websocket = ?"
        values[#values + 1] = (data.websocket == true or data.websocket == 1) and 1 or 0
    end
    if proxy_fields_present(data) then
        local merged = {}
        for _, field in ipairs(BINDING_PROXY_FIELDS) do
            if data[field] ~= nil then
                merged[field] = data[field]
            else
                merged[field] = current[field]
            end
        end
        local proxy, proxy_err = normalize_binding_proxy(merged)
        if not proxy then return nil, proxy_err, 422 end
        for _, field in ipairs(BINDING_PROXY_FIELDS) do
            fields[#fields + 1] = field .. " = ?"
            values[#values + 1] = proxy[field]
        end
    end
    if #fields == 0 then return nil, "没有可更新字段", 422 end
    values[#values + 1] = id
    local ok, err = db.exec("UPDATE bindings SET " .. table.concat(fields, ", ") .. " WHERE id = ?", unpack(values))
    if not ok then return db_error("更新应用失败", err) end
    bump_rev()
    return { message = "应用已更新" }
end

function _M.delete_application(id)
    local ok, err = db.exec("DELETE FROM bindings WHERE id = ?", id)
    if not ok then return db_error("删除应用失败", err) end
    bump_rev()
    return { message = "应用已删除" }
end

local function validate_policy_identity(value)
    local source, username = identity_key.parse(value)
    if not source then return false end
    local rows
    if source == "local" then
        rows = db.query("SELECT id FROM users WHERE username = ? AND enabled = 1", username)
    else
        rows = db.query([[SELECT subject FROM remote_users
            WHERE provider = ? AND username = ? AND enabled = 1]], source, username)
    end
    return rows and rows[1] ~= nil
end

local function normalize_policy(data)
    local ptype = data.ptype == "g" and "g" or "p"
    local v0 = tostring(data.v0 or ""):gsub("%s+", "")
    if v0 == "" or v0:find(",", 1, true) then return nil, "主体格式不合法", 422 end
    local v1, v2
    if ptype == "p" then
        if v0:sub(1, 5) == "role:" then
            if not POLICY_ROLE_SET[v0:sub(6)] then return nil, "策略角色不受支持", 422 end
        else
            if v0:sub(1, 5) ~= "user:" then v0 = identity_key.key("local", v0) or "" end
            if not validate_policy_identity(v0) then return nil, "策略用户不存在或已禁用", 422 end
        end
        local object, object_err = parse_policy_object(data.v1)
        if not object then return nil, object_err, 422 end
        v1 = object.value
        local binding_id = tonumber(data.binding_id)
        if data.binding_id ~= nil and tostring(data.binding_id) ~= "" then
            if not binding_id or binding_id < 1 or binding_id ~= math.floor(binding_id) then
                return nil, "绑定对象不存在", 422
            end
            if object.kind ~= "port" then return nil, "全局对象不能关联域名绑定", 422 end
            local selected = db.query("SELECT id, port FROM bindings WHERE id = ?", binding_id)
            selected = selected and selected[1]
            if not selected then return nil, "绑定对象不存在", 422 end
            if tonumber(selected.port) ~= object.port then
                return nil, "策略对象端口与所选绑定不一致", 422
            end
        end
        local method_err
        v2, method_err = normalize_http_methods(data.v2)
        if not v2 then return nil, method_err, 422 end
        if data.eft == "deny" then v2 = v2 .. "|deny" end
    else
        v1 = tostring(data.v1 or ""):gsub("%s+", "")
        if not HUMAN_ROLE_SET[v1:gsub("^role:", "")] then
            return nil, "用户角色仅支持 admin、staff、user、viewer", 422
        end
        v1 = "role:" .. v1:gsub("^role:", "")
        if v0:sub(1, 5) ~= "user:" then v0 = identity_key.key("local", v0) or "" end
        if not validate_policy_identity(v0) then return nil, "角色分配用户不存在或已禁用", 422 end
        v2 = "-"
    end
    return { ptype = ptype, v0 = v0, v1 = v1, v2 = v2 }
end

function _M.create_policy(data)
    local policy, err, status = normalize_policy(data)
    if not policy then return nil, err, status end
    local ok, err = db.exec(
        "INSERT OR IGNORE INTO policies(ptype, v0, v1, v2) VALUES(?,?,?,?)",
        policy.ptype, policy.v0, policy.v1, policy.v2)
    if not ok then return db_error("创建策略失败", err) end
    bump_rev()
    return { message = "策略已创建" }, nil, 201
end

function _M.update_policy(id, data)
    if not id then return nil, "策略不存在", 404 end
    local current = db.query("SELECT id FROM policies WHERE id = ?", id)
    if not current or not current[1] then return nil, "策略不存在", 404 end
    local policy, err, status = normalize_policy(data)
    if not policy then return nil, err, status end
    local duplicate = db.query([[SELECT id FROM policies
        WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND id != ?]],
        policy.ptype, policy.v0, policy.v1, policy.v2, id)
    if duplicate and duplicate[1] then return nil, "相同策略已存在", 409 end
    local ok, update_err = db.exec(
        "UPDATE policies SET ptype = ?, v0 = ?, v1 = ?, v2 = ? WHERE id = ?",
        policy.ptype, policy.v0, policy.v1, policy.v2, id)
    if not ok then return db_error("更新策略失败", update_err) end
    bump_rev()
    return { message = "策略已更新" }
end

function _M.delete_policy(id)
    local ok, err = db.exec("DELETE FROM policies WHERE id = ?", id)
    if not ok then return db_error("删除策略失败", err) end
    bump_rev()
    return { message = "策略已删除" }
end

return _M
