local authz = require "resty.authz"
local cjson = require "cjson.safe"
local db = require "resty.authz.db"
local identity_key = require "resty.authz.identity"
local session = require "resty.authz.session"
local util = require "resty.authz.util"
local discovery = require "resty.authz.discovery"

local _M = {}

local ROLE_CATALOG = { "admin", "staff", "user", "viewer" }
local ROLE_SET = {}
for _, role in ipairs(ROLE_CATALOG) do ROLE_SET[role] = true end

local HTTP_METHODS = {
    "*", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"
}
local HTTP_METHOD_SET = {}
for _, method in ipairs(HTTP_METHODS) do HTTP_METHOD_SET[method] = true end

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
            if not ROLE_SET[role] then
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

function _M.is_admin(s)
    if not s then return false end
    for _, role in ipairs(_M.roles_for(s)) do
        if role == "admin" then return true end
    end
    return false
end

function _M.session_payload(s)
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
        identity = identity_key.key(s.source, s.username),
        roles = _M.roles_for(s),
        admin = true,
        csrf = s.csrf,
        available_roles = ROLE_CATALOG,
        users = users,
        remote_users = remote_users
    }
end

function _M.authorization(s)
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
        identity = identity_key.key(s.source, s.username),
        roles = _M.roles_for(s),
        admin = admin,
        csrf = s.csrf,
        bindings = db.query("SELECT * FROM bindings ORDER BY domain") or {},
        policies = policies,
        policy_users = policy_users,
        policy_roles = ROLE_CATALOG,
        http_methods = HTTP_METHODS,
        port_min = authz.config.port_min,
        port_max = authz.config.port_max
    }
end

function _M.applications()
    return discovery.list(authz.config)
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

function _M.change_password(s, token, data)
    if s.source ~= "local" then
        return nil, "远程用户请在 NocoBase 修改密码", 409
    end
    local old_password = tostring(data.old_password or data.oldpw or "")
    local new_password = tostring(data.new_password or data.newpw or "")
    local rows = db.query("SELECT password_hash, salt FROM users WHERE username = ?", s.username)
    local user = rows and rows[1]
    if not user or not util.verify_password(old_password, user.salt, user.password_hash) then
        return nil, "当前密码错误", 422
    end
    if #new_password < 6 then return nil, "新密码至少 6 位", 422 end
    local salt = util.random_token(16)
    local hash, hash_err = util.hash_password(new_password, salt)
    if not hash then return nil, tostring(hash_err), 500 end
    local ok, err = db.exec(
        "UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE username = ?",
        hash, salt, os.time(), s.username)
    if not ok then return db_error("修改密码失败", err) end
    db.exec([[DELETE FROM sessions WHERE username = ? AND source = 'local' AND token != ?]],
        s.username, token)
    return { message = "密码已修改" }
end

local function valid_host(domain)
    return ngx.re.match(domain,
        [[^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$]]) ~= nil
end

local function normalize_host(value)
    return tostring(value or ""):lower():gsub("%s+", ""):gsub(":%d+$", "")
end

function _M.create_application(data)
    local domain = normalize_host(data.domain)
    local port = tonumber(data.port)
    if not valid_host(domain) then return nil, "域名格式不合法", 422 end
    if not port or port < authz.config.port_min or port > authz.config.port_max then
        return nil, "端口必须在 " .. authz.config.port_min .. "-" .. authz.config.port_max, 422
    end
    local ok, err = db.exec(
        "INSERT INTO bindings(domain, port, enabled, note, created_at) VALUES(?,?,?,?,?)",
        domain, port, data.enabled == false and 0 or 1, tostring(data.note or ""), os.time())
    if not ok then return db_error("创建应用失败", err) end
    bump_rev()
    return { message = "应用已创建" }, nil, 201
end

function _M.update_application(id, data)
    local rows = db.query("SELECT id FROM bindings WHERE id = ?", id)
    if not rows or not rows[1] then return nil, "应用不存在", 404 end
    local fields, values = {}, {}
    if data.domain ~= nil then
        local domain = normalize_host(data.domain)
        if not valid_host(domain) then return nil, "域名格式不合法", 422 end
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
    if data.note ~= nil then
        local note = tostring(data.note)
        if #note > 256 then return nil, "备注不能超过 256 个字符", 422 end
        fields[#fields + 1] = "note = ?"
        values[#values + 1] = note
    end
    if data.enabled ~= nil then
        fields[#fields + 1] = "enabled = ?"
        values[#values + 1] = (data.enabled == true or data.enabled == 1) and 1 or 0
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

function _M.create_policy(data)
    local ptype = data.ptype == "g" and "g" or "p"
    local v0 = tostring(data.v0 or ""):gsub("%s+", "")
    if v0 == "" or v0:find(",", 1, true) then return nil, "主体格式不合法", 422 end
    local v1, v2
    local function validate_identity(value)
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
    if ptype == "p" then
        if v0:sub(1, 5) == "role:" then
            if not ROLE_SET[v0:sub(6)] then return nil, "策略角色不受支持", 422 end
        else
            if v0:sub(1, 5) ~= "user:" then v0 = identity_key.key("local", v0) or "" end
            if not validate_identity(v0) then return nil, "策略用户不存在或已禁用", 422 end
        end
        v1 = tostring(data.v1 or "/*"):gsub("%s+", "")
        local method_err
        v2, method_err = normalize_http_methods(data.v2)
        if not v2 then return nil, method_err, 422 end
        if v1 == "" then v1 = "/*" end
        if v1:sub(1, 1) ~= "/" or v1:find(",", 1, true) then
            return nil, "对象格式不合法", 422
        end
        if data.eft == "deny" then v2 = v2 .. "|deny" end
    else
        v1 = tostring(data.v1 or ""):gsub("%s+", "")
        if not ROLE_SET[v1:gsub("^role:", "")] then return nil, "角色仅支持 admin、staff、user、viewer", 422 end
        v1 = "role:" .. v1:gsub("^role:", "")
        if v0:sub(1, 5) ~= "user:" then v0 = identity_key.key("local", v0) or "" end
        if not validate_identity(v0) then return nil, "角色分配用户不存在或已禁用", 422 end
        v2 = "-"
    end
    local ok, err = db.exec(
        "INSERT OR IGNORE INTO policies(ptype, v0, v1, v2) VALUES(?,?,?,?)",
        ptype, v0, v1, v2)
    if not ok then return db_error("创建策略失败", err) end
    bump_rev()
    return { message = "策略已创建" }, nil, 201
end

function _M.delete_policy(id)
    local ok, err = db.exec("DELETE FROM policies WHERE id = ?", id)
    if not ok then return db_error("删除策略失败", err) end
    bump_rev()
    return { message = "策略已删除" }
end

return _M
