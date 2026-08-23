local db = require "resty.authz.db"

local _M = {}

local ROLE_SET = {
    admin = true,
    staff = true,
    user = true,
    viewer = true,
}

local function config()
    return require("resty.authz").config
end

local function bump_rev()
    local dict = ngx.shared[config().cache_dict]
    if dict then dict:incr("rev", 1, 0) end
end

function _M.normalize_username(value)
    local username = tostring(value or ""):lower()
    if #username < 2 or #username > 254 or
        not ngx.re.match(username, [[^[a-z0-9][a-z0-9_.@+-]+$]], "jo") then
        return nil
    end
    return username
end

function _M.save(provider, subject, username, roles)
    provider = tostring(provider or ""):lower()
    subject = tostring(subject or "")
    username = _M.normalize_username(username)
    if not provider:match("^[a-z0-9_.-]+$") or subject == "" or #subject > 255 or
        not username then
        return nil, "invalid_remote_identity"
    end

    local selected = {}
    for _, role in ipairs(roles or {}) do
        role = tostring(role):lower()
        if ROLE_SET[role] then selected[role] = true end
    end
    local normalized_roles = {}
    for _, role in ipairs({ "admin", "staff", "user", "viewer" }) do
        if selected[role] then normalized_roles[#normalized_roles + 1] = role end
    end
    if #normalized_roles == 0 then return nil, "roles_unmapped" end

    local roles_csv = table.concat(normalized_roles, ",")
    local now = os.time()
    local ok, err = db.exec([[INSERT OR IGNORE INTO remote_users
        (provider, subject, username, roles, remote_roles, roles_overridden, enabled, synced_at,
            created_at, last_login_at, updated_at)
        VALUES(?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?)]],
        provider, subject, username, roles_csv, roles_csv, now, now, now, now)
    if not ok then return nil, "identity_insert_failed:" .. tostring(err) end
    ok, err = db.exec([[UPDATE remote_users SET username = ?, remote_roles = ?,
        roles = CASE WHEN roles_overridden = 1 THEN roles ELSE ? END,
        synced_at = ?, last_login_at = ?, updated_at = ?
        WHERE provider = ? AND subject = ?]],
        username, roles_csv, roles_csv, now, now, now, provider, subject)
    if not ok then return nil, "identity_update_failed:" .. tostring(err) end

    local saved = db.query([[SELECT username, roles, enabled FROM remote_users
        WHERE provider = ? AND subject = ?]], provider, subject)
    if not saved or not saved[1] or saved[1].username ~= username then
        return nil, "identity_conflict"
    end
    if saved[1].enabled ~= 1 then return nil, "identity_disabled" end

    local effective_roles = {}
    for role in saved[1].roles:gmatch("[^,%s]+") do
        effective_roles[#effective_roles + 1] = role
    end
    bump_rev()
    return {
        username = username,
        roles = effective_roles,
        source = provider,
    }
end

return _M
