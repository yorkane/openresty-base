-- resty.authz.api_key
-- Service API key authentication. Only SHA-256 digests are stored in SQLite.

local db = require "resty.authz.db"
local util = require "resty.authz.util"

local _M = {}

local TOKEN_PATTERN = [[^ak_[0-9a-f]{64}$]]

function _M.principal(id)
    id = tonumber(id)
    if not id or id < 1 or id ~= math.floor(id) then return nil end
    return "api-key:" .. tostring(id)
end

function _M.authenticate(token)
    if type(token) ~= "string" or #token ~= 67 then return nil end
    if not ngx.re.match(token, TOKEN_PATTERN, "jo") then return nil end
    local token_hash = util.sha256_hex(token)
    if not token_hash then return nil end
    local rows = db.query([[SELECT id, name, role FROM api_keys
        WHERE token_hash = ? AND enabled = 1]], token_hash)
    local row = rows and rows[1]
    if not row or row.role ~= "api" then return nil end
    return {
        kind = "api_key",
        id = row.id,
        name = row.name,
        username = row.name,
        source = "api-key",
        role = "api",
        roles = { "api" },
        identity = _M.principal(row.id),
    }
end

-- Returns presented, identity. A malformed or duplicate header is presented
-- but unauthenticated, so callers never fall back to a browser cookie.
function _M.authenticate_request()
    local headers = ngx.req.get_headers()
    local token = headers["x-authz-key"]
    if token == nil then return false, nil end
    if type(token) ~= "string" then return true, nil end
    return true, _M.authenticate(token)
end

return _M
