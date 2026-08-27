-- resty.authz.relay
-- 多实例 OAuth 中继: 认证实例(中枢)与身份提供方通信, 签发 HMAC 断言令牌;
-- 业务实例验证断言后在本机创建会话并同步远程身份。

local cjson = require "cjson.safe"
local hmac_mod = require "resty.hmac"

local _M = {}

local function base64url(value)
    return (ngx.encode_base64(value):gsub("=+$", ""):gsub("+", "-"):gsub("/", "_"))
end

local function base64url_decode(value)
    if type(value) ~= "string" or #value % 4 == 1 then return nil end
    local padded = value:gsub("-", "+"):gsub("_", "/")
    padded = padded .. string.rep("=", (4 - #padded % 4) % 4)
    return ngx.decode_base64(padded)
end

local function hmac_sign(secret, message)
    local mac = hmac_mod:new(secret, hmac_mod.ALGOS.SHA256)
    if not mac then return nil end
    return mac:final(message)
end

local function constant_time_equal(a, b)
    if #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        local delta = string.byte(a, i) - string.byte(b, i)
        diff = diff + delta * delta
    end
    return diff == 0
end

function _M.encode_token(payload, secret)
    local body = cjson.encode(payload)
    if not body then return nil, "payload_encode_failed" end
    local signature = hmac_sign(secret, body)
    if not signature then return nil, "hmac_failed" end
    return base64url(body) .. "." .. base64url(signature)
end

function _M.decode_token(token, secret)
    if type(token) ~= "string" or #token > 16384 then return nil, "invalid_token" end
    local body_b64, sig_b64 = token:match("^([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)$")
    if not body_b64 or not sig_b64 then return nil, "invalid_token" end
    local body = base64url_decode(body_b64)
    local signature = base64url_decode(sig_b64)
    if not body or not signature then return nil, "invalid_token" end
    local expected = hmac_sign(secret, body)
    if not expected or not constant_time_equal(signature, expected) then
        return nil, "signature_mismatch"
    end
    local payload = cjson.decode(body)
    if type(payload) ~= "table" then return nil, "invalid_payload" end
    return payload
end

-- AUTHZ_OAUTH_RELAY_CLIENTS 格式: name|https://host/path/callback[, name2|...]
function _M.parse_clients(value)
    local clients = {}
    for entry in tostring(value or ""):gmatch("[^,]+") do
        entry = entry:gsub("^%s+", ""):gsub("%s+$", "")
        if entry ~= "" then
            local name, url = entry:match("^([^|]+)|(.+)$")
            name = name and name:gsub("^%s+", ""):gsub("%s+$", ""):lower() or ""
            url = url and url:gsub("^%s+", ""):gsub("%s+$", ""):gsub("/+$", "") or ""
            if name ~= "" and name:match("^[a-z0-9_.-]+$") and #name <= 64 and
                url:match("^https?://") and not url:find("[?#%s]") and #url <= 512 then
                clients[name] = url
            else
                return nil, "invalid relay client entry: " .. entry
            end
        end
    end
    return clients
end

return _M
