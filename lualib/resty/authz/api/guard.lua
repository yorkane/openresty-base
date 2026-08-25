local authz = require "resty.authz"
local api_key = require "resty.authz.api_key"
local db = require "resty.authz.db"
local service = require "resty.authz.api.service"
local session = require "resty.authz.session"

local _M = {}

local function error_payload(code, message)
    return { error = { code = code, message = message } }
end

function _M.wrap(handler, options)
    options = options or {}
    return function(params, env, req)
        db.open(authz.config.db_path)
        local key_presented, current = api_key.authenticate_request()
        local token
        if key_presented then
            if not current then
                return error_payload("invalid_api_key", "API Key 无效或已禁用"), 401
            end
            if not options.api_key or current.role ~= "api" then
                return error_payload("forbidden", "API 角色无权调用此接口"), 403
            end
            return handler(params, env, req, current, nil)
        end

        token = session.get_request_token()
        current = token and session.get(token)
        if not current then
            return error_payload("unauthenticated", "请先登录"), 401
        end
        if options.admin and not service.is_admin(current) then
            return error_payload("forbidden", "需要管理员权限"), 403
        end
        if options.csrf and req.get_header("X-CSRF-Token", env) ~= current.csrf then
            return error_payload("csrf_failed", "CSRF 校验失败"), 403
        end
        return handler(params, env, req, current, token)
    end
end

function _M.result(data, err, status)
    if not data then
        return error_payload(status == 404 and "not_found" or "request_failed", err), status or 400
    end
    return { data = data }, status or 200
end

return _M
