local cjson = require "cjson.safe"
local guard = require "resty.authz.api.guard"
local service = require "resty.authz.api.service"
local session = require "resty.authz.session"

local router = require("klib.router").new("/_api_")

local function register(method, rule, handler)
    local _, _, err = router:register(rule, handler, method)
    assert(not err, err)
end

local function body_or_error(env, req)
    local data, err = req.get_body(env)
    if not data then
        return nil, { error = { code = "invalid_body", message = err } }, 400
    end
    return data
end

local function with_body(callback)
    return function(params, env, req, current, token)
        local data, payload, status = body_or_error(env, req)
        if not data then return payload, status end
        return guard.result(callback(params, data, current, token))
    end
end

register("GET", "/authz/v1/session", guard.wrap(function(_, _, _, current)
    return { data = service.session_payload(current) }
end))

register("DELETE", "/authz/v1/session", guard.wrap(function(_, _, _, _, token)
    session.delete(token)
    session.clear_cookie()
    return { data = { message = "已退出登录" } }
end, { csrf = true }))

register("GET", "/authz/v1/users", guard.wrap(function(_, _, _, current)
    return { data = service.list_users(current) }
end, { admin = true }))

register("POST", "/authz/v1/users", guard.wrap(with_body(function(_, data)
    return service.create_user(data)
end), { admin = true, csrf = true }))

register("PATCH", "/authz/v1/users/:id", guard.wrap(with_body(function(params, data)
    return service.update_user(tonumber(params.id), data)
end), { admin = true, csrf = true }))

register("PATCH", "/authz/v1/remote-users/:provider", guard.wrap(with_body(function(params, data)
    return service.update_remote_user(params.provider, data.subject, data)
end), { admin = true, csrf = true }))

register("DELETE", "/authz/v1/remote-users/:provider", guard.wrap(with_body(function(params, data)
    return service.delete_remote_user(params.provider, data.subject)
end), { admin = true, csrf = true }))

register("DELETE", "/authz/v1/users/:id", guard.wrap(function(params)
    return guard.result(service.delete_user(tonumber(params.id)))
end, { admin = true, csrf = true }))

register("PUT", "/authz/v1/users/:id/password", guard.wrap(with_body(function(params, data)
    return service.reset_password(tonumber(params.id), data)
end), { admin = true, csrf = true }))

register("PUT", "/authz/v1/me/password", guard.wrap(with_body(function(_, data, current, token)
    return service.change_password(current, token, data)
end), { csrf = true }))

register("GET", "/authz/v1/authorization", guard.wrap(function(_, _, _, current)
    return { data = service.authorization(current) }
end, { admin = true }))

register("POST", "/authz/v1/applications", guard.wrap(with_body(function(_, data)
    return service.create_application(data)
end), { admin = true, csrf = true }))

register("PATCH", "/authz/v1/applications/:id", guard.wrap(with_body(function(params, data)
    return service.update_application(tonumber(params.id), data)
end), { admin = true, csrf = true }))

register("DELETE", "/authz/v1/applications/:id", guard.wrap(function(params)
    return guard.result(service.delete_application(tonumber(params.id)))
end, { admin = true, csrf = true }))

register("POST", "/authz/v1/policies", guard.wrap(with_body(function(_, data)
    return service.create_policy(data)
end), { admin = true, csrf = true }))

register("DELETE", "/authz/v1/policies/:id", guard.wrap(function(params)
    return guard.result(service.delete_policy(tonumber(params.id)))
end, { admin = true, csrf = true }))

local function error_handler(_, status)
    ngx.header["Content-Type"] = "application/json; charset=UTF-8"
    local message = status == 404 and "API endpoint not found" or "Internal Server Error"
    ngx.print(cjson.encode({ error = { code = "http_" .. status, message = message } }))
end

assert(not select(2, router:error_handle(404, error_handler)))
assert(not select(2, router:error_handle(500, error_handler)))

return router
