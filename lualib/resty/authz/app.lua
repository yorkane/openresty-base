-- resty.authz.app
-- 管理界面 + 认证入口 (/_authz/*)
--
-- 路由:
--   GET  /_authz/login            登录页
--   POST /_authz/login            登录
--   POST /_authz/logout           登出
--   GET  /_authz/                 控制台 (绑定/策略/用户/改密)
--   POST /_authz/bindings/save    域名端口绑定管理  [admin]
--   POST /_authz/policies/save    casbin 策略管理   [admin]
--   POST /_authz/users/save       用户管理          [admin]
--   POST /_authz/password         修改自己密码      [any]

local db = require "resty.authz.db"
local session = require "resty.authz.session"
local util = require "resty.authz.util"
local authz = require "resty.authz"

local _M = {}

local e = util.escape_html

-- ────────────────────────────────────────────────────────────────
-- 基础工具
-- ────────────────────────────────────────────────────────────────

local function bump_rev()
    local dict = ngx.shared[authz.config.cache_dict]
    if dict then dict:incr("rev", 1, 0) end
end

local function post_args()
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()
    if not args then return {} end
    return args
end

local function redirect(location)
    ngx.status = ngx.HTTP_MOVED_TEMPORARILY
    ngx.header["Location"] = location
    ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
end

local function deny(msg, code)
    ngx.status = code or ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say("<html><body style='font-family:sans-serif'><h2>" ..
        e(msg or "403 Forbidden") .. "</h2><p><a href='/_authz/'>返回控制台</a></p></body></html>")
    return ngx.exit(ngx.HTTP_OK)
end

-- 当前登录用户; 未登录返回 nil
local function current_session()
    local token = session.get_request_token()
    if not token then return nil end
    return session.get(token), token
end

local function user_roles(username)
    local rows = db.query("SELECT roles FROM users WHERE username = ?", username)
    if not rows or not rows[1] then return {} end
    local roles = {}
    for r in rows[1].roles:gmatch("[^,%s]+") do
        roles[#roles + 1] = r
    end
    return roles
end

local function is_admin(s)
    if not s then return false end
    for _, r in ipairs(user_roles(s.username)) do
        if r == "admin" then return true end
    end
    return false
end


-- ────────────────────────────────────────────────────────────────
-- HTML 渲染
-- ────────────────────────────────────────────────────────────────

local CSS = [[
body{font-family:-apple-system,'Segoe UI',sans-serif;margin:0;background:#f4f6f8;color:#222}
header{background:#1a2733;color:#fff;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
header a{color:#9fc3e8;text-decoration:none;margin-left:16px}
main{max-width:1080px;margin:24px auto;padding:0 16px}
h2{margin:28px 0 10px;font-size:18px;border-bottom:2px solid #dde;padding-bottom:6px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:14px}
th,td{border:1px solid #e2e6ea;padding:7px 10px;text-align:left}
th{background:#eef1f4}
form.inline{display:inline}
input,select{padding:5px 8px;border:1px solid #c5ccd3;border-radius:4px;font-size:13px}
button{padding:5px 12px;border:0;border-radius:4px;background:#2563eb;color:#fff;cursor:pointer;font-size:13px}
button.danger{background:#dc2626}
button.gray{background:#6b7280}
.msg{padding:10px 14px;border-radius:6px;margin:12px 0}
.msg.ok{background:#dcfce7;color:#14532d}.msg.err{background:#fee2e2;color:#7f1d1d}
.card{background:#fff;border:1px solid #e2e6ea;border-radius:8px;padding:16px;margin-bottom:16px}
.grid{display:flex;gap:16px;flex-wrap:wrap}.grid .card{flex:1;min-width:320px}
code{background:#eef;padding:1px 5px;border-radius:3px}
.login-box{max-width:360px;margin:80px auto;background:#fff;border-radius:10px;
 box-shadow:0 4px 20px rgba(0,0,0,.08);padding:32px}
.login-box input{width:100%;box-sizing:border-box;margin:8px 0 16px}
.login-box button{width:100%;padding:10px}
.muted{color:#888;font-size:12px}
]]

local function page(title, body, s)
    local nav
    if s then
        nav = "<span>用户: <b>" .. e(s.username) .. "</b> (" ..
            e(table.concat(user_roles(s.username), ", ")) .. ")</span>" ..
            "<nav><a href='/'>网关首页</a><form class='inline' method='post' action='/_authz/logout'>" ..
            "<input type='hidden' name='_csrf' value='" .. e(s.csrf) .. "'>" ..
            "<button class='gray' type='submit'>登出</button></form></nav>"
    else
        nav = "<nav></nav>"
    end
    return [[<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>]] .. e(title) .. [[ - Authz Gateway</title><style>]] .. CSS .. [[</style></head>
<body><header><b>OpenResty Authz Gateway</b>]] .. nav .. [[</header>
<main>]] .. body .. [[</main></body></html>]]
end

-- ────────────────────────────────────────────────────────────────
-- 登录 / 登出
-- ────────────────────────────────────────────────────────────────

local function handle_login_get()
    local s = current_session()
    if s then redirect("/_authz/") end
    local err = ngx.var.arg_err
    local err_html = err and ("<div class='msg err'>" .. e(err) .. "</div>") or ""
    local next_url = ngx.var.arg_next or "/_authz/"
    local body = [[<div class="login-box"><h2>登录</h2>]] .. err_html ..
        [[<form method="post" action="/_authz/login">
<input type="hidden" name="next" value="]] .. e(next_url) .. [[">
<label>用户名</label><input name="username" autofocus required>
<label>密码</label><input name="password" type="password" required>
<button type="submit">登录</button></form></div>]]
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say(page("登录", body))
end

local function safe_next(v)
    if v and v:sub(1, 1) == "/" and v:sub(2, 2) ~= "/" then return v end
    return "/_authz/"
end

local function handle_login_post()
    local args = post_args()
    local username = args.username or ""
    local password = args.password or ""
    local rows = db.query(
        "SELECT id, password_hash, salt, enabled FROM users WHERE username = ?", username)
    local u = rows and rows[1]
    if not u or u.enabled == 0 or not util.verify_password(password, u.salt, u.password_hash) then
        redirect("/_authz/login?err=" .. ngx.escape_uri("用户名或密码错误") ..
            "&next=" .. ngx.escape_uri(args.next or ""))
    end
    local token, terr = session.create(username)
    if not token then deny("会话创建失败: " .. tostring(terr), 500) end
    session.set_cookie(token)
    redirect(safe_next(args.next))
end

local function handle_logout_post()
    local s, token = current_session()
    if s then
        local args = post_args()
        if args._csrf == s.csrf then
            session.delete(token)
        end
    end
    session.clear_cookie()
    redirect("/_authz/login")
end

-- ────────────────────────────────────────────────────────────────
-- 控制台
-- ────────────────────────────────────────────────────────────────

local function csrf_field(s)
    return "<input type='hidden' name='_csrf' value='" .. e(s.csrf) .. "'>"
end

local function render_bindings(s, admin)
    local rows = db.query("SELECT * FROM bindings ORDER BY domain") or {}
    local h = "<h2>域名绑定 (domain → 本机端口)</h2><table><tr>" ..
        "<th>域名</th><th>端口</th><th>状态</th><th>备注</th>"
    if admin then h = h .. "<th>操作</th>" end
    h = h .. "</tr>"
    for _, b in ipairs(rows) do
        h = h .. "<tr><td><code>" .. e(b.domain) .. "</code></td><td>" .. b.port ..
            "</td><td>" .. (b.enabled == 1 and "启用" or "停用") ..
            "</td><td>" .. e(b.note) .. "</td>"
        if admin then
            h = h .. "<td><form class='inline' method='post' action='/_authz/bindings/save'>" ..
                csrf_field(s) ..
                "<input type='hidden' name='action' value='toggle'>" ..
                "<input type='hidden' name='id' value='" .. b.id .. "'>" ..
                "<button class='gray'>" .. (b.enabled == 1 and "停用" or "启用") .. "</button></form> " ..
                "<form class='inline' method='post' action='/_authz/bindings/save'>" ..
                csrf_field(s) ..
                "<input type='hidden' name='action' value='delete'>" ..
                "<input type='hidden' name='id' value='" .. b.id .. "'>" ..
                "<button class='danger'>删除</button></form></td>"
        end
        h = h .. "</tr>"
    end
    h = h .. "</table>"
    if admin then
        h = h .. [[<div class="card" style="margin-top:12px"><b>新增绑定</b>
<form method="post" action="/_authz/bindings/save">]] .. csrf_field(s) ..
[[<input type="hidden" name="action" value="create">
<input name="domain" placeholder="app.example.com" required pattern="[A-Za-z0-9.-]+">
<input name="port" type="number" min="]] .. authz.config.port_min .. [[" max="]] ..
authz.config.port_max .. [[" placeholder="3000" required>
<input name="note" placeholder="备注(可选)" size="20">
<label><input type="checkbox" name="enabled" checked> 启用</label>
<button>添加</button></form>
<p class="muted">提示: 数字前缀子域名无需配置 — <code>3000-任意域名</code> 自动代理到本机 3000 端口 (范围 ]] ..
authz.config.port_min .. "-" .. authz.config.port_max .. [[)。此处配置用于固定域名映射。</p></div>]]
    end
    return h
end

local function render_policies(s, admin)
    local rows = db.query("SELECT * FROM policies ORDER BY ptype, v0") or {}
    local h = "<h2>Casbin 策略</h2><table><tr><th>类型</th><th>v0 (主体)</th><th>v1 (对象)</th><th>v2 (动作)</th>"
    if admin then h = h .. "<th>操作</th>" end
    h = h .. "</tr>"
    for _, p in ipairs(rows) do
        h = h .. "<tr><td>" .. e(p.ptype) .. "</td><td><code>" .. e(p.v0) ..
            "</code></td><td><code>" .. e(p.v1) .. "</code></td><td><code>" .. e(p.v2) .. "</code></td>"
        if admin then
            h = h .. "<td><form class='inline' method='post' action='/_authz/policies/save'>" ..
                csrf_field(s) ..
                "<input type='hidden' name='action' value='del'>" ..
                "<input type='hidden' name='id' value='" .. p.id .. "'>" ..
                "<button class='danger'>删除</button></form></td>"
        end
        h = h .. "</tr>"
    end
    h = h .. "</table>"
    if admin then
        h = h .. [[<div class="card" style="margin-top:12px"><b>新增策略</b>
<form method="post" action="/_authz/policies/save">]] .. csrf_field(s) ..
[[<input type="hidden" name="action" value="add">
<select name="ptype"><option value="p">p (授权)</option><option value="g">g (角色分配)</option></select>
<input name="v0" placeholder="role:user / alice" size="16" required>
<input name="v1" placeholder="/* 或 /3000/api/*" size="22">
<input name="v2" placeholder="* 或 GET" size="10">
<label><select name="eft"><option value="allow">allow</option><option value="deny">deny</option></select></label>
<button>添加</button></form>
<p class="muted">对象格式: <code>/&lt;端口&gt;&lt;路径&gt;</code>, 如 <code>/3000/api/*</code>; 动作为 HTTP 方法或 <code>*</code>。</p></div>]]
    end
    return h
end

local function render_users(s, admin)
    if not admin then return "" end
    local rows = db.query("SELECT id, username, roles, enabled, created_at FROM users ORDER BY id") or {}
    local h = "<h2>用户</h2><table><tr><th>ID</th><th>用户名</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr>"
    for _, u in ipairs(rows) do
        h = h .. "<tr><td>" .. u.id .. "</td><td><b>" .. e(u.username) .. "</b></td><td>" ..
            e(u.roles) .. "</td><td>" .. (u.enabled == 1 and "正常" or "禁用") .. "</td><td>" ..
            os.date("%Y-%m-%d", u.created_at) .. "</td><td>"
        if u.username ~= "admin" then
            h = h .. "<form class='inline' method='post' action='/_authz/users/save'>" .. csrf_field(s) ..
                "<input type='hidden' name='id' value='" .. u.id .. "'>" ..
                "<input type='hidden' name='action' value='" .. (u.enabled == 1 and "disable" or "enable") .. "'>" ..
                "<button class='gray'>" .. (u.enabled == 1 and "禁用" or "启用") .. "</button></form> " ..
                "<form class='inline' method='post' action='/_authz/users/save'>" .. csrf_field(s) ..
                "<input type='hidden' name='id' value='" .. u.id .. "'>" ..
                "<input type='hidden' name='action' value='delete'>" ..
                "<button class='danger'>删除</button></form> " ..
                "<form class='inline' method='post' action='/_authz/users/save'>" .. csrf_field(s) ..
                "<input type='hidden' name='id' value='" .. u.id .. "'>" ..
                "<input type='hidden' name='action' value='resetpw'>" ..
                "<input name='newpw' type='password' placeholder='新密码' size='10' required>" ..
                "<button>重置密码</button></form> " ..
                "<form class='inline' method='post' action='/_authz/users/save'>" .. csrf_field(s) ..
                "<input type='hidden' name='id' value='" .. u.id .. "'>" ..
                "<input type='hidden' name='action' value='setroles'>" ..
                "<input name='roles' value='" .. e(u.roles) .. "' size='12'>" ..
                "<button>设角色</button></form>"
        else
            h = h .. "<span class='muted'>内置管理员</span>"
        end
        h = h .. "</td></tr>"
    end
    h = h .. [[</table><div class="card" style="margin-top:12px"><b>新增用户</b>
<form method="post" action="/_authz/users/save">]] .. csrf_field(s) ..
[[<input type="hidden" name="action" value="create">
<input name="username" placeholder="用户名" required pattern="[a-z0-9_-]{2,32}">
<input name="password" type="password" placeholder="密码(≥6位)" required minlength="6">
<input name="roles" value="user" placeholder="角色,逗号分隔" size="14">
<button>创建</button></form></div>]]
    return h
end

local function render_password_form(s)
    return [[<h2>修改我的密码</h2><div class="card" style="max-width:420px">
<form method="post" action="/_authz/password">]] .. csrf_field(s) ..
[[<label>当前密码</label><input name="oldpw" type="password" required style="width:100%"><br><br>
<label>新密码 (≥6位)</label><input name="newpw" type="password" required minlength="6" style="width:100%"><br><br>
<button>修改</button></form></div>]]
end

local function handle_dashboard()
    local s = current_session()
    if not s then
        redirect("/_authz/login?next=" .. ngx.escape_uri(ngx.var.request_uri))
    end
    local admin = is_admin(s)
    local msg, err = ngx.var.arg_msg, ngx.var.arg_err
    local banner = ""
    if msg then banner = banner .. "<div class='msg ok'>" .. e(msg) .. "</div>" end
    if err then banner = banner .. "<div class='msg err'>" .. e(err) .. "</div>" end
    local body = banner ..
        render_bindings(s, admin) ..
        render_policies(s, admin) ..
        render_users(s, admin) ..
        render_password_form(s)
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say(page("控制台", body, s))
end

-- ────────────────────────────────────────────────────────────────
-- 写操作 handlers (POST, CSRF 校验)
-- ────────────────────────────────────────────────────────────────

local function back(msg, errm)
    local q = ""
    if msg then q = "?msg=" .. ngx.escape_uri(msg) end
    if errm then q = "?err=" .. ngx.escape_uri(errm) end
    redirect("/_authz/" .. q)
end

local function require_admin(s)
    if not is_admin(s) then deny("需要管理员权限") end
end

local function valid_host(domain)
    -- PCRE: 各级标签 字母数字/连字符, 至少两段
    return ngx.re.match(domain,
        [[^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$]]) ~= nil
end

local function handle_bindings_save(s)
    require_admin(s)
    local a = post_args()
    local action = a.action
    if action == "create" then
        local domain = (a.domain or ""):lower():gsub("%s+", "")
        -- 允许带端口的 Host 输入, 去掉 :port 部分
        domain = domain:gsub(":%d+$", "")
        local port = tonumber(a.port)
        if not valid_host(domain) then back(nil, "域名格式不合法") end
        if not port or port < authz.config.port_min or port > authz.config.port_max then
            back(nil, "端口必须在 " .. authz.config.port_min .. "-" .. authz.config.port_max)
        end
        local ok, derr = db.exec(
            "INSERT INTO bindings(domain, port, enabled, note, created_at) VALUES(?,?,?,?,?)",
            domain, port, a.enabled and 1 or 0, a.note or "", os.time())
        if not ok then back(nil, "保存失败: " .. tostring(derr)) end
        bump_rev()
        back("已添加 " .. domain .. " → :" .. port)
    elseif action == "toggle" then
        db.exec("UPDATE bindings SET enabled = 1 - enabled WHERE id = ?", tonumber(a.id))
        bump_rev(); back(nil)
    elseif action == "delete" then
        db.exec("DELETE FROM bindings WHERE id = ?", tonumber(a.id))
        bump_rev(); back("已删除")
    end
    back(nil, "未知操作")
end

local function handle_policies_save(s)
    require_admin(s)
    local a = post_args()
    if a.action == "add" then
        local ptype = a.ptype == "g" and "g" or "p"
        local v0 = (a.v0 or ""):gsub("%s+", "")
        if v0 == "" then back(nil, "v0 不能为空") end
        local v1, v2
        if ptype == "p" then
            v1 = (a.v1 or ""):gsub("%s+", "")
            v2 = ((a.v2 or ""):gsub("%s+", "")):upper()
            if v1 == "" then v1 = "/*" end
            if v2 == "" then v2 = "*" end
            if v2 ~= "*" and not ngx.re.match(v2, [[^[A-Z]+$]]) then
                back(nil, "动作必须是 HTTP 方法或 *")
            end
        else
            v1 = (a.v1 or ""):gsub("%s+", "")
            if v1 == "" then back(nil, "g 规则必须指定角色") end
            v2 = "-"
        end
        local eft = a.eft == "deny" and "deny" or "allow"
        -- 表无独立 eft 列, deny 编码在 v2 尾部: "METHOD|deny"
        if ptype == "p" and eft == "deny" then v2 = v2 .. "|deny" end
        local ok, derr = db.exec(
            "INSERT OR IGNORE INTO policies(ptype, v0, v1, v2) VALUES(?,?,?,?)",
            ptype, v0, v1, v2)
        if not ok then back(nil, "保存失败: " .. tostring(derr)) end
        bump_rev(); back("策略已添加")
    elseif a.action == "del" then
        db.exec("DELETE FROM policies WHERE id = ?", tonumber(a.id))
        bump_rev(); back("策略已删除")
    end
    back(nil, "未知操作")
end

local function handle_users_save(s)
    require_admin(s)
    local a = post_args()
    local action = a.action
    local id = tonumber(a.id)
    if action == "create" then
        local username = (a.username or ""):lower():gsub("%s+", "")
        local password = a.password or ""
        if not ngx.re.match(username, [[^[a-z0-9_-]{2,32}$]]) then back(nil, "用户名格式不合法") end
        if #password < 6 then back(nil, "密码至少 6 位") end
        local roles = (a.roles or "user"):gsub("%s+", "")
        if roles == "" then roles = "user" end
        local salt = util.random_token(16)
        local hash = util.hash_password(password, salt)
        local ok, derr = db.exec(
            "INSERT INTO users(username, password_hash, salt, roles, enabled, created_at) VALUES(?,?,?,?,1,?)",
            username, hash, salt, roles, os.time())
        if not ok then back(nil, "创建失败: " .. tostring(derr)) end
        bump_rev(); back("用户 " .. username .. " 已创建")
    elseif action == "delete" then
        local rows = db.query("SELECT username FROM users WHERE id = ?", id)
        if rows and rows[1] then
            if rows[1].username == "admin" then back(nil, "不能删除内置管理员") end
            db.exec("DELETE FROM users WHERE id = ?", id)
            session.delete_all_for(rows[1].username)
            bump_rev(); back("用户已删除")
        end
    elseif action == "enable" or action == "disable" then
        db.exec("UPDATE users SET enabled = ? WHERE id = ?",
            action == "enable" and 1 or 0, id)
        bump_rev(); back(nil)
    elseif action == "resetpw" then
        local newpw = a.newpw or ""
        if #newpw < 6 then back(nil, "密码至少 6 位") end
        local salt = util.random_token(16)
        local hash = util.hash_password(newpw, salt)
        db.exec("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", hash, salt, id)
        back("密码已重置")
    elseif action == "setroles" then
        local roles = (a.roles or "user"):gsub("%s+", "")
        if roles == "" then roles = "user" end
        db.exec("UPDATE users SET roles = ? WHERE id = ?", roles, id)
        bump_rev(); back("角色已更新")
    end
    back(nil, "未知操作")
end

local function handle_password(s, token)
    local a = post_args()
    local oldpw, newpw = a.oldpw or "", a.newpw or ""
    local rows = db.query("SELECT password_hash, salt FROM users WHERE username = ?", s.username)
    local u = rows and rows[1]
    if not u or not util.verify_password(oldpw, u.salt, u.password_hash) then
        back(nil, "当前密码错误")
    end
    if #newpw < 6 then back(nil, "新密码至少 6 位") end
    local salt = util.random_token(16)
    local hash = util.hash_password(newpw, salt)
    db.exec("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
        hash, salt, s.username)
    -- 更新后使其他会话失效 (保留当前)
    db.exec("DELETE FROM sessions WHERE username = ? AND token != ?", s.username, token)
    back("密码修改成功")
end

-- ────────────────────────────────────────────────────────────────
-- 路由分发
-- ────────────────────────────────────────────────────────────────

function _M.handle()
    db.open(authz.config.db_path)

    local uri = ngx.var.uri
    local method = ngx.req.get_method()

    if uri == "/_authz" then uri = "/_authz/" end

    if uri == "/_authz/login" then
        if method == "POST" then return handle_login_post() end
        return handle_login_get()
    end

    if uri == "/_authz/logout" and method == "POST" then
        return handle_logout_post()
    end

    -- 以下路由均需登录
    local s, token = current_session()
    if not s then
        redirect("/_authz/login?next=" .. ngx.escape_uri(ngx.var.request_uri))
    end

    if uri == "/_authz/" then
        if method ~= "GET" then return deny("Method Not Allowed", 405) end
        return handle_dashboard()
    end

    -- 写操作: 统一 CSRF 校验
    if method == "POST" then
        local args_ok = false
        ngx.req.read_body()
        local args = ngx.req.get_post_args() or {}
        if args._csrf and args._csrf == s.csrf then args_ok = true end
        if not args_ok then return deny("CSRF 校验失败", 403) end

        if uri == "/_authz/bindings/save" then return handle_bindings_save(s) end
        if uri == "/_authz/policies/save" then return handle_policies_save(s) end
        if uri == "/_authz/users/save" then return handle_users_save(s) end
        if uri == "/_authz/password" then return handle_password(s, token) end
    end

    return deny("Not Found", 404)
end

return _M
