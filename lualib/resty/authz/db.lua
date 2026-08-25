-- resty.authz.db
-- SQLite (FFI) 封装: 连接管理 / schema 初始化 / 默认数据 seed
--
-- 表:
--   users     用户 (roles 逗号分隔)
--   remote_users 远程身份快照 (仅用户名和映射后的本地角色)
--   sessions  服务端会话
--   policies  casbin 策略行 p/g
--   bindings  域名 -> 目标 IP + 端口绑定
--   api_keys  应用 API Key（只保存 SHA-256 摘要）

local ffi = require "ffi"
local mlcache = require "resty.mlcache"
local util = require "resty.authz.util"

ffi.cdef[[
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef long long sqlite3_int64;
int sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
int sqlite3_close_v2(sqlite3 *db);
int sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte,
                       sqlite3_stmt **ppStmt, const char **pzTail);
int sqlite3_step(sqlite3_stmt *stmt);
int sqlite3_finalize(sqlite3_stmt *stmt);
int sqlite3_column_count(sqlite3_stmt *stmt);
const unsigned char *sqlite3_column_text(sqlite3_stmt *stmt, int iCol);
sqlite3_int64 sqlite3_column_int64(sqlite3_stmt *stmt, int iCol);
int sqlite3_column_type(sqlite3_stmt *stmt, int iCol);
const char *sqlite3_column_name(sqlite3_stmt *stmt, int iCol);
int sqlite3_bind_text(sqlite3_stmt *stmt, int idx, const char *val, int n, void (*fp)(void*));
int sqlite3_bind_int64(sqlite3_stmt *stmt, int idx, sqlite3_int64 val);
const char *sqlite3_errmsg(sqlite3 *db);
]]

local SQLITE_OK        = 0
local SQLITE_ROW       = 100
local SQLITE_DONE      = 101
local SQLITE_INTEGER   = 1
local SQLITE_NULL      = 5
-- READWRITE(0x2) | CREATE(0x4) | FULLMUTEX(0x10000)
local SQLITE_OPEN_FLAGS = 0x02 + 0x04 + 0x10000
local TRANSIENT = ffi.cast("void (*)(void*)", -1) -- SQLITE_TRANSIENT

local _M = {}
local DB_CACHE_DICT = "authz_db_cache"
local DB_REV_DICT = "authz_cache"
local db_cache = nil
local db_cache_disabled = false
local db_cache_ttl = 30
local db_cache_lru_size = 500

-- 显式加载 libsqlite3 (不在 nginx 全局符号表内; Alpine 运行包无 .so 软链)
local lib = ffi.load("libsqlite3.so.0")

local conn = nil -- 每个 worker 一条连接 (懒加载)

local function current_db_revision()
    local dict = ngx.shared[DB_REV_DICT]
    if not dict then return 0 end
    return dict:get("db_rev") or 0
end

local function bump_db_revision()
    local dict = ngx.shared[DB_REV_DICT]
    if dict then dict:incr("db_rev", 1, 0) end
end

local function cache_in_master()
    return ngx.worker and ngx.worker.in_master and ngx.worker.in_master()
end

local function get_db_cache()
    if db_cache or db_cache_disabled or cache_in_master() then
        return db_cache
    end

    local cache, err = mlcache.new("authz_db", DB_CACHE_DICT, {
        lru_size = db_cache_lru_size,
        ttl = db_cache_ttl,
        neg_ttl = 5,
    })
    if not cache then
        db_cache_disabled = true
        ngx.log(ngx.WARN, "authz: database cache disabled: ", tostring(err))
        return nil
    end
    db_cache = cache
    return db_cache
end

local function query_key(sql, params)
    local parts = { tostring(current_db_revision()), sql }
    for index, value in ipairs(params) do
        parts[#parts + 1] = tostring(index)
        parts[#parts + 1] = type(value)
        parts[#parts + 1] = tostring(value)
    end
    return ngx.encode_base64(table.concat(parts, "\0"))
end

local function errmsg(db)
    local p = lib.sqlite3_errmsg(db)
    return p ~= nil and ffi.string(p) or "unknown sqlite error"
end

function _M.open(path)
    if conn then return conn end
    local pdb = ffi.new("sqlite3*[1]")
    local rc = lib.sqlite3_open_v2(path, pdb, SQLITE_OPEN_FLAGS, nil)
    if rc ~= SQLITE_OK then
        error("sqlite open failed: " .. path .. " rc=" .. tostring(rc))
    end
    conn = pdb[0]
    -- WAL + 忙等待: 多 worker 并发访问
    _M.exec("PRAGMA journal_mode=WAL")
    _M.exec("PRAGMA busy_timeout=5000")
    return conn
end

-- 关闭当前连接 (init 阶段 master 用完即关, worker 各自重开)
function _M.close()
    if conn then
        lib.sqlite3_close_v2(conn)
        conn = nil
    end
    db_cache = nil
    db_cache_disabled = false
end

local function bind_params(stmt, params)
    for i, v in ipairs(params) do
        if type(v) == "number" then
            lib.sqlite3_bind_int64(stmt, i, v)
        elseif v == nil then
            -- bind NULL 不常用; 统一转空串处理
            lib.sqlite3_bind_text(stmt, i, "", 0, TRANSIENT)
        else
            local s = tostring(v)
            lib.sqlite3_bind_text(stmt, i, s, #s, TRANSIENT)
        end
    end
end

-- 执行写语句 (带绑定参数), 返回 true 或 nil,err
function _M.exec(sql, ...)
    if not conn then return nil, "db not opened" end
    local pstmt = ffi.new("sqlite3_stmt*[1]")
    local rc = lib.sqlite3_prepare_v2(conn, sql, #sql, pstmt, nil)
    if rc ~= SQLITE_OK then return nil, errmsg(conn) end
    local stmt = pstmt[0]
    bind_params(stmt, { ... })
    rc = lib.sqlite3_step(stmt)
    lib.sqlite3_finalize(stmt)
    if rc == SQLITE_DONE or rc == SQLITE_ROW then
        bump_db_revision()
        return true
    end
    return nil, errmsg(conn)
end

local function query_uncached(sql, params)
    if not conn then return nil, "db not opened" end
    local pstmt = ffi.new("sqlite3_stmt*[1]")
    local rc = lib.sqlite3_prepare_v2(conn, sql, #sql, pstmt, nil)
    if rc ~= SQLITE_OK then return nil, errmsg(conn) end
    local stmt = pstmt[0]
    bind_params(stmt, params)
    local rows = {}
    while lib.sqlite3_step(stmt) == SQLITE_ROW do
        local row = {}
        local column_count = lib.sqlite3_column_count(stmt)
        for col = 0, column_count - 1 do
            local t = lib.sqlite3_column_type(stmt, col)
            local name_ptr = lib.sqlite3_column_name(stmt, col)
            if t ~= SQLITE_NULL and name_ptr ~= nil then
                local name = ffi.string(name_ptr)
                if t == SQLITE_INTEGER then
                    row[name] = tonumber(lib.sqlite3_column_int64(stmt, col))
                else
                    local text_ptr = lib.sqlite3_column_text(stmt, col)
                    row[name] = text_ptr ~= nil and ffi.string(text_ptr) or ""
                end
            end
        end
        rows[#rows + 1] = row
    end
    lib.sqlite3_finalize(stmt)
    return rows
end

local function query_callback(sql, params)
    return query_uncached(sql, params)
end

-- 执行查询 (带绑定参数), 返回行数组, 每行为 {列名=值} 字典
-- INTEGER → number, 其他 → string
function _M.query(sql, ...)
    local params = { ... }
    local cache = get_db_cache()
    if not cache then return query_uncached(sql, params) end

    local rows, err = cache:get(query_key(sql, params), nil, query_callback, sql, params)
    if not err then return rows end

    ngx.log(ngx.WARN, "authz: database cache read failed: ", tostring(err))
    return query_uncached(sql, params)
end

-- ─────────────────────────────────────────────────────────────────
-- Schema 初始化 + 默认 seed (幂等)
-- opts: { path, admin_password }
-- ─────────────────────────────────────────────────────────────────
local SCHEMA = [[
CREATE TABLE IF NOT EXISTS users(
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  roles         TEXT NOT NULL DEFAULT 'user',
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  last_login_at INTEGER,
  updated_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token      TEXT PRIMARY KEY,
  username   TEXT NOT NULL,
  source     TEXT NOT NULL DEFAULT 'local',
  csrf       TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS remote_users(
  provider   TEXT NOT NULL,
  subject    TEXT NOT NULL,
  username   TEXT NOT NULL,
  roles      TEXT NOT NULL,
  remote_roles TEXT NOT NULL DEFAULT '',
  roles_overridden INTEGER NOT NULL DEFAULT 0,
  enabled    INTEGER NOT NULL DEFAULT 1,
  synced_at  INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_login_at INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(provider, subject),
  UNIQUE(provider, username)
);
CREATE TABLE IF NOT EXISTS policies(
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  ptype TEXT NOT NULL,
  v0    TEXT NOT NULL,
  v1    TEXT NOT NULL DEFAULT '*',
  v2    TEXT NOT NULL DEFAULT '*',
  UNIQUE(ptype, v0, v1, v2)
);
CREATE TABLE IF NOT EXISTS bindings(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  domain     TEXT UNIQUE NOT NULL,
  target_ip  TEXT NOT NULL DEFAULT '127.0.0.1',
  port       INTEGER NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 1,
  websocket  INTEGER NOT NULL DEFAULT 0,
  note       TEXT NOT NULL DEFAULT '',
  menu_name  TEXT NOT NULL DEFAULT '',
  upstream_host TEXT NOT NULL DEFAULT '',
  forwarded_host TEXT NOT NULL DEFAULT '',
  forwarded_proto TEXT NOT NULL DEFAULT '',
  forwarded_port INTEGER NOT NULL DEFAULT 0,
  origin_mode TEXT NOT NULL DEFAULT 'auto',
  custom_origin TEXT NOT NULL DEFAULT '',
  simulate_local INTEGER NOT NULL DEFAULT 0,
  local_ip TEXT NOT NULL DEFAULT '127.0.0.1',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT UNIQUE NOT NULL,
  token_hash TEXT UNIQUE NOT NULL,
  role       TEXT NOT NULL DEFAULT 'api',
  enabled    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
]]

function _M.init(opts)
    opts = opts or {}
    db_cache_ttl = math.max(1, tonumber(opts.db_cache_ttl) or 30)
    db_cache_lru_size = math.max(50, tonumber(opts.db_cache_lru_size) or 500)
    db_cache = nil
    db_cache_disabled = false
    local path = opts.path or opts.db_path or "/data/authz/authz.db"
    _M.open(path)

    for stmt in SCHEMA:gmatch("[^;]+") do
        stmt = stmt:match("^%s*(.-)%s*$")
        if stmt and #stmt > 0 then
            local ok, err = _M.exec(stmt)
            if not ok then error("schema init failed: " .. tostring(err)) end
        end
    end

    local function ensure_column(table_name, column_name, definition)
        local columns = _M.query("PRAGMA table_info(" .. table_name .. ")") or {}
        for _, column in ipairs(columns) do
            if column.name == column_name then return end
        end
        local ok, err = _M.exec("ALTER TABLE " .. table_name .. " ADD COLUMN " .. definition)
        if not ok then
            error(table_name .. " migration failed: " .. tostring(err))
        end
    end

    ensure_column("sessions", "source", "source TEXT NOT NULL DEFAULT 'local'")
    ensure_column("users", "last_login_at", "last_login_at INTEGER")
    ensure_column("users", "updated_at", "updated_at INTEGER NOT NULL DEFAULT 0")
    ensure_column("remote_users", "remote_roles", "remote_roles TEXT NOT NULL DEFAULT ''")
    ensure_column("remote_users", "roles_overridden",
        "roles_overridden INTEGER NOT NULL DEFAULT 0")
    ensure_column("remote_users", "created_at", "created_at INTEGER NOT NULL DEFAULT 0")
    ensure_column("remote_users", "last_login_at", "last_login_at INTEGER")
    ensure_column("remote_users", "updated_at", "updated_at INTEGER NOT NULL DEFAULT 0")
    ensure_column("bindings", "menu_name", "menu_name TEXT NOT NULL DEFAULT ''")
    ensure_column("bindings", "websocket", "websocket INTEGER NOT NULL DEFAULT 0")
    ensure_column("bindings", "target_ip", "target_ip TEXT NOT NULL DEFAULT '127.0.0.1'")
    ensure_column("bindings", "upstream_host", "upstream_host TEXT NOT NULL DEFAULT ''")
    ensure_column("bindings", "forwarded_host", "forwarded_host TEXT NOT NULL DEFAULT ''")
    ensure_column("bindings", "forwarded_proto", "forwarded_proto TEXT NOT NULL DEFAULT ''")
    ensure_column("bindings", "forwarded_port", "forwarded_port INTEGER NOT NULL DEFAULT 0")
    ensure_column("bindings", "origin_mode", "origin_mode TEXT NOT NULL DEFAULT 'auto'")
    ensure_column("bindings", "custom_origin", "custom_origin TEXT NOT NULL DEFAULT ''")
    ensure_column("bindings", "simulate_local", "simulate_local INTEGER NOT NULL DEFAULT 0")
    ensure_column("bindings", "local_ip", "local_ip TEXT NOT NULL DEFAULT '127.0.0.1'")

    -- 早期 api_keys schema 将 role CHECK 固定为 api。重建表以允许固定角色目录，保留现有 Key。
    local api_key_schema_rows = _M.query([[SELECT sql FROM sqlite_master
        WHERE type = 'table' AND name = 'api_keys']]) or {}
    local api_key_schema = tostring(api_key_schema_rows[1] and api_key_schema_rows[1].sql or "")
    if api_key_schema:match("CHECK%s*%(%s*role%s*=%s*'api'%s*%)") then
        local statements = {
            "BEGIN IMMEDIATE",
            [[CREATE TABLE api_keys_role_catalog(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'api',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )]],
            [[INSERT INTO api_keys_role_catalog
                (id, name, token_hash, role, enabled, created_at, updated_at)
                SELECT id, name, token_hash, role, enabled, created_at, updated_at FROM api_keys]],
            "DROP TABLE api_keys",
            "ALTER TABLE api_keys_role_catalog RENAME TO api_keys",
            "COMMIT",
        }
        for _, statement in ipairs(statements) do
            local migrated, migration_err = _M.exec(statement)
            if not migrated then
                _M.exec("ROLLBACK")
                error("api_keys role migration failed: " .. tostring(migration_err))
            end
        end
    end
    local ok, err = _M.exec("UPDATE remote_users SET remote_roles = roles WHERE remote_roles = ''")
    if not ok then error("remote role migration failed: " .. tostring(err)) end
    ok, err = _M.exec("UPDATE users SET updated_at = created_at WHERE updated_at = 0")
    if not ok then error("user timestamp migration failed: " .. tostring(err)) end
    ok, err = _M.exec([[UPDATE remote_users SET
        created_at = CASE WHEN created_at = 0 THEN synced_at ELSE created_at END,
        last_login_at = COALESCE(last_login_at, synced_at),
        updated_at = CASE WHEN updated_at = 0 THEN synced_at ELSE updated_at END]])
    if not ok then error("remote timestamp migration failed: " .. tostring(err)) end

    local username_unique = false
    local indexes = _M.query("PRAGMA index_list(remote_users)") or {}
    for _, index in ipairs(indexes) do
        if index["unique"] == 1 then
            local index_name = tostring(index.name or ""):gsub('"', '""')
            local columns = _M.query('PRAGMA index_info("' .. index_name .. '")') or {}
            if #columns == 1 and columns[1].name == "username" then
                username_unique = true
                break
            end
        end
    end
    if username_unique then
        local statements = {
            "BEGIN IMMEDIATE",
            [[CREATE TABLE remote_users_identity(
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                username TEXT NOT NULL,
                roles TEXT NOT NULL,
                remote_roles TEXT NOT NULL DEFAULT '',
                roles_overridden INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                synced_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_login_at INTEGER,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(provider, subject),
                UNIQUE(provider, username)
            )]],
            [[INSERT INTO remote_users_identity
                (provider, subject, username, roles, remote_roles, roles_overridden, enabled, synced_at,
                    created_at, last_login_at, updated_at)
                SELECT provider, subject, username, roles, remote_roles, roles_overridden, enabled, synced_at,
                    created_at, last_login_at, updated_at
                FROM remote_users]],
            "DROP TABLE remote_users",
            "ALTER TABLE remote_users_identity RENAME TO remote_users",
            "COMMIT",
        }
        for _, statement in ipairs(statements) do
            local ok, err = _M.exec(statement)
            if not ok then
                _M.exec("ROLLBACK")
                error("remote_users identity migration failed: " .. tostring(err))
            end
        end
    end

    ok, err = _M.exec([[DELETE FROM policies WHERE v0 NOT LIKE 'role:%' AND v0 NOT LIKE 'user:%'
        AND v0 NOT LIKE 'api-key:%'
        AND EXISTS(SELECT 1 FROM policies existing
            WHERE existing.ptype = policies.ptype
            AND existing.v0 = 'user:local:' || policies.v0
            AND existing.v1 = policies.v1 AND existing.v2 = policies.v2)]])
    if not ok then error("duplicate policy migration failed: " .. tostring(err)) end
    ok, err = _M.exec([[UPDATE policies SET v0 = 'user:local:' || v0
        WHERE v0 NOT LIKE 'role:%' AND v0 NOT LIKE 'user:%' AND v0 NOT LIKE 'api-key:%']])
    if not ok then error("policy identity migration failed: " .. tostring(err)) end

    -- 默认拒绝: 管理员拥有全权；API 服务主体可请求代理目标，但控制面仍由 API guard 限制。
    _M.exec([[INSERT OR IGNORE INTO policies(ptype, v0, v1, v2) VALUES('p','role:admin','/*','*')]])
    _M.exec([[INSERT OR IGNORE INTO policies(ptype, v0, v1, v2) VALUES('p','role:api','/*','*')]])

    -- 默认管理员 (仅在 users 为空时创建)
    local users = _M.query("SELECT COUNT(*) AS c FROM users")
    if users and users[1] and users[1].c == 0 then
        local admin_pw = opts.admin_password or "admin123"
        local salt = util.random_token(16)
        local hash = assert(util.hash_password(admin_pw, salt))
        local now = os.time()
        _M.exec(
            [[INSERT INTO users(username, password_hash, salt, roles, enabled, created_at, updated_at)
                VALUES(?,?,?,?,1,?,?)]],
            "admin", hash, salt, "admin", now, now)
        ngx.log(ngx.WARN, "authz: seeded default admin user 'admin' (change password ASAP)")
    end

    -- 清理过期会话
    _M.exec("DELETE FROM sessions WHERE expires_at < ?", os.time())
    return true
end

return _M
