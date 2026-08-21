-- resty.authz.db
-- SQLite (FFI) 封装: 连接管理 / schema 初始化 / 默认数据 seed
--
-- 表:
--   users     用户 (roles 逗号分隔)
--   sessions  服务端会话
--   policies  casbin 策略行 p/g
--   bindings  域名 -> 本机端口 绑定

local ffi = require "ffi"
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

-- 显式加载 libsqlite3 (不在 nginx 全局符号表内; Alpine 运行包无 .so 软链)
local lib = ffi.load("libsqlite3.so.0")

local conn = nil -- 每个 worker 一条连接 (懒加载)

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
    if rc == SQLITE_DONE or rc == SQLITE_ROW then return true end
    return nil, errmsg(conn)
end

-- 执行查询 (带绑定参数), 返回行数组, 每行为 {列名=值} 字典
-- INTEGER → number, 其他 → string
function _M.query(sql, ...)
    if not conn then return nil, "db not opened" end
    local pstmt = ffi.new("sqlite3_stmt*[1]")
    local rc = lib.sqlite3_prepare_v2(conn, sql, #sql, pstmt, nil)
    if rc ~= SQLITE_OK then return nil, errmsg(conn) end
    local stmt = pstmt[0]
    bind_params(stmt, { ... })
    local rows = {}
    while lib.sqlite3_step(stmt) == SQLITE_ROW do
        local row = {}
        for col = 0, 63 do
            local t = lib.sqlite3_column_type(stmt, col)
            if t == SQLITE_NULL then break end -- 列越界返回 NULL 类型
            local name_ptr = lib.sqlite3_column_name(stmt, col)
            if name_ptr == nil then break end
            local name = ffi.string(name_ptr)
            if t == SQLITE_INTEGER then
                row[name] = tonumber(lib.sqlite3_column_int64(stmt, col))
            else
                local text_ptr = lib.sqlite3_column_text(stmt, col)
                row[name] = text_ptr ~= nil and ffi.string(text_ptr) or ""
            end
        end
        rows[#rows + 1] = row
    end
    lib.sqlite3_finalize(stmt)
    return rows
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
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token      TEXT PRIMARY KEY,
  username   TEXT NOT NULL,
  csrf       TEXT NOT NULL,
  expires_at INTEGER NOT NULL
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
  port       INTEGER NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 1,
  note       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
]]

function _M.init(opts)
    opts = opts or {}
    local path = opts.path or "/data/authz/authz.db"
    _M.open(path)

    for stmt in SCHEMA:gmatch("[^;]+") do
        stmt = stmt:match("^%s*(.-)%s*$")
        if stmt and #stmt > 0 then
            local ok, err = _M.exec(stmt)
            if not ok then error("schema init failed: " .. tostring(err)) end
        end
    end

    -- 默认策略: 管理员全权 / 普通用户全权 (可在管理页收紧)
    _M.exec([[INSERT OR IGNORE INTO policies(ptype, v0, v1, v2) VALUES('p','role:admin','/*','*')]])
    _M.exec([[INSERT OR IGNORE INTO policies(ptype, v0, v1, v2) VALUES('p','role:user','/*','*')]])

    -- 默认管理员 (仅在 users 为空时创建)
    local users = _M.query("SELECT COUNT(*) AS c FROM users")
    if users and users[1] and users[1].c == 0 then
        local admin_pw = opts.admin_password or "admin123"
        local salt = util.random_token(16)
        local hash = assert(util.hash_password(admin_pw, salt))
        _M.exec(
            "INSERT INTO users(username, password_hash, salt, roles, enabled, created_at) VALUES(?,?,?,?,1,?)",
            "admin", hash, salt, "admin", os.time())
        ngx.log(ngx.WARN, "authz: seeded default admin user 'admin' (change password ASAP)")
    end

    -- 清理过期会话
    _M.exec("DELETE FROM sessions WHERE expires_at < ?", os.time())
    return true
end

return _M
