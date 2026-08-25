# Authz Gateway 核心 API（Agent 使用手册）

本文档描述稳定的 Authz Gateway v1 控制面 API，以及应用使用 API Key 请求受保护本机 HTTP 服务的方式。
API 根路径固定为 `/_api_/authz/v1`。

## 1. 通用协议

- 成功响应：`{"data": ...}`
- 失败响应：`{"error":{"code":"...","message":"..."}}`
- JSON 响应类型：`application/json; charset=UTF-8`
- JSON 修改请求必须发送 `Content-Type: application/json`
- 常用状态码：`200` 成功、`201` 已创建、`400` JSON 无效、`401` 未认证或 Key 无效、`403` 无权限或
  CSRF 失败、`404` 资源不存在、`409` 冲突、`422` 参数校验失败。

不要调用已退役的 `/_authz/api/*` 或 `/_authz/*/save` 接口。

## 2. 两种认证方式

### 2.1 管理员浏览器会话

管理员通过 `POST /_authz/login` 登录，Cookie 名为 `authz_session`。先读取 session API 中的 `csrf`，再在
所有修改请求中发送 `X-CSRF-Token`。

```bash
curl -sS -c cookie.txt -X POST "${GATEWAY}/_authz/login" \
  --data-urlencode "username=${ADMIN_USER}" \
  --data-urlencode "password=${ADMIN_PASSWORD}"

CSRF=$(curl -sS -b cookie.txt "${GATEWAY}/_api_/authz/v1/session" | jq -r '.data.csrf')
```

### 2.2 应用 API Key

应用在每次请求中发送：

```http
x-authz-key: ak_<64 个小写十六进制字符>
```

API Key 的主体是 `api-key:<id>`，固定继承内置 `role:api`。默认策略允许该角色访问所有已解析的代理
目标；管理员仍可通过 Casbin `role:api` allow/deny 策略收紧目标端口、路径或 HTTP 方法。

```bash
curl -sS -H "x-authz-key: ${AUTHZ_KEY}" \
  "https://2077-m.ws.example.com:99/api/status"
```

网关不会把 `x-authz-key` 转发到上游。上游只会收到安全身份头：

```text
X-Authz-User: <API Key 名称>
X-Authz-Source: api-key
X-Authz-Identity: api-key:<id>
```

如果请求显式携带无效或已禁用的 `x-authz-key`，网关返回 `401 invalid_api_key`，不会回退到同时携带的
浏览器 Cookie。

## 3. 权限矩阵

| 接口能力 | 普通会话 | admin 会话 | `api` Key |
|---|---:|---:|---:|
| 读取/退出自己的 session | 是 | 是 | 否 |
| 读取应用入口 | 是 | 是 | 否 |
| 新建域名与端口绑定 | 否 | 是（CSRF） | 是 |
| 修改或删除绑定 | 否 | 是（CSRF） | 否 |
| 管理用户、远程身份、密码 | 仅自己的密码 | 是（CSRF） | 否 |
| 读取/修改 Casbin 策略 | 否 | 是（修改需 CSRF） | 否 |
| 创建、修改、删除 API Key | 否 | 是（修改需 CSRF） | 否 |
| 新建角色或修改核心认证 | 否 | 否（无此 API） | 否 |
| 请求受保护的代理目标 | 按用户/角色策略 | 按 `admin` 策略 | 按 `api` 策略 |

`api` 是服务主体专用角色，不能分配给本地或远程用户，也不能通过 API 创建其他角色。

## 4. API Key 管理（仅 admin 会话）

### `GET /api-keys`

列出 Key 元数据。响应永远不包含明文 token 或 `token_hash`。

### `POST /api-keys`

创建 Key。请求需要 admin Cookie 与 CSRF。

```json
{"name":"deployment-agent"}
```

名称为 2–64 位 ASCII 字母、数字、点、下划线或连字符。角色固定为 `api`，不可指定其他角色。

创建响应中的 `token` 只出现一次：

```json
{
  "data": {
    "id": 12,
    "name": "deployment-agent",
    "role": "api",
    "enabled": 1,
    "created_at": 1787580000,
    "updated_at": 1787580000,
    "token": "<仅本次返回；立即保存到密钥管理系统>"
  }
}
```

SQLite 只保存 SHA-256 摘要，丢失明文后不能恢复，应删除旧 Key 并创建新 Key。

### `PATCH /api-keys/:id`

允许字段：

```json
{"name":"deployment-agent-2","enabled":false}
```

禁用后立即拒绝控制面和代理请求。`role` 不可修改。

### `DELETE /api-keys/:id`

删除后立即失效，不能恢复。

## 5. 应用/域名绑定 API

### `GET /applications`

会话用户读取已启用绑定与发现到的本机 HTTP 服务。返回数组中的常用字段为 `id`、`domain`、`port`、
`menu_name`、`note`、`enabled`、`websocket`；主动探测项还包含 `source`。

### `POST /applications`

admin 会话或 `api` Key 均可调用。API Key 不使用 CSRF。

```bash
curl -sS -X POST "${GATEWAY}/_api_/authz/v1/applications" \
  -H "x-authz-key: ${AUTHZ_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"domain":"code","port":2077,"menu_name":"Code Server","enabled":true}'
```

请求字段：

| 字段 | 必填 | 说明 |
|---|---:|---|
| `domain` | 是 | 推荐只填最后一级前缀，例如 `code`；也接受完整域名 |
| `port` | 是 | 本机 HTTP 端口，必须位于配置的允许范围 |
| `menu_name` | 否 | 左侧菜单显示名称，最多 128 字符 |
| `note` | 否 | 备注，最多 256 字符 |
| `enabled` | 否 | 默认 `true` |
| `websocket` | 否 | 兼容字段；当前所有已解析目标默认支持 WebSocket 升级 |

前缀会按当前实例域名生成完整入口。例如实例基域名为 `m.ws.example.com`，`domain: "code"` 保存为
`code-m.ws.example.com`。域名必须唯一，重复返回 `409`。

### `PATCH /applications/:id`

仅 admin 会话。可修改 `domain`、`port`、`menu_name`、`note`、`enabled`、`websocket`。

### `DELETE /applications/:id`

仅 admin 会话，删除绑定。

## 6. 其他核心 API

| Method | Path | 身份 | 用途 |
|---|---|---|---|
| `GET` | `/session` | 会话 | 当前身份、来源、角色、admin、CSRF 与时间信息 |
| `DELETE` | `/session` | 会话 + CSRF | 退出当前会话 |
| `GET` | `/users` | admin | 本地与远程身份列表、可分配的人类角色目录 |
| `POST` | `/users` | admin + CSRF | 创建本地用户；`username/password/roles` |
| `PATCH` | `/users/:id` | admin + CSRF | 修改本地用户 `roles` 或 `enabled` |
| `DELETE` | `/users/:id` | admin + CSRF | 删除本地用户 |
| `PUT` | `/users/:id/password` | admin + CSRF | 重置本地用户密码；`password` |
| `PUT` | `/me/password` | 本地会话 + CSRF | 修改自己的密码；`old_password/new_password` |
| `PATCH` | `/remote-users/:provider` | admin + CSRF | 按 body 中 `subject` 修改远程身份角色/启用状态 |
| `DELETE` | `/remote-users/:provider` | admin + CSRF | 按 body 中 `subject` 删除远程身份快照 |
| `GET` | `/authorization` | admin | 绑定、策略、策略主体、角色与 HTTP 方法目录 |
| `POST` | `/policies` | admin + CSRF | 新建 Casbin `p` 或人类用户的 `g` 规则 |
| `DELETE` | `/policies/:id` | admin + CSRF | 删除策略 |

策略对象格式为 `/<port><path-pattern>`，例如 `/2077/*`；动作支持标准 HTTP 方法或 `*`。`p.v0` 可为
`user:<source>:<username>` 或 `role:<role>`。`deny` 优先于 `allow`。

## 7. Agent 安全要求

- 不在日志、终端输出、任务结果或错误信息中打印 API Key。
- Key 放入进程环境变量或密钥管理系统，不提交到 `.env` 模板、Git 或普通配置文件。
- 每个应用/Agent 使用独立 Key，名称可追踪用途；停用优先于共享或复用 Key。
- 仅把 Key 发给受信任的网关 Origin；不要把 Key 放进 URL、query、Cookie 或请求 body。
- 自动化遇到 `401` 时停止并请求管理员轮换/启用 Key；不要尝试回退用户密码。
- 自动化遇到 `403` 时视为策略拒绝，不要尝试调用用户、角色、策略或核心认证接口绕过限制。
