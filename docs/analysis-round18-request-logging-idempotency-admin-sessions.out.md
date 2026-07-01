让我提供所有方向的最终状态报告。

---

## 最终状态报告：第 18 轮分析

代码库扫描显示，**5 个方向中有 4 个已经实现**，剩下 1 个存在较小差距需要填补。

### 方向 1：请求/响应体调试日志 —— ✅ 已实现

**位置：**
- `interfaces/middleware/request_log.go` — `RequestLogger` 中间件，可选的 `logBodies` 参数
- `interfaces/sso/options_misc.go:521` — `WithRequestLogging(logBodies bool)` 选项
- `interfaces/sso/server_routes.go:367` — `buildMiddlewareChain` 中的集成

中间件记录 `method`、`path`、`query`、`status`、`duration`，可选包含 `request_body` 和 `response_body`。默认禁用。由 `buildMiddlewareChain` 包裹在最外层。

### 方向 2：幂等性密钥支持 —— ✅ 已实现

**位置：**
- `shared/core/spi.go:456` — `IdempotentCache` 接口
- `infrastructure/defaultimpl/memory_idempotent.go` — `MemoryIdempotentCache` 实现
- `interfaces/middleware/idempotency.go` — `Idempotency` 中间件 + `HandleIdempotentRequest` 辅助函数
- `interfaces/sso/options_misc.go:531` — `WithIdempotentStore(cache)` 选项
- `interfaces/sso/server_token.go:49` — `handleToken` 中的完整缓存检查
- 当存在 `Idempotency-Key` 标头时，在消耗授权码**之前**检查缓存，并在成功时缓存响应体

### 方向 3：Admin 会话生命周期管理 —— ⚠️ 缺口已填补

**已有（之前）：**
- `shared/core/admin_token.go` — `AdminTokenStore` 接口：`Record`、`List`、`Revoke`、`Touch`、`GetByID`
- `infrastructure/defaultimpl/memorystorecredential/admin_token.go` — `MemoryAdminTokenStore` 实现
- `interfaces/sso/options_misc.go:451` — `WithAdminTokenStore(store)` 选项
- `interfaces/sso/server_admin_tokens.go` — 端点：`GET /admin/tokens`、`POST /admin/logout`、`DELETE /admin/tokens/:id`

**新添加（本回合）：**
| 文件 | 添加内容 |
|------|----------|
| `interfaces/sso/options_admin.go` | `WithAdminSessionTTL(ttl)` — 新选项（独立于已超出 500 行预算的 `options_misc.go`） |
| `interfaces/sso/sso_selfservice.go` | `adminSessionTTL` 字段 |
| `interfaces/sso/accessors.go` | `AdminSessionTTL()` 和 `AdminTokenStore()` 访问器 |
| `interfaces/admin/middleware.go` | `adminTokenStore` + `sessionTTL` 字段；`SetAdminTokenStore()` + `SetAdminSessionTTL()` 方法；`enforceIdleTimeout()` 钩子（在 `HTTPMiddleware` 中身份验证/作用域检查之后调用） |
| `cmd/sso-server/build_app.go` | 将 token 存储 + TTL 连接到 admin 中间件的集成 |

**空闲超时行为：** 在 `HTTPMiddleware` 中每次管理请求后，通过 `Claims.JTI` 查找 `AdminTokenStore.GetByID()` → 如果 `time.Since(LastUsedAt) > sessionTTL`，则以 `401 session_expired` 拒绝 → 调用 `Touch()` 以更新 `LastUsedAt`。

### 方向 4：深色模式 —— ✅ 已实现

所有三个 SPA 都已具有 `@media (prefers-color-scheme: dark)` 支持，并使用 CSS 自定义属性：
- `interfaces/web/admin/style.css:128` — 完整深色主题
- `interfaces/web/login/style.css:143` — 完整深色主题  
- `interfaces/web/portal/style.css:60` — 完整深色主题

### 方向 5：Admin API 速率限制 —— ✅ 已实现

**位置：**
- `interfaces/admin/middleware.go:77` — 带有 `rateLimiter` 字段 + `SetRateLimit()` 的 `Middleware` 结构体
- `interfaces/admin/middleware.go:291` — 在 `HTTPMiddleware` 入口处进行速率限制检查
- `interfaces/sso/options_misc.go:458` — `WithAdminRateLimit(rate, burst)` 选项
- `interfaces/sso/accessors.go:115` — `AdminRateLimit()` 访问器
- `cmd/sso-server/build_app.go:172` — 集成

### 更改提交摘要

| # | 文件 | 操作 |
|---|------|----------|
| 1 | `interfaces/sso/options_admin.go` | **创建** — `WithAdminSessionTTL` 选项 |
| 2 | `interfaces/sso/sso_selfservice.go` | **编辑** — 添加 `adminSessionTTL` 字段 |
| 3 | `interfaces/sso/accessors.go` | **编辑** — 添加 `AdminSessionTTL()` 和 `AdminTokenStore()` |
| 4 | `interfaces/admin/middleware.go` | **编辑** — 添加 admin token 存储 + 会话 TTL 字段、设置方法、`enforceIdleTimeout()` 钩子 |
| 5 | `cmd/sso-server/build_app.go` | **编辑** — 将 token 存储 + TTL 连接到 admin 中间件 |
