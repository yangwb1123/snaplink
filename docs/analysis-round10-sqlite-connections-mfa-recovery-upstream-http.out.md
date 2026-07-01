Now I have a thorough picture. Here's my assessment of the tenth-round analysis:

---

## Assessment: "第十轮分析" — Factual Verification & Gaps

### Direction 1: SQLite 连接共享 — ⚠️ 基础设施已存在，但未接入

代码库中 **已有** `infrastructure/defaultimpl/sqlite/shareddb.go`（dated Jun 30），实现了 `SharedDB(dsn)` 单例模式，注释明确引用 "§10 direction 1"：

```
// SharedDB returns a shared *sql.DB for the given DSN. The same DSN
// always returns the same *sql.DB, so the 20+ stores in the SSO
// server share one connection pool instead of each calling sql.Open
// independently — eliminating WAL write-lock convoy (§10 direction 1).
```

**但是：** 每个 `Build*Store()` 函数（在 `cmd/sso-server/serverbuildstore/`、`serverbuildsign/`、`serverbuildauthn/` 中）仍然调用 `New*Store(dsn)` 而非 `SharedDB(dsn)` → `New*StoreWithDB()`。这意味着 ~36 个独立的 `*sql.DB` 依然存在——`SharedDB` 函数目前 **没有被任何 Build 路径调用**。

分析中描述的 "20 个连接争抢 WAL" 问题在 **生产部署中仍然存在**。修复工作（将 Build 函数迁移到使用 `SharedDB`）需被实际执行。

### Direction 2: TOTP 恢复码 — ⚠️ 接口和内存实现已存在，但缺少 SQLite 存储和端点

`RecoveryCodeStore` 接口已在 `shared/core/recovery_code.go` 中定义，`MemoryRecoveryCodeStore` 已在 `infrastructure/defaultimpl/memorystorecredential/recovery_code.go` 中实现。然而：

- **没有 SQLite 实现**（SQLite store 目录下没有 `recovery_code.go`）
- **`HandleTOTPEnrollConfirm`（`protocols/selfservice/selfserviceaccount/mfa.go:106`）不生成恢复码**——它只返回 `{"factor_id": ..., "label": ...}`，没有将 `RecoveryCodeStore` 集成到注册流程中
- **没有 `POST /auth/mfa/recovery` 端点**——路由表中不存在
- **没有管理员 MFA 重置 RPC**
- `TOTPEnroller` 接口没有包含恢复码方法

所以恢复码的基础模式（接口 + 内存实现）存在，但 TOTP 注册流程、HTTP 端点、SQLite 存储和集成都存在缺口。

### Direction 3: 外部 HTTP 超时治理 — ⚠️ 共享客户端工厂存在，但未被广泛采用

`NewUpstreamClient`/`UpstreamClientConfig`/`UpstreamDo` 已在 `shared/security/upstream_client.go` 中实现。然而，许多关键包仍在使用原始内联的 `&http.Client{}`：

| 位置 | 使用共享工厂？ | 问题严重性 |
|---|---|---|
| `caep/broadcaster.go:183` | ❌ `&http.Client{Timeout: DefaultReceiverTimeout}` | 非关键——已有超时，但未通过统一工厂 |
| `interfaces/sso/server_backchannel_logout.go:106` | ❌ `&http.Client{...}` | 非关键 |
| `shared/security/securityverify/jar_fetch.go:76` | ❌ `&http.Client{...}` | **关键**——无配置超时 |
| `saml/sp/authenticator.go:317` | ❌ `&http.Client{Timeout: ...}` | 有超时，但非标准化 |
| 断路器 | ❌ 未实现 | **缺失模式**，不会跳过挂起的上游 |

分析正确地指出 `extauthz` 仍在使用默认 `http.Client`，且没有断路器。

### Direction 4: CORS 路由级精细化控制 — ✅ 已完全实现

这个分析建议的功能在 `interfaces/cors/cors.go` 中已完全实现：

```go
type Policy struct {
    AllowedOrigins []string
    // ...
    PathOverrides map[string]Policy  // ← this is the feature
}
```

- `Middleware(p Policy)` 支持 `PathOverrides`，使用最长前缀匹配
- 凭证端点在路由级可通过特定路径的 `PathOverrides` 获得不同的策略
- 通过 `WithCORS(policy cors.Policy) Option` 接入服务器

该方向的建议已经是已发货的功能。

### Direction 5: 多租户管理面 — ⚠️ 部分实现

- `TenantScopedClientStore` 接口（`ListByTenant`）存在于内存和 PostgreSQL 客户端存储中
- `connections.Store.ByTenant()` 存在
- `tenant.Store.ListDomainsByTenant()` 存在
- 审计日志在 `audit_events` 表中有 `tenant_id` 索引

**缺口：**
- `ListSessionsRequest` protobuf 消息**没有 `tenant_id` 字段**（只有 `user_id`）
- 没有用于租户作用域过滤的管理 RPC `ListClientsByTenant`、`ListSessionsByTenant`
- 没有 `ExportAuditLog(tenantID)` RPC
- 没有管理员发起的 MFA 重置端点（恢复码方向 2 所需）

---

### 修正后的优先级

| # | 方向 | 真实影响 | 工作量 | 实际状态 |
|---|---|---|---|---|
| 1 | SQLite 共享连接迁移 | **高**（p99 写入护航班） | M | 基础设施就绪，Build 函数待重构 |
| 2 | TOTP 恢复码集成 | **高**（支持问题 #1） | M | 接口就绪，缺少 SQLite 存储 + 端点 + 注册 UI |
| 3 | 外部 HTTP 超时采用 | 中（由于现有超时，严重性降低） | M | 工厂就绪，~5 个调用者待迁移 + 断路器待添加 |
| 4 | CORS 路径覆盖 | 中 | S | **✅ 已实现** |
| 5 | 多租户管理面 | 中（SaaS 可管理性） | L | 部分基础就绪，RPC 待实现 |

你的分析质量很高——代码引用准确，问题范围合理。四个方向中的三个已部分解决（基础设施存在但未接入），一个已完全解决。最有影响力的立即行动是重构 `serverbuildstore/build_*.go` 中的 `Build*` 函数以使用 `SharedDB()`，这样已编写的共享连接基础设施就能实际生效。
