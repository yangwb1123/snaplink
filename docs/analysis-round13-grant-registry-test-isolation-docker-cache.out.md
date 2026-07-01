现在我已全面验证所有五个方向。以下是详细评估：

---

## 十三轮分析验证报告

### 方向一：Grant 类型注册表 → ❌ 已过时（代码已实现）

| 分析声称 | 实际代码状态 |
|---------|------------|
| ❌ "硬编码 switch，无法扩展自定义 Grant" | ✅ `protocols/oauth/grant_handler.go:14` 定义了 `GrantHandler` 接口 |
| ❌ "没有 GrantTypeRegistry" | ✅ `interfaces/sso/options_grants.go` 提供 `WithCustomGrant(handler)` 注册到 `s.customGrantHandlers map[string]oauth.GrantHandler` |
| ❌ "没有 GrantHandler 接口" | ✅ `oauth.GrantHandler` 接口已存在（`GrantType() string` + `Handle(ctx, client, req, dpopJKT, mtlsX5T)`） |
| ❌ "没有 WithCustomGrant 服务器选项" | ✅ `WithCustomGrant(handler oauth.GrantHandler) Option` 已实现 |
| ❌ switch 前未检查注册表 | ✅ `server_token.go:141` — `dispatchCustomGrant()` 在 switch 前先查注册表 |

**验证代码路径：**
```
protocols/oauth/grant_handler.go         ← GrantHandler 接口
interfaces/sso/options_grants.go         ← WithCustomGrant() + WithJWTBearerGrant()
interfaces/sso/server_token.go:141-147   ← dispatchCustomGrant() + checkGrantRateLimit() 先于 switch
interfaces/sso/server_token.go:485-512   ← dispatchCustomGrant + checkGrantRateLimit 实现
```

**还包括** `WithJWTBearerGrant(validator)` 用于 RFC 7523 JWT Bearer 作为内置扩展示例。

---

### 方向二：Docker 子模块缓存 → ❌ 已过时（已实现）

|<pre>```dockerfile
# 每个子模块单独缓存
COPY infrastructure/saml/go.mod infrastructure/saml/go.sum ./infrastructure/saml/
RUN go mod download ./infrastructure/saml/
COPY infrastructure/redis/go.mod infrastructure/redis/go.sum ./infrastructure/redis/
RUN go mod download ./infrastructure/redis/
# ... 12+ 子模块
```</pre>|

这正好就是当前 Dockerfile 的内容。修复中建议的每一行都已存在。

---

### 方向三：自助服务注册漏斗指标 → ⚠️ 存在缺口（宏已定义但未调用）

| 领域 | 状态 |
|-----|------|
| `Metrics` 结构体中的计数器定义 | ✅ **已实现** — `SignupStartedTotal`, `SignupVerifiedTotal`, `SignupCompletedTotal`, `PasswordResetRequestedTotal`, `PasswordResetCompletedTotal` |
| 构造函数中的注册 | ✅ **已实现** — `registerSignupFunnelMetrics(factory, m)` 在 `NewWithRegistry` 中调用 |
| Nil-safe 辅助方法 | ✅ **已实现** — `ObserveSignupStarted(outcome)`, `ObserveSignupVerified(outcome)`, `ObserveSignupCompleted(outcome)`, `ObservePasswordResetRequested(outcome)`, `ObservePasswordResetCompleted(outcome)` |
| **从 handler 中实际调用** | ❌ **从未被调用！** |

**具体缺口位置：**

1. **`protocols/selfservice/signup.go:76`** — `recordSelfRegister()` 只写审计日志，不调用 `ObserveSignupStarted`
2. **`protocols/selfservice/signup.go:224`** — 成功路径同上
3. **`protocols/selfservice/verify_email.go:97-107`** — 验证成功/失败不调用 `ObserveSignupVerified`
4. **`protocols/selfservice/password_reset.go:30`** — `recordPasswordResetRequested` 只写审计日志
5. **`protocols/selfservice/password_reset.go:156-169`** — `recordPasswordResetCompleted/Failed` 只写审计日志
6. 首次登录（`server_login.go` 或 `server_finish_login.go`）不调用 `ObserveSignupCompleted`
7. `Deps` 接口（`selfservicecore/deps.go`）不导出 `Metrics()` 方法

---

### 方向四：集成测试隔离 → ⚠️ 存在问题（需采取行动的量级减少）

**BcryptCost 全局变量：**
- 确实在 `infrastructure/defaultimpl/memorystoreidentity/client_secret.go:15` 中定义为 `var BcryptCost = bcrypt.DefaultCost`（包级可变全局变量）
- `test/main_test.go:18` — 在 `TestMain` 中设为 `MinCost`
- `platform/bootstrap/builtin/steps_test.go:25` — 也修改了它
- **没有 goroutine-safe 恢复机制**，但由于 `test/` 包中极少使用 `t.Parallel()`，目前竞态风险较低

**真实问题规模评估：**

```
test/ 目录：760+ 文件，5523 个测试，全部在 package ssotest 中
t.Parallel() 使用：仅约 8 个测试（federation + caep）
BcryptCost 竞争影响：低（串行执行）
```

**关键痛点：** `test/main_test.go` 中单一包 + `TestMain` 意味着所有测试必须串行编译 + 运行。拆分到 `test/auth/`、`test/oidc/`、`test/admin/` 等独立包可实现包级并行，将 25-40 分钟压缩到 ~10 分钟。

---

### 方向五：按 Grant 类型的速率限制 → ❌ 已过时（已实现）

| 分析声称 | 实际状态 |
|---------|---------|
| ❌ "一个速率限制器适用于所有 grant 类型" | ✅ `WithGrantTypeRateLimit(grantType, rate, burst)` 支持为每个 grant 类型配置独立的令牌桶 |
| ❌ "client_credentials 会淹没 authorization_code 桶" | ✅ 按 Grant 类型的独立桶可防止跨类型污染 |
| ❌ 分发逻辑中缺少检查 | ✅ `server_token.go:147` — `checkGrantRateLimit()` 在 switch 前执行 |

**使用的代码路径：**
```
interfaces/sso/options_grants.go        ← WithGrantTypeRateLimit()
interfaces/sso/sso_ratelimit.go         ← rateLimiterEntry 结构体
interfaces/sso/server_token.go:147-149  ← checkGrantRateLimit() 调用
interfaces/sso/server_token.go:500-512  ← 实现
```

---

## 经过验证的优先级

| # | 方向 | 工作量 | 影响 | 当前状态 |
|---|------|--------|------|---------|
| **1** | 注册漏斗指标：调用计数器 | **S** (6 个调用点 + `Deps` 接口添加 `Metrics()`) | 中（数据驱动 UX 优化） | **待实施** |
| **2** | 测试隔离：拆分包 + BcryptCost 重构 | **L** (拆分 760+ 文件到子包) | **高** (CI 25-40m → ~10m) | **待评估** |
| 3 | Grant 注册表 | 已实现 | — | ✅ **完成** |
| 4 | Docker 子模块缓存 | 已实现 | — | ✅ **完成** |
| 5 | Grant 类型速率限制 | 已实现 | — | ✅ **完成** |

---

## 方向三的实施蓝图

将注册漏斗计数器接入的步骤：

### 步骤 1：向 `selfservice.Deps` 添加 `Metrics()` 方法

**文件：** `protocols/selfservice/selfservicecore/deps.go:53`（在 `RegistrationGates()` 之后）

```go
// Metrics returns the metric collector for instrumentation.
// May return nil when no observability is wired (handler is a no-op).
Metrics() *metrics.Metrics
```

### 步骤 2：在 `signup.go` 的 `recordSelfRegister` 中添加对 `ObserveSignupStarted` 的调用

**文件：** `protocols/selfservice/signup.go`，函数 `recordSelfRegister`

```go
func recordSelfRegister(d Deps, ctx core.HandlerContext, username string, ok bool) {
    if m := d.Metrics(); m != nil {
        outcome := "success"
        if !ok {
            outcome = "failure"
        }
        m.ObserveSignupStarted(outcome)
    }
    // ... existing audit code ...
}
```

### 步骤 3：在 `verify_email.go` 的 `createVerifiedUser` 成功时调用 `ObserveSignupVerified`

在 `createVerifiedUser` 返回 `true` 之前添加对 `d.Metrics().ObserveSignupVerified("success")` 的调用；失败路径调用 `ObserveSignupVerified("failure")`。

### 步骤 4：在 `password_reset.go` 的 `recordPasswordResetRequested` 和 `recordPasswordResetCompleted` 中添加计数器

分别在两个函数中调用 `d.Metrics().ObservePasswordResetRequested(outcome)` 和 `d.Metrics().ObservePasswordResetCompleted(outcome)`。

### 步骤 5：在 `Server` 的 accessors 中实现 `Metrics()` 方法

**文件：** `interfaces/sso/server_signup.go`（添加）

```go
func (s *Server) Metrics() *metrics.Metrics {
    return s.metrics
}
```

这要求 `Server` 结构体导入 `metrics` 包（或通过现有 `Metrics` 类型包装）。

### 工作量：约 30 行代码 + 7 个调用点（S 级）
