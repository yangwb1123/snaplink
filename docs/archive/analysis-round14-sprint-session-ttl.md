# Sprint-Level 深度分析：Session TTL 与 Refresh Token TTL 生命周期一致性

> **选取依据**：analysis-round8.md 方向三 —— Session 默认 ~24h 过期后 Refresh Token 仍可存活 30 天，
> 导致"无活跃 session 但有活跃 refresh token"的幽灵状态。
>
> **本轮对抗核验结论：方案 A（Refresh 时检查关联 Session 存活）已交付。**
>
> 验证：`go build ./... && go vet ./... && go test -run TestRefresh ./test/...`

---

## 角色定义

```
┌────────────────────────────────────────────────────────────────┐
│  CTO：技术战略 + 风险权衡 + 长期可维护性                        │
├────────────────────────────────────────────────────────────────┤
│  产品经理：用户价值 + 竞品对比 + 优先级 + 验收标准              │
├────────────────────────────────────────────────────────────────┤
│  架构师：子系统边界 + 接口定义 + 兼容性 + 安全模型              │
├────────────────────────────────────────────────────────────────┤
│  实现工程师：代码变更 + 测试 + 部署 + 配置                      │
└────────────────────────────────────────────────────────────────┘
```

---

## 一、CTO：技术战略与风险权衡

### 1.1 背景

OAuth 2.0 生态中有两个独立的"会话"概念：

| 概念 | 默认 TTL | 作用域 |
|------|----------|--------|
| **Session**（`SessionManager`） | 24h | 跟踪用户在 OP 的登录状态；`ListByUser` 返回"当前在线用户" |
| **Refresh Token** | 30 天 | 允许客户端在 Access Token 过期后无摩擦地获取新令牌 |

这两个 TTL 之间没有任何绑定关系。SessionManager 过期后，Refresh Token 仍然可以继续旋转长达 30 天。

### 1.2 风险矩阵

| 风险场景 | 影响 | 严重性 | 发生概率 |
|----------|------|--------|----------|
| 用户登出后 refresh token 仍有效 | 用户以为已登出，但后台脚本可继续获取新 access token | **高** | **高**（默认配置） |
| 管理员吊销用户后 refresh token 仍有效 | 管理员 revoke session 后用户仍可通过 refresh 持续访问 | **高** | **中**（仅部分 admin 操作触发） |
| session 计数低估活跃用户 | `ListByUser` 不包含 session 过期后的 refresh 用户，运营误判 DAU | 中 | 高 |
| 合规要求（GDPR 删除后仍可 refresh） | 用户账户删除后 refresh token 可复活访问能力 | **高** | 低（取决于删除流程完整性） |

### 1.3 决策：方案 A vs 其他方案

| 方案 | 侵入 | 预期行为 | 向后兼容 | 推荐 |
|------|------|----------|----------|------|
| **A: Refresh 时检查 Session 存活** | 小（2 个文件，~20 行） | 预期：session 消失后 refresh 失败 | ✅ 对无 sessionMgr 部署为零行为变更 | **推荐 ✅** |
| B: Refresh 时检查 Session 存活（带 feature flag） | 中（新增 option + flag 判断） | 同 A，但可配置关闭 | ✅ 默认关闭 | 可选升级 |
| C: Session TTL = Refresh Token TTL 对齐 | 大（TTL 管理重构） | 过强：session 必须活 30 天，违背短 session 设计 | ❌ | 不推荐 |
| D: 仅审计事件 | 小（仅新增 audit event） | 可观测但不禁用 | ✅ | 安全不充分 |

**选择：方案 A** —— 最简实现，行为可预期，零配置开销。

### 1.4 安全模型

```
┌──────────┐     login      ┌──────────┐     issue      ┌──────────────┐
│  Login    │ ─────────────→ │ Session  │ ─────────────→ │ RefreshToken │
│  Handler  │   创建 session  │ (TTL=24h)│   SID=session.ID│ (TTL=30d)    │
└──────────┘                └──────────┘                └──────┬───────┘
                                                               │
                                      ┌────────────────────────┘
                                      ▼
                               ┌──────────────┐
                               │ Refresh Grant │ ◄── presented refresh_token
                               │  (方案 A)     │
                               └──────┬───────┘
                                      │
                            ┌─────────▼─────────┐
                            │ Check SID alive?  │
                            └────┬──────────┬───┘
                                 │          │
                           alive ▼          ▼ expired/not found
                         ┌──────────┐  ┌──────────────┐
                         │ issue    │  │ reject with  │
                         │ new token│  │ invalid_grant│
                         └──────────┘  └──────────────┘
```

---

## 二、产品经理：用户价值与验收标准

### 2.1 用户可见的变化

| 场景 | 变更前 | 变更后 |
|------|--------|--------|
| 用户登录后 25h 用 refresh token | ✅ 成功（session 已过期，但 refresh 仍有效） | ❌ 失败（session 已过期） |
| 用户主动登出后用 refresh token | ✅ 成功（幽灵刷新） | ❌ 失败（session 已销毁） |
| 管理员强制下线用户后 | ✅ refresh token 继续有效至 30 天期满 | ❌ 下次 refresh 即失败 |
| 无 SessionManager 部署（纯 JWT） | ✅ refresh 正常工作 | ✅ 不变（无 sessionMgr 时 check 为 no-op） |

### 2.2 验收标准

```
GIVEN  用户已登录并获得 refresh_token（含 SID）
WHEN   Session 被销毁（过期 / 主动登出 / 管理吊销）
THEN   Refresh Token 不能再获取新的 Access Token
       → 服务器返回 400 invalid_grant
       → 日志记录 "refresh denied: parent session not found or expired"
```

### 2.3 竞品对标

| 产品 | Session-Refresh 绑定 |
|------|---------------------|
| **Auth0** | Refresh Token rotation 默认不检查 session 存活；可启用 `token_lifetime_for_web` 策略 |
| **Keycloak** | Refresh Token 独立于 Session；但有 `RevokeRefreshToken` 策略可在 logout 时级联 |
| **Okta** | Refresh Token 存活期独立于 session，但支持 `refresh_token_rotation` + `refresh_token_grace_period` |
| **ory Hydra** | Refresh Token 与 session 无关（stateless JWT 模型） |
| **本实现（方案 A）** | **主动** 检查 SessionManager，session 消失后立即拒绝 refresh |

方案 A 的优势：**零配置即可获得 session 生命周期一致性**，无需运营团队额外配置策略。

---

## 三、架构师：子系统边界与接口定义

### 3.1 变更点

#### 3.1.1 `RefreshGrantDeps` 接口新增 `SessionManager()`

```go
// internal/handler/tokengrant/token_refresh.go
type RefreshGrantDeps interface {
    RefreshTokenStore() oauth.RefreshTokenStore
    RefreshGrace() RefreshGraceStore
    SessionManager() core.SessionManager    // ← 新增
    IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
    // ... 其余方法不变
}
```

`*sso.Server` 已有 `SessionMgr() core.SessionManager` 方法（`interfaces/sso/accessors.go:80`），
因此 compile-time guard `var _ tokengrant.RefreshGrantDeps = (*Server)(nil)` 自动满足新接口。

#### 3.1.2 `HandleRefreshGrant` 新增 session 存活检查

```go
// internal/handler/tokengrant/token_refresh.go
// Session liveness check (方案 A):
// 当 refresh token 携带 SID 且 SessionManager 已接线时，
// 检查 session 是否仍存活。session 不存在 / 过期 / 吊销 → 拒绝 refresh。
if info.SID != "" {
    if sm := d.SessionManager(); sm != nil {
        session, sErr := sm.Get(ctx.Request().Context(), info.SID)
        if sErr != nil || session == nil || session.IsExpired() || session.Revoked {
            d.LogErrorCtx(ctx, "refresh denied: parent session not found or expired",
                "sid", info.SID, "user", info.UserID, "client", client.ID,
                "session_err", sErr)
            ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
            return
        }
    }
}
```

### 3.2 检查时机：在 Check 链中的位置

```
Consume(token)
    ↓
ClientID 绑定检查
    ↓
DPoP key 绑定检查
    ↓
Session 存活检查 ← 新增（方案 A）
    ↓
Scope 解析（narrow/expand）
    ↓
Velocity gate
    ↓
Issue 新 access + refresh token
```

选择在此位置的原因：
1. **在 Consume 之后**：确保 token 本身有效，减少不必要的 session 查询
2. **在 ClientID / DPoP 绑定之后**：避免先泄露 session 信息
3. **在 Scope 解析之前**：符合 fail-fast 原则
4. **Oracle 安全**：所有凭据错误统一用 `invalid_grant`，不区分是"session 过期"还是"token 无效"

### 3.3 安全边界

| 边界条件 | 行为 | 理由 |
|----------|------|------|
| `sessionMgr == nil` | No-op（跳过检查） | JWT-only 部署无 session 概念 |
| `info.SID == ""` | No-op（跳过检查） | 旧 refresh token 无 SID 字段 |
| `sm.Get()` 返回 error | 视为 session 不存在 → 拒绝 | Fail-closed |
| `sm.Get()` 返回 `(nil, nil)` | 视为 session 不存在 → 拒绝 | 防御性编程 |
| session 过期（`IsExpired()==true`） | 拒绝 | 核心场景 |
| session 被吊销（`Revoked==true`） | 拒绝 | 主动登出 / 管理吊销 |

### 3.4 向后兼容

| 部署模式 | 变更前 | 变更后 | 兼容性 |
|----------|--------|--------|--------|
| 有 `SessionManager` + `RefreshTokenStore` | refresh 成功 | session 过期后 refresh 失败 | **行为变更**（有意的安全改进） |
| 只有 `RefreshTokenStore`（无 `sessionMgr`） | refresh 成功 | 不变（skip check） | ✅ 完全兼容 |
| 只有 `TokenIssuer`（stateless JWT） | 无 refresh 流程 | 不变 | ✅ 完全兼容 |
| `info.SID == ""`（旧 refresh token） | refresh 成功 | 不变（skip check） | ✅ 完全兼容 |

---

## 四、实现工程师：代码变更与测试

### 4.1 文件变更清单

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `internal/handler/tokengrant/token_refresh.go` | **修改** | `RefreshGrantDeps` 接口新增 `SessionManager()`；`HandleRefreshGrant` 新增 session 存活检查 |
| `docs/analysis-round14-sprint-session-ttl.md` | **新增** | 本文档 |

### 4.2 变更明细

#### 4.2.1 `internal/handler/tokengrant/token_refresh.go`

**`RefreshGrantDeps` 接口** — 新增一行：

```go
SessionManager() core.SessionManager
```

**`HandleRefreshGrant` 函数** — 在 DPoP 绑定检查之后、scope 解析之前新增约 18 行：

```go
if info.SID != "" {
    if sm := d.SessionManager(); sm != nil {
        session, sErr := sm.Get(ctx.Request().Context(), info.SID)
        if sErr != nil || session == nil || session.IsExpired() || session.Revoked {
            d.LogErrorCtx(ctx, "refresh denied: parent session not found or expired",
                "sid", info.SID, "user", info.UserID, "client", client.ID,
                "session_err", sErr)
            ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
            return
        }
    }
}
```

### 4.3 验证结果

```
$ go build ./...                    → ✅ PASS
$ go vet ./...                      → ✅ PASS
$ go test -run TestRefresh ./test/  → ✅ PASS (17 tests, including:
    TestSID_StableAcrossRefreshRotation, TestRefreshToken_ExpiredTokenRejected,
    TestRefreshToken_ScopeNarrowingAccepted, TestRefreshToken_ExchangeMismatchedClient, ...)
```

### 4.4 Session 生命周期验证（心智模型）

```
时间线
0h    用户登录 → 创建 Session(ID=S1) + 签发 Refresh Token(RT1) + SID=S1
       │
24h    Session 过期（ExpiresAt = T0+24h）
       │
25h    Refresh Token 旋转请求 → HandleRefreshGrant
       │  → Consume(RT1) ✅ 成功（refresh token TTL 仍是 30 天）
       │  → ClientID 绑定 ✅
       │  → DPoP ✅
       │  → Session 存活检查:
       │      → sm.Get("S1") → Session(ExpiredAt=24h, IsExpired=true)
       │      → 拒绝! 400 invalid_grant
       │      → 日志: "refresh denied: parent session not found or expired"
       ▼
用户需要重新登录获取新的 Session + Refresh Token
```

### 4.5 部署建议

| 步骤 | 操作 | 影响 |
|------|------|------|
| 1 | 合并本变更 | 代码生效 |
| 2 | 监控 `refresh denied` 日志 | 确认没有非预期拒绝（如网络抖动导致 session 查询失败） |
| 3 | 检查 `TestSID_StableAcrossRefreshRotation` 测试 | 确认 session 存活时 refresh 正常 |
| 4 | 通知用户支持团队 | 用户可能遇到"需要重新登录"场景，需准备 FAQ |

### 4.6 未来扩展方向

| 方向 | 描述 | 价值 |
|------|------|------|
| 审计事件 | 新增 `refresh_denied_session_expired` 事件类型 | 可观测性 |
| 优雅宽限期 | 允许短窗口内（如 5 分钟）的双重提交不触发拒绝 | 减少并发争用假阳性 |
| 管理 API 批量 kill | 管理员可通过 SessionManager.Delete 级联删除该 session 的所有 refresh token | 完全一致性 |
| 配置开关 | `WithRefreshSessionCheck(enabled bool)` 允许关闭此行为 | 应急回退 |

---

## 附录：关键代码路径

### A. Session TTL 常量

```go
// shared/core/consts_oauth.go
const (
    DefaultSessionDuration = 24 * time.Hour        // 24h
    DefaultRefreshTokenTTL = 30 * 24 * time.Hour   // 30d
)
```

### B. `Session` 结构

```go
// shared/core/types_auth.go
type Session struct {
    ID        string
    UserID    string
    CreatedAt time.Time
    ExpiresAt time.Time
    Revoked   bool
    // ...
}

func (s *Session) IsExpired() bool {
    return time.Since(s.ExpiresAt) > 0
}
```

### C. `SessionManager` 接口

```go
// shared/core/spi.go
type SessionManager interface {
    Create(ctx context.Context, userID string) (*Session, error)
    Get(ctx context.Context, sessionID string) (*Session, error)
    Destroy(ctx context.Context, sessionID string) error
    Refresh(ctx context.Context, sessionID string) (*Session, error)
    ListByUser(ctx context.Context, userID string) ([]*Session, error)
    ListAll(ctx context.Context) ([]*Session, error)
}
```

### D. SID 传播链

```
Login → Subject.SID = session.ID
  ↓
  │ 直接 mint:  Subject.SID → access token sid claim
  │ Auth Code:  AuthCode.SID = session.ID
  │              → IssueRefreshToken(info.SID) → RefreshToken.SID
  ▼
Refresh Rotation: info.SID 通过 RefreshToken 记录传播
  └── 方案 A: sm.Get(info.SID) 检查 session 是否存活
```
