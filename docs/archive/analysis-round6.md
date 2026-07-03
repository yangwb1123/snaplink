# 分析第 6 轮 — 用户会话硬限制 / SAML 索引膨胀 / OIDC 会话管理 / 租户功能开关 / 管理 API 不对称

> 扫描日期：2026-06-29
>
> 前五次路线：① 产品/协议全局 → ② `time.Now()`/集群/Postgres → ③ 刷新令牌并发 → ④ 安全头/KDF/跨区域 → ⑤ 会话管理/密码策略/限流/Branding
>
> 本次聚焦：之前五轮从未触及的会话资源管控、SAML 存储膨胀、OIDC 协议合规、多租户柔性、管理 API 表面一致性

---

## 方向一：缺乏每用户并发会话硬限制 — 会话积累不受控

**代码验证：**

```go
// shared/core/spi.go:140
ListByUser(ctx context.Context, userID string) ([]*Session, error)
```

`SessionManager` 支持 `ListByUser`、`RevokeSession`，session 创建路径在 `infrastructure/defaultimpl/defaulttoken/session_issuer.go`。

**但全库零命中：**
| 搜索词 | 命中数 |
|--------|--------|
| `MaxSessions` / `max_sessions` / `maxSession` | 0 |
| `session.*limit` / `limit.*session` | 0 |
| `session.*count` / `concurrent.*session` | 0 |
| `per.*user.*session` / `sessionPerUser` | 0 |

**风险场景分析：**

1. **Session 令牌泄漏** — 攻击者获取一个 session token 后可以无限次调用刷新端点创建新 session（每次 refresh 都可能签发新 session），session 数量线性增长
2. **资源耗尽** — 每个 session 存储在 SQLite 或 Redis 中，占用 store 资源。一个被攻击的用户可以积累数千个 session 条目（特别是如 Redis 有 TTL，但 SQLite 的 session 表没有自动 TTL 清理）
3. **运维盲区** — 没有告警阈值：无法在 session 数量异常时（如撞库后大量 session 创建）通知 operator

**现有基础设施：**
- `SessionManager` 已支持 `RevokeSession`（按 session ID 删除）和 `ListByUser`（查询全部）
- `POST /token/revoke-all` 可以批量删除（但只能"全杀"不能"超限淘汰"）
- 管理 gRPC API 已有 `ListSessions` 可实时查看

**建议修复：**

```go
// 在 SessionManager 创建 session 时增加上限检查
maxSessions := cfg.MaxSessionsPerUser  // 如 20
count, _ := s.ListByUser(ctx, userID)
if len(count) >= maxSessions {
    // 淘汰最旧的 session，创建新的（"滚动淘汰"模式）
    // 或返回错误："已达到最大会话数"
}
```

- `WithMaxSessionsPerUser(n int)` 配置选项
- 默认值 0 = 不限（向后兼容）
- 超限时两种策略：拒绝新 session（安全优先）或淘汰最旧 session（可用性优先）

---

## 方向二：SAML IdP session_index 表无 TTL/清理 — 持续写入从未释放

**代码验证：**

```sql
-- infrastructure/saml/idpsqlite/session_index.go:27
CREATE TABLE IF NOT EXISTS saml_session_index (
    subject TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,
    session_index TEXT NOT NULL DEFAULT '',
    ...
);
```

每次 SAML IdP 为某个 SP 签发断言时，在 `saml_session_index` 中写入一个记录。该记录在以下情况下被删除：
- SP 发起 SLO（`/saml/slo`），IdP 收到 LogoutRequest 后删除对应条目（`session_index.go:98` 读取 → 后续清理）
- IdP 发起 SLO 时 fan-out 到所有记录到的 SP

**但不存在自动清理的机制：**
- **无 TTL**：`session_index` 表没有 `expires_at` 列。记录永远存在，直到显式删除
- **无最大条目限制**：没有 `MaxEntries` 或 `maxRows` 保护
- **无后台清理**：没有 goroutine 定期清理过期/陈旧的 session 索引条目
- **无关闭 SLO 的 SP 的回收**：如果一个 SP 永久下线或迁移，其索引条目永远留在表中

**增长模型：**
`total_entries = users × SPs_per_user`。对于一个有 10 万用户、每个用户使用 5 个 SP 的组织（常见企业场景），就是 50 万行。

- `infrastructure/saml/idpsqlite/session_index.go:31-35` — 索引列是 `(subject, sp_entity_id)`，每次签发断言使用 `REPLACE` 或 `DELETE+INSERT`
- `infrastructure/saml/idp/session_index.go:98` — 仅在 SLO 时读取 + 清理
- `infrastructure/saml/sp/authenticator.go` — SP 侧完全不参与索引清理

**建议修复：**
- 添加 `expires_at` 列 + `default_value = datetime('now', '+24 hours')`
- 后台 goroutine 定期 `DELETE FROM saml_session_index WHERE expires_at < datetime('now')`
- `WithSAMLSessionIndexTTL(duration)` 配置选项，默认 24h
- 可选的 `MaxEntriesPerSubject` 硬限制（超过时淘汰最旧条目）

---

## 方向三：OIDC Session Management 1.0 的 `session_state` 完全缺失 — RP 无法实时感知 OP 会话状态

**代码验证：**

```go
// protocols/oidc/handle_end_session.go — RP-Initiated Logout 已实现
// 但 /end_session 依赖用户在 RP 侧主动触发，而非 OP 侧变更推送
```

**全库零命中**（`session_state`、`SessionState`、`sessionState`）：
| 搜索词 | 命中数 |
|--------|--------|
| `session_state` | 0 |
| `SessionState` | 0 |
| `postMessage` | 0 |
| `opbs` | 0 |
| `browser_state` | 0 |

**OIDC Session Management 1.0（OpenID 规范 §4）要求的机制：**

1. OP 在 `authorization_response` 中返回 `session_state` 参数（hash(salt + ":" + OP session ID)）
2. RP 嵌入一个**隐藏的 iframe**，指向 OP 的 `check_session_iframe` 端点（`/session/check` 或类似 URL）
3. RP 通过 `postMessage` 向该 iframe 发送 `ClientID + SessionState`
4. iframe 返回 `changed` 或 `unchanged` 状态
5. 当 OP 会话终止时，iframe 通知 RP，RP 清除本地 cookie

**缺失带来的影响：**

| 能力 | 当前状态 | 标准状态 |
|------|----------|----------|
| RP-Initiated Logout | ✅ `/end_session` | ✅ |
| Back-Channel Logout | ✅ `POST` to RP | ✅ |
| Front-Channel Logout | ✅ hidden iframes | ✅ |
| **Session Status Monitoring** | ❌ 无 `session_state` | ❌ **缺失** |
| **Check Session Iframe** | ❌ 无 `/session/check` | ❌ **缺失** |
| **postMessage 通信** | ❌ 不支持 | ❌ **缺失** |

**后果：**
- RP 无法在用户已在 OP 登出后获知（除非用户主动点击 RP 的"使用 SSO 登录"按钮）
- RP 必须靠**短生命周期的 access token** 来自发检测 session 过期（OIDC session 是 OP 侧状态，与 token 生命周期脱钩）
- 在第三方 cookie 被广泛禁用的 2026 年，iframe postMessage 是**唯一不依赖第三方 cookie 的跨域会话状态同步方案**

**建议修复：**
- 授权响应中添加 `session_state` 参数（`login.Response` 中增加 `SessionState` 字段）
- 新增 `GET /session/check` 端点（返回 HTML iframe，监听 `postMessage`）
- `postMessage` 交互：接收 `[clientID, sessionState]` 消息，返回 `changed` 或 `unchanged`
- 可选：`WithSessionCheckEnabled(enabled)` 开关

---

## 方向四：无每租户功能开关系统 — 功能在构建时编译入二进制，无法运行时按租户切换

**代码验证：**

`interfaces/sso/options.go` 中所有 `With*` 函数：这些选项都在 `sso.NewServer()` 构建时注入：
```go
sso.WithConnectionStore(...)         // B2B 企业连接（编译时）
sso.WithFederationAutoRegistration() // 联邦自动注册（编译时）
sso.WithSCIM(...)                    // SCIM 用户/组（编译时）
sso.WithClientStoreCache(...)        // 客户端缓存（编译时）
sso.WithCIBA(...)                    // CIBA grant（编译时）
```

**每个选项在 server 启动时全局绑定，所有租户共享相同的功能集。**

**缺失的能力：**

```go
// 想象中的 Per-Tenant 配置：
type TenantFeatures struct {
    SCIMEnabled           bool  // 当前：全局编译时决定
    SelfServiceEnabled    bool  // 当前：全局编译时决定
    B2BConnectionsEnabled bool  // 当前：全局编译时决定
    FederationEnabled     bool  // 当前：全局编译时决定
    MFAEnforcement        bool  // 当前：全局编译时决定
    PasswordPolicyID      string // 当前：无
}
```

**现实场景对比：**

| 场景 | 当前能力 | 需要的 |
|------|----------|--------|
| Tenant A 需要 SCIM + B2B | 两个团队都启用（或多都禁用） | 独立控制 |
| Tenant B 禁用自助密码重置 | 全局开关 | 按租户 |
| Tenant C 需要 SAML 联邦 | 联邦有/无 | 按租户 |
| 免费层 vs 企业层功能差异 | 无法区分 | 按层分级 |

**现有前端：**
- `cmd/sso-server/build_app_selfservice.go:57` — `selfServiceEnabled` 是全局的，注释写 "enable deliberately for B2C"
- `config/config.go` — 配置是全局 YAML 加载，没有 `TenantFeatures` map

**建议修复（增量，非重构）：**
- 新增 `shared/core/tenant_features.go` 定义 `TenantFeatures` 结构
- 在 `Tenant` 结构中添加 `Features map[string]bool` 字段
- 新增 `WithTenantFeatureStore(featureStore)` 选项
- 在 handler 层面注入 `tenant.HasFeature(key)` 检查（如 `s.tenantFeatures.HasFeature(tenantID, "scim")`）
- 功能点逐步从 `if s.xxx != nil` 迁移到 `if tenant.HasFeature("scim")`（功能可用 + 按租户控制）

---

## 方向五：管理 API 表面 REST vs gRPC 不对称 — session 列表 REST 端点缺失

**代码验证：**

**gRPC 端（已实现）：**
```go
// interfaces/grpcserver/grpcadmin/admin_tokens.go:70
func (s *TokenAdminService) ListSessions(ctx context.Context, in *adminv1.ListSessionsRequest) (*adminv1.ListSessionsResponse, error) {
    all, err := s.sessionMgr.ListByUser(ctx, in.UserId)
    ...
}
```
- 有 `ListSessions` 可在 gRPC 中按 `user_id` 列出全部活跃 session
- `Session` 包含 `device`、`user_agent`、`ip`、`created_at`、`expires_at` 等完整信息

**REST 端（缺失）：**

| 用户管理操作 | REST `/api/v1/admin/users/...` | gRPC `UserAdmin/TokenAdmin` |
|--------------|-------------------------------|----------------------------|
| 列出用户 consent | ✅ `GET /all/consents` | ✅ |
| 列出用户 MFA 设备 | ✅ `GET /all/mfa` | ✅ |
| 列出用户密码重置令牌 | ✅ `GET /all/password-reset-tokens` | ✅ |
| 列出用户邮箱变更令牌 | ✅ `GET /all/email-change-tokens` | ✅ |
| **列出用户 session** | ❌ **缺失** | ✅ `ListSessions` |
| 清空账户锁定 | ✅ `POST /clear-lockout` | ✅ |
| 修改密码 | ✅ `POST /password` | ✅ |

**`server_routes_admin.go` 中有以下 admin path 但无 session 相关：**
```go
PathAdminUserConsents           // ✅
PathAdminUserMFA                // ✅
PathAdminUserPasswordResetTokens // ✅
PathAdminUserEmailChangeTokens  // ✅
PathAdminAccountLockoutClear    // ✅
// PathAdminUserSessions — ❌ 不存在
```

**为什么需要：**
- Operator 在日常工作中（curl / Postman / Web UI）通过 REST API 管理用户。gRPC 需要 `grpcurl` 或专门的管理客户端二进制，增加了操作摩擦
- `TokenAdminService.ListSessions` 对应的 REST 代理（gRPC-gateway）路径是 `/api/v1/admin/sessions?user_id=X`，但没有挂接到路由上
- 会话查询是 SOC2 审计要求的常见操作——"列出 user X 的所有活跃登录"是 incident response 第一步

**建议修复：**
- 新建 `handleAdminListUserSessions` handler
- 路径：`GET /api/v1/admin/users/:user_id/sessions`
- 复用已有的 `SessionManager.ListByUser(ctx, userID)`
- 返回 session 列表（device, ip, user_agent, created_at, expires_at）

---

## 优先级排序

| 方向 | 价值 | 工作量 | 建议顺序 |
|------|------|--------|----------|
| **① 每用户 session 上限** | 中-高（资源管控 + 安全） | S | **第 1 Sprint** |
| **② SAML 索引膨胀** | 中（运维稳定性） | S | **第 1 Sprint** |
| **③ session_state** | 中-高（OIDC 协议合规） | M | 第 2 |
| **④ 租户功能开关** | 高（多租户产品力） | L（架构级） | Roadmap |
| **⑤ 管理 API 不对称** | 中（运维体验） | S | **第 1 Sprint 并行** |

**一句话：** ① 是会话侧的资源管控盲区（session 无限积累可被用于持久化攻击面）→ ② SAML `session_index` 无 TTL 是 SQLite 存储的持续写入泄漏 → ③ OIDC Session Management `session_state` 是协议合规的最后一块拼图（`postMessage` 式的 iframe 状态同步在当前浏览器第三方 cookie 禁令下是唯一方案）→ ④ 租户级功能开关是让产品从"启动时编译决定一切"进化到"运行时按租户弹性编排"的架构节点 → ⑤ REST `GET /users/:id/sessions` 是运维工具链中 gRPC 能力在 REST 侧的对应缺口。
