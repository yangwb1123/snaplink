# 分析第 8 轮 — 注册邮箱验证 / Device Flow UX / TTL 生命周期不匹配 / 审计版本盲区 / 自服务审计缺口

> 扫描日期：2026-06-29
>
> 前七次路线：① 产品/协议 → ② `time.Now()`/集群 → ③ 刷新令牌并发 → ④ 安全头/KDF → ⑤ 会话管理/密码策略 → ⑥ session 硬上限/SAML/session_state → ⑦ 注册防滥用/Introspect缓存/状态端点/Conformance/Fuzz
>
> 本次聚焦：之前七轮从未触及的邮箱确认流程、设备流 UX、资源生命周期一致性、运维可观测性、自服务审计完整性

---

## 方向一：自服务注册（`/auth/register`）缺少邮箱验证步骤 — 任何邮箱均可立即创建有效账户

**代码验证：**

**邮箱变更流程（有验证）：**
```
POST /me/email/change → 发送确认链接到新旧邮箱 → POST /me/email/verify → 生效
```

**用户注册流程（无验证）：**
```
POST /auth/register → 直接创建用户 + 设置密码 → 用户立即可用
```

`interfaces/sso/options_passwd.go:80-89` 的 `WithSelfServiceSignup()` 启用注册端点，但全程零邮箱验证操作：
- `domains/authenticators/email.go` — 有 `EmailAuthenticator`（发送一次验证码），但仅在已有用户时用于认证
- `domains/authenticators/password.go:14` — 注册时只调用 `PasswordCredentialStore.Create(ctx, userID, password)`，无邮箱确认
- 邮箱唯一性检查（如果 `email` 作为 userID）由 `UserProvider.CreateOrUpdate` 完成，但**不验证邮箱可送达性**

**风险场景：**

| 场景 | 影响 |
|------|------|
| 用户注册时输错邮箱 | 无法收到密码重置邮件，账户不可恢复 |
| 攻击者用虚假邮箱注册 | 填满用户表，消耗 bcrypt hash 计算资源 |
| 用户注册他人邮箱 | 对方可发起密码重置夺取账户（邮箱独占性检查可能防住，但需检查具体实现） |
| 临时邮箱注册 | 没有域名黑名单，`@tempmail.com` 类邮箱可无限制注册 |

**现有基础设施（未在注册中使用）：**
- `EmailSender` SPI — 已存在，可用于发送确认邮件
- `CodeStore` SPI — 已存在，可用于存储验证码
- `EmailAuthenticator` — 已存在，可发送验证码

**建议修复：**
- 注册时增加可选验证步骤：`POST /auth/register` → 返回 `{"status": "verification_sent"}` → 用户输入验证码 → `POST /auth/register/verify` → 创建用户
- `WithSelfServiceSignupRequireEmailVerification(enabled)` 选项，默认关闭（向后兼容）

---

## 方向二：Device Flow 的 `/device/verify` 端点是 JSON API 而非 HTML 页面 — 用户无法通过浏览器完成授权

**代码验证：**

```go
// interfaces/sso/server_device.go:214-220
// handleDeviceVerify is the user-facing approval endpoint.
// 需要：
//   1. 用户的 Bearer Token（从 /auth/login 获取）
//   2. user_code（设备上显示的）
//   3. approve=true/false（JSON body）
// 返回：{"status":"ok"}（JSON）
```

**设备授权流程（RFC 8628）标准预期 vs 当前实现：**

| 步骤 | RFC 8628 标准 | 当前实现 |
|------|--------------|----------|
| 设备显示 user_code + verification_uri | ✅ 设备端生成 | ✅ |
| 用户使用浏览器访问 verification_uri | ✅ 预期 | ✅ URI 存在 |
| 用户看到 HTML 表单输入 user_code | ✅ 预期 | ❌ **JSON API** |
| 用户输入 user_code 后看到授权页面 | ✅ 预期 | ❌ **需要 Bearer Token** |
| 用户授权后设备 pool 收到结果 | ✅ 预期 | ✅ |

**当前实现的困境：**
1. 用户在设备上看到 `user_code: ABCD-1234, 请访问 https://sso.example.com/device/verify`
2. 用户用手机浏览器访问该 URL
3. 服务器返回的是 `401 missing_token`（JSON），而不是 HTML 表单
4. 用户一头雾水

**对比标准实现（Auth0、Azure AD、Keycloak 等）：**
```
访问 /device/verify → 显示 HTML 表单输入 user_code → 
输入 user_code → 跳转到 /auth/login → 认证 → 确认授权 → 
设备 pool 收到 token
```

**建议修复（非侵入式）：**
- `/device/verify` 在 `Accept: text/html` 时渲染 HTML 页面（而非 JSON error）
- 用户输入 user_code → POST 表单 → 302 到 `/auth/login` →
  认证后自动 redirect 回 `/device/verify/confirm?code=...` →
  确认页面显示 "验证并批准设备？" → 批准 → device_code 状态变更
- 现有 JSON API 路径保留为 `POST /device/verify`，新的 HTML 路径通过内容协商切换

---

## 方向三：Session TTL 与 Refresh Token TTL 存在数量级差异 — Session 过期后 Refresh Token 仍可长期存活

**代码验证：**

```go
// shared/core/consts_oauth.go:103-106
const (
    DefaultTokenTTL        = time.Hour       // Access Token: 1 小时
    DefaultAuthCodeTTL     = 10 * time.Minute // Auth Code: 10 分钟
    DefaultRefreshTokenTTL = 30 * 24 * time.Hour // Refresh Token: 30 天
    DefaultDeviceCodeTTL   = 10 * time.Minute // Device Code: 10 分钟
)

// Session TTL：另由 SessionTTL 配置（默认 24 小时，在 Redis/SQLite 中配置）
```

**TTL 数量级对比：**

| 资源 | 默认 TTL | 生命周期终止的行为 |
|------|----------|-------------------|
| Auth Code | 10 分钟 | 代码过期后不能再交换 token |
| Access Token | 1 小时 | 过期后不能再访问资源 |
| **Session** | **~24 小时** | 过期后 `SessionManager.ListByUser` 不再列出 |
| **Refresh Token** | **30 天** | **仍可 refresh 获取新 token** |

**生命周期不一致的影响：**

1. **Refresh Token 穿透 Session**：用户在 Day 1 登录，创建 Session TTL=24h，同时签发 Refresh Token TTL=30d。Day 2，Session 过期，SessionManager 不再认为该用户"在线"。但 Refresh Token **仍然可以使用**创建新的 Access Token。用户处于"无活跃 session 但有活跃 refresh token"的幽灵状态。

2. **Session 计数的实际意义下降**：如果运营团队使用 `ListByUser` 来统计"活跃用户数"，由于 Session 在 24h 后过期而 refresh token 存活 30 天，session 计数会**大幅低估**实际活跃用户数。

3. **安全政策的操作盲区**：组织可能设置"闲置 24h 自动登出"。用户认为自己在 Day 2 已经登出（因为前端的 idle timeout 销毁了 session），但 **refresh token 仍然有效**。后台脚本或恶意软件可以在用户不知情的情况下继续使用 refresh token。

4. **审计缺失**：没有"refresh token 在 session 过期后被使用"的审计事件。运营无法区分"正常用户在活跃 session 中刷新 token"和"幽灵 refresh token 在 session 消失后被使用"。

**建议修复：**
- 新增 `EventRefreshTokenUsedAfterSessionExpiry` 审计事件（当 Refresh Token 的创建时间 > Session 的过期时间时触发）
- 可选：`WithRefreshTokenMaxSessionAge(duration)` — refresh token 的生存期上限与 session 过期时间绑定
- 文档化：`docs/ttl-matrix.md` 记录所有 TTL 之间的关系

---

## 方向四：审计事件缺少 `server_version` 字段 — 无法追溯事件由哪个版本生成

**代码验证：**

```go
// platform/audit/auditspi/event.go:23-29
type Event struct {
    Type         EventType `json:"type"`
    Timestamp    time.Time `json:"timestamp"`
    TenantID     string    `json:"tenant_id,omitempty"`
    ActorID      string    `json:"actor_id,omitempty"`
    ClientID     string    `json:"client_id,omitempty"`
    Outcome      Outcome   `json:"outcome"`
    TraceID      string    `json:"trace_id,omitempty"`
    SpanID       string    `json:"span_id,omitempty"`
    ParentSpanID string    `json:"parent_span_id,omitempty"`
    // ... 更多字段
    // ❌ 无 ServerVersion 字段
}
```

`shared/core/buildinfo.go` 中 `ReadBuildInfo()` 已经可以获取版本（`Version: "1.2.3"`），但**审计事件中没有使用它**。

**风险场景：**

在几个月的跨度中进行安全事件调查时：

1. **版本相关的行为变化**：版本 A 有一个 bug 导致特定 grant 类型不记录审计。运营团队无法区分事件是来自版本 A（bug 版本）还是版本 B（修复版本）
2. **多版本混合部署**：滚动升级期间，部分 replica 运行版本 A，部分运行版本 B。同一用户的登录事件可能由不同版本生成，但审计日志中无法追溯到具体版本
3. **升级后的回归排查**：升级到版本 N+1 后出现异常行为。要排查"这个行为是新版本引入的还是旧版本就有的"，目前只能翻看部署时间线而不是审计日志

**其他安全系统的标准做法：**
- Syslog（RFC 5424）：有 `APP-NAME` 字段
- Kubernetes Audit：有 `requestReceivedTimestamp` + `stageTimestamp`
- AWS CloudTrail：有 `eventVersion` 字段
- OWASP AppSensor：推荐 `applicationVersion` 字段

**建议修复（小改动，高价值）：**

```go
// 在 Event 中添加一个字段（内省，不引入模块依赖）
type Event struct {
    // ... 现有字段
    ServerVersion string `json:"server_version,omitempty"` // 新增
}

// 在 Recorder.Record 中自动填充：
e.ServerVersion = core.ReadBuildInfo().Version
```

这种方式：
- `ReadBuildInfo()` 在构建时嵌入版本字符串（来自 `-ldflags` 或 Go 1.24+ 的 `debug.ReadBuildInfo`）
- 零运行时开销（字符串赋值）
- 对已存在的所有事件类型零侵入（自动填充）
- 新增 `query_by_version` 不增加复杂度

---

## 方向五：自服务密码修改和 MFA 删除缺少审计事件 — 用户操作无迹可寻

**代码验证：**

**完整的审计事件类型列表（`platform/audit/auditspi/event_types*.go`）：**

| 操作 | admin 事件 | 用户自服务事件 |
|------|-----------|---------------|
| 密码重置 | ✅ `admin_password_reset` | ✅ `password_reset_completed`（通过忘记密码流程） |
| **密码修改** | — | ❌ **无 `password_changed`** |
| MFA 添加 | — | ✅ `mfa_totp_enrolled`、`webauthn_registered` |
| **MFA 删除** | ✅ `admin_mfa_factor_removed` | ❌ **无 `mfa_factor_removed`** |
| **Passkey 删除** | — | ❌ **无 `webauthn_removed`** |
| Consent 撤销 | ✅ `admin_consent_revoked` | ✅ `consent_revoked` |

**具体 Gap 分析：**

1. **`POST /me/password`** — 用户修改密码时，`handlePasswordChange`（在哪？`server_signup.go`? `options_passwd.go`?）调用 `UserProvider.UpdatePassword` 后，**没有发出任何审计事件**。如果事后发现异常登录，无法判断是"用户自己改密码"还是"攻击者利用 XSS 改密码"。

2. **`DELETE /me/mfa/{id}`** — 用户删除 MFA 因子（如移除 TOTP 绑定）。`handleMFAFactorRemove` 调用 `MFAProvider.RemoveFactor` 后，**没有发出审计事件**。删除 MFA 是高风险操作（降低账户安全性），但操作无迹可寻。

3. **`DELETE /me/mfa/webauthn/{credential_id}`** — 用户删除 passkey。没有 `webauthn_removed` 事件。

**对比：** `admin_mfa_factor_removed` 事件已经实现了（`platform/audit/event_types_admin.go:18`），但它的触发行是由管理员操作触发的。用户自己删除时，同样应该产生事件。

**关于事件类型注册的代码验证：**

```bash
$ grep "password_changed\|mfa_removed\|mfa_deleted\|webauthn_removed\|webauthn_deleted\|factor_removed" platform/audit/auditspi/event_types*.go
# 零命中 — 这些事件类型不存在
```

**建议修复：**
- 新增事件类型：
  - `EventPasswordChanged EventType = "password_changed"`
  - `EventFactorRemoved   EventType = "factor_removed"`  (通用 MFA 因子删除)
  - `EventWebAuthnRemoved EventType = "webauthn_removed"`
- 在 `handlePasswordChange`、`handleMFAFactorRemove`、WebAuthn 凭据删除 handler 中调用 `recordAuditEvent`
- 反向兼容：新增的事件类型不影响已存储的事件，只影响新写入

---

## 优先级排序

| 方向 | 价值 | 工作量 | 建议顺序 |
|------|------|--------|----------|
| **① 注册邮箱验证** | 中-高（防虚假账户、账户恢复可行性） | M | **第 1 Sprint** |
| **② Device Flow HTML 页面** | 中（产品 UX 缺口） | M | 第 2 |
| **③ TTL 生命周期一致性** | 中-高（安全政策有效性） | S（审计事件 + 文档） | **第 1 Sprint** |
| **④ Server version in audit** | 中-高（incident response 盲区） | S（一行代码） | **第 1 Sprint 并行** |
| **⑤ 自服务审计事件** | 中（安全合规要求） | S | **第 1 Sprint 并行** |

**一句话：** ① 邮箱变更流程（`/me/email/change + verify`）有完整的两步验证，而注册流程（`/auth/register`）直接创建用户——同一产品逻辑的自相矛盾 → ② Device Flow 无法直接在浏览器中使用，违背了 RFC 8628 的设计初衷（用户用手机浏览器授权设备） → ③ Session TTL（~24h）与 Refresh Token TTL（30天）的数量级差异导致"无活跃 session 但 refresh token 仍存活"的幽灵状态 → ④ 审计日志不记录生成事件的服务器版本——几个月后的安全事件调查中将无法区分哪个版本产生了哪些事件 → ⑤ 管理员有 `admin_mfa_factor_removed` 审计事件，用户自己删除 MFA 因子时却无事件——高风险操作（移除安全措施）在用户侧无跟踪。
