# Sprint-Level 深度规划：自助注册邮箱验证（Signup Email Verification）

> **选取依据**：第 8 轮方向一。代码审查确认此功能完全不存在（零 `EmailVerificationStore`、零验证路径）。
> 邮箱更改（`/me/email/change`）已有完整的验证流程可作为架构模板，但注册流程（`POST /auth/register`）直接创建用户，无任何邮箱确认步骤。

---

## 角色定义

本文档包含面向四种角色的独立内容，每节开头标注受众。

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

自助注册邮箱验证是 OIDC 登录产品的**基础信任机制**。无验证的注册意味着:

| 风险 | 严重性 | 发生场景 |
|------|--------|----------|
| 虚假账户工厂 | **高** | 攻击者可批量注册未验证账户，用于后续的密码喷洒、评论/API 滥用 |
| 邮箱占用攻击 | **中** | 攻击者用他人邮箱注册，受害者永远无法用该邮箱注册（409 已占用） |
| 无密码找回路径 | **中** | 忘记密码需要通过邮箱重置，未验证邮箱的用户无法找回 |
| 无 `email_verified` 声明 | **中** | OIDC 用户信息缺少 `email_verified` 布尔值——依赖此声明的 RP 无法信任 email claim |
| 合规风险 | **中** | GDPR/CCPA 要求合理的身份验证；「无验证注册」在某些监管框架中被视为不充分 |

### 1.2 代码审查确认的事实

深入扫描 11 轮后的代码库，对注册邮箱维度的发现：

```
协议层发现：
├── shared/core/email_change.go          — EmailChangeStore 接口（Issue/Consume）✅ 存在
├── shared/spi/email_change.go           — EmailChangeSender SPI ✅ 存在
├── shared/core/types.go                 — User.Attributes（存储 email_verified）✅ 存在
├── protocols/oidc/oidcsupport/userinfo.go:115 — 读取 email_verified ✅ 存在
├── protocols/selfservice/email_change.go     — 邮箱更改两段验证流程 ✅ 存在
│
├── shared/core/email_verification.go    — ❌ 不存在（需新建）
├── shared/spi/email_verification.go     — ❌ 不存在（需新建）
├── protocols/selfservice/signup.go      — 注册流程（无验证步骤）✅ 存在但需增强
│
└── 关键发现：email_verified 在 User.Attributes 中只读不写！
    protocols/selfservice/email_change.go — 邮箱更改验证成功后不设置 email_verified = "true"
    userinfo 的 email_verified 返回值永远为 false 或缺失
    → 这是邮箱更改流程本身的 bug，独立于此功能
```

### 1.3 技术决策树

```
邮箱验证策略选项
│
├── A) 强制验证（recommended for prod）
│     注册 → 创建 pending 用户 → 发送验证邮件 → 验证后激活
│     优点：完整信任链
│     缺点：用户体验多一步，注册转化率下降 10-30%
│
├── B) 可选验证（recommended for dev/SaaS）
│     注册 → 直接创建已激活用户 → 发送可选验证邮件
│     仅标志 email_verified（不阻塞登录）
│     优点：转化率最高
│     缺点：上表所有风险仍存在（只是加了标记）
│
├── C) 分阶段（recommended launch strategy）
│     初始：可选验证（模式 B）+ clear UI marker
│     后续：管理员可配置为强制验证（模式 A）
│     优点：产品团队根据数据决定切换时机
│
└── D) 延迟验证（recommended for migration）
     注册 → 创建已激活用户 → 发送验证邮件
     但部分功能（密码重置、敏感操作）需要已验证邮箱
     优点：功能分步解锁的平滑体验
```

**我的推荐：模式 C（分阶段）**

理由：
1. 当前 Signup 流程已有 `signupEnabled` 开关，加上 `signupRequireVerification` 是自然扩展
2. 可重用现有的 `EmailChangeStore` + `EmailChangeSender` 架构（新接口，相同模式）
3. 不影响现有用户（存量用户保持其 `email_verified` 状态）
4. 为未来的 CAPTCHA 集成（Round 7 方向一）留下组合空间

### 1.4 长期架构影响

| 维度 | 影响 | 评分 |
|------|------|------|
| `core/` 包增长 | 新增 `email_verification.go` ~60 行（与 `email_change.go` 并行） | 🟢 可接受 |
| `spi/` 包增长 | 新增 `email_verification.go` ~10 行接口 | 🟢 可接受 |
| `selfservice/signup.go` | 从 83 行 → ~130 行（分支逻辑） | 🟢 < 500 线 |
| `Server` struct | 新增 `emailVerificationStore` + `emailVerificationSender` + `signupRequireVerification` 三个字段 | 🟢 |
| `Deps` 接口 | 新增 3 个方法（`EmailVerificationStore`, `EmailVerificationSender`, `SignupRequiresVerification`） | 🟢 |
| 配置 | 新增 `self_service.registration.require_verification: false` 默认值 | 🟢 |
| OIDC 发现 | 可选的 `email_verification_endpoint` 广告 | 🟡 新增但非必需 |
| 审计 | 新增 2 个事件类型（`email_verification_sent`, `email_verification_completed`） | 🟢 |

**不可逆决策警告：** 一旦用户以未验证状态注册，后续改为强制验证时，存量未验证用户需要处理策略（grace period 邮件提醒 vs 自动锁定向未验证用户）。建议选择模式 C（可选）作为默认，为将来切换强制保留路径。

---

## 二、产品经理：用户价值与验收标准

### 2.1 竞品对比

| 产品 | 注册邮箱验证 | UX 模式 |
|------|-------------|---------|
| Auth0 | ✅ 默认开启（redirect 到 hosted login page） | 创建 → 可选 — 已验证邮箱才有 password reset |
| Okta | ✅ 强制（注册后发送验证链接） | 创建 → 验证 → 激活 |
| Keycloak | ✅ 可配置 | 可选/强制/已验证邮箱才允许登录 |
| Firebase Auth | ✅ 默认验证（verify email action code） | 创建 → 跳转 → 验证 |
| **snaplink/sso** | ❌ 当前无验证 | 直接创建，无验证步骤 |
| Cognito | ✅ 可配置（email/phone） | 创建 → 验证码 → 激活 |

### 2.2 用户旅程

**当前流程（无验证）：**

```
用户打开注册页面
→ 输入用户名 + 密码 + 邮箱（可选）
→ POST /auth/register
→ 201 {status: "created"}
→ 立即可以登录
→ 邮箱未验证（且永远无法验证）
```

**目标流程（验证可选，默认 off，迁移友好）：**

```
WITH require_verification: false（默认）:
→ 用户注册 → 创建 → 201 "created" + email_verified = false
→ 可选：发送验证邮件（/auth/register?send_verification=true）
→ 用户可立即登录（体验不变）

WITH require_verification: true（新增）:
→ 用户注册 → 创建（标记 pending_verification） → 201 "pending"
→ 发送验证邮件到邮箱
→ 用户点击验证链接 → GET /auth/verify-email?token=xxx
→ 状态改为已验证 + email_verified = true
→ 用户可登录
→ 未验证用户尝试登录 → 403 email_not_verified
```

### 2.3 验收标准

```
=== Acceptance Criteria (P0: MVP, require_verification: false mode) ===

  POST /auth/register
    [AC-1] with email → creates user + email is stored
    [AC-2] sets Attributes["email_verified"] = "true" only when
           email was provided AND require_verification is false
           (short-circuit: no verification needed → trust provided email)
    [AC-3] with email + ?send_verification=true → sends verification
           email AND creates user immediately (non-blocking)
    [AC-4] no email → creates user without email_verified attribute
           (compatible with existing behavior)
    [AC-5] duplicate username → 409 (existing behavior preserved)
    [AC-6] no CAPTCHA yet → no change (Round 7 future work)

=== Acceptance Criteria (P1: require_verification: true mode) ===

  POST /auth/register
    [AC-7] with email → HTTP 201 "pending" + EmailVerificationToken issued
           + token delivered to email address
    [AC-8] user NOT created in UserProvider yet (no orphan accounts)
    [AC-9] no email → HTTP 400 (email required when verification on)

  POST /auth/verify-email  (new endpoint)
    [AC-10] valid token → user created in UserProvider + email set +
            email_verified = "true" → HTTP 200 {status: "verified"}
    [AC-11] expired token → HTTP 400 verification_invalid + token deleted
    [AC-12] consumed token → HTTP 400 verification_invalid (single-use)
    [AC-13] unknown token → HTTP 400 verification_invalid (oracle-safe)
    [AC-14] mismatched email domain → rate-limit (anti-spray)

  POST /auth/login (when require_verification: true)
    [AC-15] unverified user → HTTP 403 email_not_verified
            (distinct from 400 invalid_grant — tells frontend to show
            "please check your email" instead of "wrong password")
    [AC-16] verified user → normal login flow (no change)

=== Acceptance Criteria (P2: Admin & Observability) ===

  Admin API
    [AC-17] GET /admin/users/:id shows email_verified status
    [AC-18] Admin can resend verification email
    [AC-19] Admin can manually mark email as verified (helpdesk)

  Audit
    [AC-20] New EventEmailVerificationSent audit event
    [AC-21] New EventEmailVerified audit event
    [AC-22] Failed verification attempts logged (anti-abuse visibility)

  Metrics
    [AC-23] Counter: signup_with_email_total
    [AC-24] Counter: email_verification_sent_total
    [AC-25] Counter: email_verification_completed_total{outcome=success/failure}
```

### 2.4 非目标（明确排除在此 Sprint）

| 功能 | 理由 |
|------|------|
| CAPTCHA 集成 | 独立功能（Round 7），邮箱验证先上线 |
| per-email 速率限制 | 依赖标准中间件，后续增强 |
| 验证邮件模板定制 | store `PKCE` 后在后续 Sprint 添加 |
| 短信验证 | OIDC 核心规范不要求 phone_verified 声明 |
| WebAuthn 注册验证 | 独立的 passkey 注册流程 |

---

## 三、架构师：子系统边界与接口定义

### 3.1 新增类型

**`shared/core/email_verification.go`** — 全新的验证 token 类型与存储接口：

```go
package core

import (
    "context"
    "errors"
    "time"
)

// EmailVerificationToken is a single-use, short-TTL token authorizing
// email ownership verification during self-service signup. Unlike
// EmailChangeToken (which is bound to an existing userID), this token
// is bound to a username that does NOT yet exist in UserProvider —
// the user is created atomically when the token is consumed.
type EmailVerificationToken struct {
    Token     string    // opaque token value (store primary key)
    Username  string    // the username being registered (becomes user ID)
    Email     string    // the email being verified
    ExpiresAt time.Time // absolute expiry
}

func (e *EmailVerificationToken) IsExpired() bool {
    return time.Now().After(e.ExpiresAt)
}

// EmailVerificationStore persists single-use email verification tokens
// for self-service signup. Issue stores a pending registration; Consume
// atomically retrieves AND deletes it, returning the registration data
// so the caller can create the user. memory + sqlite peers ship in
// defaultimpl, matching the EmailChangeStore pattern.
type EmailVerificationStore interface {
    Issue(ctx context.Context, tok *EmailVerificationToken) error
    Consume(ctx context.Context, token string) (*EmailVerificationToken, error)
}
```

**`shared/spi/email_verification.go`** — 全新的发送 SPI：

```go
package spi

import "context"

// EmailVerificationSender delivers a server-generated, single-use email
// verification token to the address the prospective user provided during
// signup. Delivering to that address proves the user controls it before
// the account is created. The token is sensitive: implementations MUST
// NOT log or persist it.
type EmailVerificationSender interface {
    SendEmailVerificationToken(ctx context.Context, email, token string) error
}
```

### 3.2 修改接口

**`protocols/selfservice/selfservicecore/deps.go`** — 新增方法：

```go
type Deps interface {
    // ... existing methods ...

    // Email verification (self-service signup)
    EmailVerificationStore() core.EmailVerificationStore
    EmailVerificationSender() spi.EmailVerificationSender
    SignupRequiresVerification() bool   // from config
    EmailVerificationTTL() time.Duration
}
```

### 3.3 修改的 handler

**`protocols/selfservice/signup.go`** — 分支逻辑：

```go
func HandleSelfRegister(d Deps, ctx core.HandlerContext) {
    // ... BindParams ...

    if d.SignupRequiresVerification() && req.Email == "" {
        ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
        return
    }

    if d.SignupRequiresVerification() {
        // MODE A: Deferred creation — issue token, send email, return "pending"
        handlePendingRegistration(d, ctx, username, req.Email, req.Password)
        return
    }

    // MODE B: Direct creation (existing behavior + optional verification send)
    // 1. GetByID → 409 check
    // 2. CreateOrUpdate (set email_verified = true if email provided)
    // 3. SetPassword
    // 4. If ?send_verification=true → send non-blocking verification email
    // 5. recordSelfRegister → 201
}
```

### 3.4 新端点

```
POST /auth/verify-email          — 消费 token + 创建用户（全局无认证）
POST /auth/resend-verification   — 重新发送验证邮件（防滥用）
```

### 3.5 安全模型

```
┌──────────────────────────────────────────────────────────┐
│  Token issue                                              │
│  POST /auth/register                                     │
│  → handler 生成 crypto/rand 32 字节 token                 │
│  → token BLAKE2b-160 hash 存入 store（明文永不落库）     │
│  → store 记录 (hash, username, email, expires_at)        │
│  → 完整 token（未 hash）发送到用户邮箱                    │
│                                                          │
│  Token consume                                           │
│  POST /auth/verify-email  {token: "..."}                 │
│  → hash 传入 token → Consume(hash) → 原子删除+返回      │
│  → 未找到 / 过期 / 已消费 → 统一 ErrVerificationInvalid  │
│  → CreateOrCreate + SetPassword 在同一个事务语义中       │
│                                                          │
│  防枚举：                                                 │
│  → Consume 失败统一 400 verification_invalid             │
│    （不区分 不存在 / 已过期 / 已消费 / 邮箱不匹配）       │
│  → Issue 成功始终返回 201 "pending"                      │
│    （不区分邮箱是否已注册——已注册邮箱也应发 token         │
│    以避免枚举。但稍后 Consume 时检查邮箱唯一性）          │
│  → 重新发送限速：per-IP 每 60s 一次                       │
└──────────────────────────────────────────────────────────┘
```

### 3.6 错误码

| 场景 | HTTP | 错误码 |
|------|------|--------|
| Token 无效/过期/已消费 | 400 | `verification_invalid` |
| 强制验证但未提供邮箱 | 400 | `invalid_request` |
| 未验证用户尝试登录 | 403 | `email_not_verified` |
| 注册邮箱已占用 | 409 | `account_exists` |

新增错误码：
```go
// shared/core/errors.go
ErrVerificationInvalid     = errors.New("sso: email verification token invalid or expired")
ErrEmailNotVerified        = errors.New("sso: email not verified")
```

同时更新 `docs/error-codes.md`（与功能代码同 commit）。

---

## 四、实现工程师：代码变更清单

### 4.1 文件清单

| # | 文件 | 操作 | 估算行数 |
|---|------|------|----------|
| 1 | `shared/core/email_verification.go` | **新建** — `EmailVerificationToken` + `EmailVerificationStore` 接口 | ~50 |
| 2 | `shared/core/errors.go` | **修改** — 新增 2 个 sentinel 错误 | ~3 |
| 3 | `shared/spi/email_verification.go` | **新建** — `EmailVerificationSender` 接口 | ~12 |
| 4 | `shared/core/consts.go` | **修改** — 新增 `PathVerifyEmail` 常量 | ~2 |
| 5 | `shared/core/consts.go` | **修改** — 新增 `EventEmailVerificationSent` + `EventEmailVerificationCompleted` 常量 | ~4 |
| 6 | `protocols/selfservice/signup.go` | **重写** — 添加验证分支逻辑 | +~50 |
| 7 | `protocols/selfservice/verify_email.go` | **新建** — `HandleVerifyEmail` handler | ~60 |
| 8 | `protocols/selfservice/selfservicecore/deps.go` | **修改** — Deps 接口新增 4 个方法 | ~6 |
| 9 | `interfaces/sso/server_signup.go` | **修改** — 新增 Deps 方法实现 | ~10 |
| 10 | `interfaces/sso/server_routes.go` | **修改** — 注册新端点 | ~4 |
| 11 | `interfaces/sso/options_passwd.go` | **修改** — 新增 `WithSignupRequireVerification()` 等选项 | ~15 |
| 12 | `infrastructure/defaultimpl/...` | **新建** memory + sqlite 的 EmailVerificationStore 实现 | ~120 |
| 13 | `cmd/sso-server/build_stores.go` | **修改** — 连线新的 store | ~10 |
| 14 | `cmd/sso-server/config.yaml` | **修改** — 新增配置段 | ~15 |
| 15 | `test/me_signup_email_verification_test.go` | **新建** — 集成测试 | ~200 |
| 16 | `docs/error-codes.md` | **修改** — 新增错误码文档 | ~5 |

**总计：~566 行新增/修改**（含 200 行测试）

### 4.2 配置变更

```yaml
# cmd/sso-server/config.yaml 新增
self_service:
  registration:
    # require_verification: when true, signup creates a pending account and
    # sends an email verification token. The user can only log in after
    # completing verification via POST /auth/verify-email. When false
    # (default), signup creates an active account immediately — the same
    # behavior as today.
    require_verification: false
    # verification_token_ttl controls how long the email verification token
    # remains valid. Shorter reduces the window for a leaked token; longer
    # accommodates slow email delivery. 0 = SDK default (15 min, matching
    # DefaultEmailChangeTTL).
    verification_token_ttl: 15m
```

### 4.3 选项 API

```go
// interfaces/sso/options_passwd.go
func WithSignupRequireVerification(v bool) Option {
    return func(srv *Server) {
        srv.signupRequireVerification = v
    }
}

// 注意：保持与 WithSelfServiceSignup() 正交
// signupEnabled = false → 无注册端点（现有行为）
// signupEnabled = true + signupRequireVerification = false → 可选验证（默认）
// signupEnabled = true + signupRequireVerification = true → 强制验证
```

### 4.4 默认实现（memory + sqlite）

遵循与 `EmailChangeStore` 完全相同的模式：

```go
// infrastructure/defaultimpl/memorystorecredential/memory_email_verification.go
type MemoryEmailVerificationStore struct {
    mu     sync.RWMutex
    tokens map[string]*core.EmailVerificationToken // key = hash of token
}
```

SQLite store 使用与 `email_change_tokens` 相同的表结构模式，或共用 `verification_tokens` 表（技术决策：分开更干净，因为不同的 TTL 和 Revoke 策略）。

### 4.5 测试策略

| 层级 | 覆盖 |
|------|------|
| 单元测试（`protocols/selfservice/signup_test.go`） | HandleSelfRegister 的两种模式（require_verification = true/false） |
| 单元测试（`protocols/selfservice/verify_email_test.go`） | HandleVerifyEmail 的正常/过期/已消费/未知 token 四种路径 |
| 存储单元测试（`infrastructure/defaultimpl/*_test.go`） | EmailVerificationStore.Issue + Consume |
| 集成测试（`test/me_signup_email_verification_test.go`） | HTTP POST → /auth/register → 验证 → POST /auth/verify-email → 登录 |
| 反枚举测试 | 已注册邮箱和未注册邮箱在强制验证模式下返回相同响应 |
| Oracle-safe 测试 | Consume 的四种失败场景全部返回 `400 verification_invalid` |
| 速率限制测试 | `/auth/resend-verification` 的 per-IP 限速 |
| 并发测试 | 两个相同 token 并发 Consume → 只有一个成功（SQL 原子性） |

---

## 五、对抗性审查（Adversarial Review）

### 5.1 需求合理性挑战

**Q1：邮箱验证真的需要吗？当前的无验证注册有什么问题？**

```
挑战者论据：
- 用户可以用用户名+密码注册，无需邮箱
- 加验证步骤增加注册摩擦，转化率下降
- 攻击者可以注册虚假邮箱（一次性邮箱 / guerillamail）

反驳：
- 无邮箱 = 无法密码重置（当前用户如果忘记密码且未提供邮箱，管理
  员必须手动介入——这是生产运营的已知痛点）
- 邮箱验证不是为了防机器人（那是 CAPTCHA 的事），而是为了：
  (a) 确保用户可找回账户
  (b) 提供 OIDC email_verified 声明（企业 RP 依赖此声明做授权决策）
  (c) 减少假冒注册（虽然不完美，但提高攻击成本）
- 一次性邮箱是独立问题——域黑名单 / 企业邮箱验证是后续增强
```

**Q2：为什么不直接用现有的 EmailChangeStore？为什么要新建 EmailVerificationStore？**

```
挑战者论据：
- EmailChangeStore 已有 Issue/Consume 接口，加一个 token type 字段即可复用
- 减少代码重复，减少测试矩阵

反驳：
- EmailChangeToken 绑定到 userID（已存在的用户）；EmailVerificationToken
  绑定到 username（尚不存在的用户）。虽然结构相似但语义完全不同。
- EmailChangeRevoker 需要按 userID 撤销；EmailVerificationRevoker 不需要
  （不存在用户来撤销）
- 共享表/接口会导致：
  (a) Token 类型字段（switch/branch）
  (b) 两个流程的 TTL 配置不同（email change 5min vs 注册 15min）
  (c) 存储实现复杂化（一个表两个使用模式）
- 分两个 store 是 Go 接口隔离原则：EmailVerificationStore 的消费者
  （signup handler）不需要知道 EmailChangeStore 的存在
```

**Q3：强制验证模式下，`POST /auth/verify-email` 成功后如何让用户登录？**

```
挑战者论据：
- 验证完成后用户需要再执行一次登录操作——两步流程
- 为什么不直接返回 session token / redirect URL？

反驳：
- 验证成功后返回 session token 是 OAuth 边界之外的行为（SSO 服务器
  的主要流程是 OAuth，不是 session cookie 管理）
- 当前 hosted login 页面可以：验证成功后 302 到 login 页面 + pre-fill
  用户名（auto-login 有安全风险——邮箱验证链接被截获则攻击者获得登录态）
- 产品决策：保持验证和登录分离（与所有主流 SSO 产品一致）
- 如果需要无缝体验，前端可以：检测验证成功 → 自动提交登录表单
```

**Q4：`email_verified` 只读不写——现有邮箱更改流程的 bug 是否要先修？**

```
挑战者论据：
- 当前 email_change 流程验证成功后不设置 email_verified = "true"
- 这意味着 userinfo 的 email_verified 永远返回 false
- 先修这个 bug 再建注册验证，否则两个不完整的验证系统共存

评估结果：✅ 合理的依赖关系！
- 这是一个独立的 bug fix（~5 行代码：在 email_change.go:HandleMyEmailVerify
  成功后设置 u.Attributes["email_verified"] = "true" 再 CreateOrUpdate）
- 应该放在同一 Sprint 中作为 P0，先于注册邮箱验证合并
- 工作量极小但影响大（修复一个让所有 RP 无法信任 email_verified 的 bug）
```

### 5.2 安全对抗

**攻击 1：邮箱验证 token 截获**

```
场景：攻击者拦截验证邮件（邮箱泄露、SMTP MITM、日志泄露）
影响：攻击者可以创建账户

缓解：
- Token 32 字节 crypto/rand（192 bits 熵）——暴力破解不可行
- 短 TTL（默认 15 分钟）
- 单次使用（Consume 原子删除，重放返回 verification_invalid）
- Token 在存储中只存 SHA-256 hash（明文永不落库）
- HSTS 和邮件传输加密由 EmailSender 实现负责
```

**攻击 2：注册枚举**

```
场景：攻击者通过 POST /auth/register 枚举已注册的邮箱
当前：POST 已存在用户名 → 409 account_exists（用户名维度的信息泄露）
加上邮箱验证后：POST 已存在邮箱的注册请求 → 201 "pending"
（验证邮件发到该邮箱——但邮箱所有者会收到不想收到的验证邮件）

权衡：
- 持久化枚举 vs 邮件滋扰
- 推荐：初始阶段不防邮箱枚举（因为注册需要验证，即使邮箱已被占用，
  攻击者也无法获得账户）。后续增强：Consume 时检查邮箱唯一性。
```

**攻击 3：验证邮件轰炸**

```
场景：攻击者对同一邮箱重复 POST /auth/register
影响：邮箱收到大量验证邮件

缓解：
- per-email 限速：相同的 email 在 TTL 窗口内只发一封邮件（更新 token）
- per-IP 限速：标准中间件 + 更激进的注册限速策略
- 与未来 CAPTCHA 集成协同（Round 7）
```

**攻击 4：邮箱竞态（两个并发注册同一邮箱）**

```
场景：用户 A 和用户 B 同时用同一邮箱注册
- 两个 POST /auth/register 各自创建 token
- 两封验证邮件几乎同时发送
- 谁先验证谁获得账户

缓解：
- Consume 时检查邮箱唯一性（用户 B 验证时邮箱已被 A 占用 → 400
  verification_invalid + 提示邮箱已被注册）
- 这是最合理的语义：先到先得，邮箱验证解决所有权问题
```

### 5.3 架构对抗

**Q：`POST /auth/verify-email` 是无认证端点，是否存在 SSRF / 拒绝服务风险？**

```
分析：
- /auth/verify-email 仅接受 {token} JSON body
- 不解析 URL 参数，不发起出站请求
- 响应体固定（验证成功 → {"status":"verified"}；失败 → 400）
- 主要消耗：两次数据库写入（consume token + create user）
- 风险级别：低（与 /auth/register 和 /token 同级别）
```

**Q：`EmailVerificationStore` 的 SQLite 实现是否应该使用 `BEGIN IMMEDIATE` 事务？**

```
分析：
- Consume 操作需要原子性（一次删除 + 一次创建用户）
- 如果使用 memory store，sync.RWMutex 即可
- 如果使用 SQLite store，使用 `BEGIN IMMEDIATE` 事务：
  ```sql
  BEGIN IMMEDIATE;
  DELETE FROM email_verification_tokens WHERE token = ? RETURNING ...;
  INSERT INTO users ...;
  COMMIT;
  ```
- 如果使用 Postgres store（未来），使用 advisory lock + serializable
- 迁移模式（部分用户在 token 消费成功但用户创建失败时）：
  token 已删除但用户未创建 → 用户可以重新注册（用户名不再被占用）
  → 与现有 signup 的回滚模式一致
```

### 5.4 产品对抗

**Q：`email_verified` 的默认值策略？**

| 场景 | `require_verification` | 用户提供邮箱 | `email_verified` |
|------|----------------------|-------------|------------------|
| 当前行为（不迁移） | false | 是 | true（立即标记，新行为） |
| 当前行为 | false | 否 | 不设置（无邮箱） |
| 强制验证 | true | 是 | 验证完成后设置 true |
| 强制验证 | true | 否 | 被拒绝（400） |

**决策：** `require_verification: false` 模式下，如果用户提供了邮箱，自动设置 `email_verified = "true"`。理由：
- 向后兼容（当前行为默认信任用户提供的邮箱）
- 不需要迁移存量用户（它们已经被视为已验证）
- 这是最宽松的策略，P0 的短期目标

如果将来需要更严格的行为，`require_verification: true` 提供逃生口。

---

## 六、实现 Prompt

以下是面向 `Implement Agent` 的 Prompt，可直接用于生成代码。

### Prompt: 实现自助注册邮箱验证

```markdown
# 角色
你是一个资深 Go 后端工程师，负责实现 snaplink/sso OAuth 2.0/OIDC SSO 服务器
的自助注册邮箱验证功能。你深入理解 OAuth 2.0、OIDC Core、API 安全性（防枚举、
oracle-safe 响应、anti-SSRF）、以及 Go 接口隔离原则。

# 任务上下文
snaplink/sso 是一个基于 Go 的 OAuth 2.0 授权服务器 + OIDC 身份提供者 SDK。
当前自助注册（POST /auth/register）在创建用户时不需要邮箱验证。邮箱更改
（/me/email/change）已实现两段式验证流程可作为模板。

# 需要阅读的现有文件（理解模式）
- protocols/selfservice/signup.go        — 当前注册 handler（需要修改）
- protocols/selfservice/email_change.go  — 邮箱更改两段验证（参考模式）
- shared/core/email_change.go            — EmailChangeToken + EmailChangeStore（参考）
- shared/spi/email_change.go             — EmailChangeSender（参考）
- protocols/selfservice/selfservicecore/deps.go — Deps 接口（需要扩展）
- interfaces/sso/server_signup.go        — Server Deps 实现（需要扩展）
- interfaces/sso/server_routes.go        — 路由注册（需要扩展）
- interfaces/sso/options_passwd.go       — Server 选项（需要扩展）

# 功能需求（按优先级排序）

## P0: 新增核心类型与接口
1. 创建 shared/core/email_verification.go:
   - EmailVerificationToken 结构体（Token, Username, Email, ExpiresAt）
   - EmailVerificationStore 接口（Issue, Consume）
2. 创建 shared/spi/email_verification.go:
   - EmailVerificationSender 接口（SendEmailVerificationToken(ctx, email, token)）
3. 在 shared/core/errors.go 新增：
   - ErrVerificationInvalid = errors.New("sso: email verification token invalid or expired")
   - ErrEmailNotVerified = errors.New("sso: email not verified")
4. 在 docs/error-codes.md 新增以上两个错误码

## P1: 修改注册流程（可选验证模式）
5. 修改 protocols/selfservice/signup.go:
   - 当 SignupRequiresVerification() 为 false 时保持现有行为
   - 但新增：如果有邮箱，设置 User.Attributes["email_verified"] = "true"
   - 新增可选的 send_verification=true query 参数
6. 扩展 protocols/selfservice/selfservicecore/deps.go 接口：
   - EmailVerificationStore() core.EmailVerificationStore
   - EmailVerificationSender() spi.EmailVerificationSender
   - SignupRequiresVerification() bool
   - EmailVerificationTTL() time.Duration

## P2: 实现强制验证模式
7. 在 protocols/selfservice/signup.go 添加 handlePendingRegistration 分支：
   - SignupRequiresVerification() == true 且 email 为空 → 400
   - 生成 crypto/rand 32 字节 token
   - 存储 hash(token) → EmailVerificationStore.Issue
   - 发送完整 token 到邮箱 → EmailVerificationSender
   - 返回 201 {"status":"pending"}
8. 创建 protocols/selfservice/verify_email.go:
   - HandleVerifyEmail handler
   - POST /auth/verify-email {token}
   - 消费 token + oracle-safe 错误处理（四种场景全部返回 400 verification_invalid）
   - 原子创建用户 + 设置密码 + 设置 email_verified
9. 修改登录流程：在强制验证模式下，未验证用户登录 → 403 email_not_verified

## P3: 配置与连线
10. 新增 WithSignupRequireVerification(bool) Server Option
11. 在 interfaces/sso/server_signup.go 实现新的 Deps 方法
12. 在 server_routes.go 注册 POST /auth/verify-email
13. 实现 memory.EmailVerificationStore（参考 memory.EmailChangeStore）
14. 在 cmd/sso-server/build_stores.go 连线

# 约束（HARD GATES）
- 所有 HTTP 错误响应必须 oracle-safe（无法枚举）
- 所有 Credential-adjacent 端点必须设置 Cache-Control: no-store
- Token 在存储中只保留 hash（明文 token 只保存在发送邮件过程中）
- 单个文件 ≤ 500 行（EmailVerificationStore memory 和 sqlite 实现各一个文件）
- 新增接口必须位于 shared/ 层（core 或 spi），不可在 interface 包中定义
- 现有测试必须全部通过（go test ./... -race）
- 遵循 architecture_layer_test.go 的依赖方向规则

# 提交信息
feat(selfservice): add email verification for self-service signup

- Add EmailVerificationToken + EmailVerificationStore (core SPI)
- Add EmailVerificationSender (SPI)
- Extend HandleSelfRegister with require_verification mode
- Add HandleVerifyEmail endpoint (POST /auth/verify-email)
- Add WithSignupRequireVerification server option
- Implement memory.EmailVerificationStore
- Wire in cmd/sso-server config
- Fix: email_change flow now sets email_verified attribute

Co-authored-by: AI
```

---

## 七、执行概要

```
Sprint: 自助注册邮箱验证
估算工作量: 566 行 / 3-5 天（单人）
依赖: 无外部依赖（复用 EmailChangeSender SPI）
风险: 低（隔离在 selfservice/ 层，不影响 OAuth 核心流程）

MVP（P0, Day 1-2）:
  core + spi 接口  →  ~60 行
  可选验证模式      →  ~50 行
  修复 email_verified 写入  →  ~5 行

核心（P1, Day 2-3）:
  强制验证模式      →  ~80 行
  memory store      →  ~60 行
  路由 + 选项      →  ~30 行

完善（P2, Day 3-5）:
  SQLite store      →  ~60 行
  集成测试          →  ~200 行
  配置 + 连线      →  ~30 行

验收后必须:
  make acceptance  — 全量评估套件通过
  bash .check-review-feature.sh  — 对抗性审查确认 oracle-safe 一致性
```

> **建议启动顺序：** 先合并 `email_verified` 写入修复（~5 行，独立 PR），再基于修复后的 master 构建注册邮箱验证功能。两个更改都集中在 `protocols/selfservice/` 包中，依赖顺序清晰。
