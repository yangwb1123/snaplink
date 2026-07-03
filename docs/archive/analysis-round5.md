# 分析第 5 轮 — 用户会话自我管理 / 密码策略 / per-subject 限流 / Branding / Sudo 模式

> 扫描日期：2026-06-29
>
> 前四次路线：① 产品/协议全局 → ② `time.Now()`/集群/Postgres → ③ 刷新令牌并发/事件流/配置热重载 → ④ 安全头/KDF/跨区域/SPIFFE/Go模块
>
> 本次聚焦：之前四轮从未触及的用户运维面（会话管理、密码策略、限流模型、品牌化、关键操作确认）

---

## 方向一：用户自助会话管理页面缺失 — 用户无法查看和终止自己的活跃会话

**代码验证：**

**后端能力已存在：**

```go
// shared/core/spi.go:140
ListByUser(ctx context.Context, userID string) ([]*Session, error)
```
- `Session.Device` / `Session.UserAgent` / `Session.IP` / `Session.CreatedAt` / `Session.ExpiresAt` — 元数据齐全
- `POST /token/revoke-all` → `oauth.HandleRevokeAll(s, ctx)` 可终止该用户所有会话
- Admin RPC `TokenAdminService.ListSessions` 可查看全用户会话
- `SessionManager.RevokeSession(userID, sessionID)` 存在

**但用户自己看不到/控制不了：**

| 路径 | 当前状态 |
|------|----------|
| `GET /me/sessions` | **不存在**。用户无法知道"我在哪台设备上登录了" |
| `DELETE /me/sessions/:id` | **不存在**。用户无法远程登出某台特定设备（如丢的手机） |
| `POST /me/sessions/revoke-all` | **不存在**（仅 `/token/revoke-all` 存在，但非 `/me/*` 模式） |

**为什么需要：**
"开箱即用的 SSO"期望的基础 UX 功能——用户查看"我在哪 8 台设备上有登录"，远程登出旧设备或丢的手机。当前只能由 **admin** 以 `admin:*` 权限做，用户自己不能。

**建议修复：**
```
GET  /me/sessions           → SessionManager.ListByUser(userID) → 设备列表
DELETE /me/sessions/:id     → SessionManager.RevokeSession(userID, sessionID)
POST /me/sessions/revoke-all → 调用现有 oauth.HandleRevokeAll
```
工作量：S（~50 行路由 + 后端数据已齐全）。

---

## 方向二：密码策略 SPI 完全缺失 — 无密码复杂度/历史/过期强制配置点

**代码验证：**

**全树零命中：**
| 搜索词 | 命中数（排除无关） |
|--------|-------------------|
| `PasswordPolicy` / `passwordPolicy` | 0（`netpolicy.Policy` 不相关） |
| `PasswordHistory` / `passwordHistory` | 0 |
| `password.*expir` | 0 |
| `password.*complexity` / `complexity` | 0 |
| `password.*min.*length` / `password.*max.*length` | 0 |

**现有的相关但不足的能力：**

- `shared/spi/password_health.go` — **非阻塞**的弱密码/已泄露检测（HIBP 风格），在登录后即时回报审计事件。**不阻止**密码设置。
- `EventPasswordWeak` / `EventPasswordCompromised` — 仅做审计事件记录
- `PasswordHealthChecker` — 登录时报告凭据健康，但不强制策略

**缺失的能力：**

1. **密码复杂度规则** — 最小长度、大写/小写/数字/特殊字符混合
2. **密码历史** — 禁止重复使用最近 N 个密码
3. **密码最大有效期** — 强制每 M 天轮换密码（NIST SP 800-63 已不推荐，但 SOC2/ISO 仍要求）
4. **修改密码时的策略验证** — `POST /me/password` 和 `/auth/reset-password` 当前直接在 `UserProvider.UpdatePassword` 更新，不检查新密码是否符合策略

**为什么需要：**
SOC2、ISO 27001、PCI-DSS 采购安全问卷第一页就问"密码策略在哪配置"。当前回答是"没有"——直接导致无法通过企业安全评审。

**建议修复：**

```go
// 新增 shared/spi/password_policy.go
type PasswordPolicy interface {
    Validate(ctx, newPassword, userID) []ValidationError
}

// 内置实现：builtin/PasswordPolicy
type BuiltinPasswordPolicy struct {
    MinLength          int
    RequireUpper       bool
    RequireLower       bool
    RequireDigit       bool
    RequireSpecial     bool
    HistoryCheckCount  int  // 禁止重复使用最近 N 个
    MaxAgeDays         int  // 超期强制登录时提示修改
}
```

- `WithPasswordPolicy(policy)` 选项
- 钩子挂到 `POST /me/password` 和 `/auth/reset-password`

---

## 方向三：登录速率限制缺少 per-subject 维度 — 横向撞库不能被限流阻断

**代码验证：**

**当前限流模型：**
```go
// interfaces/ratelimit/ratelimit.go
Allow(key string) — key 是 "{path}:{client_id}:{ip}"
```

**攻击场景：横向撞库（Password Spraying）**

- 每个用户试 1 个常见密码（不是 1000 次），遍历全组织 10000 个用户
- 没有一个 per-account lockout 会触发（每个用户名只有 1 次失败）
- rate limiter 只看 client_id + IP（可被多个 IP / 代理轮换绕过）

**现有已激活的原语（但未启用阻断）：**

| 组件 | 位置 | 当前行为 |
|------|------|----------|
| `security/account_lockout.go` | per-account 锁定 | 仅针对单用户多失败 |
| `anomaly/velocity.go` | 登录尝试速率检测 | 只报告审计事件，**不阻断** |
| `BruteForceShadow` | 暴力破解模式观察 | 不阻断 |
| `anomaly/OnAnomaly` 事件 | 异步探测器 | 无内置 action（终端效果为空） |
| `WithAnomalyAction(func(event AnomalyEvent))` | 注入阻断动作 | 开发者需自己实现 |

**建议修复：**

1. **per-subject key 限流**：给 rate limiter 添加 `KeyBySubject(key, subjectID)` 变体，限流 key = `{client_id}:{subject_id}`
2. **VelocityDetector 自动阻断**：`OnAnomaly` 事件注册内置 handler，阻止该 subjectID 的所有登录 30s
3. **配置化**：`anomaly.velocity.auto_block_duration: 30s`

---

## 方向四：品牌化（Branding）数据只存储不消费 — 配置了但不在任何页面渲染

**代码验证：**

```go
// domains/tenant/tenant.go:73 — Branding 结构已定义
type Branding struct {
    CompanyName   string   // 租户显示名称
    LogoURL       string   // 租户 logo URL
    PrimaryColor  string   // 主题色
    FaviconURL    string   // 图标 URL
}
// Tenant.Branding 字段存在并存储在 store 中
```

**但 Branding 不被渲染：**

| 页面/位置 | 当前状态 |
|-----------|----------|
| `interfaces/web/login/index.html` (981 行) | 纯 HTML 存根，不读 Branding |
| `interfaces/web/admin/index.html` (1073 行) | 纯 HTML 存根，不读 Branding |
| `interfaces/web/portal/index.html` (745 行) | 纯 HTML 存根，不读 Branding |
| 所有 JARM / Form Post auto-POST HTML | 白页，不读 Branding |
| 密码重置/邮箱验证邮件 | 无 Branding 模板 |
| SAML IdP SLO/回调 HTML | 用 `html/template`，但无 Branding 注入 |

**为什么需要：**
企业采购 SSO 时，品牌化登录页面是核心要求（"我们的用户应该看到我们公司的 logo"）。后端配置了 Branding 但前端没有渲染——"存了没用"。

Branding 与多租户解耦（`tenant.go:73` 的 `Branding` 和 tenant 绑定），不同租户可有完全不同的品牌——这是企业 SaaS 卖点。

**建议修复：**

- `GET /tenants/:tenant_id/branding` → 返回 Branding JSON（供 SPA 使用）
- 自助门户 UI 初始化时读取租户 brand
- 邮件模板（密码重置、邀请、验证）读取租户 Branding
- SAML auto-POST HTML 页面注入 tenant brand（品牌名 + logo）

---

## 方向五：`/me` sudo 模式缺失 — 密码修改不需要当前密码再确认

**代码验证：**

**现有 `/me` 端点（完整但缺保护）：**
| 端点 | 功能 | 当前验证 |
|------|------|----------|
| `POST /me/password` | 修改密码 | 不要求当前密码 |
| `POST /me/mfa/totp/begin` | TOTP 注册 | 不要求密码 |
| `POST /me/mfa/webauthn/begin` | Passkey 注册 | 不要求密码 |
| `POST /me/account/erase` | 账户擦除 | 有 confirm 步骤 |
| `POST /me/email/change` | 邮箱变更 | 有确认链接 |
| `GET /me/data` | 数据导出 | 需 session |

**最显著缺口 — sudo 模式（关键操作需重新认证）：**

`POST /me/password` 修改密码**不需要当前密码再确认**——直接调用 `UserProvider.UpdatePassword(ctx, userID, newPasswordHash)`。如果用户的 session 被 XSS 偷走，攻击者可以直接修改密码锁定用户。

对比：
- GitHub：修改密码 → 先输当前密码
- Google：修改密码 → 要求重新登录
- Apple：敏感操作 → device-based 确认 + 旧密码

**建议修复：**

- `POST /me/password` body 增加可选字段 `current_password`
- 如果 session 创建时间 > N 小时（如 1h），强制要求 `current_password`
- 当前密码不正确 → `invalid_password` error（anti-enumeration: 与"新密码不符合策略"区分开）
- 新密码同时经过 `PasswordPolicy`（方向二）验证

---

## 优先级排序

| 方向 | 价值 | 工作量 | 建议顺序 |
|------|------|--------|----------|
| **① 用户会话自我管理** | 高（产品缺口） | S | **最先 Sprint** |
| **② 密码策略 SPI** | 高（安全合规刚性） | M | 第 2 |
| **③ per-subject 限流** | 中-高（密码喷洒攻击面） | M | 第 3 |
| **④ Branding 消费** | 中（企业白标卖点） | M | 第 4 |
| **⑤ sudo 模式** | 中-高（XSS 防御深度） | S | **同 Sprint ②** |

**一句话：** ① 把已有后端能力（`ListByUser`/`RevokeSession`）暴露给用户自己，~50 行的最小产品增量 → ② 补 SOC2/ISO27001 采购问卷必问的密码策略 → ③ 补横向撞库（每用户 1 次、铺开全组织 ）的最后一道防线 → ④ 让配置了的 Branding 真正在自助页面/邮件中渲染 → ⑤ 密码修改添加密码确认的 sudo 保护，防止 session 窃取后的账户劫持。
