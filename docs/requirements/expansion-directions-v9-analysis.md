# 扩展方向分析报告 v9

> **作者：** 资深架构 & 产品经理视角  
> **日期：** 2026-07-11  
> **范围：** 全代码库全局扫描（2241 `.go` 文件、4 个嵌入式 SPA、200+ 包）  
> **前提：** 已系统阅读并引用 `ROADMAP.md` v5.0、`deferred-backlog.md`、  
>   `expansion-directions-v7-analysis.md`（BFF / select_account / i18n /  
>   SAML2 输出 / 可验证凭证）、`expansion-directions-v8-analysis.md`  
>   （B2B 委托管理门户 / select_account / i18n / 跨标签页同步 / 跨协议  
>   翻译网关）。**已逐项对抗核验确认本报告 5 个方向与上述文档零重叠。**  
> **目标：** 列出 5 个**当前任何分析文档均未覆盖**的高价值扩展方向，  
>   **专注于"产品化缺口、安全治理框架、身份生命周期完整性"**——这些是  
>   项目协议面已极完整（90+ `WithXxx` 选项、4 个 SPA、10+ 企业协议）之后  
>   的自然下一阶段。

---

## 前置声明：项目成熟度定位

经过多轮全局扫描和方向分析，本项目的基础协议覆盖面和后端能力已是行业  
顶级水平。v7 和 v8 已分别覆盖了从 BFF 安全模式到 B2B 委托门户、从 SPA  
国际化到跨协议翻译网关的 10 个高价值方向。

本报告聚焦于**另一组同样经 grep 确认的 5 个方向**，它们不属于"新协议支持"  
或"新后端能力"，而是属于以下三大领域：

| 领域 | 方向 |
|---|---|
| **身份生命周期完整性** | ① 自助账户恢复与身份证明框架 |
| **产品化消费者体验** | ② Magic Link 免密登录 |
| **企业安全治理** | ③ 推送通知基础设施与移动认证 SDK |
| **运维管理面** | ④ 令牌与会话生命周期治理面板 |
| **安全架构纵深** | ⑤ 令牌敏感度分类与自适应保护 |

这些方向共同回答一个问题：**"当你的 SSO 平台已经支持了所有协议，下一步  
应该把精力投向哪里？"** 答案是：把能力包装成完整的产品体验，补齐企业安全  
治理的管理面，并建立纵深防御的令牌安全架构。

---

## 方向 1：自助账户恢复与渐进式身份证明（Account Recovery + Progressive IAL）

### 现状

项目拥有完整的密码重置流程（`forgot-password` → 邮件重置链接 → 设置新密码）、  
MFA 恢复码（`recovery_mfa_provider.go`）、以及管理员 break-glass 账户接管  
（`interfaces/admin/break_glass.go`）。但这些是**松散的恢复路径**，不存在  
一个统一的"账户恢复"框架。

| 能力 | 状态 |
|---|---|
| 忘记密码 → 邮件重置 | ✅ `forgot-link` in login SPA + `password_reset.tmpl` |
| MFA 恢复码（替代第二因素） | ✅ `recovery_mfa_provider.go` + portal UI |
| 管理员 break-glass | ✅ `interfaces/admin/break_glass.go` + admin API |
| **全丢失恢复（密码 + MFA + 全部设备丢失）** | ❌ 零实现 |
| **渐进式身份证明（Progressive IAL）** | ❌ 零实现 |
| **身份证明级别跟踪与升级** | ❌ 零实现 |
| **账户恢复事件审计与通知** | ❌ 零实现 |
| **恢复自助门户（非管理员介入）** | ❌ 零实现 |

### 缺口（grep 核验）

- `account.*recover` / `AccountRecover` / `account.*recovery` / `AccountRecovery`：**零实现命中**  
  （仅 `break_glass.go` 有恢复相关代码，但那是管理员代操作，不是自助恢复）
- `identity.*proof` / `IdentityProof` / `identity.*assurance` / `IdentityAssurance` / `IAL`：**零实现命中**  
- `progressive.*identity` / `ProgressiveIdentity` / `step.*up.*identity` / `identity.*level`：**零实现命中**
- 没有 `IdentityVerificationStore` SPI 或 `IdentityProofingProvider` SPI
- 没有身份证明级别的概念——用户要么"已认证"要么"未认证"，没有中间状态
- 没有"账户恢复挑战"的 API 端点（`POST /auth/recover`、`POST /auth/recover/verify`）

### 范围

#### 1. 账户恢复框架

```
用户场景: 小张忘记了密码，MFA 设备丢失，恢复码也弄丢了。
         他需要证明自己身份来恢复账户访问。

恢复流程:

  Step 1: POST /auth/recover/initiate {identifier}
          系统返回可用的恢复方式列表:
          - email_verify（给注册邮箱发验证码）
          - phone_verify（给注册手机发短信）
          - admin_attestation（联系管理员确认身份）
          - backup_code（如果有备份恢复码）
          
  Step 2: POST /auth/recover/verify {method, challenge_id, proof}
          验证身份证明。
          如果单个方法的信任度不够，可以组合多个方法。
          
  Step 3: POST /auth/recover/complete {recovery_token, new_password?}
          恢复成功后设置新凭据。
```

#### 2. 渐进式身份证明（Progressive IAL）SPI

```go
// domains/identityproofing/ial.go — 新包

// IdentityAssuranceLevel defines how confidently we know who this user is.
type IdentityAssuranceLevel int

const (
    IALNone   IdentityAssuranceLevel = 0 // 未证明
    IAL1      IdentityAssuranceLevel = 1 // 自断言（邮箱验证、手机验证）
    IAL2      IdentityAssuranceLevel = 2 // 远程证明（证件上传+人工审核）
    IAL3      IdentityAssuranceLevel = 3 // 物理证明（面对面或等效）
)

// IdentityProofingProvider SPI 用于集成外部身份证明服务：
//   - 邮箱/短信验证码（内置实现）
//   - 证件扫描+活体检测（集成 Onfido / Jumio / Stripe Identity）
//   - 知识库验证（KBV，基于信用记录的问题）
//   - 管理员背书（手动审批）
type IdentityProofingProvider interface {
    // Initiate starts a proofing session for the given method.
    Initiate(ctx context.Context, userID string, method ProofingMethod) (*ProofingSession, error)
    
    // Verify processes the proof and returns the achieved level.
    Verify(ctx context.Context, sessionID string, proof map[string]string) (IALResult, error)
}
```

#### 3. 身份证明级别（IAL）在令牌生命周期中的集成

```
身份证明级别影响令牌信任:

  IAL1 用户:
    - access_token TTL: 1 小时
    - 不能获得 admin:* scope
    - 敏感操作需要 step-up 到 IAL2
    
  IAL2 用户:
    - access_token TTL: 4 小时
    - 可以获得 admin:read scope
    - 高危操作需要 step-up 确认
    
  IAL3 用户:
    - access_token TTL: 8 小时
    - 可以获得 admin:* scope
    - 可执行用户 impersonation
    
令牌的 acr claim 反映 IAL 级别:
  "acr": "urn:snaplink:ial:2"
```

#### 4. 审计与通知

```
每次恢复尝试记录详细审计事件:
  - account_recovery_initiated {method, ip, user_agent}
  - account_recovery_verified {method, ial_level}
  - account_recovery_completed {method, new_credential_type}
  
恢复成功时通知用户（邮箱 + 可选 SMS）:
  "你的账户已于 2026-07-11 14:30 UTC 通过邮箱验证恢复。
   如果这不是你操作的，请立即联系管理员。"
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 攻击者尝试恢复他人账户 | 多因素恢复（至少需要 2 种不同方法的证明）+ 速率限制（每账户每小时 3 次尝试）+ 通知原所有者 |
| 用户没有任何已验证的联系方式 | 管理员代为恢复（已有的 break-glass 流程），或者"注册时预留恢复邮箱"作为强制性注册步骤 |
| 恢复后用户仍无法登录 | 恢复完成后立即清除旧 session + 颁发临时 token 用于新密码设置 |
| 账户恢复的枚举攻击 | 所有恢复起始端点返回 `{"status":"initiated_sent_if_account_exists"}` 统一响应，不区分存在与否 |
| 恢复 Token 泄露 | 短 TTL（15 分钟）+ 一次性使用 + 成功后立即轮换所有 token family |

### 为什么值得做

**账户恢复是身份平台的安全底线。** 当用户丢失所有凭据时，缺乏自助恢复路径  
意味着：要么用户被永久锁定（客户流失），要么支持团队手动操作（安全风险 +  
运营成本）。渐进式 IAL 则是"从消费者级身份到企业级身份"的桥梁——允许系统  
根据用户的身份证明级别决定令牌信任度，是条件访问、风险评分、step-up 认证  
的上游依赖。**没有 IAL，条件访问策略只能基于"是否已登录"这一二进制决策，  
无法区分"刚注册的邮箱用户"和"已完成 KYC 的员工"。**

- **价值：** 高（安全 + 产品完整性 + 合规前提）  
- **工作量：** L 但可分阶段：
  - Phase 1：账户恢复框架 + 邮箱验证恢复（S）
  - Phase 2：IAL SPI + 身份证明级别集成（M）
  - Phase 3：多方法组合恢复 + 管理员审批流（M）
- **依赖：** `EmailSender`（已存在）、`authenticators.EmailAuthenticator`（已存在）、  
  `break_glass.go`（已存在，可作为管理审批的集成点）

---

## 方向 2：Magic Link 免密主认证（Passwordless Magic Link Primary Auth）

### 现状

项目支持以下认证方式：

| 认证方式 | 类型 | 状态 |
|---|---|---|
| 密码（用户名+密码） | 主认证 | ✅ 完整 |
| WebAuthn Passkey（发现式凭据） | 主认证 | ✅ 完整（含条件式中介） |
| WebAuthn 安全密钥 | 主认证 + MFA | ✅ 完整 |
| TOTP 验证码 | MFA | ✅ 完整 |
| 推送通知 | MFA | ✅ webhook 模式 |
| 短信/电话验证码 | MFA + 主认证 | ✅ phone.go 实现 |
| **邮箱验证码** | **MFA + 主认证** | ✅ **email.go 实现但为两步验证码** |
| **Magic Link（邮件链接一键登录）** | **主认证** | ❌ **零实现** |
| **Email OTP 一触登录** | **主认证** | ❌ **SPA 无对应 UI** |

当前的 `EmailAuthenticator`（`domains/authenticators/email.go`）实现了  
两步验证码模式：用户输入邮箱 → 收到验证码 → 输入验证码 → 登录成功。  
但缺少**更流畅的消费者身份认证模式**：Magic Link（点链接即登录）。

### 缺口（grep 核验）

- **Magic Link 完整模式**：**零实现命中**。没有 `magic_link` 作为认证器名称、  
  没有 `POST /auth/magic-link` 端点、没有 `magic_link.tmpl` 邮件模板、  
  没有 SPA 的 Magic Link UI。
- **一键登录 SPA UX**：登录页目前只有密码表单 + 可选的 provider 切换。  
  没有"发送登录链接"按钮、没有邮箱输入 → 发送链接 → 查收邮件的流程。
- **临时令牌认证器**：`temp_token.go` 实现了 TempTokenAuthenticator，但它是  
  作为**通用临时令牌验证**（用于 MFA 挑战、密码重置等），不是作为 Magic Link  
  设计的——没有集成到 OAuth 授权码流程中。
- **登录页 Magic Link 交互模式**：`login/app.js` 的 `handleSuccess` 不会处理  
  中间态（"链接已发送，请查收邮件"）。

### 范围

#### 1. Magic Link 认证端点

```go
// 新增端点:
// POST /auth/magic-link
//   Request:  {email, client_id, redirect_uri, state, scope, ...oauth_params}
//   Response: {"status":"sent"}  // 统一响应（防枚举）
//   
//   内部流程:
//   1. 生成唯一 magic_token（高熵，short TTL 15min）
//   2. 将 OAuth 请求参数绑定到 magic_token（存储在 CodeStore/TempTokenStore）
//   3. 发送邮件：<a href="https://sso.example.com/auth/magic-link/verify?token={magic_token}">
//      点击登录</a>
//   4. 用户点击链接 → GET /auth/magic-link/verify?token=xxx
//   5. 服务端:
//      a. 验证 token（存在、未过期、未使用）
//      b. 创建临时 session
//      c. 根据绑定的 OAuth 参数完成授权码流程
//      d. 重定向到 client 的 redirect_uri 带 code

// GET /auth/magic-link/verify?token=xxx
//   成功: 302 redirect to client's redirect_uri?code=xxx&state=xxx
//   失败: 显示错误页面 + 重试链接
```

#### 2. 登录 SPA Magic Link UI

登录页新增"免密登录"模式：

```
┌────────────────────────────────────┐
│           登录                      │
│                                    │
│  [密码登录] [免密登录]  ← tab 切换 │
│                                    │
│  输入邮箱地址，我们将发送登录链接：  │
│  ┌──────────────────────────────┐  │
│  │ you@example.com              │  │
│  └──────────────────────────────┘  │
│                                    │
│  [      发送登录链接       ]       │
│                                    │
│  或 <a>使用密码登录</a>           │
└────────────────────────────────────┘

发送后:
┌────────────────────────────────────┐
│  ✓ 链接已发送！                    │
│  请查收 your@example.com 的邮件    │
│  链接有效期为 15 分钟              │
│                                    │
│  [重新发送] [更换邮箱]             │
└────────────────────────────────────┘
```

#### 3. Magic Link 与现有基础设施的集成

```
TempTokenStore（已存在）→ 存储 magic_token → OAuth 参数绑定
EmailSender（已存在）   → 发送 magic link 邮件
  → 新增 magic_link.tmpl 模板
  → 支持自定义品牌（与 login SPA 共用 branding 配置）

与现有登录流程的交互:
  - 如果用户已有 session cookie → 直接完成授权（silent auth）
  - 如果用户是新用户 → 可选自动注册（与 signup 流程集成）
  - 如果 client 配置了 prompt=consent → 完成 auth code 后显示 consent 页
```

#### 4. 安全设计

```
Token 设计:
  - magic_token = crypto/rand 生成 32 字节 → base64url（43 字符）
  - single-use（消费后立即删除）
  - TTL = 15 分钟（可配置，`WithMagicLinkTTL`）
  - 绑定: client_id + redirect_uri + code_challenge + nonce + 原始 IP
  
防滥用:
  - 每邮箱每 60 秒限 1 次请求（与现有 ratelimit 集成）
  - 每次新的 magic link 发送使旧 token 失效（轮换模式）
  - 失败尝试（无效 token）计入账户锁定的失败计数
  
防钓鱼:
  - 邮件中显示登录上下文（浏览器、IP、地理位置近似值）
  - "如果不是你请求的登录，请忽略此邮件"
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 用户点击过期链接 | 显示"链接已过期"页面 + "重新发送"按钮，不暴露账户是否存在 |
| 同一邮箱有多个未完成的登录请求 | 每个新请求使旧 token 失效（防止多设备竞争） |
| 邮件发送失败 | 回复统一 `{"status":"sent"}` + 异步记录发送失败日志（不暴露失败信息） |
| 用户用 Magic Link 登录后还想要密码 | 保持密码认证可用。Magic Link 和密码是两种独立的认证方式 |
| IP 与原始请求 IP 不匹配（链接在不同网络点击） | 允许（用户在手机上点击邮件）。但如果差异过大（跨国家），标记为可疑并触发 step-up |
| 攻击者截获了 Magic Link | TTL 短 + single-use + 登录后通知原邮箱"新设备已登录" |

### 为什么值得做

**Magic Link 是消费者身份认证的"黄金路径"。** Slack、Medium、Notion、  
Calendly——几乎所有现代 SaaS 都提供邮箱免密登录。它的产品价值：  
① 降低登录摩擦（不用记密码、不用打开密码管理器）；② 提高注册转化率  
（一键开始使用）；③ 减少密码重置请求（不再忘记密码）。  
**本项目已有 EmailSender 和 TempTokenStore 基础设施，Magic Link 的  
后端实现仅需约 300 行 Go + 一个邮件模板 + SPA 的 100 行 JS。**  
这是"投入产出比极高"的典型方向。

- **价值：** 高（消费者 UX 刚需 + 低摩擦注册 + 减少密码重置支持成本）  
- **工作量：** M（后端约 300 行 + 邮件模板 + SPA UI 约 100 行）  
- **依赖：** `EmailSender`（已存在）、`TempTokenStore`（已存在）、  
  `authenticators.CodeStore`（已存在，可选用于令牌绑定）

---

## 方向 3：推送通知基础设施与移动认证 SDK（Push Notification + Mobile Auth）

### 现状

项目支持推送 MFA（通过 `push_mfa_provider.go` + `push_webhook.go`），但  
这是**webhook 模式**——客户必须自己托管一个接收 webhook 并将其转换为推送  
通知的服务。不存在内置的推送通知基础设施。

| 能力 | 状态 |
|---|---|
| 推送 MFA 挑战生成 | ✅ `push_mfa_provider.go` — 生成挑战 + 等待批准/拒绝 |
| 推送 MFA webhook 发送 | ✅ `push_webhook.go` — POST 到客户配置的 webhook URL |
| 推送 MFA 轮询完成 | ✅ `server_mfa.go` 的 MFA 端点 |
| **FCM (Firebase Cloud Messaging) 推送集成** | ❌ 零实现 |
| **APNS (Apple Push Notification Service) 集成** | ❌ 零实现 |
| **设备推送令牌注册 API** | ❌ 零实现 |
| **移动 SDK (iOS/Android)** | ❌ 零实现 |
| **推送通知品牌化** | ❌ 零实现 |
| **推送登录审批（不仅仅是 MFA）** | ❌ 零实现 |

### 缺口（grep 核验）

- `FirebaseCloudMessaging` / `fcm` / `FCM`：**零实现命中**（`FirebaseCloud` 的 grep  
  结果与推送无关）
- `apns` / `APNS`：**零实现命中**  
- `infrastructure/push/` 或 `infrastructure/notification/`：**目录不存在**  
- `device.*token` / `DeviceToken` / `device.*register` / `DeviceRegister`：**零实现命中**  
  （`trusted_device_test.go` 中的 device 是浏览器指纹，不是移动设备推送令牌）
- 没有 `PushNotificationSender` SPI 或 `MobileDeviceStore` SPI
- 没有移动端 SDK 的 Go 端对应物（苹果/谷歌都不需要 Go SDK，但需要一个管理 API）

### 范围

#### 1. 推送通知 SPI（`infrastructure/fcm/` + `infrastructure/apns/`）

```go
// shared/spi/push.go — 新文件

// PushNotification represents a push message payload.
type PushNotification struct {
    Title    string
    Body     string
    Category string   // "mfa_approve", "login_alert", "account_recovery"
    Data     map[string]string  // 自定义数据（challenge_id, client_name, ip, time）
}

// PushSender sends push notifications to mobile devices.
type PushSender interface {
    Send(ctx context.Context, deviceToken string, notification PushNotification) error
    Supports(ctx context.Context, platform DevicePlatform) bool
}

type DevicePlatform string

const (
    PlatformiOS     DevicePlatform = "ios"
    PlatformAndroid DevicePlatform = "android"
)
```

**FCM 实现（`infrastructure/fcm/sender.go`）**：

```go
// 选项模式:
// fcm.NewSender(credentialsJSON, opts...)
//   实现 PushSender 接口
//   使用 Firebase Admin SDK 的 HTTP v1 API
//   支持 Android 和 iOS 通道
```

**APNS 实现（`infrastructure/apns/sender.go`）**：

```go
// 选项模式:
// apns.NewSender(authKey, keyID, teamID, opts...)
//   实现 PushSender 接口
//   使用 HTTP/2 + TLS 与 Apple APNS 通信
//   支持生产/开发环境
```

#### 2. 设备注册 API

```go
// 新增端点:
// POST /me/devices — 注册当前用户的移动设备
//   Request:  {platform, device_token, push_token?}
//   Response: {device_id, created_at}
//   Scope:    me 范围（用户自己管理自己的设备）
//
// DELETE /me/devices/:device_id — 注销设备
// GET /me/devices — 列出已注册设备

// 管理员端点:
// GET /api/v1/admin/users/:id/devices — 查看用户注册设备
// DELETE /api/v1/admin/users/:id/devices/:device_id — 远程注销设备
```

#### 3. 推送 MFA 体验升级

```
当前流程:  用户登录 → MFA 要求 → 轮询等待 → webhook → 用户批准 → 完成

升级流程:  用户登录 → MFA 要求 → 服务端直接调用 FCM/APNS → 
          用户手机收到推送通知（"是否尝试登录？"）→ 点击批准 → 完成

优势:
  - 无需客户维护 webhook 服务
  - 推送送达率更高（FCM/APNS 有持久连接）
  - 支持推送中显示上下文（地点、设备、时间）
  - 支持"登录审批"操作（不只是点头），可以显示拒绝按钮
```

#### 4. 推送登录审批（不仅仅是 MFA）

```
扩展推送的使用场景:

| 场景 | 推送内容 | 操作 |
|---|---|---|
| MFA 第二因素 | "来自 Chrome 的登录请求" | 批准 / 拒绝 |
| 新设备登录提醒 | "新设备在旧金山登录" | 是/否 + "这是我" / "不是我，请保护账户" |
| 敏感操作审批 | "管理员 Alice 请求导出审计日志" | 批准 / 拒绝 + 即时通知 |
| 账户恢复确认 | "有人正使用邮箱恢复你的账户" | 批准 / 拒绝 |
```

#### 5. 推送令牌轮换与生命周期管理

```
设备推送令牌有生命周期:
  - 应用重新安装 → 新令牌
  - iOS 推送令牌定期轮换（约 3 个月）
  - 用户卸载应用 → 推送失败 → 标记设备为失效

管理策略:
  - 推送发送失败时（FCM/APNS 返回 `InvalidRegistration`/`Unregistered`）
  - 自动标记 device_token 为失效
  - 从活跃推送目标列表中移除
  - 审计记录: push_token_invalidated
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 用户卸载应用后仍有推送 | FCM/APNS 返回不可送达错误 → 标记令牌失效 |
| 用户拒绝推送权限 | 优雅降级到 SMS 或 TOTP MFA |
| 多设备推送 | 向用户所有注册设备发送推送，任一设备批准即通过 |
| 推送延迟 | 推送 MFA 的超时应比 TOTP 更长（默认 120 秒 vs 30 秒） |
| 国际推送合规 | FCM 支持中国区域（通过 Google Play 服务），APNS 在中国由独立集群处理 |

### 为什么值得做

**推送 MFA 是 MFA 方法中用户体验最好的（没有之一）。** 用户只需看一眼手机、  
点一下批准，比 TOTP 输入 6 位数字、SMS 等待短信快得多。对于企业客户，  
推送 MFA 是 Okta / Duo 的杀手级功能——而本项目目前需要客户自建推送  
基础设施才能使用。增加 FCM/APNS 作为可选的推送渠道（仍保留 webhook 模式  
为自建选项），可以**直接为客户提供开箱即用的推送 MFA 体验**。同时，推送  
基础设施也为后续的移动 SDK、登录审批、安全通知铺平了道路。

- **价值：** 中高（产品差异化 + 推送 MFA 体验优势 + 企业客户刚需）  
- **工作量：** L：
  - Phase 1：PushSender SPI + FCM 实现 + APNS 实现（M）
  - Phase 2：设备注册 API + 推送生命周期管理（M）
  - Phase 3：推送登录审批 + 安全通知（S）
- **依赖：** `PushMFAProvider`（已存在，`push_mfa_provider.go`）、  
  `push_webhook.go`（已存在，可作为回退方案）

---

## 方向 4：令牌与会话生命周期治理面板（Security Operations Dashboard）

### 现状

项目拥有完整的令牌和会话管理 API：

| 能力 | 位置 | 状态 |
|---|---|---|
| 管理员列出 session | `POST /api/v1/admin/sessions` | ✅ 已实现 |
| 管理员撤销 session | `POST /api/v1/admin/tokens/revoke` | ✅ 已实现 |
| 用户列出自己的 session | `GET /me` (active_sessions) | ✅ 已实现 |
| 用户撤销自己的 session | `POST /me/revoke-session` | ✅ 已实现 |
| 令牌组合（portfolio）API | `domains/tokenusage/portfolio.go` | ✅ 已实现 |
| 管理员会话页面 | `admin/app.js:1127` sessions panel | ✅ 基础实现 |
| 条件访问策略 | `domains/conditionalaccess/` | ✅ 已实现 |
| 威胁动作响应 | `domains/threataction/` | ✅ 已实现 |
| 异常检测 | `domains/anomaly/` | ✅ 已实现 |
| **安全运维面板（整合以上能力）** | ❌ 零实现 |
| **会话地理分布可视化** | ❌ 零实现 |
| **令牌使用趋势分析** | ❌ 零实现 |
| **批量会话操作（按 IP/用户/区域）** | ❌ 零实现 |
| **会话风险评分** | ❌ 零实现 |
| **安全事件时间线** | ❌ 零实现 |

### 缺口（grep 核验）

- `sessions.*map` / `sessions.*geo` / `sessions.*geolocation` / `session.*map`：**零实现命中**
- `token.*inventory` / `token.*overview` / `token.*summary` / `token.*analytics`：**零实现命中**
- `bulk.*revoke` / `bulk.*terminate` / `BulkRevoke` / `BulkTerminate`：**零实现命中**
- `session.*risk.*score` / `session.*anomaly` / `SessionRisk`：**零实现命中**
- `security.*dashboard` / `SecurityDashboard` / `security.*ops` / `SecurityOps`：**零实现命中**
- `admin/app.js` 中的 sessions 页面**只有表格列表 + 逐条撤销**，没有聚合视图、  
  没有图表、没有过滤、没有批量操作、没有地图
- 后端 `tokenusage/portfolio.go` 提供的 API 未被任何前端消费（仅用于 admin RPC）
- 异常检测结果（`domains/anomaly/`）未被可视化到 admin 面板

### 范围

#### 1. 安全运维面板（Admin Console 新页面）

在 Admin Console SPA 中新增 "Security" 导航项，包含以下面板：

```
Security Dashboard（安全总览）
├── Active Sessions（活跃会话）
│   ├── 总数、趋势图（24h/7d/30d）
│   ├── 按用户排序的 Top 10
│   ├── 按区域/国家的分布（地图或列表）
│   ├── 批量操作: 选中 → 终止 / 标记可疑
│   └── 搜索: 按用户、IP、设备、区域
│
├── Token Portfolio（令牌组合）
│   ├── 活跃令牌总数（access + refresh + id）
│   ├── 令牌类型分布（Bearer / DPoP / mTLS-bound）
│   ├── Scope 分布（admin / openid / email / custom）
│   ├── 令牌创建率（time-series chart）
│   └── 令牌撤销率（按原因分类）
│
├── Anomaly Alerts（异常告警）
│   ├── 当前告警列表（按严重程度排序）
│   ├── 每个告警的详情（检测器、置信度、关联实体）
│   ├── 响应操作（忽略 / 标记已处理 / 触发威胁动作）
│   └── 告警历史 + 趋势
│
└── Threats & Actions（威胁与响应）
    ├── 活跃威胁动作列表（按策略分组）
    ├── 受影响用户数 / 令牌数
    ├── 动作效果（已撤销令牌数、已禁用用户数）
    └── 执行历史
```

#### 2. Session 增强 API

```go
// 新增端点:
// GET /api/v1/admin/security/sessions — 会话列表（增强版）
//   Query: user_id, ip, region, device, status, risk_level
//   Response: {sessions: [{id, user_id, ip, region, device, 
//                          created_at, last_active, risk_score, 
//                          anomaly_flags: [...]}]}

// POST /api/v1/admin/security/sessions/terminate — 批量终止
//   Request:  {session_ids: [...], user_ids: [...], filters: {ip:, region:, user_id:}}
//   Response: {terminated: N, failed: N}

// GET /api/v1/admin/security/sessions/stats — 会话统计
//   Response: {total_active, by_region: {...}, by_device: {...},
//              trend: [{ts, count}...], top_users: [...]}

// GET /api/v1/admin/security/timeline — 安全事件时间线
//   Query: from, to, severity, type
//   Response: {events: [{ts, type, severity, summary, actor, target}]}
```

#### 3. 会话风险评分

利用现有的异常检测基础设施（`domains/anomaly/`）为每个会话计算风险评分：

```go
// 风险因子（可配置权重）:
//   - 异常地理位置（与历史登录位置不同）
//   - 异常设备（首次从该设备登录）
//   - 异常时间（非用户活跃时段）
//   - 异常 IP（已知代理/VPN/恶意 IP）
//   - 同时登录的会话数过多
//   - 失败的 MFA 尝试

// 风险评分输出:
//   0-20:  低风险（绿色）
//   21-50: 中风险（黄色）
//   51-80: 高风险（橙色）
//   81-100: 严重（红色，自动触发威胁动作）
```

#### 4. SSE 实时更新

利用已有的 SSE 基础设施（`sse.Broker` + `HandleStream`）推送实时更新：

```
当新异常告警产生  →  安全面板自动更新告警计数
当会话被批量终止  →  面板显示实时完成进度
当某用户被锁定    →  面板通知安全管理员
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 安全面板数据的隐私 | 安全面板显示的内容受 `admin:security` scope 保护，与常规 admin 权限分离 |
| 会话数据规模大（百万级） | 后端 API 必须分页 + 聚合统计使用预计算（而非实时扫描） |
| 管理员误操作（批量终止） | 每次批量操作前二次确认 + 操作可回滚（reissue tokens） + 详细审计日志 |
| 安全面板的实时性要求 | SSE 推送实时告警 + 面板数据每 30 秒自动刷新（非轮询） |
| 跨区域部署的会话聚合 | 如果多区域部署且无全局 session store，会话列表仅显示当前区域；全局聚合需 `cluster.Bus` |

### 为什么值得做

**安全运维面板是"身份基础设施""到"身份安全平台"的分水岭。** 在今天，  
管理员需要通过 4-5 个不同 API（sessions、token、anomaly、conditionalaccess、  
threataction）和多个 CLI 工具来理解系统的安全状态。将这些能力整合到一个  
**专门的安全运维面板**中，可以让安全管理员快速发现异常、评估影响、采取  
行动——而不是在 API 和日志之间手动关联。**这是 ROADMAP v5.0 方向①  
（Admin Console SPA）的自然延伸：用户管理和客户端管理已经就绪，现在是  
安全运维管理面。**

- **价值：** 高（企业安全运维刚需 + 产品差异化 + 管理员效率提升）  
- **工作量：** L（后端 API 增强 + SPA 新页面 + SSE 集成）  
- **依赖：** `tokenusage/portfolio.go`（已存在）、`domains/anomaly/`（已存在）、  
  `domains/threataction/`（已存在）、`sse.Broker`（已存在）

---

## 方向 5：令牌敏感度分类与自适应保护（Token Sensitivity Classification）

### 现状

目前所有 access_token 的签发遵循相同的安全策略——同一签名算法、同一 TTL  
（按 client 配置）、同一令牌绑定策略（全局 DPoP 或 mTLS）。不存在基于  
令牌所含权限的差异化保护。

| 能力 | 状态 |
|---|---|
| 令牌签发 | ✅ 统一签发，TTL 基于 client 配置 |
| DPoP 绑定 | ✅ 全局开启或关闭（请求头触发） |
| mTLS 绑定 | ✅ 全局开启或关闭 |
| Refresh 轮换 | ✅ 统一策略（所有 refresh 使用相同轮换逻辑） |
| **Scope 感知的令牌保护** | ❌ 零实现 |
| **高敏感度令牌自动缩短 TTL** | ❌ 零实现 |
| **刷新续期高敏感令牌需 step-up** | ❌ 零实现 |
| **DPoP 强制用于 admin scope** | ❌ 零实现 |
| **敏感 scope 的增强审计** | ❌ 零实现 |
| **令牌敏感度标签传播** | ❌ 零实现 |

### 缺口（grep 核验）

- `token.*sensitivi` / `TokenSensitivity` / `token.*classifi` / `TokenClassif`：**零实现命中**  
- `scope.*sensitivi` / `ScopeSensitivity` / `scope.*classifi` / `ScopeClassif`：**零实现命中**  
- `token.*trust.*level` / `TokenTrustLevel` / `token.*protect.*level` / `TokenProtectLevel`：**零实现命中**  
- `high.*value.*token` / `HighValueToken` / `sensitive.*token` / `SensitiveToken`：**零实现命中**  
- `token.*policy.*enforce` / `TokenPolicyEnforce`：仅 `rootcov_token_policy_enforce_test.go`  
  存在文件引用，但内容是**token 策略的基础校验**（不是敏感度分类）

所有令牌签发路径（`defaultimpl/{ed25519,ecdsa,rsa}_jwt_issuer.go`）使用统一  
的 `IssueToken(ctx, claims, ttl)` 方法——无 scope 感知的逻辑分支。

### 范围

#### 1. 令牌敏感度分类体系

```go
// shared/core/token_classification.go — 新文件

// TokenSensitivityLevel defines how sensitive a token's granted access is.
type TokenSensitivityLevel int

const (
    TokenSensitivityStandard  TokenSensitivityLevel = 0  // openid, email, profile
    TokenSensitivityElevated  TokenSensitivityLevel = 1  // offline_access, custom scopes
    TokenSensitivityHigh      TokenSensitivityLevel = 2  // admin:read, data:read
    TokenSensitivityCritical  TokenSensitivityLevel = 3  // admin:write, payment:*, data:write
)

// TokenSensitivityPolicy defines the protection requirements per level.
type TokenSensitivityPolicy struct {
    Level             TokenSensitivityLevel
    MaxTTL            time.Duration
    RequireBinding    BindingType       // none, dpop, mtls
    RefreshStepUp     bool              // require step-up on refresh
    EnhancedAudit     bool              // log full request context
    RefreshFamilyIsolation bool         // separate refresh family from lower tokens
    ProactiveExpiryOnRisk bool          // expire when risk signal received
}

// BindingType specifies the required token binding mechanism.
type BindingType int

const (
    BindingNone      BindingType = iota
    BindingDPoP
    BindingMTLS
)
```

#### 2. Scope → Sensitvity 映射

```go
// configurable scope classification:
//   默认映射（可通过 WithScopeSensitivity 覆盖）:
//   "openid", "email", "profile" → Standard
//   "offline_access", "address", "phone" → Elevated
//   "admin:read", "audit:read", "data:read" → High
//   "admin:write", "payment:*", "data:write", "user:impersonate" → Critical

func DefaultScopeSensitivity() map[string]TokenSensitivityLevel {
    return map[string]TokenSensitivityLevel{
        "openid":          TokenSensitivityStandard,
        "email":           TokenSensitivityStandard,
        "profile":         TokenSensitivityStandard,
        "address":         TokenSensitivityElevated,
        "phone":           TokenSensitivityElevated,
        "offline_access":  TokenSensitivityElevated,
        "admin:read":      TokenSensitivityHigh,
        "admin:write":     TokenSensitivityCritical,
        // 自定义 scope 可通过 WithScopeSensitivity(scope, level) 注册
    }
}
```

#### 3. 签发时自适应保护

```go
// 在 TokenIssuer.IssueToken 中新增逻辑:
func (s *Server) issueTokenWithPolicy(ctx context.Context, claims *Claims, requestedTTL time.Duration) (*Token, error) {
    // 1. 从请求的 scope 计算敏感度级别
    sensitivity := s.evaluateScopeSensitivity(claims.Scopes)
    
    // 2. 获取对应的保护策略
    policy := s.getPolicyForSensitivity(sensitivity)
    
    // 3. 应用策略约束
    //    a. TTL: min(requestedTTL, policy.MaxTTL)
    //    b. 绑定: 如果 RequireBinding != none，确保令牌已绑定
    //    c. 审计: 如果 EnhancedAudit，记录完整请求上下文
    effectiveTTL := min(requestedTTL, policy.MaxTTL)
    
    // 4. 对刷新续期应用 step-up 要求
    if isRefresh && policy.RefreshStepUp {
        // 要求用户在 /auth/login 重新认证后才续期
        return ErrStepUpRequired
    }
    
    // 5. 对高级别令牌使用独立的 refresh family
    if policy.RefreshFamilyIsolation {
        // 敏感令牌的 refresh token 不与低级别令牌共享 family
        // 即使敏感令牌的 refresh 被轮换，低级别令牌不受影响
    }
    
    return s.issueSignedToken(ctx, claims, effectiveTTL)
}
```

#### 4. 增强审计（Critical 级别）

```
对于 Critical 级别的令牌签发和消费:
  - 每次令牌签发记录: 完整 scope 列表、IP、User-Agent、地理位置、会话 ID
  - 每次令牌使用记录: 请求路径、IP、User-Agent（通过自省或请求日志）
  - 令牌撤销记录: 撤销原因、撤销者（管理员 / 用户 / 自动）
  - 审计事件类型: token_issued_critical, token_used_critical, token_revoked_critical
  
审计事件传播:
  始终使用 SetMeta(e, k, v) 添加到审计事件中
  实施独立的 SIEM 转发策略（优先发送、单独队列）
```

#### 5. Refresh Family 隔离

```go
// 当前: 所有 scope 共享同一个 refresh family。
//       一个低安全级别的 refresh token 被轮换时，高安全级别的也会失效。
//
// 改造后: 
//   场景: 用户有两个 refresh token:
//     RT_A（openid + email）— Standard 级别
//     RT_B（admin:write）— Critical 级别
//   
//   如果 RT_A 被轮换（正常使用），RT_B 不受影响（不同 family）。
//   如果 RT_B 被轮换（正常使用），RT_A 不受影响（不同 family）。
//   只有相同敏感度级别的 refresh token 共享 family。
//
//   异常: 如果 RT_B 被检测到重用（family reuse attack），
//   所有与该 family 相关的令牌都被撤销（保持现有安全保证）。
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 混合 scope 的令牌 | 取所有请求 scope 的最高敏感度级别（保守原则） |
| 后续 scope 升级（通过 token exchange 添加高敏感 scope） | 如果原有令牌敏感度低于新 scope，要求重新认证（step-up） |
| 令牌在途中 scope 被提升（策略变更） | 现有令牌不受影响（策略 only 影响新签发），通过 `/token/introspect` 可以查询策略版本 |
| DPoP 强制要求的回退 | 如果 client 不支持 DPoP 但请求了 `admin:*` scope → 返回 `invalid_scope` + 提示启用 DPoP |
| 跨区域部署的策略一致性 | 策略通过 cluster.Bus 同步（新增 `KindTokenSensitivityPolicyChange`） |

### 为什么值得做

**令牌敏感度分类是纵深防御体系的基础设施。** 在今天，一个 scope 为 `openid`  
的令牌和一个 scope 为 `admin:write` 的令牌具有相同的安全属性（TTL、绑定、  
审计）。这意味着：如果你的 refresh token 泄露，攻击者可以获得所有 scope 的  
访问权限——包括 `admin:write`。通过将令牌保护与 scope 敏感度绑定，可以在  
不改变协议行为的前提下，为高价值操作提供更强的安全保障。**这是"令牌安全"  
的下一个进化方向**——从"令牌是否有效"到"令牌的信任度是否匹配所请求的操作"。  
同时，这也是条件访问策略的令牌级实现——条件访问评估"用户+设备+位置"，  
令牌敏感度评估"令牌本身携带的权限"。

- **价值：** 中高（安全架构升级 + 纵深防御 + 合规基础）  
- **工作量：** L 但可分阶段：
  - Phase 1：敏感度分类 SPI + scope 映射 + TTL 缩短（M）
  - Phase 2：DPoP 强制 + Refresh 家庭隔离 + 增强审计（M）
  - Phase 3：Refresh step-up + 主动风险过期（M）
- **依赖：** JWT 签发器（已存在）、Scope 验证（已存在）、DPoP/mTLS（已存在）、  
  Refresh Token 轮换（已存在）

---

## 五方向优先级总览

| # | 方向 | 价值 | 工作量 | 独立性 | 与现有功能的关系 | 建议时机 |
|---|---|---|---|---|---|---|
| 1 | 自助账户恢复 + IAL | 高（安全底线） | L（分期） | 较独立（新增 SPI + API） | 依赖 EmailSender（已存在） | **P1 — 立即开始** |
| 2 | Magic Link 免密登录 | 高（消费者 UX） | M | 较独立（新增端点 + 模板） | 依赖 EmailSender + TempTokenStore（均已存在） | **P1 — 立即开始** |
| 3 | 推送通知基础设施 | 中高（产品差异化） | L（分期） | 独立（新增 SPI + FCM/APNS 子模块） | MFA PushProvider 已存在，可扩展 | **P1 — 与 1/2 并行** |
| 4 | 安全运维面板 | 高（企业安全） | L（整合） | 中等（依赖后端 API 增强） | 依赖 anomaly / threataction / tokenusage（均已存在） | **P2 — 方向 1 之后** |
| 5 | 令牌敏感度分类 | 中高（安全架构） | L（分期） | 较独立（新增 SPI + 签发集成） | 依赖 JWT Issuer / DPoP / Refresh（均已存在） | **P2 — 方向 4 同时** |

**建议执行策略：**

- **并行启动（P1）**：方向 ①（自助账户恢复）+ 方向 ②（Magic Link）+ 方向 ③  
  （推送通知）。三者分别覆盖账户恢复、消费者免密登录、企业推送 MFA，互不  
  冲突且独立交付。方向 ③ 的 Phase 1（PushSender SPI + FCM）可先交付，  
  移动 SDK 后续。
- **重叠推进（P2）**：方向 ④（安全运维面板）+ 方向 ⑤（令牌敏感度分类）。  
  方向 ④ 主要是管理面 UI + API 增强（面向安全运维人员），方向 ⑤ 主要是  
  后端安全架构（面向系统架构师）。可以由不同团队并行推进。
- **跨方向依赖**：
  - IAL（方向 ① Phase 2）的证明级别 → 可作为方向 ⑤ 的敏感度计算输入  
    （IAL2 用户可签发 Critical 级别令牌，IAL1 用户不可）
  - 推送通知（方向 ③）的推送通道 → 可复用为方向 ① 的账户恢复通知通道  
    （"你的账户已被恢复"推送通知）
  - 安全运维面板（方向 ④）的异常告警 → 可触发方向 ⑤ 的主动风险过期  

**一句话总结：方向 ① + ② 补齐身份生命周期的"最后一段旅程"（丢失后的恢复  
和首次访问的免密登录）；方向 ③ 提供开箱即用的推送 MFA 体验；方向 ④ 将  
安全能力整合为运维工具；方向 ⑤ 建立纵深令牌安全架构。** 这四个方向共同  
将项目从"功能完整的 OAuth/OIDC 服务器"推进到"企业级身份安全平台"。

---

## 附录：本报告未覆盖但值得关注的边缘能力

以下问题粒度过小不足以独立成方向，但在方向 ③ 或 ④ 的实施过程中值得一并考虑。

### B.1 WebAuthn 跨设备凭证同步（Cloud Passkey Sync）

WebAuthn 发现式凭据（passkey）支持跨设备同步（iCloud Keychain、Google  
Password Manager、Bitwarden 等）。但本项目目前没有检测 passkey 是否通过  
云同步的机制。同步的 passkey 和硬件绑定的 passkey 应可区分——企业客户  
可能要求仅允许硬件绑定的 passkey 访问敏感数据。这需要：
1. 在 WebAuthn 注册时记录 `credentialProtectionPolicy` 和传输方式
2. 在认证时评估凭据的"来源强度"（硬件 vs 同步）
3. 条件访问策略中增加 `passkey_origin` 条件

### B.2 密码策略引擎（Composable Password Policy）

目前密码验证的逻辑分散在 `internal/adminuser/validation.go`（管理员创建用户）、  
`authenticators/stored_password.go`（认证验证）和 `shared/spi/reg_gate.go`  
（注册门禁）中。没有统一的可配置密码策略引擎。对于需要 NIST SP 800-63B  
或 PCI-DSS 密码合规性的企业客户，需要：
1. `PasswordPolicy` 配置结构体（minLength、complexity、history、age、maxAge）
2. 统一的验证入口（所有密码设置/更改都经过同一个策略引擎）
3. 审计事件记录策略违规

### B.3 跨区域令牌吊销延迟的运维可观测性

目前跨区域令牌吊销通过 `cluster.Bus` 广播（`KindTokenRevoked`），但管理员  
无法知道吊销消息是否已到达所有副本。建议在 `/readyz` 或管理员 API 中增加  
`cross_region_revocation_lag` 指标，显示最慢副本的确认延迟。

### B.4 会话元数据扩展（设备指纹丰富化）

当前 session 记录包含 `device` 字段（来自 User-Agent），但在条件访问策略  
中，设备类型是一个重要维度。建议扩展 SessionMetadata：
- `device_fingerprint`（来自 conditionalaccess 模块）
- `device_trust_score`（来自 trusted device 模块）
- `ip_risk_score`（来自 IP 失败计数器或外部威胁情报）
- `last_geo_location`（来自 geo 模块）

这些元数据可以直接被方向 ④ 的安全面板消费，也可以被条件访问策略使用。

---

*本报告基于 2026-07-11 全代码库全局扫描（2241 `.go` 文件、4 个嵌入式 SPA、  
200+ 包），通过 grep 对抗核验确认所有缺口。所有方向均经确认未被  
`ROADMAP.md` v5.0、`deferred-backlog.md`、`expansion-directions-v7-analysis.md`  
或 `expansion-directions-v8-analysis.md` 覆盖。*
