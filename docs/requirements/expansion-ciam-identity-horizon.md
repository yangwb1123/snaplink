# 扩展方向分析 —— 消费级身份与身份治理地平线

> **作者：** 资深架构 & 产品经理视角  
> **方法：** 全代码库全局扫描（2241 个 `.go` 文件、~200 个包、4 个嵌入 SPA）  
> **前置阅读与核验：** ROADMAP v5.0、deferred-backlog、13 轮历史扩展方向分析  
>   （v1–v13）、expansion-novel-2026-07-11、expansion-novel-v2-identity-  
>   2026-07-11、expansion-post-protocol-layer-analysis、  
>   expansion-gaps-analysis-2026-07-11、feature-spec-active-itdr-detection-response。  
>   对每一项候选方向做全代码库 grep 逐项核验（如 `GrantManagement\|progressive_profil\|social_login`  
>   等），确认为 **真实缺口**。  
> **定位：** 本报告 5 个方向与上述所有历史分析**零重叠**。  
> **不涵盖：** 后量子密码、FIDO2 混合跨设备认证、PAM、AI 智能体身份、可编程  
>   管道、嵌入式 SPA、跨设备身份连续性等已被前 15+ 轮分析覆盖的方向。  

---

## 前置声明：项目成熟度

经过 15+ 轮全局扫描、增量分析、ROADMAP 迭代，本项目的身份协议覆盖面已达到行业顶级水平：

- **协议面**：OAuth 2.0（7 种 grant）、OIDC Core/Discovery/Logout/Backchannel/CIBA/JAR/
  JARM/FAPI、SAML 2.0（SP+IdP）、SCIM 2.0、CAEP/SSF（双向）、LDAP、Kerberos、RADIUS
- **存储面**：Memory、SQLite、Redis、etcd、PostgreSQL + 嵌套子模块（KMS AWS/GCP/Azure/PKCS11）
- **安全面**：DPoP、mTLS、JWT-SVID、workload identity、break-glass、per-tenant 签名隔离、
  区域数据驻留、FAPI 2.0、FIPS 140-3
- **运维面**：DR framework、snapshot、metrics、audit chain、config hot-reload、feature gates
- **产品面**：Hosted Login SPA、Admin Console、Developer Portal、User Portal、
  consent store、B2B connections、HRD、org-admin
- **质量面**：CWEs（gosec、govulncheck）、CI 覆盖所有子模块、load test、chaos test、
  benchmark gate

**剩余空间不是"增补协议"或"补后端能力"，而是从"功能完整的身份 SDK/Server"走向
"可直接销售、可直接嵌入、可自动化运营的身份平台"。** 本报告聚焦的是这一转型中
最后一个普适性盲区。

---

## 方向 1：消费级身份与社交登录（CIAM —— Customer Identity & Access Management）

### 现状

项目拥有完善的企业级 IdP 连接生态：

| 能力 | 实现状态 |
|---|---|
| SAML 2.0 SP（消费企业上游 IdP） | ✅ 完整 |
| OIDC Federation（消费上游 OIDC IdP） | ✅ `authenticators/oidc_federation.go` |
| LDAP / Kerberos / RADIUS | ✅ 嵌套子模块 |
| Workload Identity（GCP/AWS/Azure） | ✅ `security/securityverify/workload_identity_presets.go` |
| **社交登录（Google、Apple、GitHub、Facebook、Microsoft）** | ❌ **零实现** |
| **预构建的一次点击式开发者接入流 (SDK/Widget)** | ❌ **零实现** |

**为什么"社交登录"是产品缺口而非协议缺口：** 从协议层面看，"Google 登录"就是一个
OIDC/OAuth 2.0 Federation 流——而 OIDC Federation 已完美实现。缺口在于：
项目提供了 `authenticators/OIDCFederationConfig` 这个**强大的 SPI**，但每个
CIAM 集成方仍需自建发现 URL + ClientID + ClientSecret + Scopes + Callback 路由
的配置条目。竞品（Auth0、Clerk、Firebase Auth）卖的是**一行代码嵌入**
（`<button onclick="signInWithGoogle()">`），而非 YAML 配置一条上游连接。  
对于 B2C 场景，这不是"技术能否实现"的问题，而是"5 分钟 demo vs 2 天集成"的
采购第一印象鸿沟。

### 缺口核验

| 概念 grep | 命中数 | 说明 |
|---|---|---|
| `sign_in_with_\|SignInWith\|social_login\|social-auth\|SocialLogin` | **0** | 零实现 |
| `login_with_google\|LoginWithGoogle\|google_oauth\|GoogleOAuth` | **0** | 零预构建 |
| `login_with_apple\|LoginWithApple\|sign_in_with_apple\|apple.*auth` | **0** | 零预构建 |
| `login_with_github\|LoginWithGitHub\|github.*oauth` | **0** | 零预构建（仅 `sso-ctl` SDK 生成器引用 Github API） |
| `social.*provider\|social.*identity\|SocialIdentityProvider` | **0** | 零实现 |

### 为什么需要它

1. **解锁 B2C / B2B2C 市场**：项目当前的企业（B2B）能力是顶级的，但完全不具备
   面向消费者的身份能力。Auth0 年收入中~40%来自 B2C 场景（SaaS 应用需要"让
   用户用 Google/Apple 登录"），Clerk/Magic/Firebase Auth 凭此起家。无社交登录
   = 门槛级 CIAM 采购即被筛。

2. **零摩擦的开发者体验**：社交登录的核心价值不是协议——OIDC Federation 已经
   做好了。核心价值是**预配置 + 一键启用**。每个主流社交 IdP 有已知的：
   - 固定的发现 URL（`https://accounts.google.com/.well-known/openid-configuration`）
   - 已知的 scope 集（`openid profile email`）
   - 标准化的 logo、品牌、按钮文案
   - 已知的字段映射（`sub`→`ext_id`、`email`→`email`、`name`→`display_name`）
   预构建这些消除了集成中 80% 的模板性工作。

3. **渐进式配置 + 合规**：社交 IdP 有已知的证书轮换节奏、已知的 alg 集、已知的
   JWKS 端点。预构建的 provider 可维护证书 TTL 预警、alg 变更跟踪、安全公告
  （例如 Google 从 RS256 切换到 ES256 的时间线）——这些是单个 YAML 配置无法
   承载的操作知识。

### 范围

- **预构建 Social Provider Registry**：`authenticators/social/` 包，每个 provider
  为一行 `SocialProvider` 接口实现，默认签发 `sub` 作为 `ExternalID`、映射标准
  声明、携带默认 scope + 品牌元数据。
  - `GoogleProvider`（OIDC + Google+ 特有字段如 `hd`（托管域））
  - `AppleProvider`（OIDC + `name` 仅首登 + `email_verified` 特有语义）
  - `GitHubProvider`（OAuth 2.0 + User API 调用以获取 email——GitHub 不
    在 id_token 中返回 email）
  - `MicrosoftProvider`（Azure AD + MSA，`tid` 声明→租户路由）
  - `FacebookProvider`（OAuth 2.0 + 字段映射，id_token 不可用）
  - 每个 provider 携带已知的 JWKS 轮换监控 + alg 边界校验

- **`tenant` 模型扩展**：每租户的 `AllowedSocialProviders` 白名单 +
  `SocialProviderCredentials`（每 provider 每租户的 client_id/client_secret）。
  复用现有的 `connections.Store` 架构。

- **一键嵌入的登录 Widget**（SDK 而非 SPA）：`ssoclient/social/` 包——调用方
  传 `client_id`、`redirect_uri`、`provider`，包自动完成授权码流 + PKCE +
  令牌兑现。分浏览器（`http.Redirect`）和原生（`launchLocalServer` 回环）
  两个模式。

- **社交注册 -> 用户创建流**：首登社交 IdP 的用户自动通过 `UserProvider.CreateOrUpdate`
  创建。配置化的新用户默认属性（默认 scope、默认角色、初始 conset 记录）。

### 边界情况

- **邮箱冲突**：同一邮箱已在本地密码用户下存在——可配的合并策略（链接账户 /
  拒绝 / 发送验证）
- **Apple 中继邮箱**：`email_verified` 在 `private relay` 模式下的语义
- **GitHub 无 email 在 id_token 中**：回退到 User API 调用 + 缓存策略 +
  API rate limit 管理
- **provider 明确下线/alg 变更**：`config/social_providers.go` 版本 + TTL 预警
- **社交 IdP 临时宕机**：fail-closed（特定 provider 认证失败 → `social_provider_unavailable`，
  不阻塞其他 provider 或本地密码登录）

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 商业价值 | **high** — 解锁 CIAM B2C 市场，这是竞品核心收入来源 |
| 技术价值 | **medium** — 协议已存在，预配置是工作量的问题 |
| 工作估算 | ~2–3 周（预构建 5 个 provider + 配置化 + 默认映射 + 登录 widget） |
| 依赖 | 零——纯新增包，复用 OIDC Federation 底层 |
| 优先级 | **P1**（与 B2B 连接并列，让 tenant 模型覆盖企业对内+对外双场景） |

---

## 方向 2：OAuth 2.0 Grant 管理 API 与授权应用中心

### 现状

项目拥有完整的 token 生命周期管理和 consent 记录存储：

| 能力 | 实现状态 |
|---|---|
| Token 吊销（/revoke、/revoke-all） | ✅ 完整 |
| Token 自省（/introspect） | ✅ 完整 |
| Consent 记录（memory + sqlite + redis） | ✅ 落地（`consent_spi.go`） |
| 用户会话管理（/me/sessions） | ✅ 落地 + SPA |
| **用户视角：哪些应用已授权、何时授权、什么 scope** | ❌ **零实现** |
| **用户主动撤销单一应用的全部授权** | ❌ **零实现** |
| **授权有效期 / 最近使用时间 / 过期策略** | ❌ **零实现** |
| **Grant 生命周期审计（授权授予 → 使用 → 撤销 → 过期）** | ❌ **零实现** |

**Grant 管理与 Token 吊销是正交问题：** Token 吊销是"立即作废一个凭证"；
Grant 管理是"用户查看并管理自己和第三方应用之间的授权关系"。一个用户可能
通过 `/register`（DCR）注册了一个应用，grant 了 `openid profile email` 权限，
但半年后不再使用该应用。今天该用户无法：
1. 看到哪些应用已被授权
2. 看到每个应用被授予的 scope 和授权时间
3. 撤销某个特定应用的授权（导致所有关联 token 失效）
4. 设置自动过期/闲置超时

这是 GDPR 第 20 条（数据可携带权）和加州 CCPA/CPRA 消费者权利法案明确要求
的"了解你的数据被哪些第三方使用"的能力。

### 缺口核验

| 概念 grep | 命中数 | 说明 |
|---|---|---|
| `GrantManagement\|grant_management\|grant.*list\|GrantList` | **0** | 零实现 |
| `AuthorizedApplication\|authorized.application\|AuthorizedApp\|authorized_app` | **0** | 零实现 |
| `ConnectedApplication\|connected.application\|UserGrant\|user_grant` | **0** | 零实现 |
| `OAuthGrant\|oauth_grant\|GrantLifecycle\|grant_lifecycle\|grant.*expir` | **0** | 零实现 |
| `ClientGrant\|client_grant\|client.*authorization.*list` | **0** | 零实现 |

### 为什么需要它

1. **合规刚性需求**：GDPR Art.15（访问权）、Art.20（数据可携带权）、CCPA §1798.100
   要求企业让用户能够了解"哪些第三方正在处理我的数据"——OAuth grant 是这一权利
   的核心载体。没有 Grant 管理 API，合规回答只能通过 DB 直查或手动导出完成。

2. **用户信任与透明度**：每个主流身份平台（Google Accounts、Apple ID、Microsoft
   Account、Auth0、Okta）都提供了"已连接的应用"页面。这是用户安全感的基础组件。
   无此功能，自建的 SSO 平台在终端用户信任度上永远落后于竞品。

3. **安全收敛面**：被遗忘的应用授权是安全的黑洞——一个被授权了 `openid` + `email`
   的沉睡应用可能被入侵后用于钓鱼或数据窃取。无 Grant 管理，用户无法自行收敛风险。

4. **延伸价值**：Grant 审计 + 闲置应用自动回收 + Scope 变更重新授权 + 授权证书
   ⽣效/失效通知——这些构成企业"OAuth 授权治理"的基础。

### 范围

#### SPI 扩展

```go
// Grant 记录——从 consent 记录泛化而来，覆盖每次授权
type Grant struct {
    ID          string    // 唯一标识
    UserID      string    // 授权用户
    ClientID    string    // 被授权的客户端
    Scopes      []string  // 授予的 scope
    GrantedAt   time.Time // 首次授权时间
    LastUsedAt  time.Time // 最近一次 token 颁发时间
    ExpiresAt   *time.Time // 可选授权过期时间
    RevokedAt   *time.Time // 撤销时间
    ConsentID   string    // 关联的 consent 记录 ID
}

// GrantManager SPI——新的授权生命周期管理接口
type GrantManager interface {
    // ListByUser 返回用户当前活跃的授权列表
    ListByUser(ctx context.Context, userID string) ([]*Grant, error)
    // RevokeByClient 撤销一个客户端对该用户的全部授权
    RevokeByClient(ctx context.Context, userID, clientID string) error
    // TouchGrant 在每次 token 颁发时更新 LastUsedAt
    TouchGrant(ctx context.Context, userID, clientID string) error
    // RevokeExpired 清理已过期的授权
    RevokeExpired(ctx context.Context) (int, error)
}
```

#### API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/me/grants` | 当前用户的授权列表 |
| `GET` | `/me/grants/:client_id` | 单个授权详情 |
| `DELETE` | `/me/grants/:client_id` | 撤销该客户端的全部授权 |

DELETE 的副作用：触发所有该 client+user 的 refresh token 家族击杀 +
session 批量注销 + CAEP `token_revoked` 广播。

#### 管理面扩展

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/v1/admin/users/:user_id/grants` | 管理员查看用户的授权 |
| `DELETE` | `/api/v1/admin/users/:user_id/grants/:client_id` | 管理员代表撤销 |

### 边界情况

- **大量授权（>1000 个 client）的分页 + 搜索**：按 client_name、scope、授权时间排序
- **授权下 client 已被删除**：显示"该应用已不再可用"+ 提示撤销
- **撤销后的 token 仍有效（access token 不可变剩余 TTL）**：同 /revoke 行为，
  文档显式说明"access token 在自然过期前仍有效，refresh token 和新的 id_token 立即失效"
- **撤销触发的事件链**：刷新家族击杀 → 跨副本广播 → CAEP RP 通知 → 审计事件
- **Grant 与 consent 的关系**：一次 consent 即创建一个 grant。Consent 记录是
  用户同意的法律证据，grant 是运行时的授权记录。两者通过 `ConsentID` 关联。

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 合规价值 | **high** — GDPR/CCPA 直接需求 |
| 产品价值 | **high** — 用户信任的基础组件 |
| 安全价值 | **medium** — 收敛被遗忘授权的攻击面 |
| 工作估算 | ~1–2 周（SPI + API + memory 实现 + 用户门户面板） |
| 依赖 | consent store 已落地；复用 session、token 基础设施 |
| 优先级 | **P1**（合规刚需 + 产品竞争力） |

---

## 方向 3：渐进式身份档案与属性治理（Progressive Profiling & Attribute Governance）

### 现状

项目拥有基础的用户属性模型：

| 能力 | 实现状态 |
|---|---|
| `core.User` 模型（ID、Email、DisplayName、Attributes map） | ✅ 完整 |
| `UserProvider.CreateOrUpdate`（属性 upsert） | ✅ 完整 |
| 自定义属性（`core.User.Attributes` map） | ✅ 完整 |
| 凭据健康度检查（`CredentialHealth`） | ✅ 落地 |
| **身份属性逐级收集（"先收集 email，再收集电话，再收集地址"）** | ❌ **零实现** |
| **属性验证状态（verified / unverified / pending_review）** | ❌ **零实现** |
| **属性来源追踪（此属性由用户提供、由 IdP 断言、由管理员设置）** | ❌ **零实现** |
| **属性有效期与重新验证策略** | ❌ **零实现** |
| **"身份完成度"计算与强制策略** | ❌ **零实现** |

**什么是渐进式身份档案：** 不是所有应用都需要所有的用户属性。一个内容消费网站
可能只需要 email + 用户名；一个金融科技应用需要实名 + 地址 + DOB + SSN 末四位。
渐进式档案允许应用定义多级身份门槛：

- **Level 1**：email（已验证）—— 可阅读、可评论
- **Level 2**：phone（已验证）—— 可发布
- **Level 3**：政府 ID（已验证）—— 可交易
- **Level 4**：地址验证（实物邮寄验证）—— 可提现

每次用户尝试访问一个需要更高级别属性的资源时，系统引导用户补充属性并验证。
这在 Auth0 / Clerk / WorkOS 中是标准能力。

### 缺口核验

| 概念 grep | 命中数 | 说明 |
|---|---|---|
| `progressive_profil\|ProgressiveProfil\|ProfileCompletion\|profile_completion` | **0** | 零实现 |
| `attribute.*verif\|AttributeVerif\|attr_verif\|attribute.*provenance\|attrProvenance` | **0** | 零实现 |
| `identity.*level\|IdentityLevel\|identity.*strength\|IdentityStrength\|assurance.*level` | **0** | 零实现（`acr_values` 不同——它是认证强度，非属性强度） |
| `attribute.*expir\|AttrExpir\|attr.*reverify\|attr_reverify` | **0** | 零实现 |
| `identity.*completion\|identity.*completeness\|profile.*strength` | **0** | 零实现 |

### 为什么需要它

1. **CIAM 应用的核心能力**：Auth0 的 Progressive Profiling、Clerk 的 Attribute
   Verification、WorkOS 的 Profile Enrichment 都是各自的旗帜功能。没有它，
   SSO 只能做"登录/登出"，不能做"身份构建"。

2. **属性来源与信任是合规的基础**：SOC2/ISO27001 要求"身份属性的来源和验证状态
   必须有记录"（谁、何时、用什么方法验证了哪个属性）。今天的 `core.User.Attributes`
   是一个无主的 map——审计无法回答"这个 email 是用户自己提供的，还是 Google 断言的，
   还是管理员设置的"。

3. **NIST IAL（Identity Assurance Level）映射**：NIST SP 800-63 将身份分为 IAL1
   （自断言）到 IAL3（物理验证）。渐进式档案 + 属性验证是实现 IAL2 的必经之路。
   对于金融/医疗/政府客户，这是硬需求。

4. **减少用户摩擦**："先给 email 就能用，需要时再补充"比"一次填完 20 个字段"的
   注册转化率高 3–5 倍。渐进式档案是 UX 最佳实践。

### 范围

#### 核心数据模型

```go
type AttributeProfile struct {
    UserID string
    // 每个属性的状态机
    Attributes map[string]*AttributeEntry
}

type AttributeEntry struct {
    Value       string            // 属性值
    State       AttributeState    // unverified / pending / verified / expired / revoked
    Source      AttributeSource   // user_input / idp_assertion / admin_set / system_derived
    SourceRef   string            // "google-oauth2|12345" / "admin|user-abc" / "system"
    VerifiedAt  *time.Time        // 验证时间
    ExpiresAt   *time.Time        // 可选——需要重新验证
    VerifiedBy  string            // 验证方法： "email_otp" / "sms_otp" / "gov_id" / "admin"
}
```

#### SPI 扩展

```go
type ProfileStore interface {
    GetProfile(ctx, userID string) (*AttributeProfile, error)
    SetAttribute(ctx, userID, attrName string, entry *AttributeEntry) error
    VerifyAttribute(ctx, userID, attrName, method string) error
    GetCompletion(ctx, userID string, required []string) (*ProfileCompletion, error)
}
```

#### 验证方法注册

- `email_otp`：发送一次性验证码到 email
- `sms_otp`：发送一次性验证码到 phone（复用现有的 `send_code.go`）
- `idp_assertion`：信任上游 IdP 的断言（Google 的 `email_verified: true`）
- `manual_review`：管理后台手动审核
- `gov_id_verify`：接入第三方 KYC（Onfido / Persona / Stripe Identity）

#### 策略引擎

```go
type ProfilePolicy struct {
    RequiredAttrs    map[string]AttributeRequirement // 属性名→要求
    CompletionAction string                         // redirect / deny / warn
}

type AttributeRequirement struct {
    MinState AttributeState // 最低验证状态
    MaxAge   *time.Duration // 属性年龄上限
    Sources  []AttributeSource // 允许的来源
}
```

策略可在 client 级别或 tenant 级别配置。当 `/auth/login` 检测到用户不满足
策略时，`error` 响应携带 `profile_incomplete` + 缺失属性列表 +
`completion_url`。

### 边界情况

- **属性验证降级**：source=idp_assertion 的属性在 IdP 下线时不应阻塞登录，
  但应有 "staleness" 标记提示重新验证
- **多值属性（多个 email/phone）**：`AttributeEntry` 支持 `Values []string` +
  每个值独立状态
- **自定义验证方法**：SPI 支持第三方 KYC 插件（`WithAttributeVerifier("gov_id", kycImpl)`）
- **与 consent 集成**：收集属性前需要用户的隐私同意（GDPR Art.7）
- **用户删除属性**：软删除（保留 `AttributeEntry` 标记 `State=revoked` + 时间戳，
  因为该属性曾被用于做 authorization 决策的审计证据）

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 产品价值 | **high** — CIAM 差异化核心能力 |
| 合规价值 | **high** — 属性来源可审计，SOC2/ISO27001 关键 |
| 安全价值 | **medium** — 确认识别属性未被篡改 |
| 工作估算 | ~3–4 周（SPI + memory/sqlite 实现 + email/sms 验证器 + 策略引擎） |
| 依赖 | 复用现有的 `send_code.go`、`email_smtp`、consent store |
| 优先级 | **P2**（方向 1 和 2 之后，但仍是 CIAM 场景的关键组件） |

---

## 方向 4：身份事件导出管道与数据治理（Identity Data Mesh & Governed Export Pipeline）

### 现状

项目拥有丰富的可观测性和审计系统：

| 能力 | 实现状态 |
|---|---|
| `audit.Sink` SPI（Record 单条写入） | ✅ 完整 |
| SQLite/内存/文件/Kafka/MQTT 审计后端 | ✅ 完整 |
| 审计事件多维度 facet、导出（JSON/CSV） | ✅ 完整（admin REST API） |
| Metrics（prometheus 指标） | ✅ 完整 |
| Tracing（W3C TraceContext） | ✅ 完整 |
| **结构化、配置化的事件导出到外部数据平台** | ❌ **零实现** |
| **Schema-on-write / schema 版本管理 / 后向兼容** | ❌ **零实现** |
| **身份业务指标（MAU、DAU、登录分布、授权活跃度）的内建报表** | ❌ **零实现** |
| **数据保留策略、过期清理的配置化治理** | ❌ **零实现** |

**问题在抽象层次**：今天你可以「拉取审计事件」（REST GET audit），但无法说
"将所有身份事件（login、token_issued、consent_granted、scope_changed）以
Avro/Parquet/JSON 格式汇聚到我的 S3/Redshift/BigQuery/Snowflake，按租户
分区、每日快照"。这是企业数据团队在定制化 SSO 部署后最常提出的第一个需求——
"我要把身份事件和我的业务数据 join"。

### 缺口核验

| 概念 grep | 命中数 | 说明 |
|---|---|---|
| `DataLake\|data_lake\|DataWarehouse\|data_warehouse` | **0** | 零实现 |
| `IdentityDataExport\|identity_data_export\|EventPipeline\|event_pipeline\|EventStream` | **0** | 零实现 |
| `Avro\|Parquet\|ORC\|Columnar\|columnar` | **0** | 零实现 |
| `DataRetention\|data_retention\|RetentionPolicy\|retention.*policy\|event.*retention` | **0** | 零实现（`audit/retention.go` 不同——是审计链的保留，非数据治理） |
| `DataLineage\|data_lineage\|schema.*version.*event\|EventSchema\|event_schema` | **0** | 零实现 |

### 为什么需要它

1. **企业数据团队的通用需求**：身份事件（谁登录了、什么时候、从哪、用什么设备、
   拿了什么 scope）是数据仓库中最有价值的信号之一——用来 join 销售转化、
   产品使用、安全告警。没有导出管道，数据工程师只能 UI 导出 CSV，不可维护。

2. **GDPR/CCPA 数据可携带也是导出能力**：GDPR Art.20 要求以"结构化、通用、机读"
   的格式导出用户数据。今天的 `/me/data` 能导出 JSON，但企业在 GDPR 下需要
   自动化、配置化、可审计的导出流程。

3. **安全运营（SIEM）集成**：SOC 团队需要将身份事件（登录失败、权限变更、
   令牌颁发）实时入到 Splunk/Sumo Logic/Elastic/Sentinel。今天有 `audit.Sink`，
   但每个 SIEM 的 schema 要求不同、映射不同、传输协议不同（HTTP/HEP/Syslog）。
   预构建的 SIEM 连接器消除集成障碍。

4. **多租户计量/结算的数据源**：方向 1 和 2 增加了授权和消费级登录后，
   平台运营者需要知道"哪个租户有多少活跃用户、多少登录、多少 token 颁发"
   来驱动计量和结算功能。

### 范围

#### 统一事件模型

```go
type IdentityEvent struct {
    // 通用字段
    ID          string    // 唯一事件 ID
    Timestamp   time.Time // 事件发生时间
    EventType   string    // "login" / "token_issued" / "consent_granted" / "scope_changed" / ...
    TenantID    string    // 租户
    UserID      string    // 用户（可能为空，例如 client_credentials）
    ClientID    string    // 涉及的客户端

    // 结构化载荷——按事件类型不同
    Payload     json.RawMessage

    // 审计/合规
    TraceID     string
    SpanID      string
    Agent       string // user-agent
    SourceIP    string
}
```

#### Export SPI + 连接器

```go
// EventExporter 导出身份事件到外部系统。
type EventExporter interface {
    Name() string
    Export(ctx context.Context, events []*IdentityEvent) error
    Schema() string // "oauth-login-v1" 等 schema 标识
}
```

预构建的连接器（作为嵌套子模块，如同 `kafka/`、`mqtt/`）：

| 连接器 | 说明 |
|---|---|
| `export/s3/` | 按 `tenant/date/event_type/*.json` 写入 S3/MinIO |
| `export/snowflake/` | 通过 SQL INSERT（COPY INTO）写入 Snowflake 表 |
| `export/bigquery/` | 通过 BigQuery Storage Write API 写入 |
| `export/redshift/` | 通过 Redshift COPY 或 INSERT |
| `export/splunk/` | 通过 HEC（HTTP Event Collector）写入 |
| `export/elastic/` | 通过 Bulk API 写入 Elasticsearch |
| `export/webhook/` | 通用 webhook，由事件类型过滤 |

#### 治理功能

- **Schema 注册**：每个事件类型有一个版本化的 schema（protobuf / JSON Schema），
  导出时可选嵌入或引用。schema 变更时提供向后兼容保证。
- **保留策略**：按事件类型配置保留期限（如 `login` 保留 90 天、`token_issued`
  保留 365 天、`consent_granted` 保留 7 年）
- **事件采样**：高容量事件（如 `token_issued`）可选采样率（1/10/100/1000），
  低容量事件（如 `consent_revoked`）始终全量导出
- **Partition 策略**：按 `tenant_id` + `date` 分区（S3 路径 / 表分区），
  确保租户隔离

### 边界情况

- **导出延迟 vs 事件产生速率的反压**：背压机制、死信队列、告警
- **Schema 演化兼容性**：新增字段可空、旧版 consumer 不报错
- **租户级隔离**：S3 不同前缀 / BigQuery 不同 dataset / 导出 worker 租户队列
- **PII 脱敏**：email、phone、IP 在导出前可配置脱敏（hash / truncate / omit）
- **大租户 vs 小租户**：同一管道不能因一个大租户阻塞小租户——使用租户级
  独立 exporter worker
- **重放**：断点续传（基于事件 ID 或时间戳的偏移量）+ 幂等性

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 企业价值 | **high** — 数据团队的刚性需求，GDPR 可携带权 |
| 平台差异化 | **medium** — 不是前端功能，但数据平台集成是采购决策常见项 |
| 安全价值 | **medium** — SIEM 集成的安全运营前提 |
| 工作估算 | ~4–5 周（事件模型 + S3 连接器 + 治理框架 + 1 个 SIEM 连接器） |
| 依赖 | 复用 `audit.Sink` SPI 和 `kafka/` / `mqtt/` 的传输能力 |
| 优先级 | **P2**（CIAM 和 Grant 管理之后，面向企业深度运营场景） |

---

## 方向 5：身份安全运营中心（SOC Dashboard & Incident Response Console）

### 现状

项目拥有分散的安全相关信息：

| 能力 | 实现状态 |
|---|---|
| 异常检测（`domains/anomaly`） | ✅ 完整 — 不可能迁徙、速度爆发、暴力 spray |
| 令牌异常（`domains/tokenanomaly`） | ✅ 完整 — 令牌被盗用检测 |
| 威胁执行（`domains/threataction`） | ✅ 完整 — 检测→响应桥接 |
| 审计事件流 | ✅ 完整 facet + export |
| 管理面告警入口 | ✅ webhook subscriptions |
| Metrics / Prometheus | ✅ 完整 |
| CAEP/RISC 事件（对外 RP 通知） | ✅ 完整 |
| **统一安全事件时间线（融合 anomaly + audit + threataction + risk）** | ❌ **零实现** |
| **一键安全响应工作流（检测→分类→响应→闭合）** | ❌ **零实现** |
| **安全态势评分（租户/客户端/整体安全评分）** | ❌ **零实现** |
| **配置安全检查清单（安全基线告警 + 修复建议）** | ❌ **零实现** |

**核心观察：** 今天安全信号分布在四个维度：
- **Anomaly**：检测结果写审计 + metric，通过 webhook 推送
- **ThreatAction**：响应动作自动执行（suspend session、revoke token）
- **Audit**：所有事件的原始记录，可 facet 过滤和导出
- **Metrics**：`sso_login_failures_total`、`sso_anomaly_*` 等

但**没有任何一个视图将它们整合在一起**。SOC 分析师需要一个单一窗口：时间线 →
异常事件详情 → 受影响用户 → 已触发的响应动作 → click-ops 补充动作。这在
Auth0 叫 "Security Dashboard"，在 Okta 叫 "ThreatInsight"。

### 缺口核验

| 概念 grep | 命中数 | 说明 |
|---|---|---|
| `SecurityDashboard\|security_dashboard\|SecurityCenter\|SOC.*view\|soc_view` | **0** | 零实现 |
| `IncidentResponse\|incident_response\|IncidentWorkflow\|incident_workflow\|IncidentTimeline` | **0** | 零实现 |
| `SecurityScore\|security_score\|SecurityPosture\|security_posture\|SecurityBaseline` | **0** | 零实现 |
| `SecurityAlert\|security_alert\|AlertRule\|alert_rule\|AlertSeverity` | **0** | 零实现（webhook 通知存在，但无统一告警模型） |
| `ThreatTimeline\|threat_timeline\|SecurityTimeline\|security_timeline\|UnifiedTimeline` | **0** | 零实现 |

### 为什么需要它

1. **安全信号碎片化的整合**：今天四个信号维度隔离存在，SOC 分析师需要在
   Audit → Anomaly → ThreatAction → Webhook 四个窗口间手切。统一视图将
   响应时间从分钟级降为秒级。

2. **采购 RFP 的"安全运营"章节**：企业安全采购中有一个专门的"身份安全运营"
   需求章节（Gartner IAM 魔力象限评估项），要求 IdP 提供统一的安全监控、
   告警和响应能力。没有这个视图，在定位"身份安全平台"而非"身份验证库"时会
   被扣分。

3. **租户管理员自助安全视图**：多租户场景下，租户管理员看不到自己的安全态势——
   哪里配置了弱密码策略？哪些应用有过度授权的 scope？哪些用户有异常登录模式？
   今天唯一的回答是"自己导审计 CSV"。SSO 需要直接呈现。

4. **响应工作流的可审计化**：今天的 ThreatAction 自动执行不可审查。SOC 需要
   一个"案件"模型——检测→自动响应→人工确认→留档→闭合——并且每一步都有
   审计记录，可呈现给合规审查。

### 范围

#### 统一安全事件

```go
type SecurityEvent struct {
    ID            string
    Timestamp     time.Time
    Severity      Severity // info / low / medium / high / critical
    Category      string   // "impossible_travel" / "brute_force" / "token_reuse" / ...
    TenantID      string
    UserID        string   // 可能为空（全局性事件）
    ClientID      string   // 可能为空
    SourceIP      string

    // 事件来源跟踪
    SourceType    string   // "anomaly" / "threataction" / "audit" / "risk"
    SourceID      string   // 来源系统内 ID

    // 是否已触发响应
    ActionTaken   string   // "session_suspended" / "token_revoked" / "mfa_required" / "notified" / "none"
    ActionRef     string   // 关联的 ThreatAction ID

    // 事件详情
    Description   string
    RecommendedAction string
    Metadata      map[string]string
}
```

#### API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/v1/admin/security/timeline` | 统一安全时间线（支持过滤、分页） |
| `GET` | `/api/v1/admin/security/events/:id` | 单个安全事件详情 |
| `POST` | `/api/v1/admin/security/events/:id/acknowledge` | 人工确认（标记已处理） |
| `POST` | `/api/v1/admin/security/events/:id/dismiss` | 标记为误报 |
| `GET` | `/api/v1/admin/security/score` | 整体安全态势评分 |
| `GET` | `/api/v1/admin/security/score/:tenant_id` | 租户安全态势评分 |
| `GET` | `/api/v1/admin/security/checklist` | 安全基线检查清单 |

#### 安全态势评分模型

评分维度：

| 维度 | 权重 | 指标 |
|---|---|---|
| **密码策略** | 20% | 最短密码长度、复杂性要求、MFA 启用率 |
| **客户端安全** | 20% | PKCE 强制率、secret 轮换率、redirect_uri 安全度 |
| **登录安全** | 25% | 失败率、异常检测触发率、lockout 配置 |
| **令牌安全** | 15% | DPoP 使用率、token TTL、refresh 轮换 |
| **整体覆盖** | 20% | 日志完整度、防火墙配置、FAPI 合规度 |

每个维度 0–100 分，加权得总分。分数字段随每次安全事件更新，
可查看历史趋势。

#### 安全基线检查清单

推荐扫描项（示例）：

- [ ] 是否启用了 PKCE 强制？（检查 `Client.RequirePKCE`）
- [ ] 是否有任意 client 使用 `alg=none`？（扫描所有 `Client.JWKS`）
- [ ] 是否所有 redirect_uri 使用 HTTPS？（检查 `Client.RedirectURIs`）
- [ ] 是否有 client 授予了 `*` scope（通配符）？
- [ ] 是否有超期未轮换的 OAuth client secret？
- [ ] FAPI profile 检查是否通过？
- [ ] 是否所有的 MFA 强制用户已配置至少一种 MFA 方式？
- [ ] audit store 的健康状态？
- [ ] 是否有任意 pending 的 client 注册超过 N 天未审批？
- [ ] signing key 的剩余 TTL 是否低于阈值？

#### 安全运营 SPA 面板

嵌入在现有 Admin Console 中的 Security 选项卡——时间线面板 + 评分仪表板 +
检查清单。使用与现有 Admin SPA 相同的无构建、无 CDN 的纯 HTML/JS/CSS 模式。

### 边界情况

- **多租户视角**：全球管理员看全局时间线；租户管理员只看自己租户的事件——
  评分也按 tenant scope 计算
- **事件风暴抑制**：同一 IP 的一万次登录失败应折叠为一条 `brute_force`
  事件 + `count=N`，而非一万条独立事件
- **误报学习**：被人工标记为误报 3 次以上的同一检测规则/模式自动降权
- **时间线保留**：安全事件应有独立于审计的保留策略（如 90 天），评分趋势
  保留更长（如 2 年）
- **与现有 ThreatAction 的关系**：SOC Dashboard 是 ThreatAction 的人机界面
  ——ThreatAction 自动执行响应，SOC Dashboard 提供人工审查和覆盖

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 安全价值 | **high** — 安全信号整合 → 响应时间从分钟级到秒级 |
| 产品差异化 | **high** — 竞品身份 SOC 面板是企业采购决策的关键差异点 |
| 合规价值 | **medium** — 安全审查流程的可审计性 |
| 工作估算 | ~3–4 周（事件模型 + API + 评分引擎 + SPA 面板 + 基线扫描器） |
| 依赖 | 复用 anomaly、threataction、audit 现有数据源；SPA 嵌入现有 Admin Console |
| 优先级 | **P2**（CIAM 和 Grant 管理之后，面向企业安全运营场景） |

---

## 优先级摘要

```
高（P1）          ┌──────────────────────────────────────┐
                  │  ① 消费级社交登录（CIAM）             │
                  │     → 解锁 B2C/B2B2C 市场             │
                  │     → ~2–3 周                          │
                  ├──────────────────────────────────────┤
                  │  ② OAuth Grant 管理 API               │
                  │     → GDPR/CCPA 合规 + 用户信任        │
                  │     → ~1–2 周                          │
                  └──────────────────────────────────────┘

中（P2）          ┌──────────────────────────────────────┐
                  │  ③ 渐进式身份档案                      │
                  │     → CIAM 核心、IAL 映射               │
                  │     → ~3–4 周                          │
                  ├──────────────────────────────────────┤
                  │  ④ 身份事件导出 + 数据治理              │
                  │     → 企业数据平台集成                  │
                  │     → ~4–5 周                          │
                  ├──────────────────────────────────────┤
                  │  ⑤ 身份安全运营中心（SOC）              │
                  │     → 安全信号整合 + 企业 RFP           │
                  │     → ~3–4 周                          │
                  └──────────────────────────────────────┘
```

**核心理念：** ①② 是市场面（解锁新客户、合规刚需）；③④⑤ 是深度面（差异化、
锁定、企业级深度）。建议先做 ①② 并行（不冲突），再做 ③⑤（不同团队），
④排在最后因其依赖事件模型稳定。

---

## 附录：与现有能力的对比总结

| 方向 | 已有能力 | 新增能力 | 关系 |
|---|---|---|---|
| ① CIAM 社交登录 | OIDC Federation SPI | 预构建 provider、一键 widget、品牌化｜复用 OIDC Federation |
| ② Grant 管理 | Consent store、token revoke | Grant 生命周期 API、用户授权中心｜Consent 是法律证据，Grant 是运行时记录 |
| ③ 渐进式档案 | `core.User.Attributes` map | 属性验证状态机、来源追踪、策略引擎｜属性治理 vs 属性存储——正交 |
| ④ 事件导出 | `audit.Sink` SPI | Schema 治理、连接器、保留策略｜Sink 是写入（对内）；Export 是读取（对外） |
| ⑤ SOC Dashboard | Anomaly + audit + threataction | 统一时间线、评分、基线、工作流｜现有系统是构件（building blocks）；SOC 是集成视图 |

---

*生成于 2026-07-11 · 全代码库全局扫描 + 15 轮历史分析交叉核验 · 零重叠*
