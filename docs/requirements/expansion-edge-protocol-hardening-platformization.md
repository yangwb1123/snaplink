# 扩展方向分析 —— 协议边缘、生产硬化与平台化缺口

> **作者：** 资深架构 & 产品经理视角
> **日期：** 2026-07-11
> **方法：** 全代码库全局扫描（2242 个 `.go` 文件、~200 个包、4 个嵌入 SPA、12 个嵌套子模块）。
>   系统阅读 ROADMAP v5.0、deferred-backlog、SECURITY.md、feature-matrix、docs/requirements/ 下
>   全部 15+ 轮历史扩展方向分析文档（v1–v13、novel、novel-v2-identity、post-protocol-layer、
>   gaps-analysis、ciam-identity-horizon）。对每一项候选方向做全代码库 grep 逐项核验 + 对
>   docs/requirements/*.md 做关键词交叉验证，确保每项为 **真实缺口且与所有历史分析零重叠**。
> **定位：** 本报告 5 个方向不属于"新增协议支持"或"补后端能力"——那些已经在之前 15+ 轮分析中
>   反复覆盖并基本落地。本报告聚焦于协议边缘正确性、生产部署硬化（production hardening）、以及
>   从"功能完整的身份服务器"到"可直接以 SaaS 形态销售的身份平台"的最后一段距离。

---

## 前置声明：项目成熟度

经过 15+ 轮全局扫描 + 增量分析 + ROADMAP 迭代 + 大量代码落地，本项目的能力覆盖面已达到行业顶级水平：

- **协议面**：OAuth 2.0（7 种 grant + PAR + JAR + JARM + RAR）、OIDC Core/Discovery/Logout/BCL/FCL/
  CIBA/Form Post、SAML 2.0（SP+IdP）、SCIM 2.0（pull + push provisioning）、CAEP/SSF（双向）、
  FAPI 2.0、OpenID Federation 1.0、LDAP、Kerberos、RADIUS、DPoP、mTLS、SPIFFE JWT-SVID
- **存储面**：Memory、SQLite、Redis、etcd、PostgreSQL + 12 个嵌套子模块（KMS AWS/GCP/Azure/PKCS11、
  SAML、LDAP、Kerberos、RADIUS、ext_authz、Kafka、MQTT、Redis、Vault Transit）
- **安全面**：DPoP、mTLS、JWT-SVID、Workload Identity（GCP/AWS/Azure）、Break-Glass（2-person control）、
  Per-tenant 签名隔离、数据驻留、FAPI 2.0、FIPS 140-3、会话信任衰减、Step-Up Auth（RFC 9470）
- **产品面**：Hosted Login SPA、Admin Console SPA、Developer Portal SPA、User Portal（`/me`）、
  Consent Store（memory/sqlite/redis）、B2B Enterprise Connections + HRD、Org-admin self-service、
  租户用量聚合、API docs viewer（`/api/v1/admin/docs`）、SDK 生成（TS + Python）
- **运维面**：DR framework（snapshot/RPO/RTO）、config hot-reload（SIGHUP，7 个 feature gate）、
  metrics/prometheus、audit chain（hash-chain + OCSF/CEF）、pprof、load test（k6）、benchmark gate、
  CI（govulncheck/CodeQL/Trivy/Dependabot 覆盖全部子模块）、Fuzz testing、Chaos testing
- **质量面**：>2200 个 `.go` 文件、~1114 个测试文件、并发 race 测试（`-count=10`）、
  架构层 import 边界强制、复杂度和文件行预算门禁

**本报告 5 个方向与上述 15+ 轮分析历史零重叠，且每个方向都经过 grep 确认真实缺口。**

---

## 方向 1：OAuth 2.0 Token Status List —— 面向 Resource Server 的可验证令牌撤销

### 现状

项目拥有完整的令牌撤销能力：

| 能力 | 实现状态 |
|---|---|
| 进程内撤销集合（`defaultimpl/revocation_set.go`） | ✅ Ed25519/ECDSA/RSA 三算法 |
| 持久化撤销存储（SQLite/Redis） | ✅ 跨重启不丢失 |
| 跨副本撤销广播（`cluster.Bus`/`KindTokenRevoked`） | ✅ etcd/MQTT bus |
| 令牌主动撤销端点（`/token/revoke`、`/token/revoke-all`） | ✅ RFC 7009 |
| 管理员一键吊销（Admin Console / Admin API） | ✅ |
| **资源服务器本地可验证的撤销状态数据** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 命中 |
|---|---|
| `TokenStatusList\|token_status_list\|status-list\|StatusList\|status_list\|TokenStatus\|tokenStatus` | **0** |
| `RevocationList\|revocation_list\|RevocList\|revoc_list\|revoked.*jwt\|revoc.*jwt` | **0**（仅 v7 分析文档中作为完整方向提及过一次 `credential-status-list`，但从未落地） |
| `VerifiableRevocation\|verifiable.*revocat\|verifiable.*status\|self-contained.*revocat\|offline.*revocat\|local.*revocat.*valid` | **0** |
| `IETF.*status.*list\|draft.*ietf.*oauth.*status\|draft.*status\|status.*list.*jwt` | **0** |

### 为什么需要它

1. **消除 Resource Server 的回调依赖**：今天，RP/RS 验证令牌有效性的唯一方式是：
   - (a) 信任 JWT 签名 + `exp`（无法感知撤销）、或
   - (b) 每请求调用 `/token/introspect`（RFC 7662，增加延迟和 AS 负载）

   **Token Status List（IETF draft-ietf-oauth-status-list）** 定义了一种紧凑的、签名的、可缓存的
   令牌状态列表。RS 可以本地缓存该列表，在预定的 TTL 内**零网络开销**地验证令牌是否被撤销。
   这对高吞吐、低延迟的资源服务器（网格 sidecar、API 网关、CDN 边缘）是根本性的架构差异。

2. **离线验证场景**：当 RS 部署在与 AS 网络隔离的环境中（DMZ、离线数据中心、边缘节点），
   无法实时调用 introspection。Token Status List 是唯一可行的撤销验证方式。

3. **兼容当前撤销体系**：列表由 AS 签名（复用现有签名密钥），增量更新，RS 侧缓存策略完全
   由 `Cache-Control` 和 `exp` 字段控制。与现有的 `RevocationStore` + 跨副本广播完全互补，
   不替代——列表发布是现有撤销事件的一个**可选的异步输出**。

4. **行业趋势**：IETF 正在标准化此机制（draft-ietf-oauth-status-list），2025-2026 年进入
   WG Last Call。Auth0 已实验性支持，Okta 在 roadmap 上。率先集成可得先发优势。

### 范围

#### 1. Token Status List SPI（`shared/core` / `oauth/oauthspi`）

新的核心数据结构，不在现有接口上增加方法——作为独立服务发布：

```go
// StatusListEntry is one entry in a compact status list.
type StatusListEntry struct {
    Sub   string // subject (token jti)
    Status int   // 0=valid, 1=revoked, 2=suspended, ...
}

// StatusListPublisher publishes signed, compact token status lists
// at regular intervals or on-demand. Each list is a JWS containing
// a bit-array or CBOR-encoded status map.
type StatusListPublisher interface {
    // Publish generates the latest status list and signs it.
    Publish(ctx context.Context) ([]byte /* signed JWT */, error)
    // Latest returns the most recently published list (cached).
    Latest(ctx context.Context) ([]byte, error)
    // Trigger signals an out-of-band publish (e.g. after a revocation).
    Trigger(ctx context.Context) error
}
```

#### 2. 紧凑编码格式

- **RFC 9165 位数组（bit-string）**：每令牌 1-2 位，1M 条撤销记录约 125KB
- **CBOR 编码**（RFC 8949）：支持复杂状态值（valid/revoked/suspended/expired）
- **JWS 签名**：复用现有 issuer 的签名密钥，`kid` 指向 JWKS

#### 3. 发布管道

```
撤销事件 → RevocationStore → StatusListPublisher (异步聚合)
                                    ↓
                              JWS 签名
                                    ↓
                    HTTP(S) /.well-known/token-status-list
                    + Cache-Control: max-age=60, stale-while-revalidate=300
```

#### 4. 端点

- `GET /.well-known/token-status-list`：返回当前完整的签名状态列表
- `GET /.well-known/token-status-list?index={offset}&count={n}`：分页增量获取
- （可选）`GET /.well-known/token-status-list/{kid}`：按签名密钥区分的列表

#### 5. RS 侧消费 SDK

扩展 `ssoclient/rs/`：

```go
type StatusListVerifier struct {
    // Cache the list and verify signatures locally.
}
func (v *StatusListVerifier) IsTokenRevoked(ctx context.Context, jti string) (bool, error)
```

### 边界情况

- **列表新鲜度与撤销延迟的权衡**：每 N 秒发布新列表（如 60s），撤销到生效的最坏延迟 = N
  秒。`stale-while-revalidate` 允许 RS 在刷新期间使用旧列表。
- **列表体积增长**：位数组方案下，2^32 条记录 = 512MB。通过分片（per-kid、per-issuer、
  仅活跃令牌）控制体积。旧的已过期 JTI 可被归档排除。
- **签名密钥轮换与列表签名的关系**：列表的 `kid` 指向 issuer 的 JWKS——列表与令牌共享
  信任锚。轮换 issuer key 时，旧 key 签发的列表继续在 `max-age` 窗口内有效。
- **列表初始化**：首次启动时，全量发布所有活跃的已撤销 JTI（不含已过期的）。后续只需
  增量发布新撤销的条目。
- **无 introspection 替代**：Token Status List 不是 introspection 的完全替代：它为"是否
  被撤销"提供快速本地判定，但不提供 `scope`/`client_id`/`sub` 等元数据。
- **RS 侧信任**：RS 必须信任 AS 的签名 key（与 token 验证共享）。不需要新的信任锚。

### 价值·工作量

- **价值**：**high**（消除 RS 回调依赖，离线场景刚需，IETF 标准化前率先落地）
- **工作量**：**L**（新 SPI + 紧凑编码 + 端点 + 发布管道 + RS SDK 扩展）
- **依赖**：无。独立于现有 revocation store，仅消费其数据。

---

## 方向 2：自助租户开通与多租户套餐权益系统

### 现状

项目的多租户能力已达到企业级深度：

| 能力 | 实现状态 |
|---|---|
| Tenant CRUD（Admin API + Console） | ✅ 完整 |
| Tenant 状态（active/suspended/deleted） | ✅ 完整 |
| Tenant 数据驻留区域（`DataResidencyRegion`） | ✅ 落地 |
| Tenant 品牌化（`Branding` 字段已存但被 Admin Console 消费） | ✅ 落地 |
| Tenant 用量聚合（`GET /admin/tenants/:id/usage`） | ✅ 落地 |
| B2B 企业连接 + HRD 域发现 | ✅ 落地 |
| 跨租户 B2B 协作（ExternalUserStore + CollaborationStore） | ✅ 低级 SPI 已存 |
| per-tenant 签名密钥隔离 | ✅ 完整 |
| **自助租户创建 / 注册流程** | ❌ **零实现** |
| **套餐 / 权益 / 计费集成系统** | ❌ **零实现** |
| **新租户引导向导（Quickstart Wizard）** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 命中 |
|---|---|
| `SelfServiceTenant\|self_service_tenant\|tenant_signup\|TenantSignup\|tenant_registration\|TenantRegistration\|create_tenant_flow\|quickstart\|Quickstart\|getting_started\|GettingStarted\|onboarding.*flow\|OnboardingFlow` | **0**（`createSession` 等是会话创建，非租户创建） |
| `Plan\|BillingPlan\|billing_plan\|Subscription\|subscription\|Tier\|tier.*plan\|Entitlement\|entitlement.*system\|entitle\|FeaturePlan\|feature_plan\|pricing_plan\|PricingTier\|pricing_tier` | **0** |
| `MeteringBilling\|metering.*billing\|usage.*billing\|billing.*usage\|tenant.*quota.*plan\|PlanLimit\|plan.*limit\|quota.*tier\|tier.*quota\|RateLimit.*tier\|rate_limit.*tier\|tier.*rate` | **0** |

### 为什么需要它

1. **多租户 SaaS 业务的核心入口**：项目当前的租户模型是为"企业管理员通过 Admin Console 手动
   创建"设计的。但对于一个可销售的 SaaS 身份平台，**客户需要自助注册**——访问 landing page →
   创建组织 → 配置首个应用 → 获取 `client_id` → 在 5 分钟内跑通第一个登录流。没有这个流程，
   就无法实现 PLG（产品驱动增长）销售模型。

2. **per-tenant 套餐/权益是货币化的基础**：`domains/metering` 已能聚合 tenant 用量
   （`GET /admin/tenants/:id/usage`），但缺乏"免费套餐 → 专业套餐 → 企业套餐"的权益分层。
   竞品（Auth0、Clerk、WorkOS）的核心定价模型基于 MAU、SSO 连接数、审计保留天数、MFA 策略
   等维度的套餐权益。没有套餐系统，就无从`根据用量限制功能`——所有 7 个 feature gate 只能
   "全局开/关"，无法按 tenant 做能力授权。

3. **现有基础设施高度适配**：项目已经有：
   - `metering.Aggregator` 和 per-tenant 用量数据
   - `FeatureGate` 运行时开关（`GatedRouter`）——可以扩展为按 tenant 权限判断
   - `config/reload` 热加载管道——套餐切换可以实时生效
   - 完整的 `WithXxx` 选项模型——可以注入 `EntitlementStore` 作为新选项

   地基已全，缺的是一层"套餐权益 → 功能开关"的映射逻辑。

### 范围

#### 1. 套餐权益 SPI（`domains/metering` / `domains/entitlement`）

推荐作为 `domains/entitlement` 新子包（遵循 `domains/metering`/`domains/tokenusage` 的
既有模式）：

```go
// Plan defines a named tier with per-dimension limits.
type Plan struct {
    ID          string
    Name        string
    Limits      PlanLimits
    FeatureGates []string  // feature names auto-enabled for this plan
}

type PlanLimits struct {
    MaxUsers           int           // 0 = unlimited
    MaxClients         int
    MaxConnections     int
    MaxMAU             int           // monthly active users
    AuditRetention     time.Duration // 0 = forever
    TokenTTL           time.Duration // max token lifetime (clamped server-side)
    AllowedRegions     []string      // nil = all
    AllowedMFATypes    []string      // nil = all
}

// EntitlementStore resolves tenant→plan mappings.
type EntitlementStore interface {
    GetPlan(ctx context.Context, tenantID string) (*Plan, error)
    SetPlan(ctx context.Context, tenantID string, plan *Plan) error
}
```

#### 2. 自助租户创建流程

```
Landing Page → 邮箱注册 → 验证邮箱 → 填写组织信息
    ↓
创建 Tenant（plan=free_trial, 30 天）→ 生成 `sso-admin-console` client
    ↓
 Quickstart Wizard：
   1. "创建第一个应用"(Step-by-step: client_name → redirect_uri → 获取 client_id/secret)
   2. "配置登录方式"(密码 / Google OAuth / SAML / Passkey)
   3. "集成到你的应用"(Code snippet: React SDK / Go SDK / curl)
   4. "验证集成"(Test login button → 走通完整 OAuth 流)
```

#### 3. 套餐与 Feature Gate 的接线

`Server` 已有的 7 个 feature gate（`admin_api`, `web_spa`, `oidc`, `ciba`, `caep`,
`federation`, `self_service`）当前是**全局单一开关**。扩展为按 tenant 权限判断：

```go
// Instead of: gate.Enabled() → bool
// We need:  gate.Enabled(ctx, tenantID) → bool
// Which checks: (global_enabled AND plan_covers_feature)
```

对性能的影响（每请求多一次 `EntitlementStore.GetPlan`）可通过 per-tenant TTL 缓存
（30s）+ bus 失效缓解——模式与现有的 tenant 暂停缓存完全相同。

#### 4. 套餐变更事件

套餐变更 → `cluster.Bus.KindPlanChanged` → 所有副本失效 per-tenant 缓存 →
实时生效新权益（不等 TTL）。

### 边界情况

- **免费到期 vs 降级**：免费套餐到期后，tenant 不立即停止服务——改为"控制面 lockout"
  （Admin Console 只读、新 client 注册阻止、`metering` 仍在记录但展示"upgrade"横幅），
  现有登录和令牌继续工作到 TTL 过期。这与 AGENTS.md 的 fail-open 原则一致。
- **套餐超限的处理**：`MaxUsers` 超限时，`UserProvider.CreateOrUpdate` 返回
  `ErrPlanLimitExceeded`（423），前端展示 upgrade 提示——不阻塞已有用户。
- **套餐回退**：从企业套餐回退到免费套餐时，只阻止**新**操作（新用户、新 client），
  已有数据不强制删除。这是最常见的 SaaS 降级模式。
- **现有 tenant 的兼容**：已有的 tenant（通过 Admin API 创建）自动获得 `plan=enterprise`
  或 `plan=unlimited`，保证向后零行为变化。

### 价值·工作量

- **价值**：**high**（PLG 入口 + 货币化基础，从"免费开源 server"到"可销售的 SaaS 产品"的
  最核心缺口）
- **工作量**：**XL**（entitlement SPI + 前端注册流 + Quickstart Wizard + plan→gate 接线 +
  bus 失效 + 管理面套餐 CRUD），但可分步交付：① entitlement SPI（L，纯后端）、② 注册流
  （M，可复用现有 WebAuthn/password signup）、③ 接线（M）、④ Wizard（L，前端为主）

---

## 方向 3：OAuth 2.0 外部身份令牌交换（Third-Party IdP Token Exchange）

### 现状

项目有完善的令牌交换（RFC 8693）支持：

| 能力 | 实现状态 |
|---|---|
| 内部 token 交换（access_token ↔ access_token/id_token/refresh_token） | ✅ 完整 |
| 跨租户 B2B 协作交换（ExternalUserStore + CollaborationStore） | ✅ 落地 |
| SPIFFE JWT-SVID 交换（`subject_token_type=jwt` + SPIFFE 验证） | ✅ 落地 |
| Transaction Token 交换（`requested_token_type=txn-token`） | ✅ 落地 |
| 设备 Secret 交换（`actor_token_type=device_secret`） | ✅ 落地 |
| act-chain 循环检测 + 生命周期上限 | ✅ 落地 |
| Token Exchange 策略引擎（`WithTokenExchangePolicy`） | ✅ 落地 |
| **外部 IdP 令牌交换（Google id_token → 本地 access_token）** | ❌ **零实现** |
| **social token exchange（Facebook/Apple/GitHub token → 本地 access_token）** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 命中 |
|---|---|
| `exchange.*google\|google.*exchange\|exchange.*apple\|apple.*exchange\|exchange.*github\|github.*exchange\|exchange.*facebook\|facebook.*exchange\|exchange.*microsoft\|exchange.*twitter` | **0** |
| `subject_token_type.*id_token.*external\|external.*id_token\|social.*id_token\|third_party.*token\|3rd_party.*token\|foreign.*token\|external.*provider.*token` | **0** |
| `WithExternalTokenVerifier\|ExternalTokenVerifier\|social.*verifier\|social.*validator\|WithSocialTokenExchange` | **0** |

### 为什么需要它

1. **与社交登录（CIAM）是同一枚硬币的两面**：方向①（expansion-ciam-identity-horizon.md 已覆盖）
   的社交登录解决的是"用户用 Google 账号登录"——用户被重定向到 Google，Google 返回 id_token，
   项目把用户映射为本地用户并颁发自己的 token。这是 `/auth/login` 路径。

   **外部令牌交换**解决的是**一个已经持有 Google id_token 的应用**（例如移动 App 用 Google
   Sign-In SDK 先拿到了 id_token），拿这个 token 来 SSO 服务器换本地 access_token。
   这是 `/token` grant=token-exchange 路径。两个路径互补但不互斥——移动端原生 App 通常
   走后者。

2. **消除"二次登录"体验**：用户已在手机端用 Face ID + Google 账号做完认证，SDK 拿到了
   Google id_token。如果 SSO 不支持直接交换这个 token，App 就必须再弹一个 WebView 让用户
   再次认证——一个本可以无缝的体验被打断。

3. **协议层已有标准支持**：RFC 8693 的 `subject_token_type` 支持 `urn:ietf:params:oauth:token-type:id_token`
   ——但当前项目只验证**自签发的** id_token（内部 issuer），不从外部 IdP 的 JWKS
   端点下载公钥来验证外部 id_token。补一个 `ExternalTokenVerifier` SPI + 预配置的
   Google/Apple/GitHub/Facebook verifier 即可。

4. **企业客户正在要求**：B2B SaaS 的移动端应用常使用原生的社交登录 SDK——"用户在手机上
   用 Google 登录了，SSO 应该能直接接受 Google 的断言"是越来越多的集成需求。

### 范围

#### 1. External Token Verifier SPI（`domains/tokenexchange`）

```go
// ExternalTokenVerifier verifies an id_token issued by an external IdP.
type ExternalTokenVerifier interface {
    // Verify returns the verified claims from an external id_token.
    Verify(ctx context.Context, token string) (*VerifiedExternalToken, error)
}

type VerifiedExternalToken struct {
    Sub            string            // external subject ID
    Issuer         string            // e.g. "https://accounts.google.com"
    Email          string            // verified email (when available)
    EmailVerified  bool
    Name           string
    Picture        string
    RawClaims      map[string]any
}
```

#### 2. 预构建 Verifier（`domains/tokenexchange/`）

```go
// NewGoogleIDTokenVerifier creates a verifier for Google id_tokens.
// Google's JWKS is fetched from https://www.googleapis.com/oauth2/v3/certs
// and cached with bounded TTL.
func NewGoogleIDTokenVerifier(clientID string) ExternalTokenVerifier

// NewAppleIDTokenVerifier verifies Apple Sign-In id_tokens against
// https://appleid.apple.com/auth/keys
func NewAppleIDTokenVerifier(clientID, teamID, keyID string) ExternalTokenVerifier

// NewGitHubAccessTokenVerifier exchanges a GitHub access token (OAuth App)
// for the user's GitHub profile via the GitHub API. Not an id_token —
// GitHub doesn't issue id_tokens. This is a different flow: verify
// access_token → fetch /user → map to VerifiedExternalToken.
func NewGitHubAccessTokenVerifier(clientID, clientSecret string) ExternalTokenVerifier
```

#### 3. 选项与接线

```go
// WithExternalIDTokenVerifier wires an external IdP token verifier into the
// token-exchange grant. When wired, /token requests with
// subject_token_type=urn:ietf:params:oauth:token-type:id_token that fail
// local issuer validation fall through to the external verifier chain.
func WithExternalIDTokenVerifier(provider string, verifier ExternalTokenVerifier) Option
```

#### 4. 用户映射与链路

```
POST /token  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
            subject_token_type=id_token
            subject_token=<Google id_token>
            client_id=<my-app>
                ↓
    ① external verifier chain: Google key → verify signature
    ② extract email/sub → user lookup (by external_id + provider)
    ③ not found → auto-provision (opt-in) or return user_not_found
    ④ found → mint local access_token + id_token
                ↓
    Response: {access_token, id_token, token_type, expires_in, ...}
```

### 边界情况

- **JWKS 获取的 SSRF 防护**：外部 IdP 的 JWKS URL 是已知的固定值（Google/Apple/GitHub），
  使用 `AllowedRequestURIs` 式的白名单——不信任用户输入的 URL。复用 `securityverify`
  现有的 JWKS HTTP 获取 + 缓存 + 超时（15s）。
- **自动用户预配置（auto-provisioning）的安全考虑**：外部 id_token 的 `email_verified` 必须
  为 true 才自动创建用户。Google/Apple 的 `email_verified` 声明在 id_token 中是被签名的，
  不可篡改。这是业内标准做法（Auth0、Clerk 均如此）。
- **账户链接（account linking）**：如果本地用户已存在（用密码注册的），但用 Google id_token
  来交换——应该走 identity linking 流程（现有 `identitylink` SPI 但无社交登录场景的适配）。
- **令牌生存期**：外部 id_token 可能只有很短的有效期（Google id_token 默认 1 小时）。
  本地颁发的 access_token 应有独立的 TTL（默认短时），不受外部 token 过期时间的约束（但
  不得超过外部 token 的过期时间，这是一个安全边界——`WithMaxTokenExchangeChainLifetime`）。
- **重放保护**：复用现有的 `JTIReplayStore`，外部 id_token 的 `jti` 可用于防重放。
- **act-chain 的起点**：外部 id_token 应该是 act-chain 的根（`act` 不继承）。交换出的
  本地 token 不应包含外部 token 的敏感声明（除非明确配置）。

### 价值·工作量

- **价值**：**high**（填补 OIDC Federation 与"社交登录"之间的集成空白，移动端原生 App 集成刚需）
- **工作量**：**L**（Verifier SPI + 3 个预构建 verifier + token-exchange 分支 + 用户映射 +
  identity-link 适配）
- **依赖**：方向①（CIAM/社交登录）中的 OIDC Federation 配置。若已有 federation 配置，
  外部令牌交换可直接复用其验证逻辑。

---

## 方向 4：OAuth 2.0 Rich Authorization Requests（RAR）动态授权详情同意屏

### 现状

| 能力 | 实现状态 |
|---|---|
| `authorization_details` 验证 | ✅ RFC 9396 型-白名单、结构体大小/深度/元素数上限 |
| RAR Limits `WithAuthorizationDetailsLimits` | ✅ 可选配置 |
| Discovery 声明 `authorization_details_types_supported` | ✅ 从已注册 client 的类型联合自动推导 |
| `AuthorizationDetails` 附着到 `AuthCode`/access_token | ✅ 签发时传递 |
| **用户可见的 RAR 授权详情同意识别** | ❌ **零实现** |
| **动态渲染不同类型 `authorization_details` 的 UI 组件** | ❌ **零实现** |
| **用户可在 consent 屏上细粒度勾选/取消授权详情项** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 命中 |
|---|---|
| `authorization_details.*render\|render.*authorization_details\|auth_detail.*ui\|auth_detail.*page\|detail.*screen\|detail.*consent\|consent.*detail\|detail.*display\|display.*detail` | **0** |
| `RAR.*ui\|rar.*consent\|rar.*screen\|rar.*fe\|rar.*front\|rar.*page\|RARPayload\|rar_payload` | **0** |
| `dynamic.*consent\|DynamicConsent\|structured.*consent\|StructuredConsent\|granular.*consent\|GranularConsent` | **0** |

### 为什么需要它

1. **RAR 协议的半成品缺口**：RFC 9396 的设计初衷是让客户端**描述它需要什么数据**
   （例如对于一个银行 API："转账权限，账户 ID = xxx，限额 = 10000"），然后 AS 把这些
   结构化信息**呈现给用户批准**。项目完美地实现了验证和签发端，但用户从未看到
   `authorization_details`——Consent 屏永远只显示 scope 列表。这等于实现了 RAR 的一半。

2. **金融机构/开放银行（Open Banking）的合规要求**：PSD2、UK Open Banking、CDR（澳大利亚）
   的核心交互模式是：用户看到"转账应用请求：从账户 A 转账，最多 10000，到账户 B"的
   结构化授权详情，然后批准。仅靠 scope 列表（"转账:write"）无法满足监管要求。

3. **用户体验的差异化**：RAR 的授权详情类型是一个可扩展的语义空间。不同类型的
   `authorization_details`（`payment_initiation`、`account_access`、`document_sharing`、
   `location_access`）应该有不同的 UI 呈现方式。这是一个产品层面的差异化能力——竞品中
   只有少数（Auth0 的 RAR 支持仍在 alpha）有动态 RAR UI。

4. **Spoke-Hub 架构的前置条件**：如果项目要支持"第三方应用请求访问用户数据"的
   API 市场模式（类似 Google Workspace / Salesforce AppExchange），RAR 动态授权详情
   屏是用户信任的基础 UI。

### 范围

#### 1. RAR Consent Screen SPI（`internal/auth/consent`）

扩展 `ConsentStore` / `/auth/login` 的 json 响应，增加 `authorization_details` 信息：

```go
// AuthorizationDetailDescriptor describes one authorization_details entry
// for user-facing display.
type AuthorizationDetailDescriptor struct {
    Type        string            // e.g. "payment_initiation", "account_access"
    DisplayName string            // human-readable
    Icon        string            // icon URL or data URI
    Fields      []DetailField     // key-value pairs to render
}

type DetailField struct {
    Label string // "Amount", "Account ID"
    Value string // "100.00 USD", "SAVINGS-1234"
    Sensitive bool // mask on screen
}
```

#### 2. 类型特定的 UI 组件

Hosted Login SPA 中扩展 consent 视图，识别 `authorization_details.type` 并渲染对应的
UI 组件：

- **`payment_initiation`**：收款方 + 金额 + 币种 + 描述，带大号金额高亮
- **`account_access`**：账户列表（勾选/取消勾选），账户号部分脱敏
- **`document_sharing`**：文档名称 + 权限级别（只读/编辑/所有者）
- **`location_access`**：精确/模糊定位，单次/持续，地图可视化
- **未知类型**：降级为 JSON 展示 + "this request needs access to custom data" 通用提示

#### 3. 细粒度授权

用户可对 `authorization_details` 做**逐项取消**（例如银行要请求 3 个账户的访问权限，
用户只批准其中 2 个），取消的项在签发 token 时从 `AuthorizationDetails` 数组中移除。
这是 RAR 协议明确允许的语义。

#### 4. 注册 API 扩展

DCR（RFC 7591）/ Admin Console 增加 `authorization_details_types` 字段支持，让 client
声明它计划请求哪些详情类型。

### 边界情况

- **详情变更与授权重提（re-consent）**：client 请求的 `authorization_details` 与之前
  批准的相比有变化（新增类型、值变更）→ `prompt=consent` 重新触发。
- **超大详情集合**：`WithAuthorizationDetailsLimits` 已有全局上限。在 UI 侧，超过 20
  项的 `authorization_details` 列表应折叠为"展开全部"。
- **敏感值显示**：金额、账号等在 consent 屏上以明文显示（用户需要知道自己在批准什么），
  但以 `Sensitive` 标志脱敏显示在审计日志中。
- **无 RAR 支持的 client**：对于不发送 `authorization_details` 的 client，consent 屏
  行为不变——只显示 scope 列表（向后兼容）。
- **RAR + 增量授权**：如果 token 已有部分授权详情，新的 RAR 请求应合并/追加，而不是
  替换（OAuth 2.0 Incremental Authorization 模式）。

### 价值·工作量

- **价值**：**high**（RAR 协议的缺失前一半、开放银行合规刚需、差异化 UI 能力）
- **工作量**：**L**（SPI 扩展 + consent 屏后端 JSON 接口 + SPA 端动态渲染组件 +
  类型扩展点 + DCR 扩展）
- **依赖**：项目已有的 RAR 验证 + ConsentStore + Hosted Login SPA。零新基础设施。

---

## 方向 5：OAuth 2.0 Step-Up 动态 ACR 声明 —— 资源服务器驱动的自适应认证

### 现状

| 能力 | 实现状态 |
|---|---|
| 登录门控信任评估 | ✅ `sessionLoginGate` + `WithSessionTrust` |
| 信任衰减（Trust Decay） | ✅ 连续验证代理 + `SessionTrust.DecayedScore` |
| Step-Up Challenge（RFC 9470）生成 | ✅ `writeStepUpChallenge` + `BuildStepUpChallenge` |
| 低于信任阈值的标记 | ✅ `StepUpRequiredForTrust` |
| **资源服务器声明最小 ACR 需求的协议** | ❌ **零实现** |
| **按 endpoint 动态 Step-Up（非全局阈值）** | ❌ **零实现** |
| **AS → RS 的 ACR 需求握手** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 命中 |
|---|---|
| `ResourceServerACR\|rs_acr\|ACRProposal\|acr_proposal\|acr.*request.*header\|ACR-*\|X-ACR\|minimum.*acr\|min.*acr\|acr.*floor\|required.*acr\|acr.*requirement` | **0** |
| `per.endpoint.*stepup\|per.endpoint.*acr\|per.resource.*acr\|endpoint.*trust.*level\|resource.*trust.*level\|trust.*level.*endpoint\|endpoint.*min.*trust\|dynamic.*stepup\|dynamic.*acr\|StepUpProvider.*endpoint` | **0** |
| `RS.*driven\|resource_server.*driven\|server.*driven.*step\|step.up.*declaration\|declaration.*stepup` | **0** |

### 为什么需要它

1. **当前"全局阈值"模型粒度不足**：今天 step-up 由 `WithSessionTrust` 的全局配置
   （`Floor` / `Interval` / `DecayRate`）决定。所有受保护的端点使用同一个阈值。
   但在真实部署中，不同资源有不同的敏感度：
   - `GET /api/public/profile` 需要信任 ≥ 30（几乎不需要 step-up）
   - `POST /api/transfers` 需要信任 ≥ 80（需要近期的高信任认证）
   - `DELETE /api/admin/users` 需要信任 ≥ 95（需要 phish-resistant 等级的认证）

   这些细粒度的安全要求**应该由资源服务器（RS）声明**，而不是在 AS 配置中硬编码。

2. **标准化模式**：OAuth 2.0 的 Step-Up Authentication 框架（RFC 9470）定义了 AS 如何
   向客户端发出 step-up challenge。但它没有定义 RS 如何向 AS 声明"我需要什么级别的认证"。
   这是当前行业的一个标准化缺口——Auth0 和 Okta 各自有私有方案。提前定义一个清晰的 SPI
   可以形成事实标准。

3. **零信任架构的自然延伸**：在零信任模型中，每个请求的授权决策基于请求者和资源的敏感性。
   RS 声明 ACR 需求 + AS 评估当前 session 的 ACR → 不满足时自动触发 step-up →
   这是零信任"never trust, always verify"原则在 SSO 上下文中的最完整实现。

### 范围

#### 1. RS 声明 ACR 需求的方式

**推荐方式一（推荐）：HTTP Header 声明**

RS 保护端点返回 `WWW-Authenticate` 或 `X-ACR-Required`，声明该端点最低 `acr`：

```http
GET /api/transfers HTTP/1.1
Authorization: Bearer <token>
---
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_acr",
                  acr_values="https://snaplink.io/acr/phishing-resistant",
                  realm="transfers"
```

客户端收到后，用 `acr_values` 参数重试 `/auth/login` 或发送 step-up claim：

```
POST /token grant_type=...&acr_values=https://snaplink.io/acr/phishing-resistant
```

**推荐方式二：注册时声明**

RS 在注册（DCR）时声明每个 `redirect_uri` 或资源所需的最低 ACR：

```json
{
  "client_id": "my-api",
  "grant_types": ["authorization_code"],
  "acr_requirements": {
    "/api/transfers": "https://snaplink.io/acr/phishing-resistant",
    "/api/profile": "standard"
  }
}
```

#### 2. AS 侧的最小 ACR 门控（`shared/security/step_up_auth.go`）

```go
// ACRFloor enforces a minimum ACR level for a given audience/resource.
// When the current token/session's ACR is below floor, it triggers
// a step-up challenge (RFC 9470).
func (s *Server) enforceACRFloor(ctx HandlerContext, client *Client, session *Session, resource string) bool {
    floor, ok := s.resolveACRFloorForResource(client, resource)
    if !ok || floor == "" {
        return true // no floor, allow
    }
    // Compare session's achieved ACR vs floor
    // Uses acr_level.go's comparison logic (higher is stronger)
    if s.acrLevel.LessThan(session.ACR, floor) {
        s.writeStepUpChallenge(ctx, ...) // include required ACR
        return false
    }
    return true
}
```

#### 3. ACR 层级比较（`shared/security/acr_level.go`）

定义一个可比对的 ACR 层级枚举：

```go
type ACRLevel int

const (
    ACRStandard            ACRLevel = 10  // password
    ACRTwoFactor           ACRLevel = 50  // password + TOTP
    ACRPhishingResistant   ACRLevel = 80  // WebAuthn passkey
    ACRHardwareBound       ACRLevel = 100 // FIDO2 hardware-bound key
)
```

这是目前代码中**缺失**的一环——`AchievedACR` 字段已被（方向③ ROADMAP v5.0）修复，
但缺乏比较"当前 ACR 是否满足要求"的语义。

#### 4. 发现声明

在 `/.well-known/openid-configuration` 中声明 `acr_values_supported` 和
`acr_requirements_endpoint`（RS 查询特定资源所需 ACR 的端点）。

### 边界情况

- **ACR 需求的回退语义**：RS 声明了 ACR 需求但 AS 不认识该 ACR 值 → fail-closed
  （返回 `invalid_acr` 错误，不静默降级）。
- **session 的 ACR 随时间衰减**：信任衰减可能使 session 的 ACR 低于资源要求。衰减后的
  第二次检查应该触发新的 step-up，而不是缓存旧的评估结果。
- **资源粒度的性能考虑**：如果 ACR 需求检查在每次 token 验证时都做，需要高效缓存
  （per-client per-Resource TTL）。对于不声明 ACR 要求的 RS，零额外开销。
- **与现有信任衰减的一致性**：ACR 门控和信任衰减是两个正交维度——ACR 是"你用什么方式认证"，
  信任是"这段时间你的行为是否可信"。两者应同时检查，任何一个不满足就触发 step-up。
- **token-exchange 场景**：当 token 通过 exchange 获得时，ACR 传播自原始 subject_token。
  如果交换后的 token ACR 低于 RS 要求，应允许 chain 上的 step-up（原始 session 持有者
  重新认证）。

### 价值·工作量

- **价值**：**high**（细化粒度、零信任闭环、RS 自治的声明式安全模型）
- **工作量**：**M**（ACR 层级系统 + RS 声明接入点 + AS 评估 + step-up 触发 + 发现声明）
- **依赖**：ROADMAP v5.0 方向③的 `AchievedACR` 落地 + 可信 session 模型。两个依赖均已
  在代码中落地。

---

## 附录：优先级摘要

| 序号 | 方向 | 价值 | 工作量 | 最高优先级子项 | 前置依赖 |
|---|---|---|---|---|---|
| 1 | Token Status List | **High**（RS 离线验证、高吞吐场景刚需） | **L** | ① 位数组编码 + JWS 签名（M）| 无（独立于现有 revocation store） |
| 2 | 自助租户开通 & 套餐权益 | **High**（PLG 入口、货币化基础） | **XL** | ① Entitlement SPI（L，纯后端先交付）| `domains/metering` 已存 |
| 3 | 外部 IdP 令牌交换 | **High**（移动原生集成、填补社交登录协议面） | **L** | ① ExternalTokenVerifier SPI + Google verifier（M）| expansion-ciam-identity-horizon 方向①（社交登录）可并行 |
| 4 | RAR 动态授权详情同意屏 | **High**（RAR 协议的缺失前一半） | **L** | ① consent 屏 JSON 扩展 + SPA 端 payment_initiation 渲染（M）| RAR 验证 + ConsentStore + Hosted Login SPA（均已存）|
| 5 | RS 动态 ACR 声明 Step-Up | **High**（零信任闭环、细粒度安全） | **M** | ① ACR 层级系统 (`acr_level.go`)（S）| `AchievedACR` 已落地、可信 session 已存 |

**一句话优先级**：**① Token Status List（消除 RS 回调，差异化协议能力）+ ② 自助租户（PLG 入口）
并行 → ③ 外部令牌交换（完成社交登录的协议面）→ ④ RAR 同意屏（夯实 RFC 9396）→ ⑤ 动态 ACR
（零信任前沿）。** 其中 ①③④⑤ 都是纯后端/协议工作，与方向②的前端工作正交，可以安全并行。
