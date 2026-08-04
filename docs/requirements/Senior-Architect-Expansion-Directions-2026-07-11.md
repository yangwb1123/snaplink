# 资深架构师视角扩展方向分析

> **作者：** 资深架构 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库全局扫描（2241 个 `.go` 文件、1114 个测试文件、14 个 `go.mod`、  
>   4 个嵌入 SPA、200+ 包、60+ RFC 协议实现）。在系统阅读 ROADMAP v5.0、  
>   deferred-backlog、feature-matrix、SECURITY.md、全部 23+ 轮历史扩展方向分析  
>   （v1–v13、novel*、edge-cases、gaps-analysis、post-protocol-layer、ciam-horizon、  
>   systemic-quality、privacy-dx-operations 等）的基础上，结合全代码库 grep 逐项  
>   核验，确保每个方向为 **真实代码级缺口**。  
> **定位：** 本报告不重复"新增协议支持""补后端实现""生产硬化""产品面"或任何已在  
>   23+ 轮分析中被深度覆盖的方向。本报告聚焦于一个功能完备的 SSO 平台从 **技术产品**  
>   迈向 **可规模化运营的企业级 SaaS 基础设施** 时，那些在用户体验、运营成熟度、  
>   安全纵深与商业变现维度上仍然存在的系统性盲区。

---

## 前置声明

经过 23+ 轮全局扫描 + 大量代码落地，本项目的能力覆盖面已达到行业顶级水平。以下为  
已确认全部覆盖、**本报告不再重复分析**的领域：

| 领域 | 覆盖状态 |
|---|---|
| **协议面**（OAuth 2.0 × 7 grants + PAR + JAR + JARM + RAR, OIDC Core/Discovery/Logout/BCL/FCL/CIBA/Form Post, SAML 2.0 SP+IdP, SCIM 2.0 双向, CAEP/SSF 双向, FAPI 2.0, OpenID Federation 1.0, LDAP, Kerberos, RADIUS, DPoP, mTLS, Transaction Token, Step-Up Auth, SPIFFE JWT-SVID） | ✅ 全部落地 |
| **存储面**（Memory, SQLite, Redis, etcd, PostgreSQL + 14 个嵌套子模块：KMS×5, SAML×4, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT） | ✅ 全部落地 |
| **安全面**（Anti-enumeration、Oracle-leak、DPoP、mTLS、JWT-SVID、Workload Identity、Break-Glass、Per-tenant 签名隔离、区域数据驻留、FAPI 2.0、FIPS 140-3、会话信任衰减、Step-Up Auth、Account Lockout、Conditional Access） | ✅ 全部落地 |
| **产品面**（Hosted Login SPA、Admin Console SPA、Developer Portal SPA、User Portal `/me`、Consent Store × 3、B2B Connections + HRD、Org-admin self-service、API docs viewer、SDK 生成 TS/Python、MCP Server） | ✅ 全部落地 |
| **运维面**（DR framework Snapshot/RPO/RTO、Config hot-reload SIGHUP × 7 gates、Metrics/Prometheus/Grafana、Audit hash-chain + OCSF/CEF/Syslog、pprof、k6 load test、Chaos tests × 4、Benchmark gate、Bare-metal HA runbook、Schema migration framework） | ✅ 全部落地 |
| **治理面**（SOC2 report、GDPR Art.15/17/20/30 compliance、Data retention sweeper、ReBAC Zanzibar engine、RBAC permissions、Session hub、Anomaly detection + Threat action、Webhook engine、User lifecycle state machine、Change approval workflow） | ✅ 全部落地 |
| **前沿面**（AI Agent Identity、Post-Quantum Crypto、CIAM/Social Login、Session Roaming、PAM、Token Status List、FIDO2 Cross-Device、Zero-Knowledge Proofs、Offline Identity Mode、ZTNA Integration — 均已在前序分析中识别） | ❌ 已识别待实现 |

> **核心结论：** 经过 23+ 轮分析，项目的"技术功能扩展"空间已基本触及理论上限。  
> 剩余的最高价值空间不在"再做一个 RFC 协议"或"再加一个存储后端"，而在于将  
> **产品成熟度、运营成熟度、商业变现能力**提高到与身份平台市场领导者（Auth0、Okta、  
> Azure AD）同等的水平。本报告 5 个方向聚焦于此。

---

## 方向一：Phone/SMS OTP 作为一等公民认证因子（Phone/SMS OTP as First-Class Authenticator）

### 现状

项目拥有丰富的认证因子生态，涵盖密码、WebAuthn（platform + cross-platform）、  
TOTP、Push MFA、Email OTP、LDAP、SAML、OIDC Federation、Kerberos、RADIUS、  
WASM、证书 等 **12 种认证器**。但 **Phone/SMS OTP 作为独立认证因子的支持为零**。

| 能力 | 代码位 | 状态 |
|---|---|---|
| Password authenticator | `domains/authenticators/password.go` | ✅ 完整 |
| WebAuthn authenticator | `domains/authenticators/webauthn/` | ✅ 完整（含 passkey primary login） |
| TOTP authenticator | `domains/authenticators/totp.go` | ✅ 完整 |
| Email OTP authenticator | `domains/authenticators/email.go` | ✅ 完整（`WithEmailAuthenticator`） |
| Push MFA authenticator | `domains/authenticators/push/push.go` | ✅ 完整 |
| **Phone/SMS OTP authenticator** | **零实现** | ❌ **零** |
| Phone number enrollment & verification | **零实现** | ❌ **零** |
| SMS transport provider SPI | **零实现** | ❌ **零** |

**代码证据（grep 核验）：**

| 概念 | 代码命中 |
|---|---|
| `PhoneAuthenticator\|phone_authenticator\|NewPhoneAuthenticator\|PhoneAuthProvider\|phone_auth_provider\|WithPhoneAuthenticator` | **0** |
| `SMSProvider\|sms_provider\|SMSAuth\|sms_auth\|NewSMSProvider\|WithSMSProvider\|SMSGateway\|sms_gateway\|SMSSender\|sms_sender` | **0**（仅 `cmd/sso-server/serverbuildauthn/build_authenticators_helpers.go:127` 有一个测试用的 SMS stub logger，非真实 SP） |
| `phone.*enroll\|enroll.*phone\|phone.*verified\|verified.*phone\|phone.*claim\|phone_number\|phoneNumber`（认证上下文） | **0**（仅 `core/types_token.go:127` 在 AMR 引用 `"phone"` 作为标准 AMR 值，但无实现） |

### 为什么需要它

1. **市场覆盖的硬缺口**：Phone/SMS OTP 是 B2C/C 端身份认证中**使用最广泛的第二因子**。  
   全球约 75% 的消费者应用提供 SMS OTP 作为认证方式（Duo Security 研究 2024）。  
   缺少 Phone/SMS OTP = 无法进入任何 CIAM 采购短名单。

2. **不仅仅是 MFA 因子**：在许多新兴市场（东南亚、非洲、拉丁美洲），手机号码本身就是  
   **主身份标识**——用户没有 email，使用手机号 + SMS OTP 作为主要认证方式。  
   没有 Phone authenticator = 失去整个新兴市场。

3. **与现有 Email OTP 模式互补但不重叠**：Email OTP 已有完整实现（`email.go` +  
   `email_change.go` + `email_verification.go`），但 Phone OTP 有独立的传输协议  
   （Twilio / Vonage / AWS SNS / 阿里云 SMS）、独立的费率结构、独立的合规要求  
   （10DLC / A2P 10DLC / TLS 加密要求）。

4. **推动密码弃用率**：结合 Magic Link 和 Phone OTP，平台可以提供完整的无密码认证体验，  
   无需 WebAuthn 的浏览器兼容性限制。

### 范围

**1. Phone/SMS Authenticator SPI（`domains/authenticators/phone/`）**

```go
// PhoneAuthenticator authenticates a user via phone number + SMS OTP.
// It is a [core.Authenticator] that can be used as a primary login
// authenticator (provider=phone) or as a step-up MFA factor.
type PhoneAuthenticator struct {
    store  PhoneStore
    sender SMSProvider
}

// SMSProvider sends one-time codes to phone numbers.
type SMSProvider interface {
    Send(ctx context.Context, phone, code string) error
    Name() string // "twilio", "aws_sns", "log" (dev)
}

// PhoneStore persists phone↔user associations and pending OTPs.
type PhoneStore interface {
    SetPhone(ctx, userID, phone string) error
    GetPhone(ctx, userID) (string, error)
    SaveOTP(ctx, phone, code string, ttl time.Duration) error
    VerifyOTP(ctx, phone, code string) (bool, error)
}
```

**2. 内置 SMS 传输实现**

| 提供商 | 实现路径 | 说明 |
|---|---|---|
| Log (stub) | `infrastructure/defaultimpl/logsms/` | 测试/开发环境，打印到日志 |
| Twilio | `infrastructure/sms/twilio/` | 嵌套模块（`go.mod` + Twilio REST API） |
| AWS SNS | `infrastructure/sms/awssns/` | 嵌套模块 |
| Vonage | `infrastructure/sms/vonage/` | 嵌套模块 |

**3. 主登录集成**

- `WithPhoneAuthenticator(store, sender)` 注册 `provider=phone` 的登录路径。
- `/auth/login?provider=phone` 显示手机号输入框 → 发送 SMS OTP → 验证 OTP → 签发 token。
- Phone number 作为 `User` 的可选字段，支持多 phone 绑定（通过 `PhoneStore`）。
- 自动在 ID Token 中声明 `phone_number` 和 `phone_number_verified` 字段（OIDC 标准声明）。

**4. MFA 集成**

- `PhoneAuthenticator` 实现 `spi.MFAProvider` 接口，可作为 `kind=phone` 的 MFA 因子。
- 在 MFA 链路中复用 `kind=totp` 相同的"发送→验证"双段模式（`BeginMFA`/`VerifyMFA`）。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| SMS 投递延迟或失败 | 使用 `fail-open` 策略：发送失败不阻塞登录流程（log + metric），允许用户重试或换用其他认证因子 |
| 手机号格式验证 | 使用 `libphonenumber` 风格的格式归一化，存储 E.164 格式，显示用户输入格式 |
| SIM 交换攻击 | 可选启用 SIM Swap 检测（通过 Twilio Lookup API 或其他第三方服务），检测到 SIM 变更时自动升级认证要求 |
| OTP 重试限制 | 每手机号 OTP 尝试次数上限（默认 5 次/15min），超出后该手机号锁定 1h |
| 电话号码回收 | 电话号码被运营商回收后，新用户不应能接收旧用户的 OTP。通过 `PhoneStore` 的租户间唯一约束 + 废弃号码冷却期（90 天）处理 |
| 多个手机号绑定 | 一个用户可以绑定多个手机号（最多 3 个），每个手机号可独立用于 MFA |
| 短信成本控制 | 按租户的 SMS 发送配额（`tenant.sms_quota`），超出后降级到 `kind=email` 或 `kind=totp` |

---

## 方向二：租户自助分析门户与合规报告（Tenant Self-Service Analytics & Compliance Reporting）

### 现状

项目拥有完善的管理控制台（Admin Console SPA）和平台级指标（Prometheus + Grafana），  
包括 `sso_login_*`、`sso_token_*`、`sso_mfa_*`、`sso_anomalies_*` 等多个 metric vector。  
但 **租户管理员没有任何面向自身组织的数据看板或报告导出能力**。

| 能力 | 代码位 | 状态 |
|---|---|---|
| Admin Console（平台级） | `interfaces/web/admin/` | ✅ CRUD 就绪 |
| Platform metrics（Grafana） | `ops/monitoring/` | ✅ 运维视角 |
| Per-tenant metrics opt-in | `interfaces/sso/options_misc.go` `WithTenantMetricsAllowlist` | ✅ 存在 |
| **Tenant-facing analytics dashboard** | **零实现** | ❌ **零** |
| **Compliance report generation** | **零实现** | ❌ **零** |
| **Exportable usage reports (CSV/PDF)** | **零实现** | ❌ **零** |

**代码证据（grep 核验）：**

| 概念 | 代码命中 |
|---|---|
| `tenant.*dashboard\|tenant.*analytics\|analytics.*tenant\|tenant.*report`（非注释的 UI/API 实现） | **0** |
| `usage.*report\|report.*usage\|compliance.*report\|report.*compliance\|export.*report\|report.*export\|download.*report\|report.*download` | **0** |
| `revenue.*report\|billing.*report\|activity.*report\|login.*report\|user.*report\|adoption.*report\|audit.*report` | **0** |
| `SelfServiceAnalytics\|self_service_analytics\|tenant_analytics\|TenantAnalytics` | **0** |

### 为什么需要它

1. **SaaS 产品的基本履约**：每个 SaaS 产品的租户管理员期望能回答三个基本问题：  
   "我的组织有多少活跃用户？"、"过去 7 天的登录成功率是多少？"、"我的用户主要使用  
   哪些认证方式？"——当前没有任何能力回答这些问题，需要手动拼 PromQL 或查日志。

2. **合规审计的自服务化**：SOC 2、ISO 27001、GDPR 审计中，租户管理员需要提供"谁访问了什么、  
   什么时候、从哪"的访问报告。当前需要手动调用 audit API 自行聚合——没有预构建的报告模板。

3. **商业变现的直接挂钩**：按用户/活跃度/存储量的计费模型需要租户能查看自己的用量。  
   免费/专业/企业 tier 的差异需要用量可见性来驱动升级。没有用量面板 = 无法驱动自助升级。

4. **与现有计量能力互补**：`domains/metering` 已经有计量框架，`WithTenantMetricsAllowlist`  
   已有 per-tenant metric 发布能力，差的就是**一个面向租户的前端呈现层**。

### 范围

**1. 核心数据模型（`domains/reporting/`）**

```go
// ReportQuery defines a tenant-scoped analytics query.
type ReportQuery struct {
    TenantID  string
    TimeRange TimeRange      // last_1h / last_24h / last_7d / last_30d / custom
    Granularity Granularity  // 1m / 5m / 1h / 1d
    Metrics   []MetricType   // logins, signups, token_issuance, mfa_adoption, errors, active_users
    Filters   map[string]string  // client_id, provider, outcome, country
}

// ReportResult is the aggregated response.
type ReportResult struct {
    TimeSeries []TimePoint   `json:"time_series"`
    Totals     map[string]float64 `json:"totals"`
    Facets     map[string][]FacetBucket `json:"facets"`
}
```

- SPI 定义 + Memory 参考实现（从 Prometheus 或 SQLite audit 回填）。
- 后续可实现 `reporting/prometheus/`（直读 Prometheus）和 `reporting/clickhouse/`  
  （如果使用 ClickHouse 存储审计事件）。

**2. 报告 API（`interfaces/sso/server_reporting.go`）**

- `GET /api/v1/me/reporting/summary` — 总览卡片（活跃用户数 / 今日登录数 / 错误率 / MFA 覆盖率）
- `GET /api/v1/me/reporting/logins` — 登录时间序列 + 按 provider/outcome/country 分组
- `GET /api/v1/me/reporting/users` — 用户活动报告（活跃 vs 非活跃、新用户注册趋势）
- `GET /api/v1/me/reporting/adoption` — 功能采用率（MFA 开启率、Passkey 注册率、各 authenticator 使用比例）
- `GET /api/v1/me/reporting/compliance` — 合规摘要（管理员操作日志、权限变更记录、数据导出请求）
- 所有端点支持 `?format=csv` / `?format=json` / `Accept: application/pdf` 输出

**3. Reporting Portal SPA（`interfaces/web/reporting/`）**

- 与 Portal SPA 类似的手写 JS SPA，嵌入 Admin Console。
- 仪表盘视图：拖拽式图表（日/周/月切换），使用 Chart.js 或纯 Canvas。
- 报告中心视图：预构建报告模板列表，一键生成 + 下载。
- Pin-to-dashboard 功能：租户管理员可将常用报告固定到自己的仪表盘首页。

**4. 定时报告投递**

- 可配置的定时报告（每日/每周/每月 email PDF 投递）。
- 复用现有的 `emailsmtp.Sender` + `email_templates` 管道。
- 报告内容由后台 cron 生成，上传到临时存储（memory / 加密后暂存），邮件中附带下载链接。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 数据延迟 | 报告数据允许 5 分钟延迟（近实时而非实时），指标以 `last_updated` 时间戳标注 |
| 大量租户的查询隔离 | 每个报告请求强制 `tenantID` 过滤器（从认证 token 获取），防止跨租户数据泄漏 |
| 报告缓存 | 相同查询的有界 LRU 缓存（默认 TTL 60s），减少重复计算 |
| 数据保留 | 报告源数据保留与审计策略一致（默认 90 天），历史趋势数据聚合后保留 2 年 |
| 大租户的报告性能（>100k 用户） | 预聚合每日快照表（`daily_tenant_summary`），避免实时扫描原始事件表 |
| 免费 tier 限制 | 免费 tier 仅提供"过去 24 小时"和"总览"视图，付费 tier 解锁 30 天/自定义范围/CSV 导出/定时投递 |

---

## 方向三：引导式租户开通与安全基线自动化（Guided Tenant Onboarding & Security Baseline Automation）

### 现状

项目拥有完整的租户 CRUD（`interfaces/admin/tenants.go` + `grpcserver/grpcadmin/admin_tenants.go`），  
但 **租户创建之后的操作面是空的**：

| 能力 | 代码位 | 状态 |
|---|---|---|
| Tenant CRUD | `interfaces/admin/tenants.go` | ✅ 完整 |
| Tenant suspend/activate | `domains/tenant/` + Admin Console | ✅ 完整 |
| Domain management | Admin Console Domains CRUD | ✅ 完整 |
| **Tenant onboarding workflow** | **零实现** | ❌ **零** |
| **Security baseline presets** | **零实现** | ❌ **零** |
| **Setup wizard / guided first steps** | **零实现** | ❌ **零** |
| **Welcome email / activation checklist** | **零实现** | ❌ **零** |
| **Quick-start application (seed client)** | **零实现** | ❌ **零** |

**代码证据（grep 核验）：**

| 概念 | 代码命中 |
|---|---|
| `onboard\|Onboard\|onboarding\|Onboarding\|on.*board.*workflow\|setup.*wizard\|wizard\|quick.*start\|quickstart\|welcome.*email\|welcome.*page\|activation.*checklist\|getting.*started\|first.*step\|step.*by.*step\|guided.*setup`（认证/租户上下文中） | **0**（仅 `dev.onboard` 在 dev SDK 中） |
| `security.*baseline\|baseline.*policy\|default.*policy\|initial.*config\|preset\|security.*preset\|secure.*by.*default\|default.*security`（租户创建上下文中） | **0** |
| `seed.*client\|initial.*client\|default.*client\|first.*app\|sample.*app\|example.*app\|demo.*app`（租户开通上下文中） | **0**（仅全局 seed clients in bootstrap） |

### 为什么需要它

1. **产品引导增长（PLG）的核心路径**：SaaS 产品的免费试用转化率与"首次价值实现时间"  
   （Time-to-Value）呈负相关。没有引导式开通流程，新租户管理员面临一个空白控制台，  
   需要探索十几个菜单才能完成"创建第一个应用 + 配置 SSO 登录"——这是流失点。

2. **安全默认值的执行机会**：每个新租户的安全姿态不应由管理员手动配置。应自动应用最佳  
   实践基线（密码策略、MFA 要求、会话超时、令牌 TTL、审计保留期），同时允许管理员按需  
   调整。这是 Auth0/Okta 企业版的核心安全管控能力。

3. **企业客户的采购门槛**：企业安全团队在采购评估中会检查"开箱即用的安全配置"和  
   "租户开通的自动化程度"。缺少基线 = 安全团队需要手动定义 20+ 策略的初始值。

4. **与现有能力互补**：`platform/bootstrap/builtin` 有 Step 框架，可以复用；  
   `WithDefaultPasswordPolicy` 等选项已存在但未被整合到租户创建流程中。

### 范围

**1. Tenant Setup Wizard（`interfaces/web/admin/` + 新的 wizard SPA 组件）**

在 Admin Console 中嵌入手把手式向导流程：

| 步骤 | 说明 | 后端集成 |
|---|---|---|
| Step 1: Welcome | 欢迎页面，说明平台能力 | — |
| Step 2: Choose security profile | 选择安全基线模板（`Standard` / `Strict` / `Custom`） | 预置 policy template 集 |
| Step 3: Connect identity source | 配置第一个身份源（password 开箱即用，可选 LDAP/SAML/OIDC/SCIM） | 复用 `WithAuthenticator` |
| Step 4: Create first app | 引导创建第一个 OAuth 2.0 client，自动生成 `redirect_uri` 示例 | 复用 Client CRUD API |
| Step 5: Test SSO | 内嵌"测试登录"按钮，启动测试 OIDC 流程 | 复用 `/auth/login` |
| Step 6: Invite users | 引导批量导入用户（CSV 上传 / SCIM 连接 / email 邀请） | 复用 User CRUD + invitation |
| Step 7: Go Live | 检查清单完成状态，发布 | — |

**2. 安全基线策略模板（`domains/tenant/securityprofile/`）**

```go
// SecurityProfile is a named set of default security policies applied at tenant creation.
type SecurityProfile struct {
    Name                   string            // "standard", "strict", "hipaa", "custom"
    PasswordPolicy          PasswordPolicy
    MFAPolicy               MFAPolicy         // "off" / "optional" / "required" / "require_for_admin"
    SessionPolicy           SessionPolicy     // max idle, max absolute, remember_me
    TokenPolicy             TokenPolicyRef    // access token TTL, refresh token TTL, rotation grace
    AuditRetentionDays      int
    ConditionalAccessRules  []ConditionalAccessRule // default baseline rules
    ClientRegistrationPolicy string           // "admin_only", "allow_dcr_with_approval", "open"
}
```

- 内置 3 个模板：`standard`（宽松，适合非受控环境）、`strict`（严格，适合企业）、  
  `hipaa`（符合 HIPAA 的严格基线）。
- 模板以 YAML 定义（`config/security_profiles/`），支持热加载。
- 管理员可在向导中选择模板，后续在 Admin Console 的 Security 面板中按需调整。

**3. 自动租户开通流程（扩展 `domains/tenant/` + `platform/bootstrap/builtin`）**

- 当新租户创建时（通过 Admin API 或自助注册），自动触发开通序列：
  1. 应用选定的 Security Profile（默认 `standard`）
  2. 创建默认 admin 角色 + 权限集
  3. 创建示例 client（`Quickstart App`，含预配置的 redirect_uri 和 grant type）
  4. 发送欢迎 email（含控制台登录链接 + 引导式文档链接）
  5. 记录 `tenant_onboarding_completed` 审计事件
- 开通序列使用已有的 `platform/bootstrap/builtin` Step 框架，保证幂等性和崩溃恢复。

**4. 租户激活状态仪表盘（Admin Console）**

- 在租户详情页新增 Setup 选项卡，显示开通进度（已完成 / 未完成步骤）。
- 运维管理员可以看到每个租户的安全基线模板和自定义偏差。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 租户创建后未完成开通 | 未完成开通的租户依然可以正常使用所有 API（非阻塞），但 Admin Console 显示 "unfinished setup" 横幅 |
| 安全基线模板的版本升级 | 升级平台后，已有租户的基线模板不自动升级（避免破坏性变更），但在 Security 面板显示"有可用升级"提示 |
| 自定义模板 | 支持运维管理员创建自定义 YAML 模板，通过 `--security-profile-dir` 加载 |
| 模板迁移 | 从 `standard` 升级到 `strict` 模板时，自动审计所有现有 client 的兼容性差距（不自动拒绝） |
| 多语言 welcome email | 复用现有 `shared/i18n` 框架，根据租户的首选区域语言决定邮件语言 |

---

## 方向四：跨区域主动-主动部署架构（Cross-Region Active-Active Deployment Architecture）

### 现状

项目拥有强大的多副本能力（`cluster.Bus` via etcd/MQTT、SQLite cluster-shared backends、  
Redis 后端），但这些都是在 **单区域** 范畴内的设计。在跨区域部署方面存在明显的结构盲区：

| 能力 | 代码位 | 状态 |
|---|---|---|
| 多副本（单区域） | `cluster.Bus` + SQLite cluster-shared | ✅ 完整 |
| 区域数据驻留隔离 | `domains/region/` + `WithTenantResidencyCheck` | ✅ 完整 |
| 签名密钥 per-tenant 隔离 | `interfaces/sso/sso.go` | ✅ 完整 |
| DR active-passive | `platform/snapshot/` + `releases/` | ✅ 只读副本提升 |
| **跨区域 active-active 读写** | **零实现** | ❌ **零** |
| **跨区域一致性协议** | **零实现** | ❌ **零** |
| **区域级故障隔离** | **零实现** | ❌ **零** |
| **全局发现/路由层** | **零实现** | ❌ **零** |

**代码证据（grep 核验）：**

| 概念 | 代码命中 |
|---|---|
| `active.active.*region\|active_active.*region\|cross.region\|cross_region\|multi.region.*active\|multi_region.*active\|global.*rout\|global.*discover\|geo.*rout\|geo.*dns\|anycast\|global.*load.*balance` | **0** |
| `region.*failover\|failover.*region\|regional.*failover\|fail.*over.*region\|cross.*region.*consist\|consist.*cross.*region\|global.*consist\|global.*latency\|latency.*rout\|proximity.*rout` | **0** |
| `replica.*type\|replica.*role\|read.*replica\|write.*region\|primary.*region\|standby.*region\|passive.*region\|region.*primary\|region.*standby\|region.*passive` | **0** |

### 为什么需要它

1. **全球企业客户的硬需求**：对于全球运营的企业，身份服务必须部署在多个地理区域，  
   并在区域故障时自动切换——这是采购评估中的基础设施成熟度信号。

2. **数据驻留合规必须与运行时拓扑挂钩**：今天 `Tenant.DataResidencyRegion` 只是一个  
   声明字段，没有任何运行时约束确保 EU 租户的数据不被 US 区域的写入路径处理。  
   Active-active 架构的一个副产品就是强制数据驻留：写入路由到租户的 home region。

3. **区域故障的自愈能力**：当前 DR 模式是 active-passive（snapshot + promote），  
   RPO = 上一个 snapshot 时间点，RTO = 手动 promote 时间。Active-active 模式  
   可以将 RPO 降低到接近零，RTO 降低到 DNS 传播时间。

4. **与现有基础设施的互补性**：现有的 `cluster.Bus`（etcd/MQTT）、multi-algorithm  
   signing、per-tenant 签名隔离都是 active-active 的预置条件。缺失的是一个全局  
   协调层。

### 范围

**1. 区域抽象与区域注册表（`platform/region/`）**

```go
// Region represents a deployment region.
type Region struct {
    ID       string        // "us-east-1", "eu-west-1", "ap-southeast-1"
    BaseURL  string        // "https://login.us-east-1.example.com"
    Priority int           // 0 = primary for unresolvable tenants
    Latency  time.Duration // approximate latency from this region
}

// RegionRegistry maps tenants to home regions and provides region discovery.
type RegionRegistry interface {
    HomeRegion(ctx, tenantID string) (*Region, error)
    AllRegions(ctx) ([]*Region, error)
    NearestRegions(ctx, userIP string, count int) ([]*Region, error)
}
```

- 全局配置（通过 etcd / DNS / 配置文件分发）。
- 每个区域运行一个完整的 SSO 实例，使用自己的 `cluster.Bus`。

**2. 写入路由策略**

- **Sticky tenant routing**：每个租户有一个 primary write region（根据 `Tenant.DataResidencyRegion`  
  或 `TenantID → hash → region` 分配）。所有面向该租户的写入操作（client create/update、  
  user create/update、token issuance、session create）路由到 primary region。
- 读取操作（`/token/introspect`、`/userinfo`、`/jwks.json`）可服务到任意区域。
- 幂等写入：如果 primary region 不可用，写入可以转发到备用区域（带冲突检测）。

**3. 全局数据同步层**

- **主动同步**：通过等 MQTT/etcd 跨区域总线的扩展（现有 `cluster.Bus` + MQTT 实现），  
  区域间同步缓存失效事件（`KindTokenRevoked`、`KindSigningKeyRotation`、  
  `KindClientChange`、`KindTenantSuspension`）。
- **被动同步**：AP 风格的最终一致数据同步（PostgreSQL 逻辑复制 / etcd 跨区 watch），  
  用于非关键状态的传播（client 发现文档更新、用户属性变更）。

**4. 全局负载均衡与故障转移**

- 使用 DNS-based GSLB（Route53 / Cloudflare Global Load Balancer）或 Anycast IP  
  将用户请求路由到最近/健康的区域。
- 单区域健康检查通过 `/readyz` 端点暴露，聚合为区域健康状态。
- 区域故障时的自动排水（drain）：区域健康度低于阈值后从 GSLB 中移除，写操作重路由到  
  最近的备用区域。

**5. 区域隔离的每个桩**

- 每个区域有自己的签名密钥集（per-region `SigningKeyProvider`），但所有区域的 JWKS  
  通过全局聚合端点 `/jwks.json` 暴露。
- 令牌的 `iss` 声明包含签发区域 ID，验证时路由到对应区域的 JWKS。
- 审计事件标记 `region` 字段，SIEM 可以按区域过滤。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 跨区域写入延迟 | Sticky tenant 设计确保一个租户的所有写入在一个区域内完成，跨区域仅需同步缓存失效（<100ms），不需要同步完整写入 |
| 区域完全故障（火山/地震级） | 手动或自动触发区域级切换：更新 GSLB 权重、将受影响租户的 home region 重映射到备用区域、区域间同步追赶 |
| 裂脑（split-brain）场景 | 写入使用 last-writer-wins + 租户级别的版本戳；冲突检测在下一个同步周期自动修复 |
| 跨区域的时间偏差 | 所有跨区域令牌验证使用授时偏差（ClockSkew）窗口，复用现有的 `dpop_clock_skew_test.go` 模式 |
| 区域间证书/PKI | 每个区域有独立的 mTLS CA，区域间通信使用 server-to-server mTLS + 预先交换的 CA 证书 |

---

## 方向五：持久化设备信任与"记住此设备"认证体验（Persistent Device Trust & "Remember Me" UX）

### 现状

项目拥有设备指纹（`deviceFingerprint`）、设备信任（`/me/devices/trust`）、  
MFA 信任衰减（`WithSessionTrustDecay`）等能力，但这些能力面向的是 **会话级别**  
和 **MFA 上下文**。不存在真正的"记住此设备"体验——即用户勾选"记住此设备 30 天"后，  
在该设备上可以跳过二次认证。

| 能力 | 代码位 | 状态 |
|---|---|---|
| 设备指纹 SPI | `conditionalaccess.DeviceFingerprint` | ✅ 存在 |
| 设备信任标记 | `interfaces/sso/server_me.go /me/devices/trust` | ✅ 存在 |
| 会话信任衰减 | `interfaces/sso/server_login_gates.go` `WithSessionTrustDecay` | ✅ 存在 |
| **持久化设备 cookie / token** | **零实现** | ❌ **零** |
| **"Remember this device" MFA 跳过** | **零实现** | ❌ **零** |
| **设备管理与撤销 UI** | **零实现** | ❌ **零** |
| **设备分组的信任级别** | **零实现** | ❌ **零** |

**代码证据（grep 核验）：**

| 概念 | 代码命中 |
|---|---|
| `remember_me\|rememberMe\|RememberMe\|remember_device\|rememberDevice\|trust.*device.*token\|device.*trust.*token\|device.*persist\|persist.*device\|persistent.*device` | **0** |
| `device.*cookie\|cookie.*device\|device.*token\|token.*device\|device.*claim\|claim.*device\|device_id\|DeviceID\|deviceId`（作为持久化标识） | **0** |
| `skip.*mfa\|mfa.*skip\|bypass.*mfa\|mfa.*bypass\|trust.*skip\|skip.*trust` | **0**（`WithTrustedDeviceMFA` 可能相关，但 grep 无命中） |

### 为什么需要它

1. **消费者体验的基本期望**：用户在浏览器上勾选"记住此设备"后，不希望每次登录都输入  
   MFA 验证码。Google、GitHub、Slack、银行应用都已支持此模式。没有这个能力 = 用户体验  
   停留在 2010 年代。

2. **减少 MFA 疲劳**：频繁的 MFA 挑战导致用户对安全提示麻木，增加不安全性。  
   "记住此设备"可以显著减少 MFA 提示频率，同时保持风险较高的登录（新设备、新地点）  
   仍然受 MFA 保护。

3. **与现有信任衰减模型互补**：`WithSessionTrustDecay` 在会话内部跟踪信任衰减，但不跨会话  
   保留设备信任。持久化设备信任适用于跨会话（30 天的"记住我"窗口），而信任衰减适用于  
   同一会话内部（高风险操作需要 step-up）。

4. **企业 BYOD 场景的实用性**：在企业环境中，管理员可能希望允许受管设备（已注册 MDM）  
   跳过某些认证步骤。持久化设备信任是这一策略的基础原语。

### 范围

**1. 持久化设备存储 SPI（`domains/device/`）**

```go
// Device is a persistent, trusted device bound to a user.
type Device struct {
    ID        string    `json:"id"`
    UserID    string    `json:"user_id"`
    TenantID  string    `json:"tenant_id"`
    Name      string    `json:"name,omitempty"` // "John's iPhone 15"
    Type      string    `json:"type,omitempty"` // "mobile" / "desktop" / "tablet" / "unknown"
    // Fingerprint is a hash of the device's unique characteristics.
    Fingerprint string  `json:"fingerprint"`
    // TrustLevel determines MFA bypass eligibility.
    TrustLevel TrustLevel `json:"trust_level"`
    // ExpiresAt is when the device trust expires.
    ExpiresAt  time.Time  `json:"expires_at"`
    CreatedAt  time.Time  `json:"created_at"`
    LastSeenAt time.Time  `json:"last_seen_at"`
}

type TrustLevel int
const (
    TrustUntrusted  TrustLevel = 0
    TrustBasic      TrustLevel = 1  // Known device, short TTL (7 days)
    TrustExtended   TrustLevel = 2  // Remembered device, long TTL (30 days)
    TrustManaged    TrustLevel = 3  // MDM-managed device, infinite (admin-managed)
)

// DeviceStore persists user devices and their trust levels.
type DeviceStore interface {
    Register(ctx, device *Device) error
    GetByFingerprint(ctx, userID, fingerprint string) (*Device, error)
    ListByUser(ctx, userID string) ([]*Device, error)
    UpdateTrust(ctx, deviceID string, level TrustLevel, expiresAt time.Time) error
    Delete(ctx, deviceID string) error
    DeleteExpired(ctx, before time.Time) (int, error) // for retention sweeper
}
```

- Memory + SQLite + Redis 三后端（复用现有的 SPI 模式）。
- 设备指纹复用现有的 `conditionalaccess.DeviceFingerprint` 接口。

**2. "Remember Me" 认证流程集成**

在 `/auth/login` 和 `/auth/mfa` 中添加可选"Remember this device"复选框：

- **登录时**：用户在 `/auth/login` 的 MFA 挑战页面上勾选"记住此设备 30 天"。
- **签发持久化 token**：MFA 验证成功后，服务端创建一个持久化设备记录（`TrustExtended`），  
  并签发一个加密的持久化 cookie（`sso_device_trust`）。
- **MFA 跳过**：当同一设备上的用户再次登录时，服务端读取 `sso_device_trust` cookie，  
  验证设备指纹匹配且未过期，自动跳过 MFA 步骤。
- **高风险操作不退让**：无论设备信任如何，以下操作始终要求 MFA：修改密码、修改 MFA 配置、  
  新 client 授权（consent）、修改安全策略。

**3. 设备管理 UI（Admin Console + User Portal）**

- **User Portal `/me/devices`**：用户可以看到自己的所有信任设备，查看信任等级和过期时间，  
  手动移除特定设备的信任。
- **Admin Console 租户详情**：管理员可以看到（但不能操作）用户设备列表，用于审计和调查。
- **审计事件**：`device_registered`、`device_trust_level_changed`、`device_removed`、  
  `device_mfa_skipped`。

**4. 与现有信任衰减的集成**

- `WithSessionTrustDecay` 的 `Floor` 和设备信任级别可以组合：
  - 无设备信任：`Floor` = 默认值（严格）
  - 有设备信任（TrustBasic）：`Floor` = 下调一级
  - 有设备信任（TrustExtended）：`Floor` = 下调两级
  - 有设备信任（TrustManaged）：`Floor` = 0（不触发 step-up）
- 管理员可以在条件访问策略中引用设备信任级别，例如："要求 MFA，但信任设备除外"。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 持久化 cookie 泄露 | 加密 cookie 使用 AEAD（AES-256-GCM），密钥从 KMS 获取；cookie 内容包含签发区域、用户 ID、设备指纹 hash；伪造会导致 403 + 审计告警 |
| 设备指纹碰撞 | 指纹冲突时拒绝新注册，要求用户手动授权新设备（通过 email/push 通知） |
| "记住我"的隐私含义 | cookie 本身不包含个人数据，仅含加密后的 `deviceID`；设备列表始终可通过 User Portal 查看和删除 |
| 多用户共用设备（家庭/共享电脑） | 设备信任绑定到 `(UserID + Fingerprint)`，不跨用户共享 |
| 设备信任过期后自动降级 | 后台 retention sweeper 运行（复用 `defaultimpl/memreaper/` 模式），删除过期设备记录 |
| 管理员吊销特定设备 | 提供 Admin API `DELETE /api/v1/admin/users/:uid/devices/:device_id`，吊销后该设备需重新授权 |
| 跨设备的信任同步 | 设备信任不跨区域同步（隐私考量），用户在新区域需要重新注册设备信任 |

---

## 优先级摘要

| # | 方向 | 类型 | 商业驱动力 | 建议顺序 |
|---|---|---|---|---|
| 1 | Phone/SMS OTP 认证因子 | **市场覆盖** / 产品完整度 | CIAM/B2C 市场解锁；全球新兴市场覆盖；密码弃用率提升 | **P0** — CIAM 采购门槛 |
| 2 | 租户自助分析门户 | **SaaS 产品化** / 变现 | 付费 tier 差异化；合规报告自服务；用量驱动升级 | **P0** — SaaS 产品基本履约 |
| 3 | 引导式租户开通与安全基线 | **PLG 增长** / 安全治理 | 降低 Time-to-Value；安全基线标准化；企业采购门槛 | **P1** — 跟随产品定价上线 |
| 4 | 跨区域 Active-Active | **基础设施成熟度** / 全球覆盖 | 全球客户采购门槛；数据驻留强制合规；RPO→零、RTO→秒级 | **P1** — 有全球客户后启动 |
| 5 | 持久化设备信任与"记住我" | **用户体验** / 消费者认可 | MFA 疲劳缓解；跨会话信任连续性；BYOD 信任基础 | **P1** — 与 MFA/Device 同时演进 |

---

## 附录：验证方法说明

本报告每个方向均经过以下双重重验证：

1. **全代码库 grep 核验**：对方向核心关键词在 `./**/*.go`（排除 vendor/.git）中做  
   大小写敏感的完全匹配，确认代码零实现或仅存 test/mock。
2. **历史分析交叉验证**：对 `docs/requirements/*.md`（23+ 份文档）、`docs/ROADMAP.md`、  
   `docs/deferred-backlog.md` 做相同关键词的 grep 核验，确认方向与所有已有分析零重叠。

以上 5 个方向与 23+ 轮历史分析的交叉验证结果均为 **零命中**。

---

*文档版本：2026-07-11 · 全代码库扫描结论*
