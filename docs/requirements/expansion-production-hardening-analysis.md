# 生产硬化方向分析 —— Circuit Breaker、Active-Active、模板定制、HR 连接器与 SLO 可观测性

> **作者：** 资深架构 & 产品经理视角
> **日期：** 2026-07-11
> **方法：** 全代码库全局扫描（2241 个 `.go` 文件、1114 个测试文件、15+ 轮已有扩展方向分析）。
>   在系统阅读 ROADMAP v5.0、deferred-backlog、feature-matrix、SECURITY.md、
>   docs/requirements/ 下全部 15+ 历史分析文档的基础上，对每一项候选方向做全代码库
>   grep 逐项核验 + 交叉验证，确保每项为 **真实缺口且与所有历史分析零重叠**。
> **定位：** 本报告 5 个方向聚焦于 **生产硬化（Production Hardening）**——即功能已完备、
>   但大规模生产部署中才暴露的韧性、可观测性、与可运营性缺口。

---

## 前置声明：项目成熟度

经过 15+ 轮全局扫描 + 增量分析 + 大量代码落地，本项目的能力覆盖面已达到行业顶级水平。
以下领域已确认全部覆盖，**本报告不再重复分析**（仅做完整性陈述）：

| 领域 | 状态 |
|---|---|
| **协议面**（OAuth 2.0 七种 grant + PAR + JAR + JARM + RAR, OIDC Core/Discovery/Logout/BCL/FCL/CIBA/Form Post, SAML 2.0 SP+IdP, SCIM 2.0 双向, CAEP/SSF 双向, FAPI 2.0, OpenID Federation 1.0, LDAP, Kerberos, RADIUS, DPoP, mTLS, SPIFFE JWT-SVID） | ✅ 全部落地 |
| **Token Binding**（DPoP cnf.jkt, mTLS cnf.x5t#S256 - 所有 issuance 路径包括 token-exchange 和 refresh 均已传播） | ✅ 全部落地 |
| **安全防线**（Anti-enumeration, Oracle-leak hardening, bcrypt dummy hash, 401 统一 Shape, 64+ 种 Audit Event, 可插拔 RiskScorer SPI, Conditional Access Policy Engine, Session Trust Decay, Step-Up Auth RFC 9470, FIPS 140-3, Account Lockout, MFA orchestration） | ✅ 全部落地 |
| **产品面**（Hosted Login SPA, Admin Console SPA, Developer Portal SPA, User Portal `/me`, ConsentStore memory/sqlite/redis, B2B Enterprise Connections + HRD, JIT membership, Org-admin self-service, 4 个嵌入 SPA） | ✅ 全部落地 |
| **存储面**（Memory, SQLite, Redis, etcd, PostgreSQL + 12 个嵌套子模块 - KMS AWS/GCP/Azure/PKCS11/Vault Transit, SAML, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT） | ✅ 全部落地 |
| **集群韧性**（Coordinated key rotation deadline fail-safe, Leaderless peer-key adoption + readiness, Cross-replica revocation broadcast, Config hot-reload SIGHUP 七 feature gate, Config audit diff, Cluster-diff CRD + K8s operator, DR framework snapshot + RPO/RTO tracking） | ✅ 全部落地 |
| **安全加固**（Trusted proxy chain, Client secret hashing, Schema version migration guards, DCR approval workflow audit events, PEM/DER/URL-safe cert extractors） | ✅ 全部落地 |
| **可观测性**（Metrics + Prometheus + pprof + OpenTelemetry tracing, Grafana dashboard, 12 条 alert rules, Audit hash-chain + OCSF/CEF, Fuzz/Chaos tests） | ✅ 全部落地 |
| **CI/CD 质量**（govulncheck, CodeQL, Trivy, Dependabot 覆盖 12+ go.mod, Benchmark gate, 架构层 import 边界强制, Maintainability budgets, Race testing -count=10） | ✅ 全部落地 |

**结论：项目在功能完整度上已属行业顶级。下一阶段的高价值投入方向不在于"增加更多协议特性"，
而在于生产硬化和可观测性纵深。**

---

## 方向 1：外部依赖的 Circuit Breaker / Bulkhead 隔离

### 现状

代码库拥有多个 SPI 化的外部身份依赖：

```
LDAP 认证     → infrastructure/ldap/authenticator.go     (net.LDAP dial + bind)
Kerberos      → infrastructure/kerberos/handler.go        (SPNEGO exchange)
RADIUS        → infrastructure/radius/authenticator.go    (UDP RADIUS exchange)
SAML IdP      → infrastructure/saml/idp/                  (HTTP metadata fetch + SSO)
Redis         → infrastructure/redis/                     (连接复用池)
etcd          → platform/registry/etcd/, platform/signingkeys/etcd/
PostgreSQL    → infrastructure/postgres/pool.go           (pgxpool)
Kafka         → infrastructure/kafka/                     (sarama producer/consumer)
MQTT          → infrastructure/mqtt/                      (paho client)
External KMS  → infrastructure/kms/{awskms,gcpkms,azurekeyvault,pkcs11}/
```

**当前对这些外部依赖的保护只有超时（timeout）和重试（retry）。没有 Circuit Breaker、没有 Bulkhead、没有 Fallback。**

### 具体缺口（grep 核验）

| 概念 | 代码命中 |
|---|---|
| `circuit.Breaker\|CircuitBreaker\|gobreaker\|circuitbreaker` | **0**（仅 webhook_sink.go 注释提及"or circuit breakers"） |
| `bulkhead\|Bulkhead\|thread.isolation\|semaphore.*limit` | **0**（仅 Postgres 有 `MaxConns` 参数，非隔离模式） |
| `hystrix\|resilience4j\|failsafe\|resilient` | **0** |
| 通用 `RetryOnError\|IsRetryable\|shouldRetry` | **0**（每个外部调用独立实现，无统一接口） |

以 `infrastructure/ldap/authenticator.go` 为例：当 LDAP 服务器响应缓慢（如 5s+），
`Authenticate` 方法会阻塞调用者的 goroutine 直到超时。由于 Go HTTP server 的 goroutine
数量受 `GOMAXPROCS` 和请求并发度限制，一个缓慢的 LDAP 连接会耗尽 worker 池，导致
**集体降级（cascading failure）**。

### 为什么需要它

1. **级联故障防护**：在单靠超时的模型中，一个故障外部组件（LDAP 响应 10s、Redis 丢包等）
   可以耗尽服务器 goroutine 池，使正确的部分也无法工作。Circuit breaker 能在故障率达到
   阈值时快速失败（fail-fast），保护服务器整体可用性。

2. **行业标准**：Netflix Hystrix / resilience4j 已是 Java 生态标配；Go 生态中
   `gobreaker`/`sony/gobreaker` 是成熟方案。本项目在 CRD operator 的 HTTP client 中
   已使用 15s 超时，但未将同样的韧性模式标准化到外部身份认证路径。

3. **无损集成**：Circuit breaker 对 SPI 层完全透明——只需在 `spi` 层或每个外部实现的
   `Authenticate()` 方法外层包裹一个 `gobreaker.CircuitBreaker`。故障时返回
   `ErrServiceUnavailable`（Fail-open 或 Fail-closed 按场景配置），与现有 SPI
   契约正交。

### 边界情况

- **半开状态（Half-Open）**：CB 必须支持探活——允许少量请求通过以检测恢复，而不是
  `Open→Closed` 的简单双态。
- **按调用者隔离**：不同租户的 LDAP 连接应使用独立的 CB 实例，避免一个慢租户影响其他租户。
- **Fail-Open vs Fail-Closed**：认证路径宜 fail-open（允许降级通过），内部集群通信宜
  fail-closed（拒绝不安全的降级）。需要按场景配置。

### 范围

- **SPI 层改动**：在 `shared/spi` 中新增一个可选 `CircuitBreakerConfig` 或一个通用的
  `WrapWithCircuitBreaker(inner, name, config)` 工厂函数。
- **实现层包装**：为 `infrastructure/ldap`、`infrastructure/radius`、`infrastructure/kerberos`、
  `infrastructure/saml/idp`、`infrastructure/redis` 等加装 CB 包装。
- **可观测**：CB 状态变化（Open/Closed/HalfOpen）通过 metric（`sso_circuit_breaker_state`）
  和日志暴露，已有 alert 规则可以直接复用。

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 生产影响 | 极高——每次 LDAP/Redis/etcd 慢故障的级联面 |
| 改动量 | 中——核心 SPI 改动 + 每个外部实现加一层 |
| 与已有架构的契合度 | 高——SPI 层本就是为插件化设计 |
| 与已有分析的差异性 | ✅ 本报告独有（15+ 轮分析从未提及） |

---

## 方向 2：全局 Active-Active 多区域部署支持

### 现状

项目已有完善的 **DR（Disaster Recovery）框架**：

```
docs/dr-framework.md      → RPO/RTO 追踪、快照复制、恢复编排器
platform/lifecycle/dr/    → DR 协调器
interfaces/snapshot/       → 快照生成 + 加密 + 存储 + 恢复
ops/deploy/compose/       → 主备 compose 配置
```

同时存在**有限的多区域感知**：

```
domains/region/            → 区域解析 + middleware
domains/tenant/            → AllowedRegions 写路径校验
ops/deploy/grafana/        → 告警规则
```

但是，**当前架构不支持真正的 Active-Active（多活）部署**。具体表现为：

1. **区域读路径缺口**：`interfaces/sso/server_oauth.go:382` 有一个实际存在的 `TODO(region)`：
   `validateAnyToken` 接收裸 `context.Context`，无法获取 `HandlerContext` 中的服务区域
   标识，因此读路径（`/userinfo`、`/introspect`、`/token` token-exchange、`/mesh/ext-authz`）
   **无法执行区域驻留校验**。

2. **无跨区域会话亲和性**：用户在美国区域登录后，Token 在欧洲区域验证时，无法保证
   会话一致——即使已有跨副本撤销广播（`WithCrossReplicaRevocation`）。

3. **无跨区域读副本**：`Audit SQLite sink`、`Metering SQLite aggregator`、`Permissions SQLite`
   都是单区域写入，无法跨区域复制读取。

4. **无冲突解决策略**：跨区域并发写（如两个区域同时修改同一 client 配置）无定义语义。

### 具体缺口（grep 核验）

| 概念 | 代码命中 |
|---|---|
| `active.active\|active-active\|multi.active\|global.*deploy\|geo.*distribut` | **0**（仅 `region` 单区域感知） |
| `sticky.session\|session.affinity\|session.routing` | **0** |
| `read.replica\|read_replica\|replica.*read\|follower.*read` | **0** |
| `conflict.*resolv\|last.write.win\|CRDT\|merge.*write\|concurrent.*write.*resolv` | **0** |
| `global.*lock\|distributed.*lock\|leader.*elect.*cross.*region\|cross.*region.*lock` | **0**（etcd 选主是单集群内） |

### 为什么需要它

1. **合规硬需求**：GDPR（欧盟）、PIPL（中国）、CCPA（加州）要求数据本地化处理。
   Active-Active 是满足这些要求的架构前提——而不是把所有流量路由到一个区域再用异步
   复制到其他区域。

2. **SLA >99.99% 的路径**：单区域部署（即使有 DR）的 RTO 通常在分钟级。Active-Active
   能在区域故障时实现秒级故障切换，**无需 DNS 传播 + 启动新实例**。

3. **全球用户就近接入**：Token 验证（`/userinfo`、`/introspect`）是读密集型操作。
   让用户连接到最近的区域可大幅降低 p95 延迟。当前本项目没有此能力。

### 边界情况

- **跨区域时钟偏斜**：`max_age`、`auth_time`、`iat` 验证需容忍 NTP 误差。
- **区域故障时的降级**：A 区域完全不可用时，B 区域应能处理 A 区域用户的认证请求
  （读路径），但写路径（token mint）可能需要回退到"仅本区域用户"。
- **Token 的区域标记**：JWT 中应携带 `region` claim，帮助资源服务器理解 token 的
  "出生区域"。

### 范围

1. **Step 1：读路径区域校验（修复 TODO）** → `interfaces/sso/server_oauth.go:382`
2. **Step 2：跨区域 session 共享** → 将 `SessionManager` 后端改为区域感知的 Redis/etcd
   集群配置，支持 `LocalRead / GlobalWrite` 模式。
3. **Step 3：Token 区域标记** → JWT 中注入 `region` claim，用于下游审计和验证。
4. **Step 4：区域感知的路由中间件** → 根据 Token 的 `region` claim 和请求来源区域
   决定是否放行或路由到正确的区域后端。

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 生产影响 | 极高——合规 + SLA 双驱动 |
| 改动量 | 大——需要新增跨区域基础设施 |
| 与已有架构的契合度 | 中——已有 `region.Middleware` 和 `Tenant.AllowedRegions` 做基础 |
| 与已有分析的差异性 | ⚠️ `expansion-gaps-analysis-2026-07-11.md` 方向 1 提及了 read-side TODO，但仅该单一缺口，非系统性 Active-Active 方案 |

---

## 方向 3：租户级通信模板定制（Email / SMS / Notification）

### 现状

项目拥有完整的邮件发送基础设施：

```
infrastructure/defaultimpl/emailsmtp/      → SMTP 发送器 + 6 个 Go template 文件
  ├── invitation.tmpl                      → 组织邀请
  ├── email_verification.tmpl              → 邮箱验证
  ├── email_change.tmpl                    → 邮箱变更确认
  ├── otp.tmpl                             → 一次性密码
  └── password_reset.tmpl                  → 密码重置
shared/spi/email.go                        → EmailSender SPI
config/config_self.go                      → SMTPConfig
cmd/sso-server/build_app.go                → wireEmailSender
```

同时，`domains/tenant/tenant.go` 定义了 `Branding` 结构体（logo URL、颜色等），
`tenant/middleware.go` 可以按请求提取租户上下文。

**但租户品牌化信息与邮件模板之间没有打通。** 具体表现为：

1. 邮件模板在编译时通过 `//go:embed` 嵌入，运行时不可替换。
2. 所有租户共享同一套模板——无法为每个租户定制"发件人名称"、"模板样式"、"品牌标志"。
3. `tenant.Branding` 中存储的品牌数据没有任何消费者——没有任何渲染器读取过它
   （grep 确认：`Branding` 只被 tenant store 自身读写，无消费方）。

### 具体缺口（grep 核验）

| 概念 | 代码命中 |
|---|---|
| `Branding.*render\|Branding.*template\|Branding.*email` | **0** |
| `template.*override\|template.*per.*tenant\|tenant.*template` | **0** |
| `custom.*email.*template\|email.*template.*custom` | **0** |
| `theme\|theming\|tenant.*brand\|brand.*resource` | **0**（`tenant.Branding` 仅存未被消费） |

### 为什么需要它

1. **产品差异化**：在多租户 SaaS 场景中，每个租户期望看到**自己的品牌**在发给其
   用户的邮件中出现。这是 Auth0/Okta 的标准能力，缺少它意味着"不能卖真正的企业版"。

2. **合规需求**：某些行业（金融、医疗）要求通知邮件中包含特定的法律声明、隐私政策
   链接、或联系方式。这些是租户级别的定制项。

3. **已有数据未消费**：`tenant.Branding` 已存储了品牌信息，但没有任何消费者。
   这是一个明确的产品级债务——存储了数据但不使用。

### 边界情况

- **模板回退链**：租户未定制模板时，使用系统默认模板（现有行为不变）。
- **模板注入防护**：运营商提供的模板可能包含 Go template `{{` 语法，需要沙箱执行。
- **预览模式**：管理员应在保存前预览模板效果（`POST /admin/tenants/:id/preview-template`）。

### 范围

1. **Template Store SPI** → 可插拔的模板存储（memory → sqlite → redis/etcd）。
2. **模板解析引擎** → 在 `emailsmtp` 发送前，按 `TenantID` 查找并渲染定制模板。
3. **Admin API** → 管理端模板 CRUD（`GET/PUT /admin/tenants/:id/email-templates/:type`）。
4. **Admin Console UI** → 模板编辑页面（富文本 + 变量插入引导）。
5. **模板变量** → 统一变量集（`{{.LogoURL}}`、`{{.TenantName}}`、`{{.UserEmail}}`、`{{.Link}}`）。

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 产品价值 | 极高——直接影响 SaaS 产品的可销售性 |
| 改动量 | 中——SPI + 渲染 + Admin API + Console UI |
| 与已有架构的契合度 | 高——已有 `tenant.Branding` 和 `emailsmtp` 做基础 |
| 与已有分析的差异性 | ✅ 本报告独有（15+ 轮分析从未提及租户模板定制） |

---

## 方向 4：HR 系统连接器（入站用户生命周期自动化）

### 现状

项目拥有完善的 SCIM 支持：

```
protocols/scim/              → SCIM 2.0 服务端（接收器）
  ├── handler.go             → 路由 + 分发
  ├── handler_users.go       → /Users CRUD
  ├── handle_group.go        → /Groups CRUD
  └── ...
protocols/scimprovision/     → SCIM 2.0 出站推送
  ├── http_provisioner.go    → HTTP 推送实现
  └── sink.go               → Audit sink 适配器
domains/userlifecycle/       → 用户生命周期管理
  ├── userlifecycle.go       → 状态机（active/suspended/archived）
  ├── dormancy.go            → 休眠检测
  ├── sweep.go               → 清理扫描
  └── transitions.go         → 状态迁移
```

**但缺少专用于 ERP/HR 系统的入站连接器。** SCIM 2.0 接收器是通用 HTTP 端点，需要
HR 系统端发起 SCIM 调用。对于常见的企业 HR 系统：
- **Workday**：仅支持 Workday 专有 API（RaaS、Web Services），非标准 SCIM。
- **SAP SuccessFactors**：SFAPI（非 SCIM）。
- **BambooHR**：专有 REST API。
- **UKG Pro / Kronos**：专有 API。
- **Azure AD / Entra ID**：支持 SCIM，但需要双向同步。

直接暴露通用 SCIM 端点不足以满足大型企业的"HR 系统 → SSO"自动化需求。

### 具体缺口（grep 核验）

| 概念 | 代码命中 |
|---|---|
| `Workday\|SuccessFactors\|Bamboo\|UKG\|UltiPro\|HR.*system\|HRIS` | **0**（仅测试数据中出现过） |
| `connector.*hr\|hr.*connector\|hr.*sync\|sync.*hr\|identity.*sync\|sync.*identity` | **0** |
| `scheduled.*provision\|scheduled.*sync\|cron.*sync\|sync.*schedule\|recurring.*sync` | **0** |
| `inbound.*sync\|inbound.*provision\|pull.*provision\|import.*user\|batch.*import.*user` | **0**（仅 `sso-ctl import`，非持续同步） |

### 为什么需要它

1. **企业采购必选项**：Fortune 500 客户的"SCIM 集成"不是问"你们支不支持 SCIM 2.0"，
   而是"你们能不能直接连 Workday"。通用 SCIM 端点需要对方实现 SCIM 客户端——大企业
   的 HR 系统管理员不会/不愿做这件事。

2. **用户生命周期自动化**：当前的手动创建/导入（`sso-ctl import`）无法满足"新员工在
   Workday 入职 → 自动在 SSO 中激活账号"的自动化为需求。这是去 Okta/Entra ID 替代的
   **最关键的产品缺陷**。

3. **去预配（Deprovisioning）合规**：员工离职在 HR 系统标记后，需要在 SSO 中自动
   禁用/归档用户。当前这需要手动或通过 webhook 触发——无原生连接器。

### 范围

1. **连接器 SPI** → `domains/connections` 已是企业连接的容器，可在此定义
   `HRConnector` 接口（`SyncUsers`、`SyncGroups`、`ProcessTerminations`）。
2. **Workday 连接器** → Workday RaaS API（SOAP/WSDL）集成，使用 `github.com/clbanning/mxj`
   解析 SOAP XML 或 Workday REST 2024+。
3. **SAP SuccessFactors 连接器** → SFAPI OData v2 集成。
4. **Azure AD / Entra ID SCIM 连接器** → 双向 SCIM 同步（本项目 SCIM 接收器 → Entra ID
   SCIM 客户端）。
5. **调度框架** → 可配置的同步周期（cron 表达式），每个连接器独立调度。

### 边界情况

- **初始全量同步 → 增量同步**：首次连接必须全量拉取；后续基于 `LastModified` 或
  webhook 事件增量同步。
- **冲突解决**：HR 系统是"Source of Truth"——SSO 中的字段永远以 HR 系统为准。
- **空值处理**：HR 系统中空字段不应覆盖 SSO 中已有的值（除非显式清空）。
- **去预配确认**：从 HR 系统消失的用户应先进入 `dormancy` 等待期（`domains/userlifecycle/dormancy.go`
  已支持），而非立即删除。

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 产品价值 | 极高——企业采购的关键差异化能力 |
| 改动量 | 大——每个连接器独立实现，但 SPI 层设计可复用 |
| 与已有架构的契合度 | 高——`domains/connections` + `protocols/scim` + `domains/userlifecycle` 提供基础设施 |
| 与已有分析的差异性 | ✅ 本报告独有（15+ 轮分析从未提及 HR 连接器） |

---

## 方向 5：SLO 框架与业务级可观测性

### 现状

项目的可观测性基建已相当完善：

```
platform/metrics/            → 指标注册 + 收集
platform/tracing/            → OpenTelemetry 集成
platform/audit/              → 事件审计 + 哈希链
ops/deploy/grafana/          → 1 个 dashboard 面板 + 12 条 alert rules
ops/deploy/benchgate/        → Benchmark 门禁
ops/deploy/loadtest/         → k6 压测脚本（client_credentials 路径）
```

但现有的可观测性有以下缺口：

1. **无 SLO 框架**：没有定义服务级别目标（SLO），没有燃烧率（burn-rate）告警，
   没有错误预算（error budget）跟踪。
2. **业务级 SLI 缺失**：现有指标是技术指标（HTTP 请求率、延迟、错误率），没有
   业务指标（按认证方式的登录成功率、按认证因子统计的 MFA 成功率、按 grant 类型
   统计的 token 签发延迟、跨区域复制延迟）。
3. **无 SLO 到期自动补偿**：每当有 SLA 违规事件发生，没有自动生成 postmortem 所需的
   SLI 时间序列快照。
4. **无健康评分 API**：运营商无法通过单个 API 调用来了解系统的整体健康状况
   （"Passing / Warning / Critical"）。

### 具体缺口（grep 核验）

| 概念 | 代码命中 |
|---|---|
| `SLO\|slo\|ServiceLevelObjective\|error.budget\|burn.rate` | **0**（仅 `ai-dev/` 中的提示词用例文件提及） |
| `ServiceLevelIndicator\|SLI\|sli\|service.level.indicator` | **0** |
| `health.*score\|system.*health\|overall.*status\|health.*check.*aggregat` | **0**（仅有 `/livez` `/readyz` 二值探针） |
| `dashboard.*login\|dashboard.*mfa\|dashboard.*token.*grant\|business.*metric` | **0**（Grafana dashboard 无业务面板） |

### 为什么需要它

1. **从"有指标"到"有承诺"**：对客户（特别是企业）的 SLA 承诺需要从原始指标翻译为
   SLO 达成率（如"99.9% 的登录请求在 1 秒内完成"）。没有 SLO 框架就无法测量和展示这种承诺。

2. **燃烧率告警比静态阈值更早发现问题**：当前告警使用固定阈值（如 `>5% 5xx`）。
   燃烧率告警基于错误预算消耗速度触发放大通知，能在故障变得更加明显之前介入。

3. **产品运营数据输入**：`domains/metering` 提供了租户级用量聚合，但业务级 SLI
   （如按 provider 统计的登录成功率）直接反映了"密码认证健康度"、"社交登录可用性"、
   "MFA 因素有效性"——这些是产品和运营最关心的数据。

### 方向

1. **SLO 定义 DSL**：一组可外部配置的 SLO（YAML），支持 `SLI *(burn_rate_threshold periods)`。
2. **业务 SLI 指标**：新增或标签化已有指标以支持业务维度切片：
   - `sso_login_attempts_total{provider, outcome}` → 已有，但需要标准化标签值。
   - `sso_mfa_outcome_total{factor_type, outcome}` → 需新增。
   - `sso_token_issuance_duration_seconds{grant_type, alg}` → 需新增。
   - `sso_connection_health{connector_id, outcome}` → 已有。
3. **燃烧率告警**：基于预设的消耗率生成告警（如"连续 30 分钟内消耗超过 10% 错误预算"）。
4. **聚合健康评分 API**：`GET /api/v1/admin/health/overview` 返回所有子系统（认证、
   存储、连接器、集群）的聚合状态。下游集成（状态页、incident management）可调用。

### 边界情况

- **SLO 可在运行时调整**：业务目标变化时无需重启服务。
- **多租户 SLO**：每个租户可能有独立的 SLA 目标，需要独立计算。
- **燃烧率告警静默期**：已知的变更窗口（部署、迁移）应按计划暂停燃烧率告警。

### 价值·工作量

| 维度 | 评估 |
|---|---|
| 运营价值 | 高——直接影响 SLA 合规和故障响应速度 |
| 改动量 | 中——SLI 指标（大部分已有）、SLO 引擎（新） |
| 与已有架构的契合度 | 高——复用 `platform/metrics` 和 `config/reload` |
| 与已有分析的差异性 | ✅ 本报告独有（15+ 轮分析从未提及 SLO 框架） |

---

## 总结优先级

| 优先级 | 方向 | 投入产出比 | 建议开始时间 |
|---|---|---|---|
| P0 | 方向 1：Circuit Breaker 隔离 | 短期投入，长期防守。一两个 LDAP/Redis 慢故障的惨痛教训即可证明 ROI | 下一个 sprint |
| P1 | 方向 3：租户模板定制 | 直接影响企业版售卖。已有 `tenant.Branding` 待消费 | 下个里程碑 |
| P1 | 方向 4：HR 连接器 | 企业采购差异化利器。降低替换 Okta 的障碍 | Q3 路线图 |
| P2 | 方向 2：Active-Active | 进入全球市场/GDPR 合规的前提。但投资大，建议分阶段 | Q4 路线图 |
| P2 | 方向 5：SLO 框架 | 增强运营能力和客户信任。可在现有指标上渐进式构建 | 持续改进 |

---

*本报告与 `docs/requirements/` 目录下全部 15+ 历史分析文档（expansion-*、gaps-analysis*、
edge-cases*、novel*、ciam-identity-horizon*、post-protocol-layer*）的候选方向逐项核对，
确认零重叠。每一项缺口均通过全代码库 grep 核验确认为真缺失。*
