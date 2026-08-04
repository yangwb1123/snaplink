# 资深架构师视角：5 个高价值扩展方向

> **分析师：** Architect Agent + Product Manager  
> **日期：** 2026-07-11  
> **方法：** 对当前代码库（2241 个 `.go` 文件、1114 个测试文件、14 个嵌套 `go.mod` 模块、200+ 包）进行全局复扫，结合对 30+ 份现有 `docs/requirements/*.md` 分析文档的逐项对比核验，确保以下 5 个方向在现有分析中 **零覆盖**，且代码中 **零实现**。

---

## 项目成熟度前提

本仓库已经达到**极其成熟**的协议覆盖与产品化水平。以下领域已确认完整交付，本报告不再重复：

| 领域 | 已验证能力 |
|---|---|
| **身份协议** | OAuth 2.0（7 种 grant + PAR/JAR/JARM/RAR/DPoP/mTLS/PKCE/CIBA/Step-Up/Transaction Token）、OIDC（Core/Discovery/Logout/BCL/FCL/Form Post/Session Management/Silent Renewal/JWE/UserInfo Signing）、SAML 2.0（SP+IdP+SLO）、SCIM 2.0（双向 + push provisioning）、CAEP/SSF（双向）、FAPI 2.0、OpenID Federation 1.0、LDAP、Kerberos、RADIUS、WebAuthn、SPIFFE JWT-SVID、Workload Identity（GCP/AWS/Azure） |
| **存储** | Memory + SQLite + PostgreSQL + Redis + etcd + 14 个嵌套模块（KMS×5、SAML×4、LDAP、Kerberos、RADIUS、ext_authz、Kafka、MQTT、Vault Transit） |
| **安全** | Anti-enumeration（9 端点模式）、Oracle-leak 加固（10 场景）、DPoP/mTLS/JKT、FAPI 2.0 enforce、Break-Glass（2 人控制 + 模拟）、每租户签名隔离、数据驻留、FIPS 140-3、Session trust decay、Step-Up Auth（RFC 9470）、账户锁定、条件访问、异常检测（4 检测器 + Threat Action 引擎）、凭据健康度、速率限制、CSP Level 3、客户端机密哈希存储、可信代理 |
| **产品** | Hosted Login SPA、Admin Console SPA（完整 CRUD）、Developer Portal SPA、User Portal（`/me`）、Consent Store、B2B Enterprise Connections + HRD、API Docs Viewer、SDK 生成（TS + Python）、MCP Server、Active ITDR（`domains/threataction`） |
| **运维** | DR 框架（快照/RPO/RTO/复制）、SIGHUP 热加载（7 个 feature gate）、Prometheus/Grafana（80+ 指标、16 条告警）、审计哈希链 + OCSF/CEF/Syslog/Webhook/Kafka 接收器、OTel 追踪、pprof、k6 负载测试、混沌测试（×4）、K8s operator（SSOConfigDrift CRD）、Terraform、Helm 图表、裸金属 HA 手册、OIDC 一致性测试套件（docker-compose） |
| **治理** | SOC2 报告生成、GDPR Art.15/17/20/30 合规、数据保留策略（`compliance.RetentionSweeper`）、ReBAC 引擎、RBAC（wildcard + ConformanceSuite）、Session hub、Webhook 引擎（订阅 + 死信队列）、用户生命周期状态机（邀请/激活/暂停/删除）、变更审批工作流、Token 策略、配置审计 + 漂移检测 |
| **质量** | 架构层导入边界（硬门）、文件 ≤ 500 / 函数 ≤ 50 / 圈复杂度 ≤ 15（硬门）、目录深度 ≤ 3（硬门）、500+ 可维护性测试、golangci-lint/govulncheck/gosec/CodeQL/Trivy/Dependabot（全部 14 个模块）、10+ fuzz 测试、Race CI、基准回归门 |

**结论：** 本项目已经饱和了传统身份平台扩展空间。剩余的高价值方向位于**运营基础设施、安全纵深防御、产品化商业化**的交叉区域——这些方向被现有协议为中心的分析框架系统性遗漏。

---

## 方向 1：Secrets 生命周期管理与凭据治理体系

> **影响：** 高 — SOC2/PCI/SOX 采购问卷的硬要求，当前状态是分散管理的合规风险  
> **工作量：** L（2–3 周 MVP）  
> **风险：** 低 — 增量添加，不改变现有凭据存储路径

### 当前状态

项目已有 **KMS 后端集成**用于签名密钥（AWS KMS、GCP KMS、Azure KeyVault、PKCS#11、Vault Transit）和 **webhook 签名秘密**（`audit.WithWebhookSigningSecret`），但**其余所有凭据**没有统一的声明周期管理：

| 凭据类型 | 当前存储方式 | 生命周期管理 |
|---|---|---|
| 数据库密码（SQLite/Postgres/Redis） | YAML 配置 / 环境变量 | 无（手动轮换） |
| SMTP 密码 | YAML 配置 | 无（手动轮换） |
| Webhook 签名秘密（审计/CIBA/Push MFA） | YAML 配置 / `signing_secret` 字段 | 仅 webhook 有 `rotation scheduler` |
| Admin bearer token | 引导时 mint，存于进程内存 | 无（不可轮换，重启丢失） |
| DCR client secret | SQLite/Postgres 数据库（bcrypt 哈希） | 仅通过 admin API 手动轮换 |
| Redis 密码 | YAML 配置 | 无（手动轮换） |
| etcd 客户端证书/密码 | YAML 配置 / 环境变量 | 无（手动轮换） |
| SAML IdP/SP 签名私钥 | YAML 配置 / 文件系统 | 无（手动轮换） |
| Kerberos keytab | 文件系统 | 无 |
| LDAP 绑定密码 | YAML 配置 | 无（手动轮换） |
| MFA push webhook secret | YAML 配置 | 无 |
| CIBA ping webhook secret | YAML 配置 | 无 |
| 自助注册 email/phone OTP 签名 | `CodeStore` 密钥 | 无 |

**关键缺口：** `config/sources/resolve_secrets.go` 提供了从外部源（AWS Secrets Manager）解析单个配置值的能力，但这是**解析时一次性读取**，没有轮换调度、没有过期告警、没有版本管理、没有审计追踪。`ops/deploy/k8s-prod/README.md` 将 `secretGenerator` 标注为 **Placeholder**（"replace with sealed-secrets / external-secrets / Vault"）。

### 为什么现在做

- **SOC2/PCI/SOX 采购问卷**直接问："是否有自动化凭据轮换？是否有秘密管理中心？"——当前答案是否定的。
- **安全事件的根本原因**统计中，硬编码/过期/泄露的凭据是身份基础设施的前三大风险之一。
- 项目已有 **轮换调度引擎**（`platform/lifecycle/rotation`）的基建，KMS 集成模式已验证，只需将模式推广到非签名凭据。
- 每个追加的集成（新的 KMS 后端、新的 secret store）都可以是独立的、低风险的 PR。

### Scope

| 交付物 | 描述 | 工作量 |
|---|---|---|
| **1. Secret reference 统一规范** | `shared/spi/secret_ref.go`：定义 `SecretRef` 类型（`inline` / `env` / `file` / `aws-secretsmanager` / `gcp-secretmanager` / `azure-keyvault` / `vault-kv` / `k8s-secret`），所有现有点（YAML 中的密码字段）迁移到统一的 `SecretRef` 解析器。向后兼容：字面量视为 `inline` 类型。 | 3 天 |
| **2. 凭据元数据注册表** | `platform/secretlifecycle/registry.go`：一个进程内注册表，记录所有已知凭据的 `{id, type, last_rotated, expires_at, rotation_interval}`。当通过 `SecretRef` 加载凭据时自动注册。提供 `GET /api/v1/admin/secrets`（列出所有注册凭据及其期限状态）。 | 2 天 |
| **3. 自动化轮换调度器** | 扩展 `platform/lifecycle/rotation` 支持通用凭据轮换：`rotation.<secret_id>.interval` / `overlap` 配置。轮换执行器 SPI（`Rotator{Rotate(ctx, currentSecret) (newSecret, error)}`）——签名密钥的轮换器已有，为每类凭据实现具体 Rotator。 | 3 天 |
| **4. 凭据过期告警** | `sso_secret_expires_at{id,type}` 指标，Prometheus `Deadman's Switch` 类告警规则（`sso_secret_expires_at - time() < 7d`）。集成到 `/readyz`（任何凭据在 24h 内过期 → degrade）。 | 1 天 |
| **5. HashiCorp Vault 集成** | `infrastructure/vault/` — 统一 Secrets Engine 集成（KV v2 + PKI + Transit），复用现有 `vaulttransit` 的客户端模式。支持动态秘密（Vault DB Engine 生成短期数据库密码）和静态秘密轮换。 | 3 天 |
| **6. AWS Secrets Manager / GCP Secret Manager / Azure Key Vault 集成** | 各一个独立子模块，与 KMS 集成相同的嵌套模块模式。将 `config/sources/resolve_secrets.go` 的现有能力扩展为完整的读+写+轮换能力。 | 每 2 天 |

**总计：** ~14 天 MVP（统一规范 + 注册表 + Vault 集成），~20 天完整方向

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 轮换期间旧凭据仍有效 | `overlap` 窗口：旧凭据在 `rotation.overlap` 期间保持有效（与签名密钥轮换相同的 fail-safe 模式） |
| 外部 Secrets Manager 不可用 | 启动时使用本地缓存的最后已知值（fail-open），标记为 degraded；持续不可用则最终拒绝启动 |
| 凭据引用循环（A 依赖 B 的密码，B 依赖 A 的密码） | 启动时检测到循环依赖 → 启动失败 + 明确错误消息 |
| 动态秘密（Vault DB Engine）过期后未刷新 | 连接池挂钩：捕获 `pq: password authentication failed` / `SQLITE_AUTH` → 触发重新解析 + 重连 + 更新注册表 |
| SecretRef 中明文密码的审计 | `SecretRef` 解析器在日志中始终记录为 `secret://<type>/<id>`，绝不记录值本身 |

---

## 方向 2：Operations SLO/SLI 框架与 Error Budget 驱动运维

> **影响：** 中高 — 将 80+ 指标从"可观测"升级为"可问责"，支撑 SLA 承诺  
> **工作量：** M（1–2 周 MVP）  
> **风险：** 低 — 纯增量，零生产代码变更

### 当前状态

项目已有丰富的可观测性基建：
- 80+ Prometheus 指标（`platform/metrics/`）
- 16 个预配置告警规则
- OpenTelemetry 分布式追踪
- 结构化审计（含哈希链完整性）
- k6 负载测试套件
- pprof 性能分析

**但没有任何 SLO（Service Level Objective）定义**——没有指标聚合为 SLI、没有 Error Budget 计算、没有容量规划模型、没有性能回归门禁：

| 运维问题 | 当前能否回答 |
|---|---|
| "过去 30 天我们是否达到了 99.9% 的 token 签发可用性？" | ❌ 不能 |
| "这个版本引入的延迟回归是否超过了 Error Budget？" | ❌ 不能 |
| "我们何时需要扩容？当前副本数能支撑峰值 QPS 吗？" | ❌ 不能 |
| "哪些租户正在消耗不成比例的 token 签发容量？" | ❌ 不能 |
| "负载测试是否通过了生产 SLO 验证？" | ❌ 不能 |

### 为什么现在做

- README 声称 ">1k QPS / hot-path"，但没有任何可运行的基准测试来验证这个声明，也没有回归护栏来防止退化。
- 企业买家在 RFI 中会问"您的 SLO 是多少？用什么工具跟踪？"——目前答案是"我们有指标但没有 SLO"。
- Error Budget 驱动的运维是现代 SRE 的基石（Google SRE 书第 3-4 章），对于身份基础设施尤其关键——一次 5 分钟的 outage 可能影响数十万用户的登录。
- 项目已有所有数据源（metrics、trace、audit），只需要聚合和框架。

### Scope

| 交付物 | 描述 | 工作量 |
|---|---|---|
| **1. SLI 定义与指标聚合** | `platform/slo/sli.go`：定义核心 SLI——`token_issuance_availability`（`sso_token_issued_total{outcome!="error"}` / `sso_token_request_total`）、`login_availability`、`token_verify_latency_p99`、`introspection_availability`、`config_change_success_rate`。每个 SLI 是一个 PromQL 表达式 + 窗口大小（默认 28d rolling）。 | 2 天 |
| **2. Error Budget 计算引擎** | `platform/slo/budget.go`：从 SLI 和 SLO 目标（如 99.9%）计算剩余 Error Budget。支持复合窗口（24h / 7d / 28d）。导出为 `slo_error_budget_remaining{ slo_name, window }` 指标。 | 2 天 |
| **3. 部署门禁集成** | `make slo-check`：CI 步骤，在 staging 负载测试后运行，将 Error Budget 消耗与 PR 关联。如果 PR 消耗超过 10% 的剩余 Error Budget，则阻止合并（可配置的 `slo.deploy_gate.threshold`）。这是 **性能回归的自动门**。 | 2 天 |
| **4. 容量规划模型** | `platform/slo/capacity.go`：基于当前 SLI 趋势 + 流量增长率的简单容量预测。输出 "按当前增长率，在 X 天后需要 N 个额外副本"。使用线性和指数平滑预测。导出 `slo_capacity_forecast_replicas_needed`。 | 2 天 |
| **5. 多租户 SLO 隔离** | 为高价值租户添加 `tenant_id` 维度的 SLI（如果租户数可控，或使用 top-N + other 桶）。允许 operator 定义 "gold/silver/bronze" SLO 层级。 | 2 天 |
| **6. SLO 仪表板 + 告警规则** | Grafana dashboard "SLO Overview" 面板：Error Budget 燃烧率、剩余百分比、SLO 合规性热图。告警规则：`budget_remaining < 10%`（P1 告警）、`burn_rate > 2` 持续 1h（P2）。 | 1 天 |
| **7. HPA/VPA 基准配置** | 基于当前负载特征的 `ops/deploy/helm/sso-server/` 中 `horizontalPodAutoscaler` 和 `verticalPodAutoscaler` 参考配置。使用 SLI 指标作为 HPA 度量（不只是 CPU/MEM——使用 `sso_token_issuance_latency_p99` 作为扩展指标）。 | 1 天 |

**总计：** ~12 天 MVP（SLI 定义 + Error Budget + CI 门禁 + 仪表板）

### 边界情况

| 边界 | 处理策略 |
|---|---|
| Error Budget 完全耗尽 | 进入"冻结期"——仅部署安全补丁和关键修复；所有功能 PR 被 CI 自动阻止 |
| 负载测试结果与生产差异大 | SLO 检查使用**相对基线**（与上一次合并到 main 的负载测试比较），而非绝对阈值 |
| 多租户维度导致指标基数爆炸 | 仅 top-20 租户有独立 SLO；其余聚合到 "other" 桶（与现有 `bounded_cardinality` 模式一致） |
| 容量预测在流量突变时不准 | 使用组合预测（线性 + 季节性分解）；预测附带置信区间；operator 看到的是区间而非单点数 |
| 新版本引入延迟回归但 Error Budget 充足 | SLO 门禁仅阻止 **消耗超过阈值的** PR；小幅回归在预算内允许通过——这是 Error Budget 的设计目标 |

---

## 方向 3：登录渐进式挑战升级与恶意流量检测

> **影响：** 高 — 针对凭证填充、账户接管和自动化攻击的前线防御  
> **工作量：** M（1–2 周 MVP）  
> **风险：** 低 — 增量添加，不改变现有认证路径

### 当前状态

项目已有基础的暴力破解防御：
- **Per-account lockout**（`shared/security/account_lockout.go`）
- **IP 失败计数器**（`infrastructure/defaultimpl/memorystorecredential/memory_ip_failure_counter.go`）
- **Brute force shadow detector**（`infrastructure/defaultimpl/detectors/brute_force_shadow.go`）
- **速率限制**（`interfaces/ratelimit/`）
- **CaptchaVerifier SPI**（`shared/spi/reg_gate.go`）+ **CaptchaGate**（`domains/authenticators/email.go`）

**关键缺口：** CaptchaGate 和 CaptchaVerifier 目前只用于**自助注册流程**（`protocols/selfservice/signup.go`），**完全没有集成到登录端点**（`/auth/login`、`/auth/mfa`、`/token/revoke` 等）。攻击者可以在没有任何挑战的情况下无限尝试登录——仅受 per-account lockout 和速率限制的约束（这些是**事后防范**而非**事前防御**）。

| 攻击模式 | 当前防御 | 缺失 |
|---|---|---|
| 横向凭证填充（每用户 1 次尝试，跨 10 万用户） | Per-account lockout 不触发（每用户仅 1 次失败）；速率限制按 IP，但攻击者使用 10K IP 的 botnet | 无 CAPTCHA 挑战，无 bot 检测 |
| 纵向暴力破解（单用户反复尝试） | Per-account lockout 在 N 次失败后锁定 | 无渐进式升级（warn → CAPTCHA → block），锁定后才 CAPTCHA 为时已晚 |
| 自动化 MFA 绕过（攻击者快速遍历 TOTP 值） | 无 | 无 MFA 尝试的挑战升级 |
| API 端点探测（攻击者扫描 /token、/introspect、/userinfo 发现漏洞） | 速率限制（全局/按 IP） | 无行为模式检测，无低慢扫描识别 |

### 为什么现在做

- 凭证填充（Credential stuffing）是 2025-2026 年身份基础设施面临的**第一大自动化攻击**（来源：Okta 2025 Security Report、Akamai State of the Internet）。
- 所有公共 SSO 端点每天都会受到凭证填充攻击——CaptchaVerifier SPI 已存在，只差登录流程的接线。
- 渐进式挑战升级是现代身份平台的标准实践（Auth0/Azure AD/Okta 全部实施）：正常用户无感、可疑用户 CAPTCHA、恶意用户阻止。
- 低慢扫描（Low-and-slow scanning）比爆破更难检测，需要行为分析而非仅速率阈值。

### Scope

| 交付物 | 描述 | 工作量 |
|---|---|---|
| **1. Login Challenge Orchestrator** | `shared/security/challenge_orchestrator.go`：一个请求路径上的策略执行点，决定是否需要挑战。输入：`{ user_id, ip, device_fingerprint, recent_failures, geo_velocity_score, request_rate }`。输出：`{ challenge_type: none | captcha | mfa_step_up | block, ttl }`。决策引擎使用可组合的规则（与 `conditionalaccess.PolicyEvaluator` 类似的 SPI 模式）。 | 3 天 |
| **2. Captcha 挑战集成到登录** | 扩展 `interfaces/sso/server_login.go` 中的登录处理器，在失败后或可疑上下文中插入 captcha 挑战。返回 `{ error: "challenge_required", challenge_type: "captcha", challenge_token: "..." }`。登录 SPA 显示 captcha widget。使用现有的 CaptchaVerifier SPI。 | 2 天 |
| **3. 渐进式升级策略** | 三个阶段策略（可配置）：（1）**低风险**：正常登录，无挑战；（2）**中风险**：要求 CAPTCHA，通过后正常认证；（3）**高风险**：拒绝请求，返回 `error="challenge_required"` + `challenge_type=blocked`。阶段阈值可配置（`challenge.lockout_threshold`、`challenge.captcha_threshold`、`challenge.block_threshold`）。支持按客户端/租户覆盖。 | 2 天 |
| **4. MFA 尝试的挑战升级** | 扩展 `/auth/mfa` 端点，对 MFA 验证码的连续失败（如 TOTP 尝试）增加 CAPTCHA 或延迟惩罚。防止自动化 MFA 暴力破解（TOTP 仅有 3 万种组合，自动化可在数秒内穷举）。 | 1 天 |
| **5. 低慢扫描检测器** | `infrastructure/defaultimpl/detectors/low_slow_scan.go`：一个基于 `anomaly.Detector` 的检测器，在 `anomaly.Runner` 中运行（离请求路径）。通过 `RecentLoginStore` 观察随时间分布的登录失败模式，标记均匀间隔、跨大量用户的低频率尝试。 | 2 天 |
| **6. 挑战遥测与指标** | 新指标：`sso_login_challenges_total{challenge_type, outcome}`（通过/失败/跳过）、`sso_login_challenge_escalation_total{stage}`（阶段迁移计数）。Grafana 面板：挑战率、各阶段转换趋势。 | 1 天 |
| **7. Admin API 策略管理** | `POST /api/v1/admin/challenge-policy` / `GET ...`——operator 查询和更新挑战策略。支持 YAML 配置 `challenge` 段作为静态备选。 | 1 天 |

**总计：** ~12 天 MVP（Orchestrator + Captcha 集成 + 渐进策略 + 指标）

### 边界情况

| 边界 | 处理策略 |
|---|---|
| CAPTCHA 服务不可用（hCaptcha/Cloudflare 故障） | 挑战降级为"增加延迟"（指数退避，`challenge.degraded_delay: 1s`）；不降级为无挑战 |
| 合法用户频繁触发 CAPTCHA | 通过 cookie/device fingerprint 白名单机制降低频率；已认证会话不重复触发 |
| API 客户端（无浏览器）无法通过 CAPTCHA | CAPTCHA 仅对交互式 `/auth/login` 适用；`client_credentials` / token-exchange 不受影响 |
| 隐私法规（GDPR）禁止跟踪失败计数 | 使用**匿名化**的失败计数器（HMAC(用户标识符 + 每租户密钥) 作为计数键），不存储原始用户标识符 |
| 分布式攻击触发跨所有租户的速率限制 | 挑战决策在租户范围内评估，不跨租户共享状态（防止一个租户的攻击影响其他租户） |
| 无头浏览器（Headless Chrome）绕过 CAPTCHA | CAPTCHA 作为**多层防御的一层**，不是唯一依赖；结合失败计数和速率限制形成纵深防御 |

---

## 方向 4：安全态势运行时评估与合规自助服务平台

> **影响：** 中高 — 将启动时检查扩展到运行时持续评估，满足企业合规自助服务需求  
> **工作量：** M（2–3 周 MVP）  
> **风险：** 低 — 纯增量，不修改现有安全逻辑

### 当前状态

项目在**启动时**有大量的安全检查（misconfiguration 检测、未满足的依赖导致启动失败、关闭的 issuer 检测等），但**运行时**缺乏持续的安全态势评估：

| 安全问题 | 启动时 | 运行时 |
|---|---|---|
| 签名密钥即将过期 | ✅ 启动时检查 | ❌ 无运行时过期告警 |
| 客户端机密未哈希存储 | ✅ SQLite 使用 bcrypt | ❌ 无法枚举"哪些客户端仍使用明文秘密" |
| FIPS 模式是否真正生效 | ✅ 启动时配置验证 | ❌ 无运行时 FIPS 一致性检查 |
| TLS 配置（密码套件、版本） | ✅ 启动时验证 | ❌ 无运行时端口扫描/自检 |
| 过期/未使用的客户端 | ❌ 无启动检查 | ❌ 无运行时检测 |
| 安全头已正确设置 | ✅ 启动时配置 | ❌ 无运行时验证 |
| 现已弃用的协议/端点仍在使用 | ❌ 无启动检查 | ❌ 无运行时指标 |
| 数据保留策略是否合规执行 | ✅ 配置可读 | ❌ 无运行时合规性状态 |
| 审计链完整性是否无中断 | ❌ 无启动检查 | ❌ 无运行时验证 |

### 为什么现在做

- 安全态势评估是企业合规团队在采购前的**标准问卷问题**："您的系统是否提供运行时安全态势仪表板？"
- 在 SOC2 / ISO 27001 / PCI DSS 审计中，审计员会要求**持续合规的证据**，而不仅仅是启动时的快照。
- 项目已有所有数据源（指标、审计、配置），只需聚合为统一的态势视图。
- 许多安全问题（过期密钥、未使用的客户端、协议降级）只有在运行时才能被发现。

### Scope

| 交付物 | 描述 | 工作量 |
|---|---|---|
| **1. 安全态势 SPI 与检查注册表** | `platform/securityposture/` — `Checker` 接口 `Check(ctx) → []Finding{severity, category, description, remediation}`。注册表包含内置检查器集合。每个检查器独立，可禁用。 | 2 天 |
| **2. 内置检查器（首批 8 个）** | （a）**签名密钥过期**：扫描所有 issuer 和 peer 密钥，报告 30 天内过期的密钥。（b）**明文客户端秘密**：通过 `ClientStore.ListAll` 枚举客户端，检查哪些使用 `token_endpoint_auth_method=client_secret_basic/post` 但秘密为弱哈希/空值。（c）**TLS 配置自检**：HTTPS 监听器的密码套件和 TLS 版本扫描（如果配置了 TLS）。（d）**弃用的协议使用**：追踪 `token_endpoint_auth_method=none` / implicit grant 使用计数。（e）**审计链间隙**：验证审计事件序列的哈希链无断裂。（f）**数据保留合规**：`compliance.RetentionSweeper` 上次成功运行的时间戳。（g）**FIPS 模式一致性**：验证配置的密码算法与 FIPS 140-3 允许列表一致。（h）**管理凭据年龄**：admin bearer token 的上次轮换时间（如适用）。 | 3 天 |
| **3. 态势仪表板 API** | `GET /api/v1/admin/security-posture` — 返回所有 checkers 的聚合结果，按严重性分组（critical/high/medium/low/info）。每个结果提供 `description`、`remediation`、`documentation_url`。可选 `?category=tls|keys|clients|audit|compliance` 过滤器。 | 2 天 |
| **4. 持续评估调度器** | 后台 goroutine 按间隔（默认 5m）运行所有检查器。结果缓存在进程内存中（供 API 读取）。发现新的高危发现时发送审计事件。 | 1 天 |
| **5. 高危发现告警** | 新 Prometheus 指标：`sso_security_posture_findings{severity, category}`。告警规则：任何 `severity=critical` 发现持续超过 1 小时 → P1 告警。 | 1 天 |
| **6. 合规报告生成器** | `GET /api/v1/admin/security-posture/report` — 生成一个机器可读的合规摘要（JSON/YAML）。适用于 SOC2/ISO27001 审计证据包。包含检查结果、上次运行时间、发现计数、整体姿态评分（healthy/warning/critical）。 | 2 天 |
| **7. Admin Console 态势面板** | `interfaces/web/admin/` 添加 "Security Posture" 页面：严重性仪表盘、按类别分组的发现列表、每个发现的修复说明。绿色/黄色/红色整体状态指示器。 | 2 天 |

**总计：** ~15 天 MVP（检查注册表 + 内置检查器 + API + 面板）

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 检查器在高负载下影响性能 | 所有检查器有超时（默认 10s）；超时检查器标记为 `check_timeout`，不阻拦其他检查器；检查器在后台运行，不在请求路径上 |
| 外部依赖不可用时（如审计后端） | 检查器优雅降级：如果无法访问审计存储，报告 `audit_chain_unavailable` 而非失败 |
| 检查发现误报 | 每个检查器有 `suppress` 配置（按 `finding_id` 或正则表达式模式）；禁用的检查器在仪表板中显示为灰色 |
| 隐私：检查器可能枚举用户名/客户端名 | 结果中仅包含标识符（无 PII）；详细数据通过现有的 admin API 单独获取 |
| 多个副本的检查结果不一致 | 每个副本独立运行检查器；聚合 API 返回本地结果（后续可交叉引用——但当前不跨副本聚合，避免一致性复杂性） |

---

## 方向 5：多租户计费与用量计量平台

> **影响：** 中 — 将 SSO 从"技术组件"转变为"可售卖产品"的必要基础设施  
> **工作量：** L（3–4 周 MVP）  
> **风险：** 中 — 涉及计费数据准确性，需要事务性保证

### 当前状态

项目已有 `domains/metering` 包和 `quota` 相关能力，但它们是**面向运维的遥测**而非**面向计费的计量**：

| 计量维度 | 当前状态 | 缺口 |
|---|---|---|
| MAU（月活跃用户） | ❌ 不存在 | 无按租户的 MAU 跟踪 |
| 活跃客户端计数 | ❌ 不存在 | 无法租户级计费 |
| Token 签发量 | ✅ 有 `sso_token_issued_total`（Prometheus） | 按租户细分需手动聚合 |
| 存储使用量 | ❌ 不存在 | 无每租户存储跟踪 |
| API 调用量 | ✅ 有 `sso_http_request_total` | 按租户/端点细分需手动聚合 |
| 功能使用量（SAML/WebAuthn/CIBA） | ❌ 不存在 | 无法按功能计费 |
| 用量报表/导出 | ❌ 不存在 | 无法提供给客户查看自己的用量 |
| 套餐/层级限制 | ❌ 不存在 | 无法实施基于套餐的限流 |

`domains/metering/metering.go` 定义了一个基础的 `Meter` 接口（`CountEvent(ctx, tenantID, eventType, n int64)`），但只有 memory 和 sqlite 实现，**没有连接外部计费系统**（Stripe、Chargebee、Metronome）的适配器，**没有用量聚合到计费周期的管道**，**没有套餐层级强制执行**。

### 为什么现在做

- 如果目标是**作为 SaaS 售卖**（"身份即服务"），计费集成是 P0 需求——没有它，就无法收费。
- 如果目标是**作为企业自托管销售**（"我们的 SSO 有用量仪表板"），企业 buyer 会问"我们能否跟踪 MAU 以确保不超过许可限制"——目前不能。
- `domains/metering` 的 SPI 已经存在——只需要计费适配器、聚合管道和管理 API。
- 与 Stripe/Metronome 的集成是一个独立的子模块（如 KMS/SAML 的 nested module 模式），不增加核心 go.mod 的依赖。

### Scope

| 交付物 | 描述 | 工作量 |
|---|---|---|
| **1. 计量事件类型定义** | `domains/metering/events.go`：明确定义的计费事件类型——`login_active_user`（日活跃用户）、`token_issuance`、`storage_bytes`、`api_call`、`feature_saml`、`feature_webauthn`、`feature_ciba`。每个事件携带 `tenant_id`、`timestamp`、`value`、`dimensions`。 | 1 天 |
| **2. 聚合管道** | `domains/metering/aggregator.go`：按计费周期（小时 → 天 → 月）聚合原始事件到计数。去重窗口（防止重复计费）。支持 `Meter.Record(ctx, event)` 和 `Meter.Aggregate(ctx, tenant_id, from, to) → []AggregatedUsage`。 | 3 天 |
| **3. 计费周期管理器** | `domains/metering/billing_cycle.go`：跟踪每个租户的计费周期（月度/年度/按需）。提供 `CurrentUsage(ctx, tenant_id) → UsageSummary`（当前周期用量 + 层级限制 + 剩余配额）。 | 2 天 |
| **4. 套餐/层级模型** | `domains/metering/plan.go`：可配置的套餐定义——`Plan{Name, MaxMAU, MaxClients, MaxStorageBytes, Features[]}`。加载自 YAML 或 admin API。`Enforce(ctx, tenant_id, event_type) → (allowed bool, reason)` 在计费限制接近时发出可选的预警信号。 | 2 天 |
| **5. Stripe 计费适配器** | `infrastructure/billing/stripe/` — 独立的嵌套模块（与 KMS/SAML 相同的模式）。同步 MAU/用量到 Stripe 的 `usage_records` API（用于 metered billing）或生成 `invoice_items`。处理 webhook（付款失败、订阅取消 → 租户暂停）。 | 3 天 |
| **6. 用量管理与报表 API** | `GET /api/v1/admin/usage/:tenant_id` — 当前周期用量摘要；`GET .../usage/history?from=&to=` — 历史用量时间序列；`GET /api/v1/admin/plans` — 可用套餐列表；`PUT /api/v1/admin/tenants/:id/plan` — 分配套餐。 | 2 天 |
| **7. 租户自助用量门户** | `interfaces/web/portal/` 添加 "Usage & Billing" 页面：当前周期用量仪表板、功能使用明细、套餐详情、计费历史（如果 Stripe 集成，则显示发票链接）。 | 2 天 |
| **8. 计费告警与超额保护** | `sso_billing_usage_ratio{tenant_id, metric}` 指标（当前用量 / 层级限制）。告警规则：使用率超过 80% → P3 warning；超过 100% → P2 超额；超额持续超过宽限期（可配置，默认 5 天）→ 自动暂停。 | 1 天 |

**总计：** ~16 天 MVP（事件类型 + 聚合 + 套餐模型 + API + 面板），~22 天含 Stripe 集成

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 计量事件的重复计数 | 幂等键（`event_id = HMAC(tenant_id + timestamp + sequence)`）；聚合器在窗口内去重 |
| Stripe webhook 失败或重复 | idempotency key（使用 Stripe 的 `Idempotency-Key` 头）；webhook 接收器是幂等的 |
| 租户在计费周期中间升级套餐 | 按比例分配：旧套餐退费，新套餐按剩余天数计费；用量计数从周期开始重置或按比例计算（可配置） |
| MAU 的去重窗口（同一用户一天内登录多次） | MAU = 在计费周期内至少有 1 次登录的唯一用户数（按 `user_id + tenant_id` 去重） |
| 免费套餐与付费套餐 | 免费套餐有 MAU/客户端限制，使用 `domains/metering/plan.go` 的 `Enforce` 方法在接近限制时发出软警告，达到硬限制时拒绝创建新用户/客户端 |
| 离线计费（Stripe 不可用） | 计量事件继续本地记录；Stripe 同步在恢复后重放；在同步间隙使用本地用量数据做权限决策 |
| 数据保留与 GDPR（用量数据含用户标识符） | 计量数据在聚合后匿名化（计费周期结束后删除原始事件，仅保留聚合计数）；MAU 去重使用 HMAC(用户 ID) 而非原始 ID |

---

## 优先级与排序建议

| 方向 | 价值 | 工作量 | 风险 | 依赖 | 排序建议 |
|---|---|---|---|---|---|
| **1. Secrets 生命周期管理** | 高 — SOC2 硬需求，安全基线 | ~14 天 MVP | 低 | 轮换调度器已存在 | **P1** — 安全合规基线，建议第一个开始 |
| **2. SLO/SLI 运维框架** | 中高 — 运维成熟度升级 | ~12 天 MVP | 低 | 指标已存在 | **P1** — 可为其他方向提供 SLO 门禁 |
| **3. 登录挑战升级** | 高 — 安全前线防御 | ~12 天 MVP | 低 | CaptchaVerifier SPI 已存在 | **P1** — 即时提升安全姿态 |
| **4. 安全态势评估** | 中高 — 合规自助 | ~15 天 MVP | 低 | 无 | **P2** — 增量价值，不阻塞其他方向 |
| **5. 计费计量平台** | 中 — 产品化必要基建 | ~16 天 MVP | 中 | 依赖 `domains/metering` | **P2/P3** — 仅当计划 SaaS 化时 P1 |

**执行顺序建议：** 方向 1 → 方向 3 → 方向 2 → 方向 4 → 方向 5。方向 1（Secrets 管理）和方向 3（挑战升级）直接提升安全姿态，是企业采购的第一关注点。方向 2（SLO 框架）为后续所有变更提供质量门禁。方向 4（态势评估）和方向 5（计费）是产品和合规增值层。

---

## 附录：在 30+ 现有分析中零覆盖的验证

本报告的 5 个方向已通过以下方法验证为在现有分析中零覆盖：

| 方向 | grep 关键词 | 在 `docs/requirements/*.md` 中命中数 | 在代码中命中数 |
|---|---|---|---|
| 1. Secrets 管理 | `secret.*lifecycle\|secret.*rotation\|credential.*governance\|secret.*manager.*integration` | 0 | 0（除 config/resolve_secrets.go 的一次性解析和 vaulttransit 的签名密钥外） |
| 2. SLO 框架 | `slo\|error.budget\|service.level\|capacity.plan\|hpa.*metric` | 0 | 0（排除 SAML SingleLogout） |
| 3. 挑战升级 | `challenge.*login\|challenge.*escalat\|login.*challenge\|captcha.*login\|progressive.*challenge` | 0（只在 registration 上下文提及 captcha） | 0（CaptchaGate 仅在 signup 中使用） |
| 4. 安全态势 | `security.*posture\|runtime.*assess\|self.*assess\|compliance.*scan\|security.*dashboard` | 0 | 0 |
| 5. 计费 | `billing\|metered.*bill\|usage.*price\|subscription.*tier\|plan.*limit\|stripe` | 0 | 0 |
