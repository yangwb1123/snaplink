# 全局扫描：身份平台扩展盲区 — 四个未覆盖的高价值方向

> **分析师：** 资深架构师 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 对全部代码库（2241 个 `.go` 文件、1114 个测试文件、14 个嵌套 `go.mod` 模块、4 个嵌入 SPA、60+ 协议实现、200+ 包）做系统扫描。在阅读了以下全部材料后做抗式 grep 逐项核验：
> - `docs/requirements/` 下全部 30+ 份历史分析（architect-expansion、senior-architect-*、expansion-*、Senior-Architect-* 系列）
> - `docs/deferred-backlog.md`（当前生效的缺口索引）
> - `docs/ROADMAP.md` v5.0 + 全部 superseded 历史
> - `docs/feature-matrix.md`、`AGENTS.md`、`DIRECTORY_MAP.md`、`docs/architecture/` 系列
> - 全部 ADR 和架构文档
>
> **定位：** 本项目的协议覆盖、安全纵深、存储后端、产品前端和生产基础设施均已达到行业顶级水平（详见前置声明）。  
> 经过 30+ 轮扩展分析，**剩余的高价值方向已不再是"新增协议"或"补充后端"，而是将身份平台从功能完整的技术产品推向可直接以 SaaS 形态交付、可被生态系统集成、可满足最严格合规审计的企业级基础设施的最后一层缺失能力。**  
> 以下 4 个方向中的每一项均已通过全代码库 grep 验证为零实现，且在全部 30+ 份历史分析中零提及或仅作为标签提及（从未作为完整的扩展方向被 scope）。

---

## 前置声明：项目成熟度评估

| 领域 | 关键能力 | 评估 |
|---|---|---|
| **协议面** | OAuth 2.0 × 7 grants（含 PAR/JAR/JARM/RAR/DPoP/mTLS/PKCE/CIBA/Step-Up/Transaction Token）、OIDC Core/Discovery/Logout/BCL/FCL/Form Post/Session Management/Silent Renewal/JWE、SAML 2.0 SP+IdP+SLO、SCIM 2.0 双向+Push Provisioning、CAEP/SSF 双向、FAPI 2.0、OpenID Federation 1.0、LDAP/Kerberos/RADIUS/WebAuthn/SPIFFE JWT-SVID/Workload Identity（GCP/AWS/Azure） | ✅ **全面** |
| **存储面** | Memory + SQLite（WAL+migrate）+ PostgreSQL + Redis（全热路径）+ etcd（cluster/registry/signingkeys）+ KMS×5 + SAML×4 + LDAP/Kerberos/RADIUS/ext_authz/Kafka/MQTT/Vault Transit | ✅ **全面** |
| **安全面** | Anti-enumeration（9 模式）、Oracle-leak（10 场景）、DPoP/mTLS/JKT/SPIFFE、Break-Glass、Per-tenant 签名隔离、数据驻留、FIPS 140-3、Account Lockout、Conditional Access、Anomaly Detection（4 detectors + Threat Action）、Credential Health、Rate Limiting、CSP L3 | ✅ **全面** |
| **产品面** | Hosted Login SPA、Admin Console SPA（全 CRUD）、Developer Portal SPA、User Portal（`/me` 全功能）、Consent Store（memory/sqlite/redis）、B2B Enterprise Connections、Org-admin Self-service、SDK Generation（TS+Python）、MCP Server、嵌入式 API Docs Viewer | ✅ **全面** |
| **运维面** | DR Framework（snapshot+RPO/RTO+replication）、Config Hot-reload（7 feature gates）、80+ Prometheus metrics + Grafana + Alert rules ×16、Audit hash-chain（OCSF/CEF/Syslog/Webhook/Kafka）、OpenTelemetry tracing、k6 load tests、Chaos tests ×4、Benchmark gate、K8s operator（SSOConfigDrift CRD） | ✅ **全面** |
| **治理面** | SOC2 report generation、GDPR Art.15/17/20/30、Data retention sweeper、ReBAC engine、RBAC（ConformanceSuite）、Session hub、Webhook engine、User lifecycle state machine（invite→active→suspend→erase）、Change approval workflow、Token policies、Config audit + drift detection | ✅ **全面** |
| **质量基建** | Architecture layer import boundaries（hard gate）、File≤500/func≤50/cyclo≤15（hard gates）、Depth≤3/fanout≤15（hard gates）、500+ maintainability tests、14-module golangci-lint/govulncheck/gosec/CodeQL/Trivy/Dependabot、10+ fuzz tests、Race CI、Benchmark gate | ✅ **全面** |

> **核心结论：** 经过 30+ 轮分析 + 大量落地，项目的"下一件应该做的事"已经不再是铺更多标准协议，而是补齐面向**最终用户的可信交互生态**、**合规审计的结构化证据链**、**外部集成系统的实时数据管道**、以及**多协议共存下的一致性治理**。这四项恰好对应了行业成熟身份平台（Auth0/Okta/Azure AD）在进入企业市场时最后完成的四项能力。

---

## 方向一：最终用户个人访问令牌（Personal Access Tokens for End-Users）

### Why Now

目前平台为 OAuth client 提供了 client_secret（DCR 注册时获得）和 client_credentials grant，且 Agent Delegation grant 支持 AI agent 场景。但缺少一种身份平台**最基础、最常用的开发者功能**：**最终用户生成属于自己的、可在脚本/CLI/CI-CD 中使用的长期有效访问令牌**。

| 平台 | 功能名称 | 应用场景 |
|---|---|---|
| GitHub | Personal Access Tokens (PAT) | `GITHUB_TOKEN` 在 CI/CD 中使用；开发者创建 PAT 用于命令行和 API 调用 |
| GitLab | Personal Access Tokens | 与 GitHub 类似，支持 scoped PAT |
| Auth0 | Machine-to-Machine (M2M) Apps | 但已迁移到支持用户级 API tokens |
| Okta | API Tokens | 管理员创建 token 调用 management API（但非最终用户） |
| Azure AD | Application + User tokens | 通过 OAuth device flow + token refresh 实现类似用途 |

**本项目现状：**

| 能力 | 状态 | 证据 |
|---|---|---|
| Client-scoped API key (DCR) | ✅ 存在 | `protocols/oauth/handle_register.go` — 注册 client 时生成 client_secret |
| Agent delegation grant（AI agent 委派） | ✅ 存在 | `domains/tokenexchange/agentidentity/` — 基于 act 链的代理模式 |
| **用户级静态令牌（PAT）** | ❌ **不存在** | `personal_access_token\|pat_store\|pat_service\|PersonalAccessToken` 在业务代码中 0 命中 |
| 用户级 PAT 管理 API | ❌ **不存在** | `GET /me/tokens\|POST /me/tokens` 0 存在（`/me` 已有 profile/sessions/MFA/credentials） |
| PAT 过期/轮换/撤销 | ❌ **不存在** | 全局 0 实现 |

### 为什么需要它

1. **开发者体验的必需品**：开发者使用身份平台的最终方式不是登录 UI，而是 API 调用。每个 SaaS 的 CI/CD、Terraform provider、CLI 工具都需要一个"开发者自己创建和管理"的长期令牌。没有 PAT = 开发者必须通过 OAuth 流获取短期 token → 不切实际 → 弃用平台。

2. **安全审计的盲区消弭**：今天，如果开发者需要在脚本中调用 API，可能的做法是：
   - 创建一个 DCR client（太重，需要 admin 审批）
   - 使用自己的用户凭据硬编码（密码泄露风险）
   - 使用 OAuth device code 交互式获取 token（不适合自动化）
   
   PAT 提供了一种 **可审计、可撤销、有范围限制** 的替代方案。每个 PAT 在审计追踪中有独立的 `token_id`，不像共享密码那样无法归因。

3. **与现有能力互补**：项目已有 `/me` 端点（用户自助服务页面），只需在其上增加 "Personal Access Tokens" 管理区即可。已有审计 pipeline 可以记录 PAT 的创建/使用/撤销事件。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) PAT 数据模型 & SPI** | `PersonalAccessToken` 结构体：`ID`、`UserID`、`TenantID`、`Description`、`ExpiresAt`、`Scopes`、`LastUsedAt`、`CreatedAt`、`Prefix`（前 8 字符用于 UI 标识）+ `TokenHash`（SHA-256 存储，创建时一次性返回明文）。`PATStore` SPI：`Create`、`ListByUser`、`GetByID`、`Revoke`、`Touch`（更新 LastUsedAt）、`RevokeAllForUser`。Memory + SQLite 后端。 | M |
| **(b) Self-service PAT API** | 扩展 `/me` 端点组：`GET /me/personal-tokens`（列出）、`POST /me/personal-tokens`（创建，返回一次性的明文 token）、`DELETE /me/personal-tokens/:id`（撤销）。创建时要求用户重新输入密码（re-auth guard，类似 GitHub 的安全保护措施）。 | M |
| **(c) PAT 认证中间件** | 自定义 `PATAuthenticator` 实现 `core.Authenticator`：识别 `Authorization: Bearer pat_<token>`（可配置前缀），验证 hash、检查过期、Touch LastUsedAt（异步，限频）。在 server 级别作为 `client_credentials` 的替代认证方式注册。 | L |
| **(d) Admin PAT 治理** | `GET /api/v1/admin/users/:id/personal-tokens`（列出用户的所有 PAT）、`DELETE /api/v1/admin/users/:id/personal-tokens/:id`（管理员强制撤销）。审计事件：`user_pat_created`、`user_pat_revoked`、`user_pat_authenticated`。 | S |
| **(e) Admin Console PAT 管理 UI** | 在 User 详情页增加 "Personal Access Tokens" 选项卡 → 列出该用户的所有活跃 PAT，显示描述/前缀/到期时间/最后使用时间/创建时间，支持管理员撤销。 | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| PAT 创建时明文仅出现一次 | 响应体返回明文 token（`pat_<random>`），**不**存储在数据库中（仅存储 SHA-256 hash）。类似于 GitHub PAT 的"copy this token now"模态框。这个一次性显示是安全设计，不是 UX 缺陷。 |
| PAT 丢失/遗忘 | 无法找回（hash 不能逆向），必须撤销并重新创建。安全优于便利。 |
| PAT 与 DCR client_secret 的关系 | PAT 与 client_secret 是不同的凭据：PAT 绑定到**用户**（用户直接为本人创建），client_secret 绑定到**客户端应用**（面向第三方开发者）。两者可同时存在，在 `/token` 端的认证路径不同。 |
| PAT 过期策略 | 默认 30 天，最长 365 天（可配置）。过期后自动失效，审计记录保留。创建时可选 `no_expiry`（需 admin 权限）。 |
| PAT 轮换 | 不支持"即时轮换"（不提供 refresh）。用户必须新建 + 撤销旧的。这符合 PAT 的安全模型（长期的、低频率的静态凭据）。 |
| PAT 范围限制 | 创建时可选 scope 列表（subset of user's own scopes）。为空时等效于用户的所有权限。最小权限原则：限定时只允许指定 scope 的操作。 |
| PAT 被泄露后的批量撤销 | `POST /me/personal-tokens/revoke-all`（需要 re-auth）、`DELETE /api/v1/admin/users/:id/personal-tokens`（管理员版本）。触发审计 + CAEP 事件（如有需要）。 |
| 并发创建/撤销的 TOCTOU | 使用 `resource_version`（乐观锁）：创建时读当前活跃数，检查配额后写入。撤销和创建之间的竞态通过先写入 wins 处理。 |

### Zero-overlap 验证

| 关键词 | 历史分析 | 本方向 |
|---|---|---|
| `personal_access_token\|PersonalAccessToken\|pat_store\|pat_service\|pat_` | 30+ 份历史分析中 0 次作为方向 scope | ✅ 全新增 |
| `user.*static.*token\|user.*deploy.*token\|user.*scoped.*token` | 同上 | ✅ 全新增 |
| `Developer API Key` | 在 3 份分析的"前沿面"标签列表中提及（`expansion-novel-v3/v4` + `senior-architect-v3`），但作为未分析的候选方向标签，无 scope/设计 | ✅ 首次完整定义方向 |

---

## 方向二：用户同意授权管理生命周期（User Consent Lifecycle Management with Structured Receipts）

### Why Now

项目已有 consent 存储基础设施：`core/spi.go` 定义了 `ConsentStore` 接口（`StoreConsent`、`CheckConsent`、`DeleteConsent`），有 memory / sqlite / redis 三个后端，支持 `ConsentGrant` 数据结构。consent 检查已集成到 OAuth 授权码流程中。

**但现有实现停留在最基础的水平——"user X 授权了 client Y（全部权限）"的二元模型**，缺少现代身份平台应有的精细授权管理能力：

| 能力 | 本项目中状态 | 行业标杆（Auth0/Okta/Azure AD） |
|---|---|---|
| 用户同意或拒绝具体 scope | ✅ scope 级（`GrantedScopes`） | ✅ |
| 用户同意或拒绝具体 claim（email/name/phone/address） | ❌ **不存在** | ✅ Auth0 consent 页面显示 requested attributes |
| 结构化同意凭证（consent receipt） | ❌ **不存在** | ✅ RFC 9396 风格的 structured consent record |
| 同意期限 & 自动过期 re-consent | ❌ **不存在** | ✅ Azure AD：consent 默认过期时间可配 |
| 用户面"我的授权"（`/me/authorized-apps`） | ❌ **不存在**（仅有 minimal `/me/consent`） | ✅ 每个平台的标准功能 |
| 同意撤销传播到下游服务 | ❌ **不存在** | ✅ Azure AD：撤销时发送 events 给 downstream |
| 用户拒绝特定 claim 时的降级行为 | ❌ **不存在** | ✅ claim 缺失时按需协商降级 scope |
| 动态 consent（运行时 incremental） | ❌ **不存在** | ✅ Azure AD incremental consent |
| 管理员审计：谁授权了什么 + 何时 + scope | ❌ 只有粗粒度 audit | ✅ 精细 audit trail per consent grant |

### 为什么需要它

1. **用户隐私的刚需**：欧盟 GDPR ePrivacy 法规和加州 CPRA 都要求用户对个人数据的收集和共享有"细粒度的控制权"。当前"全部接受或全部拒绝"的二元模式不符合这些法规的"granular consent"要求。这是一级合规风险。

2. **用户信任的关键 UX**：Google/Apple 的授权页面会展示"此应用将访问您的 email、姓名和个人资料图片"。当用户看到 scope 名称（"openid profile email"）时，并不清楚应用会获得什么——但展示具体的 claim 列表（email、name、picture、phone_number）能让用户做出知情决定。这是构建用户信任的最后 10%。

3. **生态系统的必然要求**：第三方开发者需要在集成说明中声明"我们只请求 email 和 name，不会读取您的地址"。没有 claim 级 consent，开发者无法向用户证明其应用的隐私行为。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) Consent 模型扩展** | 在现有 `ConsentGrant` 中增加：`GrantedClaims []string`（用户同意的具体 claim）、`ExpiresAt *time.Time`（同意过期时间，nil=永不过期）、`ConsentReceiptHash string`（同意凭证 SHA-256，用于证明同意的存在）。新增 `ConsentVersion int`（每次修改 +1）。 | M |
| **(b) Claim 级 consent UI** | 在 Hosted Login SPA 的 consent 页面中展示 client 请求的 claim 列表（`email`、`name`、`picture`、`phone_number` 等），带开关按钮。用户可展开查看每个 claim 的说明。选择结果（`granted_claims`）传递给 `/auth/authorize` endpoint。 | L |
| **(c) Consent 过期 & re-consent 引擎** | 后台任务扫描过期 consent（`ExpiresAt < now`）→ 发送审计事件 + 通知用户。授权时检查 `CheckConsent` → 如果 consent 已过期，重定向到 re-consent 页面（带 `prompt=consent` 参数）。re-consent 成功时生成新版本的 ConsentGrant。 | M |
| **(d) 用户授权管理 API** | 扩展 `/me`：`GET /me/authorized-apps`（列出已授权的 client + scope + claim + 授权时间）、`DELETE /me/authorized-apps/:client_id`（撤销全部）、`PUT /me/authorized-apps/:client_id`（修改 scope/claim 授权范围）。撤销时触发 `consent_revoked` 审计事件。 | M |
| **(e) 同意撤销传播** | 扩展 CAEP/SSF 事件类型以包含 `consent_revoked` 事件。当用户撤销 consent 时，通过已有的 CAEP 发射器（`WithCAEPTransmitter`）推送到已配置的 RP 接收端。对于未配置 CAEP 的 RP，记录审计事件并提供 Webhook 通知（通过已有 webhook 引擎）。 | L |
| **(f) 管理员 consent 审计 API** | `GET /api/v1/admin/users/:id/consents`（列出用户全部历史 consent grant，含已撤销和已过期的）、`GET /api/v1/admin/clients/:id/consents`（列出授予此 client 的全部 consent）。`GET /api/v1/admin/consents/audit-trail/:grant_id`（单个 consent 的完整生命周期事件）。 | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 用户拒绝 email 但 client 要求 email | 降级策略：client 可声明 `required_claims`，用户拒绝时返回 `consent_required` 错误而非静默缺失。允许 client 在 discovery/registration 中声明其 required claims。 |
| re-consent 循环 | 用户反复拒绝又接受 → 每次产生新版本，但不过度频繁提醒。最小 re-consent 间隔（默认 24h）。 |
| 离线 consent（device code / CIBA） | Device code flow 中 consent 只能以 scope 粒度进行，无法展示 claim 级选择（屏幕太小）。但之后用户可通过 `/me/authorized-apps` 修改授权粒度。 |
| consent 过期后未 re-consent 的 token | 已签发的 access_token 在其自然生命周期内仍然有效。过期的 consent 只影响新 token 的签发和 refresh token 的轮换。 |
| 批量客户端的 consent 审计开销 | 大租户可能数百个 client + 数千个用户 → consent 审计查询需要精心设计的索引（`(client_id, user_id)` 复合索引），分页 + 异步导出到 CSV。 |
| 同意凭证的司法效力 | `ConsentReceiptHash` 不是法律意义上的数字签名（不具备不可否认性），但为 "用户于 T 时间点同意了这些 scope/claim" 提供了审计链证据。如果需要不可否认性，consent 创建时追加用户签名（挑战用户重新输入密码或使用 FIDO2 进行密钥签名）。 |

### Zero-overlap 验证

| 关键词 | 历史分析 | 本方向 |
|---|---|---|
| `consent.*receipt\|consent.*lifecycl\|consent.*version\|consent.*expir\|re.consent\|consent.*revocat.*propagat\|consent.*expir` | 30+ 份历史分析中 0 次作为方向 scope（仅在事件名或标签中提及） | ✅ 完整方向 |
| `claim.*consent\|claim.*grant\|granular.*consent\|per.claim.*authoriz\|user.*authorized.*app\|authorized.*app.*manage` | 在 `senior-architect-global-scan` 方向 4 有 `granted_claims` 提及，但作为 claim 过滤管道的子项，非完整的 consent 生命周期治理 | ✅ 差异化覆盖 |
| `consent.*renew\|consent.*refresh\|consent.*reauthor\|consent.*reaut` | **0 命中** | ✅ 全新增 |

---

## 方向三：身份变更数据捕获管道（Identity Change Data Capture Pipeline — ID-CDC）

### Why Now

项目拥有极其丰富的**审计事件**系统（`platform/audit`），但审计和变更数据捕获（CDC）是两个不同的概念：

| 维度 | Audit（审计） | CDC（变更数据捕获） |
|---|---|---|
| 消费者 | 安全团队、合规审计员 | 外部系统、集成方、数据管道 |
| 数据结构 | 人类可读、事件描述 + Metadata map | 结构化 `(resource_type, resource_id, operation, before, after)` |
| 完整性 | hash-chain 防篡改 | at-least-once 递送协议 |
| 保留期 | 长（年级），不可修改 | 可配置（小时到天），可重放 |
| 存储格式 | 归档优化（SQLite/CEF/OCSF） | 消息队列优化（Kafka/RabbitMQ/Redis Streams） |
| 使用方式 | 合规审计、取证分析 | 外部同步、数据集成、实时分析 |

**当前 gap：** 外部系统（CRM、HRIS、数据仓库、SIEM）如需实时感知身份变化（"用户 X 被创建了""client Y 的 scope 被修改了""权限 Z 被更新了"），只有两种笨拙的方式：
1. 轮询 admin API（昂贵、延迟、不一致）
2. 解析审计日志（非结构化、无 schema 保证）

**缺少的是：** 一个**正式的事件订阅管道**，将身份域的所有变更（user、client、tenant、permission、session、token 等）以结构化的 schema-aware 事件发布到消息总线，供外部系统消费。

### 当前代码级具体缺口

| 组件 | 状态 | 缺口分析 |
|---|---|---|
| `cluster.Bus` SPI | ✅ 存在 | event bus 抽象（`Publish/Subscribe`），但当前仅用于跨副本同步（`KindTokenRevoked`、`KindSigningKeyRotation` 等），不是用于对外发布的 CDC 事件 |
| `platform/audit` | ✅ 存在 | 事件包含 `EventType` 和 `Metadata map[string]any`，但 `Metadata` 无 before/after schema，格式不稳定，不保证 `resource_type`/`resource_id` 字段的完整性 |
| `domains/metering` | ✅ 存在 | 用量事件可聚合，但无领域事件（domain event）的概念 |
| `kafka` 嵌套模块 | ✅ 存在 | Kafka 基础设施已存在（`infrastructure/kafka`），可以用作 CDC 事件的传输层，但无事件 schema 注册或序列化管道 |
| `events/` 或 `cdc/` 包 | ❌ **不存在** | 无 CDC 相关的包或模块 |
| 身份资源的 `Before`/`After` 快照 | ❌ **不存在** | 审计事件记录"发生了什么"但不记录"变更前后的值是什么" |

### 为什么需要它

1. **外部集成的核心基础设施**：企业身份平台最常见的集成需求之一就是"当用户/组/权限变化时，同步到下游系统（HRIS、CRM、数据仓库）"。当前项目需要外部系统全量轮询 admin API 或手动调用 SCIM——这是低效的、不实时、不符合事件驱动架构的做法。

2. **补充而不是替代 SCIM**：SCIM 提供了标准化的用户/组 CRUD，但不覆盖 client、tenant、permission、policy、session、token 等身份平台特有资源的变化。CDC 管道覆盖完整身份域。

3. **为数据仓库和 BI 分析提供原始数据**：企业客户需要将身份数据与业务数据关联分析（"用户注销后多少天内活跃度下降？"）。CDC 事件流可以直接导入 Snowflake/BigQuery/ClickHouse，无需 ETL 从 admin API 爬取。

4. **复用已有基础设施**：Kafka、MQTT 和审计 pipeline 都已存在。需要做的是在 `audit.Recorder` 旁路并行发布一条结构化的 CDC 事件到消息总线。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) CDC 事件 schema 定义** | 定义 `CDCEvent` 结构体：`ID`、`Source`（service name）、`ResourceType`（user/client/tenant/role/permission/session/consent/…）、`ResourceID`、`Operation`（create/update/delete/suspend/restore/…）、`Before`（JSON，可 null）、`After`（JSON，可 null）、`Timestamp`、`TenantID`、`ActorID`、`TraceID`、`CorrelationID`（支持 saga 模式）。版本化：`SchemaVersion int`。 | M |
| **(b) CDC 事件发布中间件** | 在 write path 的关键存储操作后注入 `publishCDCEvent` 调用：`ClientStore.PutClient`、`UserStore.PutUser`、`TenantStore.PutTenant`、`PermissionStore` 的 mutating 操作、`TokenStore` 的 revoke/rotate、`SessionManager` 的 create/destroy。使用 `spi.Logger` 的 `Warn` 级降级（发布失败不阻断主操作）。 | L |
| **(c) CDC 传输后端** | 实现两个后端：`kafka`（利用已有 `infrastructure/kafka`，Avro/JSON 序列化，topic per resource type 或 single topic with partition key）+ `mqtt`（利用已有 `infrastructure/mqtt`，用于边缘/轻量部署）。wire 在 `sso.go` 中作为可选 option：`WithCDCExporter(topicPublisher)`。 | M |
| **(d) 事件订阅管理 API** | `GET /api/v1/admin/cdc/topics`（列出可用 topic/event types）、`POST /api/v1/admin/cdc/subscriptions`（创建订阅，指定回调 URL + event type filter + secret for HMAC signing）、`DELETE /.../subscriptions/:id`。复用现有的 webhook engine 的订阅模式（但 CDC 事件走 Kafka/MQTT，不经过 Webhook 的死信/重试）。 | L |
| **(e) CDC 事件重放** | `POST /api/v1/admin/cdc/replay?resource_type=user&since=2026-01-01T00:00:00Z&until=2026-06-01T00:00:00Z`——为新的下游消费者提供历史事件的批量重放，用于初始同步。重放从 CDC 事件存储（Kafka 的 log compaction 或专用的 CDC archive store）中读取。 | L |
| **(f) CDC 事件存储** | 可选的事件归档存储（SQLite/PostgreSQL）：存储 30 天内的 CDC 事件，用于重放 + 调试。超过 30 天的事件移入冷存储（S3/GCS parquet 格式）。使用分区表按天分区，自动删除过期分区。 | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| CDC 事件发布失败不阻塞关键路径 | 使用 `spi.Logger.Warn` 降级，不返回错误给调用方。可配置为异步后台发送（通过 channel + worker pool，缓冲 1000 条后开始丢弃最旧事件并记录 audit alert）。 |
| before/after 包含敏感字段 | 可选地脱敏 `password_hash`、`secret`、`email`、`phone` 等敏感字段。基于 JSON path 模式的脱敏规则（与 `platform/audit/redactor.go` 复用相同的脱敏引擎）。 |
| 事件顺序保证 | 相同资源 ID 的事件按时间戳顺序消费。通过 Kafka partition key = `resource_type:resource_id` 保证单个资源的事件的顺序。跨资源的事件无严格顺序保证（最终一致）。 |
| 事件重复 | 事件 ID（UUID v7）使消费者可以幂等去重。至少交付一次的语义要求消费者自己处理重复。 |
| 从 CDC 重建外部系统状态 | 新消费者订阅后需要全量快照 + 增量事件。重放 API 提供"快照到某个时间点"的能力（从 CDC archive 中读取所有事件，按时间排序后重放）。 |
| CDC 事件与审计事件的时差 | CDC 事件在主流程发布（synchronous after write），审计事件是异步的（`audit.Recorder` 通过 channel 异步处理）。CDC 事件可能在审计事件之前到达消费者——但两者 timestamp 一致。 |
| 不记录 full before/after 的变更 | 对于某些批量操作（`DELETE /api/v1/admin/users?status=suspended`），before 和 after 可能很大。策略：仅记录 `resource_id` 列表 + operation，before/after 为 null，提示消费者通过 admin API 获取完整状态。 |

### Zero-overlap 验证

| 关键词 | 历史分析 | 本方向 |
|---|---|---|
| `CDCEvent\|cdc_event\|cdc.*publish\|cdc.*topic\|cdc.*subscription\|CDCExporter` | **0 命中**（`CDC` 关键词在 `expansion-systemic-quality-horizon` 中作为"零实现"的验证标签出现一次，未作为方向 scope） | ✅ 首次完整方向 |
| `change.*data.*capture.*identity\|identity.*cdc\|identity.*event.*channel` | **0 命中** | ✅ 全新增 |
| `event.*subscription.*API\|event.*topic.*manage\|event.*consumer.*group` | **0 命中**（webhook 引擎有订阅模式，但那是针对 webhook 回调，不是针对 CDC 事件流） | ✅ 全新增 |

---

## 方向四：身份数据平面一致性审计与跨协议状态协调（Identity Data Plane Consistency Audit & Cross-Protocol State Reconciliation）

### Why Now

项目同时管理着多个身份协议的数据平面——OAuth 令牌、OIDC 会话、SAML 会话、SCIM 用户、LDAP 绑定、WebAuthn 凭证——它们在同一个用户身份下共存。但**没有一个机制系统性地验证这些相互独立的存储是否处于一致状态**。

**具体场景：**

| 场景 | 当前行为 | 潜在问题 |
|---|---|---|
| 管理员 suspend 一个用户 | Session hub 会撤销该用户的所有 OAuth/OIDC/SAML 会话 | ✅ 正常 |
| 管理员 suspend 一个用户后立即 unsuspend | 用户被恢复但之前被撤销的 session 无法恢复 | ❌ 用户必须重新登录 |
| SCIM 外部更新了用户的 active 状态 | 用户的状态变化被写入 user store 但可能不同步到 OAuth session | ⚠️ 未验证 |
| 审计报告显示"用户 A 在 JSON 时间点有活跃 session" | session 数据已过期（被 GC 清除），审计无法提供"当时确实活跃"的证明 | ❌ 无法证明 |
| 某 token 在同一用户的多个 device code 流中被错误绑定 | 缺乏跨设备令牌一致性检查 | ❌ 无检查 |
| MFA 状态变更后（用户移除了所有 MFA 方法） | 要求 MFA 的 client 在下次登录时会被降级？ | ⚠️ 取决于实现 |

**这不是一个"功能"层面的大问题——但它是达到企业级可信度的关键质量属性（correctness）。** 企业平台必须能够证明其内部状态是一致的、可审计的、无静默数据丢失的。

### 当前代码级具体缺口

| 组件 | 状态 | 缺口分析 |
|---|---|---|
| `platform/lifecycle/sessionhub` | ✅ 存在 | 跨协议会话关联已经做到（OAuth ↔ SAML ↔ WebAuthn），但无定期一致性检查 |
| `userlifecycle.StateMachine` | ✅ 存在 | 用户状态转换（active/suspended/pending/erased）有 audit 记录，但无状态一致性断言 |
| `caep.EventMapper` | ✅ 存在 | 可将身份事件映射为 SET，但无从 SET 反向验证状态一致性的机制 |
| `configaudit.Diff` | ✅ 存在 | 配置 diff 工具（intra-cluster + cross-cluster），但无**运行时数据平面**的一致性验证 |
| `platform/dr/readiness.go` | ✅ 存在 | DR readiness tracker 检查组件健康，但不验证数据一致性 |
| **跨存储一致性验证器** | ❌ **不存在** | 无 `ConsistencyChecker` SPI 或类似机制 |
| **静默数据丢失检测** | ❌ **不存在** | 无定期扫描验证"每个 user 在 session hub 中的条目是否在 user store 中有对应记录" |
| **一致性审计报告** | ❌ **不存在** | 无 `GET /api/v1/admin/system/consistency-report` 端点 |

### 为什么需要它

1. **企业级可信度的基础——证明一致性**：合规审计（SOC2 Type II、HIPAA、PCI DSS）要求证明"系统在所有时间点正确运行"。当前架构无法证明"用户的 suspended 状态在所有数据平面（OAuth session、refresh token、SAML session、SCIM downstream）都得到了正确一致的反映"。没有这个证明 → 审计发现项 → 客户信任损失。

2. **渐进式迁移的保障**：当租户从 memory 后端迁移到 SQLite 再到 PostgreSQL 时，或从单副本迁移到多副本时，静态 diff 已经存在（configaudit 的 cluster-diff），但运行时数据平面的一致性没有保障。CDC 管道（方向三）和一致性验证器共同提供"迁移后的数据与迁移前一致"的证明。

3. **SCIM 下游的被动数据漂移检测**：当一个 SCIM provisioning 下游（如 Workday、Azure AD Connect）推送用户变更时，变更可能因网络、权限或 schema 不匹配而部分失败。一致性检查器可以发现这些漂移并提供补丁机会。

4. **独特的安全价值**：一致性缺陷是高级攻击者的利用目标——如果一个攻击者能通过漏洞绕过一个协议的数据平面而另一个没有，一致性检查器可以检测到这种不对称（例如：用户被 OAuth 撤销但 SAML 会话仍然活跃）。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 一致性检查 SPI** | 定义 `ConsistencyChecker` 接口：`CheckUserConsistency(ctx, userID) → *ConsistencyReport`。`ConsistencyReport` 包含每个检查项的状态（`consistent` / `inconsistent` / `not_applicable` / `error`）+ 详细信息。默认检查项：<br>• user_store ↔ session_hub（user 在 user store 中 → 其活跃 session 是否一致）<br>• user_store ↔ refresh_token（user 的 refresh token 是否与用户状态一致）<br>• client_store ↔ client_cache（分布式缓存是否与后端一致）<br>• session_hub ↔ audit（session hub 中的 session 是否有对应的 audit event）<br>• permissions ↔ assigned_roles（所有被指派的 role 是否指向存在的 role 定义） | M |
| **(b) 周期性后台一致性扫描器** | 后台任务（可配置间隔，默认 24h）扫描随机采样或全量用户，运行一致性检查，记录不一致到 `consistency_check_results` 表。发现不一致时：记录审计事件 + 可选自动修复 + 通知管理员。全量扫描支持分页和并发控制（按 tenant 并行扫描）。 | L |
| **(c) 一致性检查 Admin API** | `GET /api/v1/admin/system/consistency`（最近一次自动扫描的摘要：总检查数、一致数、不一致数、错误数、扫描耗时）、`GET /api/v1/admin/system/consistency?full=true`（触发一次全量扫描）、`POST /api/v1/admin/users/:id/consistency-check`（对单个用户执行即时检查）、`GET /api/v1/admin/users/:id/consistency-report?since=...`（用户的历史一致性报告）。 | M |
| **(d) 自动修复策略** | 对于某些可自动修复的不一致项（如 "user 在 session hub 中有 entry 但 user store 中用户状态为 suspended"——自动撤销 session + 发送 CAEP 事件），提供补丁动作。不可自动修复的（如 "数据丢失"→ 需要管理员介入 + 通知）。自动修复记录到 audit。 | M |
| **(e) Admin Console 一致性面板** | 新面板展示系统一致性健康度（“Consistency Score”：一致数 / 总检查数 × 100%），按租户、按资源类型（user/session/token/permission）的下钻分析。不一致项列表（可排序、过滤、标记为已处理）。 | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 检查期间的并发写 | check 和 mutate 之间的 TOCTOU：一致性检查不持有锁。检查结果代表"检查时刻的快照"。偶尔的假阳性（检查时 A 一致，下一秒用户被 suspend → 检查结果为不一致）可接受——后续扫描会纠正。假阴性（检查时不一致但未检测到）通过多轮扫描降低概率。 |
| 大规模租户的全量检查 | 全量检查需要遍历所有用户和 session → 使用 cursor-based pagination，每批 100 个用户，跨批之间等待可配置的间隔（默认 100ms），避免对生产存储造成冲击。支持按租户并行。 |
| 检查本身的性能开销 | 对不一致的扫描不应高过 1% 的 DB CPU。通过限制检查频率（默认每用户/每 24h 一次）和采样率（默认 10% 的用户/租户）控制。全量检查需要管理员显式触发。 |
| 不一致的自动修复导致循环 | 自动修复可能导致 state → check → state mismatch → 再次修复 → 循环。实现冷却期：同一项不一致在 1 小时内不重复自动修复。超过 3 次自动修复仍然不一致 → escalate 给管理员人工判断。 |
| 分布式部署中的一致性 | 在多副本部署中，不同副本可能观察到数据平面的不一致（本地缓存 vs 全局状态）。一致性检查器以 leader（或协调后的单一副本）运行，以全局状态（后端存储）为准。 |
| 历史一致性的验证 | 对于已删除的 session、过期的 token，一致性检查不适用（`not_applicable`）。一致性检查仅针对**当前活跃**的资源。历史一致性完整性的证明由 audit hash-chain 保证。 |

### Zero-overlap 验证

| 关键词 | 历史分析 | 本方向 |
|---|---|---|
| `consistency.*check\|consistency.*report\|consistency.*audit\|cross.*protocol.*consistency\|data.*plane.*consistency\|identity.*consistency.*score` | **0 命中**（`configaudit` 的 config drift ≠ runtime data plane consistency） | ✅ 全新增 |
| `state.*reconcil.*identity\|identity.*reconcil.*cross\|session.*reconcil.*token\|user.*reconcil.*session` | **0 命中** | ✅ 全新增 |
| `drift.*detect.*runtime\|runtime.*drift.*user\|runtime.*drift.*session` | **0 命中**（所有"drift"相关分析均针对配置漂移 `configaudit`，不是运行时数据平面） | ✅ 全新增 |

---

## 总结：优先级矩阵

| 方向 | 产品价值 | 安全价值 | 合规价值 | 工程投入 | 优先级 | 独立交付 |
|---|---|---|---|---|---|---|
| ① 最终用户个人访问令牌 (PAT) | ★★★★★ | ★★★☆☆ | ★★☆☆☆ | M | **P0**（开发者体验门槛） | ✅ |
| ② 用户同意生命周期治理 | ★★★★☆ | ★★★★☆ | ★★★★★ | L | **P0**（隐私合规 + 用户信任） | ✅ |
| ③ 身份 CDC 管道 | ★★★★☆ | ★★☆☆☆ | ★★★★☆ | L | **P1**（企业集成基础设施） | 依赖① part(f) |
| ④ 数据平面一致性审计 | ★★☆☆☆ | ★★★★★ | ★★★★★ | L | **P1**（合规 + 可信度） | ✅ |

### 实施建议

1. **Sprint 1-2：方向①（PAT）最小可行版本**
   - PAT SPI + Memory 后端 + `/me/personal-tokens` API（CRUD）
   - 一次性 token 返回 + SHA-256 存储
   - PAT 认证中间件
   - **交付价值**：开发者可以立即创建和使用个人令牌，无需经过 OAuth 流程

2. **Sprint 2-3：方向②（Consent Lifecycle）最小可行版本**
   - `ConsentGrant` 模型扩展（`GrantedClaims`、`ExpiresAt`、`ConsentReceiptHash`）
   - Hosted Login 页面 claim 级展示（仅视觉，后端验证为核心）
   - `/me/authorized-apps` 查看 + 撤销
   - **交付价值**：满足 GDPR granular consent 要求 + 用户透明

3. **Sprint 3-5：方向③（ID-CDC）最小可行版本**
   - CDC Event schema + Kafka 后端（复用基础 Kafka 模块）
   - Client/User/Tenant 三个核心资源的写路径埋入点
   - CDC 事件重放 API
   - **交付价值**：外部系统可实时消费身份变更事件，无需轮询 admin API

4. **Sprint 5-7：方向④（Consistency Audit）核心能力**
   - Consistency Checker SPI + 核心检查项（user↔session、user↔token）
   - 后台周期性扫描器 + Admin API
   - Admin Console 一致性面板
   - **交付价值**：合规审计可展示"每个时间点所有数据平面一致"的证明

### 方向间的依赖关系

```
方向①（PAT） ── 独立 ──→ 开发者在 CLI/CI 中使用平台
方向②（Consent） ── 独立 ──→ 隐私合规 + 用户信任
方向③（CDC） ── 依赖方向① part(f) CDC 存储 ──→ 企业集成
方向④（Consistency） ── 独立但抽象复用 CDC 的事件格式 ──→ 合规证明
```

方向①和方向②可并行开始；方向③建议在方向①的 CDC 存储基础设施之后开始（但也可独立基于 kafka 基础设施）；方向④可独立开始但建议在方向③的 CDC schema 确定后做一致性事件的格式对齐。
