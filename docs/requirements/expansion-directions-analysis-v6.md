# 扩展方向分析报告 v6

> **作者：** 资深架构 & 产品视角  
> **日期：** 2026-07-10  
> **范围：** 全代码库全局扫描（2227+ `.go` 文件，~1300 包）  
> **方法：** 逐项 grep 对抗核验（默认"大概率已实现"，读到代码证伪），排除已落地特性  
> **目标：** 列出 3-5 个尚未覆盖的高价值扩展方向、边界情况处理与性能优化点

---

## 执行摘要

本项目是目前最全面的开源 OAuth 2.0 / OIDC SSO 平台之一。覆盖了几乎所有主流 RFC（authorization code、PKCE、DPoP、mTLS、JARM、JAR、CIBA、RAR、PAR、token-exchange、transaction tokens、device flow、FAPI 2.0、OpenID Federation 1.0），包含 4 个内嵌 SPA（登录页、管理控制台、自助门户、开发者门户）、多种存储后端（memory、SQLite、Postgres、Redis、etcd）、生产级可观测性（Prometheus metrics、OpenTelemetry tracing、Merkle 链审计）、以及对 KMS（AWS/Azure/GCP/PKCS#11/Vault）和多种企业协议（SAML 2.0、SCIM 2.0、Kerberos、LDAP、RADIUS）的支持。

以下 5 个方向经过全库核验，确认是目前尚未覆盖或存在显著差距的高价值扩展领域。

---

## 方向 1：Terraform Provider —— 以基础设施即代码管理 SSO 配置

### 现状

SSO 的管理面通过两层暴露：管理员的 gRPC/REST gateway（`grpcserver/admin_*.go`）和嵌入式 Admin Console SPA（`interfaces/web/admin/`）。通过这两个界面可以进行 clients/users/tenants/permissions/snapshots 等全量 CRUD、签名密钥轮换、审计查询等操作。

当前需求：**任何 >= 中型企业的平台工程团队，在采购评估时第一个问题总是"你们有 Terraform Provider 吗？"**。这是将 SSO 配置纳入 GitOps 工作流的前提条件。

### 缺口（grep 核验）

- 全树无 `terraform` 或 `pulumi` 或 `cdktf` 关键词（零命中）
- 存在 `cmd/sso-operator`（K8s operator，仅做集群间配置 drift 检测，不做配置 APPLY），但它并非 Terraform Provider
- 没有与任何声明式配置管理系统集成的代码或文档

### 范围

1. **Terraform Provider SDK v2 / Plugin Framework 实现**（独立的 Go 模块，不污染核心 go.mod）：
   - Resource: `sso_client`（创建/更新/删除，支持所有 Client 字段：redirect_uris、grant_types、allowed_scopes、jwks、token_endpoint_auth_method 等）
   - Resource: `sso_user`（创建/更新/删除，含 attributes、permissions 绑定）
   - Resource: `sso_tenant`（创建/更新/删除/暂停/激活，含 domain、residency、branding）
   - Resource: `sso_permission_role`（创建/更新/删除 RBAC 角色 + 权限绑定）
   - Resource: `sso_webhook_subscription`（管理事件订阅）
   - Data source: `sso_client`、`sso_user`、`sso_tenant`、`sso_keys`、`sso_discovery`
   - Data source: `sso_jwks`（获取当前签名公钥集合）

2. **Pulumi Provider**（可选，基于 Terraform Bridge 或原生 Go SDK）

3. **配套 Acceptence Tests（`terraform-plugin-testing`）** 和文档

### 边界情况

| 边界 | 处理策略 |
|---|---|
| `client_secret` 在 Terraform state 中明文 | 标记为 `Sensitive: true`；提供 `ignore_changes` 支持；实现 `rotation_secret` 属性仅做轮换触发（`POST /admin/clients/{id}/rotate-secret`） |
| 配置 drift（外部修改 vs Terraform state） | 默认 `Read` 回源核对；可选 `PreventDestroy` 生命周期钩子防止误删 |
| 导入已有资源 | 实现 `ImportState` + `Importer` 接口，支持 `terraform import sso_client.xxx <id>` |
| 多 accept-language Provider 版本 | 按照 Terraform Provider SDK 约定，版本号与 SSO server 版本解耦 |
| 大规模资源（上千 client/user）的 refresh 性能 | 提供 Data Source 的 pagination 和 filter 支持 |

### 为什么值得做

**Terraform Provider = 企业采购的入场券**。没有 Provider，平台工程团队无法将 SSO 配置纳入其现有的 IaC 流程（`terraform plan / apply` → PR review → 自动部署）。这是 Auth0、Okta、Keycloak、WorkOS 都提供的基础设施，缺失意味着在 RFP 首轮就被排除。同时它是**纯度极高的 SDK 消费方**——所有操作通过现成的 admin REST API 完成，核心 SDK 零改动。

---

## 方向 2：跨组织联邦信任网络（Cross-Org Federation Trust Network）

### 现状

OpenID Federation 1.0 已在代码中实现（`domains/federation/` 中的 trust chain、entity statement、metadata policy 等全套逻辑；`/.well-known/openid-federation` 和 `/fetch` 端点）。Tenant 模型（`domains/tenant/`）支持多租户、租户域名映射和租户隔离。

**但是**：当前的 Federation 是"协议层面的底层能力"——它描述了如何解析和验证联盟实体之间的信任链。它**不是**一个面向产品的"Org-to-Org 信任网络"：没有跨租户的信任建立流程、没有可见的"外部组织"概念、没有可接受的外部 IdP 发现与邀请机制。

### 缺口（grep 核验）

- `Tenant` 结构体没有指向外部组织的信任连接字段（仅有 `domains/connections/` 的 DNS 域验证等基础连接模型）
- 没有"cross-tenant trust relationship"（跨租户信任关系）的 SPI / 存储 / API
- 没有自发现机制：Org A 如何发现并信任 Org B 的 IdP 端点？
- `TokenExchange`（RFC 8693）支持跨租户 B2B 协作的 `/token` 交换（`WithExternalUserStore` + `WithTenantCollaborationStore`），但仅限单次 token-exchange，不是持续的信任连接

### 范围

1. **Org-to-Org Trust Relationship SPI**（`domains/federation/trust/`）：
   - `TrustRelationship{ID, SourceTenantID, TargetEntityID, Status: pending/active/revoked, CreatedAt, ExpiresAt}`
   - `TrustRelationshipStore` 接口（memory + sqlite 实现）
   - 每条关系代表一个方向性信任——Org A 信任 Org B 的 IdP

2. **信任邀请与接受 API**：
   - `POST /api/v1/admin/federation/trust-relationships`（发起信任邀请，用 OpenID Federation 实体语句签名邀请 JWT）
   - `PUT /api/v1/admin/federation/trust-relationships/{id}/accept`（接受入站邀请）
   - `DELETE .../trust-relationships/{id}`（撤销信任）

3. **跨 Org IdP 发现**：
   - 信任建立后，自动发现被信任方的 IdP 实体（获取其 entity configuration、JWKS、authorization/token endpoints）
   - 以 `Connection` 形态表现（复用 `domains/connections/` 的 Domain Verification 机制）

4. **Product UX 增强**：
   - Admin Console 增加"Trusted Organizations"页面
   - 跨组织用户搜索（`/admin/users/search?org=external-org-id`）
   - 跨组织令牌交换/身份映射策略配置

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 信任链环检测（A→B→C→A） | `TrustRelationshipStore` 禁止创建已存在目标 + 源的反向关系；Graph cycle detection |
| 信任撤销后的活跃令牌 | CAEP/SSF 事件广播（`token_revoked`），现有 `caep/` 可复用 |
| 被信任方实体暂停/删除 | 信任关系转为 `degraded` 状态，现有 `degradation` 框架（`platform/lifecycle/degradation/`）可对接 |
| 信任的 TTL 与自动续期 | 继承 OpenID Federation 的 `exp` 字段，到期前自动重验证 |

### 为什么值得做

这是从"多租户 IdP"升级到"**身份互联网络**"的关键差异化能力。Auth0 的 Organizations、WorkOS 的 Directory Sync、Okta 的 Org2Org 都定位在同一赛道。本项目的 Federation 协议实现（信任链、实体语句、元数据策略）已经在协议层完备——需要的只是一个产品层的**包装**，把底层协议能力暴露为可管理、可审计的信任关系。**核心 SDK 改动极小，主要是新的 API 层和 UI 层**。

---

## 方向 3：主动身份威胁检测与响应（Active ITDR —— 从观察到自动防御）

### 现状

当前的安全检测系统（`domains/anomaly/` + `domains/tokenanomaly/`）是**纯观察性**的：

- `anomaly.Runner` async 运行 detectors（`brute_force_shadow`、`impossible_travel`、`new_baseline`、`velocity`），但**永不参与 auth 决策**——日志审计 `anomaly_*` 事件后不做任何响应
- `tokenanomaly.Detector` 同样是 async 的 token 使用异常检查（地理位置突变、时段异常等），仅记录发现
- `RiskScorer`（`shared/trust/`）可以评分但不能采取行动
- `BruteForceShadow` 仅观测撞库模式，不阻止
- **没有任何"检测到威胁后自动阻断"的机制**——没有自动吊销令牌、没有自动触发 MFA 挑战、没有自动暂停用户/客户、没有 IP 自动封锁

### 缺口（grep 核验）

- 全树无 `auto_remediate`、`automatic_block`、`automatic_suspend` 关键词
- `anomaly.Runner` 的回调接口只有 `OnDetect`（记录事件），没有 `OnThreatResponse` 接口
- `tokenanomaly` 检测到异常后只记录，不触发撤销
- `shared/risk` 的评分结果（`score`、`level`）没有任何消费者——既不尽早熔断请求，也不触发 step-up auth
- 没有"威胁情报馈入 → 自动响应策略 → 执行"的闭环

### 范围

1. **ThreatResponse SPI**（`platform/threatresponse/`）：
   - `ThreatResponse{ID, Type: revoke_token/suspend_user/challenge_mfa/block_ip/notify_admin, Target, Severity, CreatedAt}`
   - `ThreatResponseStore`（memory + sqlite）
   - `ThreatExecutor` 接口：`Execute(ctx, response) error`

2. **预置的 Threat Executors**：
   - `RevokeTokenExecutor`：调用现成的 `TokenRevocationStore.MarkRevoked` 和 `SessionManager.Revoke`
   - `ForceMFAAction`：对该用户的下一次请求要求 MFA（复用 `step_up_auth.go`）
   - `SuspendUserAction`：临时暂停用户（复用 `tenant` 的 suspension 机制）
   - `BlockIPAction`：向 `IPFailureCounter` 写入 IP 黑名单
   - `NotifyAdminAction`：发送审计事件 + 可选 webhook 通知

3. **Detection ↔ Response 接线**：
   - 改造 `anomaly.Runner` 的 `OnDetect`，增加 `OnThreat(ctx, anomaly) → ThreatResponse`
   - 为 `tokenanomaly.Detector` 增加相同的回调
   - 设计 `ThreatDetectionPolicy`（YAML 可配置）：`severity_to_action_map`（如 `critical → revoke_token+suspend_user`，`high → challenge_mfa`，`medium → audit_only`）

4. **同步风险评分的行动化**：
   - 改造 `login` 路径：`RiskScorer.Score()` 返回的分数进入响应决策——若 `level=high` 则强制 `step-up MFA`；若 `level=critical` 则拒绝请求
   - 这是从"事后审计"到"实时阻断"的核心转变

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 误报阻断 | 所有自动响应可逆：`suspend_user` 有自动化解除（时间窗口+无新事件）；`revoke_token` 不可逆（安全设计） |
| 响应风暴（检测到 flood → 自动封大量合法用户） | 限速器保护：`ThreatExecutor` 自带 rate-limit（每分钟最多 N 次自动响应）；响应链必须有 `cooldown` |
| 攻击者利用 ITDR 进行 DoS（伪造异常、触发其他用户封锁） | `IPFailureCounter` 区分"真实失败"与"异常检测触发的响应"；`ThreatResponse` 有 `source: auto/manual` 标签 |
| 自定义响应策略 | `ThreatDetectionPolicy` 用户可编程：`critical: [revoke_token, notify_admin]; high: [challenge_mfa]; medium: [audit_only]` |
| 调试模式 | 可选 `dry_run: true`——响应被记录但不执行，策略调整期使用 |

### 为什么值得做

所有企业安全团队都在从"检测和响应"向"**主动防御**"转型（Gartner 的 CARTA、MITRE ATT&CK 的自动响应覆盖）。当前代码已经有**业界最强之一的检测管道**（4 个内置 detector + token 异常检测 + geo/trust scorer），但这些检测的 output 止于日志——是一个"装了烟雾报警器但没人去灭火"的状态。把检测回路接到自动响应，是**极低成本、极高安全价值**的转变（检测管道 SDK 零改，只需加一层 action executor + 政策引擎）。

---

## 方向 4：分布式部署中的时间安全 —— 时钟偏斜硬化与 NTP 异常处理

### 现状（边界情况 / 性能优化方向）

当前代码在多个关键路径上使用 `time.Now()`，假设系统时钟为单调递进、且跨副本时钟同步。这在一个分布式 SSO 系统中存在一系列安全风险。

具体代码位置（grep 核验）：

| 路径 | 文件 | 代码 | 风险 |
|---|---|---|---|
| Session Refresh 过期检查 | `defaultimpl/sqlite/sessions.go` | `WHERE expires_at>now` | NTP 回跳 → 已过期 session 复活 |
| Refresh Token 过期判断 | `protocols/oauth/oauthspi/refresh_token.go` | `IsExpired(t time.Time)` | NTP 步进 → 同一 token 被判定"未过期" |
| DPoP iat 校验 | `interfaces/sso/server_extensions.go` | 硬编码 1min skew | 跨区域集群的 1min 窗口过小，正常请求被拒 |
| AuthCode 过期 | `infrastructure/defaultimpl/memorystoreoauth/memory_auth_code.go` | `time.Now().After(exp)` | 同上 |
| JTI replay 窗口 | `shared/security/jti_replay.go` | 基于 `time.Now()` 判断 | 回跳可让已见过的 JTI 被接受 |
| Session 创建/刷新 | `infrastructure/defaultimpl/sqlite/sessions.go` | `expires_at = ?` | 时钟前跳导致 session 早于预期过期 |
| Discovery 缓存 | `protocols/oidc/oidcsupport/discovery_doc_cache.go` | `time.Now().After(expires)` | 时钟跳变 → 缓存异常失效/不失效 |
| 签发的 token iat/nbf | `infrastructure/defaultimpl/defaulttoken/jwt_issuer.go` | `time.Now()` | 跨副本 iat 乱序 → RP 侧验证失败 |
| 审计时间戳 | `platform/audit/recorder_events_session.go` | `time.Now()` | 跨副本审计日志时间线错乱 |

### 当前缓解措施

- AGENTS.md §2 记录："Forward/monotonic wall clock — ops MUST slew, never step"（操作者必须 slew 时钟，禁止步进）
- 但这是操作文档**非代码强制**——没有任何运行时护栏检测时钟回跳

### 建议范围

1. **单调时钟基础设施**（`shared/core/monotime/`）：
   - `MonoClock` 接口：`Now() time.Time`（挂钟）、`MonotonicNow() time.Duration`（进程单调时间，用于相对间隔判断）
   - `WallClock` 默认实现（当前行为，用于需要真实时间的场景）
   - `SafeClock` 实现：检测时钟回跳（`monotonic - last_monotonic < 0` 时触发告警，使用 `last_known_wall + elapsed` 作为回退值）

2. **关键路径替换**：
   - Session/TTL 过期检查使用 `min(wall_expires_at, monotonic_now + ttl)` 而非裸 `time.Now()`
   - DPoP iat 校验窗口改为可配置（`WithDPoPMaxClockSkew(duration)`），默认放宽到 5min
   - AuthCode/Refresh/Device/PAR 的 TTL 检查：绝对时间用 wall clock，相对时间（"该值在 N 秒前创建"）用 monotonic

3. **跨副本时钟偏斜检测**：
   - 在 `cluster.Bus` 层面增加时钟信息心跳（每个消息带本副本的 `monotonic_now` + `wall_now`）
   - 接收方检测 `|their_wall - our_wall| > threshold` 时，记录审计警告 `clock_skew_detected`
   - /readyz 增加 `clock_health` 检查：skew > 阈值（如 5s）→ degraded

4. **时钟安全写入实现指南**（更新 AGENTS.md §2）：
   - 显式记录"可接受的时钟偏斜范围"
   - 强制 ops 采用 `chrony slewing` 而非 `ntpd -g` 步进
   - 提供 `sso-ctl check-clock` 诊断命令

### 为什么值得做

**时钟是分布式系统的隐藏单点故障**。NTP 回跳/步进在 SSO 系统中不仅仅是"小故障"——**它会直接导致：已撤销的令牌复活、已过期的 session 被续期、已用过的 JTI 被重放、审计时间线不可信**。这些问题在压力测试/灾难恢复演练中最容易暴露（刚恢复的 VM 时钟未同步即开始服务），且一旦发生难以诊断。相比其他功能扩展，这是一个**纯安全/正确性方向**，修复成本相对低（主要是系统性的时钟抽象替换），但修复后消除的是一整类分布式安全漏洞。

---

## 方向 5：全局统一搜索与运营智能

### 现状

Admin API 提供了对 users、clients、tenants、sessions、audit 事件的列表和查询接口。但这些查询是**分库分表、各自独立的**：

- `GET /api/v1/admin/users` — 按用户属性筛选
- `GET /api/v1/admin/clients` — 按客户端属性筛选
- `GET /api/v1/admin/audit/events` — 预定义的 facet 聚合查询
- `GET /api/v1/admin/tokens/portfolio` — 按用户/客户端查看令牌

**没有跨实体的统一搜索**——管理员无法通过一个搜索框找到"所有与 email 为 foo@bar.com 的用户相关的东西"（她的 sessions、clients、审计事件、consent grants、令牌）。

### 缺口（grep 核验）

- 全树无 `FullTextSearch`、`SearchEngine`、`Elasticsearch`、`Meilisearch`、`bleve`、`typesense` 关键词
- `audit.Query` 不支持正文全文搜索
- 没有跨资源类型的关联查询

### 范围

1. **搜索索引 SPI**（`platform/search/`）：
   - `IndexableDocument{ID, Type: user/client/tenant/session/event, TenantID, Body: json, CreatedAt}` 
   - `SearchIndex` 接口：`Index(ctx, doc)`, `Delete(ctx, id)`, `Search(ctx, query, opts) → Results`
   - 内置 `memory.SearchIndex`（用于单元测试）和 `sqlite.SearchIndex`（基于 SQLite FTS5，零外部依赖）

2. **索引接入点**：
   - 在现有写路径上附加索引：`UserProvider.CreateOrUpdate` → 索引 user；`ClientStore.Set` → 索引 client；`TenantStore.Set` → 索引 tenant；`audit.Sink` → 索引事件
   - 异步、fail-open（索引失败不阻塞主请求，通过重试队列兜底）

3. **搜索 API**：
   - `POST /api/v1/admin/search?q=...&type=user,client&tenant=...&page=...`
   - 返回带 `relevance` 评分的混合结果，按类型分组

4. **运营智能面板**：
   - Admin Console 增加"Search"页面（统一搜索框 + 过滤 + 详情下钻）
   - "Related entities"面板：展示用户的活跃 sessions、clients、recent events、consent grants

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 索引延迟 | 异步索引默认 ~1s 可见；Admin Console 提示"搜索结果可能存在短暂延迟" |
| 多租户数据隔离 | 索引文档带 `TenantID`；搜索 API 强制当前 admin 的 tenant 过滤；跨租户搜索需要 `admin:read.*` scope |
| 敏感字段索引 | `client_secret`、`registration_access_token` 等不在索引中；索引字段白名单控制 |
| FTS5 并发限制 | SQLite FTS5 写入串行化（WAL 模式缓解）；达到规模阈值后可切换到外部搜索引擎（es/meilisearch）作为不同实现 |
| 索引规模 | 提供可配置的保留策略（audit 索引仅保留 N 天）；FTS5 支持增量 VACUUM |

### 为什么值得做

运营一个 SSO 平台时，**最频繁的管理员操作就是"找到 X 相关的一切"**——有用户报告问题 → 搜索用户 ID → 查看她的 sessions / 令牌 / 最近事件 / 授权应用。没有统一搜索，管理员必须在 5 个不同的页面之间手动跳转。这是**当前 DX 的最大感官差距**，也是从"功能完整"到"运营愉悦"的关键一步。SQLite FTS5 零依赖、自包含，即使作为过渡方案也即刻可用。

---

## 附录 A：高优先级边界情况与性能优化 sprint-filler

以下问题来自全库扫描，颗粒度不足以独立成方向，但价值明确、修复范围小，适合作为 sprint filler 逐项消化。

### A.1 MemoryLimiter O(N) 全表扫描 + 单一全局锁（安全 → 性能）

**位置**：`interfaces/ratelimit/ratelimit.go:87`

`Allow()` 持 `sync.Mutex` 后无条件 `pruneLocked` 全 map 扫描。默认限流器位于中间件链最前、对每个请求执行。N（活跃 key）正是其防御的撞库攻击所放大的——攻击期合法登录被串行化在 O(N) 扫描后，**自成 DoS 放大器**。SQLite 兄弟已 `%64` 采样（`sqlite_limiter.go:204`），照搬 + 分片锁即可。

**建议**：分片锁（如 64 个 shard）+ 随机采样 prune（每请求仅 prune 1/N 概率）。

### A.2 SQLite 连接池配置真空 + `busy_timeout` DSN 参数失效（稳定性）

**位置**：全树无 `SetMaxOpenConns` 等调优；`_busy_timeout` 作为 DSN 参数被传入但 `modernc.org/sqlite` 不认（需 `_pragma=busy_timeout(N)`）。

**影响**：cmd 对同一 WAL 文件开 ~18 个独立 `*sql.DB` 池（各默认无上限）。WAL 仅一个 writer → `SQLITE_BUSY` 抖动。

**建议**：写池设 `MaxOpenConns=1`，经现有 `WithDB` 共享一个调优过的池；`config.yaml` 默认改用 `_pragma=busy_timeout(5000)`。

### A.3 Refresh Token 并发优雅窗口缺失（正确性 → UX）

**位置**：`protocols/oauth/oauthspi/refresh_token.go`（rotation 严格单用）

**影响**：多标签 SPA、移动端冷启竞态、丢响应后重试——与真正的重放攻击无法区分，良性双提交导致 `DeleteFamily` 触发登出风暴。

**建议**：补充有界 reuse-grace（N 秒内对同一叶子 token 返回已铸造的后继），不削弱 BCP §4.13。

### A.4 JWKS 服务端 Body 缓存缺失（性能）

**位置**：`interfaces/sso/accessors.go:226`（`ComputeJWKSDocument` 仅合并并发，每次串行重走 issuer + 重 marshal + 重 sha256）

**影响**：JWKS 端点每次请求都重新计算，与 discovery 的 body+ETag 缓存不一致（federation 已缓存同样的 issuer-JWKS）。

**建议**：补 1-5s 有界 body 缓存（与 discovery 缓存共用 TTL 策略）。

### A.5 审计无批量写路径（性能 + 合规）

**位置**：`platform/audit/`（`Sink` 仅单条 `Record`，async worker 逐条 drain）

**影响**：一次登录发多事件，高 QPS 下单 writer SQLite 封顶审计吞吐，队列满则 drop-newest（合规隐患）。

**建议**：补充 `RecordBatch` group-commit 接口（内存批次合并 → 单次 INSERT 多行 / 单次网络调用）。

### A.6 Federation/JAR SSRF DNS-Rebind 窗口（安全）

**位置**：`domains/federation/fetcher.go:173`（仅拒字面 private IP，不复查解析后 IP）

**影响**：域名 DNS 解析到 `169.254.169.254`（metadata endpoint）可绕过检查。

**建议**：`net.Dialer.Control` 钩子对解析后 IP 复核 `isInternalIP`（JAR 侧已有 `AllowedRequestURIs` 强缓解，但 Federation 缺同等保护）。

---

## 附录 B：优先级一句话总结

**若只能选一件先做 → 方向 1（Terraform Provider）**：零 SDK 改动、直接打开企业采购大门、工作量明确（独立 Go 模块）。

**次选 → 方向 3（Active ITDR）**：现有检测管道唯一缺失的闭环，安全价值最高，对核心 SDK 侵入最小（新增 action executor SPI + 接线）。

**Sprint filler 最高 ROI → A.1（MemoryLimiter 分片锁） + A.3（Refresh 优雅窗口）**：前者修复一个真实的自 DoS 放大路径，后者消除生产环境中确认发生的良性登出风暴。

**基础安全投资 → 方向 4（时钟偏斜硬化）**：系统性消除一整类分布式安全漏洞。建议作为架构标准（`monotime` 包）在下一个重构周期中逐步落地。
