# 资深架构师全局扫描：五项未覆盖的高价值扩展方向（v2 — 真正的新缺口）

> **分析师角色：** 资深架构师 & 产品经理
> **日期：** 2026-07-11
> **方法：** 全代码库全局扫描（~93,000 行 Go，2241 `.go` 文件，~200 包，12 嵌套子模块，4 嵌入 SPA）。
>   系统性阅读 ROADMAP v5.0、deferred-backlog、feature-matrix、所有 50+ 份历史分析文档
>   （`docs/requirements/*.md`）、`docs/adr/` 全部 ADR、最新 `senior-architect-fresh-scan-2026-07-11.md`
>   及 `architect-*` 系列今日文档。每个方向经全代码库 grep + 历史文档关键词反查双重核验，
>   确保与所有已有分析文档**零重叠**或仅在目标层面有本质差异。

---

## 前置声明：项目项目成熟度

经过 50+ 轮架构分析与大量代码落地，本项目已覆盖身份平台的几乎所有协议层、存储后端、
安全防线、产品前端与运维基础设施。以下为经最新扫描确认的核心能力覆盖（仅列关键数据）：

| 维度 | 状态 | 关键覆盖数据 |
|---|---|---|
| **协议** | ✅ 全面 | OAuth 2.0 ×7 grants + OIDC (Discovery/Session Mgmt/Backchannel Logout/Frontchannel Logout/Form Post/JARM/CIBA) + SAML 2.0 SP+IdP + SCIM 2.0 + CAEP/SSF + FAPI 2.0 + OpenID Federation 1.0 + LDAP/Kerberos/RADIUS/SPIFFE/Workload Identity |
| **存储** | ✅ 全面 | Memory + SQLite + PostgreSQL + Redis + etcd + KMS×5 (AWS/GCP/Azure/PKCS#11/Vault) + Kafka/MQTT |
| **安全** | ✅ 全面 | DPoP/mTLS/JKT、Break-Glass、FIPS 140-3、Anti-enumeration×9、Oracle-leak×10、Account Lockout、Conditional Access、Anomaly Detection×4、Session Trust Decay、Threat Executor |
| **产品** | ✅ 全面 | Hosted Login SPA、Admin Console SPA（全 CRUD）、Developer Portal SPA、User Portal（`/me`）、Consent Store×3、B2B Connections、SDK Generation（TS+Python）、MCP Server、API Docs Viewer |
| **运维** | ✅ 全面 | DR Framework、Config Hot-reload（SIGHUP）、80+ Prometheus Metrics、Audit Chain（OCSF/CEF/Syslog/Kafka/Merkle hash-chain）、OTel Tracing、k6 + Chaos Tests、K8s Operator（SSOConfigDrift CRD） |
| **质量** | ✅ 全面 | 架构层 import 边界强制、File≤500/Func≤50/Cyclo≤15 强制、500+ maintainability tests、govulncheck/CodeQL/Trivy/Dependabot、Fuzz×10+、Race CI、directory_fanout/maxdepth 门禁 |
| **企业化** | ✅ 全面 | 多租户域路由、租户 Residency 强制执行、数据保留策略自动化、SCIM 推式预配、合规数据导出/GDPR 擦除、SOC2 就绪报告、Subject 导出/erasure、跨集群 Config Diff |

**核心发现：** 经过 50+ 轮分析 + 本轮全量 grep 核验，项目已不存在"缺失某标准协议"或
"缺少某存储后端"这类传统缺口。所有已有分析文档提出的方向，要么已落地为代码，
要么明确标记为 deferred-backlog 中的"Done/Pending"。ROADMAP v5.0 的五方向未覆盖在
`senior-architect-fresh-scan-2026-07-11.md` 中已系统陈述。

**本 v2 文档关注的 5 个方向，是经双向核验确认与所有已有文档零重叠的"真正新缺口"**
——聚焦于生产级认证流水线可扩展性、大规模令牌运维治理、用户通知基建、会话协议桥接、
以及密码生命周期标准化管理。

---

## 方向一：认证流水线中间件引擎（Authentication Pipeline Middleware Engine）

### 类型

认证可扩展性 / 运行时流水线 / 插件化逻辑注入

### 为什么需要

当前认证流水线是一条**硬编码的链**（`server_login.go` → `handler_login.go` →
`handleLogin` → `authenticateWithProvider` → 可选 MFA → `conditionalaccess.Evaluate` →
`RiskScorer.Score` → 发放 token），所有逻辑在代码级静态组合。虽然 WASM 授权引擎
（`platform/lifecycle/wasmauthz`）提供了授权决策点的扩展性，但**认证路径本身完全
不可扩展**。

具体来说，以下场景当前无法实现而不改核心代码：

| 场景 | 当前做法 | 期望做法 |
|---|---|---|
| 对新用户做强制 Profile 补齐 | ❌ 不存在，需 fork SSO 代码 | 注册后/首次登录时插入"补齐 Profile"步骤 |
| 基于公司网络判断跳过 MFA | ❌ 不存在 | 在 MFA 步骤前插入"IP 白名单跳过"钩子 |
| 登录时同步 IdP 属性到本地 | ❌ 只在现有声明映射点执行 | 认证后、Token 签发前注入自定义属性变换 |
| 登录失败计数达到阈值触发第三方 SIEM | ❌ 仅 audit event + webhook | 登录失败后插入异步通知（已有 `threataction` 但不够细粒度） |
| 登录前设备合规检查（非 CAP） | ❌ 仅 conditionalaccess.Evaluate | 登录前 Hook 做 MDM/Jamf/JumpCloud 设备状态查询 |

**当前代码缺口验证：**

| 检查项 | 结果 |
|---|---|
| `WithLoginPipelineHook` / `WithPreLoginHook` / `WithPostAuthHook` | ❌ 任何版本的此类 SPI 均不存在 |
| `LoginPipeline` 可编程配置 | ❌ 不存在——流水线是将代码中逐个调用的函数 |
| `platform/lifecycle/authpipeline/` | ❌ 目录不存在 |
| 仓库中 `auth.*pipeline\|auth.*hook\|login.*pipeline\|login.*hook\|auth.*middleware.*chain\|PreAuth.*Hook\|PostAuth\|custom.*auth` 匹配 | ❌ 0 命中（非测试文件） |
| 已有分析文档覆盖（grep 50+ 份文档） | ❌ `auth.*pipeline.*engine\|auth.*hook.*spi\|login.*middleware.*engine\|auth.*plugin.*runtime\|auth.*chain.*configurable\|LoginPipeline.*Hook` 在全部 50+ 份文档中 **0 命中** |

### Scope

1. **Pipeline Hook SPI** — 定义 `core/AuthPipelineHooks`：
   ```go
   // LoginPhase identifies a named point in the login pipeline.
   type LoginPhase string
   const (
       PhasePreAuthenticate      LoginPhase = "pre_authenticate"       // 认证前（可拒绝请求）
       PhasePostAuthenticate     LoginPhase = "post_authenticate"      // 认证成功后、MFA 前
       PhasePreTokenIssuance     LoginPhase = "pre_token_issuance"     // Token 签发前（可修改 claims）
       PhasePostTokenIssuance    LoginPhase = "post_token_issuance"    // Token 签发后（仅通知）
       PhaseOnLoginFailed        LoginPhase = "on_login_failed"        // 认证失败时
   )

   // AuthHook is an extension point in the login pipeline.
   type AuthHook interface {
       Phase() LoginPhase
       // Execute runs the hook. For pre-hooks, returning an error aborts
       // the pipeline with that error (mapped to the right HTTP error code).
       Execute(ctx context.Context, in *HookInput) (*HookOutput, error)
   }
   ```

2. **Hook Registry** — 嵌入 `sso.Server` 的可注册钩子集合：
   - `WithAuthHook(...AuthHook)` 接受一个或多个钩子
   - 单期按注册顺序执行；多期支持 `priority` 排序 + `skip_on_error` 语义
   - `authHookExecutionDuration_seconds` 指标 + `auth_hook_{phase}_{name}` 审计事件
   - 每个钩子有独立超时（默认 5s，fail-OPEN 时超时不阻止流程继续）

3. **与现有 WASM 授权引擎的关系**：
   - WASM authz (`wasmauthz`) 是**授权**扩展点（决定"是否允许这个请求"）
   - Pipeline Hook 是**认证**扩展点（影响"如何认证这个用户"）
   - 两者正交：WASM 授权可在 PreTokenIssuance 阶段作为 AuthHook 运行

4. **SDK 迁移原则**：
   - 现有流水线**不迁移到 Hook 架构**——硬编码链保持默认路径
   - 新 `AuthHook` 接口是在默认链的**关键坐标点**注入切面，不重写现有代码
   - 零钩子注册时性能零开销（`if len(s.authHooks[phase]) == 0 { continue }`）

### 边界情况

| 边界 | 处理策略 |
|---|---|
| Hook 执行超时不响应 | 独立 goroutine + context timeout；超时后按 hook 的 `FailClosed` 属性决定继续或拒绝 |
| Hook 链路中断 | `PhasePreAuthenticate` 钩子返回错误 = 返回原始错误码（`invalid_request` / `access_denied` 等） |
| 钩子修改 claims 导致签名不一致 | Hook 在 PreTokenIssuance 阶段操作 `*HookOutput.Claims`（类型安全的 map），仅在该阶段可修改 |
| 第三方 WASM Hook 恶意消耗资源 | 与 wasmauthz 共用 `wazero` 运行时沙箱；每钩子 guests 内存上限（`WithWASMGuestMemory`） |
| 钩子状态泄漏跨请求 | HookInput 是每个请求新建的 `*HookInput`，不接受全局可变状态 |
| PreAuthenticate 钩子做用户查找 | 禁止修改`UserProvider` 结果——PreAuth 仅用于 IP 检查/请求变形，用户查找在 Authenticate 步骤自己完成 |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **高** — 这是成熟 IdP（Auth0 Actions、Okta Event Hooks、Azure AD Conditional Access Custom Controls）的标配功能；缺失它在采购"可定制性"评估中失分 |
| 技术复用 | **高** — 复用 `shared/core` 错误映射、`wasmauthz` 沙箱、现有 audit/metering 基础设施 |
| 工作量 | **L** — SPI 定义（S）+ Hook Registry（M）+ WASM 适配器（S）+ 测试（M）|
| 独立性 | 高 — 不改变任何现有流水线代码；纯加算 |
| 建议优先级 | **P1**（差异化能力强，中等投入） |

---

## 方向二：令牌与会话批量运维治理（Bulk Token & Session Lifecycle Governance）

### 类型

运维治理 / 批量管理 / SLA 监控

### 为什么需要

当前令牌/会话管理操作是**单记录级**：

| 操作 | 当前支持 | 上限 |
|---|---|---|
| 吊销令牌 | `POST /token/revoke`（单令牌） | 单条 |
| 吊销刷新族 | `DeleteFamily(familyID)` | 一族 |
| 吊销用户所有 session | `SessionManager.RevokeUser(ctx, userID)` | 单用户 |
| 列出用户的 session | `SessionManager.ListByUser(ctx, userID)` | 单用户 |
| Admin 吊销 | `/api/v1/admin/tokens/revoke` | 单条 refresh token |

但企业运维场景中，以下需求**当前无法满足**：

| 运维场景 | 期望 | 当前缺口 |
|---|---|---|
| 某 client_id 泄密需吊销该 client 的所有 token | `DELETE /api/v1/admin/tokens?client_id=leaked-app` | ❌ 不支持过滤 |
| 某租户需批量下线所有超过 90 天未活跃的 session | `DELETE /api/v1/admin/sessions?tenant_id=acme&max_last_active=90d` | ❌ 不支持批量过滤 |
| 某 IP 段被列为恶意，需吊销所有来自该 IP 的活跃 session | session 无 IP 属性的批量索引 | ❌ SessionRecord 不存储 IP |
| 需查询当前系统中所有即将过期的 session（Next N 天） | `GET /api/v1/admin/tokens/expiring?within=7d` | ❌ 无过期预查询 |
| 审计要求"展示 X 时间内吊销的所有令牌及吊销原因" | `GET /api/v1/admin/tokens/revoked?since=2026-06-01` | ❌ 无吊销日志查询 |
| SLA 要求 token 签发 P99 < 50ms | Prometheus 指标存在但**无 SLO 承诺 + 告警规则** | ❌ 无 SLO 框架 |

**当前代码缺口验证：**

| 检查项 | 结果 |
|---|---|
| `POST /api/v1/admin/tokens/bulk-revoke`（按 filter 批量） | ❌ 不存在 |
| `GET /api/v1/admin/tokens/expiring`（预过期查询） | ❌ 不存在 |
| `GET /api/v1/admin/sessions?ip=`（按 IP 查询/过滤） | ❌ SessionRecord 无 IP 字段 |
| `GET /api/v1/admin/tokens/revoked`（吊销历史查询） | ❌ 无 RevocationLogStore SPI |
| `platform/slo/` 包或框架 | ❌ 目录不存在；无 SLI/SLO 聚合框架 |

### Scope

1. **RevocationLogStore SPI** — `platform/audit/revocation_log.go`：
   - 新 SPI 记录每次吊销操作（token/session）：`{RevocationID, TokenID/SessionID, RevokedBy(adminID|system), Reason, RevokedAt, Filter(批量时), ClientIP}`
   - 支持 SQLite/Postgres/Redis 持久化
   - Admin API `GET /api/v1/admin/tokens/revoked` + 分页 + 日期范围 + 按 admin 过滤

2. **SessionRecord 扩展** — `SessionRecord` 加可选字段：
   - `ClientIP string` — 创建 session 时的客户端 IP
   - `LastActiveAt time.Time` — 最后活跃时间（现有 session 刷新路径已可在无额外 I/O 开销下更新）
   - `DeviceFingerprint string` — 设备指纹（可选）
   - 背景迁移：`ListByFilter(ctx, SessionFilter{TenantID, ClientID, UserID, IP, MaxLastActive, MinCreated})`

3. **批量吊销 API**：
   ```go
   POST /api/v1/admin/tokens/revoke-batch
   { "filter": {
       "tenant_id": "acme",
       "client_id": ["leaked-app", "compromised-service"],
       "max_last_active": "2026-06-01T00:00:00Z",
       "reason": "Security incident INC-2026-0711"
     },
     "confirm": true
   }
   ``` 
   - `DELETE /api/v1/admin/sessions` 同样参数模式
   - 大结果集通过后台 Job（`platform/lifecycle/batchjob` 暂不存在——可新建）异步执行
   - 审计事件 `admin_tokens_bulk_revoked`/`admin_sessions_bulk_terminated`

4. **SLO 框架（最小可行）**：
   - 定义 SLI 指标：`token_issuance_availability`、`token_verify_latency_p99`、`login_availability`
   - `WithSLO(window time.Duration, budget float64)` 配置可用性预算
   - SLO 状态在 `/readyz` 中暴露（SLO 违反 → `Ready=false`——可配置 `fail_open` 默认 false）
   - 配套 Prometheus `slo_*` 指标 + `slo_violations_total`

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 批量吊销涉及 100 万 + token | 后台 Job + chunked cursor（每次 1000）+ 可取消（`DELETE ... WHERE id IN (...) LIMIT 1000` 循环） |
| Commit/rollback 语义 | 批量操作是 best-effort 而非事务性——审计日志记录每个 chunk 的结果（成功数、失败数、第一错误） |
| 批量操作与并发的授权请求冲突 | Job 无锁——被删除 token 在并发请求中遇到时，由正常 token 验证路径自然拒绝（`ErrTokenRevoked`） |
| 管理员误操作 | `confirm: true` 是显式确认字段；操作前有 `POST .../tokens/revoke-batch/dry-run` 统计受影响的 token 数；操作后有 `POST .../tokens/revoke-batch/rollback`（仅恢复 `revoked_at` 标记——不是恢复 token 可用性） |
| SLO 准确率边界 | 28d rolling window，`availability = successful_requests / total_requests`；窗口内可配置 `min_data_points` 避免冷启动假告警 |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **高** — 企业安全运维的核心需求（incident response 场景）；SOC/IT 团队常常将"能否批量吊销 token"作为采购评估条目 |
| 技术复用 | **中** — 复用现有 `RevokeToken`/`RevokeSession` 底层操作 + `admin` 认证框架；需新建 `RevocationLogStore` |
| 工作量 | **XL** — RevocationLogStore（M）+ SessionRecord 扩展 + Filter（M）+ Batch API（L）+ 后台 Job 框架（M）+ SLO 框架（M）|
| 独立性 | 高 — 不破坏现有 token 验证/吊销路径 |
| 建议优先级 | **P2**（高价值但工程量较大，可分批交付：先做 RevocationLogStore + SessionRecord 扩展 → 再做 Batch API → 最后 SLO） |

---

## 方向三：用户通知基础设施（User Notification Infrastructure）

### 类型

用户通信 / 事件驱动通知

### 为什么需要

当前项目有**完整的审计事件系统**（`platform/audit` -> `audit.Recorder` -> `Event{Type, SubjectID, Metadata}`），
但**这些事件只有管理员消费路径**（admin API 查询、审计 Webhook、Sink 导出），完全没有
面向最终用户的转换路径：

| 场景 | 当前 | 期望 |
|---|---|---|
| 用户在新设备/新 IP 登录 | ✅ audit 记录 | 🔔 用户收到邮件/应用内通知"新设备登录" |
| 密码将在 7 天后过期 | ❌ 无密码过期机制 | 🔔 提前通知 "密码将在 7 天后过期，请修改" |
| MFA 因子被移除 | ✅ audit 记录 | 🔔 用户收到通知"MFA 因子被移除"（可能恶意的） |
| Consent 被授予/撤销 | ✅ audit 记录 | 🔔 用户收到通知"你对 XX 应用授权了 YY 权限" |
| 管理员更改了你的权限 | ✅ audit 记录 | 🔔 用户收到通知"你的角色已更新" |
| 账号被锁定 | ✅ `EventAccountLocked` | 🔔 用户收到通知"你的账号因多次登录失败已锁定" |
| 安全事件（威胁检测触发） | ✅ `EventAnomalyDetected` (admin 可见) | 🔔 用户收到通知"我们检测到可疑活动" |

**当前代码缺口验证（双重重核验）：**

| 检查项 | 结果 |
|---|---|
| `NotificationStore` SPI（ListBySubject/MarkRead/Create） | ❌ 不存在 |
| `NotificationSender` SPI（Send(event) → error） | ❌ 不存在（仅有用于密码重置的 `PasswordResetSender`，不是通用通知 SPI） |
| `GET /me/notifications` API | ❌ 不存在 |
| 应用内通知 UI 页面（`/me/notifications`） | ❌ 不存在 User Portal 中无此页面 |
| 通知模板引擎（`password_expiring` / `new_device_login` 等模板） | ❌ `emailsmtp/templates.go` 仅含密码重置和邮箱验证模板 |
| `infrastructure/push/` 或 `infrastructure/notification/` | ❌ 目录不存在 |
| 仓库中 `NotificationStore\|NotificationSender\|NotificationEvent\|user.*notif.*spi` 匹配 | ❌ 0 命中 |
| 已有分析文档覆盖 | ✅ `senior-architect-expansion-v3` 确认为零实现（见 v3 表 `notification.*store: 0`）但**从未作为独立方向提出** |

### Scope

1. **NotificationEvent 核心类型** — `shared/core/notification.go`：
   ```go
   type NotificationEvent struct {
       ID        string
       SubjectID string    // 目标用户
       TenantID  string
       Type      NotificationType  // password_expiring, new_device_login, mfa_removed, consent_granted, session_expiring, password_leaked, account_locked, security_event
       Title     string            // 模板渲染后的标题（空 = 需要渲染器处理）
       Body      string            // 同上
       Severity  NotificationSeverity // info / warning / critical
       Channel   NotificationChannel  // email / in_app / push（future: sms）
       CreatedAt time.Time
       ReadAt    *time.Time       // nil = 未读（仅 in_app 通道使用）
   }
   ```

2. **NotificationStore SPI** — `Create(ctx, event) error`、`ListBySubject(ctx, subjectID, since, limit) ([]NotificationEvent, error)`、
   `MarkRead(ctx, id) error`、`UnreadCount(ctx, subjectID) (int, error)`

3. **NotificationSender SPI** — 通道适配器接口：`Send(ctx, event) error`
   - `email.NotificationSender` — 复用现有 `emailsmtp.Sender`，新增通用通知模板
   - `inapp.NotificationSender` — 写入 `NotificationStore`，用户 Portal 拉取
   - Future: `push.NotificationSender` — 需要 `MobileDeviceStore` + FCM/APNs 集成

4. **事件→通知路由引擎** — 监听 `audit.Event` 中的用户相关事件：
   - 异步 goroutine（`srv.notificationRouter`），消费 `audit.Event` 通道
   - 事件类型 → 通知类型映射表（operator 可配置）
   - 按用户通知偏好（email / in_app / off）分发
   - fail-OPEN：通知失败不影响业务（`logger.Error` + `notifications_delivery_failed_total`）

5. **通知偏好 API + UI**：
   - `GET /me/notifications/preferences` — 各事件类型的通道偏好
   - `PUT /me/notifications/preferences` — 修改偏好
   - `GET /me/notifications` — 列出未读/历史通知
   - `POST /me/notifications/{id}/read` — 标记已读
   - User Portal（`/me`）新增通知面板（右上角铃铛图标 + 下拉列表）

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 通知风暴（同一事件短时间内触发 N 次） | 聚合冷却：同一 `{SubjectID, Type}` 在 5 分钟内只生成一条通知（合并计数器） |
| 用户选择 "全部关闭" | `NotificationPreference` 为空 = 不发送任何通知；此时事件→通知路由引擎直接跳过该用户 |
| 邮件发送失败 | fail-OPEN + 重试 3 次（指数退避）+ 邮件失败不阻塞应用内通知在同一事件上的发送 |
| 通知保留期限 | `NotificationStore` 实现自动清理 >90 天的已读通知（可配置） |
| 批量通知（如租户管理员批量操作影响 1000 用户） | 不每条发一条通知——用批量通知模板（"你的权限已被管理员更新"），必要时附带详情链接 |
| GDPR 擦除 | `EraseSubject` 必须同时清除该用户的 `NotificationStore` 记录 |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **高** — 用户通知是现代身份平台的标准功能；无此功能的平台在用户体验和安全性（用户自行注意可疑活动）上存在明显差距 |
| 技术复用 | **高** — 复用 `audit.Event`（数据源）、`emailsmtp`（邮件通道）、`User Portal`（UI 框架） |
| 工作量 | **L** — SPI + 核心类型（S）+ in-app 通知（M）+ 邮件通知（M）+ 事件路由（M）+ UI（M）|
| 独立性 | 高 — 不依赖任何其他方向 |
| 建议优先级 | **P1**（中低投入，高用户可见度，安全增益显著） |

---

## 方向四：跨协议会话桥接（Cross-Protocol Session Bridge）

### 类型

身份互操作性 / 会话一致性

### 为什么需要

当前项目支持多种认证协议：

| 协议 | 有无独立会话 | 会话是否与其他协议共享 |
|---|---|---|
| OAuth 2.0 / OIDC | ✅ `SessionManager` | 独立（OIDC session ≠ SAML session） |
| SAML 2.0 SSO | ✅ SAML `SessionIndex` | 独立（与 OIDC 会话无关） |
| SAML 2.0 IdP-Initiated SSO | ✅ SAML `SessionIndex` | 独立 |
| LDAP/Kerberos/RADIUS | ✅ 作为 Authenticator 的一部分 | 产生的 session 归入 OIDC Session |
| CIBA | ✅ CIBA `auth_req_id`+ session | 独立 |

核心问题：**一个用户通过 SAML 登录后，再用 OIDC 登录，产生两个完全独立的会话。
这两个会话之间没有关联关系，一个的结束不会影响另一个。**

| 场景 | 当前行为 | 期望行为 |
|---|---|---|
| 用户通过 SAML IdP 登录了 App A，再通过 OIDC 登录了 App B | 两个独立会话，各自过期 | ✅ 跨协议单点登出——SAML SLO 触发 OIDC session 终止（反之亦然） |
| 用户 SAML session 因密码变更在 IdP 端过期 | SAML session 失效，但 OIDC session 仍有效 | ✅ OIDC session 同步感知 SAML 会话状态变化 |
| 审计追踪：用户 U 通过 SAML 登录后多久通过 OIDC 做了什么 | 无法关联两个协议下的操作 | ✅ 会话桥接 ID 让跨协议审计可关联 |
| Admin 查询"用户 U 的所有活跃会话" | `SessionManager.ListByUser` 只返回 OIDC 侧 | ✅ 统一视图包含 SAML + OIDC 所有 session |

**当前代码缺口验证：**

| 检查项 | 结果 |
|---|---|
| `SessionBridge` 或 `LinkedSession` 实体 | ❌ 不存在 |
| 跨协议 Session 关联机制（`session_bridge_id` / `linked_session_id`） | ❌ 不存在 |
| SAML SLO 触发 OIDC `/end_session` | ❌ 不存在（SAML SLO `/saml/slo` 仅处理 SAML 侧登出） |
| OIDC BCL 触发 SAML Session 终止 | ❌ 不存在 |
| 跨协议 Session 统一查询 API | ❌ 不存在 |
| 仓库中 `cross.*protocol.*session\|session.*bridge\|protocol.*bridge\|SAML.*OIDC.*session\|oidc.*saml.*session\|bridge.*session\|session.*link.*protocol\|LinkSession\|LinkedSession` 匹配 | ❌ 0 命中 |
| 已有分析文档覆盖（grep 50+ 份文档） | ❌ `cross.*protocol.*session\|session.*bridge.*protocol\|protocol.*session.*bridge\|inter.*protocol.*logout\|saml.*oidc.*logout.*session` 在全部 50+ 份文档中 **0 命中** |

### Scope

1. **SessionBridge 核心实体** — `shared/core/session_bridge.go`：
   ```go
   type SessionBridge struct {
       BridgeID      string                // 统一桥接 ID（UUID v7）
       PrimarySessionID string             // 主协议 session ID
       PrimaryProtocol SessionProtocol     // "oidc" / "saml" / "ciba"
       LinkedSessions []LinkedSession      // 已关联的副协议 session
       CreatedAt     time.Time
       LastRefreshedAt time.Time
   }
   type LinkedSession struct {
       SessionID  string
       Protocol   SessionProtocol
       ExpiresAt  time.Time
   }
   ```

2. **关联建立点**：
   - 用户已完成 SAML `AuthnResponse` 验证后，再调用 OIDC `/auth/login` 时——检查是否存在该用户的 SAML `SessionBridge`，有则关联
   - 用户通过 SAML IdP-Initiated SSO 获得 session，然后访问 OAuth 资源时——在 `/token` 用 `SAMLResponse` 断言兑换 token 时自动关联
   - Admin 手动关联（`POST /api/v1/admin/sessions/{id1}/link/{id2}`）— 用于运维合并

3. **跨协议登出传播**：
   - SAML SLO handler（`/saml/slo`）在完成 SAML 侧登出后，查询 `SessionBridge`，如有关联的 OIDC session → 调用 `RevokeSession` + 通过 `cluster.Bus` 广播（`KindSessionRevoked`）
   - OIDC `/end_session` / Backchannel Logout 同样同步到 SAML 侧（调用 SAML SLO 端点或直接删除 SAML `SessionIndex`）
   - **防循环**：每 session 携带协议标记；OIDC → SAML 不再反向传播回 OIDC

4. **统一会话视图 API**：
   - `GET /api/v1/admin/sessions/unified?user_id=x` — 返回该用户在 OIDC + SAML + CIBA 下的所有 session，按 `SessionBridge` 分组
   - 用户面 `GET /me/sessions`（已有）可选扩展 `include_linked=true` 显示关联的 SAML session

### 边界情况

| 边界 | 处理策略 |
|---|---|
| SAML 和 OIDC session 的 TTL 不同 | 关联不试图使 TTL 一致——各协议独立过期；跨协议登出仅在显式登出事件时触发 |
| 用户从 SAML SP 发起 SLO，但 OIDC session 已过期 | `SessionManager.RevokeSession` 对已过期的 session 是安全无操作 |
| 通过非桥接路径建立的 session（如直接从 OIDC 登录的用户没有 SAML 侧） | 无 `SessionBridge` 时的行为字节等同于当下 |
| 大规模租户的跨协议关联开销 | `SessionBridge` 写入时间在 10ms 内；查询通过 `bridge_id` 主键或 `user_id` 索引 |
| 在 SAML IdP 侧吊销了 SAML session 后 | IdP SLO 通知 SAML SP → SAML SP handler 收到后必须触发 OIDC 侧吊销 |
| OIDC 侧已有 BCL 注销传播 | BCL 传播到下游 RP 后，也需反向解析 `SessionBridge` 以同步 SAML 侧 |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **中-高** — 对部署了 SAML+OIDC 双协议栈的企业特别有价值；单个协议部署场景价值较低 |
| 技术复用 | **高** — 复用 `SessionManager`、`RevokeSession`、`cluster.Bus`、SAML SLO handler、OIDC `/end_session` |
| 工作量 | **L** — SessionBridge 实体（S）+ 关联建立点（M）+ 跨协议登出（M）+ 统一视图 API（S）|
| 独立性 | 中 — 依赖于 SAML 子模块和 OIDC 模块都已存在（都已就绪） |
| 建议优先级 | **P2**（差异化强但市场广度有限；适合在已有 SAML+OIDC 双栈客户场景下优先交付） |

---

## 方向五：密码生命周期策略管理（Password Lifecycle Policy Engine）

### 类型

安全策略 / 合规管理

### 为什么需要

当前项目拥有完整的密码认证支持（`domains/authenticators/stored_password.go`）以及
密码健康检查（`defaultrisk/hibp_password_health_checker.go` 的 HIBP 泄露检测 +
`password_health_dictionary.go` 的弱口令字典），但**缺少完整的企业密码生命周期管理**：

| 策略维度 | 当前状态 | NIST SP 800-63B / 企业合规要求 |
|---|---|---|
| 密码过期轮换 | ❌ 不存在 | 许多框架要求 90/180 天强制轮换 |
| 密码历史（避免重复使用） | ❌ 不存在 | 不得重复使用最近 N 个密码（N 通常 5-24） |
| 密码复杂度策略 | ⚠️ 部分 | 仅 `PasswordPolicyValidator` 接口存在但**无引用实现** |
| 登录时强制改密（首次/重置后） | ❌ 不存在 | 首次登录 / 管理员重置密码后须强制用户改密 |
| 密码过期前通知 | ❌ 不存在 | 过期前 7/14 天提醒用户 |
| 密码强度评估面板 | ⚠️ 部分 | HIBP + 弱口令字典存在但无用户面展示 |
| 依角色/租户不同密码策略 | ❌ 不存在 | 不同安全等级的租户适用不同策略 |
| 密码年龄作为风险信号 | ❌ 不存在 | 老密码 = 高风险，影响信任评估 |

**当前代码缺口验证：**

| 检查项 | 结果 |
|---|---|
| `UserProvider.PasswordChangedAt(userID)` 或 `PasswordExpiresAt` 字段 | ❌ 不存在——`User` 实体无密码相关时间戳 |
| `PasswordHistoryStore` SPI（`RecordPasswordChange` / `RecentlyUsed`） | ❌ 不存在 |
| `PasswordComplexityValidator` 引用实现（minLen / upper+lower / digit / special） | ❌ 仅有接口 `PasswordPolicyValidator` 但**零引用实现** |
| `ForcePasswordChange` 标记 | ❌ User 实体无此标记 |
| 登录时检查 `password_expired` | ❌ `handleLogin` 从不检查密码年龄 |
| 仓库中 `password.*expir\|password.*history\|password.*reuse\|ForcePasswordChange\|PasswordExpiresAt\|password.*age\|password.*rotate` | ⚠️ 仅 `password_reset.go` 和 `passwords.go` 的相关注释中有"password expiry"关键词——但**全是文档注释/注释提及，无实现** |
| 已有分析文档覆盖 | ⚠️ `senior-architect-5-gaps` 提到 `PasswordHistory` SPI 和 `RecordPasswordChange` 但**作为其他方向的一部分**，从未作为独立方向 |

### Scope

1. **User 实体扩展** — 添加密码生命周期字段：
   ```go
   // 在 core.User 或 UserProvider 相关类型中
   type UserPasswordMeta struct {
       PasswordSetAt      time.Time   // 密码设置时间
       PasswordExpiresAt  time.Time   // 密码过期时间（零值 = 永不过期）
       ForcePasswordChange bool       // 下次登录是否需要强制改密
   }
   ```
   注意：`UserProvider.GetUser` 只返回核心字段。新增 `UserProvider.PasswordMeta(ctx, userID) (*UserPasswordMeta, error)` SPI
   方法（可选实现——`nil` 返回表示不支持密码生命周期）。

2. **PasswordHistoryStore SPI** — `domains/authenticators/password_history.go`：
   ```go
   type PasswordHistoryStore interface {
       RecordPasswordChange(ctx context.Context, userID string, passwordHash []byte) error
       RecentlyUsed(ctx context.Context, userID string, passwordHash []byte, historyCount int) (bool, error)
       RecentPasswords(ctx context.Context, userID string, historyCount int) ([][]byte, error)
   }
   ```
   Memory + SQLite 引用实现（最多保留 N 条历史，自动裁剪）。

3. **Password Policy Operator 配置**：
   ```yaml
   # config.yaml 新增段
   authenticators:
     password:
       enabled: true
       policy:
         min_length: 12
         min_lowercase: 1
         min_uppercase: 1
         min_digits: 1
         min_special: 1
         max_age: 90d              # 密码 90 天过期（0 = 不过期）
         history_count: 5          # 禁止使用最近 5 次密码（0 = 不检查历史）
         require_change_on_first_login: true
         require_change_on_reset: true
         notify_before_expiry: 14d  # 过期前 14 天开始通知
   ```

4. **登录路径密码生命周期检查**：
   - `handleLogin` 在验证密码成功后、Token 签发前检查：
     - `PasswordExpiresAt` 是否已过期？→ 返回 `password_expired` 错误 + 引导至改密页（非 `invalid_grant`，避免 oracle leak）
     - `ForcePasswordChange` 是否为 true？→ 返回 `password_change_required` 错误 + 引导
     - 密码即将过期（≤通知阈值）？→ Token 中嵌入 `password_expiring` claim + HTTP header `X-Password-Expiring: <days>`

5. **Admin API 密码管理**：
   - `GET /api/v1/admin/users/{id}/password-status` — 查看密码年龄、过期日、是否强制改密
   - `POST /api/v1/admin/users/{id}/expire-password` — 手动使密码过期（触发下次登录强制改密）
   - `POST /api/v1/admin/users/{id}/clear-force-change` — 清除强制改密标记（admin 覆盖）

6. **用户面改密流程增强**：
   - 当用户收到 `password_expired` 错误时，Hosted Login SPA 自动跳转至改密页
   - 改密时检查 `PasswordHistoryStore.RecentlyUsed` → 如返回 true 则拒绝（"你不能重复使用最近 5 次用过的密码"）
   - 改密成功后清除 `ForcePasswordChange` + 重置 `PasswordExpiresAt`
   - 登录时即将过期的提示 SPA 可选择展示横幅

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 密码过期但用户无改密入口（Hosted Login SPA 未配置） | Fallback：返回 `password_expired` 但允许一次"紧急登录"（仅限 `/me/password` 改密——其他操作被限制） |
| 密码历史存储 hash 对比 | `RecentlyUsed` 使用 `bcrypt.CompareHashAndPassword` 与历史 hash 比较——不存储明文 |
| 批量用户强制改密（Admin 一键要求部门全部改密） | Admin API `POST /api/v1/admin/users/bulk-expire-password`（支持 `tenant_id` + `user_id[]` 过滤），后台批量设置 `ForcePasswordChange=true` |
| 与 HIBP 检查的关系 | HIBP 是**被动检测**（检查密码是否已泄露），密码策略是**主动管理**（确保密码符合强度+有效期）——两者共存不冲突 |
| IdP 联邦用户的密码策略 | 联邦用户的密码由上游 IdP 管理——本端对于 `PasswordSetAt` 为零值的用户跳过所有密码生命周期检查（即不对 SAML/OIDC 联邦用户执行） |
| 并发改密竞争 | `RecordPasswordChange` + `SetPassword` 在同一事务中执行（SQLite/Postgres 的 `BEGIN IMMEDIATE`） |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **高** — 这是企业合规审计（SOC2、ISO 27001、PCI DSS、NIST SP 800-53）的最常见发现项之一；无此功能的企业在合规审查中会直接产生发现项 |
| 技术复用 | **高** — 复用 `PasswordPolicyValidator`（已有接口）、`stored_password.go`（认证）、`emailsmtp`（通知）、`UserProvider` |
| 工作量 | **M-L** — User 扩展 + SPI（M）+ PasswordHistoryStore（S）+ 策略配置（S）+ 登录检查（M）+ Admin API（M）|
| 独立性 | 高 — 不改变现有密码认证核心路径 |
| 建议优先级 | **P1**（合规刚需，中等投入，与方向三的通知基础设施可协同——密码过期通知复用 Notification Engine） |

---

## 综合优先级与工作量矩阵

| 方向 | 市场价值 | 技术复用 | 工作量 | 优先级 | 建议日程 | 与现有功能的关系 |
|---|---|---|---|---|---|---|
| ① 认证流水线中间件引擎 | 高 | 高 | L | **P1** | 第 1-2 月 | 纯加算，不影响现有流水线 |
| ② 令牌与会话批量运维治理 | 高 | 中 | XL | **P2** | 第 4-6 月 | 分批发：先做 SPI 再做 API 最后 SLO |
| ③ 用户通知基础设施 | 高 | 高 | L | **P1** | 第 1-2 月 | 与方向五密码过期通知可协同 |
| ④ 跨协议会话桥接 | 中-高 | 高 | L | **P2** | 第 3-4 月 | 依赖 SAML + OIDC 均已就绪 |
| ⑤ 密码生命周期策略管理 | 高 | 高 | M-L | **P1** | 第 2-3 月 | 与方向三通知基建有交集 |

### 一句话推荐

**先并行方向①（认证流水线——差异化能力）+ 方向③（通知基建——用户可见性，3-4 周）→
方向⑤（密码策略——合规刚需，4-6 周）→ 方向④（会话桥接，3-4 周）→ 方向②（批量治理，
分批交付，5-8 周）。**

---

## 附录：边界情况与性能优化速查

除五大方向外，以下为扫描中发现的**无需独立方向但有价值的优化点**：

### Token / Session 层面
- **SessionRecord 缺少 `CreatedIP` 和 `LastActiveIP`** — 导致无法按 IP 过滤 session、无法在用户安全时间线中展示 IP
- **无 `RevocationLogStore`** — 吊销操作无法追溯"谁在什么时候因为什么吊销了什么"
- **Token 签发无 P99 延迟 SLO** — Prometheus 指标已有但未聚合为可告警的 SLO

### 配置 / 部署层面
- **配置文件中 `password.policy` 段完全不存在** — 导致无法通过 YAML 一站式配置密码复杂度/过期/历史策略
- **`WithPasswordPolicyValidator` 有接口但零引用实现** — SDK 用户调用 `WithPasswordPolicyValidator(myValidator)` 需完全自实现
- **PostgreSQL 连接池无默认 max_conn / max_idle 配置** — 生产部署时 operator 需要自行查阅 pgx 文档补充这些参数

### 开发体验

- **`docs/examples/` 中没有完整展示所有 `With*` 选项的 all-in-one demo** — 现有 quickstart/basic 只覆盖核心 OAuth/OIDC 流程
- **没有标准的 `Makefile` target 做性能基准回归** — `go test -bench=.` 可运行但缺乏对比基线
- **TypeScript SDK 缺少 `error_description_localized` 的类型定义** — `i18n` 功能已实现但 TS SDK 中无对应字段

### 安全
- **`ForcePasswordChange` / `PasswordExpired` 登录拦截会产生新的区别路径** — 需确保 oracle-leak 加固（密码过期 vs 密码错误返回不同的错误码？参照 AGENTS.md §3 Anti-Enumeration 的 bcrypt 模式——应当返回同一 `invalid_credentials` 吗？不，`password_expired` 不是凭据错误，是策略状态——返回 `password_expired` 本身不构成 oracle leak，因为攻击者已经提供了正确密码）
