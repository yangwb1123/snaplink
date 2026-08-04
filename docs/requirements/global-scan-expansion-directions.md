# 全局扫描扩展方向分析

> **分析师：** 资深架构师 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 对全部代码库（2241 个 `.go` 文件、1114 个测试文件、14 个嵌套 `go.mod` 模块、60+ 协议实现、200+ 包）做系统性全局扫描。逐项阅读了：
> - 全部 `docs/requirements/` 下 30+ 份历史分析文档
> - `docs/deferred-backlog.md`（当前缺口中索引）
> - `docs/feature-matrix.md`、`AGENTS.md`、`DIRECTORY_MAP.md`、`ARCHITECTURE.md`
> - 全部 ADR 文档
> - 关键包的源码（`protocols/`、`domains/`、`shared/`、`platform/`、`interfaces/`）
>
> **定位声明：** 本项目的协议覆盖、安全纵深、后端实现、产品化和运维基建均已达到行业顶级水平。经过 30+ 轮扩展分析，**剩余的高价值方向已不再是补充更多标准协议或存储后端，而是补齐身份平台在**跨协议一致性、风险驱动自动化、分布式部署一致性、外部生态集成治理 **等交叉领域最后几项企业级能力。**

---

## 前置声明：项目成熟度评估

| 领域 | 关键能力 | 评估 |
|---|---|---|
| **协议面** | OAuth 2.0 × 7+ grants（含 PAR/JAR/JARM/RAR/DPoP/mTLS/PKCE/CIBA/Step-Up/Transaction Token/Token Exchange）、OIDC Core/Discovery/Logout/BCL/FCL/Form Post/Session Management/Silent Renewal/JWE、SAML 2.0 SP+IdP+SLO、SCIM 2.0 双向+Push Provisioning、CAEP/SSF 双向、FAPI 2.0、OpenID Federation 1.0、LDAP/Kerberos/RADIUS/WebAuthn/SPIFFE JWT-SVID/Workload Identity（GCP/AWS/Azure） | ✅ **全面** |
| **存储面** | Memory + SQLite（WAL+migrate）+ PostgreSQL + Redis（全热路径）+ etcd（cluster/registry/signingkeys）+ KMS×5 + SAML×4 + LDAP/Kerberos/RADIUS/ext_authz/Kafka/MQTT/Vault Transit | ✅ **全面** |
| **安全面** | Anti-enumeration（9 模式）、Oracle-leak（10 场景）、DPoP/mTLS/JKT/SPIFFE、Break-Glass（2人控制+impersonation）、Tenant-isolated signing、Data residency、FIPS 140-3、Account Lockout、Conditional Access、Anomaly Detection（4+ detectors + Threat Action engine）、Credential Health、Rate Limiting、CSP L3、Continuous Verification | ✅ **全面** |
| **产品面** | Hosted Login SPA、Admin Console SPA（全 CRUD）、Developer Portal SPA、User Portal（`/me` 全功能）、Consent Store（memory/sqlite/redis）、B2B Enterprise Connections + HRD、Org-admin Self-service、SDK 生成（TS+Python）、MCP Server、嵌入 API Docs Viewer | ✅ **全面** |
| **运维面** | DR Framework（snapshot/RPO/RTO/replication/recovery timing）、Config SIGHUP hot-reload（7 feature gates）、80+ Prometheus metrics + Grafana + 16 alert rules、Audit hash-chain（OCSF/CEF/Syslog/Webhook/Kafka sinks）、OpenTelemetry tracing、pprof、k6 load tests、Chaos tests ×4、Benchmark gate、K8s operator（SSOConfigDrift CRD）、Terraform、Helm、Bare-metal HA runbook | ✅ **全面** |
| **治理面** | SOC2 report generation、GDPR Art.15/17/20/30 compliance、Data retention sweeper、ReBAC engine、RBAC（wildcard + ConformanceSuite）、Session hub、Webhook engine（subscription + dead-letter）、User lifecycle state machine（invite→active→suspend→erase）、Change approval workflow、Token policies、Config audit + drift detection、Metering/Usage aggregation | ✅ **全面** |
| **质量基建** | Architecture layer import boundaries（hard gate）、File≤500/func≤50/cyclo≤15（hard gates）、Depth≤3/fanout≤15（hard gates）、500+ maintainability tests、14-module golangci-lint/govulncheck/gosec/CodeQL/Trivy/Dependabot、10+ fuzz tests、Race CI、Benchmark gate | ✅ **全面** |

---

## 方向一：安全信号闭环——内部威胁检测到 CAEP/RISC 事件的标准桥接

### Why Now

项目已具备业界领先的异常检测能力（`domains/anomaly`——impossible travel、credential stuffing、velocity burst；`domains/tokenanomaly`——token behavior anomaly）和威胁执行框架（`domains/threataction`——session suspension、family revocation、MFA step-up、admin notification）。同时，CAEP/SSF 发射器（`protocols/caep/broadcaster`）已能向受影响的 RP 推送标准的 SSF 安全事件令牌。

**核心缺口：这两套系统之间没有桥接。** 当前 CAEP event mapper（`protocols/caep/event_mapper.go`）只映射了 3 种审计事件（refresh reuse、tenant tokens revoked、admin token revoked），且明确注释 "deliberately conservative"。异常检测产生的 threat action 执行结果（如 session 被威胁执行器 suspend、token family 被 revoke）**不会通过 CAEP/SSF 通知任何 RP**。

| 场景 | 现状 | 影响 |
|---|---|---|
| Impossible travel 检测 → threat policy → session suspend | Suspended session 被记录到 audit，但 RP 不知情 | RP 继续接受该用户已过期的 access token，直到 refresh 失败 |
| Credential stuffing 检测 → threat policy → revoke refresh family | Family 被删除，用户下次 refresh 收到 `invalid_grant`，但 RP 的 session 仍标记为 active | RP 侧 session 管理不一致，安全响应延迟 |
| Step-up MFA 被威胁执行器触发 | MFA step-up 标记写入 session store，但 RP 未收到 `token-claims-change` | RP 无触发重新检查 session 的信号 |

**为什么这是高价值方向**

从安全运营的角度看，一个 IDP 最大的价值不仅是自己能检测威胁，还要能将标准化的风险信号推送给所有依赖方（RPs）。这是 NIST SP 800-63 持续评估和 OpenID RISC/CAEP 的核心设计目标。缺少这个桥接，项目的 ITDR（Identity Threat Detection & Response）能力只完成了检测和执行，没有完成**通知和协同**。

### Scope

| 子项 | 描述 | 关联文件 | 工作量 |
|---|---|---|---|
| **(a) CAEP Event Mapper 扩展** | 将 `anomaly_detected` audit event 映射为 `https://schemas.openid.net/secevent/risc/event-type/credential-compromise`（credential stuffing）、`https://schemas.openid.net/secevent/caep/event-type/session-revoked`（impossible travel）、`https://schemas.openid.net/secevent/caep/event-type/token-claims-change`（velocity burst） | `protocols/caep/event_mapper.go` → 新增 case + map 函数 | M |
| **(b) Threat Action → CAEP 反馈循环** | `domains/threataction/executor.go` 的 `SuspendSessionExecutor`、`RevokeFamilyExecutor`、`StepUpMFAExecutor` 执行成功后，通过依赖注入的 `CAEPBroadcaster` 发射对应 SSF SET | `domains/threataction/actions.go` → 增 `CAEPBroadcaster` 依赖 + Execute 成功后发射 | M |
| **(c) 多 subject 扇出支持** | 当前 event mapper 仅支持 single-client scope 和 tenant-wide scope；缺失 per-subject fan-out（一个用户被多个 RP 使用，需向所有相关 RP 推送）。新增 `scopeSubject` scope，基于 SubjectClientIndex（`shared/security/subject_client_index.go`）解决"哪个 RP 需要知道"的准确性问题 | `protocols/caep/event_mapper.go` + `protocols/caep/broadcaster.go` | L |
| **(d) RISC 事件类型常量补齐** | 补充完整 RISC 事件类型 URI 常量：`credential-compromise`、`account-credential-change-required`、`identifier-recycled`、`account-purged`、`session-revoked` | `protocols/caep/security_event_token.go` | S |
| **(e) 风险事件重试保证** | 当前 `broadcaster.go` 对传输失败只记录 `caep_broadcast_failed` 审计事件，不重试。新增指数退避重试 + deadline 超时，确保风险事件至少一次投递 | `protocols/caep/broadcaster.go` + `protocols/caep/broadcaster_retry.go`（已有骨架） | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| Threat action 失败（store 不可用）不应导致虚构的风险事件 | Execute 成功后才调用 Broadcaster；失败只记录 audit |
| 同一信号多次触发（flapping） | Broadcaster 层对相同 `(jti, subject, event_type)` 在 TTL 窗口内去重 |
| 批量场景（tenant suspension 触发所有用户的 CAEP 事件） | 使用 tenant-scope 扇出 + 批量 SET（RFC 8417 §3 支持一个 JWT 多个 events 字段） |

### 验证

```bash
# 当前 3 种映射
grep -c "case audit.Event" protocols/caep/event_mapper.go  # → 3

# 威胁执行器无 CAEP 依赖
grep "CAEP\|Broadcaster\|SetTransmit" domains/threataction/actions.go  # → 0 命中
```

---

## 方向二：跨协议身份传播与统一审计链

### Why Now

项目已支持 OAuth 2.0（含 token exchange 的 `act` 链）、SAML 2.0（IdP + SP）、SCIM 2.0（双向 + push provisioning）、LDAP/Kerberos/RADIUS 等多种身份协议。**但是，每个协议维护着独立的身份链，没有框架能在协议边界间传播原始调用者身份。**

| 真实场景 | 当前行为 | 缺口 |
|---|---|---|
| OAuth token exchange (3 hops) → SAML IdP assertion → downstream SP | SAML assertion 携带一个新的 NameID（映射自最后跳的 subject），无链接回原始 OAuth subject | 跨协议身份链断裂 |
| Token exchange (human → backend → API) → SCIM PATCH to downstream app | SCIM 操作使用最终 token 的 `sub`；`act` 链只在 OAuth 端可见 | SCIM 审计轨迹只能看到最终跳，无法追溯到原始用户 |
| 跨租户协作（OAuth → SAML） | 每个租户只看到自己的身份信息 | 跨租户操作无端到端问责 |
| AI agent 委派（human → agent → API → SAML） | `act` 链在 OAuth token 中可见，但 agent 调用非 OAuth API 时丢失 | Agent 操作无法审计回委派的 human |

这不是一个协议扩展——而是一个跨接每个已支持协议的**治理和审计基础设施**。没有它，"这个操作的原始请求者是谁"永远只能得到不完整的答案。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) PropagationContext SPI** | `shared/spi/propagation.go`：`PropagationContext` 携带 `OriginalSubject`、`OriginalTenant`、`ProtocolChain`（有序的 `{protocol, subject, issuer}` 列表）、`AuthMethod`、`AuthTime`。不可变、只追加。每个协议桥接点接收/传递该 context | 2 天 |
| **(b) OAuth→SAML 桥** | 扩展 SAML IdP assertion builder 接受 `PropagationContext`，将 `OriginalSubject` / `OriginalAuthMethod` 作为 SAML 属性（Attribute）盖到 assertion 中。通过 `sso.WithPropagationContextInjector` 注入 | 2 天 |
| **(c) OAuth→SCIM 桥** | 扩展 SCIM outbound provisioner 在出站 HTTP 请求中携带 `PropagationContext` 作为 `X-Original-Subject` / `X-Propagation-Chain` 头 | 1 天 |
| **(d) 跨租户传播** | 在跨租户协作 token exchange 中，将 home tenant 的身份盖到 guest tenant 签发 token 的 `PropagationContext` 中 | 2 天 |
| **(e) 审计链集成** | 扩展 `audit.Event` 增加 `OriginalActor` / `PropagationChain` 字段。在每次跨协议可审计操作上填充该字段。新增管理 API `GET /api/v1/admin/operations/:id/propagation-chain` 用于重建完整操作链 | 2 天 |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 下游系统不支持 propagation header | 作为可选字段，不影响主协议流程；下游忽略即可 |
| PropagationChain 过长 | 固定最大深度（默认 10），超出时截断并在 audit 中记录 `chain_truncated` |
| 敏感信息泄露（跨租户 propagation） | `PropagationContext` 中的 `OriginalSubject` 在跨租户场景中使用 pairwise subject（与 `pairwise.SubjectMapper` 配合） |
| 跨协议链的审计去重 | 以 `(trace_id, span_id)` 为唯一标识，同一条链产生的审计事件共享 propagation chain |

### 验证

```bash
# 当前 OAuth→SAML 传播
grep "Propagat\|OriginalSubject\|OriginalAuth" protocols/saml/ --include="*.go" | wc -l  # → 0

# 当前 SCIM 出站无 original identity
grep "original.*subject\|original.*actor\|propagat" protocols/scimprovision/ --include="*.go" | wc -l  # → 0

# audit 无 propagation 字段
grep "OriginalActor\|PropagationChain" platform/audit/ --include="*.go" | wc -l  # → 0
```

---

## 方向三：Token Exchange 链可视化管理与治理

### Why Now

项目完全支持 RFC 8693 token exchange 和 `act` 链传播，且实现了链深度限制（`MaxTokenExchangeChainDepth`）、链生命周期限制（`WithMaxTokenExchangeChainLifetime`）、hop 授权策略（`WithTokenExchangePolicy`）。然而，**运维人员没有任何工具可以查看、审计或管理这些链。**

| 能力 | 当前状态 | 证据 |
|---|---|---|
| act 链传播 | ✅ | `internal/handler/tokengrant/token_exchange.go` — `act` claim 自动传播 |
| 链深度限制 | ✅ | `MaxTokenExchangeChainDepth` — 默认 5，可配置 |
| 链生命周期限制 | ✅ | `WithMaxTokenExchangeChainLifetime` |
| Hop 授权策略 | ✅ | `domains/tokenexchange` — per-hop access policy |
| **链可视化** | ❌ | 全局 0 命中用于 chain visualization / graph |
| **链审计追溯** | ❌ | 全局 0 命中用于查看某条 token 的完整 delegation 链 |
| **按链撤销** | ❌ | 只能按 family 或 user 撤销，不能撤销整条 exchange 链 |
| **链分析/预警** | ❌ | 深链（>3 hops）无声无息，operator 只能从审计日志逐条分析 |

在 AI agent 委派和企业 B2B 协作场景中，token exchange 链可能快速变深（human → backend service → AI agent → third-party API → microservice）。运维人员需要回答这些问题：
- "当前系统中有多少 4+ hop 的 exchange 链？"
- "这个可疑 token 的完整委派路径是什么？"
- "谁最先发起了这条链？"
- "如何撤销某个特定跳之后的所有委派？"

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) Exchange Chain Store** | 一个新的 `ExchangeChainStore` SPI：每次 token exchange 记录一条 `ChainLink{ChainID, ParentLinkID, SubjectID, ClientID, IssuedAt, ExpiresAt, Scope, ActActor}`。支持 `ListByChainID`（遍历完整链）、`ListBySubject`、`ListDeepChains(depth)` | L |
| **(b) 管理 API** | `GET /api/v1/admin/token-exchanges/:id`（返回完整链）、`GET /api/v1/admin/token-exchanges?min_depth=3`（列举深链）、`DELETE /api/v1/admin/token-exchanges/:id/revoke-chain`（按链撤销所有关联 token） | M |
| **(c) Admin Console UI** | Token Exchange 链可视化页面：树形展示委派图，每个 hop 显示 subject/client/scope/timestamp。支持点击特定 hop 展开详情 | M |
| **(d) 链预警** | 当检测到异常深链（>配置阈值）或来自不可信 client 的 hop 时，产生 `admin_token_exchange_deep_chain` 审计事件 + webhook 通知 + Prometheus alert | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 链数据量过大（频繁 exchange） | `ExchangeChainStore` 只保留活跃 token 的链；已过期 token 的链由 data retention sweeper 清除。每个入口默认保留 7 天 |
| 链撤销的 TOCTOU | 撤销时标记 `ChainRevoked=true` 但不删除记录，新的 hop 必须检查 parent 链是否被撤销 |
| 匿名/无状态 chain（client_credentials 作为 first hop） | 允许 chain root 为 `client_credentials`，`SubjectID` 为 client_id，`ActActor` 为空 |

### 验证

```bash
grep -rn "ExchangeChain\|ChainLink\|ChainStore\|chain.*store\|chain.*list\|chain.*graph" --include="*.go" . | grep -v "_test.go" | wc -l  # → 0
```

---

## 方向四：Dynamic Client Registration 治理框架

### Why Now

DCR（RFC 7591/7592）已完整实现：client 注册、读取、更新、删除、client_secret 轮换、审批工作流、注册访问令牌。**然而，缺少企业级 DCR 治理的多个关键组件。**

以下是具体缺口及其影响：

| 缺口 | 当前状态 | 影响 |
|---|---|---|
| **Software Statement 验证** | RFC 7591 §2.3 定义的 `software_statement` 字段被解析但**从未验证签名/issuer**（`protocols/oauth/handle_register.go` 无相关代码）。JWT 格式的 software statement 可直接伪造 | 攻击者可伪造 software statement 声称来自可信软件商 |
| **Client Metadata Schema Policy** | 没有框架允许运营商定义 client 注册的 metadata 约束：`redirect_uris` 模式白名单、`grant_types` 允许列表、`token_endpoint_auth_method` 强制要求、`response_types` 约束 | 弱安全配置通过 DCR 注册，增加风险面 |
| **自动 Client Lifecycle 管理** | 没有"不活跃 client 自动禁用"机制。没有 client 元数据定期审计策略。client 注册后永远活跃，除非 admin 手动处理 | Client 膨胀：废弃的 client 占用安全策略资源 |
| **软件商管理** | 没有软件商（software provider）实体：不能将一组 client 归属到同一软件商、不能按软件商设置全局默认值或策略、不能跨软件商统计 | B2B SaaS 自助注册场景缺乏软件商标识管理 |
| **Client 注册域验证** | 对于需要验证 `client_uri` / `logo_uri` / `policy_uri` / `tos_uri` 归属的需求（如高安全等级 client），没有内置验证机制 | 攻击者可注册带恶意 URI 的 client |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) Software Statement 验证** | `SoftwareStatementValidator` SPI：接收 `software_statement`（JWT），验证其签名、`iss`、`exp`、`software_id`。内置实现支持 JWKS URI / 预配公钥。验证失败 → 拒绝注册（`invalid_client_metadata`）。通过 `WithSoftwareStatementValidator` 注入 | L |
| **(b) Client Metadata Policy Engine** | `ClientMetadataPolicy` 配置结构体：允许定义 `AllowedRedirectURIPatterns`（正则）、`RequiredAuthMethods`、`ForbiddenGrantTypes`、`MaxScopeCount`、`RequirePKCE`、`RequireJWKS`、`MinSecretLength` 等。注册时检查 → 不符合返回 `invalid_client_metadata` | M |
| **(c) Client Lifecycle Auto-Governance** | `ClientDormancySweeper`：定期扫描不活跃 client（基于 `last_used_at` 或 token 签发活动），超过 `DormantThreshold` 自动标记为 `Inactive=true`。支持 `DryRun` 模式。产生 `admin_client_auto_disabled` 审计事件 | M |
| **(d) Software Provider 模型** | `SoftwareProvider` 实体：`ID`、`Name`、`ContactEmail`、`DefaultMetadataPolicy`、`JWKSSet`（software statement 验证使用）。DCR 注册时携带 `software_id` 自动关联 | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| Software statement 验证失败但 `software_id` 不在白名单 | Fail-close：拒绝注册，返回 `invalid_client_metadata`，不泄露 issuer 信息 |
| 新 policy 覆盖已有 client | `ClientMetadataPolicy` 只适用于**新注册**；已有 client 不受影响（除非显式 migrate）。policy 变更记录到 config audit |
| 不活跃 client 自动禁用后又被使用 | 认证时检查 `Active=false` → 返回统一的 `invalid_client`。admin 手动 re-activate。不自动 re-activate（安全设计） |
| 软件商多 JWKS 轮换 | 支持 `SoftwareProvider.JWKSSet` 为 JWKS Set URI，定期缓存轮换（复用现有 `remote/jwks.go` 逻辑） |

### 验证

```bash
# software_statement 被解析但未验证
grep "software_statement\|SoftwareStatement" protocols/oauth/handle_register.go --include="*.go" | wc -l  # → 2 (解析体 + 字段映射)

# 无 client metadata policy 框架
grep "MetadataPolicy\|ClientMetadataPolicy\|client.*metadata.*policy" --include="*.go" . | grep -v "_test.go" | wc -l  # → 0

# 无 client 自动禁用
grep "auto.*disable\|auto.*inactive\|dormancy.*client\|client.*dormancy\|ClientDormancy\|auto.*deactivate" --include="*.go" . | grep -v "_test.go" | wc -l  # → 0

# 无 software provider 模型
grep "SoftwareProvider\|software.*provider\|software.*vendor" --include="*.go" . | grep -v "_test.go" | wc -l  # → 0
```

---

## 方向五：Multi-Region Active-Active 部署一致性框架

### Why Now

项目已具备企业级多区域部署的多个基础能力，但**缺少支持 active-active 多区域部署的关键一致性框架**。

| 已有能力 | 是什么 | 局限性 |
|---|---|---|
| **Data Residency**（`domains/region/`） | 用户/租户数据绑定到特定区域，跨区域访问被策略拒绝 | 只做隔离，不做跨区域访问优化 |
| **Cluster Bus**（`platform/cluster/bus.go`） | 跨副本令牌撤销/签名密钥轮换/client 变更广播 | 扇出模型，非主动同步 |
| **DR Framework**（`docs/dr-framework.md`） | Snapshot + 复制 + RPO/RTO 时间线 | 冷备/温备模型，非 active-active |
| **Snapshot/Restore**（`platform/releases/`） | 全状态快照 + 恢复 | 面向 DR，不面向实时一致性 |
| **Signing Key Per-Tenant Isolation** | 每个租户有独立签发密钥 | 密钥区域绑定未被表达 |

**缺失的能力矩阵：**

| 能力 | 缺失详情 | 影响 |
|---|---|---|
| **区域感知 Token 签发** | Token 不携带 `issuer_region` 信息。跨区域验证时无法判断 token 由哪个区域的 issuer 签发 | 跨区域 token 验证必须回源 |
| **无中心化协调的跨区域验证** | Token 验证需要到签发区域的 store 查询 revocation/consent 状态 | 延迟增加、可用性降低 |
| **区域间冲突解决** | 两个区域同时修改同一资源时无冲突检测机制 | 静默数据覆盖 |
| **延迟优化路由** | 认证请求总是到达任意区域，不对用户进行区域亲和性路由 | 不必要跨区域延迟 |
| **Region 级 Issuer Identifier** | 所有 token 共享同一 issuer URL | RP 无法区分 token 的签发区域 |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 区域感知 Token 签发** | `Issuer.Region` 字段：签发 token 时 stamp `iss` 为区域特定 URL（`https://eu.sso.example.com`），且将 region 信息作为 token claim（`region` / `issuer_region`）。discovery 文档的 `issuer` 返回全局 URL 但 `additional_issuers` 列出所有区域 | L |
| **(b) 跨区域 Token 验证协议** | 使用 `SignedIntrospection`（RFC 9701）或 `IntrospectionBatch` 实现跨区域 token 验证，无需回源。每个区域缓存其他区域的 JWKS 和 revocation 集 | L |
| **(c) 区域路由与亲和性** | OIDC Discovery 返回 `additional_issuers`（每个区域一个），login_hint 和 ui_locales 可用于路由提示。新增 `WithRegionAwareRouter` 将用户定向到最近的区域进行认证 | M |
| **(d) 乐观冲突检测** | 每个资源携带 `resource_version`（region ID + monotonic counter）。跨区域同步时检测版本冲突 → 产生 `admin_region_conflict` 审计事件，由 operator 介入 | M |
| **(e) 区域间 CAEP/SSF 桥** | 一个区域检测到的威胁通过 cross-region CAEP bridge 传播到所有区域，确保风险事件全局生效 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 区域故障时跨区域 fallback | 健康探测 + 自动路由到最近健康区域；`region_not_allowed` 策略仅在数据驻留约束下触发 |
| 区域间时钟偏差 > token exp 检查 | 使用 monotonic clock 比较 + `ClockSkew` 宽容窗口（复用现有 `dpop_clock_skew` 模式） |
| 区域间网络分区 | 每个区域独立运行（degraded），分区恢复后通过 conflict detection 修复不一致 |

### 验证

```bash
# Token issuance 无 region 感知
grep -rn "issuer_region\|region.*issuer\|additional_issuers" --include="*.go" . | grep -v "_test.go" | wc -l  # → 0

# 无区域路由
grep -rn "region.*route\|region.*affin\|region.*redir\|region.*discovery" --include="*.go" . | grep -v "_test.go" | wc -l  # → 0

# 无区域冲突检测
grep -rn "region.*conflict\|cross.*region.*conflict\|version.*conflict\|conflict.*detect" --include="*.go" . | grep -v "_test.go" | wc -l  # → 0
```

---

## 优先级建议

| 方向 | 价值 | 工作量 | 依赖 | 建议顺序 |
|---|---|---|---|---|
| 方向一：Threat→CAEP/RISC 桥接 | **极高**——补齐 ITDR 最后一公里，直接影响安全运营效果 | M-L（~5-7 天） | 无外部依赖，完全在项目内部完成 | **🥇 第一** |
| 方向二：跨协议身份传播 | **高**——直接解决多协议企业部署的核心审计/问责需求 | M（~4-6 天） | 需逐个协议桥接点改造 | **🥈 第二** |
| 方向三：Token Exchange 链治理 | **高**——AI agent 委派和企业 B2B 协作的核心可观测性需求 | M-L（~5-8 天） | 需要新的存储 SPI + 管理 API | **🥉 第三** |
| 方向四：DCR 治理框架 | **中-高**——B2B SaaS 自助注册的企业级治理需求 | M（~4-6 天） | 与现有 DCR 审批流程正交 | **第四** |
| 方向五：Active-Active 多区域 | **中**——全局低延迟和 HA 需求；但项目已有温备 DR 覆盖 | XL（~15-20 天） | 需跨多个组件改造 | **第五** |

---

## 总结

这五个方向代表了项目从"功能完整的身份平台"迈向"可直接以 SaaS 形态交付、满足最严格合规审计、具备原生多区域一致性、可被外部生态深度集成的企业级基础设施"所需的最后几项核心能力。每个方向都已在全代码库和全部 30+ 份历史分析中验证为**零实现或仅部分实现**，且每个方向都瞄准了行业成熟身份平台（Auth0/Okta/Azure AD）在企业市场中必须具备但极易被忽视的交叉领域能力。

**最优先推荐：方向一（Threat→CAEP/RISC 桥接）**——投入产出比最高，单独补齐后即可将项目的 ITDR 能力从"检测+响应"提升为"检测+响应+协同"，直接提升安全运营价值主张。
