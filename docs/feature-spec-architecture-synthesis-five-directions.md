# 架构综合分析报告：全球多活身份平台演进路径

> **作者：** 架构师 Agent  
> **日期：** 2026-07-11  
> **基于：** 65+ 份历史分析文档、全代码库扫描（2209 `.go` 源文件）、ROADMAP v5.0、DIRECTORY_MAP、AGENTS.md 门禁体系  
> **输出格式：** 架构级综合分析，可进一步拆分为具体 `docs/feature-spec-*.md` 供 Implement Agent 执行

---

## 1. 架构评估

### 1.1 当前架构的核心优势

经过 50+ 轮系统分析迭代，本项目已达到身份平台领域的顶级架构成熟度。

| 优势维度 | 具体表现 | 支撑证据 |
|----------|----------|----------|
| **物理分层** | 六层严格分层（`shared/ → platform/ → domains/ → protocols/ → interfaces/ → infrastructure/`），依赖方向单向朝下 | `architecture_layer_test.go` 自动化门禁，`layerExemptions` 缩容不扩容 |
| **SPI 驱动** | 每个横切关注点 = interface + `memory` impl ± 持久化 peer（SQLite/PostgreSQL/Redis/etcd） | 65+ Store SPI；无 mocks，所有测试使用 Memory* 实现 |
| **协议覆盖面** | OAuth 2.0（7 grant）、OIDC Core/Discovery/Logout/BCL/FCL/CIBA、SAML 2.0 SP+IdP+SLO、SCIM 2.0 双向、CAEP/SSF 双向、FAPI 2.0、OpenID Federation 1.0、WebAuthn | [feature-matrix.md](docs/feature-matrix.md) 80+ 行 |
| **安全纵深** | Oracle-leak 防护、Anti-enumeration、DPoP、mTLS、JWT-SVID、Workload Identity、Break-Glass、Per-tenant 签名隔离、FIPS 140-3 | AGENTS.md §3 全局约束 |
| **异步架构** | 审计、令牌遥测、异常检测均 off-path fail-open | `anomaly/`、`audit/`、`tokenusage/` 的 Offer+drain 模式 |
| **无外部 SaaS 依赖** | 纯 Go 构建，零 CGO；所有后端可选（内存/SQLite/Redis/etcd/PostgreSQL/KMS×5） | `go.sum` 无外部 SaaS SDK |
| **维护性门禁** | 文件 ≤ 500 行、函数 ≤ 50 行、循环复杂度 ≤ 15、目录深度 ≤ 3 | `maintainability_*_test.go`、`maxdepth_test.go`、`directory_fanout_test.go` |
| **多集群运营** | K8s Operator、Helm chart、DR framework、config hot-reload、metrics/tracing/audit 全覆盖 | `cmd/sso-operator/`、`ops/deploy/` |

### 1.2 当前架构的局限性

局限性不来自设计缺陷，而来自演进阶段的天花板——从"协议完备的 SDK"向"全球多活身份平台"演进中遇到的架构瓶颈：

#### 1.2.1 存储层无拓扑感知（阻塞全球部署）

**问题：** 所有 Store SPI 方法签名中无 `region` / `consistency` 参数。跨 region 部署要么共享同一数据库（违反复原隔离要求），要么数据完全不互通。

```
// 当前所有 SPI 签名——无一致性参数
type SessionStore interface {
    Create(ctx context.Context, session *Session) error
    FindByID(ctx context.Context, id string) (*Session, error)
    // ... 无 ReadConsistency 参数
}
```

**影响规模：** ~12 个 Store SPI，65+ 个实现，遍布 12 个子模块。

**根因：** 项目演进从"单体 SDK"起步，多 region 是后置需求。当前 ROADMAP v5 §④ 聚焦于总线健壮性和签名密钥协调，未触及数据复制。

#### 1.2.2 外部依赖缺乏弹性隔离（可导致级联故障）

**问题：** 所有外部依赖（KMS、SAML IdP、CAEP webhook、Federation fetch、SMTP）共享同一 goroutine 池和 HTTP 连接池。一个慢 KMS（5rps 限频 + 重试风暴）可耗尽所有 goroutine，导致正常 `/token` 请求排队超时。

**影响规模：** 5+ 条外部依赖路径，均无熔断器/舱壁保护。

**根因：** 早期架构未预期到 KMS/外部 IdP 会成为生产瓶颈（嵌入式部署无此问题）。

#### 1.2.3 客户端注册/管理端点限流缺失（安全攻击面）

**问题：** `DCR（/register）`、Admin API（gRPC）部分端点、`/.well-known/`、`/me/*`、`/userinfo`、`/end_session` 等端点无速率限制。

```
端点                     现有限流状态
POST /register             ❌ 无
PUT /register/{id}         ❌ 无
/admin/* (gRPC)            ❓ 独立令牌桶，不与 PolicyStore 联动
/me/*                      ❌ 无
/.well-known/*             ❌ 无
/end_session               ❓ 模糊
```

**影响：** DCR 端点无保护是直接攻击面——攻击者可无限制注册客户端，消耗存储资源和审计容量。

#### 1.2.4 管理操作缺乏结构化变更日志（合规缺口）

**问题：** 审计事件记录了"发生了管理操作"但缺少结构化 `(who, what, before, after, resource_type, resource_id)` 字段。无法回答合规审计问题：

- "谁在何时修改了 client X 的 redirect_uris？"
- "client X 24 小时前的配置是什么？"
- "谁批准了管理员 Y 的变更请求？"

不影响运行时正确性，但阻塞 SOC2/SOX/HIPAA/PCI DSS 合规审计。

#### 1.2.5 令牌生命周期不可追溯（审计复杂性）

**问题：** 审计事件不记录令牌 `jti`，token exchange 的 `act` 链仅在 JWT claim 中——令牌过期后丢失全部链信息。无法回答：

- "令牌 T 是用哪个授权码换来的？"
- "令牌 T 通过 token exchange 衍生出哪些下游令牌？"
- "用户 U 在 6 月授权了哪些客户端、获取了哪些令牌？"

不影响运行时，但增加合规查询成本。

### 1.3 架构债务评估

| 债务类型 | 严重程度 | 影响范围 | 备注 |
|----------|---------|----------|------|
| SQLite ClientStore 字段丢失 | **高** | SQLite 用户 | JWKS/AllowedResources/JAR 字段重启归零——静默安全降级；ROADMAP v5 §④f 已识别 |
| 跨副本 deny-set 仅内存 | **高** | 所有 issuer | 滚动重启期被撤销的 access token 可能复活 |
| etcd watch/lease 死亡不自愈 | **中** | etcd 总线用户 | 分区后副本永久失去跨副本撤销能力，`/readyz` 仍绿 |
| 根目录文件接近上限 | **中** | 根目录 | 当前 13 个非豁免文件；上限 15 个 |
| `Domain.Branding` 数据死存储 | **中** | `tenant/` | `Branding` 已存储但仅 `/branding` 端点消费——无 SPA 渲染器使用品牌色/Logo |

**整体判断：** 架构债务存在但可控。所有债务都有明确门禁或 ROADMAP 项跟踪，无"不可见"债务。新功能开发时必须注意不堆入已有大文件（遵守 AGENTS.md §0.1 代码预算）。

---

## 2. 扩展方向分析

基于对现有代码库、ROADMAP v5.0、65+ 份历史分析、以及上述架构局限性的综合分析，我提出以下 **5 个高价值扩展方向**，按"如果只能挑一件先做"的优先级排序。

### 方向一：多区域主动-主动复制（P0 — 架构级）

#### 2.1.1 为什么需要

| 维度 | 说明 |
|------|------|
| **合规驱动** | GDPR、金融监管要求数据驻留在指定区域——当前 `WithTenantResidencyCheck` 只检查写入时是否允许，不提供跨区域数据复制 |
| **全球延迟** | 用户在 region A 登录后，`/token` 请求如果跨 region 处理，B 区域的用户面临 200ms+ 跨洋延迟 |
| **高可用 SLA** | 单 region 故障（如 AWS us-east-1 宕机）导致全球 SSO 不可用——无跨 region 故障转移能力 |
| **商业价值** | 全球多活是企业级 SSO 的标配能力；Okta/Auth0/Azure AD 均以此为核心卖点 |

#### 2.1.2 核心挑战

| 挑战 | 难度 | 说明 |
|------|------|------|
| **存储层 SPI 无拓扑感知** | **高** | 现有 12+ Store SPI 无 `region`/`consistency` 参数——改 SPI 是核爆炸级变更（65+ 实现） |
| **写转发协议** | **中** | follower 收到写请求时需通过 gRPC 转发到 leader，等确认后回复——现有处理器需透传 |
| **读一致性语义** | **中** | 不同 endpoint 需要不同一致性级别：`/token` 需 leader 读（防 replay 漏检），`/userinfo` 可 local 读 |
| **冲突检测** | **中** | 跨 region 同用户并发操作（如两个管理员同时修改同一 client 配置）需要 LWW（Last-Writer-Wins）或版本向量 |
| **性能影响** | **中** | follower 转发路径增加一次 gRPC RTT（同区域 ~1-5ms，跨区域 50-200ms） |

#### 2.1.3 关键设计决策

**决策 1：Store 包裹器模式（推荐）**——而非 SPI 扩展

```
// 新的一致性子包裹（装饰器模式）
type ConsistentSessionStore struct {
    inner     core.SessionStore
    bus       cluster.Bus
    topology  *ReplicationTopology
}

func (s *ConsistentSessionStore) FindByID(ctx, sid string) (*Session, error) {
    if s.topology.ConsistencyFor(ctx) == LeaderRead && !s.topology.IsLeader() {
        return s.forwardToLeader(ctx, "FindByID", sid)  // gRPC inter-region
    }
    return s.inner.FindByID(ctx, sid)
}
```

| 方案 | 优点 | 缺点 |
|------|------|------|
| **A：包裹器模式** | 零改动现有 SPI；单 region 部署短路为零开销；可逐步引入（先包裹 SessionStore + AuthCodeStore） | 转发路径多一层间接；需写 ~12 个包裹器 |
| **B：SPI 扩展模式** | 类型安全，调用方明确知道自己要的一致性级别 | 接口膨胀；65+ 实现需加空方法——核爆炸级变更 |

**推荐 A**。理由：AGENTS.md §0.6（不改 SPI）是本项目铁律。

**决策 2：ReplicationTopology 作为 `sso.With*` 选项**

```go
// 新选项——默认 nil = 单 region = 零开销
type ReplicationTopology struct {
    LocalRegion    RegionID
    PeerRegions    []PeerRegion  // 远端 region 地址 + 角色
    ConsistencyFor func(ctx) ReadConsistency  // 可选，按端点定制
}

// 接线
sso.New(
    sso.WithReplicationTopology(topology),  // nil = 当前行为
    // ... 其他选项 ...
)
```

**决策 3：一致性策略矩阵**

| Endpoint | 默认一致性 | 理由 |
|----------|-----------|------|
| `/token`（grant_type=authorization_code） | **LeaderRead** | 防 auth code 重复消费 |
| `/token`（grant_type=refresh_token） | **LeaderRead** | 防 refresh 家族轮换竞态 |
| `/token/revoke` | **LeaderRead** | 立即生效 |
| `/userinfo` | **LocalRead** | 最终一致性可接受 |
| `/auth/login`（session 创建） | **LocalWrite + AsyncReplicate** | 写本地立即返回，异步复制 |
| Admin 写操作 | **LeaderWrite** | 避免冲突 |

#### 2.1.4 对现有系统的影响

| 影响 | 程度 |
|------|------|
| 新增包 | `platform/cluster/topology/`——`ReplicationTopology` + `ReadConsistency` 枚举 |
| 新增选项 | `sso.WithReplicationTopology(ReplicationTopology)` |
| 新增文件 | ~12 个 `consistent_*_store.go` 包裹器（每个核心 Store SPI 一个） |
| 新增依赖 | inter-region gRPC 连接（复用现有 `grpcserver`） |
| 向后兼容 | **完全二进制兼容**——单 region 用户不加选项即当前行为 |
| ROADMAP 触发 | 与 ROADMAP v5 §④（多副本数据面韧性）互补——可并行推进 |

#### 2.1.5 不做之事

- 不要引入 Kafka/CDC 管道——PostgreSQL 流复制 + 应用层 ReplicaRole 已足够
- 不要做真实多 region e2e 测试——用 `gRPC loopback + simulated latency` 模拟
- 初始版本不要支持 >2 region——先验证双 region 写转发 + 读一致性

---

### 方向二：外部依赖韧性工程——熔断器 & 舱壁（P1 — 架构韧性）

#### 2.2.1 为什么需要

一个慢 KMS（AWS KMS 限频 5rps + 持续重试）可通过共享 goroutine 池拖垮整个 SSO 服务器。当前架构脆弱点：

```
                      ┌──────────────────────┐
   请求                │     SSO Server       │
   ────────────────►   │                      │
                       │  goroutine pool ─────┼──► KMS（限频 → hang）
                       │                      │
                       │  HTTP conn pool ─────┼──► SAML IdP（下线 → 30s timeout）
                       │                      │
                       │  etcd watch ─────────┼──► 分区后不愈合
                       └──────────────────────┘
```

这不仅是性能问题——**这是生产可用性的必要条件**。无熔断器/舱壁保护，一个第三方依赖的偶然慢速可将整个平台拉低。

#### 2.2.2 核心挑战与设计

**设计：`platform/resilience/` 新包**

熔断器和舱壁作为通用横切关注点，放在 `platform/` 层（与 `cluster/`、`metrics/`、`tracing/` 平级）。

```
platform/resilience/
├── circuitbreaker.go        # CircuitBreaker SPI + 滑动窗口实现
├── circuitbreaker_test.go   # 集成测试
├── bulkhead.go              # Bulkhead SPI + 有界信号量实现
├── bulkhead_test.go
├── metrics.go               # Prometheus metrics 注册
└── doc.go                   # 包文档
```

**为什么不自建而是使用第三方？**

| 方案 | 评估 |
|------|------|
| **hystrix-go** | 已归档（2018 年最后提交），Netflix 已弃用 Hystrix |
| **resilience4j-go** | 非官方移植，Go 生态不成熟，审计成本高 |
| **sony/gobreaker** | 只有熔断器无舱壁，接口不够通用 |
| **自建** | ~100 行滑动窗口 + ~80 行信号量 = 总 ~200 行核心逻辑，零外部依赖，完全可控 |

**推荐：自建。** 需求极轻量，不值得引入外部依赖。

**熔断器 SPI 设计：**

```go
// CircuitBreaker 是熔断器 SPI。
// FAIL-OPEN：如果底层统计不可用（计数器溢出），breaker 默认关闭（允许请求通过）。
type CircuitBreaker interface {
    Name() string
    State() State
    Execute(ctx, func(ctx) error) error
    Metrics() CircuitBreakerMetrics
}

// 滑动窗口熔断器配置（基于 Google SRE 通用模式）
type Config struct {
    Duration             time.Duration // 默认 60s
    MinRequestCount      uint64        // 默认 5
    FailureRateThreshold float64       // 默认 0.5（50%）
    OpenDuration         time.Duration // 默认 30s
    HalfOpenMaxRequests  int           // 默认 1
}
```

#### 2.2.3 接线策略（fail-open / fail-closed 矩阵）

| 接线目标 | 优先级 | 熔断配置 | 熔断时行为 | 理由 |
|----------|--------|---------|-----------|------|
| KMS 签名 | P1 | 5req/60s/50%→开 120s | **fail-closed** → 503 | 降级到本地签名可接受，但绝不能静默弱化密钥 |
| SAML IdP fetch | P1 | 10req/60s/50% | **fail-open** → `invalid_grant` | SAML 断言失败应表现为凭证错误，非 500 |
| CAEP webhook push | P1 | 20req/60s/30% | **fail-open** → 日志+丢事件 | CAEP 推送可丢 |
| Federation fetch | P2 | 10req/60s/50% | **fail-open** → nil 元数据 | 无 federation 元数据不影响签名 |
| SMTP 邮件 | P2 | 10req/60s/30% | **fail-open** → 日志+降级 | 邮件可延迟 |
| etcd watch | P2 | 不适用（已有 backoff） | — | etcd client 已有重连逻辑 |

#### 2.2.4 注意：与 Service Mesh 的关系

| 维度 | 应用层熔断器 | Service Mesh（Istio/Linkerd） |
|------|-------------|------------------------------|
| 粒度 | 按 KMS/SAML/CAEP 等逻辑依赖 | 按 HTTP/gRPC 目标服务 |
| 语义感知 | 业务语义（KMS 限频 vs KMS 不可用） | 仅 HTTP 状态码 |
| fallback | 可按路径 fail-open/closed | 通常统一 503 |

**两者互补，不冲突。** 应用层熔断器处理"业务语义的故障"，Service Mesh 处理"连接故障"。

---

### 方向三：管理操作不可变审计追踪 + 令牌链式溯源（P1 — 合规 & 可观测）

#### 2.3.1 为什么需要

**合规驱动：** SOC2、SOX、HIPAA、PCI DSS 均要求"对配置变更的完整审计追踪，包含变更前和变更后的值"。当前审计事件记录了"发生了管理操作"但缺少结构化 `(before, after)` 字段。

**运营驱动：** 生产事故发生时，运维人员需要快速回答"谁在何时修改了什么"。没有结构化变更日志，只能从零散的应用日志和 Git 历史中拼凑。

**整合决策：** 将管理操作审计（方向四）和令牌溯源（方向五）合并为一个方向，因为两者共享相同的底层基础设施——`audit.Store` 的事件模型 + 结构化查询。

#### 2.3.2 架构设计

**变更日志 SPI：**

```go
// ChangeLogStore SPI——记录可审计的配置变更
// 独立于 audit.Sink（audit 是事件流，ChangeLogStore 是结构化变更历史）
type ChangeLogStore interface {
    RecordChange(ctx, *ChangeEntry) error
    ListChanges(ctx, ChangeFilter) ([]ChangeEntry, error)
    GetChange(ctx, id string) (*ChangeEntry, error)
}

type ChangeEntry struct {
    ID           string    `json:"id"`
    Timestamp    time.Time `json:"timestamp"`
    ActorID      string    `json:"actor_id"`      // 管理员 userID 或 "system/scim"
    ActorIP      string    `json:"actor_ip"`       // 可选
    Action       string    `json:"action"`          // create/update/delete/approve/revoke
    ResourceType string    `json:"resource_type"`   // "client", "tenant", "user", "policy"
    ResourceID   string    `json:"resource_id"`
    Before       *json.RawMessage `json:"before"`   // 变更前快照（PII 脱敏后）
    After        *json.RawMessage `json:"after"`    // 变更后快照
    SessionID    string    `json:"session_id"`
    TraceID      string    `json:"trace_id"`
    ApprovedBy   string    `json:"approved_by,omitempty"` // 需审批操作时的审批人
}
```

**令牌链式溯源：** 利用审计事件 + 运行时索引，不新增持久化存储。

```
Token Mint ──→ recorder.Offer(TokenEvent{Minted, jti, subject, client_id, ...})
                    ↓
              async drain ──→ audit.Store（现有）
                    ↓
              TokenFamilyIndex（按 jti 建立父子关系——仅内存映射）
```

查询时从 `audit.Store` + `TokenFamilyIndex` 重建令牌族谱 DAG。

#### 2.3.3 存储后端策略

| 数据 | 存储位置 | 理由 |
|------|---------|------|
| ChangeEntry | 独立 SQLite/PostgreSQL 表 `change_log` | 独立于 audit 事件流，保留期 7 年（HIPAA） |
| TokenFamilyIndex | 内存 + 启动时从审计事件重建 | 不增加热路径持久化；重启丢失可重建 |

#### 2.3.4 Admin Console 集成

- 每个资源详情页增加"变更历史"选项卡
- 渲染 Before/After JSON diff（使用 `r3labs/diff` 或逐字段对比）
- 支持按时间、操作者、操作类型过滤

#### 2.3.5 边界情况

| 边界 | 策略 |
|------|------|
| Before 与 After 之间的并发修改 | 使用乐观锁（`resource_version`）验证 |
| 批量操作（如删除 500 用户） | 每条变更记录作为独立 ChangeEntry；支持 `BulkRecordChanges` |
| PII 在 Before/After 中 | 可选地脱敏 `password_hash`、`secret`、`email` 等字段 |
| 变更日志自身被篡改 | 利用 `audit` 的 hash chain 技术链接变更日志条目 |
| SCIM 触发的变更 | ActorID = `system/scim:{provider}` |

---

### 方向四：多租户自定义域名生命周期管理 + 统一通知通道基础设施（P1 — 产品成熟度）

#### 2.4.1 为什么需要

**自定义域名**是企业级 SaaS 的门槛条件——企业客户要求 `login.acmecorp.com` 而非 `login.snaplink.com/acme`。当前 `Domain.Branding` 已存储但**从未被任何 SPA 渲染器消费**——这是明确的产品债务。

**统一通知通道**是身份平台的核心职责——密码重置、邮箱验证、账户恢复、MFA 挑战、异常登录告警。当前邮件模板编译时嵌入，无法租户定制，无 SMS 通道，无用户偏好。

#### 2.4.2 架构设计

**自定义域名 + TLS（需新包 `domains/domainverification/`）：**

```
domains/domainverification/
├── verifier.go         # DomainVerifier SPI
├── memory.go           # MemoryVerifier（测试用）
├── dns.go              # DNSVerifier（TXT record / CNAME）
├── acme.go             # ACMEProvisioner SPI + Let's Encrypt 实现
└── types.go            # VerificationStatus 枚举 + DomainCert 结构体
```

```go
// DomainVerifier SPI——验证租户声称的域名是否归其所有
type DomainVerifier interface {
    // Verify 触发域名所有权验证，返回 VerificationResult
    Verify(ctx, hostname, tenantID string) (*VerificationResult, error)
    // Status 查询当前验证状态
    Status(ctx, hostname string) (VerificationStatus, error)
}

// ACMEProvisioner SPI——自动签发和续期 TLS 证书
type ACMEProvisioner interface {
    Provision(ctx, hostname string) (*DomainCert, error)  // 签发
    Renew(ctx, hostname string) (*DomainCert, error)      // 续期
    Revoke(ctx, hostname string) error                     // 吊销
}

// 接线：sso.WithCustomDomain(verifier, acmeProvisioner)
```

**统一通知通道（需新包 `domains/notifications/`）：**

```
domains/notifications/
├── channel.go          # Channel SPI（Send(ctx, *Message) -> (deliveryID, error)）
├── email.go            # EmailChannel（适配现有 emailsmtp）
├── sms.go              # SMSChannel（Twilio / SNS）
├── push.go             # PushChannel（FCM / APNS，适配现有 push_mfa_provider）
├── webhook.go          # WebhookChannel（通用 webhook）
├── service.go          # NotificationService（通道选择 + 路由 + 降级）
├── preference.go       # 用户偏好存储
└── template.go         # 租户模板管理
```

**关于方向合并的决策推理：**

自定义域名和通知通道分属不同域（域名管理 vs 通知基建），但共享两个特征：
1. 均依赖 `Domain.Branding` 数据——域名验证成功后，品牌信息应用于通知模板和 SPA
2. 均为"产品成熟度"方向，投入产出节奏相似（先做 SPI + 基础实现，后接 SPA/管理面集成）

**建议做为一个 Sprint 组并行推进，而非合并为单一方向。**

#### 2.4.3 与现有系统的关系

| 现有组件 | 自定义域名影响 | 通知通道影响 |
|----------|--------------|-------------|
| `tenant.Store`（GetDomain/ListDomains） | 扩展验证状态字段 | 无影响 |
| `emailsmtp` | 无影响 | 适配为 `EmailChannel` |
| `push_mfa_provider.go` | 无影响 | 适配为 `PushChannel` |
| `domains/i18n` | 无影响 | 模板多语言化基础 |
| `/branding` 端点 | 扩展返回域名+品牌+TLS 状态 | 无影响 |

---

### 方向五：并发会话配额与生命周期治理 + 用户会话自助管理（P2 — 安全 & 合规基线）

#### 2.5.1 为什么需要

- **NIST SP 800-63B / PCI DSS / SOC2** 要求"限制并发会话数量"
- **凭证泄露缓解**：限制攻击者使用泄露凭证的访问窗口
- **SaaS 商业模型**：按"活跃用户数"定价需要区分"一个用户 20 个设备"和"20 个用户"
- **用户自助**：当前无 `GET /me/sessions` 或 `DELETE /me/sessions/:id` 端点

#### 2.5.2 核心设计

**会话配额策略层级：** 全局默认（无限 / 配置值）→ 租户覆盖 → 用户覆盖

```go
// 在 domains/tenant/ 或现有 policy 包中扩展
type SessionPolicy struct {
    MaxActiveSessions int  // < 1 = 无限制
    EvictionStrategy  string  // "deny_new"（拒绝新会话）或 "lru"（驱逐最旧）
}
```

**配额检查注入点：** `server_finish_login.go` 的会话创建路径中插入 `checkSessionQuota()` 守卫。

**LRU 驱逐引擎：** 使用 `sessionhub` 查询目标用户的所有活跃会话，按 `last_used_at` 排序，关闭最旧的一个或多个。

**自管理 API：** 扩展 `/me` 端点

```
GET    /me/sessions             ← 列出活跃会话（设备、IP、登录时间、最后活动）
DELETE /me/sessions/:id         ← 结束特定会话（不能踢自己）
DELETE /me/sessions             ← 结束所有其他会话
```

**边界情况：**

| 边界 | 策略 |
|------|------|
| 配额为 0 或负数 | 视为无限制（向后兼容） |
| 驱逐自己的当前会话 | 禁止——至少保留一个活跃会话 |
| 并发下竞态 | 使用租户级锁或 Redis 原子操作；配额检查 + 会话创建需在同一事务 |
| SAML IdP-Initiated SSO | 也通过 `sessionhub` 注册，受同一配额约束 |

---

## 3. 接口设计建议

### 3.1 通用设计原则

| 原则 | 说明 | 违反后果 |
|------|------|---------|
| **SPI 不膨胀** | 新功能以包裹器/中间件实现，不修改现有 SPI 签名 | 改 SPI = 改 65+ 实现 + 测试 |
| **默认 nil = 当前行为** | 所有新 `With*` 选项的零值必须是"不启用" | 现有用户升级后有行为变化 |
| **Fail-open 优先** | 新组件的错误（熔断器、复制层、溯源索引）默认 fail-open | 新组件不降级单 region 用户可用性 |
| **热路径零分配** | 热路径上不得新增 heap allocation | 令牌签发路径每请求已有 ~20 次 allocation |
| **SPI 先于实现** | 先定义接口，再提供 memory 实现，最后加持久化 peer | 避免实现细节污染抽象 |
| **无 mocks** | 测试使用 Memory* 实现而非 mock 框架 | 保持项目规范一致性 |

### 3.2 各方向接口映射总表

| 方向 | 新接口 | 所属包 | 设计模式 |
|------|-------|--------|---------|
| 方向一 | `ReplicationTopology` | `platform/cluster/topology/` | 值类型 + 配置 |
| 方向一 | `ReadConsistency` 枚举 | 同 | 枚举 |
| 方向一 | `Consistent*Store` 包裹器 | `protocols/oauth/` 等 | 装饰器 |
| 方向二 | `CircuitBreaker` | `platform/resilience/` | SPI + 滑动窗口实现 |
| 方向二 | `Bulkhead` | 同 | SPI + 信号量实现 |
| 方向三 | `ChangeLogStore` | `domains/changelog/` | SPI + sqlite/postgres 实现 |
| 方向三 | `TokenFamilyIndex` | `domains/tokenusage/` | 内存索引 + 审计重建 |
| 方向四 | `DomainVerifier` | `domains/domainverification/` | SPI + DNS/ACME 实现 |
| 方向四 | `ACMEProvisioner` | 同 | SPI + Let's Encrypt 实现 |
| 方向四 | `Channel`（通知通道） | `domains/notifications/` | SPI + email/sms/push 实现 |
| 方向四 | `NotificationService` | 同 | 门面模式 |
| 方向五 | `SessionPolicy` | `domains/tenant/` | 值类型扩展 |
| 方向五 | 会话配额守卫 | `protocols/session/` | 中间件 |

### 3.3 向后兼容策略

| 变更类型 | 策略 | 示例 |
|----------|------|------|
| 新 `With*` 选项 | 默认 nil → 行为不变 | `WithReplicationTopology(nil)` = 当前单 region |
| 新 SPI 方法（必须时） | 使用 `optional` 接口检查 | `if chk, ok := store.(ConsistencyChecker); ok { ... }` |
| Go struct 新增字段 | 仅追加，不删除不重命名 | `SessionPolicy.MaxActiveSessions int` |
| 新包 | 放在正确层下，注册 `layerName()` | `platform/resilience/` → `platform` 层 |

### 3.4 不需要引入的抽象层

| 被否决的抽象 | 理由 |
|-------------|------|
| 统一 Store SPI（所有 Store 合并为一个 mega-interface） | 违反接口隔离原则；当前每个 Store SPI 职责清晰 |
| 全局事件总线（在 cluster.Bus 之外再加一层） | `cluster.Bus` 已是事件总线的正确抽象 |
| 配置变更的统一监听器模式 | `configaudit` + `config/reload` 已覆盖 |

---

## 4. 技术选型

### 4.1 引入新技术栈的决策

| 方向 | 建议 | 理由 |
|------|------|------|
| 方向一（多区域） | **不引入**新技术栈 | 复用现有 gRPC + cluster.Bus |
| 方向二（熔断器/舱壁） | **自建** ~200 行核心逻辑 | 需求极轻量；Go 生态无活跃成熟替代 |
| 方向三（变更日志 + 令牌溯源） | **不引入**新技术栈 | 复用现有 audit.Store 事件模型 + SQLite/PostgreSQL |
| 方向四（自定义域名/通知） | **ACME 库**（go-acme/lego）+ **SMS SDK** | ACME 协议实现成本高；SMS SDK 是必要的外部依赖 |
| 方向五（会话配额） | **不引入**新技术栈 | 复用现有 sessionhub + quota.go 模式 |

**结论：** 五个方向中，仅方向四需要引入新的外部依赖（ACME 客户端 + SMS SDK）。其余四个方向完全在现有技术栈内完成。

### 4.2 关键外部依赖评估

#### 4.2.1 `go-acme/lego`（ACME 证书签发）

| 维度 | 评估 |
|------|------|
| **必要性** | ACME 协议实现（Let's Encrypt / ZeroSSL）——自建成本极高（需处理 HTTP challenges、DNS-01、TLS-ALPN-01）、证书链验证、OCSP stapling |
| **生态成熟度** | ★★★★☆ — 5k+ GitHub stars，广泛用于 Traefik、Caddy 等 |
| **替代方案** | `golang.org/x/crypto/acme/autocert`——更轻量但仅支持 HTTP-01 challenge |
| **推荐** | `go-acme/lego`（灵活支持多 challenge 类型） |

#### 4.2.2 SMS SDK（Twilio / AWS SNS / Azure Communication Services）

| 维度 | 评估 |
|------|------|
| **必要性** | 不可自建——SMS 需要电信运营商直连或聚合服务商 |
| **选型策略** | 定义 `SMSProvider` SPI（`Send(ctx, to, message) -> (messageID, error)`），提供 Twilio + SNS + Azure 三个实现 |
| **推荐** | 先实现 Twilio（市场占有率最高），其他提供者为插件化可选 |

#### 4.2.3 被否决的引入

| 技术 | 被否决策原因 |
|------|------------|
| Kafka / CDC 管道 | PostgreSQL 流复制 + 应用层 ReplicaRole 已足够；Kafka 增加运维复杂度 |
| hystrix-go / resilience4j-go | hystrix-go 已归档；resilience4j-go 非官方移植，Go 生态不成熟 |
| OpenTelemetry（作为令牌溯源存储） | 失去与现有 audit.Store 的自然关联——审计事件已就绪 |
| 新的 schema/DSL 语言（配置验证） | 现有反射式 JSON Schema + struct tag 已满足 |
| ML 启发式限流 | 限流层应保持清晰可解释；ML 是 `domains/anomaly/` 的领域 |

### 4.3 自建 vs 采购的完整决策框架

| 决策项 | 决策 | 理由 |
|--------|------|------|
| 熔断器/舱壁 | **自建** | ~200 行核心逻辑；零外部依赖；完全可控 |
| ACME 证书管理 | **采购**（go-acme/lego） | ACME 协议实现成本高；错误处理（rate limits、challenge 重试、订单状态机）复杂 |
| SMS 发送 | **采购**（Twilio/SNS/Azure） | 物理基础设施不可自建 |
| 通知模板渲染 | **自建** | 现有 Go `text/template` 已足够；增加沙箱即可 |
| 域名所有权验证 | **自建** | DNS lookup + HTTP fetch = 几十行代码 |
| 令牌溯源索引 | **自建** | 利用现有审计事件；内存索引 + 启动重建 |

---

## 5. 实施路线图

### 5.1 优先级矩阵

```
        高 │ 方向一（多区域主动-主动复制）        方向三（变更日志 + 令牌溯源）
           │     P0 ─── 全球架构基础                   P1 ─── 合规刚需
           │
   业务    │ 方向二（熔断器/舱壁）
   价值    │     P1 ─── 生产韧性
           │
        低 │ 方向四（自定义域名 + 通知）          方向五（会话配额 + 自助）
           │     P1 ─── 产品成熟度                     P2 ─── 安全基线
           │
           └──────────────────────────────────────────────
              低                                   高
                        技术复杂性
```

### 5.2 阶段划分

#### 阶段一：安全速赢 + 基础组件（Sprint 1-2，2 周）

| 子项 | 工作量 | 产出 | 验证标准 |
|------|--------|------|----------|
| DCR/admin/`/.well-known` 限流接线 | S（~50 行改动） | 消除 3 个攻击面 | `go test -run RateLimit` 通过 |
| Admin API 限流域合并到 PolicyStore | M | 统一限流配置面 | 动态限流策略生效 |
| `platform/resilience/` 包（CircuitBreaker + Bulkhead SPI + 滑动窗口实现） | M | 通用韧性原语 | 集成测试验证熔断/恢复 |
| KMS client 接线熔断 | M | 防"KMS 限频搞垮 SSO" | 模拟 KMS 限频时 `/token` 仍正常 |

**依赖关系：** 无前置依赖，可立即开始。

#### 阶段二：架构韧性（Sprint 3-5，3 周）

| 子项 | 工作量 | 产出 | 验证标准 |
|------|--------|------|----------|
| `ConsistentStore` 包裹器（SessionStore + AuthCodeStore） | M | 写转发 + 读一致性 | 双 region 部署验证写转发 |
| `ReplicationTopology` + `ReadConsistency` | M | 复制拓扑声明 | 单 region 部署零行为变化 |
| inter-region gRPC 转发管道 | L | 跨区转发基础设施 | gRPC 转发 + 超时 + 重试 |
| SAML IdP / CAEP webhook / federation 熔断接线 | M | 全面外部依赖保护 | 模拟 IdP 离线时快速失败 |

**依赖关系：** 依赖阶段一的 `platform/resilience/` 包。

#### 阶段三：合规审计 + 可观测（Sprint 4-6，3 周，可与阶段二并行）

| 子项 | 工作量 | 产出 | 验证标准 |
|------|--------|------|----------|
| `ChangeLogStore` SPI + 存储后端 | M | 结构化变更存储 | Record+List+Get 通过 |
| Admin handler 埋入点 | L | 5+ admin handler 写操作跟踪 | 每次 API 调用产生 ChangeEntry |
| Admin Console 变更历史视图 | M | 操作历史可视化 | 资源详情页显示变更列表 |
| TokenFamilyIndex + 令牌族谱查询 API | M | 令牌生命周期 DAG | `/admin/tokens/{jti}/lineage` 返回完整 DAG |

**依赖关系：** 依赖 `audit.Store`（已存在）和 `tokenusage`（已存在）。

#### 阶段四：产品成熟度（Sprint 6-8，3 周，可并行于阶段二/三）

| 子项 | 工作量 | 产出 | 验证标准 |
|------|--------|------|----------|
| `DomainVerifier` SPI + DNS 验证实现 | M | 域名所有权验证 | DNS TXT/CNAME 验证通过 |
| `ACMEProvisioner` SPI + Let's Encrypt 实现 | L | 自动 TLS 证书签发 | 自定义域名 HTTPS 可达 |
| `Channel` SPI + SMTP 通道适配 | M | 通知通道抽象 | 现有邮件发送通过新接口 |
| SMS 通道实现（Twilio） | M | SMS 通知能力 | SMS 验证码发送成功 |
| 用户通知偏好 API | M | `/me/notification-preferences` | CRUD 通过 |

**依赖关系：** `emailsmtp`（已存在）→ EmailChannel 适配；`push_mfa_provider`（已存在）→ PushChannel 适配。

#### 阶段五：安全基线 + 运维门禁（Sprint 7-9，2 周）

| 子项 | 工作量 | 产出 | 验证标准 |
|------|--------|------|----------|
| 会话配额策略 + 配额检查守卫 | M | 并发会话上限 | `MaxActiveSessions` 生效 |
| LRU 驱逐引擎 | M | 超配额时自动驱逐 | 最旧会话被自动关闭 |
| `/me/sessions` 自管理 API | M | 用户会话管理 | CRUD 通过 |
| 配置验证 `--ci` 模式 + 能力注册表 | S | CI 门禁 | `sso-ctl config validate --ci --strict` 非零退出 |

**依赖关系：** 会话配额依赖 `sessionhub`（已存在）。

### 5.3 总体时间线

```
Sprint   1   2   3   4   5   6   7   8   9
          │   │   │   │   │   │   │   │   │
阶段一   ████▓▓▓▓░░                         限流 + resilience 包
阶段二         ░░████▓▓▓▓░░░░               多区域复制
阶段三         ░░░░████▓▓▓▓░░░░             变更日志 + 令牌溯源  ← 并行
阶段四               ░░░░████▓▓▓▓░░         自定义域名 + 通知    ← 并行
阶段五                     ░░░░████▓▓▓▓     会话配额 + 配置门禁
```

**并行策略：**
- 阶段一 → 阶段二（串行，resilience 包是后续熔断接线的基础）
- 阶段三（合规审计）与阶段二（多区域）**可并行**——不同技能树
- 阶段四（产品成熟度）与阶段二/三**可并行**——独立代码路径
- 阶段五（安全基线）**可后移**到阶段三/四之后

### 5.4 风险与缓解

| 风险 | 概率 | 影响 | 缓解策略 |
|------|------|------|----------|
| **写转发延迟增加用户登录时间** | M | H | 读路径默认 local-read（最终一致性）；仅 `/token` 等关键路径用 leader-read；gRPC 连接池复用减少握手 |
| **熔断器误报**（正常流量触发熔断） | L | H | 滑动窗口 MinRequestCount 默认值保护（至少 5 请求才开）；half-open 试探保证自动恢复；metrics 告警阈值 |
| **令牌族谱索引重建慢** | M | L | 后台渐进重建，不影响 `/readyz`；`withCascadeRevocation` 默认关闭 |
| **ACME 证书签发失败导致租户域名不可用** | M | M | 降级到全局域名（fail-open）；到期前 30 天自动续期告警；staging/production 环境隔离 |
| **SMS 通道成本失控** | M | M | 通知频率限制（默认每用户每类型 5/min）；高 bounce 率自动暂停 |
| **多区域一致性模型理解错误** | M | H | 先做存储层 ReadConsistency 枚举 + 包裹器测试（gRPC loopback + simulated latency）；再做集成测试 |
| **代码预算违规**（新功能导致文件超 500 行） | M | M | AGENTS.md §0.1 硬门禁：编辑前先 split。每个新文件都正确放在对应包下，不往大文件追加 |

### 5.5 依赖关系图（完整）

```
阶段一：限流完备化 + resilience 包
  │
  ├──→ 阶段二：多区域复制（依赖 resilience 包保护 inter-region gRPC）
  │
  ├──→ 阶段三：合规审计 + 令牌溯源（独立路径，可并行）
  │
  ├──→ 阶段四：自定义域名 + 通知通道（独立路径，可并行）
  │
  └──→ 阶段五：会话配额 + 配置门禁（可后移，独立路径）
```

---

## 6. 否决项与不做事清单

| 不会做的事 | 原因 |
|-----------|------|
| 📌 **不引入 Kafka/CDC 管道** | PostgreSQL 流复制 + 应用层 ReplicaRole 已足够 |
| 📌 **不引入 hystrix-go/resilience4j** | 外部依赖审计成本；Go 生态无活跃成熟替代 |
| 📌 **不引入新数据库（时序数据库、图数据库）** | 现有 SQLite/PostgreSQL 通过 JSON 字段 + 索引满足所有新需求 |
| 📌 **不改现有 SPI 签名**（方向一的包裹器模式设计的原因） | 65+ 实现变更 = 核爆炸级 |
| 📌 **不做真实多 region e2e 测试** | 用 `gRPC loopback + simulated latency` 模拟 |
| 📌 **不引入 ML 启发式限流** | 限流层应保持清晰可解释；ML 是 `domains/anomaly/` 的领域 |
| 📌 **不引入新的 schema/DSL 语言（配置验证）** | 现有反射式 JSON Schema + struct tag 已满足 |
| 📌 **不做配置加密/凭据管理** | 那是系统外部队列的事务 |
| 📌 **不做全面前端重写**（方向四的 SPA 改造） | 专注于后端 SPI + 存储 + API；SPA 消费是后续 sprint |

---

## 7. 总结

| 维度 | 评估 |
|------|------|
| **架构健康度** | 极高——六层分层清晰、SPI 驱动、门禁严格、协议覆盖面全 |
| **核心缺口** | 五个方向均为"从单 region 单依赖架构向全球多活韧性架构演进"的天花板缺口 |
| **投入产出比最高** | 限流完备化（~50 行改动消除安全隐患） |
| **架构价值最高** | 多区域主动-主动复制（解锁全球部署架构） |
| **次高架构价值** | 外部依赖韧性（防"一个慢依赖搞垮整个 SSO"） |
| **合规刚需** | 管理操作不可变审计追踪（SOC2/SOX/HIPAA 审计路径） |
| **不做之事** | 五个方向全部在现有技术栈内完成（仅 ACME + SMS 需外部库）；零新数据库；零改现有 SPI 签名 |
| **推荐启动顺序** | 阶段一（速赢）→ 阶段二+三+四（并行）→ 阶段五（后移） |

---

## 附录 A：与 ROADMAP v5.0 的关系对照

| ROADMAP v5.0 方向 | 本分析关系 | 整合建议 |
|-------------------|----------|---------|
| ① Hosted Login + Consent 存储 | **互补** | 本分析方向四的自定义域名 + 通知通道与 ROADMAP 方向①无冲突，可并行 |
| ② B2B 企业化 | **互补** | 多区域复制 / 自定义域名是企业化基础 |
| ③ OIDC 一致性收口 | **独立** | 与本分析所有方向正交 |
| ④ 多副本数据面韧性 | **部分重叠但互补** | 本分析方向一聚焦数据复制/拓扑感知；ROADMAP §④ 聚焦总线健壮性/签名密钥 |
| ⑤ 安全姿态与供应链 | **互补** | 本分析限流完备化 + 配置门禁 + 变更审计是其补充 |

## 附录 B：文件创建清单（按方向）

```
方向一：platform/cluster/topology/
  ├── topology.go           # ReplicationTopology + ReadConsistency
  ├── consistent_session_store.go
  ├── consistent_authcode_store.go
  └── consistent_refresh_store.go

方向二：platform/resilience/
  ├── circuitbreaker.go     # CircuitBreaker SPI + sliding window impl
  ├── bulkhead.go           # Bulkhead SPI + semaphore impl
  ├── metrics.go            # Prometheus metrics
  └── examples_test.go

方向三：domains/changelog/
  ├── store.go              # ChangeLogStore SPI
  ├── memory.go             # MemoryStore
  ├── sqlite.go             # SQLiteStore
  ├── entry.go              # ChangeEntry struct
  └── filter.go             # ChangeFilter

方向四：domains/domainverification/
  ├── verifier.go           # DomainVerifier SPI
  ├── acme.go               # ACMEProvisioner SPI
  ├── dns.go                # DNSVerifier
  └── memory.go             # MemoryVerifier

方向四：domains/notifications/
  ├── channel.go            # Channel SPI
  ├── email.go              # EmailChannel
  ├── sms.go                # SMSChannel（adapter）
  ├── service.go            # NotificationService
  ├── preference.go         # UserPreference store SPI
  └── template.go           # TemplateManager

方向五：protocols/quota/
  ├── session_quota.go      # checkSessionQuota + SessionPolicy
  ├── lru_evict.go          # LRU eviction engine
  └── quota_test.go         # Concurrency-safe test
```

> 本报告可作为架构决策记录（ADR）的基础。每个方向在启动实现前，应由 Implement Agent 拆分为 `docs/feature-spec-<name>.md`，遵循 `docs/templates/feature-spec.md` 格式。
