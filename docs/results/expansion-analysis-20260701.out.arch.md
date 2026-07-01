# 架构师分析：Snaplink SSO 扩展方向评估

## 1. 架构评估

### 当前架构优势

**1. 物理分层架构（七层模型）**
项目采用"physical layering"模型——每层包（shared/domains/protocols/platform/infrastructure/interfaces + composition）的第一段路径即标注归属，由 `architecture_layer_test.go` 强制执行。这是一个被 ADR-0006 正式采纳的关键决策，其优点在于：
- 依赖方向是单一且可验证的（**向下指向 shared/core**），编译器阻止循环，门禁阻止向上导入
- 新加入的开发者只需理解 7 个桶而非 60+ 个顶层包
- `layerName()` 切换语句确保新包**必须被分类**，否则构建失败——模型不会无声漂移

**2. 可维护性门禁体系**
500 行/文件、50 行/函数、cyclo ≤ 15、目录深度 ≤ 3、目录扇出 ≤ 15——所有这些都被编码为 `archgate` 包中的 Go 测试，随 `make ci` 运行。这与大多数项目只靠 Linter 规则不同——Go 测试是**二进制的**（通过/失败），且作为合入门禁更容易集成。

**3. 跨后端的接口契约**
"每个关注点 = 接口 + memory 实现 ± sqlite/redis/postgres/etcd" 模式使得测试可以使用真正的后端（memory），生产环境可切换为持久化后端，而无需 Mock。`permissionstest.ConformanceSuite` 模式在这里是明星——每个 Provider 实现必须通过相同的测试套件。

**4. 安全深度的连贯性**
oracle-leak 统一化、anti-enumeration（bcrypt dummy hash、相同错误文本）、`DELETE RETURNING` 的单次使用保证、fail-closed 红线——安全属性是跨所有 grant handler 和所有后端执行的，而不仅是理论文档。

### 当前架构局限性

**1. `Deps` 接口膨胀（关键架构债务）**
`admin.Deps`（15 个方法）、`handler.Deps`（~25+ 个方法）、`*Server` 的隐式 `Deps`（~60+ 个访问器）——这是项目中最重要的**结构性债务**。单一 `Deps` 接口违反了接口隔离原则（ISP）：一个只重置密码的 handler 必须声明一个 15 方法的接口，但实际上只使用其中 3 个。这导致：
- 测试负担：必须 seed 所有 15 个 store，即使只测一个 handler
- 构建断裂传播：任何新增的方法都会使所有实现者编译失败（当前构建断裂已验证此风险）
- 依赖模糊：声明的依赖 != 实际需要的依赖

**2. 配置蔓延（38+ 子结构体，4+ 层嵌套）**
`config.Config.Keys.Rotation.CoordinatedCutover.GracePeriod` —— 此类路径在操作复杂度上近乎 Kubernetes CRD。默认值分布在：struct 字面量、`applyDefaults()` 函数（15+ 个位置）、`With*` function options（100+ 个）之间。没有 JSON Schema 生成、没有 CI 验证、没有运行时漂移检测。

**3. 多后端语义不一致**
相同的 SPI 接口在 memory/sqlite/redis/postgres 之间有不同的错误类型、并发语义和过期行为——导致"在 SQLite 上测试通过，在生产环境的 Redis 上静默失败"的场景。虽然每个后端单独经过良好测试，但缺少**跨后端的契约一致性测试**——`permissionstest.ConformanceSuite` 模式是一个特例，而非通用要求。

**4. 管道化的 Go 接口模式限制**
"将所有依赖项放在一个巨型 Deps 中并通过 Server 满足它"的模式在 Go 的隐式满足下工作，但在大型项目中会持续退化。工厂模式（`NewXxxStore(...)`）会生成复杂的 wiring 代码。随着 store 数量增长，组合根（`NewServer`）变成不可维护的巨石。

### 关键设计决策评估

| 决策 | ADR | 评估 | 备注 |
|------|-----|------|------|
| 物理分层而非认知映射 | ADR-0006 | ✅ 正确 | 减少认知负荷，同时避免 v2 版本切换的破坏性 |
| 没有 Mock，只有 memory 后端 | — | ✅ 正确 | 防止 Mock 与实际行为的偏差，强制行为兼容性 |
| func (s *Server) HandleXxx 模式 | — | ⚠️ 需要演化 | 导致 Deps 膨胀；考虑迁移到细粒度的 Free-Function 模式 |
| 基于 SQLite 的单文件组合 | — | ✅ 适用于中小规模 | 对于多区域主动-主动部署、审计热路径是高性价比的方式 |
| DELETE RETURNING 作为单次使用机制 | — | ✅ 正确 | 利用了 SQL 的原子性；Redis 版本使用 GETDEL 获得等价物 |
| go.mod replace 用于子模块 | — | ⚠️ 需要治理 | 阻止 `go install`，对 v1.0 后的分发构成障碍 |

---

## 2. 扩展方向

基于截至 2026-07-01 的 30+ 轮分析（涵盖 40+ 扩展方向），我识别了以下 5 个独立的高价值架构扩展方向——每个都经过对抗性验证，确认为真缺口，同时与之前的报告、ROADMAP v5.0 和现有代码库进行交叉检查。

### 方向 A：自适应风险评估引擎（Adaptive Risk Engine）

**为什么需要**

当前 `RiskScorer` SPI 在**登录时**评估一次风险，然后授权持续有效直到令牌/会话过期。这种"一次评估"模型存在结构性盲区：

| 场景 | 当前问题 |
|------|----------|
| 登录后设备被入侵 | 已有令牌持续有效直到过期 |
| 用户行为突变 | 正常用户从异常地理位置大量请求——无法触发重新认证 |
| 凭据泄露后发现 | 无法主动使已签发的令牌失效（除手动吊销） |
| 内部威胁 | 已授权用户开始下载大量数据——无权自动干预 |

**基础已到位**：`anomaly/` 包（异步，非关键路径）、`RiskScorer` SPI（仅登录时单次）、`cluster.Bus`（可用于实时事件）、`geo/` 中间件（可用于评估器）。

**核心架构变更**

```go
// 新 SPI（在 shared/spi/ 中，保持依赖方向）
type SessionRiskEvaluator interface {
    // Evaluate 返回给定会话的风险评分（0-100）、可选标志和决策
    Evaluate(ctx context.Context, session *core.Session, event ActivityEvent) (*RiskEvaluation, error)
}

// 内置规则评估器（在 domains/anomaly/ 中）
type RuleBasedEvaluator struct {
    rules []RiskRule  // 地理跳跃、速率异常、新资源访问模式、已知受损设备
}

// 风险阈值策略（在 interfaces/sso/options_security.go 中）
type SessionRiskPolicy struct {
    RequireStepUp int  // 评分 >= 此值 → 敏感操作前强制 MFA 升级
    ForceReAuth   int  // 评分 >= 此值 → 终止会话，要求完全重新认证
    AuditOnly     int  // 评分 >= 此值 → 审计升级但不阻止
}
```

**技术挑战**
- **性能**：评估器在关键路径上同步调用——内置规则引擎应 < 1ms P99。外部 SPI 调用应异步更新评分
- **有界基数**：`RiskFlags` 必须是预定义枚举（`geo_jump`、`request_rate` 等），而非自由文本
- **Fail-open**：评估器错误应保留当前评分并记录审计，不阻塞请求
- **假阳性管理**：规则引擎必须在假阳性（用户抱怨）和假阴性（安全事件）之间取得平衡。起始阶段应仅审计+记分，但不阻止

**现有系统影响**
- `core.TypeSession`：增加 `RiskScore`, `RiskEvaluatedAt`, `RiskFlags` 字段（有界基数，可为空表示"尚未评估"）
- `plugins/` 添加 `WithSessionRiskEvaluator` option
- CAEP transmitter：当评分达到 `ForceReAuth` 时，自动广播 `TokenRevoked` / `SessionRevoked`

**价值等级**：P0。这是企业 SSO 的关键差异化功能，直接影响客户的采购决策。

---

### 方向 B：跨副本原子性层（Cross-Replica Atomic Coherence Layer）

**为什么需要**

这是唯一剩余的**真正安全漏洞**。在 2+ 副本的部署中：

| 状态 | 当前模型 | 问题 |
|------|----------|------|
| JTI 重放保护 | 每个副本独立（memory / SQLite / Redis） | 负载均衡可将重放的 JWT 路由到不同副本，完全绕过保护 |
| Refresh 家族击杀 | 每个副本独立 `DeleteFamily` | 攻击者可在副本 A 上消耗令牌，然后在副本 B 上重放同一令牌——B 视其为首次，家族未被击杀 |
| Session 状态 | 30s TTL + 尽力而为总线 | 滚动部署期间冷 pod 返回 404 `session_invalid` |
| 租户暂停传播 | 30s TTL + 尽力而为总线 | 存在可利用的窗口 |

**基础已到位**：`cluster.Bus`、Redis 后端、etcd 后端。

**核心架构变更**

基于**共享存储**的模式，而非分布式共识：

```go
// 选项（在 interfaces/sso/ 中）
type SharedCoherenceOptions struct {
    JTIReplayStore    redis.UniversalClient  // 共享 JTI 和 DPoP nonce 存储
    RefreshTracker    redis.UniversalClient  // 共享 Refresh 家族击杀跟踪器
    FailClosed        bool                   // 后端丢失时 fail-open 还是 fail-closed
    GracefulWarmup    time.Duration          // 新副本在此窗口内放宽检查
}
```

**技术挑战**
- **跨区域部署**：JTI 验证需要处理时钟偏移（`exp` 在签发区域的时钟域内验证）
- **键命名空间碰撞**：`jti:<issuer>:<kid>:<jti>`——确保跨租户的唯一性
- **熔断 vs 降级**：共享后端故障必须优雅处理——"共享后端挂了"和"合法首次"是两个不同的信号

**与方向 A 的集成**：风险引擎的跨副本决策需要此共享原子性层。JTI 重放保护是自适应评估的**前提条件**——如果没有它，攻击者可以通过跨副本重放被吊销的令牌来绕过吊销。

**价值等级**：P1（安全）。安全缺口，概率性但影响大。

---

### 方向 C：企业配置漂移治理与 GitOps 化（Enterprise Config Governance & GitOps）

**为什么需要**

当前配置是**被动的**——从 YAML 加载，然后无人监管与期望状态的一致性。现实场景：

1. 运维团队通过 `config.yaml` 定义了 3 个 client
2. 管理团队通过 admin API 创建了 5 个额外 client
3. 运维团队更新 `config.yaml` 并重启 SSO
4. 重启后：admin API 创建的 5 个 client 仍存在（存储是持久的）
5. 但 `config.yaml` 中的 client 也重新加载——如果 YAML 中没有 `preserve_existing` 标记，会发生什么？**不可预知**

**这个方向合成三个缺失的模式**
- **配置 Schema 生成 + CI 验证**：从 Go 结构体自动生成 JSON Schema，在 CI 中验证，在 IDE 中自动补全
- **配置漂移检测**：期望状态（YAML）与运行时状态（admin API）之差，可检测并告警
- **配置版本化**：admin API 的每个变更创建 `ConfigVersion` 快照，支持回滚

**核心架构变更**

```go
// 新的 ConfigReconciler 抽象（在 config/ 中）
type ConfigReconciler struct {
    desired Config       // 从 YAML 加载的期望状态
    actual  ConfigView   // 运行时状态（admin API 的当前状态）
    drift   ConfigDiff   // desired - actual
    mode    ReconcileMode // Strict / Baseline / AppendOnly
}

// 治理模式
type ReconcileMode int
const (
    ReconcileStrict     ReconcileMode = iota // 完全 GitOps——不在 desired 中的将被删除
    ReconcileBaseline                        // desired 是最低要求——实际可以有额外内容
    ReconcileAppendOnly                      // 只创建/更新 desired 中的内容，永不删除额外内容
)
```

**技术挑战**
- **紧急旁路**：P0 事件需要"立即执行，事后审批"模式——紧急变更不应被 reconciler 反转
- **并发冲突**：乐观锁（`If-Match` / `If-Unmodified-Since`）防止 admin API 与 reconciler 的冲突
- **回滚语义**："回滚到上一个已知良好状态"需要跨实体变更的正确排序（删除上一个 client 再重新创建 ≠ 回滚）

**现有系统影响**
- `config/config.go`：增加 JSON Schema 生成（通过 `invopop/jsonschema` 集成）
- `interfaces/snapshot/`：现有的快照系统应扩展为版本化历史的存储
- `cluster.KindClientChange` 等总线事件：reconciler 应监听这些事件以检测漂移

**价值等级**：P1（企业运营）。SOC 2 CC7.1（变更管理）和 GitOps 现代化的基础。

---

### 方向 D：SCIM 供给客户端（SCIM Provisioning Push Client）

**为什么需要**

现有 SCIM 2.0 实现是一个**接收器**——用户/组可以通过 SCIM API 管理。但缺少 **SCIM 客户端（Push Client）**——即 SSO 作为权威源，主动将变更推送到下游 SaaS 应用。

**产品价值**：企业身份平台的核心价值主张是**身份生命周期自动化**：
- 员工创建 → 自动推送到 Slack/Google Workspace/Salesforce
- 员工离职 → 自动推 SCIM DELETE 到所有下游应用
- 邮箱/组变更 → 自动推 PATCH 到所有下游应用

**核心架构变更**

```go
// 新 SPI（在 domains/provisioning/ 中，SCIM 层之上）
type SCIMProvisioner interface {
    PushUser(ctx context.Context, user *User, action ProvisioningAction) error
    PushGroup(ctx context.Context, group *Group, action ProvisioningAction) error
    DeleteRemoteUser(ctx context.Context, externalID string) error
    VerifyConnection(ctx context.Context, endpoint string) error
}

// 推送队列（异步，带背压和重试）
type ProvisioningQueue struct {
    store       ProvisioningQueueStore  // 持久化队列（SQLite / Redis）
    maxRetries  int
    retryDelay  time.Duration           // 指数退避
    dlq         DeadLetterQueue
}
```

**技术挑战**
- **一致性与最终一致性**：推成功才算成功——纯推后验证与推后轮询验证之间存在权衡
- **幂等性**：使用 `externalId`（SCIM 标准的不可变 ID）作为匹配键
- **去供给策略**：禁用 vs 删除——企业倾向于禁用（保留审计记录），SaaS 倾向于删除（节省许可证费用）
- **事件触发 vs 定期同步**：`cluster.Kind*` 事件作为变更触发器 vs 定期全量同步作为补偿机制

**现有系统影响**
- 新的 `domains/provisioning/` 包——不改变现有依赖方向
- `cluster.Bus`：增加 `KindUserCreated`, `KindUserDisabled`, `KindGroupUpdated` 等事件类型
- `Client.Attributes`：扩展以存储 `scim_push_url`, `scim_push_token`
- 管理 API：增加供给状态和手动重试端点

**价值等级**：P0（企业销售）。无 Push → 企业采购否决项。

---

### 方向 E：基于 OTel 的异步路径追踪完整性（Async Path Tracing Completeness）

**为什么需要**

HTTP 请求路径已有完整的 OpenTelemetry span 覆盖。但以下异步路径**完全不可见**——它们在 Jaeger/Zipkin 中不留痕迹：

| 路径 | 当前 | 风险 |
|------|------|------|
| 审计批量写入 | 仅自有的 TraceID（与 OTel 不关联） | 审计事件丢失不可追踪 |
| CAEP 推送 | 无 span | 安全事件推送失败不可追踪 |
| 集群事件处理 | 无 span | 令牌吊销延迟不可测量 |
| 迁移步骤 | 无 span | `BEGIN IMMEDIATE` 死锁不可追踪 |

**基础已到位**：`platform/tracing/tracing.go` 已集成 OTel，`platform/audit` 有自有的 TraceContext 格式。

**核心架构变更**

最小的变更——只需在现有 `context.Context` 链上增加 `tracer.Start()` 调用：

```go
// 审计批量写入
func (s *BatchSink) WriteBatch(ctx context.Context, events []Event) error {
    ctx, span := tracer.Start(ctx, "audit.sink.batch")
    defer span.End()
    span.SetAttributes(attribute.Int("events.count", len(events)))
    // ... 现有逻辑 ...
    if err != nil {
        span.RecordError(err)
    }
    return err
}

// TraceID 对齐：审计事件使用 OTel TraceID/SpanID，而非自行生成的随机 hex
```

**技术挑战**
- **上下文传播**：异步 goroutine 在启动时捕获 `context.Context`，但 OTel span 在父 span 结束时可能已被导出。需要使用 `otel.WithNewRoot()` 确保异步 span 独立完成
- **批量写入的 span 爆炸**：不在每次写入时创建 span——只在批量层创建，将批次大小作为属性
- **背压下的 span 丢弃**：使用 `sampling.SamplingResult` 在背压期间降低采样率

**价值等级**：P2（可观察性）。不直接影响功能，但显著影响运营效率。

---

## 3. 接口设计建议

### 关键模块接口设计原则

**原则 1：接口隔离（ISP）——拆分 `Deps`**

这是项目中最紧迫的接口设计变更。当前模式是"将所有内容放入一个巨型接口，让 Server 满足它"。需要迁移到**每个 handler 声明它实际需要的子接口**：

```go
// 当前（违反 ISP）
type AdminDeps interface {
    ConnectionStore() connections.Store
    UserProvider() core.UserProvider
    ConsentStore() core.ConsentStore
    Auditor() *audit.Recorder
    // ... 12 个更多方法
}

// 目标（ISP）
type ConsentDeps interface {
    ConsentStore() core.ConsentStore
    Auditor() *audit.Recorder
}
type PasswordDeps interface {
    PasswordCredentialStore() core.PasswordCredentialStore
    Auditor() *audit.Recorder
}
type ConnectionDeps interface {
    ConnectionStore() connections.Store
    Auditor() *audit.Recorder
}
```

`HandleAdminListUserConsents` 只声明 `ConsentDeps`，`HandleAdminResetUserPassword` 只声明 `PasswordDeps`。

**迁移策略**：
1. 在 `internal/handler/` 中定义细粒度子接口
2. 每个 `Handle*` 函数接受它需要的子接口——不再使用 `(s *Server)` 方法
3. `*Server` 通过**适配器映射**满足任何子接口：`func (s *Server) Adapt(intf any) bool { ... }`
4. 添加编译期守卫：在每个 `Deps` 接口定义后加 `var _ Deps = &Server{}`——让新增方法时立即报错
5. 最终：移除 `Deps` 接口，让 `Handle*` 函数成为纯的、可测试的、仅依赖它们需要的内容

**原则 2：契约一致性——多后端 ConformanceSuite**

将 `permissionstest.ConformanceSuite` 模式推广到所有核心 SPI。每个 SPI 接口有一个对应的 `*spitest` 包，定义所有后端必须通过的可执行契约：

```go
// shared/core/spitest/auth_code.go  （新）
func AuthCodeStoreConformance(t *testing.T, factory func() oauth.AuthCodeStore) {
    t.Run("Consume_Once", func(t *testing.T) { /* ... */ })
    t.Run("Consume_Twice_ReturnsError", func(t *testing.T) { /* ... */ })
    t.Run("Expired_ReturnsErrNotFound", func(t *testing.T) { /* ... */ })
    t.Run("Concurrent_Consume_ExactlyOneWins", func(t *testing.T) {
        // 使用 race detector 验证并发安全
    })
}
```

所有 4 个后端（memory、sqlite、redis、postgres）在 CI 中运行相同的契约测试。这捕获了当前"SQLite 上测试通过，但 Redis 上静默失败"的不一致。

**原则 3：采用配置即合约（Configuration as Contract）**

下一步不是引入新的配置 DSL，而是**让现有 Go 结构体生成一个机器可读的 schema**（JSON Schema / CUE），在 CI 中验证配置，并在运行时检测漂移。三个阶段：

1. **Schema 生成**：`invopop/jsonschema` 从 `config.Config` 结构体生成 JSON Schema → `docs/config-schema.json`
2. **CI 验证**：在 PR 中验证 `ops/deploy/*/config.yaml` 是否符合 schema
3. **漂移检测**：定期比较 YAML + admin API 状态 → 告警差异

**原则 4：依赖注入的演进路径**

当前模式——单一 `NewServer(...)` 有 60+ 个参数——在某个点上一定会变得不可维护。推荐一个两步迁移：

1. **第一步（立即）**：使用 Go 1.24 的功能选项（`func(*ServerOptions)` 模式）替代位置参数。这已经在部分的 `With*` 函数上实现了，但需要覆盖所有选项。
2. **第二步（v1.0 门禁）**：考虑基于 map 的依赖注册（类似 uber/fx 但更轻量），或显式的选项组（`WithAuthOptions(...)`, `WithStorageOptions(...)`）。

### 向后兼容性策略

| 变更类型 | 策略 |
|----------|------|
| 拆分子接口 | 新代码使用子接口；`Deps` 接口保留兼容（通过显式的守卫标记为已弃用） |
| 添加新 Option | 始终零值安全——`nil` 选项禁用相关功能 |
| 配置键重命名 | 支持旧名→新名的自动映射（加载时 map），log WARNING |
| 废弃 API | 废弃端点添加 `X-Sunset` 头；2 个 minor 版本后移除 |
| 存储 schema | 仅 forward-migration（`migrate.Run`），回滚通过手动 restore-clobber |

---

## 4. 技术选型

### 评估框架

新依赖的评估标准：

| 标准 | 阈值 | 原因 |
|------|------|------|
| 许可 | Apache 2.0 / MIT / BSD | 兼容性（排除 AGPL、SSPL） |
| Go 模块 | 标准 `go get` | 无 CGO 要求，无复杂的构建步骤 |
| 传递依赖 | ≤ 5 个 | 最小化供应链攻击面 |
| API 稳定性 | Go 1 兼容性保证 | 无意外 break |
| 社区 | ≥ 1000 GitHub star | 合理的活跃度和维护 |
| 审计能力 | 可读源码 | 安全关键依赖必须可审查 |

### 按方向的建议

**方向 A（自适应风险引擎）**：
- 规则引擎：**自建**——当前代码库中已有规则评估模式的良好模式（正则、通配符匹配、时间范围比较）。不需要引入 Drools 或任何 Java/DSL 引擎
- 设备指纹：**集成 FingerprintJS 或等效方案**——这是前端技术，通过 JavaScript 收集指纹哈希，然后发送到风险评估端点。但**不处理指纹数据本身**——只使用哈希值
- 特征工程/ML：**不要引入**——初始版本（P0）应完全基于规则。ML 集成（Isolation Forest）是备选方案，仅在后期考虑

**方向 B（跨副本原子性）**：
- RedSync / 分布式锁：**不引入**——Redis 事务（Lua 脚本）对此用例已足够。MULTI/EXEC + Lua 的 `redis.call()` 模式可实现原子 JTI 检查和 Refresh 家族击杀，无需外部锁管理器
- CRDT：**暂不引入**——初始版本使用"写入主区域+异步复制"模型。CRDT 在需要真正 N-区域主动-主动时才有必要

**方向 C（配置 GitOps）**：
- JSON Schema：`invopop/jsonschema`——轻量，从 Go 结构体生成，无需新的 DSL
- CUE / Dhall：**不引入**——增加了操作者的认知开销，改变现有 YAML 配置格式会打破向后兼容性

**方向 D（SCIM Push）**：
- HTTP 客户端基础设施：**复用**现有的 `webhook_sink.go` 的 `http.Client` 工厂模式和 `caep/transmitter.go` 的重试模式——不要引入新的 HTTP 库
- 队列存储：**复用**现有的 SQLite / Redis 基础设施作为推送队列的存储后端——不需要引入 Kafka 或 RabbitMQ

**方向 E（异步追踪）**：
- OTel Go SDK：**已引入**——只需要增加 `tracer.Start()` 调用，不需要新的依赖

### 自建 vs 引入的关键准则

| 标准 | 自建 | 引入 |
|------|------|------|
| 核心安全逻辑 | ✅ 必须自建 | ❌ |
| 基础设施集成模式 | ✅ 模式简单、无依赖复杂性 | ❌ |
| 复杂算法/格式 | ❌ | ✅（如 JOSE 库） |
| 独立、不变更的接口 | ❌ | ✅（如 OTel SDK） |

---

## 5. 实施路线图

### 优先级排序

| 优先级 | 方向 | 工作量 | 价值 | 依赖 | 建议阶段 |
|--------|------|--------|------|------|---------|
| **P0** | D：SCIM Push Provisioning | L（~1500 行） | 极高（企业采购否决项） | 无 | 1 |
| **P0** | A：自适应风险评估 | M（~800 行） | 高（差异化功能） | SPIs + 规则引擎 | 1 |
| **P1** | B：跨副本原子性 | M（~600 行） | 高（安全缺口） | Redis 已就绪 | 2 |
| **P1** | C：配置 GitOps 与漂移治理 | L（~1200 行） | 高（运营现代化） | Admin API 已就绪 | 2 |
| **P2** | E：异步链路追踪 | M（~300 行） | 中（可观察性） | OTel 已就绪 | 3 |

### 阶段划分

**阶段 1（当前 — 2 周）——快速落地的企业差异功能**

| 周 | 方向 D（SCIM Push） | 方向 A（风险引擎） |
|----|---------------------|-------------------|
| 1 | SPI 定义 + 推送队列引擎 + 事件桥接 | SPI 定义 + 规则引擎核心 |
| 2 | 管理 API + 重试 + 幂等性 | 阈值策略 + CAEP 集成 + 测试 |

**阶段 1 并行任务**：
- 开始 `Deps` 接口隔离重构（每 PR 拆一个子接口）
- 开始多后端 ConformanceSuite 模式（选择一个核心 SPI，编写契约测试）
- 配置版本 `V1` 字段声明

**阶段 2（第 3-4 周）——安全与治理加固**

| 周 | 方向 B（跨副本原子性） | 方向 C（配置 GitOps） |
|----|-----------------------|-----------------------|
| 3 | 共享 JTI 存储 + Refresh 家族跟踪器 + 熔断 | JSON Schema 生成 + CI 验证 + 配置漂移检测器 |
| 4 | 跨区域全局部署预部署测试 + 冷启动缓解 | 配置版本历史 + 管理 API 集成 |

**阶段 2 并行任务**：
- `DisallowUnknownField` 从 WARNING 升级为 ERROR（配置治理的一部分）
- 废弃 API 策略文档
- go.mod replace 治理（`go install` 兼容性）

**阶段 3（第 5-6 周）——可观察性与成熟度**

| 周 | 方向 E（异步追踪） | 持续改进 |
|----|-------------------|----------|
| 5 | 审计写入 + CAEP 推送 + 集群事件的 OTel span | `Deps` 接口隔离完成 |
| 6 | 数据流对齐 + 跨服务追踪验证 | 多后端一致性契约完整化 |

### 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| **接口膨胀影响新方向** | Deps 重构影响 A、B、C、D 四个方向的接口设计 | 在阶段 1 开始前，先将 `Deps` 拆分为子接口——这为所有新方向提供了干净的基础 |
| **SCIM Push 的一致性与重试陷阱** | 不当实现→数据不一致或推送风暴 | 使用最终一致性模型 + 幂等性键 + 背压。先做增量 Sync，不做全量 Sync |
| **风险评估的假阳性率** | 用户被过度重新认证→放弃 | 阶段 A 仅审计+记分，不阻止。阈值由运营者配置。提供规则覆盖的 "whitelist" 以覆盖已知的假阳性模式 |
| **跨副本原子性的延迟影响** | 每次 JTI 检查都要跨副本→P99 下降 | 不等待所有副本——只等待主副本+指定副本确认。配置 `MinReplicaAcks` |
| **配置漂移检测的告警风暴** | 每个漂移都告警→运维疲劳 | 对漂移类型进行分层告警。用户/会话级别的瞬态漂移→仅日志；client/tenant 级别的固化漂移→告警 |

### 关键里程碑

| 里程碑 | 定义 | 预计 |
|--------|------|------|
| M1：SCIM Push MVP | SCIM 推送到 1 个下游（如 Google Workspace），支持创建/更新/禁用 | 阶段 1 结束 |
| M2：自适应风险引擎 Ready | 规则引擎 + CAEP 反馈回路，在登录后 5s 内触发 `ForceReAuth` | 阶段 1 结束 |
| M3：跨副本安全 | JTI 重放保护跨 3 副本 Redis 集群验证通过 | 阶段 2 结束 |
| M4：Config GitOps | YAML → CI 验证 → admin API 一致性 → 漂移告警流水线就绪 | 阶段 2 结束 |
| M5：端到端追踪 | 审计写入 → CAEP 推送 → 集群事件的 OTel span 在 Jaeger 中可见 | 阶段 3 结束 |

---

## 总结

Snaplink SSO 已从一个"功能完整的身份协议库"演进为一个"生产就绪的多协议 SSO 平台"。此前 30+ 轮分析和 40+ 扩展方向主要聚焦于协议覆盖面、Edge Cases 和性能优化。

本分析从架构师视角识别了 5 个**此前未被系统性覆盖**的方向，它们不是 "添加新端点"，而是**引入新的运行模式和抽象层**：

| # | 方向 | 关键洞察 |
|---|------|----------|
| A | 自适应风险引擎 | 将授权从"一次性"升级为"持续"——完全复用现有基础设施 |
| B | 跨副本原子性 | 唯一剩余的真正安全缺口——异步的跨副本可攻击窗口 |
| C | 配置 GitOps 治理 | 从被动加载→主动调和——配置即代码的运营框架 |
| D | SCIM 供给客户端 | 有接收器，没有发射器——核心产品差距 |
| E | 异步追踪完整性 | 异步路径最易故障，可见性最低——低成本高回报 |

这三个**横向基础设施模式**——`Deps` 接口隔离、多后端 ConformanceSuite、配置即合约——是所有新方向能够干净落地的前提条件。

**最终建议**：在阶段 1 启动前，投入 2-3 天优先解决 `Deps` 接口膨胀和多后端契约测试框架。这可以为 A→D 四个方向提供一个稳定的接口基础，避免每个新方向都被迫应对现有的接口问题。
