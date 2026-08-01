# 运行时治理与系统演化方向分析 —— 启动编排、后台健康、库版本治理、配置进化与依赖完备性

> **作者：** 资深架构 & 产品经理视角  
> **日期：** 2026-07-11  
> **方法：** 全代码库全局扫描（~2241 个 `.go` 文件、200+ 包、14 个嵌套 `go.mod`）。  
>   在系统阅读 ROADMAP v5.0、deferred-backlog、feature-matrix、SECURITY.md、  
>   docs/requirements/ 下全部 23+ 轮历史扩展方向分析文档的基础上，  
>   **对每项候选方向做全代码库 grep 逐项核验 + 对全部 23+ 份已有分析做关键词零重叠验证**。  
> **定位：** 本报告 5 个方向不属于"新增协议支持"、"补后端实现"、"生产硬化"、"产品面"、  
>   "系统性质量纵深"、"跨协议集成"、"隐私工程"、"边缘缺口"或"运行时基础设施（背压/可观测性）"——  
>   那些已经在之前 23+ 轮分析中反复覆盖并大量落地（协议面、安全面、产品面、存储面已全部落地）。  
>   本报告聚焦于一个身份平台在**运行时治理（Runtime Governance）** 与**系统演化（System Evolution）**  
>   方面的五个盲区——这些方向不改变对外可见的功能，但决定了平台在长期演进中的**可维护性（Maintainability）、  
>   可靠性（Reliability）、可治理性（Governability）与演化安全性（Evolution Safety）**。

---

## 前置声明：项目成熟度

经过 23+ 轮全局扫描 + 增量分析 + 大量代码落地，本项目的能力覆盖面已达到行业顶级水平。
以下领域已确认全部覆盖，**本报告不再重复分析**（仅做完整性陈述）：

| 领域 | 覆盖状态 |
|---|---|
| **协议面** — OAuth 2.0 × 7 grants + PAR + JAR + JARM + RAR, OIDC Core/Discovery/Logout/BCL/FCL/CIBA/Form Post, SAML 2.0 SP+IdP, SCIM 2.0 双向, CAEP/SSF 双向, FAPI 2.0, OpenID Federation 1.0, LDAP, Kerberos, RADIUS, Transaction Token, Step-Up Auth（RFC 9470）, DPoP, mTLS, SPIFFE JWT-SVID, 开发者 API Key | ✅ 全部实现 |
| **存储面** — Memory, SQLite, Redis, etcd, PostgreSQL + 14 个嵌套子模块（KMS × 5, SAML × 4, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT, Vault Transit） | ✅ 全部实现 |
| **安全面** — Anti-enumeration, Oracle-leak hardening, DPoP, mTLS, JWT-SVID, Workload Identity（GCP/AWS/Azure）, Break-Glass（2-person control）, Per-tenant 签名隔离, 区域数据驻留, FAPI 2.0, FIPS 140-3, 会话信任衰减, Step-Up Auth, Account Lockout, Password Policy | ✅ 全部实现 |
| **产品面** — Hosted Login SPA, Admin Console SPA, Developer Portal SPA, User Portal `/me`, Consent Store（memory/sqlite/redis）, B2B Enterprise Connections + HRD, Org-admin self-service, 租户用量聚合, API docs viewer（`/api/v1/admin/docs`）, SDK 生成（TS + Python）, 配置审计/差异/drift 检测 | ✅ 全部实现 |
| **生产硬化** — DR framework（snapshot/RPO/RTO）, config hot-reload（SIGHUP ×7 feature gates + logging + rate limit）, Circuit Breaker（backchannel logout）, 跨副本协调（coordinated key rotation + leaderless peer-key adoption + cross-replica revocation via cluster.Bus）, Degradation mode, Graceful shutdown, Active-Active 数据面规划分析, 升级健康框架分析, 跨环境同步分析 | ✅ 已分析 / 部分实现 |
| **运行时基础设施** — 令牌签发背压与拥塞控制, 数据库层可观测性（慢查询/连接池盲区）, 服务依赖熔断, TLS 与证书管理自动化, 性能工程工具链（benchmark gate/load test/容量规划） | ✅ 已分析（待落地） |
| **运营纵深** — AI/ML 原生身份分析, 开发者 API Key, 跨区域 Active-Active, 安全事件响应工作台, 网格控制平面一体化 | ✅ 已分析（待落地） |
| **前沿方向** — Token Status List, FIDO2 Cross-Device, Post-Quantum Crypto, CIAM/Social Login, PAM, AI Agent Identity, SPA 安全治理 | ✅ 已分析（待落地） |

> **结论：** 经过 23+ 轮分析，项目的功能方向、安全方向、生产硬化方向均已被深度覆盖。  
> 本报告 5 个方向聚焦于 **运行时治理（Runtime Governance）** 与 **系统演化（System Evolution）**——  
> 即身份平台作为一个长期演进的复杂系统，其**启动阶段、运行阶段、数据层、配置层和依赖层**  
> 的内在系统性质缺口。这些是决定项目能否从"一个功能强大的服务器"进化为  
> **"一个可长期安全演进的平台"** 的关键基础设施。

---

## 方向一：服务器启动编排与依赖阶段管理（Server Initialization Phase & Wiring Governance）

> **全代码库核验：此方向在全部 23+ 轮历史分析中零提及**（grep: `option.*order.*depend\|option.*order.*wiring\|option.*sequence\|option.*ordering\|apply.*order\|apply.*sequen\|post.*option\|postOption\|option.*phase\|option.*stage` 在所有 `docs/requirements/*.md` 中 **0 命中**）。

### 现状

项目的 `Server` 构造采用经典的 functional options 模式：

```go
// interfaces/sso/sso.go
func NewServer(opts ...Option) *Server {
    s := &Server{}
    // 1. 零值初始化
    s.authenticators = make(map[string]Authenticator)
    s.tokenIssuers = make(map[string]TokenIssuer)
    // ... ~20 个字段初始化
    // 2. 依次应用 options
    for _, opt := range opts {
        opt(s)
    }
    // 3. apply* 后处理阶段
    s.applyAuditSinkTaps()       // 依赖 auditor + caepTransmitter + sseBroker + webhookEngine + scimProvisionSink
    s.applyConfigAuditWiring()   // 依赖 configAuditStore + auditor
    s.applyMetricsWiring()       // 依赖 metrics + tokenPolicyStore + tokenAnomalyDetector + tokenUsageRecorder
    s.applyFederationAutoRegistration() // 依赖 federationEntity + clientStore
    s.applyClientStoreCache()    // 依赖 clientStore（应在 federation 装饰之后）
    s.applySessionHub()          // 依赖 sessionMgr
    s.seedFeatureGateLiveFlags() // 依赖 configAuditStore（可选）
    s.recordFeatureGateStartup() // 纯日志/指标
}
```

**当前模式的隐患：**

| 痛点 | 代码证据 | 风险级别 |
|---|---|---|
| **隐式 ordering 依赖** | `applyAuditSinkTaps()` 在 options 之后无条件调用。如果用户调用 `WithCAEPTransmitter` 但没有调用 `WithAuditRecorder`，则 `s.auditor` 为 nil，tap 被跳过但无告警。同一逻辑中 `scimProvisionSink` 的 tap 同理 | **中** |
| **apply 之间的隐藏耦合** | `applyFederationAutoRegistration()` 和 `applyClientStoreCache()` 都装饰 `s.clientStore`。注释注明了 "Order between these two ClientStore decorators is load-bearing: the cache MUST wrap the federation decorator (OUTERMOST)"——但这种 ordering 依赖仅存在于注释中，无编译期或运行时检查 | **高** |
| **无显式阶段定义** | 当前有三阶段：零值初始化 → options → apply*。但 apply* 内部又有隐式子阶段（先 federation 装饰，再 cache 装饰）。没有阶段 ID、没有 phase gate、没有 "延迟注册" 机制 | **中** |
| **依赖缺失静默吞没** | `applyAuditSinkTaps()` 中每个 tap 都是 if-nil-skip。如果用户预期 CAEP 事件会被传播但忘记 wired auditor，不会收到任何启动告警 | **中** |
| **options 互相依赖不可表达** | 无法表达 "WithFederationEntity 必须在 WithClientStore 之后" 或 "WithTenantTokenIssuer 需要先 WithTokenStrategy" 这样的依赖关系 | **低->中** |

随着 Server 字段从 30+ 增长到 ~60+，options 从 50+ 增长到 ~100+，这个隐式依赖网络将越来越难以安全地维护。

### 为什么需要它

1. **长期可维护性拐点**：30 个 options 时可以靠大脑记忆 ordering 约束。100 个 options 时不可能。需要显式阶段 + 依赖图来防止"某次重构后 applyAuditSinkTaps 在某个新 apply* 之前被调用"这类错误。
2. **启动时故障检测**：目前 Server 构造从不失败（不返回 error）。所有启动期错误都是静默吞没的（nil-skip）。一个期望 CAEP 工作但忘记 wired auditor 的部署直到生产运行时才发现缺少事件——这应该是启动时告警甚至拒绝启动。
3. **插件/扩展的 enabler**：随着 SDK 被外部开发者扩展（`WithXxx` 来自不同包），隐式 ordering 约束成为不可跨越的障碍。显式阶段管理是"SDK 可扩展性"的前提条件。
4. **测试可观察性**：测试中 `NewServer(opts...)` 出错时，当前得不到"option X 需要先设置 Y"的错误信息——得到的是一个 nil deref 或静默行为。

### 代码级缺口

```bash
# 全代码库 grep 核验
grep -rn "option.*order\|option.*depend\|option.*phase\|apply.*order\|apply.*seq\|phase.*manager\|boot.*phase\|startup.*stage\|boot.*stage\|wiring.*graph\|dep.*graph" docs/requirements/*.md
# → 0 命中
```

| 概念 | 命中 |
|---|---|
| `option.*order\|option.*depend\|option.*phase\|option.*stage` | **0** |
| `apply.*order\|apply.*sequen\|apply.*depend` | **0** |
| `phase.*manager\|boot.*phase\|startup.*phase\|startup.*stage\|boot.*stage` | **0** |
| `wiring.*graph\|dep.*graph\|dependency.*graph\|option.*graph` | **0** |
| `option.*validat\|option.*check\|option.*guard\|option.*assert`（启动时 validation） | **0** |

### 范围

| 分层 | 组件 | 说明 |
|---|---|---|
| **Phase 定义** | `newType Phase int` + 预定义常量 | `PhaseBase`（零值初始化）→ `PhaseOptions`（应用 options）→ `PhaseValidate`（依赖完备性检查）→ `PhaseWire`（apply* 交叉连接）→ `PhaseReady`（就绪检查注册）。每个 phase 有明确的 entry gate 和 exit gate |
| **依赖声明** | 每个 `With*` option 可选择声明依赖 | `WithCAEPTransmitter(store)` 声明 `DependsOn(PhaseWire, "WithAuditRecorder")`——如果 auditor 不存在，在 `PhaseValidate` 输出告警。非侵入式：不声明的 option 按当前行为运行 |
| **延迟注册** | `apply*` 不再在 `NewServer` 结尾统一调用 | 改为每个 `apply*` 注册一个 phase 回调（`s.onPhase(PhaseWire, s.applyFederationAutoRegistration)`），确保按 phase 顺序执行 |
| **启动告警收集器** | `StartupWarning` 列表 | 收集非致命但值得注意的启动状态（如 "CAEP transmitter wired without auditor——events will not be forwarded"），在 `Handler()` 首次调用时输出到日志和指标。可选提升为硬错误（`WithStrictStartup`） |
| **依赖可视化** | `s.DependencyGraph() string` 调试端点 | 输出 DOT 格式或文本格式的 option-apply 依赖图，帮助开发者理解启动顺序 |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 现有代码零改动 | Phase 系统是**新增的、可选的**。不调用 `WithPhaseManager` 的 Server 按当前行为运行。`Phase` 类型零值为 `PhaseLegacy`，跳过所有 phase gate |
| 第三方 With* 与内部 apply* 的交互 | 第三方 option 只能注册到 `PhaseOptions`，不能注册到 `PhaseWire`——wire 阶段的回调是 SDK 内部的 |
| Circular dependency detection | 依赖图是 DAG；检测到 cycle 时 `PhaseValidate` 返回 `ErrCircularDependency`，中断启动 |
| Phase 超时 | `PhaseWire` 可能涉及网络操作（如 federation 自动注册需要解析 trust chain）。需要 phase-level context + timeout |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 生产影响 | 中——不改变运行时行为，但显著降低长期维护成本和启动期故障定位时间 |
| 改动量 | 中——新增 `phase.go`（~200 行）+ 修改 `sso.go` 的 `NewServer`（~50 行）+ 每个 `apply*` 改为 phase 注册（各 ~5 行） |
| 与已有架构的契合度 | 高——零侵入式设计，只影响构造时间 |
| 与已有分析的差异性 | ✅ **本报告独有**（23+ 轮分析从未提及启动编排与阶段管理） |

---

## 方向二：后台运行时生命周期可观测生态（Background Runtime Lifecycle Observatory）

> **全代码库核验：此方向在全部 23+ 轮历史分析中零提及**（grep: `background.*loop\|goroutine.*lifecycle\|loop.*lifecycle\|goroutine.*health\|loop.*health\|background.*health\|background.*observab\|loop.*observab\|goroutine.*observab` 在所有 `docs/requirements/*.md` 中 **0 命中**）。

### 现状

项目有 15+ 个后台 goroutine 循环，覆盖了关键的基础设施功能：

| 后台循环 | 代码位置 | 生命周期管理 | 健康可见性 |
|---|---|---|---|
| 签名密钥聚合订阅 | `signing_key_aggregation_loop.go` | ctx cancel + stop chan ✅ | ❌ 无 |
| 失效总线订阅 | `server_invalidation.go` | ctx cancel + stop chan + backoff ✅ | ❌ 无 |
| 协调式密钥轮换 watcher | `server_key_rotation.go` | ctx cancel + stopped chan ✅ | ❌ 无 |
| NetPolicy classifier watch | `server_admin_handlers.go` | ctx cancel + stop chan ✅ | ❌ 无 |
| 数据保留 sweep | `server_backup.go` | ctx cancel + ticker ✅ | ❌ 无 |
| Session trust 连续验证 | `server_login_gates.go` | ctx cancel ✅ | ❌ 无 |
| Break-glass sweeper | `break_glass.go` | ctx cancel + done chan ✅ | ❌ 无 |
| 审计保留调度器 | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| 快照保留调度器 | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| DR 复制调度器 | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| Push 审批清理 | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| CIBA 请求清理 | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| Refresh grace 清理 | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| 凭证轮换调度器 | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| 配置 drift 检测 | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| Token anomaly sweep | `shutdownSchedulers` | ctx cancel + done chan ✅ | ❌ 无 |
| JWKS 客户端缓存刷新 | `remote/jwks.go` | ctx cancel ✅ | ❌ 无 |
| ECDSA/RSA/Ed25519 轮换 | `*_rotation_scheduler.go` | ctx cancel ✅ | ❌ 无 |
| 数据保留 retention sweep | `server_backup.go` | ctx cancel + ticker ✅ | ❌ 无 |

**每个循环都有良好的生命周期管理（ctx cancel + 关闭通道），但没有任何一个循环向外部暴露其运行状态：**

| 能力 | 覆盖情况 |
|---|---|
| 每个后台循环的「存活」指标（`sso_background_loop_up{name}`） | ❌ **0** |
| 每次循环迭代的耗时直方图（`sso_background_loop_iter_duration_seconds{name}`） | ❌ **0** |
| 循环异常退出的告警（非 ctx cancel 的退出） | ❌ **0** |
| 当前循环迭代的进度（正在执行的操作） | ❌ **0** |
| 上次成功迭代的时间戳 | ❌ **0** |
| 循环中 panic 的捕获和上报 | 部分（个别 loop 有 `defer recover()`，大多数没有） |
| 集中式循环注册表（for 健康检查 / 自诊断） | ❌ **0** |

**这意味着：如果一个后台循环静默崩溃（例如 signing-key aggregation subscriber 因 etcd 连接超时而 panic 退出），没有任何告警通知运维人员。直到几分钟后发现新轮换的签名密钥未被拾取才意识到问题。**

### 为什么需要它

1. **"看不见的"故障是最危险的**：一个崩溃的后台循环通常不会立即影响用户请求——签名密钥仍然有效（缓存的）、令牌仍可验证（cache hit）、租户缓存仍存活着。但平台的**控制面操作**（密钥轮换、租户变更传播、策略更新）逐渐失效。这种故障模式被称为 "缓慢退化"（slow degradation），是身份平台最致命的故障模式之一——因为没人注意到它在变坏。
2. **现有 shutdown 编排已经做了生命周期管理的 70%**：shutdownSubsystems 中的 `stopScheduler` 模式已经证明了后台循环的管理模式（cancel + done chan）。**剩下的 30% 是完全缺失的运行时健康可见性**——这是投入产出比极高的工作。
3. **操作手册的盲区**：在 incident response 中，"检查所有后台循环是否正常运行"应该是运维人员的第一个诊断步骤。当前没有任何工具能回答这个问题。

### 代码级缺口

```bash
# 全代码库 grep 核验
grep -rn "background.*loop\|goroutine.*lifecycle\|loop.*health\|background.*health\|loop.*observab\|goroutine.*observab" docs/requirements/*.md
# → 0 命中
```

| 概念 | 代码命中 |
|---|---|
| `background.*loop.*health\|loop.*up\|loop.*alive\|loop.*running` | **0** |
| `goroutine.*lifecycle\|goroutine.*registry\|goroutine.*manager` | **0** |
| `iter.*duration\|loop.*duration\|loop.*latency`（后台循环的） | **0** |
| `loop.*panic\|loop.*crashed\|loop.*failed\|loop.*exited`（告警上下文） | **0** |
| `last.*success.*time\|last.*iteration\|last.*heartbeat` | **0** |

### 范围

#### 1. BackgroundLoop SPI（`platform/lifecycle/background/loop.go`）

一个轻量接口，所有后台循环实现：

```go
type Loop interface {
    Name() string
    Run(ctx context.Context) error   // blocks; returns on ctx cancel or fatal error
}

// LoopObserver is embedded in Server for health/observability.
type LoopRegistry struct {
    mu     sync.Mutex
    loops  map[string]*trackedLoop
}

type trackedLoop struct {
    Loop
    startedAt    time.Time
    lastOK       time.Time
    iterCount    atomic.Int64
    lastErr      error
    panicCount   atomic.Int64
}
```

不要求所有现有循环立即迁移——LoopRegistry 是**增量采用的**。新建的循环使用它；现有循环在重构时自然迁移。

#### 2. 指标与健康端点

| 指标 | 类型 | 说明 |
|---|---|---|
| `sso_background_loop_info{name}` | Gauge | 1 表示注册且存活 |
| `sso_background_loop_iter_total{name,status}` | Counter | 每次迭代计数，status=ok/error/panic |
| `sso_background_loop_iter_duration_seconds{name}` | Histogram | 迭代耗时 |
| `sso_background_loop_last_success_timestamp{name}` | Gauge | Unix 时间戳 |
| `sso_background_loop_panics_total{name}` | Counter | panic 总数 |

`GET /debug/loops` 管理端点（需要 admin:read）返回每个后台循环的状态详情的 JSON：

```json
{
  "loops": [
    {
      "name": "signing_key_aggregation",
      "status": "running",
      "uptime_seconds": 86400,
      "last_success": "2026-07-11T12:00:00Z",
      "iter_count": 1234,
      "last_error": "",
      "panic_count": 0
    },
    {
      "name": "invalidation_bus",
      "status": "backoff",
      "uptime_seconds": 3600,
      "backoff_remaining": "5s",
      "last_error": "etcd: connection refused",
      "panic_count": 0
    }
  ]
}
```

#### 3. 后台循环的熔断告警

基于 LoopRegistry 构建 Prometheus alerting rules：

- `sso_background_loop_info == 0` → 循环未注册（可能是启动失败）
- `sso_background_loop_panics_total > 0` → 循环发生过 panic（需要调查）
- `sso_background_loop_last_success_timestamp > 5m` → 循环超过 5 分钟未成功迭代
- `sso_background_loop_iter_total{status=error} > 10` → 循环连续失败

#### 4. shutdown 一致性的验证锁

目前 shutdown 编排中，每个子系统都有自己的 cancel + done chan + wait。LoopRegistry 可以作为这种模式的**标准化框架**——所有后台循环通过同一个 `LoopRegistry.Start(ctx, loop)` 启动，返回的 `stop` 函数统一在 shutdown 流程中使用。

### 边界情况

| 场景 | 处理策略 |
|---|---|
| 循环在短期 backoff 中（如 etcd 瞬断） | `last_error` 记录但不触发告警直到超过阈值。状态为 `backoff` 而不是 `error` |
| 循环正常退出（ctx cancel） | `lastOK` 保留最后成功时间，状态为 `stopped`——不触发告警 |
| 循环 panic 且 recover 后继续 | panic counter +1，然后循环继续；panic 次数超过阈值后自动降级 |
| 循环从未成功运行过（启动失败） | `startedAt` 设置但 `lastOK` 为零值，状态为 `starting`；超过启动超时后变为 `failed` |
| 高频率循环（每秒多次迭代） | 指标收集自带 rate-limiting：每 10 次迭代采样一次 duration，或使用 `ratelimit` 的 `Sometimes` |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 生产影响 | **高**——后台循环静默崩溃是生产环境最可怕的故障模式之一；本方向直接将这个盲区变为可视化 |
| 改动量 | 中——`platform/lifecycle/background/` 新包（~300 行）+ 每个后台循环适配（各 ~20 行）+ `/debug/loops` 端点（~50 行） |
| 与已有架构的契合度 | 高——复用 `cmd/sso-server/main_shutdown.go` 的 `stopScheduler` 模式，将其提升为一等公民 |
| 与已有分析的差异性 | ✅ **本报告独有**（23+ 轮分析从未提及后台运行时生命周期可观测） |

---

## 方向三：多后端 Schema 版本治理（Multi-Backend Schema Version Governance）

> **全代码库核验：** 已有分析 `expansion-systemic-quality-horizon.md` 方向一覆盖了 **二进制升级健康框架**（pre-flight check、canary rollout、rollback），聚焦于**部署过程的安全性**。本方向聚焦于**运行时的多后端 schema 版本一致性与健康**——一个正交但互补的维度。grep `cross.*store.*migrat\|global.*schema.*version\|schema.*version.*coordinat\|migrate.*order\|migration.*order\|schema.*governance` 在所有已有分析中 **0 命中**。

### 现状

项目的 schema 迁移系统（`platform/migrate/migrate.go`）是设计良好且成熟的：

- 每个后端拥有自己的迁移序列和版本号
- 每张表/每组表是一个独立的 `namespace`（如 `sessions`、`ciba_requests`、`consent`）
- 迁移是 forward-only 的，打包在一个 `BEGIN IMMEDIATE` 事务中

**目前注册的 migration namespaces（不完全统计）：**

| 后端 | Namespace 示例 | 数量估计 |
|---|---|---|
| `infrastructure/defaultimpl/sqlite/` | sessions, consent, ciba_requests, jti_replay, par, refresh_tokens, password_credentials, totp_enrollment, email_change, password_reset, invitations, recent_login, tenant_user, client_secret, push_approvals, ... | 20+ |
| `interfaces/ratelimit/sqlite_limiter.go` | rate_limit | 1 |
| `platform/audit/sqlite/` | audit (×2 基表) | 1 |
| `platform/signingkeys/sqlite/` | signing_keys | 1 |
| `infrastructure/postgres/migrate.go` | postgres（跨 store 共享命名空间） | 10+ |
| `infrastructure/saml/*sqlite/` | saml_sp, saml_idp | 2+ |
| `domains/connections/sqlite/` | connections | 1+ |

**迁移系统的成熟度与运行时治理之间存在显著差距：**

| 治理能力 | 状态 |
|---|---|
| **每个 namespace 的当前 schema 版本查询** | ✅ `migrate.CurrentVersion()` 存在 |
| **所有 namespace 版本一致性检查** | ❌ **无**——没有一个 API 回答 "所有后端的 schema 版本是否与二进制兼容" |
| **schema 版本与二进制版本的交叉验证** | ❌ **无**——`CurrentVersion()` 注释提到这是 readiness gate，**但零调用方** |
| **跨副本的 schema 版本不一致检测** | ❌ **无**——集群中不应该出现两个副本使用不同 schema 版本的情况（应该被 etcd lease+版本检查阻止） |
| **ns 之间 schema 版本依赖**（如 sessions v3 依赖 consent v2） | ❌ **无**——这是很多运维事故的来源 |
| **schema 健康端点** | ❌ **无**——运维人员无法用 `GET /readyz` 或 `sso-ctl` 检查所有后端的 schema 版本状态 |
| **迁移顺序执行保证**（各 store 初始化时的迁移顺序） | ❌ **无**——每个 store 在其 `New*Store` 中自行调用 `migrate.Run`；如果一个 store 的迁移依赖于另一个 store 的表结构，没有机制确保顺序 |

### 为什么需要它

1. **完全在同一个进程中的 20+ 个独立 schema 版本**：在单体部署中，所有 SQLite store 共享同一个文件（`SharedDB`），但每个 store 管理自己的版本。一个 store 迁移后另一个 store 的查询可能因为外键约束、共享表结构变化或索引变更而失败。当前没有任何运行时检查能检测到这种**跨 store 的 schema 不兼容**。
2. **`CurrentVersion` 是已实现但零调用的安全原语**：代码中有一个完整的 readiness gate（`migrate.CurrentVersion`），注释明确说 "a readiness gate that refuses to serve when the binary expects a newer schema"——但从未在任何 readiness check 中调用。这是已投入但浪费的工程资本。
3. **PostgreSQL 和 SQLite 混合部署的版本一致性**：在 `postgres` + `sqlite` 混合部署中，两组后端的 schema 各自演化。没有保证 "postgres consent namespace 版本 3 的语义与 sqlite consent namespace 版本 3 一致"——这是一个等价的语义约束，当前完全靠人工保证。
4. **恢复场景的 schema 版本验证**：从 snapshot 恢复时，如果数据库 schema 版本与二进制不匹配，当前行为是未定义的。`migrate.CheckSchema` 部分处理了这种情况，但缺少一个完整的 schema 兼容性矩阵。

### 代码级缺口

```bash
grep -rn "schema.*version.*check\|schema.*version.*enforc\|global.*schema\|schema.*health\|migrate.*version.*check\|schema.*consistency\|migrate.*compat\|schema.*matrix" docs/requirements/*.md
# → 0 命中（"upgrade health" 分析提到 CurrentVersion 但作为部署流程的一部分，非运行时治理）
```

| 概念 | 代码命中 |
|---|---|
| `schema.*health\|schema.*status\|schema.*endpoint` | **0** |
| `schema.*consistency\|schema.*compat\|cross.*store.*schema` | **0** |
| `migrate.*check.*all\|migrate.*audit\|schema.*audit` | **0** |
| `schema.*version.*matrix\|schema.*compat.*matrix` | **0** |

### 范围

#### 1. Schema 注册表（`platform/migrate/registry.go`）

集中注册所有 migration namespace 及其当前期望的版本：

```go
type SchemaRegistry struct {
    namespaces map[string]int // namespace → expectedMaxVersion
}

func NewSchemaRegistry() *SchemaRegistry
func (r *SchemaRegistry) Register(namespace string, maxVersion int)
func (r *SchemaRegistry) Check(ctx context.Context, db Querier) SchemaHealth
```

每个 `New*Store` 在创建时注册自己的 namespace + 版本号：

```go
func NewSessionStore(db *sql.DB) (*SessionStore, error) {
    if err := migrate.Run(ctx, db, "sessions", sessionMigrations); err != nil { ... }
    schema.Registry.Register("sessions", len(sessionMigrations))
    // ...
}
```

注册表是 package-level 的全局变量（如同 `sharedDBs`），所以不需要修改 Server 的选项。

#### 2. Schema 健康端点

`GET /debug/schema`（需要 admin:read）返回所有后端的 schema 版本状态：

```json
{
  "binary_version": "v5.2.0",
  "namespaces": {
    "sessions":     { "expected": 4, "actual": 4, "status": "ok" },
    "consent":      { "expected": 2, "actual": 2, "status": "ok" },
    "ciba_requests":{ "expected": 3, "actual": 2, "status": "stale" },
    "rate_limit":   { "expected": 1, "actual": 1, "status": "ok" },
    "audit":        { "expected": 5, "actual": 5, "status": "ok" }
  },
  "overall": "degraded"  // one namespace is stale
}
```

`/readyz` 自动集成 schema health：

```go
s.readyChecks = append(s.readyChecks, namedReadyCheck{
    Name: "schema_version",
    Check: func(ctx context.Context) error {
        health := schema.Registry.Check(ctx, s.db)
        if health.Overall != "ok" {
            return fmt.Errorf("schema health: %s", health.Overall)
        }
        return nil
    },
})
```

#### 3. 迁移顺序编排

当前每个 store 在 `New*Store` 中自行调用 `migrate.Run`，顺序由 options 的调用顺序决定。Schema Registry 可以被赋予 namespace 之间的依赖关系：

```go
schema.Registry.DependsOn("sessions", "consent") // sessions 迁移依赖 consent 先完成
```

当 `Check()` 发现依赖的 namespace 版本更低时，返回 `ErrSchemaDependencyUnsatisfied`。

#### 4. PostgreSQL + SQLite 之间的等价校验器

一种轻量的**语义等价校验机制**——不比较 SQL schema（完全不同），而是比较两个后端上的同一 namespace 的 expected version。如果 `postgres.sessions == 4` 且 `sqlite.sessions == 3`，这表明两个后端的 schema 版本有差异——可能是部署时漏掉了其中一个后端的迁移。

### 边界情况

| 场景 | 处理策略 |
|---|---|
| 某个 namespace 完全未注册（store 未初始化） | Registry 中标记为 `unavailable`，不视为 fatal——可能是该 feature 未启用 |
| 多个 *sql.DB 实例上的同一个 namespace 版本不同 | `Check()` 接受多个 `Querier`，每个 namespace 在每个 db 上独立检查 |
| namespace 的 maxVersion 在升级后增加 | 部署新二进制 → schema migration 在新版本执行 → 版本号增加 → 健康检查变为 ok。健康检查在 migrate.Run 之后执行 |
| 降级部署（新二进制 → 旧二进制回滚） | `Check()` 发现 actual > expected，返回 `ErrSchemaTooNew`——回滚保护（migrate.CheckSchema 的逻辑已经存在） |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 生产影响 | **高**——schema 不匹配是数据库相关运维事故中最常见的原因之一；在单体部署中 20+ 个独立 namespace 使问题放大 |
| 改动量 | 小-中——`platform/migrate/registry.go`（~150 行）+ 每个 store 加一行 `schema.Registry.Register` + 已有的 `CurrentVersion` 函数复用 |
| 与已有架构的契合度 | 高——复用 `migrate` 包已有的 `CurrentVersion` 和 `CheckSchema` |
| 与已有分析的差异性 | ✅ **本报告独有**（升级健康框架聚焦部署过程安全性；本方向聚焦运行时多后端 schema 版本治理） |

---

## 方向四：配置进化治理（Configuration Evolution Governance）

> **全代码库核验：** 已有 `senior-architect-expansion-v3-identity-system-quality.md` 方向三覆盖了 **配置合规与验证能力**（配置 lint、策略检查、Cross-reference 验证）。本方向聚焦于配置模式的**版本化进化**（schema migration、deprecation、breaking change detection）——一个正交维度。grep `config.*schema.*migration\|config.*version.*bump\|config.*upgrade\|config.*compat.*break\|config.*evolution\|config.*deprecat\|config.*revision` 在所有已有分析中 **0 命中**（"upgrade health" 分析提到了 `config/schema/validate.go` 但作为升级流程中的组件提及，非配置治理维度）。

### 现状

配置架构（`config/` 包）的成熟度：

| 能力 | 状态 |
|---|---|
| YAML 配置文件加载（多层合并：file → env → etcd → flags） | ✅ 实现 |
| 配置 schema 版本（`Config.Version` 字段） | ✅ 定义为 `int`，当前 `CurrentSchemaVersion = 1` |
| Schema 验证（`config/schema/validate.go`） | ✅ 对 `map[string]any` 做结构匹配，报告未知字段和类型不匹配 |
| 热重载（`config/reload/`） | ✅ 7 个 feature gates + logging + rate_limit |
| 配置审计（`platform/configaudit/`） | ✅ 运行时快照、applied 快照、diff、cluster diff、drift 检测 |
| 配置生成（`config/schema/generate.go`） | ✅ 从 `config.Config` 生成 Document（JSON schema 风格的元数据） |

**但配置的长期演化治理存在系统性盲区：**

| 治理能力 | 状态 |
|---|---|
| **`Config.Version` 的运行时强制** | ❌ **零实现**——`Version` 字段被读取，但没有任何代码检查版本是否匹配 `CurrentSchemaVersion`。`config.Load` 只打印一个警告 |
| **配置 schema 的版本迁移路径** | ❌ **零实现**——如果 `v2` 配置格式重命名了某个字段（如 `rate_limit.default_per_sec` → `rate_limit.default_tokens_per_sec`），没有机制自动迁移旧配置 |
| **字段弃用标记与告警** | ❌ **零实现**——无法标记某个字段为 `Deprecated`，在检测到时输出告警 |
| **破坏性变更检测** | ❌ **零实现**——升级后，如果旧配置文件使用了在新版本中移除的字段，没有检查 |
| **热重载 allowlist 的自动验证** | ❌ **零实现**——`config/reload/reload.go` 中的 `safeReloadPaths` 是一个手动维护的字符串列表。没有编译期检查确保该列表与 `config.Config` 的字段结构同步。每次新增字段时，开发者必须记得同时更新 allowlist——否则该字段永不会被热重载 |
| **多版本配置兼容性测试** | ❌ **零实现**——没有 "使用 v1 配置启动 v2 二进制" 的兼容性测试 |
| **Config struct 的字段变更治理** | ❌ **零实现**——重命名字段、移除字段、更改字段类型时，没有机制通知下游消费者或提供迁移路径 |

**`config/config.go` 当前 178 行。其辅助文件（`config/config_*.go`）总约 5100 行，50+ 个 section。** 一个如此大规模且持续演化的配置结构没有版本迁移机制，长期将产生配置兼容性负债。

### 为什么需要它

1. **配置 schema 版本字段存在但不执行**：`Config.Version` 和 `CurrentSchemaVersion` 是投入了工程成本但**没有 runtime effect** 的代码。这是一个"已经修好的门但没有装门框"的情况——只需要一个检查就能变为有意义的 safety gate。
2. **无版本迁移路径限制了配置重构**：今天无法重命名一个配置字段，因为旧配置文件一旦使用了旧字段名就会静默忽略（或报 unknown field 警告）。一个版本化迁移系统允许 "v1 字段 `old_name` → v2 自动映射到 `new_name` + 输出 deprecation 警告"。
3. **热重载 allowlist 的手动维护是 bug 的来源**：每次新增配置字段，如果忘记加入 `safeReloadPaths`，该字段就"碰巧"不是热重载的——直到运维人员在生产环境 SIGHUP 后发现预期要变化的配置没有生效。应该有一个自动化工具（go:generate 或 Test）来验证 allowlist 与 struct 字段的覆盖关系。
4. **多版本部署中的配置兼容性**：在 canary 部署中，旧版二进制使用新版配置文件（或反之），应该有一个明确的兼容性结果（兼容/不兼容/有条件兼容），而不是当前未知的运行时行为。

### 代码级缺口

```bash
grep -rn "config.*schema.*migration\|config.*version.*bump\|config.*upgrade.*path\|config.*deprecat\|config.*compat.*break\|config.*evolution\|config.*revision\|config.*changelog" docs/requirements/*.md
# → 0 命中（配置合规与验证被分析过，但那是配置 lint/policy/validation，不是版本化进化治理）
```

| 概念 | 代码命中 |
|---|---|
| `config.*version.*enforc\|config.*version.*check\|config.*version.*match` | **0** |
| `config.*migrat.*path\|config.*schema.*migrat\|config.*upgrade.*path` | **0** |
| `config.*deprecat\|config.*field.*deprecated\|deprecated.*config\|config.*warn.*deprecated` | **0** |
| `config.*compat.*break\|config.*break.*change\|config.*backward.*compat` | **0** |
| `safeReloadPath.*check\|reload.*allowlist.*check\|reload.*list.*valid` | **0** |
| `config.*version.*test\|config.*compat.*test\|config.*v[0-9].*test` | **0** |

### 范围

#### 1. 配置版本强制（`config/version.go`）

在 `config.Load` 中增加 `Version` 字段的强制检查：

```go
func ValidateVersion(cfg *Config) error {
    switch cfg.Version {
    case 0:
        return ErrVersionMissing // 警告 + 降级兼容模式
    case CurrentSchemaVersion:
        return nil // perfect match
    case 1: // 旧版本：可以自动升级
        return ErrVersionDeprecated // 继续加载，但输出明确的 deprecation 指引
    default:
        if cfg.Version > CurrentSchemaVersion {
            return ErrVersionTooNew // 二进制太旧，不兼容
        }
        return ErrVersionUnknown
    }
}
```

配合 `WithStrictConfigVersion` Option——在严格模式下，版本不匹配使 `NewServer` 返回错误（当前 `NewServer` 从不失败）。

#### 2. 配置迁移注册表（`config/migrate/`）

一个可选的迁移管线，支持配置版本之间的自动升级：

```go
// config/migrate/migrate.go
type Migration struct {
    FromVersion int
    ToVersion   int
    Migrate     func(*Config) error
}

func Run(cfg *Config, migrations []Migration) error
```

例如 `v1` → `v2` 迁移：

```go
migrations = append(migrations, configmigrate.Migration{
    FromVersion: 1,
    ToVersion:   2,
    Migrate: func(cfg *Config) error {
        // v1 → v2: "rate_limit.max_requests_per_second" renamed to "rate_limit.max_tokens_per_second"
        if cfg.Version == 1 {
            cfg.RateLimit.MaxTokensPerSecond = cfg.RateLimit.MaxRequestsPerSecond
            cfg.RateLimit.MaxRequestsPerSecond = 0 // zero = unused in v2
        }
        return nil
    },
})
```

迁移管线在配置加载后、Server 构造前运行。输出迁移日志和 deprecation 告警。

#### 3. 字段弃用注解与告警

在 Config struct 中使用注释标记弃用字段：

```go
type RateLimitConfig struct {
    // Deprecated: use MaxTokensPerSecond instead. Will be removed in v3.
    MaxRequestsPerSecond int `yaml:"max_requests_per_second,omitempty"`
    MaxTokensPerSecond   int `yaml:"max_tokens_per_second,omitempty"`
}
```

一个 `go:generate` 命令（`config/schema/deprecation_check.go`）解析 Config struct，提取 `Deprecated:` 注释，生成一个运行时检查函数。在配置加载时检查弃用字段是否被使用，输出结构化告警。

#### 4. 热重载 allowlist 的自动化验证

添加一个 `TestHotReloadAllowlistCoverage` 测试，它：

1. 反射 `config.Config` 的所有字段路径
2. 与 `safeReloadPaths` 列表做对比
3. 报告每个**未在 allowlist 中的不在 Config 中的路径**（dead allowlist entry）和每个**在 Config 中但不在 allowlist 中的安全字段**（缺失的 allowlist entry）

#### 5. 配置兼容性测试框架

在 `test/configcompat/` 中添加：

- 一个目录 `testdata/configs/`，按版本存放样例配置文件：`v1_full.yaml`、`v2_full.yaml`
- 一个测试 `TestConfigVersionCompat` 尝试用当前版本的 `config.Load` 加载所有旧版本的配置文件，验证没有 panic 或数据丢失
- 一个测试 `TestConfigRoundTrip`：加载 → 序列化 → 重新加载，验证 round-trip 保真度

### 边界情况

| 场景 | 处理策略 |
|---|---|
| 旧版本配置使用了已移除的字段 | 迁移注册表中的 Migrate 函数处理移除；无迁移路径的未知字段在 Validate 阶段报告 `ErrFieldRemoved` |
| Deprecated 字段同时被旧值和新值设置 | 输出告警，新值胜出，旧值被忽略（与现有 yaml 解码行为一致） |
| 配置版本 0（无版本声明的旧配置文件） | 宽限模式：加载 + 告警，建议设置 `version: N` |
| 配置迁移失败（Migate 函数返回 error） | 加载失败——输出迁移错误详情，建议手动更新配置文件或恢复旧版本二进制 |
| 热重载 allowlist 中新增的字段 | Test 在 CI 中捕获——如果 PR 新增了一个配置字段但没有更新 allowlist，CI 失败 |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 生产影响 | 中-高——防止配置回退兼容性问题、弃用字段导致的混淆、热重载不生效等长尾但烦人的生产问题 |
| 改动量 | 中——`config/version.go`（~50 行）+ `config/migrate/` 新包（~150 行）+ `go:generate` 弃用检查（~100 行）+ 热重载 allowlist 测试（~50 行）+ 兼容性测试（~100 行） |
| 与已有架构的契合度 | 高——配置加载管线是现有的；`config/schema/` 已经做了 50% 的工作 |
| 与已有分析的差异性 | ✅ **本报告独有**（配置合规与验证被分析过，但那是 lint/policy 维度，非版本化进化治理） |

---

## 方向五：运行时依赖完备性验证（Runtime Dependency Completeness Validation）

> **全代码库核验：此方向在全部 23+ 轮历史分析中零提及**（grep: `nil.*check.*server\|nil.*guard.*option\|option.*validat\|option.*check.*nil\|missing.*store.*check\|dep.*complet.*check\|server.*complet.*valid\|wiring.*validat` 在所有 `docs/requirements/*.md` 中 **0 命中**）。

### 现状

`NewServer` 的 Options 模式允许用户选择性注册 store、issuer 和其他依赖。**但没有完备性验证**：

| 依赖 | 是否必需的？ | 缺失时的当前行为 |
|---|---|---|
| `WithUserProvider` | **是**（大多数端点） | 运行时 nil deref panic |
| `WithClientStore` | **是**（所有 OAuth 端点） | 运行时 nil deref panic |
| `WithSessionManager` | **是**（登录 session） | 运行时 nil deref panic |
| `WithTokenIssuer("jwt", ...)` | **是**（签发令牌） | 运行时 degenerate 行为（策略找不到 issuer） |
| `WithDefaultTokenStrategy(...)` | **是**（签发令牌） | 运行时 `defaultTokenStrategy` 为空 → token 端点 panic |
| `WithIDTokenIssuer(...)` | **如果 OIDC 启用** | OIDC 端点运行时 nil deref |
| `WithRateLimitPolicy(...)` | **否**（可选） | 无限制（安全但允许） |
| `WithMetrics(...)` | **否**（可选） | 指标缺失 |
| `WithAuditRecorder(...)` | **否**（可选） | 审计缺失 |

**关键缺失：**

```go
// NewServer 的结尾——无任何 validation step
func NewServer(opts ...Option) *Server {
    // ...
    for _, opt := range opts { opt(s) }
    // ... apply* helpers ...
    // ❌ 没有 s.validateDependencies()
    return s
}
```

**缺失的校验应该包括：**

| 校验 | 说明 |
|---|---|
| `s.userProvider == nil` → 构造失败 | 没有用户提供者，所有认证端点将 panic |
| `s.clientStore == nil` → 构造失败 | 没有客户端存储，所有 OAuth/OIDC 端点将 panic |
| `s.sessionMgr == nil` → 构造失败 | 没有 Session 管理器，登录流程将 panic |
| `s.tokenIssuers["jwt"] == nil` 但 `s.defaultTokenStrategy == "jwt"` → 构造失败 | 声明了默认策略但没有对应 issuer |
| `s.auditor != nil && s.caepTransmitter != nil && !s.auditor.HasSink(s.caepTransmitter)` → 启动告警 | CAEP transmitter 已 wired 但没有加入 auditor 的 sink 链（当前被 applyAuditSinkTaps 处理，但如果 apply 顺序不对则静默丢失） |
| `s.federationEntity != nil && s.clientStore == nil` → 构造失败 | Federation 需要 ClientStore |
| `s.oidcOn() && s.idTokenIssuer == nil` → 构造失败 | OIDC 启用但没有 ID Token 签发者 |

### 为什么需要它

1. **"Fail fast" 原则**：当前 Server 构造从不失败。所有依赖缺失都会延迟暴露——通常是在第一个用户请求到来时，表现为一个 nil pointer dereference 导致的 HTTP 500。对于身份服务器，更早地失败（在启动时）比在生产请求中失败要好无数倍。
2. **100+ options 的记忆负担**：随着 options 数量增长，用户（和测试作者）越来越容易忘记包含某个必需的 With* 调用。一个明确的 `Validate()` 调用在构造时提供清晰的错误消息："WithClientStore is required—add it to opts"。
3. **SDK 的可发现性**：对 SDK 的新用户来说，"NewServer 需要哪几个最小 options？" 不是通过阅读文档知道的——它应该由构造器本身强制执行。当前的经验法则只是 "如果没有 panic 就是对的"。
4. **测试的准确度**：测试中构造 Server 时常省略非必要的 store。如果一个测试后来开始使用 feature X，但没有添加对应的 With*，测试会在运行时 panic 而不是在 setup 时失败。这降低了对测试失败的根本原因判断速度。

### 代码级缺口

```bash
grep -rn "nil.*check.*server\|nil.*guard.*option\|option.*validat\|option.*check.*nil\|missing.*store.*check\|dep.*complet.*check\|server.*complet.*valid\|wiring.*validat" docs/requirements/*.md
# → 0 命中
```

| 概念 | 代码命中 |
|---|---|
| `option.*valid\|option.*assert\|option.*guard\|option.*require` | **0** |
| `nil.*check.*server\|server.*nil.*check`（启动时验证） | **0** |
| `depend.*complet\|depend.*valid\|dep.*valid\|dep.*missing` | **0** |
| `must.*have.*provider\|must.*have.*store\|must.*have.*issuer\|required.*provider` | **0** |

### 范围

#### 1. `Server.Validate()` 方法

```go
type ValidationError struct {
    Severity ValidationSeverity // Fatal | Warning
    Message  string
    Field    string // 便于定位的字段路径，如 "Server.tokenIssuers['jwt']"
}

type ValidationSeverity int
const (
    ValidationWarning ValidationSeverity = iota
    ValidationFatal
)

func (s *Server) Validate() []ValidationError {
    var errs []ValidationError

    // === FATAL: 没有这些依赖 Server 无法工作 ===
    if s.userProvider == nil {
        errs = append(errs, ValidationError{
            Severity: ValidationFatal,
            Message:  "UserProvider is required for all authentication flows",
            Field:    "Server.userProvider",
        })
    }
    if s.clientStore == nil {
        errs = append(errs, ValidationError{
            Severity: ValidationFatal,
            Message:  "ClientStore is required for all OAuth/OIDC endpoints",
            Field:    "Server.clientStore",
        })
    }
    if s.sessionMgr == nil {
        errs = append(errs, ValidationError{
            Severity: ValidationFatal,
            Message:  "SessionManager is required for login sessions",
            Field:    "Server.sessionMgr",
        })
    }
    if len(s.tokenIssuers) == 0 {
        errs = append(errs, ValidationError{
            Severity: ValidationFatal,
            Message:  "At least one TokenIssuer is required (use WithTokenIssuer)",
            Field:    "Server.tokenIssuers",
        })
    }
    if _, ok := s.tokenIssuers[s.defaultTokenStrategy]; s.defaultTokenStrategy != "" && !ok {
        errs = append(errs, ValidationError{
            Severity: ValidationFatal,
            Message:  fmt.Sprintf("Default token strategy %q not found in token issuers", s.defaultTokenStrategy),
            Field:    "Server.defaultTokenStrategy",
        })
    }

    // === WARNING: 非缺失但配置可能不符合预期 ===
    if s.auditor != nil && s.caepTransmitter != nil && !s.auditor.HasSink(s.caepTransmitter) {
        errs = append(errs, ValidationError{
            Severity: ValidationWarning,
            Message:  "CAEP transmitter wired but not connected to audit sink chain—events will not be forwarded",
            Field:    "Server.caepTransmitter",
        })
    }
    if s.oidcOn() && s.idTokenIssuer == nil {
        errs = append(errs, ValidationError{
            Severity: ValidationFatal,
            Message:  "OIDC enabled (FeatureGates.OIDC) but no ID Token issuer configured (WithIDTokenIssuer)",
            Field:    "Server.idTokenIssuer",
        })
    }

    return errs
}
```

#### 2. `NewServer` 中的 integration

```go
func NewServer(opts ...Option) *Server {
    s := &Server{}
    // ... existing init ...
    for _, opt := range opts { opt(s) }
    // ... existing apply* helpers ...
    if errs := s.validateDependencies(); len(errs) > 0 {
        for _, e := range errs {
            s.logger.Error("server validation", "severity", e.Severity, "message", e.Message, "field", e.Field)
        }
        // Fatal 级别的错误通过一个 package-level 函数处理
        if hasFatal(errs) {
            if s.bootFailHandler != nil {
                s.bootFailHandler(errs)
            } else {
                // 默认行为：log.Fatal（在测试中用 WithBootFailHandler 替换为 t.Fatal）
                log.Fatalf("server initialization failed: %v", errs)
            }
        }
    }
    return s
}
```

为测试添加 `WithBootFailHandler(func([]ValidationError))` Option，允许测试捕获启动错误而非 fatal：

```go
var validationErrors []ValidationError
srv := sso.NewServer(
    sso.WithUserProvider(...),
    // 故意遗漏 ClientStore
    sso.WithBootFailHandler(func(errs []ValidationError) {
        validationErrors = errs
    }),
)
// → validationErrors 包含 "ClientStore is required"
```

#### 3. 条件性必需依赖的声明式表达

对于非总是必需但在特定条件下必需的依赖（如 `idTokenIssuer` 在 OIDC 启用时必需），使用 Option 上的元数据表达：

```go
func WithFeatureGates(g FeatureGates) Option {
    return func(s *Server) {
        // ...
        if g.OIDC != nil && *g.OIDC {
            s.registerConditionalRequirement("idTokenIssuer", "WithIDTokenIssuer required when OIDC feature gate is enabled")
        }
    }
}
```

`validateDependencies()` 遍历这些条件性要求。

#### 4. `sso-ctl config validate` 的扩展

现有的 `sso-ctl config validate-schema` 命令扩展为 `sso-ctl config validate-server`，它在不启动 HTTP 服务器的情况下构造一个 `Server` 并运行 `Validate()`，输出所有验证错误。这允许在 CI/CD 流水线的部署前阶段检查配置完整性。

### 边界情况

| 场景 | 处理策略 |
|---|---|
| 某些依赖在「存储降级」模式下可选 | `degradation.Policy` 影响必需性判定——如果降级策略禁用了所有需要 userProvider 的端点，则 `userProvider` 可为 nil |
| 第三方自定义 Store 在测试中用 mock 替代 | 验证系统只检查接口是否为 nil——mock 实现了接口则不触发验证错误 |
| 迟初始化（lazy init）的 store | 使用 `LazyDependency` 包装器：在首次使用时初始化，在 `Validate()` 阶段检查包装器的初始化函数是否已设置 |
| 降级部署中的验证（只运行管理 API，不运行 OAuth） | 验证允许用户通过 `WithDegradationPolicy` 声明哪些部分是禁用的——禁用的部分的依赖被标记为可选 |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 生产影响 | **高**——将运行时 nil deref panic 转换为启动时明确的构造失败，对生产可靠性和开发者体验有直接提升 |
| 改动量 | 小——`Server.Validate()` 方法（~100 行）+ `NewServer` 中调用 + `WithBootFailHandler` Option（~20 行）+ `sso-ctl` 扩展（~30 行） |
| 与已有架构的契合度 | 高——不改变现有 Option 模式，只在构造的最后阶段增加一个检查步骤 |
| 与已有分析的差异性 | ✅ **本报告独有**（23+ 轮分析从未提及运行时依赖完备性验证） |

---

## 优先级排序与实施建议

### 按"投入产出比"排序

| 优先级 | 方向 | 为什么先做 | 预期工作量 | 依赖 |
|---|---|---|---|---|
| **P0** | 方向五：运行时依赖完备性验证 | **投入最小、价值最高**——~100 行 `Validate()` 方法即可将大量运行时 nil deref panic 转换为启动时明确错误。所有开发者和测试立即受益 | **小（1 周）** | 无 |
| **P1** | 方向二：后台运行时生命周期可观测生态 | 后台循环静默崩溃是生产环境最危险的故障模式之一。已有 `stopScheduler` 模式提供 70% 的架构基础，剩下的 30%（健康可见性）投入产出比极高 | 中（2-3 周） | 无 |
| **P2** | 方向三：多后端 Schema 版本治理 | `CurrentVersion` 函数已实现但零调用——这是"已修好但没装门框"的代码。Schema Registry + 健康端点可以在 1 周内提供一个显著的运维改进 | 小-中（1-2 周） | `platform/migrate` 已有 |
| **P3** | 方向一：服务器启动编排与依赖阶段管理 | 长期最重要的方向——它为所有其他四个方向提供了结构化的基础。但短期改动量中等，且当前阶段的隐式 ordering 约束尚未造成严重事故 | 中（2-3 周） | 方向五的 Validate 可作为 PhaseValidate 的入口 |
| **P4** | 方向四：配置进化治理 | 配置版本强制可在 1 天内完成，但完整的迁移管线 + 弃用管理是中到大的工作。在配置文件数量和使用者增多之前，优先级较低 | 中-大（3-4 周） | 需要方向一的 PhaseValidate 来注入配置版本检查 |

### 依赖关系

```
方向五（依赖完备性验证）   ← 独立，无阻塞依赖
     │
     ▼
方向一（启动编排与阶段）   ← 使用方向五的 Validate 作为 PhaseValidate 的入口
     │
     ▼
方向二（后台生命周期）     ← 使用方向一的 phase 系统来注册后台循环
     │
     ▼
方向三（Schema 治理）      ← 使用方向一的 ready check 注册 schema 健康检查
     │
     ▼
方向四（配置进化治理）     ← 使用方向一的 Validate 阶段检查配置版本
```

### 实施建议

1. **方向五的 Wave 1（Validate + 必需依赖检查）可以立即开始**——与所有其他工作并行。只需要在 `sso.go` 中添加一个方法 + 在 `NewServer` 结尾调用它。一周内可交付。
2. **方向二的 Wave 1**（`LoopRegistry` + 指标 + `/debug/loops` 端点）可以独立于 Wave 2（全量迁移现有循环）交付。建议先交付 Wa​​ve 1，然后逐步在重构中迁移现有循环。
3. **方向三的 Wave 1**（`SchemaRegistry` + `/debug/schema` 端点 + `CurrentVersion` 的 readiness 集成）可以在一周内交付。Wave 2（迁移顺序编排 + PostgreSQL/SQLite 等价校验）是后续工作。
4. **方向一的 Wave 1**（仅 Validate 后的 Phase 标记，不改变现有 apply* 顺序）可以安全地对现有代码无入侵。Wave 2（apply* 改为 phase 注册）需要更谨慎的测试。
5. **方向四的 Wave 1**（配置版本强制检查）是一天的工作。Wave 2（迁移管线）和 Wave 3（热重载 allowlist 自动化验证）可以在配置结构下次需要 breaking change 时触发。

---

## 附录：与所有已有分析的方向矩阵对比

| 已有分析文档 | 方向一 | 方向二 | 方向三 | 方向四 | 方向五 |
|---|---|---|---|---|---|
| v1-v13 扩展方向分析 | ❌ | ❌ | ❌ | ❌ | ❌ |
| novel, novel-v2, novel-v3, novel-v4 | ❌ | ❌ | ❌ | ❌ | ❌ |
| post-protocol-layer | ❌ | ❌ | ❌ | ❌ | ❌ |
| production-hardening | ❌ | ❌ | ❌ | ❌ | ❌ |
| systemic-quality-horizon | ❌ | ❌ | ❌（升级健康框架方向正交——二进制部署安全 ≠ 运行时多后端治理） | ✅（配置合规被提及但方向正交——lint/policy ≠ 版本化进化） | ❌ |
| edge-cases | ❌ | ❌ | ❌ | ❌ | ❌ |
| gaps-analysis | ❌ | ❌ | ❌ | ❌ | ❌ |
| ciam-identity-horizon | ❌ | ❌ | ❌ | ❌ | ❌ |
| next-wave-analysis | ❌ | ❌ | ❌ | ❌ | ❌ |
| runtime-infrastructure | ❌ | ❌ | ❌ | ❌ | ❌ |

> **结论：** 本报告 5 个方向在全部 23+ 轮历史分析中均**未被覆盖**，且每个方向都有明确的代码级证据证明其存在真实的工程缺口。

<!-- EOF -->
