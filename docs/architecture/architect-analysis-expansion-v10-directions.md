# 架构分析：v10 扩展方向评估与实现建议

> **分析师：** 架构师代理  
> **依据：** `docs/requirements/expansion-directions-v10-analysis.md`（评估报告）  
> **同行评审版本：** `docs/requirements/expansion-directions-v10-analysis.out.md`（9/10 分）  
> **补充上下文：** `docs/architecture/architect-analysis-expansion-five-directions.md`（前期五方向分析）  
> **日期：** 2026-07-11

---

## 1. 架构评估

### 1.1 当前架构的优势

v10 评估报告未系统评价架构，但五个方向的分析从侧面反映了一个高度成熟的项目。从架构视角看，核心优势体现在：

| 维度 | 体现 | 架构意义 |
|---|---|---|
| **存储后端的正交可替换** | Memory/SQLite/Redis/Postgres 同为四个同级后端 | 存储 SPI 设计足够精良，新增 Postgres OAuth store 不需要新接口——说明核心抽象已经稳定 |
| **可观测性锚点丰富** | W3C Traceparent、OpenTelemetry OTLP、审计 TraceID/SpanID | 基础设施到位后，方向②（OAuth 流级 trace）只需填充语义层，不需要改造管道 |
| **依赖抽象清晰** | 所有下游（LDAP/SAML/KMS/CAEP）通过 SPI 接入 | 方向④（舱壁+断路器）可以每个依赖独立包裹，不需要侵入核心逻辑 |
| **多租户隔离已成基因** | Per-tenant 数据隔离、scope 模型、API 设计 | 方向⑤（跨租户管理）的核心风险是权限模型设计而非基础设施——隔离机制已就位 |
| **审计元数据纪律** | `SetMeta` 禁止直接 map 赋值 | 方向②③⑤都依赖审计来承载增强数据（flow trace/credential health/global audit），现有的元数据管控为扩展提供了可信的基础 |

### 1.2 五个方向反映的架构局限性

v10 评估报告识别了五个独立的缺口。从架构视角聚合，它们暴露了四个**系统级**局限性：

#### 局限性 A：存储后端的非对称完备性

```
Memory     → 所有 store ✅
SQLite     → 所有 store ✅
Redis      → 所有 store ✅
Postgres   → 仅持久化 identity store，无 OAuth ephemeral stores ❌
```

Postgres 是所有后端中最"企业级"的，却在 OAuth 协议核心的短期存储上处于最弱状态。这说明：

- **架构历史债务**：项目"先做了 Redis 后端"（因为 OAuth 短期存储常驻缓存层），但 Postgres 后端的地位在后续演进中从"对标 Redis"降级为"仅持久层"
- **架构决策隐含假设**：部署 Postgres 的用户也愿意部署 Redis——这个假设在企业环境中可能不成立（管控要求、运维成本、安全审计）
- **修复成本极低**：SQLite 已有完整实现（纯 Go、无网络依赖），Postgres 实现本质上是 SQLite 的 DDL 翻译 + 事务隔离级别调整——说明缺口不是技术复杂度问题，而是优先级问题

#### 局限性 B：观测性聚焦请求内，忽略协议流

现有观测性三件套（tracing/metrics/audit）全部在**单次 HTTP 请求**的边界内。OAuth 协议的核心特征——多请求分离（auth → redirect → token exchange）——使得单请求 trace 在重定向处断裂。

这暴露了更深的架构局限：

- **语义鸿沟**：系统理解"请求"，不理解"流"（auth flow、refresh chain、device session）。数据模型（AuthCode、RefreshToken）是个体，缺乏流一级的聚合实体
- **工具链空白**：没有"按流查询"的 API，运维人员只能反向关联（先查登录事件找到 auth_time，再查 token 事件找到 exchange_time）
- **这不是"缺少 trace ID 传播"一个点的修复**，而是需要引入**流 ID（flow_id）**作为一级概念

#### 局限性 C：安全治理的单点化

方向③指出 `CredentialHealth` 是 emit-and-forget。更深层的问题是：

- **告警 ≠ 治理**：系统能检测弱口令、泄露密码、过期凭据，但无法执行策略（force-change、suspend、notify）
- **缺乏闭环**：安全事件（HIBP 命中）→ 聚合 → 决策 → 执行 → 验证，这个链条缺了中间三段
- **凭据异构性未抽象**：密码、secret、API key、证书、WebAuthn 凭据各自有不同的健康定义和修复动作，但没有统一的 `CredentialStore` SPI 来统一管理
- **合规报告是事后手工活**：没有可导出的时间序列数据证明"x% 的用户在 y 天内完成了凭据轮换"

#### 局限性 D：弹性策略的粗粒度

方向④指出缺少通用舱壁和断路器。但更本质的是：

- **弹性是逐个依赖的决策**：不是"全开/全关"的二元切换。现有 `degradation/manager.go` 是全局的——要么全降级，要么全正常——但与实际需求不匹配
- **速率限制 ≠ 弹性**：rate limit 控制"频率"，bulkhead 控制"并发"，circuit breaker 控制"健康感知的自愈"——三者正交，需要组合
- **下游依赖没有健康信号**：当前无法回答"LDAP 健康吗？""KMS 响应正常吗？"。断路器的引入本质上是为每个下游依赖建立健康信号

### 1.3 架构债务量化评估

综合前期五方向分析（session hub 只写不读、授权模型并行不组合、配置验证无回滚）和 v10 分析的五方向，当前架构债务优先级如下：

| 债务 | 来源 | 严重度 | 根因类型 | 修复模式 |
|---|---|---|---|---|
| Postgres OAuth 存储缺失 | v10 方向① | 中 | 非对称实现 | 填补（参考 SQLite 翻译） |
| OAuth 流无 flow_id | v10 方向② | 中 | 缺失概念实体 | 引入 flow_id 作为一级概念 |
| Credential health emit-and-forget | v10 方向③ | 中 | 闭环断裂 | 后台聚合 + 策略引擎 |
| 无通用舱壁/断路器 | v10 方向④ | 中 | 缺失基础设施 | 新构建 shared/bulkhead + shared/circuitbreaker |
| 无跨租户管理面 | v10 方向⑤ | 低-中 | 缺失管理面 | 新构建跨租户 API + 权限 scope |
| Session hub 只写不读 | 前期分析 | 中 | 调用边缺失 | 3-4 处加调用 |
| 授权模型无决策管道 | 前期分析 | 中 | 编排缺失 | 管道 meta-SPI |
| 配置变更无自动回滚 | 前期分析 | 低-中 | 运维流缺失 | pre-flight check + 健康观察窗 |

---

## 2. 扩展方向

本节对 v10 评估报告的五个方向进行架构层面深入评估，按实施依赖关系和架构深度排序，而非简单按价值排序。

### 方向 A：Postgres OAuth 短期存储面补齐 — P1

#### 架构分析

这是五个方向中**架构侵入最小、收益确定性最高**的一个。现有 SQLite 实现是纯 Go、无网络、使用 `database/sql` 接口的，Postgres 实现本质上是：

1. 将 SQLite 专用的 DDL（`INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL PRIMARY KEY`）翻译为 Postgres 方言
2. 将 SQLite 的 `DELETE RETURNING`（Postgres 原生支持）直接复用
3. 将 SQLite 的 `INSERT OR REPLACE` 翻译为 Postgres 的 `INSERT ... ON CONFLICT`
4. Refresh 家族轮换将 SQLite 的 `IMMEDIATE` 事务隔离改为 Postgres 的 `SERIALIZABLE`

**为什么不是 Redis 优先？** 评估报告已充分论证。从架构角度补充一个观点：补齐 Postgres 存储后，项目的存储层达到了**任何后端均可作为唯一后端**的完备状态（Memory/SQLite/Postgres 均可独立运行全功能 OAuth 服务器；Redis 仍需配合一个持久化后端）。

#### 核心设计决策

| 决策点 | 选项 | 推荐 | 理由 |
|---|---|---|---|
| 复用 SQLite 代码 vs 新建 postgres 包 | ① 在 infrastructure/postgres/ 新建文件 ② 在 defaultimpl/ 下共享 base | **① 新建** | SQLite 和 Postgres 的 DDL/驱动/连接池完全不同，共享 base 会导致 condition 爆炸 |
| JTI replay 使用 ON CONFLICT 还是 advisory lock | ① INSERT ON CONFLICT ② pg_try_advisory_xact_lock | **① INSERT ON CONFLICT** | 更简单，与 SQLite 模式一致；advisory lock 在连接池模式下有释放风险 |
| Refresh 家族隔离级别 | ① SERIALIZABLE ② SELECT FOR UPDATE 作为乐观锁 | **① SERIALIZABLE** | 与 CockroachDB 兼容（分布式 SERIALIZABLE 是它的默认），且 SQLite 兄弟也用 `IMMEDIATE` 模式——语义等价 |
| 清理策略 | ① pg_cron ② 应用层周期性 sweep ③ 纯 TTL 被动过滤 | **② 应用层 sweep** | pg_cron 需要扩展、不足以保证所有部署都有；纯 TTL 会导致表膨胀。应用层 sweep 可复用现有的 `Expire` SPI |
| 迁移版本号 | ① 新表一次迁移 ② 逐表迁移 | **② 逐表迁移** | AuthCodeStore 最高频，可独立先上线；CIBAStore 低频，可滞后 |

#### 实现路径

```
infrastructure/postgres/
├── oauth_auth_codes.go      # AuthCodeStore 实现
├── oauth_refresh_tokens.go  # RefreshTokenStore 实现（含家族表）
├── oauth_device_codes.go    # DeviceCodeStore 实现
├── oauth_par.go             # PARStore 实现
├── oauth_ciba.go            # CIBAStore 实现
├── security_jti_replay.go   # JTIReplayStore 实现
├── migrate_oauth.go         # 新表 DDL 迁移
└── oauth_cleanup.go         # 周期性 sweep 协程
```

每个文件 120-180 行（参考 SQLite 兄弟），总计 ~1000 行。

#### 风险

- ⚠️ **SERIALIZABLE 隔离级别的重试逻辑**：Postgres 的 SERIALIZABLE 在冲突时会报 `40001` 错误，需要调用方实现重试。SQLite 的 `IMMEDIATE` 事务则无此问题。如果 Refresh 路径上的重试逻辑未实现，可能引入偶发性的 `invalid_grant` 失败。
- ✅ **CockroachDB 兼容**：上述 SERIALIZABLE + 重试逻辑恰好也是 CockroachDB 的推荐模式——可以只实现一次就兼容两个数据库。

---

### 方向 B：OAuth 流级可观测性 — P1

#### 架构分析

这是五个方向中**架构设计挑战最大**的一个，因为需要引入一个全新的概念实体：**flow_id**。

当前架构的 trace 模型：
```
HTTP Request A (trace_id=TA, span=spanA)          → /auth/login
HTTP Request B (trace_id=TB, span=spanB, 无关联)   → /token?code=...
```

引入 flow_id 后的目标模型：
```
OAuth Flow F-12345 (flow_id=F-12345)
├── Span 1: /auth/login (trace_id=TA, span=spanA, flow_id=F-12345)
├── [浏览器重定向——零服务器可见]
└── Span 2: /token (trace_id=TB, span=spanB, flow_id=F-12345, parent=spanA)
```

**关键问题：flow_id 应该在何时、以何种方式生成？**

| 方案 | 生成时机 | 传递方式 | 优点 | 缺点 |
|---|---|---|---|---|
| **方案 A：state 中编码** | /auth/login 生成 | 加密后嵌入 OAuth `state` 参数，浏览器携带返回 | 与 OAuth 协议天然绑定；不需要修改 AuthCode 数据模型 | state 可选的（response_mode=form_post 无 state）；加密密钥管理成本 |
| **方案 B：AuthCode 自带 flow_id** | /auth/login 生成 flow_id，存储在 AuthCode 中 | Redis/Postgres AuthCode 记录携带 flow_id；/token 兑换时读出 | 数据模型清晰；不依赖浏览器行为 | AuthCode 数据模型需加字段；memory/sqlite/postgres/redis 四个后端全部要改 |
| **方案 C：/token 按 auth_code 逆向索引** | 不在请求时关联，事后由聚合服务匹配 | 按 auth_code 查事件日志关联 | 无需修改任何请求路径 | 延迟关联（分钟级）；依赖日志系统支持 code 索引 |
| **方案 D：独立 Flow Registry** | /auth/login 写入 flow_id + 上下文到新存储 | 独立 flow_registry 表，/token 兑换时查 | 不修改 AuthCode 模型；可存储丰富上下文 | 新增存储实体，增加写路径复杂度 |

**推荐：方案 B（AuthCode 自带 flow_id）+ 方案 A（state 中编码，作为冗余传递路径）**

理由：
- AuthCode 是 OAuth 授权码流的唯一跨请求关联键 —— 用数据模型承载是最自然的
- state 中编码作为补充路径，在处理 state 已存在但 AuthCode 未写入的边界情况时兜底
- 四个存储后端的 AuthCode 都需要加 `FlowID` 字段，但这是每个后端几十行的改动
- flow_id 的生成使用 ULID（时间有序+唯一），支持按时间范围查询

#### 架构组件

```
新增概念:
  shared/core/
  └── flow.go               # FlowID 类型 + FlowEvent 事件类型
  
新增 SPI:
  oauthspi.FlowStore        # 可选的 FlowStore SPI（看是否独立存储 vs AuthCode 承载）
  
修改:
  protocols/oauth/
  ├── handle_auth.go        # 生成 flow_id → 注入 AuthCode
  └── handle_token.go       # 从 AuthCode 读出 flow_id → 设置为父 span
  
  infrastructure/postgres/  # 所有四个后端加 FlowID 字段
  infrastructure/redis/
  defaultimpl/
  infrastructure/sqlite/
  
新增 API:
  interfaces/admin/
  └── flow_api.go           # GET /admin/flows/{flow_id} — 返回完整流信息
```

#### 存储成本

每个 flow_id 大约 50 字节，AuthCode TTL 5 分钟。在 10,000 QPS 的峰值负载下，flow 存储开销：
- 并发 flow 数：10,000 QPS × 300s（5min TTL）= 3,000,000
- 存储增量：3M × 50 字节 ≈ 150MB（内存/Redis）或 300MB（Postgres 含索引）
- **完全可以接受**

#### 扩展路径

```
阶段 1（S）：AuthCode 增加 FlowID → /token 建立父子 span
阶段 2（M）：Admin API GET /admin/flows/{flow_id} + 按 user/code 索引
阶段 3（L）：Admin Console 流调试面板（时序图展示完整请求链）
阶段 4（XL）：SSE 实时流追踪推送（运维人员"订阅"特定用户的流）
```

---

### 方向 C：凭据健康治理与自动修复框架 — P1-P2

#### 架构分析

当前凭据健康状态的架构是**信号型**的：

```
认证路径 →
  recordCredentialHealth(ctx, event) → 审计日志 + Prometheus metric → 结束
```

需要演变为**状态型**架构：

```
认证路径 →
  recordCredentialHealth(ctx, event) → CredentialStatusStore 更新状态
  
后台 Scanner（周期性，不与请求路径耦合）→
  扫描所有凭据 → 更新 CredentialStatusStore → 触发策略评估
  
策略引擎 →
  条件匹配 → 生成 RemediationAction（force_change / force_mfa / suspend）
  
登录路径（修复执行）→
  读取用户待处理修复 → 重定向到强制操作页 → 完成 → 清除修复标记
```

#### 核心设计决策

| 决策点 | 选项 | 推荐 | 理由 |
|---|---|---|---|
| 扫描引擎架构 | ① 单进程 goroutine ② 分布式协调（leader election） | **① 单进程 goroutine** | 凭据扫描不是实时要求；多副本同时扫描也不会造成数据损坏（幂等更新）。leader election 增加复杂度，收益很小 |
| 策略引擎位置 | ① 扫描引擎内嵌 ② 独立策略引擎 SPI | **② 独立 SPI** | 策略是业务规则，扫描是数据收集——分离后策略可独立热加载、独立审计 |
| 修复动作执行时机 | ① 扫描时立即执行 ② 登录路径延迟执行 ③ 异步通知用户 | **② 登录路径延迟执行** | 扫描时执行可能打扰不在线的用户；登录路径执行是自然接触点；异步通知作为补充 |
| 跨凭据类型统一抽象 | ① 每个凭据类型独立 handler ② 统一 Credential SPI | **② 统一 SPI** | `Credential{Type, ID, Owner, LastRotated, HealthScore, Metadata}` 可作为新 SPI 的核心 |
| 合规报告导出 | ① 即时生成（用户查询时聚合） ② 定时快照（每日/每周） | **两者都要** | 即时生成用于管理面查看，定时快照用于外部审计 |

#### 新增 SPI 设计

```go
// shared/core/spi_credential.go

type CredentialType string

const (
    CredentialTypePassword   CredentialType = "password"
    CredentialTypeMFA        CredentialType = "mfa"
    CredentialTypeClientSecret CredentialType = "client_secret"
    CredentialTypeAPIKey     CredentialType = "api_key"
    CredentialTypeWebAuthn   CredentialType = "webauthn"
    CredentialTypeSSHKey     CredentialType = "ssh_key"
    CredentialTypeCertificate CredentialType = "certificate"
)

type CredentialHealthScore int

const (
    CredentialHealthUnknown   CredentialHealthScore = 0
    CredentialHealthHealthy   CredentialHealthScore = 1
    CredentialHealthWarning   CredentialHealthScore = 2
    CredentialHealthCritical  CredentialHealthScore = 3
)

// CredentialStatus represents the current health state of a single credential
type CredentialStatus struct {
    ID           string             `json:"id"`
    Type         CredentialType     `json:"type"`
    OwnerID      string             `json:"owner_id"`      // user ID or client ID
    OwnerType    string             `json:"owner_type"`    // "user" or "client"
    TenantID     string             `json:"tenant_id"`
    HealthScore  CredentialHealthScore `json:"health_score"`
    LastChecked  time.Time          `json:"last_checked"`
    LastRotated  *time.Time         `json:"last_rotated,omitempty"`
    ExpiresAt    *time.Time         `json:"expires_at,omitempty"`
    Metadata     map[string]string  `json:"metadata"`      // type-specific: hibp_count, algorithm, device_type
    Remediation  *RemediationAction `json:"remediation,omitempty"`
}

type RemediationAction struct {
    ID            string    `json:"id"`
    Type          string    `json:"type"`     // force_password_change, force_mfa_enroll, suspend, notify
    Status        string    `json:"status"`   // pending, in_progress, completed, skipped
    CreatedAt     time.Time `json:"created_at"`
    CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

// CredentialStatusStore is the SPI for reading/writing credential health state
type CredentialStatusStore interface {
    GetCredential(ctx context.Context, ownerID string, credType CredentialType) (*CredentialStatus, error)
    ListCredentials(ctx context.Context, ownerID string) ([]*CredentialStatus, error)
    UpdateCredential(ctx context.Context, status *CredentialStatus) error
    ListByHealth(ctx context.Context, maxScore CredentialHealthScore) ([]*CredentialStatus, error)
    GetRemediations(ctx context.Context, ownerID string) ([]*RemediationAction, error)
    ApplyRemediation(ctx context.Context, action *RemediationAction) error
    CompleteRemediation(ctx context.Context, actionID string) error
}
```

这个 SPI 设计是方向③成功的关键。它在 `shared/core` 中（不是 `domains/credentialhealth/`），因为它被多个层引用：认证路径（写）、扫描引擎（读/写）、管理 API（读）、策略引擎（写）。

#### 与方向②的关系

flow_id + credential health data 一起能为安全团队提供完整故事："用户 X 在时间 Y 使用凭据 Z 认证，flow_id=F-12345，凭据健康状况 = Warning（密码已使用 300 天）"。

---

### 方向 D：API 弹性与舱壁隔离框架 — P2

#### 架构分析

这是五个方向中**对现有代码侵入最小、但架构设计需要最谨慎**的一个。

核心洞察：断路器和舱壁的实现本身不难（~300 行核心逻辑），难的是**正确地将它们应用到 7+ 个下游依赖的每个调用点，而不引入副作用**。

现有依赖调用模式：

```go
// 当前：直接调用
func (s *LDAPAuthenticator) Authenticate(ctx context.Context, req) (*User, error) {
    conn, err := s.pool.Get(ctx)  // 直接 LDAP TCP 调用
    // ...
}

// 目标：通过断路器调用
func (s *LDAPAuthenticator) Authenticate(ctx context.Context, req) (*User, error) {
    result, err := s.circuitBreaker.Execute(ctx, func() (interface{}, error) {
        conn, err := s.pool.Get(ctx)
        // ...
    })
    // result/err 来自断路器
}
```

**关键设计决策：断路器应该放在哪里？**

| 位置 | 方案 | 优点 | 缺点 |
|---|---|---|---|
| **A: SPI 实现包装** | 每个下游实现的每个方法内嵌断路器调用 | 与业务逻辑最近，语义最清晰 | 实现类内代码重复；每种依赖的包装逻辑不同 |
| **B: 中间件装饰器** | 用装饰器模式包裹整个 SPI 接口 | 无侵入；可以统一控制 | 丢失方法级语义（整个接口全开或全关）；粒度太粗 |
| **C: 代理层** | 对每个下游依赖创建一个 Proxy，代理所有调用 | 调用方零改动；统一管理重试、超时、熔断 | 需要为每个下游定义代理接口；部署拓扑复杂化 |
| **D: 调用点包装** | 在调用处用 `circuitbreaker.Do(ctx, name, fn)` 包装 | 灵活；每个调用点可配置 | 调用点太多，容易遗漏 |

**推荐：方案 A（核心库）+ 方案 D（调用点包装）的混合**

- 核心库提供 `shared/circuitbreaker` + `shared/bulkhead` 两个低耦合的工具包
- 每个下游依赖的维护者在关键调用点手动包装
- 不需要统一框架——每个下游依赖有自己的熔断策略

不推荐方案 B（装饰器），因为装饰器要求 SPI 接口的每个方法返回 `(interface{}, error)`，要么擦除类型安全。

#### 核心库设计

```go
// shared/bulkhead/bulkhead.go

type Bulkhead struct {
    name          string
    maxConcurrent int
    queueSize     int
    timeout       time.Duration
    metrics       MetricsRecorder
}

func New(name string, opts ...BulkheadOption) *Bulkhead

func (b *Bulkhead) Execute(ctx context.Context, fn func(context.Context) error) error
// 返回: nil | ErrBulkheadRejected | ErrBulkheadTimeout | fn 的错误

// shared/circuitbreaker/circuitbreaker.go

type State int
const (
    StateClosed   State = iota
    StateOpen
    StateHalfOpen
)

type CircuitBreaker struct {
    name             string
    failureThreshold int
    successThreshold int
    timeout          time.Duration
    halfMaxRequests  int
    state            State
    failures         int
    successes        int
    lastStateChange  time.Time
    onStateChange    func(name string, from, to State)
    metrics          MetricsRecorder
}

func New(name string, opts ...CBOption) *CircuitBreaker

func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error
// 返回: nil | ErrCircuitOpen | fn 的错误
```

两个库的接口风格统一（`Execute(ctx, fn)`），方便组合使用：

```go
// 组合使用示例
func (s *LDAPAuthenticator) Authenticate(ctx context.Context, req) (*User, error) {
    var user *User
    err := s.bulkhead.Execute(ctx, func(ctx context.Context) error {
        return s.circuitBreaker.Execute(ctx, func(ctx context.Context) error {
            var err error
            user, err = s.pool.Get(ctx).Bind(req).Authenticate()
            return err
        })
    })
    return user, err
}
```

#### 关键复杂性：断路器状态同步问题

断路器和舱壁是**每副本本地**的状态——不需要跨副本同步。但有一个微妙问题：

```
副本 A: LDAP 正常 → 断路器关闭
副本 B: LDAP 超时 x 5 → 断路器打开（拒绝所有 LDAP 请求）

结果: 副本 B 上的用户无法登录，但副本 A 上的用户正常
```

这是**设计意图**而非 bug——每个副本独立判断下游健康。但运维人员需要理解这种行为，避免"某些用户能登录、某些不能"时误判为 SSO 失效。

#### 优先包裹的下游依赖

| 依赖 | 优先级 | 舱壁大小 | 断路器阈值 | 降级行为 |
|---|---|---|---|---|
| LDAP 认证器 | P1 | max=5 | 5 failures → 30s open | 不能降级（无 LDAP = 不能登录） |
| SAML IdP 元数据 | P1 | max=3 | 3 failures → 60s open | 使用缓存元数据（24h 内缓存的仍可用） |
| KMS 签名 | P1 | max=50 | 5 failures → 10s open | 降级到本地签名（如果 fallback key 存在） |
| CAEP 推送 | P2 | max=10 | 10 failures → 5m open | 记录失败，队列后续重试 |
| ext_authz gRPC | P2 | max=100 | 10 failures → 30s open | 降级到默认 deny |
| OIDC Federation | P2 | max=3 | 3 failures → 60s open | 使用缓存 |

---

### 方向 E：联邦式跨租户管理与全局搜索 — P2

#### 架构分析

这是五个方向中**对权限模型的挑战最大**的一个。现有管理 API 的设计是：

```
GET /api/v1/admin/tenants/{tid}/users  →  scope: admin:read.tenant.{tid}
```

当前 API 模式假设管理员"在某个租户上下文中"操作。跨租户管理需要引入一个新的 scope 层级：

```
scope: admin:read.global       → 可以查看所有租户数据（只读）
scope: admin:write.global      → 可以操作所有租户数据（写入）
scope: admin:read.tenant.{tid} → 只能查看指定租户数据（现有）
```

**核心挑战：scope 语义的层级冲突**

现有 scope 模型是 `admin:read.tenant.{tid}`——scope 自身编码了租户 ID。但 `admin:read.global` 是跨租户的——它不绑定到某个租户。这两种 scope 的授权检查逻辑不同：

```go
// 当前 per-tenant 检查
func RequireTenantScope(tid string) middleware {
    return func(next) {
        token := extractBearer(ctx)
        if !token.HasScope("admin:read.tenant." + tid) {
            return 403
        }
        next()
    }
}

// 新增 global 检查——tenant ID 从请求参数中取，而非从 scope 编码
func RequireGlobalScope() middleware {
    return func(next) {
        token := extractBearer(ctx)
        if token.HasScope("admin:read.global") {
            next() // global 管理员可以访问任意租户
            return
        }
        // 退回到 per-tenant 检查
        tid := extractPathParam(ctx, "tid")
        if token.HasScope("admin:read.tenant." + tid) {
            next()
            return
        }
        return 403
    }
}
```

**这不是"加一个常量"的问题。** scope 的层级关系（global ⊇ per-tenant）需要在授权检查点表达。

#### 搜索索引架构

跨租户搜索的核心难点是**性能**——100 个租户、100 万用户时，线性扫描 100 个表不可接受。

| 方案 | 原理 | 优点 | 缺点 |
|---|---|---|---|
| **A: 统一索引表** | 在 `global_search_users` 表中建立所有租户的搜索索引（含 tenant_id 分区键） | 单一查询即可跨租户搜索；PostgreSQL 分区表天然支持 | 写入路径多一跳；租户删除时需要清理索引 |
| **B: 每个租户独立表 + UNION** | 执行 `SELECT ... FROM tenant_{tid}.users UNION ALL ...` | 数据隔离最强 | 100+ 表 UNION 性能差；SQL 动态拼接有注入风险 |
| **C: 专用搜索引擎** | 引入 Elasticsearch/Meilisearch 作为搜索后端 | 全文搜索性能最好；支持模糊匹配和权重 | 新增外部依赖；运维成本高 |

**推荐：方案 A（统一索引表）作为第一阶段，方案 C（专用搜索引擎）作为规模化路径**

第一阶段在 Postgres 中建 `global_search_users` 表（tenant_id, user_id, email, username, display_name, search_vector tsvector），用 `pg_trgm` 做模糊搜索。单表 100 万用户时 PostgreSQL 的 gin/tgrm 索引仍可 < 100ms 响应。

超过 1000 万用户或 500+ 租户时，再评估 Elasticsearch 迁移。

#### 全局审计查询的架构

全局审计查询的技术挑战更大——审计事件每天数百万条，按月分区：

```sql
-- 现有：per-tenant 查询
SELECT * FROM audit_events_202607 
WHERE tenant_id = $1 AND event_type = 'login.failure' 
AND created_at > now() - interval '24h'
ORDER BY created_at DESC LIMIT 100;

-- 新增：全局查询——去掉 tenant_id 过滤，需要全分区扫描
SELECT * FROM audit_events_202607
WHERE event_type = 'login.failure' 
AND created_at > now() - interval '24h'
ORDER BY created_at DESC LIMIT 100;
```

**解决方案：tenant_id 作为分区键 + 跨分区查询**

如果审计表按 tenant_id hash 分区（PostgreSQL 分区表），全局查询需要扫描所有分区。中小规模（< 50 个租户）时可以接受。更大规模时，建议引入实时物化视图（`materialized view`）在写入时预聚合。

---

## 3. 接口设计建议

### 3.1 核心 SPI 设计原则

基于五个方向的需求，提出以下 SPI 设计指导原则：

| 原则 | 适用方向 | 说明 |
|---|---|---|
| **存储 SPI 保持稳定** | ① Postgres | 五个方向的 Postgres 实现都不需要修改现有 SPI——这是验证 SPI 设计质量的信号 |
| **新概念用新类型** | ② 流级观测 | `FlowID` 应为 `string` 别名类型而非裸 `string`，防止与其他 ID 混用 |
| **功能默认关闭** | ③④⑤ | 新功能 default no-op / opt-in，不影响现有行为 |
| **上下文传递用 ctx** | ②③ | flow_id、credential health 通过 `context.Context` 传递，不污染 handler 签名 |
| **审计元数据纪律保持** | ②③⑤ | 所有新增数据通过 `audit.SetMeta` 写入，禁止直接 map 赋值 |

### 3.2 新的抽象层评估

| 方向 | 需要新抽象层？ | 说明 |
|---|---|---|
| ① Postgres | 不需要 | 复用 `oauthspi.*` 和 `core.*` |
| ② 流级观测 | 需要新概念 | `FlowID` 类型（shared/core）、`FlowStore`（可选 SPI） |
| ③ 凭据健康 | 需要新 SPI | `CredentialStatusStore`（shared/core）、`CredentialScanner`（domain） |
| ④ 弹性 | 需要新库 | `shared/bulkhead`、`shared/circuitbreaker`（纯工具库，非 SPI） |
| ⑤ 跨租户管理 | 需要新 scope | `admin:read.global`（permissions 模型扩展）、搜索索引层 |

### 3.3 向后兼容性策略

| 方向 | 兼容性策略 |
|---|---|
| ① Postgres store | 新表通过 migrate 添加版本号；老版本升级时不影响已有 SQLite/Redis 用户 |
| ② Flow trace | AuthCode 加 FlowID 字段为 `NULLABLE` — 老 code 兑换时无 trace 信息但正常进行 |
| ③ Credential health | 扫描引擎默认关闭；`recordCredentialHealth` 继续 emit metrics |
| ④ Bulkhead/CB | 零默认配置；配置了才启用包装；未启用时调用路径零开销 |
| ⑤ Cross-tenant | 全局 scope 需显式授予；无全局 scope 的管理员继续看到 per-tenant 视图 |

---

## 4. 技术选型

### 4.1 新依赖引入评估

| 方向 | 新依赖 | 评估结果 |
|---|---|---|
| ① Postgres OAuth store | **无** | 使用标准 `database/sql` + `lib/pq`（已存在）或 `pgx`（已存在于 `infrastructure/postgres/`） |
| ② Flow trace | **无** | 使用标准 OpenTelemetry API（已存在） |
| ③ Credential health | **无** | 扫描引擎是纯 Go 逻辑；HIBP 检查已存在 |
| ④ Bulkhead/CB | **无** | ~300 行核心逻辑，自建比引入外部库更可控（sony/gobreaker 存在但接口不统一） |
| ⑤ Cross-tenant search | **可能** | 第一阶段自建（Postgres + pg_trgm）；扩展期评估 Meilisearch（Rust 写的替代 Elasticsearch，单二进制部署） |

**结论：五个方向零必需外部依赖。** 这是项目"纯 Go、零外部运行时依赖"原则的自然结果。

### 4.2 自建 vs 引入的决策

| 组件 | 决策 | 理由 |
|---|---|---|
| **Circuit breaker 库** | ✅ 自建 | 核心逻辑 ~200 行；`sony/gobreaker` 接口不满足 `Execute(ctx, func(ctx) error)` 模式 |
| **Bulkhead 库** | ✅ 自建 | ~100 行；标准 semaphore 模式 |
| **搜索引擎** | 一期自建 → 二期评估 Meilisearch | pg_trgm 足够支撑 50 租户/100 万用户；Meilisearch 在 Go 项目中集成便利（HTTP API + 无 Java 依赖） |

### 4.3 与现有技术栈的集成

```
方向① → infrastructure/postgres/ 已有 pgx 连接池和 migrate 框架 → 直接复用
方向② → platform/tracing/ 已有 OpenTelemetry 设置 → 新增 FlowID 传播
方向③ → platform/audit/ 已有 SetMeta 机制 → 新增 CredentialEvent 类型
方向④ → platform/lifecycle/degradation/ 已有全局降级 → 扩展 per-dependency 降级
方向⑤ → interfaces/admin/ 已有 admin gRPC API 模式 → 新增 global scope 检查
```

---

## 5. 实施路线图

### 5.1 优先级排序

评估维度：**架构价值 × 业务影响 × 实施风险 × 依赖关系**

```
P0 — 立即：高价值、低风险、无侵入、无前置依赖
P1 — 短期：高价值、中低风险、有侵入但可控
P2 — 中期：高价值、中高风险、需要前置条件或更多设计
P3 — 远期：中高价值、高风险、需要大规模投入
```

| 优先级 | 方向 | 价值 | 风险 | 侵入 | 估算 | 最小独立交付物 |
|---|---|---|---|---|---|---|
| **P0** | 无（五个方向均非 P0） | - | - | - | - | - |
| **P1** | ① Postgres OAuth 存储补齐 | ★★★★★ | ★ | 低 | ~1000 行 | AuthCodeStore 单表 |
| **P1** | ② Flow trace 嵌入（阶段 1） | ★★★★ | ★ | 低 | ~400 行 | AuthCode 加 FlowID + `/token` 建立 span 链 |
| **P1-P2** | ③ 凭据健康扫描引擎（阶段 1） | ★★★★ | ★★ | 中 | ~1500 行 | `CredentialScanner` 后台进程 + `CredentialStatusStore` |
| **P2** | ④ 舱壁+断路器核心库 | ★★★★ | ★ | 低 | ~600 行 | `shared/bulkhead` + `shared/circuitbreaker` |
| **P2** | ⑤ 跨租户搜索 API | ★★★★ | ★★ | 中 | ~1200 行 | `GET /admin/search/users` API |
| **P2** | ④ 下游依赖包裹（LDAP/KMS） | ★★★ | ★★ | 中 | ~800 行/依赖 | LDAP 认证器 + KMS 签名包装 |
| **P3** | ② Flow 调试面板（Admin Console） | ★★★ | ★★ | 中 | ~2000 行 | 时序图面板 |
| **P3** | ③ 自动修复策略引擎 | ★★★★★ | ★★★ | 高 | ~2000 行 | 策略引擎 + 登录路径修复执行 |
| **P3** | ⑤ 全局仪表盘（Fleet View） | ★★★★ | ★★ | 中 | ~2500 行 | Admin Console 全局视图 |

**核心判断：** 五个方向没有一个达到 P0（紧急）级别——它们都是"已有的优秀平台上的增强"。但 ①② 的 P1 定位合理——它们是基础设施层面的补全，影响后续所有方向的开发体验。

### 5.2 阶段划分与里程碑

#### 阶段 1：基础设施补全（2-3 周）

聚焦方向① + 方向②阶段 1 + 方向④核心库。三者互不依赖，可并行推进。

```
Sprint 1A: Postgres OAuth Store（方向①）
├── 里程碑: AuthCodeStore + JTIReplayStore Postgres 实现
├── 测试: 复用现有 oauthspi 测试套件（替换 test suite 的 backend）
└── 验收: make acceptance 全通过

Sprint 1B: Flow Trace 嵌入（方向②阶段 1）
├── 里程碑: AuthCode 增加 FlowID（四个后端） → /token 建立父子 span
├── 测试: 集成测试验证 span 链跨请求关联
└── 验收: GET /admin/flows/{code} 返回关联 trace_id

Sprint 1C: 弹性核心库（方向④核心库）
├── 里程碑: shared/bulkhead + shared/circuitbreaker + 单元测试
├── 测试: 并发测试（验证 maxConcurrent 行为）+ 状态机测试
└── 验收: 单元测试覆盖率 > 90%
```

#### 阶段 2：治理与管理面（3-4 周）

聚焦方向③扫描引擎 + 方向⑤搜索 API + 方向④第一个依赖包装。

```
Sprint 2A: 凭据健康扫描引擎（方向③阶段 1）
├── 里程碑: CredentialStatusStore SPI + memory 实现 + 后台扫描器（密码/MFA）
├── 前置: 无
└── 验收: 扫描后凭据健康状态可查询

Sprint 2B: 跨租户搜索（方向⑤阶段 1）
├── 里程碑: GET /admin/search/users + pg_trgm 索引 + global scope 权限检查
├── 前置: direction ⑤ 权限模型设计评审
└── 验收: 跨 3 个租户搜索用户 < 500ms

Sprint 2C: LDAP 断路器包装（方向④第一个依赖）
├── 里程碑: LDAP 认证器包裹 bulkhead(max=5) + circuit breaker(5→30s)
├── 前置: Sprint 1C
└── 验收: LDAP 不可用时断路器在 5 次失败后打开，不再尝试连接
```

#### 阶段 3：治理闭环与面板（4-6 周）

聚焦方向③策略引擎 + 方向②调试面板 + 方向⑤仪表盘。

```
Sprint 3A: 凭据修复策略引擎（方向③阶段 2）
├── 里程碑: 策略引擎 + 登录路径强制改密/强制 MFA 重定向
├── 前置: Sprint 2A
└── 验收: 配置 password_age > 90d → force_change 后，95 天未换密的用户被重定向到改密页

Sprint 3B: Flow 调试面板（方向②阶段 2）
├── 里程碑: Admin Console 新增 OAuth Flow Debugger 面板
├── 前置: Sprint 1B
└── 验收: 输入 auth_code → 时序图展示完整请求链

Sprint 3C: Fleet View 仪表盘（方向⑤阶段 2）
├── 里程碑: Admin Console 新增全局视图页面
├── 前置: Sprint 2B
└── 验收: 展示所有租户健康状态 + 跨租户审计趋势
```

### 5.3 关键依赖关系

```
阶段 1                         阶段 2                         阶段 3
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│ ① Postgres store    │      │ ③ 扫描引擎  ←──────│──────│ ③ 策略引擎          │
│ (无依赖)             │      │ (无依赖)             │      │ (依赖: 扫描引擎)     │
└─────────────────────┘      └─────────────────────┘      └─────────────────────┘
                                                                         
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│ ② Flow trace 嵌入   │      │ ⑤ 跨租户搜索         │      │ ② Flow 调试面板     │
│ (无依赖)             │      │ (无依赖)             │      │ (依赖: ②阶段1)       │
└─────────────────────┘      └─────────────────────┘      └─────────────────────┘
                                                                         
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│ ④ Bulkhead + CB 库  │──────│→ ④ LDAP 包装         │      │ ⑤ Fleet View        │
│ (无依赖)             │      │ (依赖: ④库)          │      │ (依赖: ⑤阶段1)       │
└─────────────────────┘      └─────────────────────┘      └─────────────────────┘
```

### 5.4 风险矩阵

| 风险 | 概率 | 影响 | 缓解策略 |
|---|---|---|---|
| Postgres SERIALIZABLE 重试未实现 → Refresh 偶发失败 | 中 | 高 | 在 RefreshTokenStore 实现中包含明确的重试循环（`pgx` 的 `ErrTxSerialization` 检测） |
| FlowID 只加到 AuthCode，未覆盖 CIBA/Device 流 | 中 | 中 | 确保 SPI 设计时 FlowID 作为可选字段在所有短期存储中铺开 |
| Credential scanning 在 100 万用户时性能不达标 | 低 | 中 | 分页扫描 + 限速 + 全量扫描安排在低峰期；首次扫描后增量更新 |
| 断路器阈值配置不当导致频繁熔断 | 中 | 中 | 默认阈值保守（偏高）；提供 dry-run 模式（记录但不断开）让运维在真实流量中校准 |
| 全局搜索 scope 与现有 per-tenant scope 不兼容 | 低 | 高 | 方向⑤启动前必须完成权限模型设计评审（permissions 团队参与） |
| 流量 trace 的存储成本超预期 | 低 | 低 | 默认 TTL=5min（AuthCode TTL）；监控 `bulkhead_active_flows` 指标，超阈值自动降级 |
| 数据隔离审查：全局管理员误操作导致跨租户数据污染 | 中 | 高 | 全局视图默认只读；写操作必须显式切换到租户上下文（与现有 per-tenant API 一致） |

### 5.5 与前期分析的合并建议

本分析的五方向 + 前期架构分析的五方向（授权管道、Session Hub 登出、Token Proxy、状态 Fuzzing、硬件 Attestation）存在协同效应：

| 合并点 | 方向组合 | 协同价值 |
|---|---|---|
| **FlowID + 状态 Fuzzing** | ② + 前期 D | Fuzzing 的 oracle 可以利用 FlowID 追踪多步状态机，在断言失败时提供完整请求链 |
| **Credential Health + 授权管道** | ③ + 前期 A | 凭据健康分可以作为授权管道的一个输入信号——"password > 90d" → 触发 step-up |
| **Bulkhead + Token Proxy** | ④ + 前期 C | Token Proxy 的出站调用（JWKS 获取、introspect）是舱壁的主要应用场景 |
| **Cross-tenant + 授权管道** | ⑤ + 前期 A | 全局管理员可以配置跨租户的策略模板——"所有租户的登录失败率 > 10% 时触发告警" |

建议在实施计划中考虑这些合并点，但不要因此延迟独立交付。

---

## 附录 A：与 v10 评估报告的分歧说明

| v10 报告结论 | 本分析立场 | 理由 |
|---|---|---|
| 方向①②可在同一 sprint 并行启动 | **赞同** | 确实互不依赖；建议 Sprint 1 就并行 |
| 方向①优先级 P1 | **赞同** | Postgres 用户的采购决策瓶颈 |
| 方向②优先级 P1（trace 嵌入 S） | **赞同但细化** | trace 嵌入本身 S，但完整价值需要调试面板（L）。建议分两阶段交付 |
| 方向③优先级 P1-P2 | **赞同** | 扫描引擎 P1，策略引擎 P2 |
| 方向④优先级 P2 | **赞同** | 核心库 P2，下游包装 P2-P3 |
| 方向⑤优先级 P2 | **赞同但强调前置条件** | scope 权限模型必须先行设计评审 |
| v10 报告未讨论 flow_id 的必要性 | **补充** | 引入 flow_id 作为一级概念是方向②的架构核心，不仅仅是"在 state 中嵌入 trace ID" |
| v10 报告未讨论搜索索引架构 | **补充** | 提供三种搜索方案及推荐（统一索引表 → 专用搜索引擎） |
| v10 报告未讨论断路器状态同步问题 | **补充** | 每副本独立断路器是设计意图，但运维需知悉；提出明确建议 |
| v10 报告未讨论 CredentialStatusStore SPI 设计 | **补充** | 提供完整的 SPI 设计草案——这是方向③成功的核心 |

## 附录 B：与前期五方向分析的关系

前期分析（`architect-analysis-expansion-five-directions.md`）覆盖了另一组五方向：
- 方向 A：授权决策管道
- 方向 B：Session Hub 登出协调
- 方向 C：Edge Token Proxy
- 方向 D：状态协议 Fuzzing
- 方向 E：硬件设备 Attestation

v10 的五方向 + 前期的五方向 = **10 个高价值扩展方向**，无方向重叠，无方向矛盾。两个分析的共同点是：

- **都强调了增量交付**：每个方向都列出了最小可独立交付物
- **都优先"架构侵入最小"**：都推荐从无侵入、高收益的方向开始
- **都认同安全设计纪律**：oracle-leak 防护、anti-enumeration 在前期分析中是§3 门禁，在 v10 分析中是设计约束

两个分析的互补关系：

| | 前期五方向 | v10 五方向 |
|---|---|---|
| 聚焦 | 架构补齐（Session Hub、授权管道）、安全纵深（Fuzzing、Attestation）、产品能力（Token Proxy） | 基础设施（Postgres）、运营（Flow trace、弹性）、治理（Credential Health）、管理面（Cross-tenant） |
| 角色 | 平台架构师 | 产品 + 运维架构师 |
| 共同推荐 | 增量交付、零侵入优先 | 增量交付、零侵入优先 |

建议将两个分析的 10 个方向合并为一个全局路线图，按"基础设施 → 运营 → 治理 → 产品"的优先级顺序排列。
