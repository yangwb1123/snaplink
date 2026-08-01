# 架构分析报告：五项未覆盖的高价值扩展方向

> **分析师：** 资深架构师 Agent  
> **日期：** 2026-07-11  
> **基于：** `docs/requirements/architect-expansion-novel-5-directions-v6-code-scan.md`  
> **输出格式：** 本文件为架构级分析，后续可进一步拆分为 `docs/feature-spec-*.md`

---

## 1. 架构评估

### 1.1 当前架构的优势

本项目历经 50+ 轮系统分析，架构成熟度已达行业顶级水平。核心优势：

| 优势 | 表现 |
|------|------|
| **物理分层清晰** | 六层物理目录（`shared/→platform/→domains/→protocols/→interfaces/→infrastructure/`），依赖方向单向朝下，由 `architecture_layer_test.go` 门禁强制 |
| **SPI 驱动** | 每个横切关注点 = interface + `memory` impl ± 持久化 peer（sqlite/redis/etcd），无 mocks |
| **协议覆盖面全** | OAuth 2.0 + OIDC + SAML 2.0 + SCIM + FAPI + CAEP/RISC + 所有标准 grant 类型 |
| **异步架构合理** | 审计、令牌遥测、异常检测均 off-path fail-open，不影响热路径延迟 |
| **无外部 SaaS 依赖** | 所有后端可选（内存/SQLite/Redis/etcd/PostgreSQL），纯 Go，无 CGO |
| **维护性门禁严格** | 文件 ≤ 500 行，函数 ≤ 50 行，循环复杂度 ≤ 15，依赖方向有自动化门禁 |

### 1.2 当前架构的局限

局限不来自设计缺陷，而来自**演进阶段的天花板**——项目从"协议完备的 SSO SDK"向"全球多活身份平台"演进中遇到的架构瓶颈：

| 局限 | 表现 | 根因 |
|------|------|------|
| **存储层无拓扑感知** | 所有 store 接口无 region/一致性级别概念，跨 region 部署要么共享同一数据库（违反复原隔离），要么数据完全不互通 | v5.0 ROADMAP §④ 多副本数据面韧性聚焦于总线健壮性和签名密钥协调，未触及数据复制 |
| **外部依赖缺乏弹性隔离** | 一个慢 KMS 或挂起的 SAML IdP 通过共享 goroutine 池 + 连接池拖垮整个 SSO 服务器 | 早期架构未预期到 KMS/外部 IdP 会成为生产环境瓶颈（嵌入式部署无此问题） |
| **限流覆盖面有断层** | DCR、Admin API、`/.well-known` 端点无保护，admin middleware 使用独立限流域不与统一策略联动 | 限流基础设施（`interfaces/ratelimit`）功能完整但接线以"热路径优先"，管理面/自助面被遗漏 |
| **运维门禁缺失 CI 集成** | 配置验证是 `sso-ctl` 的手动 CLI 模式——没有 `--ci` 退出码、没有版本兼容矩阵、没有能力注册表 | 项目早期焦点在"构建正确的 SSO"，部署质量门禁是后置考虑 |
| **令牌生命周期不可追溯** | 审计事件不记录令牌 `jti`，token exchange 的 `act` 链仅在 JWT claim 中——令牌过期后丢失全部链信息 | Token usage 和审计是两个独立子系统，设计时未要求关联 |

### 1.3 架构债务评估

| 债务类型 | 严重程度 | 影响范围 | 备注 |
|---------|---------|---------|------|
| Client 字段持久化丢失 | **高** | SQLite 后端 | JWKS/AllowedResources/JAR 字段重启归零——静默安全降级（ROADMAP §④f 已识别） |
| 跨副本撤销 deny-set 仅内存 | **高** | 所有 issuer | 滚动重启期被撤销的 access token 可能复活 |
| etcd watch/lease 死亡不自愈 | **中** | etcd 总线用户 | 分区后副本永久失去跨副本撤销/租户暂停/协调轮换能力，`/readyz` 仍绿 |
| 根目录包只允许 15 个文件 | **中** | 根目录 | 当前 13 个，接近上限；新 `ReplicationTopology` 等选项可能突破 |
| SQLite ClientStore 仅 10 列 | **高** | SQLite 用户 | 与 `core.Client` 的 20+ 字段严重不匹配 |

**整体判断：** 架构债务存在但可控。所有债务都有明确的门禁或 ROADMAP 项跟踪，无"不可见"债务。

---

## 2. 扩展方向分析

### 2.1 方向一：多区域主动-主动复制（P0）

#### 为什么需要（业务价值）

- **合规驱动：** GDPR、金融监管要求数据驻留在指定区域——当前租户模型只检查写入时是否允许，不提供跨区域读取
- **全球延迟：** 用户在 region A 登录后，`/token` 请求如果需要回 region A 处理，B 区域的用户遭遇 200ms+ 跨洋延迟
- **高可用 SLA：** 单 region 故障（如 AWS us-east-1 宕机）导致全球 SSO 不可用

#### 核心挑战

| 挑战 | 难度 | 说明 |
|------|------|------|
| 写转发协议 | L | follower 收到写请求时需通过 gRPC 转发到 leader，等确认后回复——这是对现有处理器的完全透传 |
| 读一致性语义 | M | 不同 endpoint 需要不同一致性级别：`/token` 需 leader 读（防止 replay 漏检），`/userinfo` 可 local 读 |
| 存储层 SPI 扩展 | L | 现有 `core.SessionStore`、`oauth.AuthCodeStore` 等接口无 region/一致性参数——扩展时不能破坏单 region 语义 |
| 冲突检测 | M | 跨 region 同用户并发操作（如两个管理员同时改同一 client 配置）需要 LWW 或版本向量 |

#### 关键设计决策分析

**选项 A：Store 包裹器模式（推荐）**

```
// 新的一致性子包裹
type ConsistentSessionStore struct {
    inner     core.SessionStore
    bus       cluster.Bus
    topology  *ReplicationTopology
}

func (s *ConsistentSessionStore) Get(ctx, sid, consistency) {
    if consistency == LeaderRead && !topology.IsLeader() {
        return s.forwardToLeader(ctx, ...)  // gRPC inter-region
    }
    return s.inner.Get(ctx, sid)
}
```

- **优点：** 零改动现有 Store SPI，纯装饰器模式；单 region 部署的 import path 不变
- **缺点：** 转发路径多了 gRPC 序列化开销；需为每个 Store 写一个包裹器（~12 个）

**选项 B：SPI 扩展模式**

```
type SessionStore interface {
    Get(ctx, sid)  // 当前签名
    GetConsistent(ctx, sid, ReadConsistency)  // 新方法
}
```

- **优点：** 显式类型安全，调用方明确知道自己要的一致性级别
- **缺点：** 接口膨胀；memory/sqlite 实现需要加空方法（有 `ReadConsistency` 参数但本地部署忽略它）

**推荐：选项 A**。原因：
1. 现有 65+ 个 Store 实现遍布 12 个子模块——改 SPI 是核爆炸级变更
2. `ReplicationTopology` 是一个新 `sso.With*` 选项，默认 `nil` = 单 region = 包裹器短路为零开销
3. gRPC 转发路径可通过连接池和批处理优化（同一请求内的跨 region 查询可 batch）

#### 对现有系统的影响

| 影响 | 程度 |
|------|------|
| 新增接口 | `ReplicationTopology`（值类型 + `ReplicaRole` 枚举）、`ReadConsistency` 枚举、`ConsistentStore` 包裹器集合 |
| 新增选项 | `sso.WithReplicationTopology(ReplicationTopology)` |
| 新增依赖 | inter-region gRPC 连接（复用现有 `grpcserver` 基础设施） |
| 性能影响 | follower 转发路径增加一次 gRPC RTT（~1-5ms 同区域/跨区域 50-200ms） |
| 向后兼容 | 完全二进制兼容——单 region 用户不加选项即当前行为 |

---

### 2.2 方向二：外部依赖韧性工程——熔断器 & 舱壁（P1）

#### 为什么需要（技术价值）

当前架构有一个根本性脆弱点：**所有外部依赖共享相同的 goroutine 池和 HTTP 连接池**。

```
                     ┌─────────────────────┐
  请求 →             │     SSO Server      │
                     │                     │
                     │  goroutine pool ────┼──→ KMS（AWS KMS 限频 → hang）
                     │                     │
                     │  HTTP conn pool ────┼──→ SAML IdP（IdP 下线 → 30s timeout）
                     │                     │
                     │                     │
                     └─────────────────────┘
```

一个慢 KMS（5rps 限频 + 持续重试）可耗尽所有 goroutine，导致正常 `/token` 请求排队超时。

#### 设计决策：组件位置

`CircuitBreaker` 和 `Bulkhead` 放在哪一层？

**选项 A：`shared/security/` （作为通用 resilience 原语）**

```
shared/security/
├── circuitbreaker.go    # CircuitBreaker 接口 + 滑动窗口实现
├── circuitbreaker_test.go
├── bulkhead.go          # Bulkhead（有界信号量 + 等待队列 + 超时）
└── bulkhead_test.go
```

- **优点：** 所有层都可以用（不仅是 KMS client，还有 SAML fetch、CAEP push、federation fetch）
- **缺点：** `shared/security` 当前是"加密/安全"的包——加 resilience 原语后包名不再纯粹

**选项 B：`platform/resilience/` （新包）**

- **优点：** 语义清晰，跟 `platform/cluster/`、`platform/metrics/` 平级
- **缺点：** 新包需加到 `architecture_layer_test.go` 的 `layerName()` 中（当前 0 处新增 = 底层）

**推荐：选项 B**。理由：
- `platform/` 正好是横切关注点的家——`cluster/`（集群通信）、`metrics/`（度量）、`tracing/`（链路追踪）、`resilience/`（韧性原语）
- resilience 原语不依赖 `shared/security/` 的任何加密原语，放在 `shared/` 层反而会让上层安全包依赖它（违反最小知识原则）
- 熔断器的指标（`circuit_open_total`、`circuit_half_open`）自然属于 `platform/metrics/`

#### 设计：`platform/resilience/` 的 API

```go
// State 是熔断器的状态。
type State int
const (
    StateClosed   State = iota // 正常——请求通过
    StateHalfOpen              // 一个试探请求被放行
    StateOpen                  // 熔断——请求快速失败
)

// CircuitBreaker 是熔断器 SPI。
// FAIL-OPEN：如果底层存储/统计不可用（计数器溢出），breaker 关闭（允许请求通过）。
type CircuitBreaker interface {
    // Name 标识此熔断器（用于 metrics）。
    Name() string

    // Execute 带熔断保护地执行 fn。
    // 如果熔断器打开且未到 half-open 时机，返回 ErrCircuitOpen。
    // fn 返回的错误由熔断器统计（计入失败计数）。
    Execute(ctx context.Context, fn func(context.Context) error) error

    // State 返回当前状态。
    State() State

    // Metrics 返回熔断器的运行时统计。
    Metrics() CircuitBreakerMetrics
}

// CircuitBreakerConfig 是滑动窗口熔断器的配置。
// 基于 Google SRE 的通用模式：
//   当滑动窗口（Duration）内的失败率 >= FailureRateThreshold（0-1）
//   且总请求数 >= MinRequestCount，熔断器打开。
//   OpenDuration 后进入 HalfOpen（单请求试探）。
//   HalfOpenMaxRequests 个试探请求成功后关闭。
type CircuitBreakerConfig struct {
    Duration            time.Duration // 滑动窗口大小（默认 60s）
    MinRequestCount     uint64       // 最少请求数（默认 5）
    FailureRateThreshold float64     // 失败率阈值 0-1（默认 0.5）
    OpenDuration        time.Duration // 熔断持续时间（默认 30s）
    HalfOpenMaxRequests int          // 半开试探请求数（默认 1）
}

// Bulkhead 是舱壁隔离器。
// 限制并发执行数 + 等待队列 + 超时。
type Bulkhead interface {
    Name() string
    // Acquire 尝试获取一个执行槽。ctx 控制等待超时。
    Acquire(ctx context.Context) (ReleaseFunc, error)
    // Metrics 返回隔离器的运行时统计。
    Metrics() BulkheadMetrics
}

type BulkheadConfig struct {
    MaxConcurrent   int           // 最大并发（默认 10）
    MaxWaitDuration time.Duration // 等待队列超时（默认 500ms）
    QueueSize       int           // 等待队列大小（默认 10）
}
```

#### 接线策略

| 接线目标 | 优先级 | 熔断配置 | Bulkhead 配置 | 备注 |
|---------|--------|---------|-------------|------|
| KMS 签名 | P1 | 5 req / 60s 窗口 / 50% 失败率 → 开 120s | `MaxConcurrent=5` | 防限频耗尽；本地 fallback（软HSM） |
| SAML IdP assertion fetch | P1 | 10 req / 60s / 50% | `MaxConcurrent=20` | IdP 下线时快速失败 |
| CAEP webhook push | P1 | 20 req / 60s / 30% | `MaxConcurrent=50` | Best-effort 推送可丢 |
| Federation fetch | P2 | 10 req / 60s / 50% | `MaxConcurrent=10` | 有限 TTL 缓存已减少大部分请求 |
| etcd watch | P2 | 不适用 | 不适用 | etcd 已经有 backoff 重连 |
| SMTP 邮件 | P2 | 10 req / 60s / 30% | `MaxConcurrent=5` | |

#### fail-open / fail-closed 决策矩阵

| 路径 | 熔断时行为 | 理由 |
|------|-----------|------|
| KMS 签名 | **fail-closed** → 503 | 降级到本地签名可接受，但绝不能静默用不安全的密钥 |
| SAML IdP fetch | **fail-open** → 返回 token 链未验证错误 | SAML 断言验证失败应表现为 `invalid_grant`，非 500 |
| CAEP push | **fail-open** → 日志记录 + 度量 + 丢事件 | CAEP 推送可丢 |
| Federation fetch | **fail-open** → 返回 nil federation 元数据 | 无 federation 元数据不影响签名正确性 |

---

### 2.3 方向三：限流覆盖完备化（P1）

#### 为什么需要（安全价值）

这是**投入产出比最高的安全速赢项**。DCR 端点接线仅 ~50 行改动，但消除了一个显著攻击面。

#### 接线策略

```
端点                  现有限流    接入方式                 默认阈值
───────────────────   ─────────   ────────────────────   ──────────
POST /register         ❌         ratelimit.Middleware   10/min per IP
PUT /register/{id}     ❌         ratelimit.Middleware   10/min per IP
DELETE /register/{id}  ❌         ratelimit.Middleware   10/min per IP
/admin/* (gRPC)        ❓独立     合并到 PolicyStore      30/min per IP
/me/*                  ❌         ratelimit.Middleware   20/min per IP
/userinfo              ❓模糊      ratelimit.Middleware   100/min per IP
/.well-known/*
                       ❌         ratelimit.Middleware   30/min per IP（因响应体大）
/end_session           ❓模糊      ratelimit.Middleware   30/min per IP
/auth/mfa              ❓部分      per-IP 限流接线       5/min per IP（已有 per-session）
```

#### 关键设计决策：Admin API 限流域合并

当前的 admin middleware 使用 Go 标准库 `rate.NewLimiter`（独立的令牌桶）：

```go
// admin/middleware.go（当前——不与 PolicyStore 联动）
var adminLimiter = rate.NewLimiter(rate.Inf, 0) // 默认无限流
```

合并方案：

```go
// 修改后——从 PolicyStore 获取动态限流策略
func adminRateLimitMiddleware(store ratelimit.PolicyStore) gin.HandlerFunc {
    return func(c *gin.Context) {
        policy := store.GetPolicy("admin") // 动态加载
        if policy != nil && !policy.Allow(c.Request.Context()) {
            c.AbortWithStatusJSON(429, gin.H{"error": "rate_limit_exceeded"})
            return
        }
        c.Next()
    }
}
```

#### Per-Subject 限流扩展

当前 `Policy` SPI 仅支持 `KeyByIP` 和 `KeyByClientID`。新增 `KeyBySubject` 以支持**跨 IP 的同账户暴力破解防御**。

新增 SPI 方法：

```go
// 在 interfaces/ratelimit/policy.go 中扩展
type Policy struct {
    // ... 现有字段 ...
    SubjectLimiter *RateLimiterConfig `yaml:"subject_limiter"` // nil = 不限流
}

// KeyBySubject 从请求上下文中提取用户标识（通过 SubjectResolver SPI）。
// 通过在 AuthenticateSubject 之后调用的 middleware 注入。
type SubjectKeyExtractor func(ctx context.Context) (string, bool)
```

---

### 2.4 方向四：配置验证门禁（P2）

#### 为什么需要（运维价值）

配置错误是 SSO 停机的首要原因。Gartner 报告 75% 的身份基础设施停机由配置错误而非软件缺陷导致。

#### 架构设计：`--ci` 模式的能力注册表

```go
// 在 platform/buildinfo/ 中扩展
type Capability struct {
    Name    string   // "saml", "oidc_federation", "kms_aws"
    Enabled bool     // 是否在此构建中包含
}

// 注册：每个 With* 选项在 init() 或 New() 时调用
func RegisterCapability(name string)

// 查询：验证器使用
func Capabilities() map[string]bool
```

验证流程：

```
sso-ctl config validate --ci --version v5.0 --strict

  1. 解析 YAML
  2. JSON Schema 格式验证（现有）
  3. 版本兼容矩阵检查（config struct 的 struct tag 声明引入/弃用版本）
  4. 能力注册表检查：配置引用 saml → Capabilities["saml"] == true？
  5. 逻辑一致性检查（client_registration.enabled → ClientStore 非 nil？）
  6. 输出 JSON 报告：
     {
       "valid": false,
       "version": "v5.0",
       "errors": [
         {"field": "saml.enabled", "code": "capability_not_built",
          "message": "SAML submodule is not included in this binary. Build with -tags saml or disable saml.enabled"}
       ],
       "warnings": [...]
     }
  7. 退出码：0 = 通过，1 = 验证错误，2 = 配置与运行环境差异
```

#### 不做之事

- 不引入新的 schema 语言（保持现有反射式 JSON Schema 生成）
- 不做运行态配置漂移检测（那是 `platform/configaudit` 的领域——已有）
- 不做配置加密/凭据管理（那是外部队列）

---

### 2.5 方向五：令牌链式溯源与全生命周期合规追踪（P2）

#### 为什么需要（合规价值）

SOC2 / 金融监管 / GDPR 要求"一枚特定令牌从 mint 到 expire/revoke 的完整旅程"。
当前架构无法回答以下审计问题：

1. "令牌 T 是用哪个授权码换来的？"
2. "令牌 T 通过 token exchange 衍生出哪些下游令牌？"
3. "用户 U 在 2026 年 6 月授权了哪些客户端、获取了哪些令牌、令牌在哪些端点使用过？"

#### 架构设计

**核心原则：审计事件作为底层存储，不在热路径上新增持久化。**

```
Token Mint ──→ recorder.Offer(TokenEvent{Minted, jti, subject, client_id, ...})
                    ↓
              async drain ──→ audit.Store (现有)
                    ↓
              TokenFamilyIndex（按 jti 建立父子关系——仅 trace_id + jti 的轻量索引）
```

**不新加数据库表**——令牌生命周期事件写入现有 `audit.Store`，用 `trace_id` + `jti` 做关联键。查询层做聚合和关系重建。

```
GET /admin/tokens/{jti}/lineage

    1. 从 audit.Store 加载所有关联 jti 的令牌事件（Minted/Used/Refreshed/Exchanged/Revoked）
    2. 从 TokenFamilyIndex 加载父子关系（jti → parent_jti, jti → child_jtis）
    3. 构建有向无环图（DAG）
    4. 返回 JSON：
       {
         "token": { "jti": "t1", "type": "access_token", "minted_at": ..., "client_id": "c1" },
         "parent": { "jti": "ac1", "type": "authorization_code", "minted_at": ... },
         "children": [
           { "jti": "t2", "type": "access_token", "via": "token_exchange", "minted_at": ... }
         ],
         "events": [
           { "type": "used", "at": ..., "endpoint": "/userinfo" },
           { "type": "refreshed", "at": ..., "new_jti": "rt2" }
         ]
       }
```

#### 关键设计决策：TokenFamilyIndex

| 方案 | 优点 | 缺点 |
|------|------|------|
| **A: 审计事件 + 运行时索引** | 无持久化开销；索引可在启动时从审计日志重建；不增加热路径延迟 | 索引重建需 scan 审计日志（可并行 batch）；大租户可能有数百万事件 |
| **B: 单独的事件存储表** | 查询快（索引在 DB 中）；不依赖审计日志的查询能力 | 新 DB 表 + 迁移；热路径多一次写入（即使异步） |

**推荐：方案 A**。原因是：
- 令牌生命周期事件量级远小于审计日志（每次请求产生 1-5 个审计事件，每 100 次请求才产生 1 个令牌事件）
- `audit.Store` 的查询能力已在扩展（ROADMAP v5 §① 的 audit export）
- 启动重建可通过背景 goroutine 渐进完成，不影响 `/readyz`

#### 级联吊销

```
func (s *Server) cascadeRevoke(ctx, jti) {
    lineage := s.tokenLineage.Get(jti)  // 从 TokenFamilyIndex 加载
    for _, child := range lineage.Children {
        s.issuer.Revoke(ctx, child.JTI)  // 吊销下游令牌
        s.cascadeRevoke(ctx, child.JTI)  // 递归
    }
}
```

- **默认关闭：** `WithCascadeRevocation(enabled bool)`——因为级联吊销有性能成本（递归查询 + 多次存储写入），且某些场景不需要（如简单的 access token 刷新不需要级联）
- **免环保护：** DAG 保证 + `visited` set 防止 token exchange 环（如果 A→B→A）

---

## 3. 接口设计原则

### 3.1 通用原则

| 原则 | 说明 | 违反后果 |
|------|------|---------|
| **SPI 不膨胀** | 新功能以包裹器/中间件模式实现，不修改现有 SPI | 改 SPI = 改 12+ 子模块的实现 + 测试 |
| **默认 nil = 当前行为** | 所有新 `With*` 选项的默认值必须是其零值（nil/0/false） | 现有用户升级后无行为变化 |
| **Fail-open 比 fail-closed 好** | 新组件的错误（熔断器、复制层、溯源索引）必须 fail-open | 新组件不应将单 region 用户的可用性降级 |
| **热路径零分配** | 任何新组件在热路径上不得产生 heap allocation（`tokenusage` 的 Offer+drain 模式即为正确） | 令牌签发路径每请求已有 ~20 次 allocation——不能再加 |

### 3.2 各方向接口映射

| 方向 | 新接口 | 所属包 | 类型 |
|------|-------|--------|------|
| 方向一 | `ReplicationTopology` | `platform/cluster/` | 值类型 + 配置 |
| 方向一 | `ReadConsistency` enum | 同 | 枚举 |
| 方向一 | `ConsistentSessionStore` 等 | `protocols/oauth/` 内 | 包裹器 |
| 方向二 | `platform/resilience.CircuitBreaker` | `platform/resilience/` | SPI + 实现 |
| 方向二 | `platform/resilience.Bulkhead` | 同 | SPI + 实现 |
| 方向三 | `Policy.SubjectLimiter` | `interfaces/ratelimit/` | 现有 SPI 扩展 |
| 方向三 | `SubjectKeyExtractor` | 同 | 函数类型 |
| 方向四 | `buildinfo.Capability` | `platform/buildinfo/` | 值类型 |
| 方向四 | `buildinfo.RegisterCapability` | 同 | 注册函数 |
| 方向五 | `TokenFamilyIndex` | `domains/tokenusage/` | 索引 |
| 方向五 | `LineageQuery` | 同 | 查询接口 |

---

## 4. 技术选型

### 4.1 引入新技术栈的决策

| 方向 | 建议 | 理由 |
|------|------|------|
| 方向一（多区域） | **不引入**新技术栈 | 复用现有 gRPC + 集群总线 |
| 方向二（熔断器） | **自建** ~100 行滑动窗口 | 不引入 hystrix-go/resilience4j（外部依赖审计成本） |
| 方向三（限流） | **利用现有** ratelimit | 接线即可，零新技术 |
| 方向四（配置门禁） | **扩展现有** config/schema | 不需要新 schema 语言 |
| 方向五（令牌溯源） | **利用现有** audit.Store | 不需要新数据库 |

**结论：所有五个方向均不需要引入新的第三方依赖或技术栈。**

### 4.2 自建 vs 采购决策

| 决策项 | 自建理由 |
|--------|---------|
| 熔断器 | 需求极轻量（滑动窗口 + 失败率），第三方库（hystrix-go 已归档，resilience4j 是 Java）生态不匹配 Go |
| 令牌溯源 | 利用现有审计系统的事件模型——外部队列（如 OpenTelemetry）反而失去了与现有 audit.Store 的自然关联 |
| 多区域复制 | 利用 PostgreSQL 原生流复制 + 应用层 ReplicaRole 感知——Kafka 级别的 CDC 管道是过度设计 |

### 4.3 与服务网格的关系

方向二（熔断器/舱壁）和服务网格（Istio/Linkerd）提供的断路器有重叠但**不冲突**：

| 维度 | 应用层熔断器（本设计） | 服务网格熔断器 |
|------|----------------------|--------------|
| 粒度 | 按 KMS/SAML/CAEP 等逻辑依赖 | 按 HTTP/gRPC 目标服务 |
| 语义 | 业务语义感知（KMS 限频 vs KMS 不可用） | 仅 HTTP 状态码 |
| fallback | 可按路径选择 fail-open/closed | 统一（通常是 503） |

两者互补：服务网格处理"到目标服务的连接故障"（网络层），应用层熔断器处理"业务语义的故障"（KMS 返回限频错误但不是连接失败）。

---

## 5. 实施路线图

### 5.1 优先级总览

```
        高 │ 方向一（多区域主动-主动）          方向三（限流完备化）*
           │     P0 ───── 架构级                       P1 ───── 安全速赢
           │
   价值    │ 方向二（外部依赖韧性）
           │     P1 ───── 架构韧性
           │
        低 │ 方向五（令牌溯源）                 方向四（配置门禁）
           │     P2 ───── 合规复杂                    P2 ───── 运维质量
           │
           └──────────────────────────────────────────────
              低                                    高
                        实现复杂度
```

*方向三标注为速赢项——DCR 接线仅 ~50 行改动，可独立于其他方向在 1-2 天内完成。

### 5.2 阶段划分

#### 阶段一：安全速赢 + 基础组件（2-3 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| DCR / admin / `/.well-known` 限流接线 | S | 消除 3 个攻击面 |
| Admin API 限流域合并到 PolicyStore | M | 统一限流配置面 |
| `platform/resilience/` 包（CircuitBreaker + Bulkhead SPI + 滑动窗口实现） | M | 通用韧性原语 |
| KMS client 接线熔断 | M | 防"KMS 限频搞垮 SSO" |

**验证标准：** `make acceptance` 通过，DCR 端点限流默认值生效，KMS 熔断器可通过集成测试验证。

#### 阶段二：架构韧性（3-4 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| `ReplicationTopology` 值类型 + `ReplicaRole` 声明 | M | 复制拓扑声明 |
| `ConsistentStore` 包裹器模式（SessionStore + AuthCodeStore） | M | 写转发 + 读一致性 |
| inter-region gRPC 转发管道 | L | 跨区转发基础设施 |
| SAML IdP / CAEP webhook / federation fetch 熔断接线 | M | 全面外部依赖保护 |

**验证标准：** 双 region 部署验证写转发 + 读一致性；熔断器全覆盖（KMS + SAML + CAEP + federation）。

#### 阶段三：合规 + 运维质量（3-4 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| 配置验证 `--ci` 模式 | S | CI 门禁 |
| 能力注册表 + 版本兼容矩阵 | M | 部署前兼容性检查 |
| TokenFamilyIndex 审计事件驱动模型 | L | 令牌生命周期追踪 |
| 令牌族谱查询 API | M | 合规审计用 API |
| 级联吊销（默认关闭） | M | 可选安全增强 |

**验证标准：** `sso-ctl config validate --ci --strict` 在错误配置下非零退出；令牌族谱查询返回完整 DAG。

### 5.3 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| 方向一写转发路径引入额外的请求延迟 | M | M | 默认 local-read（最终一致性）；leader-read 仅用于 `/token` 等关键路径；gRPC 连接池复用 |
| 方向二熔断器错误地熔断正常请求（误报） | L | H | 滑动窗口的 MinRequestCount 默认值保护（至少 5 个请求才开熔断）；half-open 试探保证恢复 |
| 方向五令牌族谱索引重建 scan 影响启动时间 | M | L | 后台渐进重建，不影响 `/readyz`；`withCascadeRevocation` 默认关闭 |
| ROADMAP 方向一（Hosted Login UI）与此处方向一（多区域）争夺 P0 资源 | M | H | 两者不冲突——前端 UI 和后端多区域复制可并行开发（不同技能树） |
| 代码库超过 500 行限制的文件被进一步塞入新功能 | M | M | AGENTS.md §0.1 硬门禁：在编辑前先 split。每个方向的新文件都应创建在正确的包下，不往已有大文件追加 |

### 5.4 依赖关系图

```
方向三（限流完备化）     ← 无前置依赖，可立即开始
      │
      ▼
方向四（配置门禁）       ← 依赖 buildinfo（已存在），可并行于方向三
      │
      ▼
方向二（熔断器/舱壁）    ← 无前置依赖（platform/resilience/ 是全新包）
      │
      ▼
方向五（令牌溯源）       ← 依赖 audit.Store（已存在）+ tokenusage（已存在）
      │
      ▼
方向一（多区域复制）     ← 依赖 cluster.Bus（已存在）+ gRPC（已存在）
                       但依赖方向五的 TokenFamilyIndex？不依赖——独立
```

**推荐启动顺序：** 方向三（速赢）→ 方向二（韧性原语）+ 方向四（并行）→ 方向五 → 方向一

实际方向一可在方向二之后启动（方向一的写转发可复用方向二的熔断器保护 inter-region gRPC 连接）。

---

## 6. 与其他已知工作的整合

### 6.1 与 ROADMAP v5 的关系

| ROADMAP v5 方向 | 与本分析重叠/互补 |
|----------------|-----------------|
| ① Hosted Login + Consent 存储 | **互补**——本分析不涉及 UI/前端，多区域复制可为全球部署的托管登录提供后端基础 |
| ② B2B 企业化（per-org IdP + HRD） | **互补**——多区域复制确保企业 IdP 连接在全球可用 |
| ③ OIDC 一致性收口 | **独立**——OIDC 正确性修复与韧性/多区域无关 |
| ④ 多副本数据面韧性 | **部分重叠但互补**——ROADMAP §④ 聚焦总线健壮性/签名密钥 lease/deny-set 持久化；本分析方向一聚焦数据复制/拓扑感知 |
| ⑤ 安全姿态与供应链 | **部分重叠但互补**——ROADMAP §⑤ 聚焦 client secret 明文存储/SAST/子模块 CI；本分析方向三（限流）/方向四（配置门禁）是安全/运维的另一面 |

### 6.2 与现有 `docs/requirements/` 文档的关系

声明：本分析的五个方向经逐项 grep 核验，与 65+ 份历史分析文档无重叠。无现存文档覆盖：
- 多区域数据复制
- 熔断器/舱壁
- DCR/Admin API 限流空白
- CI/CD 配置验证
- 令牌链式溯源

---

## 7. 否决项与不做之事

| 不会做的事 | 原因 |
|-----------|------|
| Kafka/CDC 管道作为复制层 | PostgreSQL 流复制 + 应用层 ReplicaRole 已经足够 |
| 引入 hystrix-go/resilience4j | 外部依赖审计成本 + Go 生态无活跃成熟替代 |
| 令牌溯源的新数据库表 | 审计事件 + 运行时索引已足够，新表增加迁移复杂度 |
| 配置验证的 DSL/Schema 语言 | 现有反射式 JSON Schema 生成 + struct tag 已满足 |
| ML 启发式限流 | 限流层应保持清晰可解释；ML 是 `domains/anomaly` 的领域 |
| 全面的端到端多 region 测试 | 真实多 region 测试需要多集群基础设施——建议用 `gRPC loopback + simlated latency` 模拟 |

---

## 8. 总结

| 维度 | 评估 |
|------|------|
| 架构健康度 | 极高——协议覆盖面全、层级清晰、门禁严格 |
| 剩余缺口 | 五个方向均为"从单 region 单依赖架构向全球多活韧性架构演进"的天花板缺口，非传统协议缺失 |
| 投入产出比最高 | 方向三（限流完备化）~50 行改动消除安全隐患 |
| 架构价值最高 | 方向一（多区域主动-主动）——解锁全球部署架构 |
| 次高架构价值 | 方向二（外部依赖韧性）——防"一个慢依赖搞垮整个 SSO" |
| 不做之事 | 五个方向均不需要新依赖/新语言/新框架——全在现有技术栈内完成 |
