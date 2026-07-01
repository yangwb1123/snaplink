Now I have a solid understanding of the project architecture. Let me provide the comprehensive analysis.

---

# Architecture Analysis: Audit System & Observability Roadmap

## 1. 架构评估

### 优势

当前代码库表现出几个值得强调的架构优势：

1. **有界基数聚合原则在 `FacetQuerier` 中贯彻良好。** `facets.go:19-52` 明确排除 ActorID（高基数），将其限定在 Outcome（2）、Type（固定词汇表）、ClientID、Provider（操作员配置的有限集合）。这是一个深思熟虑的决定，与 metrics 层的标签基数纪律一致。UI 层因此获得一个 O(1) 的 facet 响应，而不是一个随着用户数增长的响应。

2. **可选接口模式（`FacetQuerier` 作为 `Sink` 的可选扩展）。** 写路径的 `WebhookSink`、`WriterSink`、`RetryingSink` 不需要实现聚合能力——它们通过类型断言保持惰性，`AsyncSink`/`MultiSink` 委托给内部的 `FacetQuerier` 或报告 `ErrFacetsUnsupported`。这种按能力组合而非按类型继承的设计可以单独推广到其他跨领域关注点。

3. **`Recorder` 的 nil-safe 和零依赖设计。** `Recorder.Record` 在 nil Recorder 上短路，`RecordTokenIssued` 等辅助函数在所有 handler 中可无条件调用。这意味着引入 audit 不会在调用方引入防御性检查。

4. **Hash Chain 的跨重启连续性设计。** `ChainTip` 接口允许 SQLite sink 在启动时从最后一个持久化的 hash 恢复，保持跨部署边界的链完整性。这是一个在生产环境中经常被忽略的细节。

5. **物理分层架构强制依赖方向。** `architecture_layer_test.go` 和 `TestArchitecture_ImportBoundaries` 是一种可执行的架构 PRA（Policy as Code），比写在 wiki 里的文档更有效。

### 局限性

1. **FacetQuerier 的设计排除了任何超越"explorer filter UI"的聚合用例。** 这意味着方向五（MFA 覆盖率、弱密码检测、休眠账户）是*有意排除*的——不是疏忽，而是设计选择。代价是：需要用一个新的聚合层来填补这个缺口，该聚合层有自己的存储、查询和扩展模型。

2. **缺乏统一的跨协议 session 存储抽象。** 方向四（SessionHub）暗示需要跨 OAuth/OIDC/SAML/SCIM 协议的 session 数据统一视图。目前，每个协议的 session 数据分散在各自的 store 中（`oauth/token.go`、`oidc/...`），没有共享的 session 类型或生命周期钩子。

3. **`Recorder.Record` 是同步的。** 虽然 `AsyncSink` 提供异步写入，但主 Recorder 路径对 `Sink.Record` 的调用是同步的。在请求路径上（`/token`、`/auth/login`），这意味着 audit 事件的延迟直接叠加到请求延迟上。对于内存 sink 这不是问题，但一旦引入 SQLite、webhook、或后续的聚合层，延迟预算会成为一个约束。

4. **缺少聚合预计算层。** `FacetQuerier.Facets` 在查询时扫描整个匹配的事件集。对于超过几千个事件的窗口，扫描全部事件来统计 4 个维度的计数是不可持续的。SQLite 可以建索引，但内存扫描的时间复杂度是 O(N)。

5. **`Recorder` 的 `AddSink` 不是并发安全的。** 文档说"Not safe for concurrent use with Record"，这限制了热重载的能力——如果运营商在运行时想添加一个新的 audit sink（例如一个调试用的 webhook），他们必须协调所有请求线程。

### 关键设计决策评估

| 决策 | 评估 | 选项 |
|---|---|---|
| FacetQuerier 排除 ActorID | ✅ 正确的选择。高基数维度在有界基数模式下无法处理 | 后续聚合层可以支持高基数维度，因为底层存储模型不同（OLAP 风格的列存或物化视图） |
| `FacetQuerier` 作为可选接口 | ✅ 符合 Go 哲学，最小化 sink 实现者的负担 | 另一种选择是使用 `func (q Query) Facets() (*Facets, error)` 上的装饰器模式——但可选接口更轻量 |
| Recorder 同步 Record | ⚠️ 对于内存 sink 可接受，但对 SQLite/webhook 有延迟风险 | 可以将 sync 路径改为默认 async，但这会增加复杂度（背压、丢事件） |
| Hash chain 在 Record 中计算 | ✅ 正确——redaction 在 hash 之前，hash 在 sink 看到之前 | 可以推迟 hash 计算到后台批处理，但这会弱化 tamper-evident 保证 |

---

## 2. 扩展方向

### 方向 A：聚合查询层（Analytics Query Layer）— P1-P2

**为什么需要：**
- FacetQuerier 有意排除高基数聚合。方向五的"哪些用户 MFA 注册了？"、"哪些用户密码弱？"、"休眠账户"等查询需要对 ActorID 进行 GROUP BY + COUNT 聚合
- 运营者需要跨用户维度的安全态势概览，而不是逐个用户排查

**核心挑战和技术难点：**
- **索引 vs 扫描：** 如果直接使用 SQLite audit store，`WHERE actor_id = ? AND type = 'password_changed' GROUP BY outcome` 在百万级事件上需要合适的索引
- **物化还是实时：** 是引入一个预计算聚合的 Materialized View（类似 Prometheus 的 recording rules），还是所有聚合都在查询时计算？
- **存储模型：** 现有 `Event` 的 Metadata 是 `map[string]string`——metadata 中的字段（`auth_req_id`、`rotation`、`count`）在 SQL 层不可索引，除非引入 JSON 索引或列存
- **与 FacetQuerier 的关系：** 是不改 FacetQuerier 新建独立的聚合服务，还是把 FacetQuerier 扩展为支持高基数维度（违反有界基数原则）？

**建议：独立的 `AnalyticsQuerier` 接口（非 Sink 扩展，而是 Sink 的同行）**

```
// platform/audit/analytics.go
type AnalyticsQuerier interface {
    // MFAEnrollmentRate returns the fraction of active users who have
    // completed MFA enrollment.
    MFAEnrollmentRate(ctx context.Context, since time.Time) (float64, error)
    
    // UserAggregation runs a user-level aggregation query.
    // For a query like "count events per user for type=login_failure
    // in the last 7 days", the result is a UserCounts slice.
    UserAggregation(ctx context.Context, q UserAggregationQuery) (*UserAggregationResult, error)
    
    // Report returns a pre-defined report by name.
    Report(ctx context.Context, name string, params map[string]string) (*ReportResult, error)
}
```

**预期架构变更：**
- 新增 `platform/audit/analytics/` 目录
- `MemorySink` 和 SQLite sink 实现 `AnalyticsQuerier`（可选）
- `AnalyticsQuerier` 通过 `Recorder` 的 `Sink()` 返回的可选接口暴露
- 新增 HTTP handler `GET /api/v1/audit/reports/:name`

**对现有系统的影响：**
- 零侵入——`AnalyticsQuerier` 是完全可选的新接口
- 现有的 `FacetQuerier` 保持不变
- SQLite sink 需要针对聚合查询的索引优化，但可逐步添加

**选项 A1：Query-time 聚合** — 依赖 SQLite 索引，查询时计算聚合。简单，但对大数据量性能不可预测。

**选项 A2：物化聚合表** — 引入一个后台协程，定期对 audit event 运行聚合并写入聚合表。复杂度更高，但查询 O(1)。

**选项 A3：混合** — 对于常见报告（MFA 覆盖率、登录失败排行）用物化表，对于 ad-hoc 查询用 query-time 聚合。

**推荐：选项 A3（混合）** 作为方向五的起点。MFA 覆盖率和休眠账户是明确的、有限的聚合，适合物化；ad-hoc 用户级聚合用 SQLite 索引支撑。

---

### 方向 B：容量感知健康检查 + 级联健康 — P0

**为什么需要：**
- 当前 `/readyz` 是一个简单的二值检查（所有依赖都 OK → ready，否则 not ready）。在生产环境中，一个 SQLite SQLITE_BUSY、一个 audit sink 背压、或一个接近容量限制的 rate limiter，都不应该直接导致实例"not ready"
- K8s 的 rolling update 会 drain not-ready pods——一个瞬间的 SQLite 慢查询触发 not-ready，会导致整个 deployment 回滚

**核心挑战和技术难点：**
- **容量阈值确定：** 健康度从 0 到 1 的标量值（0.8 = 轻度压力，0.95 = 临界），需要为每个子健康检查定义阈值
- **级联健康：** 当 audit sink（例如 webhook）不健康时，是整个实例降级，还是只影响 audit 路径？
- **/readyz 的分流：** K8s 的 readiness probe 是二值的（HTTP 200/503），需要对标量健康度做截断

**预期架构变更：**
- 引入 `HealthProbe` 接口：`type HealthProbe func(ctx context.Context) (Health, error)` 其中 `Health` 包含 Status、Message、Capacity（可选浮点数）
- 引入 `HealthTree` 作为 `map[string]HealthProbe`，支持级联聚合（min/average）
- `/livez` 返回存活状态（goroutine 栈存活）
- `/readyz` 返回 readiness 及其子组件详细状态（JSON）
- `/capacity` 返回每个组件的容量百分比

```
// platform/health/probe.go
type Probe interface {
    Name() string
    Check(ctx context.Context) Result
}

type Result struct {
    Healthy  bool    // 是否可以服务流量
    Capacity float64 // 0.0 (dead) → 1.0 (fully healthy)
    Message  string  // 用于 operator 排查
}
```

**对现有系统的影响：**
- 新增 `platform/health/` 包
- 现有的 `/livez` `/readyz` handler 迁移到新包
- 每个子系统（audit、oauth store、oidc、signing keys）注册自己的 probe

---

### 方向 C：RiskScorer ↔ RateLimiter 上下文传递（L2→L3 协同）— P1

**为什么需要：**
- 当前 `RiskScorer` 和 `RateLimiter` 是独立的策略点，没有任何共享上下文
- 攻击者可以通过分布式慢速攻击绕过独立的限流器，同时风险评分器因为单个请求看起来正常而给出低分
- 协同的核心价值：一个登录请求的风险评分如果上升了（多个信号组合，例如新设备+非工作时间+未知IP），限流器应该立即给该用户/IP 降权

**核心挑战和技术难点：**
- **共享上下文的生命周期：** 风险评分发生在请求处理的中途（认证后、授权前），限流发生在请求入口。如何将评分结果传回到限流器？
- **同步 vs 异步：** 同步（request-scoped context）还是异步（event-driven，评分改变触发限流权重更新）？
- **限流权重的定义：** 是简单的"高风险→限制+1"，还是"高风险→rate limit window / 10"？
- **与 cluster bus 的关系：** 评分变化是否跨副本传播？如果是，需要新的 cluster event 类型

**预期架构变更：**
- 引入 `RiskContext` 接口，作为 `context.Context` 的值携带风险评分、信号摘要
- `RateLimiter` 接口扩展为 `RateLimiterWithContext`：`Allow(ctx context.Context, key string) (bool, RiskAdjustedLimit)`
- `SecurityContextMiddleware` 在请求入口初始化 `RiskContext`，认证过程的风险信号写入其中，限流器在入口和出口读取
- 新增 cluster event `KindRiskProfileChange` 用于跨副本传播评分变化

```
// platform/risk/context.go
type RiskContext struct {
    Score         float64          // 0.0 (safe) → 1.0 (certain attack)
    Signals       []RiskSignal     // 触发的风险信号
    RateLimitPenalty float64       // 0.0 (no penalty) → 1.0 (full block)
    lastUpdated   time.Time
}
```

**对现有系统的影响：**
- 中等侵入——需要修改请求处理流程
- 但独立于方向二和方向五——可以并行开发
- 新增 event type 需要 cluster bus 版本升级

**选项 C1：request-scoped 同步传递（context.Context）。** 简单，但限流器需要在请求入口就检查，而评分在中间——所以要么二次限流（入口一次+出口一次），要么批处理。

**选项 C2：event-driven 异步传递。** 评分变化通过 channel/bus 传播，限流器监听并更新权重。更复杂但更松耦合。

**推荐：C1（同步）+ 二次限流。** 入口有基础限流（基于 IP/client_id），出口有风险调节限流（基于评分）。二次限流是 fail-closed——出口限流器默认允许，只有在收到明确的高风险信号时才限制。

---

### 方向 D：SessionHub — 跨协议 Session 统一 — P3

**为什么需要：**
- 当前 OAuth/OIDC/SAML/SCIM 各自的 session 存储在各自的 domain 包中
- 没有统一的 session 生命周期管理（全局登出、跨协议 session 失效、session 审计）
- `/logout` 端点只能注销当前协议的 session

**核心挑战和技术难点：**
- **session 类型的统一抽象：** OAuth 的 session（AuthCode、RefreshToken、AccessToken、DeviceCode）和 OIDC 的 session（IDToken、SessionState）有不同的生命周期和字段
- **存储的统一：** 是共享一个 store 还是保持各自独立 store 但加入注册中心？
- **生命周期钩子：** 当用户触发登出时（OIDC RP-initiated logout），需要通知所有协议注销 session

**预期架构变更：**
- 引入 `session.Hub`：`Register(provider SessionProvider)`、`LogoutUser(ctx, userID) → []Session`、`RevokeSession(ctx, sessionID)`
- 每个协议实现 `SessionProvider` 接口
- `SelectiveLogout`（OIDC 特有的 `logout_hint` + `id_token_hint`）通过对应的 provider 处理
- `/session` 端点提供统一的 session 管理 API

```
// domains/session/hub.go
type SessionProvider interface {
    Protocol() string                    // "oauth", "oidc", "saml"
    ListByUser(ctx, userID) ([]Session, error)
    Revoke(ctx, sessionID) error
    LogoutUser(ctx, userID) error
}
```

**对现有系统的影响：**
- 中度侵入——需要为每个协议实现 `SessionProvider`
- 但不会修改现有协议的业务逻辑——只是增加了一个新的外部视角
- 依赖方向来自 SessionHub → domains（因为协议包不能互相导入），所以 SessionHub 只能引用 session 类型，不能引用协议包

---

### 方向 E：设备指纹和用户代理分析 SPI — P2

**为什么需要：**
- 方向一的设备管理（设备清单、可信设备、新设备检测）需要一个设备指纹 SPI
- 当前没有跨请求的用户代理/设备标识模型
- 设备指纹是风险评分的关键输入之一（"这个用户突然从新设备登录"）

**核心挑战和技术难点：**
- **指纹稳定性：** 被动指纹（User-Agent + IP + TLS handshake 特征）在稳定性和独特性之间权衡
- **SPI 抽象：** 是引入 SPI 层（允许接入 FingerprintJS、ThreatMetrix 等外部服务）还是内置一个轻量级被动指纹？
- **PII 处理：** 设备指纹可能包含 PII/标识符，需要 GDPR/CCPA 合规
- **与 RiskScorer 和 SessionHub 的关系：** 设备指纹的输出是 risk 信号，设备清单是 SessionHub 的扩展

**预期架构变更：**
- 引入 `spi.DeviceFingerprinter` 接口
- 引入 `domains/device/` 目录：`Device` 模型、`DeviceStore`、`DeviceSessionLink`
- 新增 API 端点：`GET /api/v1/user/devices`、`DELETE /api/v1/user/devices/:id`

**对现有系统的影响：**
- 低度侵入——新的 SPI + domain，不影响现有认证流程
- RiskScorer 可选择性集成

---

## 3. 接口设计建议

### 3.1 关键设计原则

**原则 1：可选接口（Optional Interface Pattern）**

审计系统中的 `FacetQuerier` 是可选接口模式的一个教科书案例。这个模式应该被复用：

```go
// 每个可选能力 = 一个接口，通过类型断言访问
type Sink interface {
    Record(ctx context.Context, event *Event) error
}

// 可选扩展 1：查询
type Querier interface {
    Query(ctx context.Context, q Query) ([]*Event, error)
    Get(ctx context.Context, id string) (*Event, error)
}

// 可选扩展 2：facet 聚合
type FacetQuerier interface {
    Facets(ctx context.Context, q Query) (*Facets, error)
}

// 可选扩展 3：物化分析
type AnalyticsQuerier interface {
    Reports(ctx context.Context) ([]ReportDefinition, error)
    RunReport(ctx context.Context, name string, params ReportParams) (*ReportResult, error)
}

// 可选扩展 4：健康
type HealthReporter interface {
    Health(ctx context.Context) ProbeResult
}
```

**原则 2：Handler 层零业务逻辑**

所有 handler 应是薄委托层：解析请求 → 调用 domain 函数 → 序列化响应。审计 handler（`handlers.go`）已经做到这一点——只做参数解析 + 调用。

**原则 3：Dagger 依赖（Deps 接口模式）**

`HandlerDeps` 模式（一个为 handler 聚合所需 SPI 的最小接口）应该推广到所有新 handler。它比直接传 `*sso.Server` 更易测试，且编译时保证不依赖 Server 的内部状态。

### 3.2 新的抽象层需求

| 抽象层 | 是否必要 | 理由 |
|--------|---------|------|
| `platform/health/` | ✅ 是 | 容量感知健康检查需要自己的包。当前的 `health.go`（可能在 `internal/handler/` 中）不足以支持方向二 |
| `platform/risk/` | ✅ 是 | RiskScorer + RateLimiter 协同需要风险上下文模型。`spi.RiskScorer` 已存在，但只有评分没有上下文传播 |
| `platform/analytics/` | ✅ 是 | 方向五的聚合需求。独立于 audit 的 FacetQuerier，不破坏有界基数原则 |
| `domains/device/` | ⚠️ 可能 | 如果设备管理只是存储设备+序列号+UserAgent，用 `domains/` 足够。如果需要设备指纹引擎，需要 SPI |
| `domains/session/` | ✅ 是（方向四） | 跨协议 session 统一需要自己的 layer，但不能被任意 domain 包导入 |

### 3.3 向后兼容性

所有新接口都是可选的、通过类型断言发现的，或者通过新的 Deps 接口方法访问的：

- **新增端点不会破坏现有客户端。** 新的 `/api/v1/audit/reports/*` 端点只对实现 `AnalyticsQuerier` 的 sink 有意义
- **新接口不修改现有接口签名。** `Sink` 接口不变。`FacetQuerier` 不变
- **配置向后兼容。** 新功能通过新的配置节启用，旧配置保持有效

---

## 4. 技术选型

### 4.1 需要的技术和框架评估

| 能力 | 自建 | 引入外部库 | 建议 |
|------|------|-----------|------|
| 分析聚合（物化聚合表） | ✅ 自建 | ❌ 不需要 | 核心需求有限（MFA覆盖率、弱密码统计、休眠账户），不值得引入 OLAP 引擎。SQLite WITH WINDOW functions 已足够 |
| 设备指纹 | 轻量级被动指纹 | FingerprintJS / Akamai 等 | **建议：SPI + 轻量级内置 + 可插拔外部**。100 行的被动指纹（User-Agent + Accept-Language + Timezone）覆盖 80% 的新设备检测需求。引用外部服务是可选扩展 |
| 限流权重传递 | ✅ 自建 | ❌ 不需要 | 就是 context.Context 携带 float64 |
| 健康模型 | ✅ 自建 | ❌ 不需要 | Probing 模式是 Go 标准模式，不需要框架 |
| Session 统一管理 | ✅ 自建 | ❌ 不需要 | 只是每个协议的 SessionProvider 注册中心 |

**结论：不需要引入新的外部依赖。** 当前的技术栈（Go stdlib + SQLite + net/http）完全涵盖方向一至五的需求。这是项目的一个重要优势——避免外部依赖贬值。

### 4.2 Bounded-box 模式：何时自建、何时 SPI

**自建的条件：**
- 核心安全决策路径的性能和正确性（MFA 覆盖率的计算、风险评分的传递）
- 与现有域模型的集成成本（跨协议的 SessionProvider）
- 无标准的稳定接口（设备指纹 SPI 在行业中没有统一的 Go 接口）

**SPI/插件的条件：**
- 有明确的提供商替换需求（LDAP、SAML、外部 KMS 已经遵循此模式）
- 合规或监管原因（GDPR 导出格式可插拔）
- 外部服务的特性在与核心逻辑解耦时更合适（CAEP/SSF 发射器已经是 SPI）

---

## 5. 实施路线图

### 优先级矩阵

| 优先级 | 方向 | 工作量估计 | 侵入程度 | 风险 | 关键依赖 |
|-------|------|-----------|---------|------|---------|
| **P0** | 方向二 L1（容量感知 health） | ~300 行 | 低 | 低 | 无 |
| **P0** | 方向一安全评分（MFA覆盖率 MVP） | ~300 行 | 低 | 低 | MFAEnrollmentStore（已有） |
| **P1** | 方向三 L2→L3 协同（RiskScorer + RateLimiter） | ~500 行 | 中 | 中 | RiskScorer SPI + RateLimiter SPI |
| **P1** | 方向五 MFA 覆盖率 + 休眠账户 | ~400 行 | 中 | 中 | AnalyticsQuerier 接口 |
| **P2** | 方向一设备管理 + 地理可视化 | ~600 行 | 中 | 中 | 设备指纹 SPI（新建） |
| **P3** | 方向四 SessionHub | ~800 行 | 高 | 高 | 依赖 Phase 1 SessionHub 协议统一 |

### 阶段划分

**Phase 0（当前 Sprint — 2-3 天）：方向二 L1**

```
Day 1:
  - platform/health/ 包创建
  - HealthProbe 接口 + HealthTree 聚合
  - /livez, /readyz, /capacity 端点
  - audit.Sink.Health() 注册（如果实现了 HealthReporter）

Day 2:
  - oauth store 健康检查
  - signing keys 健康检查  
  - K8s readiness probe 配置更新
  - 文档 + 测试
```

**Phase 1（下一 Sprint — 3-4 天）：方向一安全评分 MVP + 方向五聚合层**

```
方向一安全评分 MVP:
  - Recorder.MFAEvent("mfa_enrolled", "mfa_challenge_started", "mfa_challenge_completed")
  - 聚合层 AnalyticsQuerier 接口
  - MemorySink + SQLiteSink 实现 MFAEnrollmentRate()

方向五 MFA 覆盖率 + 休眠账户:
  - Report("mfa_coverage", {since: 30d})
  - Report("dormant_accounts", {threshold_days: 90})
  - GET /api/v1/audit/reports/:name
```

**Phase 2（后续 — 3-5 天）：方向三 L2→L3 协同**

```
- RiskContext 模型（platform/risk/）
- SecurityContextMiddleware 初始化
- RateLimiter 扩展：AllowWithContext(key, ctx) (bool, RiskAdjustedLimit)
- 二次限流：入口基础限流 + 出口风险调节限流
- Cluster event: KindRiskProfileChange
```

**Phase 3（长期 — 5-8 天）：方向四 SessionHub + 方向一设备管理**

```
SessionHub:
  - SessionProvider 接口
  - OAuthSessionProvider 实现
  - OIDCSessionProvider 实现
  - /session 端点
  - 全局登出

设备管理:
  - DeviceFingerprinter SPI + 被动指纹实现
  - DeviceStore
  - /user/devices 端点
```

### 风险点和缓解策略

| 风险 | 概率 | 影响 | 缓解策略 |
|------|------|------|---------|
| 方向三协同导致 RiskScorer 和 RateLimiter 耦合增加 | 中 | 高 | 保持 RiskScorer + RateLimiter 的 SPI 接口不变。RiskContext 只是 context-value，不是接口修改 |
| 方向五 AnalyticsQuerier 在大数据集上性能不可预测 | 中 | 中 | 先用物化表+后台协程。查询超时 5s fallback 到降级响应 |
| 方向四 SessionHub 与现有协议 session 生命周期不一致（session 过期时间不同步） | 高 | 高 | SessionHub 初期只提供*查询*能力，不管理生命周期。后续再添加 Revoke。Honeymoon 期/grace period 同步 |
| Phase 2 容量感知 health check 导致 K8s rolling update 过于敏感 | 中 | 高 | 容量 < 0.8 才触发 readyz 503。0.8-1.0 在 body 中报告但不影响 readiness |
| 新接口增加 TestMaintainability 门槛压力 | 低 | 中 | 新包在新目录中，不在现有大文件上增加代码。每个新文件被限制在 500 行 |

---

## 总结

你提议的优先级微调与我基于代码库的分析一致。方向二 L1（容量感知 health）确实是零侵入、高回报的起点——它能立即可见地改进生产 operator 体验，而无需触及任何认证路径。

方向一安全评分 MVP + 方向五聚合层是**最值得组合推进**的下一组：它们共享同一个架构缺口（没有用户级聚合的能力），通过引入 `AnalyticsQuerier` 可以一次性解决两个方向的核心依赖。方向三的协同价值高，但依赖风险管理实践——在 Phase 1 的聚合层完成后再推进会更安全。

方向四 SessionHub 的正确放置取决于跨协议 session 存储的统一程度。如果 P0/P1 阶段发现 OAuth 和 OIDC 的 session store 差异太大（字段、过期策略、存储后端不同），SessionHub 的 Phase 1 应该仅限于*查询* + 只读视图，跨协议的 `Revoke` 操作留到 Phase 2。
