# 架构分析报告：协议层收口后的下一阶段

> **角色：** 架构师  
> **来源：** `docs/requirements/expansion-post-protocol-layer-analysis.md`  
> **核验：** `docs/requirements/expansion-post-protocol-layer-analysis.out.md`  
> **日期：** 2026-07-12  

---

## 0. 执行摘要

本文档基于 2241 个 `.go` 文件的全局扫描结果，对 5 个扩展方向进行架构层面的评估、排序和设计建议。**核心发现：** 项目在协议覆盖和基础能力上已达到行业顶级水平，但面临从"功能完整"到"平台化运营"的架构跃迁。5 个方向中，3 个属于**架构跃迁**（授权即服务、事件智能、跨设备连续性），2 个属于**工程深度**（令牌运营优化、分析 BI）。

---

## 1. 架构评估

### 1.1 当前架构的优势

| 优势 | 评估 |
|---|---|
| **极致 SPI 化** | 638 个 `WithXxx` 配置选项、100+ SPI 接口（`TokenStore`、`SessionStore`、`JTIReplayStore` 等），几乎每个存储/策略/认证维度都有可插拔接口 |
| **协议覆盖完整** | OAuth 2.0 / OIDC / SAML2 / FAPI / CAEP / SCIM / WebAuthn / FIDO2 — 全套企业协议 |
| **六边形架构清晰** | `interfaces/` → `protocols/` → `shared/` 的依赖方向严格执行，`architecture_layer_test.go` 门禁 |
| **多后端支持** | memory / sqlite / postgres / redis / 各 KMS 后端 / LDAP / Kerberos — 每个 SPI 至少 2 个实现 |
| **零外部 SaaS 依赖** | 纯自包含，适合私有化部署 |

### 1.2 当前架构的局限性

| 局限性 | 影响 | 关联方向 |
|---|---|---|
| **事件子系统竖井化** | 审计、CAEP、webhook、SSE、cluster bus 五个事件出口互不感知，无法做跨源关联 | ② 事件智能平台 |
| **令牌签发完即"甩手"** | token 签发后不再参与授权决策，资源服务器各自为政 | ③ 授权即服务 PDP |
| **身份状态只存在于一次会话** | 无跨设备会话模型，用户每换设备需重新完成完整登录 | ① 跨设备身份连续性 |
| **运营设施只对运维可见** | Prometheus 指标面向运维，租户管理员对使用模式零可见性 | ⑤ 身份分析 BI |
| **生产运行深度不足** | 吊销集仅进程内、JWT 无瘦身、DPoP 无分片 — 在大规模下不可持续 | ④ 令牌生命周期优化 |

### 1.3 架构债务评估

**没有重大架构债务，但有 3 个架构缺口：**

1. **缺少统一事件抽象层** — 当前 5 个事件出口各自定义自己的事件模型，无共享的 `Event` 类型、无统一注册表、无跨源订阅。这不是"坏代码"，而是"缺少一个层"。

2. **授权决策与令牌签发的耦合** — 当前 `permissions.Provider` / `rebac.Check` 被 `tokenpolicy` 包在签发时调用，但签完令牌后资源服务器的授权决策不再经过系统。这不是代码耦合问题，是**架构边界缺口**：缺少一个与令牌路径解耦的授权决策路径。

3. **身份模型的单设备假设** — `SessionHub` 存在于 `platform/lifecycle/sessionhub/`，但其模型假设"一个用户一个活跃会话"，缺少多设备子会话模型。这是**领域模型缺口**：需要在 session hub 中建立设备维度。

> **建议：** 这三个缺口都可以增量补齐，不需要重写现有代码。每个缺口对应一个成熟的外部模式（事件源/事件驱动架构、PDP/PEP 模式、多设备会话图），有成熟的参考实现模式。

---

## 2. 扩展方向深度分析

### 2.1 P0 方向：授权即服务 PDP

#### 为什么是 P0

这是**架构跃迁**最大的一步。当前项目作为"令牌签发者"的能力已完整，但从企业采购视角看，"你签发 token 后怎么参与授权决策？"是关键的采购决策因素。REST `POST /api/v1/authorize` 端点将系统从**令牌引擎**升级为**授权平台**。

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| 统一策略模型 | ★★★ | 现有 RBAC + ReBAC + 条件访问（`conditionalaccess`）+ 信任评分（`trust`）是三个独立子系统，需整合到统一决策管道 |
| 决策日志 | ★★ | 需定义 `AuthorizationDecision` 结构体，包含 `decision_id`、`matched_policies`、`reason`、`context`。现有审计事件缺少 `reason` 字段 |
| 策略 DSL | ★★★ | 从 YAML 定义 → 编译 → 评估的完整管道。现有策略以代码形式嵌入（`permissions` 的 role-permission 映射） |
| 性能 | ★★ | 决策需在 5-10ms 内完成（同步调用场景），需策略索引和短路评估 |
| 向后兼容 | ★ | 新增 REST 端点，不修改现有路径。`mesh_authz.go` 的 Envoy ext_authz 路径继续保持 |

#### 架构变更

```
当前：
  tokenpolicy  → permissions.Provider + rebac.Check（签发时调用）
  
目标：
  ┌───────────────┐
  │ REST Authorize│ ← POST /api/v1/authorize
  │ HTTP Handler   │
  └───────┬───────┘
          │
  ┌───────▼─────────────────────────────────┐
  │ Authorization Pipeline                   │
  │  1. Identity Resolution (token → subject)│
  │  2. RBAC Check (permissions.Provider)    │
  │  3. ReBAC Check (rebac.Check)            │
  │  4. Condition Check (conditionalaccess)  │
  │  5. Decision Log (audit + metrics)       │
  └──────────────────────────────────────────┘
```

#### 设计决策选项

| 选项 | 权衡 |
|---|---|
| **A) 新包 `pdp/`** | 职责清晰，但新增包违反了 §0.1 目录深度规范。建议放在 `domains/authorization/` 下 |
| **B) 集成到 `permissions/`** | 避免了新包，但 `permissions/` 当前是 RBAC-only，混合条件引擎会增加复杂度 |
| **C) 集成到 `tokenpolicy/`** | 自然扩展，但 `tokenpolicy` 是"签发策略"，不是"授权决策策略"，语义不匹配 |
| **建议: A+B 混合** | 新建 `domains/pdp/` 做编排层，`permissions/` 做 RBAC 引擎，`conditionalaccess/` 做条件引擎，`pdp` 做管道编排 |

---

### 2.2 P0 方向：统一身份事件智能平台

#### 为什么是 P0

项目的事件基础设施（5 个出口）是**已投资但未充分利用的资产**。当前每个出口只产生数据但从不消费数据，相当于建好了高速公路但没有出口匝道。事件关联引擎是让这些数据产生价值的关键桥梁。

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| 统一事件模型 | ★★ | 5 个事件源各有自己的结构体，需要定义共享的 `Event` 类型和 `EventRegistry` |
| 关联窗口管理 | ★★★ | 时间窗口内的多事件关联需要"事件时间"而非"处理时间"语义，处理延迟到达事件 |
| 规则引擎性能 | ★★★ | 关联规则需在事件到达时快速匹配，O(N) 规则扫描对延迟敏感。需规则索引 |
| 自动响应执行 | ★★ | 现有 `threataction/` 包（动作注册表+执行器）可作为基础，但需扩展事件→动作的映射 |
| 存储成本 | ★★ | 事件存储的 TTL 策略和采样率直接决定存储成本 |

#### 架构变更

```
当前（竖井）：
  audit → SQLite sink
  caep  → SET push
  webhook → HTTP POST
  sse   → EventSource
  
目标（统一层）：
  所有事件源 → Event Bus → Event Store → Correlation Engine → Actions
                                        → Query API
                                        → Rule Engine
```

#### 设计决策选项

| 选项 | 权衡 |
|---|---|
| **A) 基于 `cluster/bus` 扩展** | 不需要新基础设施，但 cluster bus 是内部跨副本通信，语义是"内部信号"，非"业务事件" |
| **B) 新建 `domains/eventintelligence/`** | 干净起点，可以定义完美的事件模型，但需要新增 event bus 基础设施 |
| **C) 基于 `platform/sse` 扩展** | SSE 是单向流且无持久化，不适合做事件存储基础 |
| **建议: B** | 新建 `domains/eventintelligence/`，使用与 cluster bus 不同的通道（channel-based in-process event bus），避免跨租户事件泄漏 |

---

### 2.3 P1 方向：令牌生命周期大规模运营优化

#### 为什么是 P1（但 Phase 1 应该先做）

**安全修正**（吊销集持久化）应该实际上作为**最高优先级**执行，因为它修复一个已确认的安全漏洞。文档中已指出 ROADMAP v5.0 #4c 确认了问题："仅进程内内存、重启后空"。

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| 吊销集持久化 | ★ | 现有 `revocation_set.go` 是进程内 sync.Map，需加持久化后端 peer。纯增量 |
| DPoP nonce 分片 | ★★★ | 需要一致性哈希 + bloom filter + 滑动窗口，分布式系统复杂度高 |
| 令牌瘦身 | ★★ | 需要按 scope 过滤 claim + 可选的参考令牌模式，对现有 JWT 签发路径有影响 |
| CDN 内省缓存 | ★ | 签名自省令牌已有实现，只需要 CDN 缓存头策略配置 |

#### 架构变更

```
当前 revocation_set.go：
  sync.Map[string]time.Time（仅进程内）
  
目标：
  ┌────────────┐
  │ Memory LRU  │ ← 本地缓存
  ├────────────┤
  │ SQLite/Redis│ ← 持久化后端（新增 SPI: PersistentRevocationBackend）
  └────────────┘
```

#### 设计决策选项

| 选项 | 权衡 |
|---|---|
| **A) 扩展 `revocation_set.go` 加后端** | 最小代码变更，在现有 `RevocationSet` 接口上加持久化方法 |
| **B) 新建 `domains/revocation/`** | 职责更清晰，但对现有调用路径改动大 |
| **建议: A** | 不超过 200 行新增，使用现有存储后端（sqlite/redis 已有），不改变 `Validate()` 接口签名 |

---

### 2.4 P1 方向：跨设备身份连续性

#### 为什么是 P1（Phase 1 可前置）

Session Roaming 是**中等复杂度的产品差异化能力**，对企业远程办公场景高价值。但 FIDO2 CTAP 2.2 Hybrid 依赖浏览器 API 成熟度和标准草案稳定性，风险较高。

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| Session Roaming 安全模型 | ★★★ | Claim token 的设计（绑定源会话、短 TTL、单次使用、带外传输）是安全关键 |
| 并发会话管理 | ★ | 在已有 SessionHub 上扩展设备维度，数据结构已定义 |
| Hybrid CA | ★★★★ | CTAP 2.2 草案级实现 + QR/Bluetooth/NFC 传输 + 浏览器 API 集成 |
| 中继攻击防御 | ★★★ | 挑战绑定 IP + 设备指纹 + 地理位置突变检测 |

#### 架构变更

```
当前 SessionHub：
  User → Session（一对一）

目标 SessionHub：
  User → SessionGroup → DeviceSession[]（一对多）
                        └── 每个 DeviceSession 有独立的 claim_token 和信任等级
```

#### 分阶段建议

| Phase | 范围 | 工作量 | 风险 |
|---|---|---|---|
| Phase 1 | Session Roaming + 并发会话管理 | 3-4 周 | 低（纯后端，不涉及浏览器标准） |
| Phase 2 | FIDO2 CTAP 2.2 Hybrid | 8-12 周 | 高（浏览器兼容性 + 草案变动） |

---

### 2.5 P2 方向：身份分析与多租户 BI

#### 为什么是 P2

这是**纯新增**方向，不修复安全漏洞、不补齐架构缺口、不直接影响核心用户体验。它的价值在客户成功和运营效率，属于"有了更好"而非"必须有"。

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| 分析引擎预聚合 | ★★★ | 原始审计事件 → 时间桶预聚合（5m/1h/1d）→ 趋势检测，需要批量处理管道 |
| 租户隔离 | ★ | 分析引擎强制租户过滤，防止跨租户数据泄露 |
| 健康评分定义 | ★★ | 评分因子权重需要产品验证，可能在运营中持续调整 |
| 仪表盘前端 | ★★★ | 嵌入式 SPA + 图表库 + 定时报告 PDF 生成 |

#### 架构变更

```
当前：
  audit store（原始事件）
  Prometheus metrics（技术指标）

目标：
  ┌──────────────────┐
  │ Analytics Engine   │ ← 新包 domains/analytics/
  ├──────────────────┤
  │ Aggregation Tiers   │
  │ 5m → 保留 7 天      │
  │ 1h → 保留 90 天     │
  │ 1d → 保留 3 年      │
  ├──────────────────┤
  │ Report Scheduler    │ ← 定时生成 + 邮件投递
  └──────────────────┘
```

#### 降低工作量的选项

- **前端使用嵌入式 Grafana 而非自建仪表盘** — 但需要 Grafana 作为外部依赖，违背零外部 SaaS 原则
- **分析 API 先行（Phase 1），前端 UI 后置（Phase 4）** — 最务实的路径
- **健康评分基于 Prometheus 记录规则（recording rules）** — 利用已有基础设施，但 PromQL 表达能力有限

---

## 3. 接口设计建议

### 3.1 关键新 SPI 设计

以下是 5 个方向需要引入的新 SPI 接口：

```
// 方向 3：授权决策 SPI
type Authorizer interface {
    Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeDecision, error)
}

type PolicyStore interface {
    ListPolicies(ctx context.Context, tenantID string) ([]Policy, error)
    GetPolicy(ctx context.Context, policyID string) (*Policy, error)
    CreatePolicy(ctx context.Context, policy *Policy) error
    UpdatePolicy(ctx context.Context, policy *Policy) error
    DeletePolicy(ctx context.Context, policyID string) error
}

type DecisionLogger interface {
    LogDecision(ctx context.Context, decision *AuthorizeDecision) error
}

// 方向 2：事件智能 SPI
type EventStore interface {
    Append(ctx context.Context, event *Event) error
    Query(ctx context.Context, filter *EventFilter) (*EventCursor, error)
    Correlate(ctx context.Context, eventIDs []string) (*CorrelationGraph, error)
}

type CorrelationRule interface {
    Name() string
    Match(events []*Event) (bool, *SynthesizedEvent)
}

type ActionExecutor interface {
    Execute(ctx context.Context, action *Action) error
}

// 方向 1：设备会话 SPI
type DeviceSessionStore interface {
    Register(ctx context.Context, session *DeviceSession) error
    GetBySessionID(ctx context.Context, sessionID string) ([]DeviceSession, error)
    UpdateTrust(ctx context.Context, deviceID string, trusted bool) error
    Revoke(ctx context.Context, deviceID string) error
}

// 方向 4：持久化吊销 SPI
type PersistentRevocationBackend interface {
    Add(ctx context.Context, key string, exp time.Time) error
    Contains(ctx context.Context, key string) (bool, error)
    Sweep(ctx context.Context) (int, error)
}

// 方向 5：分析 SPI
type AnalyticsStore interface {
    Record(ctx context.Context, bucket *MetricBucket) error
    QueryTimeSeries(ctx context.Context, filter *TimeSeriesFilter) (*TimeSeries, error)
    QueryTenantHealth(ctx context.Context, tenantID string) (*TenantHealth, error)
}
```

### 3.2 接口设计原则

| 原则 | 说明 |
|---|---|
| **已有 SPI 优先扩展** | 如 `RevocationStore` 加持久化方法、`SessionManager` 加设备维度，而非大包大揽的新 SPI |
| **单 SPI 单职责** | `Authorizer` 只负责决策，不负责策略管理。`PolicyStore` 独立出来 |
| **同步决策、异步分析** | 授权决策必须是同步的（5-10ms），事件关联和分析可以是异步的 |
| **上下文透传** | 所有新接口的第一个参数是 `ctx context.Context`，包含 `tenant_id`、`span`、`trace_id` |
| **失败模式明确** | 每个 SPI 文档中标注 fail-open / fail-closed，遵循现有 §3 规范 |

### 3.3 向后兼容性策略

| 变更类型 | 策略 |
|---|---|
| 新增端点 | 无兼容性问题。`POST /api/v1/authorize` 是全新端点 |
| 新增 SPI 方法 | 使用 Go interface 的扩展模式：定义新接口 `PersistentRevocationBackend`，不修改现有 `RevocationSet` |
| 新增配置选项 | 新增 `WithXxx` 选项，不影响现有 `NewServer()` 调用 |
| 数据结构扩展 | 如 `SessionHub` 的设备维度：新字段零值表示"未使用兼容模式" |
| 审计事件扩展 | 新增 `reason` 字段：空值做"unkown_decision"处理，不改变现有消费者 |

---

## 4. 技术选型

### 4.1 新增依赖评估

| 方向 | 建议依赖 | 评估 |
|---|---|---|
| ① 跨设备 | **无新增外部依赖** | QR 码生成使用标准库 + Web Bluetooth/NFC 为浏览器 API |
| ② 事件智能 | **无新增外部依赖** | 事件存储可复用已有的 sqlite/postgres/redis。规则引擎用 Go 原生的表达式求值（如 `expr` 或 `cel-go`） |
| ③ 授权即服务 | **可选：策略表达式引擎** | 建议使用 Google `cel-go`（CEL）做条件表达式求值，而非自研 DSL。CEL 是 Istio/K8s 使用的策略语言，成熟度高 |
| ④ 令牌运营 | **无新增外部依赖** | 持久化吊销集使用已有存储后端；bloom filter 可用 `willf/bloom` 或自实现 |
| ⑤ 身份分析 | **可选：时序数据库** | 预聚合桶存储可以复用现有 postgres，但 3 年粒度的时序数据建议使用独立的列存（如 sqlite 按时间分区） |

### 4.2 自建 vs 采购/集成

| 决策 | 建议 | 理由 |
|---|---|---|
| 决策 DSL | **自建基于 CEL** | CEL 是成熟的表达式语言，Go 原生实现，无外部依赖。不需要自研完整 DSL |
| 事件规则引擎 | **自建规则注册表** | 项目的规则引擎不需要通用 CEP 引擎（如 Esper/Spark），每秒事件量在千级，Go 原生 `[]Rule` 足够 |
| 分析仪表盘 | **自建 API + 可选 Grafana** | 分析 API 必须自建（深度集成多租户隔离和身份模型），仪表盘前端可以用嵌入式 Chart.js/Grafana |
| 定时报告 | **自建调度器** | Go 的 `cron` 包 + 现有 EmailSender，不需要外部调度器 |

### 4.3 评估标准

所有新增依赖必须满足以下条件：

1. **Go 原生实现，无 CGO** — 保持纯 Go 编译链
2. **Apache 2.0 / MIT 许可** — 避免 AGPL/GPL 传染
3. **零外部 SaaS 依赖** — 可离线部署
4. **与现有 sqlite/postgres/redis 后端兼容** — 不引入新数据库
5. **与现有 `memory.` 实现同级** — 每个新 SPI 必须有内存实现以支持测试

---

## 5. 实施路线图

### 5.1 优先级矩阵

```
                    高
                    │
    高价值          │  ② 事件智能      ③ 授权PDP
    低工作量        │  (Phase 1)       (Phase 1)
                    │
                    │  ④ 令牌运营       ① 跨设备
                    │  (Phase 1)       (Phase 1)
                    │
                    │  ④ Phase 2-3    ① Phase 2    ⑤ 身份分析
                    │  ② Phase 2-3    ③ Phase 2-3   (全阶段)
                    │
                    └─────────────────────────────
                    低                               高
                             工作量
```

### 5.2 推荐阶段划分

#### Sprint 1-2：安全修正 + 基础设施（P0 修正）

| 项 | 内容 | 工作量 |
|---|---|---|
| ④ Phase 1 | 吊销集持久化（sqlite/redis peer） | 2 周 |
| ② Phase 1 | 统一事件类型定义 + EventRegistry | 1 周 |
| ③ Phase 1 | `AuthorizationDecision` 结构体 + 决策日志 SPI | 1 周 |

#### Sprint 3-6：P0 方向并行（2 个团队）

**团队 A — 授权即服务**

| 项 | 内容 | 工作量 |
|---|---|---|
| ③ Phase 1 | `POST /api/v1/authorize` 端点 + RBAC/ReBAC 集成 | 3 周 |
| ③ Phase 1 | 条件引擎集成（conditionalaccess + trust） | 2 周 |
| ③ Phase 2 | 策略 DSL（CEL）+ PolicyStore + 管理 API | 4 周 |

**团队 B — 事件智能**

| 项 | 内容 | 工作量 |
|---|---|---|
| ② Phase 1 | Event Store（sqlite/postgres + memory） | 3 周 |
| ② Phase 1 | 查询 API + 规则注册表 | 2 周 |
| ② Phase 2 | 事件关联引擎 + 合成事件管道 | 4 周 |

#### Sprint 7-9：P1 方向 + P0 收尾

| 项 | 内容 | 工作量 |
|---|---|---|
| ① Phase 1 | Session Hub 扩展 + 设备子会话 | 3 周 |
| ① Phase 1 | 并发会话管理 + 管理 API | 1 周 |
| ④ Phase 2 | DPoP nonce 分片 + JTI 分层存储 | 3 周 |
| ③ Phase 3 | 策略管理 UI | 3 周 |
| ② Phase 3 | 可配置规则 UI + 时间序列分析 | 3 周 |

#### Sprint 10-12：P2 + 剩余项

| 项 | 内容 | 工作量 |
|---|---|---|
| ⑤ Phase 1 | 分析引擎 + 预聚合桶 + 分析 API | 3 周 |
| ④ Phase 3 | 令牌瘦身 + CDN 内省缓存 | 3 周 |
| ① Phase 2 | FIDO2 CTAP 2.2 Hybrid（实验性） | 6 周 |
| ⑤ Phase 2 | 租户健康评分 + 趋势检测 | 3 周 |
| ⑤ Phase 3-4 | 定时报告 + 仪表盘前端 | 4 周 |

### 5.3 风险点与缓解策略

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| **策略 DSL 范围蔓延**（从简单的 CEL 表达式蔓延到图灵完备策略语言） | 中 | 高 | 坚持 CEL-only，拒绝自定义 DSL；复杂策略推荐使用 OPA sidecar |
| **事件关联规则性能不达标**（全量规则扫描导致事件处理延迟） | 低 | 中 | 规则索引（按事件类型预分组）+ 规则编译到有限状态机 + 超时熔断 |
| **CTAP 2.2 标准草案变动** | 高 | 高 | Phase 2 标记为实验性，加入 feature flag（`WithHybridCA(experimental bool)`） |
| **分析查询影响主库性能** | 中 | 高 | 分析引擎使用独立的只读副本/连接池 + 查询超时 5s + 长范围查询只返回预聚合数据 |
| **团队同时推进 5 个方向导致质量下降** | 高 | 高 | 严格 gate：每个方向 Phase 1 完成后必须通过现有所有 gate（`make ci` + `python cli.py accept`）才能进入下一方向 |

### 5.4 依赖关系图

```
④ Phase 1（吊销持久化）
  └── 无依赖，可最先做

③ Phase 1（REST 授权端点）
  └── 依赖：permissions.Provider ✅、rebac.Check ✅、conditionalaccess ✅

② Phase 1（统一事件存储）
  └── 依赖：platform/audit ✅、caep ✅、webhook ✅

① Phase 1（Session Roaming）
  └── 依赖：SessionHub ✅、SessionStore ✅

③ Phase 2（策略 DSL）
  └── 依赖：③ Phase 1 ✅、cel-go（新增依赖）

② Phase 2（关联引擎）
  └── 依赖：② Phase 1 ✅

① Phase 2（Hybrid CA）
  └── 依赖：① Phase 1 ✅、webauthn ✅

⑤ 全阶段
  └── 依赖：platform/audit ✅、platform/metrics ✅、multi-tenant model ✅
```

### 5.5 Gates 验收标准

每个方向 Phase 1 完成时必须通过以下门禁：

| Gate | 检查项 |
|---|---|
| `go build ./...` | 编译通过 |
| `go vet ./...` | 无 vet 错误 |
| `make acceptance` | 全测试套件通过 |
| `python cli.py check-root` | 根目录合规 |
| `go test -run 'TestMaintainability_'` | 预算 gate 通过（无新增豁免） |
| `go test -run 'TestArchitecture_'` | 依赖方向 gate 通过 |
| 新 SPI 必须有 `memory.` 实现 | 测试可使用真实内存实现而非 mock |

---

## 6. 总结性建议

### 执行优先级

```
必须先做（安全修正）：
  ④ Phase 1 — 吊销集持久化（2 周）

架构跃迁（P0，并行）：
  ③ 授权即服务 PDP  —— 从令牌引擎到授权平台
  ② 事件智能平台      —— 从事件竖井到智能网络

产品差异化（P1，串行，优先 Session Roaming）：
  ① Phase 1 — Session Roaming + 并发会话
  ④ Phase 2-3 — DPoP 分片 + 令牌瘦身

运营增值（P2，最后）：
  ⑤ 身份分析 BI
  ① Phase 2 — Hybrid CA（实验性）
```

### 关键架构决策总结

| 决策 | 选择 | 理由 |
|---|---|---|
| 授权 DSL | CEL（cel-go） | 成熟、Go 原生、无外部依赖、Istio/K8s 验证 |
| 事件关联引擎 | 自建规则注册表 | 千级 TPS 不需要通用 CEP 引擎 |
| 设备会话模型 | SessionHub 扩展 | 不新增包，利用现有关系 |
| 分析存储 | 预聚合桶复用 postgres | 不引入新数据库 |
| 吊销集持久化 | 扩展现有 revocation_set.go | 最小变更路径 |

### 最终建议

**不要试图同时推进 5 个方向。** 推荐采用"1+2"策略：一个安全修正先行（④ Phase 1），两个 P0 架构跃迁并行（③ + ②），等前三个 Sprint 稳定后再启动 P1/P2。这保证了：安全漏洞 2 周内修复、架构跃迁 6 周内交付核心能力、产品差异化在 Q2 内交付。

