# 架构分析报告：NHI、姿态扫描、后量子方向的架构设计评审

> **分析师：** 资深架构师 Agent  
> **日期：** 2026-07-11  
> **基于：** `docs/requirements/architect-expansion-novel-5-directions-v6-code-scan.md` +   
>   `docs/architect-analysis-v6-five-directions.md` +   
>   针对 NHI/Posture/PQ 方向的深度代码验证与架构推演  
> **状态：** 架构分析文档（非 feature spec），后续可拆分为 `docs/feature-spec-*.md`

---

## 1. 架构评估

### 1.1 当前架构的优势（与扩展方向的适应性分析）

从 NHI、ISPM、PQ 三个待建方向的视角重新审视现有架构，可以看到**大量可复用资产**：

| 优势 | 对扩展方向的适配价值 |
|------|---------------------|
| **六层物理分层 + 依赖方向门禁** | NHI 放入 `domains/nonhumanidentity/` 自然获得正确的向下依赖方向；`protocols/oauth/` 可在不违反层规则的前提下引用 NHI 域 |
| **SPI 驱动 + memory peer 范式** | NHIStore 的 SPI + memory/sqlite/etcd 三实现完全复用现有模式；RotationScheduler 的 SPI 可借鉴 `signingkeys.RotationScheduler` |
| **`cluster.Bus` 跨副本广播** | NHI 的 `KindCredentialRotated` / `KindServiceAccountDisabled` 复用现有 `Kind*` 枚举 + 总线，零新基础设施 |
| **`shared/trust/composite.go` 加权组合评分器** | ISPM 的姿态评分可原样复用 `WeightedComposite.Score()` 的加权组合模式——无需新框架 |
| **`platform/audit` + `SetMeta` 模式** | NHI 审计事件复用 `audit.Recorder`；令牌溯源复用 `tokenusage` 的 Offer+drain 异步模式 |
| **`security` 的算法注册表 + 多 alg 矩阵** | PQ 迁移的混合签名模式（Ed25519 + ML-DSA-65）可直接扩展 `asymmetric_algs_test.go` 的算法枚举 |

### 1.2 当前架构的局限（从三个方向看）

| 局限 | 影响方向 | 根因 |
|------|---------|------|
| **`core/spi.go` 的 `User` 接口不含凭据管理方法** | **NHI** | User SPI 设计为认证主体查询，非凭据生命周期管理——ServiceAccount 不能复用该 SPI |
| **`protocols/oauth/handle_register.go` 的 `DCRResponse.client_secret_expires_at` 硬编码 0** | **NHI** | 凭据过期域模型不存在于 `core.Client` 中——`ServiceAccount` 须从零定义凭据过期 |
| **`shared/trust/composite.go` 的 `Scorer` 未在热路径外被消费** | **ISPM** | 信任评分模式存在但仅限于 `anomaly.RiskScorer`——无通用姿态断言 SPI |
| **`security` 的 JWS 头硬编码为 `{alg, kid, typ}`** | **PQ** | 无扩展点支持 `pq` / `x5t` / 混合签名额外字段——需改 JWT 序列化 |
| **`cluster.Bus` 事件种类有限（仅有 KindTokenRevoked / SigningKeyRotation / ClientChange / AuthzPolicyChange）** | **NHI, ISPM** | 需新增 `KindCredentialRotated`、`KindPostureAlert`、`KindServiceAccountChange` |
| **`platform/audit` 事件类别无 `NHI` 或 `Posture` 分类** | **NHI, ISPM** | 审计查询无法按方向过滤——扩展 `audit.EventType` 枚举 |

### 1.3 架构债务评估（与三个方向相关的部分）

| 债务类型 | 严重程度 | 影响方向 | 备注 |
|---------|---------|---------|------|
| **refresh 令牌的 HMAC-SHA256 数据库查找——Grover 算法下安全降级** | **中** | **PQ** | SHA-256 约为 128 位安全性（Grover 减半）。短期（3-5 年）不紧急，但 HNDL 攻击者今天可捕获密文 |
| **SQLite ClientStore 丢弃 10+ 字段** | **高** | **NHI** | ServiceAccount 的 `allowed_algorithms`、`max_keys`、`rotation_policy` 需要持久化——SQLite 的列不足问题将直接影响 NHI |
| **Token exchange `act` 链仅有 JWT claim，无可查询持久化** | **中** | **ISPM** | 姿态扫描需要完整的令牌衍生图谱——当前仅在 JWT 存活期内可追溯 |
| **无外部依赖熔断器** | **中** | **ISPM** | 姿态评分器的数据源（审计、令牌使用、客户端配置）查询失败会影响姿态评分可用性 |
| **`security/asymmetric_algs_test.go` 的主算法列表硬编码** | **低** | **PQ** | 算法注册表未设计为可扩展——PQ 算法新增需要修改注册表而非注册新项 |

---

## 2. 扩展方向架构分析

### 2.1 方向一：NHI 生命周期管理（P0 — 立即启动）

#### 2.1.1 为什么需要：业务价值 + 技术价值

**业务价值：**
- 当前只能管理人类用户的认证生命周期——ServiceAccount（GitHub Actions、K8s ServiceAccount、Terraform 工作负载）没有一等公民支持
- 凭据轮换完全靠外部手动流程——无自动过期、无旋转策略、无审计追踪
- 安全扫描会标记"无过期时间的长期凭据"——这是 SOC2 / ISO 27001 合规的高频发现项

**技术价值：**
- 统一碎片化的现有设施（`apikey.go`、`client_creds`、SPIFFE、workload_identity）
- 提供可审计的凭据生命周期（颁发 → 使用 → 轮换 → 吊销）
- 为后量子迁移提供凭据清单基础（PQ 迁移需要知道哪些令牌用了经典算法）

#### 2.1.2 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **ServiceAccount 与 User 的关系** | M | 选项：独立实体（独立 `svc-` 前缀）vs User 子类型（共享 `usr-` 命名空间）。独立实体会导致认证流程中多一次条件分支；子类型会泄露人类用户的不变量（密码、MFA、个人资料）到非人类实体 |
| **凭据轮换的推/拉决策** | H | 推模式（服务器主动推送新凭据到回调 webhook）更安全（减少凭据在传输中的窗口），但要求客户端有公网可达的接收端点；拉模式（客户端定期轮询）+ 轮询死期（不拉则吊销）更普适但增加延迟 |
| **单一事务中禁用 + 吊销所有活跃凭据** | H | `DisableServiceAccount` 需要在一个事务中完成 `UPDATE status=disabled` + `DELETE所有活跃凭据`。当前 `revocation_set.go` 仅处理 JWT JTI，不处理 API 密钥 / X.509 证书——需要新的吊销 SPI |
| **跨副本撤销的时序一致性** | M | NHI 凭据在 region A 被吊销，region B 需要尽快知晓。`cluster.Bus` 的 best-effort 语义意味着必须有 TTL 收敛窗口 |

#### 2.1.3 关键设计决策分析

**决策 1：ServiceAccount 是独立实体还是 User 子类型？**

| 选项 | 优点 | 缺点 |
|------|------|------|
| **A: 独立实体（推荐）** | 零泄漏人类用户不变量；`svc-` 前缀可直接路由；`core.User` 的 SPI 不变 | 认证流程需多一个条件分支（"是 User 还是 ServiceAccount？"）；某些共享逻辑（如会话管理）需抽象 |
| **B: User 子类型** | 复用 `UserProvider` 的 CRUD；认证流程改动最小 | 污染 User SPI（密码、MFA 方法等字段对 SA 无意义）；查询需过滤 type 字段；`usr-` 前缀冲突 |

**推荐：选项 A。** 理由：
1. `core.User` 已有 15+ 方法——加 `IsServiceAccount()` 和 `Credentials()` 将膨胀接口
2. ServiceAccount 的认证协议不同（不是密码/MFA，是 `client_secret` / SPIFFE / 预置 X.509）——需要独立的认证器
3. ID 前缀区分使得审计日志一眼可辨

**决策 2：凭据轮换推还是拉？**

| 选项 | 优点 | 缺点 |
|------|------|------|
| **A: 拉模式 + 轮询死期（推荐）** | 客户端不需要公网端点；复用现有 `POST /token` 的认证流程 | 凭据在轮询间隔内可能已被窃取但未被轮换 |
| **B: 推模式（webhook 回调）** | 减少凭据窗口；与 CAEP webhook 复用相同基础设施 | 要求客户端有可接收 webhook 的端点——降低了普适性 |
| **C: 混合（推荐变体）** | 结合两者的优点 | 双倍实现成本；需要决定何时用推、何时用拉 |

**推荐：选项 A 拉模式，带轮询死期。** 当轮换发生时：
1. 服务器标记旧凭据为 `pending_rotation`——仍有效但不可用于新建认证
2. 服务器创建新凭据但标记为 `pending_activation`
3. 客户端下次认证时用旧凭据认证，收到新凭据（类似 refresh token 的 rotation）
4. 如果客户在 `RotationDeadline` 内没有用新凭据认证——强制吊销旧凭据

#### 2.1.4 建议的包结构

```
domains/nonhumanidentity/
├── nhidentity.go           # ServiceAccount 聚合根 + NHI 核心 SPI
│                           #   type ServiceAccount struct {
│                           #     ID: string           // "svc-" + ulid
│                           #     Name: string
│                           #     Owner: Subject        // 谁创建了这个 SA
│                           #     Status: SAStatus      // Active / Disabled / PendingRotation
│                           #     MaxKeys: int
│                           #     AllowedAlgorithms: []string
│                           #     RotationPolicy: *RotationPolicy
│                           #     ...metadata...
│                           #   }
│                           #   type NHIProvider interface {
│                           #     Get(ctx, id) (*ServiceAccount, error)
│                           #     Create(ctx, sa) error
│                           #     Update(ctx, sa) error
│                           #     Disable(ctx, id) error  // 隐含吊销所有活跃凭据
│                           #     ListByOwner(ctx, subject) ([]*ServiceAccount, error)
│                           #     ListStale(ctx, deadline) ([]*ServiceAccount, error)
│                           #   }
│
├── nhcredential.go         # APIKeyCredential / X509Credential / OAuth2ClientCredential
│                           #   凭据值类型 + CredentialStore SPI
│                           #   type CredentialStore interface {
│                           #     Issue(ctx, sa_id, type, metadata) (*Credential, error)
│                           #     Revoke(ctx, credential_id) error
│                           #     RevokeAll(ctx, sa_id) error          // 禁用时调用
│                           #     GetActive(ctx, sa_id) ([]*Credential, error)
│                           #   }
│
├── nhrotation.go           # RotationPolicy / RotationScheduler 接口
│                           #   type RotationScheduler interface {
│                           #     Schedule(ctx, sa_id, policy) error
│                           #     Cancel(ctx, sa_id) error
│                           #     Next(ctx) ([]DueRotation, error)    // 供 scheduler loop 调用
│                           #   }
│
├── nhrotation/             # 参考实现：基于时间 + 审计的默认轮换调度器
│   └── scheduled.go
│
├── nhpolicy.go             # 治理策略：风险分级、最大密钥数、允许的算法
│
├── nh_test.go              # 域级别单元测试
└── mem/
    ├── nhidentity.go       # MemoryNHIProvider
    └── nhcredential.go     # MemoryCredentialStore (也提供吊销原子性)
```

#### 2.1.5 对现有系统的影响

| 影响 | 程度 | 说明 |
|------|------|------|
| 新增 SPI | M | NHIProvider + CredentialStore + RotationScheduler |
| 新增 cluster.Bus 事件种类 | S | `KindCredentialRotated`、`KindServiceAccountDisabled` |
| 认证流程变更 | M | `OAuthGrantHandler` 需要区分人类用户与 SA 的认证路径 |
| Admin API 扩展 | M | 新增 ServiceAccount + Credential CRUD gRPC + REST |
| 审计扩展 | S | 新增 `NHI` 事件类别，`SetMeta` 支持 `credential_id`、`rotation_phase` |
| 现有文件影响 | L | 不修改现有 `core/spi.go`——`ServiceAccount` 走新 SPI |

---

### 2.2 方向二：运行时安全态势管理（Runtime ISPM）（P2 — 6-8 周后启动）

#### 2.2.1 为什么需要：业务价值 + 技术价值

**业务价值：**
- 企业客户需要持续评估自己的 SSO 配置安全姿态——"我的 Client 配置是否都用了安全算法？refresh token 是否设置了合理的 TTL？"
- 当前的姿态是离散的（客户端配置在 `oauth/handle_register.go`，令牌审计在 `audit/recorder_events_token.go`，密码健康在 `spi/password_health.go`）——没有统一的视图

**技术价值：**
- 复用 `shared/trust/composite.go` 的 `WeightedComposite` 评分框架——零新基础设施
- 姿态评分可作为 `anomaly.RiskScorer` 的补充特征，丰富风险决策的信号源
- 统计基线 + 漂移检测可提前发现配置漂移或攻击后篡改

#### 2.2.2 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **姿态评分器的输入数据来源分散** | M | 客户端配置（`store.go`）、令牌审计（`audit/recorder_events_token.go`）、密码健康（`spi/password_health.go`）、配置审计（`configaudit/`）——需要统一的 `PostureSubject` 抽象 |
| **规则引擎的放置位置** | H | `platform/` 层 vs `domains/` 层。`platform/` 是基础设施层（无业务逻辑），但姿态规则本质是业务规则——放在 `domains/` 更合理，但 `domains/` 不能引用 `platform/audit` 的查询接口 |
| **评分延迟与请求路径的隔离** | M | 姿态评分不应阻塞认证请求。异步评分（如 `anomaly/` 的 Offer+drain 模式）更合适，但会引入评分结果到达时间的不确定性 |
| **规则的可扩展性与版本管理** | L | 客户可能需要自定义姿态规则——需要 SPI 支持注册外部规则 |

#### 2.2.3 架构方案

**建议：双层分离——`domains/posture/`（规则引擎）+ `platform/posturescan/`（扫描调度器 + 存储）**

```
domains/posture/
├── posture.go              # PostureRule 接口 + PostureReport 值类型
│                           #   type PostureRule interface {
│                           #     Name() string
│                           #     Category() PostureCategory  // Config / Token / Credential / Password / Audit
│                           #     Severity() Severity         // Critical / High / Medium / Low / Info
│                           #     Evaluate(ctx, subject PostureSubject) (*RuleResult, error)
│                           #   }
│
│                           #   type RuleResult struct {
│                           #     Passed    bool
│                           #     Score     float64          // 0.0 (fail) - 1.0 (pass)
│                           #     Evidence  []Evidence        // 具体问题项
│                           #     Remediation string          // 如何修
│                           #   }
│
├── rules/
│   ├── client_secret_ttl.go     # 检查 client_secret_expires_at 是否设置
│   ├── refresh_rotation.go      # 检查 refresh token rotation 是否启用
│   ├── allowed_algorithms.go    # 检查客户端只允许安全的签名算法
│   ├── password_health.go       # 检查 bcrypt cost 是否达标
│   ├── audit_coverage.go        # 检查审计事件覆盖率
│   └── token_ttl.go             # 检查 access_token TTL 是否合理
│
├── posture_test.go          # 域级别 + conformance 测试
└── mem/
    └── posturerules.go      # 规则注册表（内存）

platform/posturescan/
├── scanner.go               # PostureScanner — 按计划执行全量或增量扫描
│                           #   type PostureScanner struct {
│                           #     rules    []PostureRule
│                           #     results  PostureStore
│                           #     schedule cron.Schedule
│                           #   }
│
├── store.go                 # PostureStore — 扫描结果存储
│                           #   type PostureStore interface {
│                           #     SaveReport(ctx, tenant_id, report) error
│                           #     GetLatest(ctx, tenant_id) (*PostureReport, error)
│                           #     ListHistory(ctx, tenant_id, from, to) ([]*PostureReport, error)
│                           #     ListFindings(ctx, tenant_id, severity) ([]*Finding, error)
│                           #   }
│
├── notifier.go              # 发现 Critical/High 问题时发送告警
│
├── mem/
│   └── store.go             # MemoryPostureStore
└── sqlite/
    └── store.go             # SQLitePostureStore
```

**分层决策的原因：**
- `domains/posture/` 定义 `PostureRule` 接口和 `PostureSubject` 值类型——它依赖 `shared/core` 的 `Client`、`User`、`Token` 类型（业务知识）
- `platform/posturescan/` 负责"什么时候跑、结果存哪里、怎么通知"——纯基础设施，不包含业务规则
- `domains/posture/rules/` 的每条规则是纯函数（输入 `PostureSubject` → 输出 `RuleResult`）——可独立测试
- `platform/` 层的扫描器引用 `domains/posture` 的规则——这是从上层到下层，合法

#### 2.2.4 复用模式：`WeightedComposite`

```go
// shared/trust/composite.go 已存在
type WeightedComposite struct {
    scorers []WeightedScorer
}

func (wc *WeightedComposite) Score(ctx, subject) (*Score, error) {
    // 加权求和、归一化、可靠线
}
```

姿态评分的复用方式：

```go
// 在 domains/posture/posteure.go 中
// 不新接口——适配到 trust.Scorer
type PostureScorer struct {
    inner trust.Scorer  // 实际是 WeightedComposite 或用户自定义
}

// trust.Scorer 的 Score 返回 *trust.Score（0.0-1.0 + 可靠线）
// PostureReport 包装 Score + Evidence 明细
```

这避免了新框架的引入——姿态评分框架本质是一个领域特化的加权组合器。

#### 2.2.5 对现有系统的影响

| 影响 | 程度 | 说明 |
|------|------|------|
| 新增 `PostureRule` SPI | M | 5-10 条初始规则 |
| 新增 `PostureStore` SPI | M | memory + sqlite 参考实现 |
| 新增扫描调度器 | M | 基于 cron 的定时扫描 / 事件触发扫描 |
| `shared/trust/composite.go` 的 `Scorer` 扩展 | L | 无改动——直接适配 |
| Admin API 扩展 | M | `GET /admin/posture/report`、`GET /admin/posture/findings` |
| 审计扩展 | S | 新增 `PostureScanCompleted` 事件类型 |
| 现有文件影响 | L | 不修改现有 `anomaly.RiskScorer`——姿态评分是新增数据源 |

---

### 2.3 方向三：后量子就绪（PQ Readiness）（P1 — 并行启动）

#### 2.3.1 为什么需要：业务价值 + 技术价值

**业务价值（紧急性）：**
- Harvest-Now-Decrypt-Later（HNDL）攻击者今天可以捕获所有 TLS 流量和 JWT 令牌——等量子计算机可用时批量解密
- 刷新令牌（长寿命，可能 90 天 +）、授权码（短寿命但用于 token exchange 链）是 HNDL 的高价值目标
- PQ 迁移是 5-10 年大项目，**开始越晚，过渡期越痛苦**

**技术价值：**
- 混合签名（经典 + PQ 并行）是 NIST 推荐的迁移路径——不破坏现有验证者，同时部署 PQ 能力
- 尽早建立密钥类型清单（`platform/lifecycle/cryptoinventory/` 路线图 Wave 2）
- 算法韧性是长期架构属性——晚加不如早加

#### 2.3.2 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **JWT 大小膨胀** | H | ML-DSA-65 ≈ 4.4KB，混合（ML-DSA-65 + Ed25519）≈ 5KB。访问令牌从 ~2KB 到 ~7KB——触及 HTTP 头大小限制（默认 8KB） |
| **算法敏捷性（Crypto Agility）** | H | 当前 `security/asymmetric_algs_test.go` 的算法注册表是静态枚举。PQ 算法需动态注册——新旧算法共存 + 迁移编排 |
| **JWT 头格式扩展** | M | 混合签名需要标准化的 JWT 头格式 —— `{alg, typ, pq, ...}`。当前 JWS 序列化未预留扩展点 |
| **刷新令牌的 PQ 加固** | M | Refresh Token 的数据库查找键（HMAC-SHA256）在 Grover 算法下从 256 位降至 128 位安全性——需要升级到 SHA-384/SHA-512 |
| **令牌大小对基础设施的影响** | H | 7KB 令牌接近 Istio/Envoy 默认缓冲区限制；JWK 集包含 PQ 公钥后也膨胀——可能超过 etcd 的单值限制 |
| **预演攻击窗口** | M | 攻击者今天可以捕获 PQ 算法尚未保护的数据——需要为高价值资源（联邦连接凭据、CAEP 接收端点密钥）提前启动 PQ 保护 |

#### 2.3.3 架构方案

**阶段一：基础能力（1-2 周）—— 混合签名 SPI + 算法注册表扩展**

```
shared/security/
└── pq/                          # 新包——PQ 辅助类型
    ├── algorithm.go              # 算法敏捷性注册表（扩展已有 registry）
    │                             #   type AlgorithmRegistry struct {
    │                             #     mu sync.RWMutex
    │                             #     algs map[string]AlgorithmInfo  // "ML-DSA-65" → {signer, verifier, size}
    │                             #   }
    │                             #   func Register(algo string, info) — 动态注册
    │                             #   func Get(algo string) — 运行时查找
    │
    ├── mixedsign.go              # 混合签名结构
    │                             #   type MixedSignatureHeader struct {
    │                             #     Primary  Algorithm   // 主算法（PQ）
    │                             #     Fallback Algorithm   // 回退算法（经典）
    │                             #     PrimarySig []byte
    │                             #     FallbackSig []byte
    │                             #   }
    │
    └── tokensize.go              # 令牌大小预估 + 阈值告警
                                  #   输入：algorithm + claims → 输出：估算 size
                                  #   如果 > 6KB 触发 warn 审计事件
```

**阶段二：令牌路径接线（2-3 周）—— 签发混合签名的 JWT**

```go
// defaultimpl/jwt_issuer.go（修改）
func (i *issuer) signWithPQ(ctx, claims, primaryAlg, fallbackAlg) (string, error) {
    primaryJWT := jws.Sign(claims, primaryAlg, primaryKey)     // 用 PQ 算法签
    fallbackJWT := jws.Sign(claims, fallbackAlg, fallbackKey)  // 用经典算法签

    // 构造混合 JWT：typ="JWT+PQ"
    // 在 JWT header 中包含 primary sig + fallback sig
    return serializeMixedJWT(claims, primaryJWT, fallbackJWT)
}
```

**阶段三：验证者更新（1-2 周）—— 接受混合签名 + 降级到经典签名**

```go
// security/jwks_verify.go（扩展）
func VerifyCompactJWSWithPQ(ctx, token) (claims, error) {
    if isMixedSignature(token) {
        // 提取 PQ 签名和经典签名
        // 验证 PQ 签名（如果验证者支持 PQ）
        //   → 成功：接受
        //   → 失败：验证经典签名（降级）
        //      → 成功：接受 + 审计 "pq_verify_fallback"
        //      → 失败：拒绝
    }
    return verifyClassicJWS(token)  // 回退到经典流程
}
```

**阶段四：短寿命凭据 PQ 加固（2-3 周）**

| 凭据类型 | 当前安全假设 | PQ 加固措施 | 优先级 |
|---------|------------|------------|--------|
| Refresh Token（存储键） | SHA-256（128 位 Grover） | 升级到 SHA-384/SHA-512；可选加盐 | P1 |
| Authorization Code | SHA-256 码 + 单用语义 | 码本身不需要加固（单用），但传输层需 PQ-TLS | P2 |
| 客户端鉴权凭证（`private_key_jwt`） | 当前基于 RS256/ES256/EdDSA | 签发混合签名的 client assertion | P1 |
| 会话令牌 | EdDSA 签名 | 签发混合签名的会话 JWT | P2 |
| DPoP proof | SHA-256 thumbprint | 升级到 SHA-384 thumbprint | P2 |
| CAEP 事件（SSF） | 由 push token 签名 | 用混合签名保护 push token | P3 |

#### 2.3.4 令牌大小管理策略

```
目标：混合签名 access_token 保持在 6KB 以下

策略组合：
1. 压缩 claims：默认 claims 约 1KB
   → 可选：使用压缩 claim 名（"sub"→"s", "iss"→"i"）— 不符合 OIDC 标准，仅用于内部令牌
   → 可选：移除可选非必要 claims（如 auth_time / AMR 在非必要场景）

2. 选择 PQ 算法变体：
   | 算法       | 签名大小 | 公钥大小 | NIST 等级 |
   |-----------|---------|---------|----------|
   | ML-DSA-44 | ~2.4KB  | ~1.3KB  | 2（≈AES-128）|
   | ML-DSA-65 | ~4.4KB  | ~2.0KB  | 3（≈AES-192）|
   | ML-DSA-87 | ~6.6KB  | ~2.8KB  | 5（≈AES-256）|
   → 建议：默认 ML-DSA-44（混合后约 4-5KB，6KB 内安全）

3. 传输层优化：
   → 启用 HTTP 头压缩（HPACK/QPACK 对 JWT 头不友好——但可压缩到 <1KB）
   → 考虑 access_token 的引用模式（opaque reference → introspection）
     （但这改变了协议语义——仅限内部调用）

4. 代理/网格配置检查：
   → Istio/Envoy：`max_request_headers_size: 16K`（默认 8K 太紧）
   → AWS ALB/NLB：检查 header 大小限制
```

#### 2.3.5 对现有系统的影响

| 影响 | 程度 | 说明 |
|------|------|------|
| `security/asymmetric_algs_test.go` 算法注册表扩展 | M | 从静态枚举变为可动态注册；添加 PQ 算法枚举 |
| `security/jwks_verify.go` 验证端 | M | 增加混合签名验证路径 + fallback 逻辑 |
| 3 个 issuer（`ed25519_jwt_issuer.go`、`ecdsa_jwt_issuer.go`、`rsa_jwt_issuer.go`） | M | 每个需要支持 PQ 签名的 with-PQ 变体 |
| HTTP 头大小限制 | H | 需要文档化和配置检查——所有代理/网关需调整 `max_request_header_size` |
| JWKS 缓存大小 | M | PQ 公钥更大——JWK 文档可能从 ~1KB 增长到 ~4KB |
| 刷新令牌存储 SPI | S | HMAC-SHA256 查找键升级到 SHA-384——仅改 hash 函数，不改 SPI |
| `platform/lifecycle/cryptoinventory/` | M | 新增"密钥算法类型的运行时清点"——记录每个密钥是经典 / PQ / 混合 |
| 现有文件影响 | M | 修改 `security/` 下的算法注册表 + 验证路径；不修改 `shared/core` 的类型 |

---

### 2.4 方向四：Connection 驱动 IdP 编排（P2 — 等待路线图阶段）

#### 2.4.1 真正的架构缺口

经代码验证，方向三的原始分析不准确：

| 原分析声称 | 实际状态 | 代码证据 |
|-----------|---------|---------|
| Connection 路由完全未被消费 | ⚠️ **HRD 路由存在** | `server_login_resolve.go:205` `resolveHomeRealm` 和 `:259` `handleHomeRealm` 已用 email domain 路由 |
| ConnectionStore 未连接 | ⚠️ **已连接** | `server_federation.go:345-358` + `accessors.go:231` — ConnectionStore + DNSResolver + Prober 已接线 |
| IdP 认证器实例化不存在 | ✅ **真正的缺口** | `build_authenticators_helpers.go:341` 从**静态 `config.OIDCFederationAuthConfig`** 创建——不从 Connection 对象动态实例化 |
| ConnectionStore 在认证构建中引用 | ❌ **零引用** | `serverbuildauthn/` 中搜索 `ConnectionStore` → 0 命中 |

**正确的缺口描述：**
- HRD **路由**（domain → connection 查找）▶️ **有效**
- 运行时 **IdP 认证器动态实例化**（Connection → authenticator）▶️ **不存在**
- 当前认证器在服务器启动时一次性构建——不能为新租户 / 新 connection 动态创建新认证器

#### 2.4.2 架构建议

设计一个 `ConnectionAuthenticatorFactory`：

```
domains/connections/
└── factory.go                # ConnectionAuthenticatorFactory 接口
                              #   type ConnectionAuthenticatorFactory interface {
                              #     // 根据 Connection 对象创建（或重用）认证器实例
                              #     GetOrCreate(ctx, conn *Connection) (Authenticator, error)
                              #     // 清除缓存（当 Connection 更新时调用）
                              #     Invalidate(ctx, connectionId string) error
                              #   }
                              #
                              #   // 默认实现：基于内存的 LRU 缓存，每个 Connection 一个认证器实例
                              #   // 过期策略：30min TTL + ConnectionStore 变更事件刷新
```

**关键设计决策：**

| 决策 | 建议 | 理由 |
|------|------|------|
| 认证器实例是否共享？ | **每个 Connection 一个实例** | Connection 的 IdP 元数据（证书、端点、SSO URL）不同——不可共享 |
| 缓存还是每次创建？ | **LRU 缓存（1024 条目）** | 实例创建有初始化成本（TLS 握手缓存、metadata fetch） |
| Connection 变更时？ | **缓存失效 + 热重载** | 监听 `cluster.Bus` 的 `KindConnectionChange` + 管理 API 变更 |
| 无缓存命中时？ | **同步创建 + 后备到异步预热** | `/auth/login` 不可依赖异步——如果 Connection 缓存未命中，同步创建；后台异步预热下一个 |

**接线映射：**

```
server_login_resolve.go (HRD决策)
         │  resolveHomeRealm → connections.Resolve(domain) → Connection
         ▼
server_federation.go (连接获取)
         │  ConnectionStore.Get(connectionId) → Connection
         ▼
build_authenticators_helpers.go
         │  当前：静态 config → OIDCFederationAuthenticator
         │  改为：ConnectionAuthenticatorFactory.GetOrCreate(ctx, connection) → Authenticator
         ▼
authenticators/oidc_federation.go
         │  实例化时从 Connection 对象读取所有配置
```

---

### 2.5 方向五：跨协议身份解析与合并（P2 — 等待路线图验证阶段）

#### 2.5.1 纠正：已有 vs 缺失

| 功能 | 状态 | 代码位置 |
|------|------|---------|
| 用户身份链接 UI（用户手动关联账户） | ✅ 存在 | `protocols/selfservice/selfserviceaccount/identities.go` |
| 自动身份解析（登录时自动判断"这是同一个用户"） | ❌ 不存在 | 缺口 |
| 自动身份合并策略（冲突解决） | ❌ 不存在 | 缺口 |

#### 2.5.2 架构建议

```
domains/identitylink/
├── resolver.go               # IdentityResolver 接口
│                             #   定义如何将来自不同 IdP 的身份解析为同一用户
│                             #   type IdentityResolver interface {
│                             #     // Resolve 接收登录事件，返回已链接的 account 或 nil
│                             #     Resolve(ctx, login *LoginEvent) (*Account, error)
│                             #   }
│
├── strategies/
│   ├── email_normalized.go   # 策略：对 emails 做 Unicode 规范化后比较
│   ├── email_verified.go     # 策略：仅使用已验证的 email（更安全）
│   └── subject_id.go         # 策略：使用外部 IdP 的 subject + issuer 对
│
├── merger.go                 # IdentityMerger 接口
│                             #   确定如何合并属性（优先级、保留策略、审计）
│                             #   type IdentityMerger interface {
│                             #     Merge(ctx, primary, secondary) (*Account, error)
│                             #   }
│
├── store.go                  # IdentityLinkStore（如果有额外的合并元数据）
│
└── mem/
    └── resolver.go           # MemoryIdentityResolver
```

**关键风险：误判率高。**
- email 是弱匹配条件（不同人可访问同一邮箱，邮箱可转发）
- 自动合并误判 = 将用户 A 的数据暴露给用户 B → GDPR 风险
- **推荐：仅使用已认证的 email（email_verified=true）+ 管理员确认门**

---

## 3. 接口设计原则

### 3.1 新 SPI 的通用设计原则

| 原则 | 说明 | 违反后果 |
|------|------|---------|
| **SPI 最小化** | 新 SPI 控制在 3-5 个方法——扩展方法通过包裹器而非接口膨胀 | 每个 SPI 方法需 3 个实现（memory + sqlite + redis） |
| **零值 = 禁用** | 所有 `With*` 选项的零值表示"不启用此功能" | 新用户升级后无行为变化 |
| **Fail-open 优先** | 新组件的错误不能降低可用性（姿态评分器不可用 → 评分为 0 不影响认证） | 新组件不可用 = 服务降级 |
| **异步 off-path** | 评分/扫描/清点走 Offer+drain 异步模式 | 热路径延迟增加 |

### 3.2 各方向的 SPI 设计

| 方向 | 核心接口 | 预期方法数 | 所属包 |
|------|---------|-----------|--------|
| NHI | `NHIProvider` | 6-8 | `domains/nonhumanidentity` |
| NHI | `CredentialStore` | 5 | `domains/nonhumanidentity` |
| NHI | `RotationScheduler` | 3 | `domains/nonhumanidentity` |
| ISPM | `PostureRule` | 4 | `domains/posture` |
| ISPM | `PostureStore` | 5 | `platform/posturescan` |
| PQ | `AlgorithmRegistry`（动态注册） | 3 | `shared/security/pq` |
| PQ | `MixedSigner`（混合签名器） | 1-2 | `shared/security/pq` |
| IdP 编排 | `ConnectionAuthenticatorFactory` | 3 | `domains/connections` |
| 身份关联 | `IdentityResolver` | 1 | `domains/identitylink` |

### 3.3 向后兼容性策略

| 场景 | 策略 |
|------|------|
| 现有文件不引入新 SPI | 新功能全部在新包中创建——不修改 `core/spi.go` |
| ServiceAccount 与 User 共存 | 认证路径做 `type switch`——不影响现有 User 的查询路径 |
| 混合签名与经典签名共存 | 验证者先尝试 PQ 验，失败回退经典验——不修改经典 JWS 验证路径 |
| 姿态评分对现有 risk 引擎透明 | 姿态评分为新数据源，`RiskScorer` 可选择性消费 |
| 动态 IdP 认证器实例化 | 现有静态 `map[string]Authenticator` 保留——动态实例化为新增，默认不启用 |

---

## 4. 技术选型

### 4.1 新技术需求评估

| 方向 | 需要新技术？ | 说明 |
|------|------------|------|
| NHI | **不需要** | 全部复用现有基础设施（`cluster.Bus`、`platform/audit`、`defaultimpl/memory` 范式） |
| ISPM | **不需要** | 复用 `shared/trust/composite.go` 的评分模式——零新框架 |
| PQ | **不需要** | ML-DSA 等 PQ 算法使用 Go `crypto` 标准库（Go 1.24+ 已有实验性支持）或 `cloudflare/go` 的 fork |
| IdP 编排 | **不需要** | 复用现有 `authenticators/oidc_federation.go` + `saml/` SP——只需动态实例化 |
| 身份解析 | **不需要** | 纯逻辑匹配——无存储/网络依赖 |

**结论：所有方向均不需要引入新的第三方依赖或技术栈。与 `docs/architect-analysis-v6-five-directions.md` 一致。**

### 4.2 PQ 算法的 Go 生态评估

| 算法 | Go 支持状态 | 建议 |
|------|------------|------|
| ML-DSA（FIPS 204，原名 Dilithium） | Go 1.24 `crypto/ml-dsa`（实验性）；`cloudflare/go` fork 有完整支持 | 使用 Go 1.24 标准库——不引入外部 CGO 依赖 |
| SLH-DSA（FIPS 205，原名 SPHINCS+） | `crypto/slhdsa` 实验性 | 暂缓——签名更大，性能更差，NIST 等级对等 ML-DSA |
| ML-KEM（FIPS 203，原名 Kyber） | Go 1.24 `crypto/ml-kem` | 不需要——SSO 不直接做密钥封装 |
| **混合模式（PQ + Ed25519 / ES256）** | **无标准库支持**——需手搓 JWT 头扩展 | 自建 ~200 行，复用 JWS 序列化基础设施 |

**结论：不引入 CGO / 外部 PQ 库。使用 Go 1.24 标准库的 ML-DSA 实验性支持 + 自建混合签名 JWT 头序列化。**

### 4.3 自建 vs 采购决策

| 组件 | 决策 | 理由 |
|------|------|------|
| NHI 凭据生命周期管理 | **自建** | 核心领域逻辑——无法采购为一独立产品 |
| 混合签名 JWT | **自建** | ~200 行 JWT 头扩展——市场上没有 Go 的混合签名 JWT 库 |
| 姿态规则引擎 | **自建** | 规则是 SSO 领域特化的——通用规则引擎（如 OPA/Rego）不适合 SSO 配置姿态 |
| 后量子算法 | **标准库** | Go 1.24 标准库已包含——第三方库反而增加审计成本 |

### 4.4 与已有基础设施的关系

| 方向 | 复用 | 扩展 | 新写 |
|------|------|------|------|
| NHI | `cluster.Bus`、`platform/audit`、`defaultimpl/memory` 范式 | `audit.EventType` 枚举 | `NHIProvider`、`CredentialStore`、`RotationScheduler` |
| ISPM | `shared/trust/composite.go` `Scorer` | `trust.Scorer` 的 domain 特化 | `PostureRule` 集合、`PostureStore` |
| PQ | `security/jwks_verify.go`、`security/asymmetric_algs_test.go` | 算法注册表（静态→动态）、JWS 验证器 | `pq/mixedsign.go`、`pq/algorithm.go` |
| IdP 编排 | `authenticators/oidc_federation.go`、`server_federation.go` | `ConnectionAuthenticatorFactory` 接线 | 工厂实现 + 缓存 |
| 身份解析 | `protocols/selfservice/selfserviceaccount/identities.go` | 自动解析流程 | `IdentityResolver` 策略集 |

---

## 5. 实施路线图

### 5.1 优先级总览

```
        高 │ NHI 生命周期管理（P0）             后量子就绪（P1）
           │     ───── 最高市场价值                 ───── 时间敏感
           │     4-6 周                             2-3 周概念验证
   价值    │
           │
        中 │ 运行时 ISPM（P2）│ IdP 编排（P2）│ 身份解析（P2）
           │ 6-8 周后启动     │ 等待路线图     │ 等待路线图
           │
        低 └─────────────────────────────────────────────
              低                    高
                        实现复杂度
```

### 5.2 阶段划分

#### 阶段一：NHI 基础 + PQ 概念验证（并行，4-6 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| `domains/nonhumanidentity/` 包（NHIProvider SPI + 值类型） | M | SPI + 类型定义 |
| `domains/nonhumanidentity/mem/` 内存参考实现 | M | 可测试的 memory peer |
| `domains/nonhumanidentity/nhrotation.go` RotationScheduler SPI | S | 轮换调度接口 |
| **PQ** `shared/security/pq/algorithm.go` 算法注册表 | S | 动态算法注册 |
| **PQ** `shared/security/pq/mixedsign.go` 混合签名结构 | M | JWT 混合签名格式 |
| **PQ** `security/jwks_verify.go` 扩展——接受混合签名 | M | 验证者升级 |
| NHI + PQ 域内单元测试 | M | 覆盖核心路径 |

**验证标准：**
- NHI：`go test ./domains/nonhumanidentity/...` 通过；`NHIProvider` 可 CRUD ServiceAccount
- PQ：`go test ./shared/security/pq/...` 通过；混合签名可签发 + 验证
- 全部通过 `make acceptance`

#### 阶段二：NHI 深度集成 + PQ 令牌路径接线（4-6 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| ServiceAccount 认证路径（`client_credentials` grant 扩展） | M | SA 可获取 access_token |
| CredentialStore.RevokeAll 在 DisableServiceAccount 时调用 | M | 事务级安全 |
| `cluster.Bus` 新增 `KindCredentialRotated`、`KindServiceAccountDisabled` | S | 跨副本通知 |
| Admin API CRUD（gRPC + REST） | M | 管理员可管理 SA |
| `audit.SetMeta` 扩展 + NHI 事件类别 | S | 可审计 |
| **PQ** 3 个 issuer 的 with-PQ 变体实现 | M | 签发混合签名 JWT |
| **PQ** 刷新令牌 HMAC-SHA256 → SHA-384 | S | 存储层加固 |
| **PQ** 令牌大小告警 + 配置检查 | S | 运维安全 |

**验证标准：**
- NHI E2E：创建 SA → 认证 → 轮换凭据 → 禁用 SA → 确认凭据全部吊销
- PQ E2E：签发混合签名令牌 → 用过期/无效 PQ 签名 → 回退到经典签名成功
- `go test ./... -race` 通过

#### 阶段三：ISPM 基础 + PQ 扩展（6-8 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| `domains/posture/` 包 + `PostureRule` SPI | M | 姿态规则框架 |
| 5 条初始规则（client_secret_ttl, refresh_rotation, allowed_algorithms, password_health, audit_coverage） | M | 可运行的姿态检查 |
| `platform/posturescan/` 扫描调度器 + `PostureStore`（memory + sqlite） | M | 定时扫描 + 结果存储 |
| Admin API `GET /admin/posture/report` | M | 姿态报告 API |
| **PQ** `platform/lifecycle/cryptoinventory/` 集成 | M | 密钥算法类型清点 |
| **PQ** DPoP thumbprint SHA-256 → SHA-384 | S | 加固 |

**验证标准：**
- 执行全量扫描 → 生成 `PostureReport` → 报告包含每条规则的结果和证据
- 修改客户端配置（如将算法改为不安全值）→ 下次扫描标记为 Critical
- Cryptoinventory 报告所有密钥的算法类型（经典 / PQ / 混合）

### 5.3 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| **PQ 令牌大小超标导致 HTTP 代理拒绝** | H | H | 阶段一就加令牌大小告警 + 代理配置检查文档；默认用 ML-DSA-44 而非 65 |
| **ServiceAccount 认证路径与现有 OAuth 流程竞争** | M | M | 设计阶段明确 `client_credentials` 的 ServiceAccount 变体 vs 传统 client credential 的界限 |
| **姿态评分结果被用于授权决策但评分器不可用** | L | M | 默认 fail-open（评分不可用 = 评分为 0 = 不触发告警）；评分不做 access 门禁仅做告警 |
| **PQ 混合签名使 token exchange 的 act 链更复杂** | M | M | `act` 链只包含 JTI——不包含签名类型信息。混合签名对 act 链透明 |
| **NHI 凭据轮询死期太短 → 合法客户端被吊销** | M | M | 默认死期建议 24h（可根据客户端的轮询间隔配置）；审计事件记录每次死期延长 |
| **动态 IdP 认证器实例化与静态认证器冲突** | M | L | 设计时约定优先级：Connection 动态认证器 > 静态 config 认证器。HRD 只返回 Connection，不参与认证器选择 |

### 5.4 依赖关系图

```
阶段一（并行）
┌──────────────────┐  ┌────────────────────┐
│ NHI 基础         │  │ PQ 概念验证         │
│ ─ SPI + 类型    │  │ ─ 算法注册表        │
│ ─ memory 实现   │  │ ─ 混合签名结构      │
│ ─ Rotation SPI  │  │ ─ 验证者扩展        │
└────────┬─────────┘  └─────────┬──────────┘
         │                      │
         ▼                      ▼
阶段二
┌──────────────────┐  ┌────────────────────┐
│ NHI 集成         │  │ PQ 令牌路径接线     │
│ ─ 认证路径       │  │ ─ issuer 扩展      │
│ ─ RevokeAll      │  │ ─ refresh 加固     │
│ ─ cluster.Bus    │  │ ─ 大小告警         │
│ ─ Admin API      │  └─────────┬──────────┘
│ ─ 审计           │            │
└────────┬─────────┘            │
         │                      │
         ▼                      ▼
阶段三
┌────────────────────────────────────────┐
│ ISPM 基础 + PQ 扩展                     │
│ ─ PostureRule SPI + 5 条初始规则        │
│ ─ 扫描调度器 + PostureStore             │
│ ─ Cryptoinventory 集成                  │
└────────────────────────────────────────┘
```

### 5.5 验证与门禁

| 门禁类型 | 适用方向 | 验证方法 |
|---------|---------|---------|
| 域级单元测试 | 全部 | `go test ./domains/nonhumanidentity/...` |
| 集成测试 | NHI, ISPM | `go test ./test/ -run TestNHIE2E` |
| PQ 算法一致性 | PQ | 固定测试向量验证混合签名 = 经典签名 + PQ 签名分别验证 |
| 向后兼容 | PQ | 混合签名验证失败 → 回退到经典签名 → 接受 |
| 性能门禁 | PQ, NHI | Benchmark 测试：混合签名延迟 vs 经典签名延迟（阈值：< 2x） |
| 令牌大小门禁 | PQ | CI 检查：`TokenSize(ML-DSA-44 + Ed25519) < 6KB` |
| 审计完整性 | NHI, ISPM | 审计事件覆盖率检查：每个 SA 操作都生成预期事件 |

---

## 6. 与其他路线图工作的整合

### 6.1 与 ROADMAP v5.0 的关系

| ROADMAP v5.0 方向 | 与本分析的交集 |
|------------------|--------------|
| **① 终端体验产品层** | **无直接交集**——NHI 和 PQ 都是后端能力，不依赖前端 |
| **② B2B 企业化** | **IdP 编排（方向四）直接对齐** — `ConnectionAuthenticatorFactory` 是 B2B 企业连接的实现细节 |
| **③ OIDC 一致性收口** | **无直接交集**——但 PQ 混合签名的 JWT 头格式需对齐 OIDC 标准（`typ="JWT+PQ"` vs 标准 `typ="JWT"`） |
| **④ 多副本数据面韧性** | **NHI 依赖** `cluster.Bus` 的跨副本撤销（`KindServiceAccountDisabled`）。**PQ 依赖**跨副本签名算法注册表的一致性 |
| **⑤ 安全姿态与供应链** | **ISPM（方向二）直接对齐** — 姿态规则覆盖的客户端配置审计是 §⑤ 的补充。PQ 迁移是 §⑤ 的安全姿态指标 |

### 6.2 与已有 `docs/requirements/` 文档的关系

本分析与以下文档无重叠——交叉验证确认：

| 本分析方向 | 已有文档覆盖？ | 确认方式 |
|-----------|--------------|---------|
| NHI 生命周期管理 | ❌ 零覆盖 | grep `ServiceAccount\|NHI\|nonhumanidentity\|workload.*lifecycle` 在 65+ 份文档中无匹配 |
| 运行时 ISPM | ❌ 零覆盖 | grep `Posture\|posture\|姿态` 无匹配 |
| 后量子就绪 | ❌ 零覆盖 | grep `PQ\|post-quantum\|quantum\|hybrid.*sign\|混合签名\|后量子` 无匹配 |
| Connection 动态 IdP 实例化 | ✅ 已部分覆盖 | `docs/architect-analysis-v6-five-directions.md` §2.2 已验证 HRD 路由存在 |
| 自动身份解析/合并 | ❌ 零覆盖 | 现有 `identitylink` 仅为手动链接 UI |

### 6.3 与 `docs/deferred-backlog.md` 的关系

`deferred-backlog.md` 的 33 项中有 31 项已落地。剩余 2 项（Multi-IDP auto-resolution 和 PQ cryptographic migration）与本分析的**方向五（身份解析）** 和 **方向三（PQ）** 重叠——但 backlog 只标记为"deferred"而无设计，本分析提供了具体架构方案。

---

## 7. 否决项与不做之事

| 不会做的事 | 原因 |
|-----------|------|
| ServiceAccount 作为 `core.User` 的子类型 | 违反最小权限原则——SA 不需要 MFA/密码/SSH key |
| 引入外部 PQ 库（`cloudflare/go` fork / `pqcrypto`） | Go 1.24 标准库已有 ML-DSA（实验性）——外部库增加审计成本 |
| 姿态评分阻断认证（fail-closed） | SSO 是身份基础设施——姿态仪表的缺失不应对认证可用性产生负面影响 |
| 通用的规则引擎（OPA/Rego） | 姿态规则只有 5-10 条，都是 SSO 域名化的——通用规则引擎是过度设计 |
| PQ 迁移的自动回退（检测到经典算法自动降级） | 降级路径必须显式配置——静默降级会引入安全盲区 |
| Kafka/CDC 管道作为姿态事件流 | 姿态扫描是定时执行，不是连续流——cron 足以 |
| 多区域 NHI 凭据复制 | NHI 凭据与 region 绑定（SA 在 home region 签发）——跨区可用 `cluster.Bus` 广播吊销即可 |

---

## 8. 总结

| 维度 | 评估 |
|------|------|
| **整体方向相关性** | NHI、PQ、ISPM 三个方向均**正交**——可独立并行推进，无阻塞依赖 |
| **现有资产复用率** | 极高——三个方向都在现有基础设施（`cluster.Bus`、`platform/audit`、`shared/trust`、`security`）上构建 |
| **零新技术引入** | 所有方向均不需要新的第三方依赖或框架——全部在 Go 标准库 + 现有代码库能力范围内 |
| **最大技术风险** | PQ 令牌大小超标（5-7KB → HTTP 头限制）——建议默认 ML-DSA-44 + 阶段一就启用大小告警 |
| **最大业务价值** | NHI——填补"人类用户 SSO 完备但机器凭据零管理"的产品空白 |
| **建议启动顺序** | NHI（P0，立即）+ PQ 概念验证（P1，并行）→ ISPM（P2，6-8 周后）|
| **不做之事** | 不膨胀 `core.User` SPI、不引入外部 PQ 库、不阻断姿态评分、不推通用规则引擎 |
