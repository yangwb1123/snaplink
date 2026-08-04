# 扩展方向分析报告 v12 —— 安全纵深、规模韧性、与平台智能化

> **作者：** 资深架构 & 产品经理视角  
> **日期：** 2026-07-11  
> **范围：** 全代码库全局扫描（2241+ `.go` 文件、200+ 包、4 个嵌入式 SPA、6+ 存储后端）  
> **前提：**  
>   本轮分析已系统阅读并逐项对抗核验以下全部现有文档，确保零重叠：  
>   - `ROADMAP.md` v5.0  
>   - `deferred-backlog.md`  
>   - `expansion-directions-analysis.md`（v1 原始）  
>   - `expansion-directions-v6~v11-analysis.md`（共 7 轮分析，覆盖 35+ 方向）  
>   - `expansion-post-protocol-layer-analysis.md`（协议层收口后阶段）  
>   - `feature-spec-active-itdr-detection-response.md`  
>   - `feature-spec-security-docs.md`  
>   - `docs/superpowers/plans/2026-07-02-implementation-roadmap.md`  
> - **本报告 5 个方向与上述所有文档零重叠。** 所有 gap 声明均经过 grep 核验确认。

---

## 前置声明：项目成熟度定位

经过多轮全局扫描和方向分析，本项目已是行业顶级的开源身份平台：

| 维度 | 状态 |
|---|---|
| 协议覆盖 | OAuth 2.0/OIDC/SAML/SCIM/CAEP/FAPI/JARM/JAR/DPoP/mTLS/CIBA… 全协议面 |
| 存储后端 | Memory + SQLite + Redis + Postgres + etcd + KMS(4) |
| 嵌入式 SPA | Admin Console + Login + Developer Portal + Self-Service Portal |
| 企业特性 | 多租户 + Federation + 数据驻留 + 条件访问 + RBAC + ReBAC + 审计链 + Break-Glass |
| 运维面 | gRPC admin API + REST gateway + 可观测性（Metrics/Tracing/Audit）+ K8s Operator + DR |
| 质量基建 | 架构层测试 + 维护性预算 + 代码复杂度门禁 + 模糊测试(9) + 混沌测试(4) + Benchmark 门禁 |
| 开发者体验 | Go SDK + TS/Python SDK + MCP Server + CLI + OpenAPI docs |
| 安全供应链 | Dependabot(12 模块) + CodeQL + Trivy + govulncheck + gosec + golangci-lint |

前十一轮分析 + 协议层收口分析已覆盖了从基础设施完备度到身份智能平台、
从安全治理到商业智能的 40 多个高价值方向。ROADMAP v5.0 + 实现路线图进一步
覆盖了产品化、企业连接、供应链安全与质量门禁。

**本报告的 5 个方向不属于"新增协议支持"或"补齐后端能力"——而是属于以下三个
更高阶的架构领域：**

| 领域 | 方向 |
|---|---|
| **安全纵深防御 + 边缘场景** | ① 令牌绑定传播与委派链的发送者约束连续性 |
| **跨实例威胁协同** | ② 联邦化跨实例威胁情报与关联异常检测 |
| **规模韧性 + 全球部署** | ③ 多区域 Active-Active 身份数据面 |
| **平台智能化** | ④ 应用所有者身份可观测性与令牌生命周期分析 |
| **运维安全** | ⑤ 密码算法生命周期管理与迁移框架 |

---

## 方向 1：令牌绑定传播与委派链的发送者约束连续性

### 现状

项目支持多种发送者约束（Sender Constraint）机制：

| 机制 | 应用场景 | 状态 |
|---|---|---|
| DPoP（RFC 9449） | access_token 与 client 证明密钥绑定 | ✅ `dpop.go` + `jti_replay.go` + nonce |
| mTLS（RFC 8705） | access_token 与客户端证书绑定 | ✅ `tls_client_auth.go` + `header_cert_extractor.go` |
| SPIFFE JWT-SVID | workload identity 与 SPIFFE ID 绑定 | ✅ `spiffe_svid.go` |
| Transaction Token（RFC 9321） | token 与特定资源/操作的绑定 | ✅ `txntoken/` |
| **上述绑定在 token-exchange 后的传播** | **❌ 零实现** |

### 缺口（grep 核验）

- `cnf.*propagat\|CnfPropagat\|cnf.*inherit\|cnf.*propagate\|jkt.*propagat\|binding.*inherit`：**零实现命中**
- `sender.*constrain.*propagat\|sender.*constrain.*chain\|sender.*constrain.*exchange`：**零实现命中**
- `token.*exchange.*binding\|exchange.*dpop\|exchange.*mtls\|exchange.*sender`：**零实现命中**
- `delegat.*chain.*secur\|chain.*of.*trust.*exchange\|act.*cnf\|act.*binding\|cnf.*act`：**零实现命中**

代码中 `protocols/oauth/token_exchange_helpers.go` 会从 `subject_token` 提取 `sub`、`iss`、`act`、`acr`、`auth_time` 等声明，但**从不提取或传播 `cnf`（confirmation）声明**。

### 为什么需要它

这是 **OAuth 2.0 体系中最容易被忽视的安全漏洞之一**。具体攻击场景：

1. **DPoP 令牌委派泄露**：服务 A 收到一个 DPoP 绑定的 access_token（携带 `cnf.jkt`）。服务 A 通过 token-exchange 获得访问服务 B 的令牌。交换后的令牌是纯 Bearer 令牌，无任何绑定。攻击者只要获取了服务 A 的交换结果，无需知晓原始 DPoP 私钥即可使用。

2. **mTLS 令牌委派降级**：类似地，mTLS 绑定的令牌在交换后降级为无绑定令牌。

3. **多跳放大**：项目支持 token-exchange 的多跳 `act` 链。每一跳都丢失发送者约束。经过 3 跳后，安全属性完全退化。

4. **与工作负载身份的组合风险**：SPIFFE JWT-SVID 作为 `subject_token` 交换后，工作负载身份的身份保证丢失——下游服务看到的是 bearer token，无法确认请求是否真的来自合法的工作负载。

### 范围

#### 1. 核心绑定传播模型

```
输入绑定 (来自 subject_token)         输出绑定 (到 issued_token)
───────────────────────────────      ─────────────────────────────
DPoP cnf.jkt                       → 传播相同 jkt 到新 token 的 cnf.jkt
mTLS cnf.x5t#S256                  → 传播相同 x5t#S256 到新 token 的 cnf.x5t#S256
DPoP + mTLS (双重绑定)              → 传播更强或全部绑定
无绑定 (bearer)                     → 维持无绑定
```

#### 2. 绑定传播策略（可配置）

```go
type BindingPropagationMode string

const (
    // 传播 subject_token 的所有绑定到 issued_token（默认，最安全）
    BindingPropagateAll BindingPropagationMode = "propagate_all"
    // 仅传播最强的绑定（DPoP > mTLS > bearer）
    BindingPropagateStrongest BindingPropagationMode = "propagate_strongest"
    // 不传播绑定（当前行为——不安全，兼容模式）
    BindingPropagateNone BindingPropagationMode = "propagate_none"
)

type BindingPropagationConfig struct {
    Mode          BindingPropagationMode
    // 是否在 act 链中记录每个 hop 的绑定状态
    RecordInChain bool
    // DPoP 绑定传播时，是否要求 subject_token 的 DPoP proof 仍然有效
    RequireFreshProof bool
}
```

#### 3. 验证要求

- 当 `subject_token` 携带 `cnf` 时，交换请求方（client）必须证明对绑定密钥的占有：
  - DPoP 绑定：请求方必须在 token-exchange 请求中附加 DPoP proof，且 `jkt` 匹配
  - mTLS 绑定：请求方必须通过 mTLS 连接，且证书指纹匹配
- 如果 client 无法证明对绑定密钥的占有，交换请求返回 `invalid_target`（与 `invalid_grant` 同 oracle-leak 安全）
- 多跳场景：每个 hop 的 client 都需要证明对前一个绑定密钥的占有

#### 4. 管理控制

```
admin:write 配置:
  POST /api/v1/admin/token-exchange/binding-policy
  {
    "propagation_mode": "propagate_all",
    "require_fresh_dpop_proof": true,
    "act_chain_binding_log": true
  }

指标暴露:
  sso_token_exchange_binding_propagated_total{from_type="dpop",to_type="dpop"}
  sso_token_exchange_binding_dropped_total{reason="no_client_proof"}
  sso_token_exchange_binding_rejected_total{reason="proof_mismatch"}
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| `subject_token` 同时有 DPoP + mTLS 绑定 | `propagate_all` 模式传播全部绑定；RS 端至少满足其一即可 |
| 第一跳是 DPoP 绑定，第二跳 client 无 DPoP 密钥 | 失败：`invalid_target`（oracle-safe），除非配置 `propagate_none` |
| `subject_token` 即将过期（< 5min）但绑定完好 | 绑定可传播——令牌时间短但绑定属性完整 |
| act 链环数超过限制（当前有 `MaxTokenExchangeChainLifetime`） | 生命周期限制优先；绑定传播不能绕过链长限制 |
| 与 Transaction Token 的交互 | Transaction Token 已有自身绑定（`txn` 声明）；绑定传播应额外添加而非覆盖 |

### 价值·工作量

- **价值：高**（填补 RFC 8693 常见实现漏洞；提升企业安全审计评分；防御 token 委派泄露）
- **工作量：M**（binding propagation 策略 + DPoP proof 验证 + 管理端点 + 指标 + E2E 测试）
- **依赖：** `protocols/oauth/token_exchange_helpers.go`（已存在，需修改 act 链处理）

---

## 方向 2：联邦化跨实例威胁情报与关联异常检测

### 现状

项目拥有丰富的单实例异常检测设施：

| 能力 | 状态 |
|---|---|
| 单租户异常检测器 | ✅ `domains/anomaly/` |
| 令牌异常检测器 | ✅ `domains/tokenanomaly/` |
| 事件行为评分器 | ✅ `shared/trust/behavior_scorer.go` |
| IP 信誉评分器 | ✅ `shared/trust/ip_reputation_scorer.go` |
| 设备姿态评分器 | ✅ `shared/trust/device_posture_scorer.go` |
| 地理评分器 | ✅ `shared/trust/geo_scorer.go` |
| 威胁动作执行器（Active ITDR） | ✅ `domains/threataction/` |
| 多因子账户锁定 | ✅ `shared/security/account_lockout.go` |
| 条件访问策略引擎 | ✅ `domains/conditionalaccess/` |
| **跨实例威胁情报共享** | **❌ 零实现** |
| **聚合关联检测** | **❌ 零实现** |
| **全局信誉源聚合** | **❌ 零实现** |
| **跨组织攻击面可见性** | **❌ 零实现** |

### 缺口（grep 核验）

- `threat.*intelligence.*feed\|ThreatFeed\|threat.*feed\|CTI\|TI.*feed`：**零实现命中**
  （`shared/trust/ip_reputation_scorer.go` 有本地 IP 评分器，但无外部信誉源集成，
  更无跨实例共享机制）
- `cross.*instance.*threat\|inter.*instance\|federated.*threat\|multi.*instance.*anomaly`：**零实现命中**
- `consensus.*threat\|aggregate.*anomaly\|global.*risk.*score\|global.*reputation\|reputation.*exchange`：**零实现命中**
- `threat.*sharing\|threat.*exchange\|STIX\|TAXII\|MISP\|OpenC2\|threat.*protocol`：**零实现命中**
- 无 `WithThreatIntelligenceFeeder`、`WithGlobalReputationSource`、`WithCrossInstanceAnomalyCorrelation` 选项

### 为什么需要它

当前的威胁检测模型是**孤岛式**的——每个 SSO 实例、每个租户内部独立检测攻击。
以下是孤岛模型的固有盲区：

1. **凭证填充攻击的跨租户集群**：攻击者使用同一个 IP 池探测 100 个租户的 `/token`
   端点。单个租户看到的是正常的失败率（0.1%），但全局视角看到的是 15,000
   次失败/小时——明显的凭证填充攻击。没有跨实例聚合，这种攻击完全不可见。

2. **慢速 Credential Stuffing**：攻击者以每个租户 1 次/分钟的速度尝试凭据，
   分散在 1000 个租户上。任何单个租户的账户锁定策略不会触发。全局聚合可检测。

3. **已知恶意令牌的扩散**：一个实例检测到某个令牌被泄露（例如，通过暗网监控），
   但其他实例不知道该令牌已被泄露。没有跨实例的「吊销传播」通知通道。

4. **多实例同一组织**：大型企业部署了 3 个 SSO 实例（生产/暂存/开发、或
   不同区域）。攻击者先从低价值的暂存环境开始探测，成功后再攻击生产环境。
   暂存环境的告警没有传递到生产环境。

CAEP/SSF 解决了单实例到 RP 的事件推送，但不解决实例之间的威胁情报聚合。

### 范围

#### 1. 威胁情报事件规范

```go
type ThreatIndicatorType string

const (
    IndicatorIP            ThreatIndicatorType = "ip"
    IndicatorUser          ThreatIndicatorType = "user"
    IndicatorToken         ThreatIndicatorType = "token_jti"
    IndicatorClientID     ThreatIndicatorType = "client_id"
    IndicatorSessionID    ThreatIndicatorType = "session_id"
    IndicatorDeviceID     ThreatIndicatorType = "device_id"
    IndicatorCertificate  ThreatIndicatorType = "cert_fingerprint"
)

type ThreatSeverity string

const (
    SeverityInfo     ThreatSeverity = "info"
    SeverityLow      ThreatSeverity = "low"
    SeverityMedium   ThreatSeverity = "medium"
    SeverityHigh     ThreatSeverity = "high"
    SeverityCritical ThreatSeverity = "critical"
)

// ThreatIndicator 是跨实例共享受限的威胁指标
type ThreatIndicator struct {
    ID           string            // 全局唯一 ID
    Type         ThreatIndicatorType
    Value        string            // hash of the indicator value (don't leak PII)
    HashMethod   string            // "sha256" - always hash to avoid sharing raw data
    Severity     ThreatSeverity
    Confidence   float64           // 0.0-1.0
    FirstSeen    time.Time
    LastSeen     time.Time
    Count        int64             // 观测次数
    Source       string            // 来源实例 ID
    Tags         []string          // "credential_stuffing", "brute_force", "token_scanning", etc.
    ExpiresAt    time.Time         // 自动过期
    // 可选：额外上下文（加密或仅内部使用）
    EncryptedPayload []byte        // 额外信息（PII 相关）的加密负载
}

// ThreatObservation 是单次观测事件
type ThreatObservation struct {
    Indicator ThreatIndicator
    Context   ObservationContext // requesting IP, user agent, geo, timestamp
    TenantID  string
}
```

#### 2. 威胁情报交换模式

```
┌─────────────────┐     CAEP/SSF (events)       ┌─────────────────┐
│  SSO Instance A  │ ◄─────────────────────────► │  SSO Instance B  │
│  (us-east-1)     │                             │  (eu-west-1)     │
│                  │   Threat Feed (aggregates)  │                  │
│  Anomaly → Score │ ◄─────────────────────────► │  Anomaly → Score │
└───────┬─────────┘                             └───────┬─────────┘
        │                                               │
        │           ┌──────────────────────┐            │
        └──────────►│   Threat Exchange     │◄──────────┘
                    │   (optional, central) │
                    │   - Dedup             │
                    │   - Aggregate         │
                    │   - Enrich            │
                    └──────────────────────┘
```

**模式 A（P2P，去中心化）**：每个实例将其高置信度威胁指标广播给对等实例。
适用于小型部署或组织内实例。

**模式 B（Hub-and-Spoke，中心化）**：一个可选的中心威胁交换服务负责去重、
聚合和 enrich 指标。适用于多组织共享或多区域大型部署。

两种模式均支持：

- **PUSH**：实例产生高置信度指标时立即推送
- **PULL**：实例定期拉取更新（用于不能主动推送的网络隔离环境）
- **HYBRID**：高严重性 PUSH，低严重性 PULL

#### 3. 威胁检测规则引擎（跨实例维度）

```go
// 跨实例检测规则（区别于 per-instance anomaly detector）
type GlobalDetectionRule struct {
    ID             string
    Name           string
    Condition      GlobalCondition
    Action         ThreatAction
    Cooldown       time.Duration // 同一规则触发的冷却期
    MinInstances   int           // 至少需要多少个实例报告
    Threshold      int           // 聚合计数阈值
    Window         time.Duration // 时间窗口
}

// 规则示例：
//   规则 1: 同 IP 在 5 分钟内被 3 个以上实例标记 → 升级为 Critical
//   规则 2: 同 user 在 10 分钟内从 2 个不同实例触发锁定 → 提示跨实例会话迁移
//   规则 3: 同 client_id 在 1 小时内被 5 个实例报告异常 → 可能是 client secret 泄露
```

#### 4. 管理端点

```protobuf
service ThreatIntelligenceService {
    // 报告威胁指标（PUSH）
    rpc ReportIndicator(ReportIndicatorRequest) returns (ReportIndicatorResponse);
    // 查询威胁指标（PULL）
    rpc QueryIndicator(QueryIndicatorRequest) returns (QueryIndicatorResponse);
    // 列出活跃威胁
    rpc ListActiveThreats(ListActiveThreatsRequest) returns (ListActiveThreatsResponse);
    // 配置威胁共享（admin:write）
    rpc ConfigureThreatSharing(ConfigureThreatSharingRequest) returns (ConfigureThreatSharingResponse);
    // 全局检测规则 CRUD
    rpc ListGlobalRules(ListGlobalRulesRequest) returns (ListGlobalRulesResponse);
    rpc CreateGlobalRule(CreateGlobalRuleRequest) returns (GlobalRule);
    rpc DeleteGlobalRule(DeleteGlobalRuleRequest) returns (google.protobuf.Empty);
}
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 恶意指标误报（合法请求被标记为攻击） | 指标有 `confidence` 字段；多实例交叉验证降低误报；支持"false positive"标记 |
| PII 泄露（跨实例共享用户标识） | 所有指标默认 SHA-256 哈希化；支持 encryption-only 通道；实例间共享需签署数据共享协议 |
| 指标风暴（DDoS 级指标报告） | 指标接收端自带速率限制；每个源实例有配额；低置信度指标降采样 |
| 实例间信任建立 | 可选 mTLS 双向认证 + token-based 鉴权；自有实例间信任自动建立 |
| 指标过期 | 所有指标有 `expires_at`；默认 TTL 按严重性分层（info=24h, critical=7d） |
| 法律合规（GDPR 数据删除） | 删除请求跨实例传播；指标使用 `hash` 而非原始值，使个人数据不可复原 |

### 价值·工作量

- **价值：高**（填补多实例部署的核心安全盲区；大规模企业部署必备；差异化安全竞争力）
- **工作量：XL**（指标规范 + Exchange 协议 + P2P/Hub 实现 + 全局检测规则 + 管理端点 + 加密通道）
  - Phase 1：P2P 指标共享 + 本地消费（M）
  - Phase 2：全局检测规则 + Hub 聚合器（L）
  - Phase 3：管理 UI + 误报管理 + 合规集成（L）
- **依赖：** `domains/anomaly/`、`domains/threataction/`、`shared/trust/` 的评分器（均已存在）

---

## 方向 3：多区域 Active-Active 身份数据面

### 现状

项目拥有完整的高可用与灾难恢复设施：

| 能力 | 状态 |
|---|---|
| 多副本集群（cluster bus） | ✅ `platform/cluster/`（memory + etcd + mqtt） |
| 跨副本令牌撤销广播 | ✅ `WithCrossReplicaRevocation` |
| 签名密钥跨副本协调 | ✅ `signing_keys/etcd/` + `WithCoordinatedKeyRotation` |
| 灾难恢复（DR）协调器 | ✅ `platform/lifecycle/dr/`（tracker + replicator + orchestrator + readiness） |
| 数据快照与恢复 | ✅ `interfaces/snapshot/` |
| **多区域 Active-Active 数据面** | **❌ 零实现** |
| **冲突解决（CRDT / LWW）** | **❌ 零实现** |
| **区域感知会话亲和性** | **❌ 零实现** |
| **跨区域延迟优化令牌验证** | **❌ 零实现** |

### 缺口（grep 核验）

- `active.*active.*region\|ActiveActive\|active.active\|active-active`：不在任何方向文档中
  （`ROADMAP.md` 中作为方向 §1 的依赖提及——"跨区域 active-active：依赖方向 §1（HSM 解决密钥跨区分发）"，但非独立方向）
- `CRDT\|conflict.*free.*replicat\|conflict.*resol\|merge.*conflict.*identity`：**零实现命中**
- `session.*affinity.*region\|region.*affinity\|geo.*route\|geo.*aware.*session\|read.*local.*write.*global`：**零实现命中**
- `cross.*region.*validat\|region.*token.*validat\|latency.*optim.*token\|token.*validat.*edge`：**零实现命中**

现有的 DR 解决方案是**主动-被动（Active-Passive）** 模式：一个区域处理所有流量，
另一个区域待命。切换需要人工或自动故障转移决策（几分钟级 RTO）。

### 为什么需要它

1. **全球用户的地域分布**：用户的认证请求应该由其最近的区域处理。跨区域
   往返（例如：新加坡用户从 us-east-1 认证）增加 200-500ms 延迟——对于
   交互式登录，每 100ms 延迟降低 5-7% 的转化率。

2. **区域故障无需切换**：Active-Active 架构中，一个区域故障只影响该区域的
   流量——其他区域继续服务。没有故障转移延迟（RTO≈0），没有决策风险。

3. **企业 SaaS 的强制要求**："我们的用户分布在欧美亚三个区域，你们支持
   就近接入吗？"是跨国企业采购时的常见问题。仅有的 Active-Passive DR 会导致
   回答"不支持"。

4. **区别于 DR 的架构本质**：DR 解决的是"故障时恢复"，Active-Active 解决的
   是"所有区域同时服务用户"——前者是运维能力，后者是架构模式。两者互补
   但不重叠。

### 范围

#### 1. 区域感知路由与数据分区

```
请求流:
  用户 (us-west) → DNS/GSLB → us-west 入口
                         ↓
                   us-west SSO 实例
                         ↓
           ┌── 读取: 本地区域存储 (读延迟 < 5ms)
           │
           ├── 写入: 本地区域存储 + 异步复制到其他区域
           │
           └── 令牌验证:
                 ├── 本地签发的令牌 → 本地验证
                 └── 其他区域签发的令牌 → 缓存验证 (JWKS 跨区域复制)

数据域分区:
  ┌──────────────────────────────────────────────┐
  │  区域本地数据 (Region-Local)                  │
  │  ├── OAuth 短期数据 (auth codes, device       │
  │  │   codes, PAR, refresh tokens, sessions)    │
  │  ├── 审计事件                                  │
  │  └── 流量指标 (metrics)                       │
  ├──────────────────────────────────────────────┤
  │  全局复制数据 (Globally Replicated)            │
  │  ├── 租户配置                                  │
  │  ├── 客户端注册                                │
  │  ├── 用户身份 (只读副本)                       │
  │  ├── 签名密钥 JWKS                            │
  │  └── 吊销集合 (只读副本)                       │
  ├──────────────────────────────────────────────┤
  │  区域主数据 (Region-Primary)                   │
  │  └── 用户身份变更 (写主区域, 异步复制至其他)    │
  └──────────────────────────────────────────────┘
```

**关键原则：** 热路径数据（OAuth 短期存储）必须是区域本地的——写入不需要
跨区域共识。配置数据（租户、客户端）使用最终一致性模型，允许秒级延迟。
每次区域写入通过 `cluster.Bus` 或异步复制流同步到其他区域。

#### 2. 冲突解决策略

身份数据（用户、客户端、租户）可能在多个区域被并发修改——需要冲突解决方案。

```go
type ConflictStrategy string

const (
    // 最后写入者获胜（LWW）——适用于大多数配置变更
    // 使用 wall clock 确定"最后"，但容忍 ≤5s 的时钟偏差
    ConflictLWW ConflictStrategy = "last_writer_wins"

    // 仅允许一个区域写入——适用于密码 hash、client_secret 等敏感字段
    // 其他区域只读；写入通过区域重定向
    ConflictSingleWriter ConflictStrategy = "single_writer"

    // CRDT 合并——适用于集合类数据（角色、scope、权限）
    // 使用 Observed-Remove Set (OR-Set) 或相关的 CRDT 类型
    ConflictCRDT ConflictStrategy = "crdt_merge"
)

type ReplicationEvent struct {
    ID            string
    Region        string       // 来源区域
    EntityType    string       // "tenant", "client", "user", "key"
    EntityID      string
    Data          []byte       // 序列化后的实体数据
    Timestamp     time.Time    // 发生时间（wall clock）
    VectorClock   map[string]int64  // 向量时钟（用于 CRDT）
    ConflictStrategy ConflictStrategy
}
```

#### 3. JWKS 跨区域分发

```
每个区域有自己的签名密钥（按区域命名空间隔离）:

  us-west-1: kid="uswest1-20260711-ed25519"
  eu-west-1: kid="euwest1-20260711-ed25519"
  ap-southeast-1: kid="apse1-20260711-ed25519"

全局 JWKS 端点（聚合所有区域的公钥）:
  GET /.well-known/jwks.json → [uswest1-..., euwest1-..., apse1-...]

客户端/RS 验证：
  - 从本地区域的 JWKS 端点获取（包含所有区域的公钥）
  - 按 kid 选择对应区域的公钥验证
  - 本地 JWKS 缓存通过区域间的 Bus 订阅更新

令牌验证延迟优化：
  - 本地签发的 token → 本地 JWKS 缓存（0 额外延迟）
  - 远程区域签发的 token → 本地 JWKS 缓存已有（warm cache，~2ms）
  - 冷启动 → 远程区域 JWKS 获取（~50-100ms，仅首次）
```

#### 4. 区域健康与故障隔离

```go
type RegionHealth struct {
    RegionID    string
    Status      RegionStatus // healthy, degraded, offline
    // 最后心跳时间
    LastHeartbeat time.Time
    // 延迟统计 (对其他区域的探测)
    LatencyStats map[string]LatencyStat
    // 服务容量（低于阈值时其他区域接管）
    Capacity     int  // 剩余容量百分比
    // 区域隔离状态：true 表示该区域因故障被自动隔离
    IsIsolated  bool
}

type RegionStatus string

const (
    RegionHealthy  RegionStatus = "healthy"
    RegionDegraded RegionStatus = "degraded"   // 部分能力不可用
    RegionOffline  RegionStatus = "offline"    // 完全不可达
)

// 隔离策略：
//   - 一个区域心跳超时（通常 15-30s） → 标记 degraded
//   - 持续超时（60s）→ 标记 offline
//   - offline 区域不再接收用户请求，已存在的会话通过其他区域继续
//   - region 恢复后，通过回填同步缺失数据
```

#### 5. 会话亲和性（用于某些需要粘滞会话的场景）

```
Cookie: sso_session_hint=<region_id>

用户首次认证时分配到最近的区域，写入 cookie。
只要该区域健康，用户后续请求由同一区域处理。
区域故障时，cookie 被忽略，用户被路由到下一个最近区域。
不需要粘滞会话的场景（如纯 API 调用）无需该 cookie。
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 两个区域并发创建相同 tenant_id 的租户 | LWW 策略，后写入者获胜；客户端 ID 使用 UUID 几乎消除冲突 |
| 一个区域的时钟偏差 (-5s) 导致 LWW 顺序错误 | NTP 监控 + 5% 容忍阈值；超过 5s 偏差的区域自动隔离 |
| 区域间网络分区 | 每个区域自主运行（分区容忍）；恢复后通过向量时钟合并或全量同步 |
| 密码 hash 在区域 A 更新，但区域 B 仍使用旧 hash | 密码认证是"写"操作——用户认证时路由到其 home 区域；或所有区域均可认证（最终一致性） |
| 全局吊销集合的传播延迟 | 令牌验证时检查本地吊销缓存（< 1s 延迟）；高危吊销走紧急通道（区域内同步 → 跨区域秒级） |
| 区域 A 签发 refresh_token，用户从区域 B 使用 | refresh token 携带 home_region 信息；区域 B 查询区域 A 的 refresh 状态（或 refresh token 自包含断言+签名） |
| 与现有的 DR 协调器的关系 | DR 解决的是"整个堆栈故障"，Active-Active 解决的是"跨区域正常运行"。两者互补：Active-Active 减少 DR 触发频率；DR 是 Active-Active 的最后防线 |

### 价值·工作量

- **价值：极高**（架构战略级能力；全球企业必备；与 AWS/GCP/Azure 全球基础设施对齐）
- **工作量：XXL**（区域路由 + 数据分区 + CRDT/LWW 冲突解决 + JWKS 分发 + 会话亲和性 + 监控）
  - Phase 1：区域感知 JWKS 分发 + 短期存储区域化（L）
  - Phase 2：全局配置复制 + LWW 冲突解决（L）
  - Phase 3：CRDT 合并 + 区域路由 + 会话亲和性（XL）
  - Phase 4：区域健康监控 + 自动故障隔离 + 恢复回填（L）
- **依赖：** `platform/cluster/bus.go`（已有，需扩展事件类型）、`platform/lifecycle/dr/`（已有，需兼容 active-active 而非取代）

---

## 方向 4：应用所有者身份可观测性与令牌生命周期分析

### 现状

项目拥有丰富的可观测性设施，但全部面向 **IdP 运营者**：

| 能力 | 面向角色 | 状态 |
|---|---|---|
| Prometheus 指标（令牌/API/会话/审计等） | IdP 运营者 | ✅ |
| 结构化审计事件记录与查询 | IdP 运营者 / 合规 | ✅ |
| 管理员实时 SSE 事件流 | IdP 运营者 | ✅ |
| 多租户 BI 仪表盘（post-protocol 方向 5） | IdP 运营者 / 租户管理员 | ❌ 未实现 |
| **应用（OAuth Client）所有者令牌分析** | **应用开发者/所有者** | **❌ 零实现** |
| **令牌发放/刷新/吊销的按应用维度洞察** | **应用开发者/所有者** | **❌ 零实现** |
| **应用授权健康评分** | **应用开发者/所有者** | **❌ 零实现** |

### 缺口（grep 核验）

- `app.*analytics\|app.*dashboard\|application.*dashboard\|client.*dashboard\|client.*analytics`：**零实现命中**
- `token.*churn\|token.*hygiene\|refresh.*ratio\|token.*refresh.*rate\|access.*token.*lifetime`：**零实现命中**
- `client.*health.*score\|app.*health.*score\|application.*health\|client.*insight\|app.*insight`：**零实现命中**
- `token.*usage.*by.*client\|client.*token.*usage\|client.*metrics.*dashboard`：**零实现命中**
- 无 `WithApplicationAnalyticsStore`、`WithClientMetricsCollector` 等配置

### 为什么需要它

> **"我的应用正常吗？为什么用户的令牌失效了？刷新率是正常的吗？为什么认证失败的次数变多了？"**

这是 OAuth 客户端所有者（通常是后端团队或应用开发团队）在集成 SSO 后最常问的问题。
当前项目仅向 IdP 运营者提供可观测性——应用所有者能看到的只有 `401` 响应和
"请稍后再试"。这造成了以下具体缺口：

1. **应用所有者无自服务诊断能力**：每次认证失败都需要联系 IdP 运营团队查看
   审计日志。在大型组织中，这种跨团队沟通的 MTTR（平均修复时间）可能是
   数小时而非数分钟。

2. **无法区分"应用层的 bug"和"身份层的故障"**：应用所有者看到 5% 的令牌
   刷新失败，但不知道是因为 refresh token 已过期、scope 已变更、还是 IdP
   本身的故障。没有应用维度的令牌生命周期数据，无法快速定界。

3. **令牌浪费无法识别**：有些应用每小时请求 5 次新的 access_token，但本应
   使用 refresh_token 或延长 TTL。每个多余的令牌签发都增加了 IdP 的负载——
   但对应用所有者完全不可见。

4. **安全审计盲区**：应用所有者无法知道某个 client_id 在过去 24 小时内认证
   了多少次、从多少种 IP 段、使用的 auth method 分布——这些都是安全异常检测
   的基础信号，但现在完全归零。

### 范围

#### 1. 客户端指标收集器

```go
// ClientMetricsCollector 收集按客户端（OAuth client）聚合的身份数据维度
type ClientMetricsCollector interface {
    // 记录令牌事件（单次，低延迟）
    RecordTokenEvent(ctx context.Context, event TokenEvent) error

    // 批量查询指标
    QueryClientMetrics(ctx context.Context, clientID string, window TimeWindow) (*ClientMetrics, error)

    // 多客户端概览
    ListClientSummaries(ctx context.Context, filter ClientFilter) ([]*ClientSummary, error)
}

type TokenEventType string

const (
    TokenEventIssued        TokenEventType = "issued"
    TokenEventRefreshed     TokenEventType = "refreshed"
    TokenEventRevoked       TokenEventType = "revoked"       // 主动吊销
    TokenEventExpired       TokenEventType = "expired"       // TTL 自然到期
    TokenEventExchange      TokenEventType = "exchanged"     // token-exchange 产出
    TokenEventRejected      TokenEventType = "rejected"      // refresh 因 family 重用被拒
    TokenEventAuthFailed    TokenEventType = "auth_failed"   // 认证失败
    TokenEventGraceRefresh  TokenEventType = "grace_refresh" // grace window 内的刷新
)

type TokenEvent struct {
    ClientID      string
    EventType     TokenEventType
    GrantType     string        // authorization_code, client_credentials, refresh_token, etc.
    AuthMethod    string        // client_secret_basic, private_key_jwt, tls_client_auth, etc.
    TenantID      string
    UserID        string        // 适用于有用户上下文的令牌
    Scope         string        // 请求的 scope（空格分隔）
    TokenType     string        // access_token, refresh_token, id_token, exchange_token
    TokenTTL      time.Duration
    Region        string
    GeoCountry    string        // 请求来源国家
    IPHash        string        // SHA-256(IP) 不存储原始 IP
    StatusCode    int           // HTTP 状态码
    ErrorCode     string        // 如果是失败事件
    Timestamp     time.Time
}
```

#### 2. 应用所有者指标与视图

**每个 OAuth Client 自服务面板（面向应用开发者/所有者）：**

```
概览:
  ├── 健康评分: 98/100（基于认证成功率、令牌浪费率、异常率）
  │
  ├── 最近 24 小时:
  │   ├── 认证请求: 12,847 次（同比 +3.2%）
  │   ├── 成功率: 99.2%（失败: 103 次）
  │   ├── 活跃令牌: 2,341 个（access_token）
  │   ├── 刷新令牌: 892 个（refresh_token，当前轮换家族数）
  │   └── 平均令牌生命周期: 45 min（access_token）/ 7天（refresh_token）
  │
  ├── 认证方法分布:
  │   ├── authorization_code (PKCE): 65%
  │   ├── client_credentials: 20%
  │   ├── refresh_token: 10%
  │   └── token_exchange: 5%
  │
  ├── 失败分析（Pareto 排序）:
  │   ├── #1 invalid_grant (过期 refresh_token): 45%
  │   ├── #2 invalid_token (过期 access_token): 30%
  │   ├── #3 invalid_scope (scope 扩大): 12%
  │   └── #4 unauthorized_client (无权限): 8%
  │
  ├── 令牌新鲜度:
  │   ├── refresh_token 复用率: 2.3次/令牌（理想: 1次）
  │   ├── 令牌浪费率: 15%（提前 30% 以上过期前被替换）
  │   └── 推荐 TTL 优化: access_token TTL 可从 30min 延长至 60min
  │
  └── 安全信号:
      ├── 唯一 IP 数: 847（异常: 比昨天 +40%）
      ├── 认证来源国家: 12（异常: 新出现: RU, NG）
      └── 应用内 client_secret 轮换天数: 未轮换（73天）
```

**全局应用所有者概览（面向平台/安全团队）：**

```
所有已注册客户端排序（默认: 健康评分从低到高）:
  ├── client_app_1: 健康 45/100 ❌（认证成功率 < 80%，存在泄露风险）
  │     └── 建议: 检查 client_secret 是否泄露，考虑轮换
  ├── client_app_2: 健康 72/100 ⚠️（令牌浪费率高）
  │     └── 建议: 实现 refresh_token 管理，减少不必要的 access_token 重发
  ├── client_app_3: 健康 98/100 ✅
  └── ...
```

#### 3. 客户端健康评分算法

```go
type ClientHealthScoreInput struct {
    // 认证成功率（权重: 40%）
    AuthSuccessRate float64 // 近 7 天加权

    // 令牌效率（权重: 25%）
    TokenWasteRate  float64 // 提前超过 20% TTL 替换的令牌比例
    RefreshRatio    float64 // 每次 refresh 的平均 access_token 使用次数

    // 安全姿态（权重: 20%）
    SecretAgeDays   int     // client_secret 距离上次轮换的天数
    UnusualIPRatio  float64 // 来自新 IP 的请求比例（>20% 扣分）
    AnomalyCount    int     // 近 7 天被异常检测器命中的请求数

    // 协议合规（权重: 15%）
    PKCEUsage       bool    // 是否使用 PKCE（强制使用）
    DPoPUsage       bool    // 是否使用 DPoP（推荐使用）
    UsesRotation    bool    // 是否支持 refresh 轮换
}

// 评分映射:
//   90-100: 健康（绿色）✅
//   70-89:  注意（黄色）⚠️
//   50-69:  需要改进（橙色）🔶
//   <50:    危险（红色）❌
```

#### 4. 管理端点和数据访问

```protobuf
service ClientObservabilityService {
    // 客户端维度概览（列出 client_id + 健康评分 + 关键指标）
    rpc ListClientSummaries(ListClientSummariesRequest) returns (ListClientSummariesResponse);
    // 单个客户端详情
    rpc GetClientMetrics(GetClientMetricsRequest) returns (ClientMetricsDetail);
    // 令牌事件流（某 client_id 的实时令牌事件 SSE）
    rpc StreamClientEvents(StreamClientEventsRequest) returns (stream TokenEvent);
    // 令牌发放/刷新/吊销的时序图数据
    rpc QueryTokenTimeSeries(QueryTokenTimeSeriesRequest) returns (TokenTimeSeries);
    // 应用健康评分（触发重新计算）
    rpc GetClientHealthScore(GetClientHealthScoreRequest) returns (ClientHealthScore);
    // 获取健康建议
    rpc GetClientRecommendations(GetClientRecommendationsRequest) returns (RecommendationList);
}
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 大量客户端（10万+）的指标存储 | 使用预聚合（Pre-aggregation）时序表；原始事件 TTL=7d，聚合数据 TTL=90d |
| 客户端间指标隔离 | 应用所有者只能看到自己的 client_id；平台管理员可查看所有 |
| 健康评分算法更新 | 评分版本化；通知客户端所有者评分算法更新（更新日志） |
| 存储开销 | 每个令牌事件约 200 字节；单日 100M 事件 → 20GB（预聚合后 < 1GB） |
| 与现有审计系统的关系 | 审计系统是**持久记录**（不可变、防篡改），客户端指标是**聚合衍生数据**（可重算、可回填） |
| 公共客户端 vs 机密客户端 | 公共客户端（SPA/原生）的健康评分侧重 PKCE 和 CORS，机密客户端侧重 secret 管理和 mTLS |

### 价值·工作量

- **价值：高**（显著降低应用所有者的诊断 MTTR；改善开发者体验；提供安全基线信号）
- **工作量：L-M**（ClientMetricsCollector SPI + 指标存储 + 健康评分引擎 + 查询 API + 指标嵌入 SPA）
  - Phase 1：指标收集器 + 聚合存储 + 基础查询 API（M）
  - Phase 2：健康评分引擎 + 建议生成器（M）
  - Phase 3：开发者门户嵌入健康面板（L）
- **依赖：** `platform/metrics/`（已有基础设施）、`internal/handler/tokengrant/`（已有 token 事件点）

---

## 方向 5：密码算法生命周期管理与迁移框架

### 现状

项目支持广泛且强健的密码学算法选择：

| 算法 | 用途 | 状态 |
|---|---|---|
| EdDSA (Ed25519) | 令牌签名 | ✅ `defaultimpl/ed25519_jwt_issuer.go` |
| ECDSA (ES256/384/512) | 令牌签名 | ✅ `defaultimpl/ecdsa_jwt_issuer.go` |
| RSA (RS256/PS256) | 令牌签名 | ✅ `defaultimpl/rsa_jwt_issuer.go` |
| HMAC-based (HS256+) | 令牌签名 | ❌ 显式禁止（AGENTS.md §2） |
| 对称加密 (AES-GCM) | snapshot 加密 | ✅ `snapshot/encryptionaesgcm/` |
| 非对称 JWE (RSA-OAEP/ECDH-ES) | id_token/userinfo 加密 | ✅ `security/jwe.go` |
| SAML 签名 (SHA-1/SHA-256) | SAML 断言/响应 | ✅ `infrastructure/saml/`（SHA-1 显式禁止后） |
| **算法迁移/Migration 框架** | **❌ 零实现** |
| **算法弃用 Lifecycle 模型** | **❌ 零实现** |
| **算法兼容性声明 / 协商** | **❌ 零实现** |

### 缺口（grep 核验）

- `alg.*migrat\|AlgorithmMigrat\|alg.*transition\|AlgTransition\|key.*migrat\|KeyMigrat`：**零实现命中**
- `alg.*deprecat\|alg.*lifecycle\|AlgorithmLifecycle\|alg.*sunset\|crypto.*agility.*framework`：**零实现命中**
- `alg.*compat.*mode\|alg.*dual\|dual.*alg\|alg.*phase\|phase.*out.*alg\|signing.*alg.*policy`：**零实现命中**
- `WithAlgPolicy\|WithAlgorithmTransition\|signing_alg_migration`：**零实现命中**

当前的 `WithSupportedSigningAlgs` 是一个简单的 allowlist——禁用不安全的算法，
但没有任何机制来**逐步迁移**（例如：从 RS256 → ES256，或从 Ed25519 → 未来量子安全算法）。

### 为什么需要它

1. **密码学算法会变弱**：SHA-1 已被实际碰撞攻击攻破。RSA-2048 在未来
   10-15 年内可能被量子计算削弱。当这些事件发生时（或 NIST 发布新标准时），
   整个令牌生态需要从**一个算法族迁移到另一个**。没有迁移框架，
   这将是一次"全有或全无"的协调切换——极高风险。

2. **遵循 NIST / BSI / ANSSI 指南**：政府客户通常要求"截止 YYYY-MM-DD 后
   必须使用 ≥256 位 ECDSA"。没有算法生命周期管理，每次新要求都需要手动、
   全量、停机操作。

3. **客户特定的算法要求**：金融客户可能要求 FIPS 140-3 批准的算法组合
   （RSA-3072+, ECDSA P-384+），而 IoT 客户可能偏好 Ed25519 以获得
   更小的签名。没有算法迁移框架，每个客户要求都是定制分支。

4. **与密钥轮换的差异**：密钥轮换（当前实现）更换的是**同一算法的新密钥**。
   算法迁移更换的是**整个算法族**——这涉及签名验证器、JWKS 端点行为、
   admin 客户端配置、以及依赖算法的所有下游系统。这是一个比密钥轮换
   更广泛的变更。

### 范围

#### 1. 算法生命周期模型

```go
type AlgPhase int

const (
    // 活跃：算法被积极使用于签发和验证。默认设置
    AlgPhaseActive AlgPhase = iota

    // 仅验证：新令牌不再用该算法签发，但现有令牌仍然可以验证
    // 允许下游系统有时间升级
    AlgPhaseVerifyOnly

    // 弃用（Deprecated）：算法仅用于验证现有令牌，签发时
    // 记录警告事件，标记在指标中。弃用期通知
    AlgPhaseDeprecated

    // 退役（Retired）：算法不再用于签发或验证，任何持有
    // 该算法令牌的请求返回标准错误。移除前需确认所有依赖方已升级
    AlgPhaseRetired
)

type AlgorithmPolicy struct {
    ID           string          // 策略唯一 ID
    Algs         []string        // 目标算法列表
    Phase        AlgPhase
    EffectiveAt  time.Time       // 策略生效时间（支持预配置）
    NotifyBefore time.Duration   // 在进入下一阶段前 N 天发送通知
    AutoAdvance  bool            // 是否自动推进（预配置的时间线）
}

// 示例迁移时间线：
//   2026-07-01: RS256 Active
//   2026-10-01: RS256 → VerifyOnly (ES256 设为 Active)
//   2027-01-01: RS256 → Deprecated
//   2027-04-01: RS256 → Retired (完全移除)
```

#### 2. 迁移运行模式

```
迁移前的状态（Active: RS256 + ES256）:
  JWKS: 包含 RS256 和 ES256 的公钥
  签发: 使用 RS256（默认签发算法）
  验证: RS256 + ES256 均可验证

迁移进行中（Phase 1: ES256 成为默认签发）:
  JWKS: 不变（两种公钥都存在）
  签发: 新令牌使用 ES256
  验证: RS256 + ES256 均可验证（旧的 RS256 令牌在 TTL 内仍然有效）
  事件: 签发 RS256 令牌时记录 audit event "signing_with_deprecated_alg"

迁移进行中（Phase 2: RS256 → VerifyOnly）:
  JWKS: 保留 RS256 公钥
  签发: 所有新令牌使用 ES256
  验证: RS256 + ES256 均可验证（仍在 TTL 内的 RS256 令牌）
  事件: 尝试签发 RS256 返回错误

迁移完成（Phase 3: RS256 → Retired）:
  JWKS: 移除 RS256 公钥
  签发: ES256
  验证: 仅 ES256
  事件: RS256 令牌验证失败返回标准 invalid_token
  清理: 任何持有 RS256 令牌的 client 收到异常，需要重新认证
```

#### 3. 兼容性模式

```go
type CompatibilityMode struct {
    // 双签发模式（Dual-Issuance Mode）
    // 在迁移期间，同时签发旧算法和新算法的令牌（用于无缝过渡）
    DualIssuance Duration `yaml:"dual_issuance"`

    // 混合验证集（Hybrid Verify Set）
    // 允许跨迁移阶段的验证集合——旧算法令牌在 TTL 内仍然有效
    HybridVerifyTTL time.Duration `yaml:"hybrid_verify_ttl"`

    // 宽限期配置（Grace Period）
    // 客户端在收到 Deprecated 算法的令牌后，还有多长时间可以升级
    ClientGracePeriod time.Duration
}

// 双签发示例：
//   2026-10-01 ~ 2026-11-01: 每个 token 同时包含
//     - 旧算法签名（RS256，位于 JWT header 的第二个签名中）
//     - 新算法签名（ES256，作为主 JWT 签名）
//   2026-11-01 后: 仅 ES256 签名
```

#### 4. 算法发现与协商

扩展现有 OIDC Discovery 和 JWKS 端点，支持算法生命周期信息：

```
GET /.well-known/openid-configuration
{
  ...
  "id_token_signing_alg_values_supported": ["ES256", "RS256", "EdDSA"],
  "id_token_signing_alg_phases": {
    "ES256": "active",
    "RS256": "verify_only",
    "EdDSA": "deprecated"
  },
  "id_token_signing_alg_sunset": {
    "RS256": "2027-04-01T00:00:00Z",
    "EdDSA": "2027-01-01T00:00:00Z"
  }
}
```

允许客户端通过注册参数请求未来算法：

```json
POST /register
{
  "client_name": "my-app",
  "token_endpoint_auth_method": "private_key_jwt",
  // 请求未来的算法偏好
  "requested_signing_alg": "ES512",
  "alg_migration_contact": "team@example.com"
}
```

#### 5. 管理端点

```protobuf
service AlgorithmLifecycleService {
    // 查看当前算法策略
    rpc GetAlgorithmPolicy(google.protobuf.Empty) returns (AlgorithmPolicySet);

    // 更新算法策略
    rpc UpdateAlgorithmPolicy(UpdateAlgorithmPolicyRequest) returns (AlgorithmPolicy);

    // 查看算法使用情况统计
    rpc GetAlgorithmUsageStats(google.protobuf.Empty) returns (AlgorithmUsageStats);

    // 获取建议的算法迁移时间线
    rpc RecommendMigrationTimeline(RecommendRequest) returns (MigrationPlan);

    // 模拟迁移影响（dry run）
    rpc SimulateMigration(SimulateRequest) returns (MigrationImpact);
}

// 算法使用统计：
type AlgorithmUsageStats struct {
    // 各算法的令牌分布（近 7 天）
    TokenDistribution map[string]int64  // alg → count
    JWKSDistribution  map[string]int64  // alg → JWKS 中该算法密钥数
    // 仍然使用已弃用算法的活跃客户端列表
    ClientsOnDeprecatedAlgs []*ClientAlgUsage
}
```

#### 6. 指标与告警

```
sso_alg_signing_total{alg="ES256",phase="active"} 12487
sso_alg_signing_total{alg="RS256",phase="deprecated"} 342
sso_alg_verification_total{alg="RS256",phase="verify_only"} 891
sso_alg_verification_total{alg="RS256",phase="retired",result="rejected"} 23

告警规则：
  - sso_alg_signing_total{phase="deprecated"} > 0 for 24h
    → "⚠️ 仍有令牌使用已弃用算法签发，建议检查签发逻辑"
  - sso_alg_verification_total{phase="retired",result="rejected"} > 0
    → "🚨 客户端使用已退役算法令牌认证失败，需要立即升级"
  - clients_on_deprecated_algs > 100
    → "数十个客户端仍未迁移，建议发起迁移通知"
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 迁移期间旧算法令牌的剩余 TTL | 令牌签发时在其 TTL 内保留验证能力（默认 access_token=1h，refresh_token≥14d 内都可验证） |
| 客户端使用弃用 JWKS 公钥验证 | 弃用算法的公钥保留在 JWKS 中，直到退役阶段才移除；退役后返回 `invalid_token` |
| 多个算法同时处于迁移状态（A→B 同时 B→C） | 允许嵌套迁移；复杂场景推荐链式而非并行迁移 |
| 密钥轮换与算法迁移同时发生 | 算法迁移框架与现有轮换框架正交运行；轮换更换密钥材料，迁移更换算法族 |
| 3075+ 量子安全算法（如 ML-KEM、SLH-DSA） | 框架设计为算法无关——新增算法只需注册到算法注册表即可 |
| 不同协议的不同算法策略 | 允许 per-protocol 策略：OIDC ID Token 用 ES256，SAML Assertion 用 RS256-3072 |
| 联邦伙伴的算法兼容性 | 迁移完成后 JWKS 中不再包含旧算法公钥，联邦伙伴需要同步更新其信任锚 |

### 价值·工作量

- **价值：高**（密码学合规刚需；防止"钥匙断裂"式迁移事件；未来量子安全的战略准备）
- **工作量：L-XL**（生命周期模型 + 双签发 + 发现扩展 + 管理端点 + 指标/告警）
  - Phase 1：生命周期模型 + 阶段切换引擎 + 签发/验证依阶段决策（M）
  - Phase 2：双签发兼容模式 + 发现扩展 + 算法使用统计（M）
  - Phase 3：管理端点 + 迁移模拟 + 客户端通知（L）
- **依赖：** `shared/security/` 的算法 allowlist（已存在）、`protocols/oidc/metadata.go`（已存在）、
  签发器和验证器（已存在，需注入阶段感知逻辑）

---

## 总结

| 方向 | 价值 | 工作量 | 优先级 | 战略领域 |
|---|---|---|---|---|
| ① 令牌绑定传播与委派链安全 | 高 | M | **P1** | 安全纵深防御 |
| ② 联邦化跨实例威胁情报 | 高 | XL | P2 | 跨实例安全协同 |
| ③ 多区域 Active-Active 数据面 | 极高 | XXL | P3 | 全球规模韧性 |
| ④ 应用所有者令牌分析 | 高 | M | **P1** | 平台智能化 |
| ⑤ 密码算法生命周期管理 | 高 | L-XL | **P1** | 运维安全合规 |

### 优先级逻辑

- **P1（立即启动）**：方向①（安全漏洞修复——委派链失去绑定）、方向④（核心开发者体验差距）、
  方向⑤（合规/安全运维的预防性投资）
- **P2（中期）**：方向②（高价值但依赖现有异常检测设施的稳定性，且跨实例机制需更多设计）
- **P3（长期）**：方向③（战略级但工作量极大，需依赖前序方向①和方向②的成果，
  以及 `ROADMAP` 方向 §1 HSM 密钥跨区分发的完成）

### 与现有路线图的关系

- 方向①（令牌绑定传播）直接与 `ROADMAP` 方向③ FAPI 一致性互补——FAPI 要求
  sender-constraint，而绑定传播是 sender-constraint 在委派链中的延续
- 方向②（跨实例威胁情报）建立在现有的 `domains/anomaly/` 和 `domains/threataction/`
  之上，并扩展了 `shared/trust/` 评分器的覆盖范围
- 方向③（Active-Active）与 `ROADMAP` 方向④ 多副本韧性和 `platform/lifecycle/dr/`
  互补——DR 解决故障恢复，Active-Active 解决正常运行时的全球就近接入
- 方向④（应用所有者令牌分析）是 post-protocol 方向⑤ 身份分析 BI 的镜像——
  BI 面向 IdP 管理员，令牌分析面向应用开发者
- 方向⑤（算法迁移）是 `shared/security/` 算法 allowlist 和密钥轮换的自然演进——
  从"硬编码的 allowlist"到"可编程的算法生命周期"

---

*本报告基于 2026-07-11 全代码库扫描。所有 gap 声明均经 grep 核验确认与现有文档零重叠。*
