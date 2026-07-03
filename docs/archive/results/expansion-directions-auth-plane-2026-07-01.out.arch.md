Now I have a thorough understanding of the codebase. Let me produce the architecture analysis.

---

# Architecture Analysis: OAuth 2.0 / OIDC SSO Platform

## 1. 架构评估

### 1.1 当前架构的优势

| 维度 | 评估 |
|---|---|
| **依赖方向** | 七层物理分层模型（shared → platform → domains → protocols → infrastructure → interfaces → composition）是最大亮点。向上导入即 CI 失败的设计防止了架构腐烂的常见路径（domain → infrastructure 等）。 |
| **模块化程度** | 每个关注点 = interface + memory 实现 ± sqlite/etcd 的六边形模式执行彻底。所有存储后端的切换通过 YAML 一行完成，无厂商锁定。 |
| **安全约束** | Oracle-leak 塌缩、反枚举、fail-closed/fail-open 开关被作为提交级门禁而非代码 review 建议，将安全模式从"最佳实践"升级为"编译时检查"。 |
| **预算门禁** | 文件 500 行、函数 50 行、圈复杂度 15 的红线 + 豁免列表只缩不增的ratchet，主动防止了技术债务的累积。 |

### 1.2 关键架构债务

1. **根目录 sso 包的体积**：虽然大部分 handler 逻辑已提取到 `internal/handler/` 和 `protocols/oauth/`，但 `sso.go` + `server_*.go` + `accessors.go` + `aliases.go` 构成的 Server 对象仍然承担过多职责。`Deps` 接口族（`IntrospectDeps`, `TokenExchangeDeps`, `AuthCodeDeps`...）正在增长但缺乏统一的依赖注入模式。

2. **物理目录 vs 逻辑层不一致**：ADR-0006 承认了这一 gap。`layerName()` 的手工维护是持续风险——新增顶级包时必须同步更新，否则 CI 失败。随着嵌套模块（ldap/kerberos/saml/redis）的增加，维护成本线性增长。

3. **Token Exchange 的 act 链深度保护**：`MaxActChainDepth = 10` 是硬编码常量。对于 deep delegation 场景（A→B→C→...→Z），10 跳可能不够但也可能被用作 DoS 向量。缺乏可配置性。

4. **RiskScorer 与 anomaly.Detector 的割裂**：二者几乎是同一问题的同步/异步两面，但 SPI 定义完全隔离。`LoginContext` 本应是二者的桥梁，但代码中甚至不存在该类型（输入文档提到的 `RiskPolicyDecision` 字段在当前代码库中不可查——这意味着该设计尚未落地，仅是分析中的假设）。

### 1.3 关键决策合理性与风险

| 决策 | 合理性 | 风险 |
|---|---|---|
| handler.go 作为唯一 wiring 层 | ✅ 清晰的依赖注入点 | 随着 grant 类型增加，handlers.go 超过 500 行 |
| 每个 grant 使用独立 Deps 接口 | ✅ 接口隔离原则 | 重复代码（每个 Deps 都要申明 ClientStoreAccessor()） |
| 异步 anomaly 脱离请求路径 | ✅ 安全：不因检测延迟拖垮登录 | 异步意味着检测结果无法用在当前请求的 auth 决策中——这是有意为之，但需要自适应策略 DSL 桥接 |
| 所有存储接口选内存实现优先 | ✅ 降低入门门槛、测试友好 | 内存实现在高并发下的数据竞争需额外防护（已通过 race detector 覆盖） |

---

## 2. 扩展方向

### 方向 A：自适应认证策略引擎（Adaptive Authentication Policy Engine）

**业务价值：** 当前 RiskScorer（同步）和 anomaly.Detector（异步）是完全割裂的两条轨道。同步检测无法做时间窗口聚合（50ms 预算限制），异步检测的信号不能影响当前请求的 auth 决策。一个策略引擎桥接二者——风险评分 + 历史异常信号 → DSL 驱动的认证策略（Allow / Deny / Step-Up / MFA Challenge）——是走向企业级智能认证的关键一步。

**核心挑战：**
1. **50ms 同步窗口约束**：策略评估必须在请求路径内完成，而异步信号的聚合结果需要从本地缓存或内存存储快速读取。需要设计"信号摘要"结构——每个用户/客户端的轻量级状态指纹，而非完整事件历史。
2. **DSL 设计权衡**：是采用现有策略语言（Rego/OPA、CEL）还是自建？Rego 引入外部依赖和二进制体积，CEL 是 Go 原生但表达能力有限。自建 DSL 开发成本高。
3. **信号到策略的映射**：anomaly.Detector 的信号类型（`impossible_travel`, `velocity_burst`, `new_country`）是开放性集合。策略 DSL 需要支持对这些信号类型的组合式匹配（加权和、阈值门限、时间衰减）。

**技术方案选项：**

| 选项 | 复杂度 | 灵活性 | 性能 |
|---|---|---|---|
| A1: 集成 OPA/Rego 作为策略引擎 | 中 | 高 | 10-20μs/策略 |
| A2: 自建 Go-native CEL 策略引擎 | 低 | 中 | 5-10μs/策略 |
| A3: 自建 YAML 配置式规则引擎 | 低 | 低 | < 5μs/策略 |

**推荐路径：** 先做 A3（YAML 配置式），在 `domains/anomaly/strategy` 包中定义加权信号规则：
```yaml
# 策略定义
policy:
  rules:
    - name: "impossible_travel_stepup"
      when:
        all:
          - signal: "impossible_travel"
            min_severity: "warn"
          - signal: "velocity_burst"
            min_score: 60
      then: "require_step_up"  # 或 "deny", "mfa", "allow_with_audit"
    - name: "new_device_allow"
      when:
        and:
          - not:
              signal: "impossible_travel"
          - signal: "new_device"
            max_occurrences: 3  # 过去 24 小时内允许 3 次
      then: "allow_with_audit"
```

**架构变更：**
- 新增：`domains/anomaly/strategy/`——策略引擎内核
- 修改：`shared/spi/risk.go`——RiskScorer 接口扩展，支持策略 ID 注入
- 修改：`domains/anomaly/runner.go`——异步信号写回策略引擎的缓存状态
- 新增：`config/policy.yaml`——策略配置根

**对现有系统影响：** 低。RiskScorer 已存在 fail-open 开关，策略引擎可以作为 RiskScorer 的装饰器实现，不影响已存在的 sync-only scorer 用户。

---

### 方向 B：Token Exchange 增强——自动范围收缩 + 循环检测 + may_act 审计链

**业务价值：** RFC 8693 token-exchange 是企业 OAuth 的基石（服务间身份传播）。当前实现已支持 act 链和 may_act，但三个关键缺陷：
1. 范围默认复制而非收缩——下游服务默认获得上游的全部权限
2. 无循环检测——恶意或错误的 delegation 链可能形成死循环
3. `may_act` 无审计跟踪——管理员无法追溯"谁以谁的名义做了什么"

**核心挑战：**
- **范围收缩的默认行为变更**：从"复制 subject 范围"改为"intersect(subject 范围, 下游 client 允许范围)"是破坏性变更。现有 token-exchange 的消费者可能会收到 scope 变少的 token。需要版本化行为或 opt-in/opt-out 开关。
- **循环检测的性能开销**：act 链遍历是 O(n) 操作，当前 `MaxActChainDepth = 10`，递归指针遍历在链上递归查找时性能可接受。但需要在每次 prepend 操作时做环检测。

**技术方案：**

```
功能: 范围自动收缩 (opt-in by default, opt-out per client)
位置: tokExResolveScope() 中
变更: 新增 Client.TokenExchangeScopePolicy 字段
      取值: "copy" (当前行为) | "intersect" (新默认)

功能: 循环检测
位置: tokExResolveActor() 中 prepend 之前
算法: walk(fast/slow pointer or pointer-compare)
      快速失败: 若 act 链已有当前 actor sub，拒绝

功能: may_act 审计链
位置: tokExAuditSPIFFE() 旁，新增 tokExAuditDelegation()
输出: 独立审计事件类型 EventTokenExchangeDelegation
      包含: actor_sub, subject_sub, downstream_client_id, may_act_constraint
```

**预期架构变更：**
- 修改：`internal/handler/tokengrant/token_exchange_stages.go`——`tokExResolveScope` 内加入 `intersect` 模式
- 修改：`shared/core/types.go`——Client 结构新增 `TokenExchangeScopePolicy` 字段
- 修改：`platform/audit/events.go`——新增 `EventTokenExchangeDelegation`
- 新增：`shared/core/consts.go`——`ScopePolicyCopy`, `ScopePolicyIntersect` 常量

**对现有系统影响：** 中。范围收缩行为变更需要明确的迁移策略：
1. 默认 `intersect`，但通过配置 `TokenExchangeScopePolicyDefault: "copy"` 保留旧行为
2. 每个 client 可通过 `Client.TokenExchangeScopePolicy: "copy"` 选择退出
3. 审计日志中标记使用 `copy` 模式的 exchange 事件

---

### 方向 C：带内省签名的可缓存令牌内省（Signed Introspection Response）

**业务价值：** 当前 `IntrospectionCache` 是每个服务器本地的 best-effort 缓存。对于 Envoy sidecar 或微服务网格部署，每个服务实例都做内省产生大量重复签名验证开销（JWT 签名验证约 200-500μs/MAC 或 1-3ms/RSA）。带签名的内省响应允许 RS 侧缓存内省结果，无需信任 RS 的缓存基础设施。

**核心挑战：**
1. **签名密钥管理**：内省签名密钥与令牌发行密钥的隔离。内省签名应该是独立的 key（或多一个 JWK 条目 `use: introspection`），防止误用发行密钥做内省签名。
2. **缓存失效窗口**：签名内省响应有明确 TTL，但令牌可能在 TTL 内被撤销。当前缓存已是 eventual-consistency，签名版本不会更糟但需要明确文档。
3. **批量端点**：Envoy sidecar 通常在一个请求中检查多个令牌（每个上游服务一个）。新增 `/token/introspect/batch` 减少连接开销。

**技术方案：**

```
端点: POST /token/introspect
扩展: 当 Accept: application/jwt 或 ?format=jwt 参数时，返回 JWT 封装的内省响应

JWT Claims:
  {
    "active": true,
    "sub": "user@example.com",
    "exp": 1719782400,
    "iat": 1719778800,
    "ttl": 300,         // 建议客户端缓存时长（秒）
    "iss": "https://as.example.com",
    "jti": "unique-native-introspect-id", // 用于撤销检测
    "cnf": { ... },     // 转发令牌的 sender-constraint
    "scope": "openid profile",
    "client_id": "client123",
  }

端点: POST /token/introspect/batch
输入: { "tokens": ["token1", "token2", ...] }
输出: { "results": [{ "token_hash": "sha256...", "response": {...} }, ...] }
```

**预期架构变更：**
- 新增：`protocols/oauth/introspect_signer.go`——内省响应 JWT 签名器
- 修改：`protocols/oauth/handle_introspect.go`——响应格式协商
- 新增：`protocols/oauth/handle_introspect_batch.go`——批量端点
- 新增：`shared/core/introspect_response.go`——签名内省响应类型
- 修改：`interfaces/sso/server_token.go`——路由注册
- 修改：`shared/security/securityverify/jwks_verify.go`——`use: introspection` JWK 验证

**对现有系统影响：** 低。签名内省是完全可选的能力——不配置签名密钥就回退到当前行为。批量端点是独立端点，不影响现有端点。

---

### 方向 D：事件驱动架构升级——CAEP / SSF 异步信号 + 集群事件总线

**业务价值：** 当前 CAEP/SSF 已支持 push-only 的 SET 发射器和接收器，但事件模型与内部集群总线（cluster.Bus）脱钩。CAEP 事件（token revocation、client change、key rotation）已经在 cluster.Bus 上有对应 `KindTokenRevoked`/`KindSigningKeyRotation`/`KindClientChange`，但这些事件的跨副本传播不会自动触发 CAEP SET 发射。统一的"内部事件 → CAEP SET 推送到订阅者"管道可以减少全量广播的延迟。

**核心挑战：**
1. **事件过滤**：CAEP 推送到受影响的 client 的接收端点（`Client.Attributes["caep_receiver_endpoint"]`）。当 token 被撤销时，只有拥有该 token 的 client 需要收到 SET。需要高效的 client→SET 事件映射。
2. **幂等性**：集群中的多个副本可能同时触发相同事件的 SET 推送。需要在 CAEP 发射器侧做 dedup。
3. **背压处理**：client 的接收端点可能不可达。当前 fail-closed 的设计需要决定：是重试队列还是丢弃并记录。

**技术方案：**

```
架构变更:
1. 新增: domains/caep/bridge.go — cluster.Bus 订阅者 → CAEP SET 发射器
2. 新增: domains/caep/queue.go — 失败重试队列（内存或 SQLite）
3. 修改: platform/cluster/events.go — 新增 CAEP-relevant 事件类型
4. 新增: config/caep.yaml — 背压策略配置

事件流:
    令牌撤销
      ↓
  cluster.Bus.Publish(KindTokenRevoked)
      ↓
  跨副本广播
      ↓
  CAEP Bridge (订阅者) — 过滤受影响的 client
      ↓
  CAEP Transmitter — 推送 SET 到 client 的接收端点
      ↓
  成功 → 记录审计
  失败 → 入重试队列 (配置 TTL + 最大重试次数)
```

**对现有系统影响：** 中。需要扩展 cluster.Bus 的事件类型集，但 bus 接口本身有良好抽象（memory/etcd），新增事件类型只影响具体消息体的编解码。CAEP 发射器已经是异步路径，不阻塞请求处理。

---

### 方向 E：FAPI 2.0 深度集成——JARM 响应签名 + PAR 必需 +  sender-constrain 强制

**业务价值：** 当前 FAPI 2.0 的集成是 Inspection/Enforce 两种模式的简单开关。生产部署通常需要更细粒度的控制——例如只对特定 client 类（金融机构）强制 PAR，对其他 client 可选。FAPI 2.0 Message Signing（JARM + DPoP）的强制执行需要更细粒度的配置模型。

**核心挑战：**
1. **粒度控制**：当前的 `WithFAPIProfile(Inspection|Enforce)` 是全局开关。需要 client 级别的 FAPI profile 覆盖，使得金融机构 client 使用 `Enforce` 而普通第三方 app 使用 `Inspection`。
2. **JARM 当前 position**：JARM 已实现但以全局开关运行。FAPI 2.0 需要特定 endpoint 的 JARM 为 mandatory。
3. **Client 认证强度**：FAPI 2.0 要求 `private_key_jwt` 或 mTLS。当前实现支持但不强制。

**技术方案：**

```
配置模型:
  - Global FAPI profile: disabled | inspection | enforce
  - Per-client override: Client.FAPIProfile 覆盖全局
  - 在 enforce 模式下:
    - 拒绝 mTLS/private_key_jwt 之外的 client_auth
    - 拒绝 PAR 未使用的 authz request
    - 拒绝 JARM 未签名的响应
    - 拒绝未绑定 DPoP/mTLS 的 token

架构变更:
  - 修改: protocols/fapi/validator.go — 考虑 client 级配置
  - 修改: shared/core/types.go — Client 新增 FAPIProfile 字段
  - 修改: protocols/oauth/handle_par.go — 按 client 检查 PAR 强制
  - 修改: protocols/oidc/jarm.go — 按 client 检查 JARM 签名
```

**对现有系统影响：** 低到中。FAPI 2.0 本质上是在现有功能上的策略层强化。所有底层原语（PAR、JARM、DPoP、mTLS、private_key_jwt）都已实现，新增的是检查/拒绝逻辑。

---

## 3. 接口设计原则

### 3.1 核心原则

| 原则 | 现有表现 | 建议增强 |
|---|---|---|
| **接口最小化** | `RiskScorer` 只有 `Score(context, *RiskRequest) (*RiskAssessment, error)` | 策略引擎接口同样保持单一方法，策略 DSL 解析在内部 |
| **Fail-Open 作为默认** | `RiskScorer` 的 error 处理是 fail-open | 所有新 SPI 默认 fail-open，要求 fail-closed 的调用方显式 opt-in |
| **无供应商锁定** | 每个接口都有 memory 实现 | 策略引擎的 memory 实现应包含基本规则引擎，使单节点部署无需外部依赖 |
| **向后兼容性** | `TokenClaims` 新字段通过 omitempty 兼容旧 token | 所有新响应字段通过 `omitempty` 或协商机制控制 |

### 3.2 新抽象层需求

**策略引擎 DSL 解析器——不需要新层，但需要新子包：**

```
domains/anomaly/
  ├── strategy/          ← 新增
  │   ├── engine.go      ∘ 策略评估引擎 (递归规则匹配)
  │   ├── engine_test.go
  │   ├── rule.go        ∘ 规则 DSL 模型
  │   ├── signal.go      ∘ 信号聚合器
  │   └── config.go      ∘ YAML 配置加载
  ├── types.go           (已有, 扩展)
  ├── runner.go          (已有)
  └── detector.go        (已有)
```

**CAEP 桥接层——`protocols/caep/bridge.go`：**

新文件，不违背现有依赖方向。`protocols/caep` 层（layer 3 protocols）可以导入 `platform/cluster`（layer 1 platform）、`shared/core`（layer 0）和 `domains/tenant`（layer 2 domains）。符合依赖方向。

**内省签名器——`protocols/oauth/introspect_signer.go`：**

符合 oauth 包的位置（layer 3 protocols），能导入 `shared/security` 完成 JWT 签名。

### 3.3 向后兼容策略

| 变更类型 | 策略 |
|---|---|
| 新端点（如 `/token/introspect/batch`） | 不影响现有端点 |
| 新可选字段（如 `Client.TokenExchangeScopePolicy`） | 零值 = 旧行为 |
| 新响应格式（如 JWT-wrapped introspection） | 通过 Accept header 或 query 参数协商 |
| 现有行为变更（如 scope 默认收缩） | 通过配置开关控制默认值，逐个 client opt-out |
| 新 SPI 方法 | 通过可选的 extension interface 模式（如 `TenantScopedClientStore`） |

---

## 4. 技术选型

### 4.1 策略引擎技术选型

| 技术 | 适用场景 | 在本项目中的评估 |
|---|---|---|
| **Rego/OPA** | 复杂的策略即代码（CICD、Kubernetes admission） | **不推荐**。引入 14MB+ 的二进制 + 外部进程，超出纯 Go 零外部依赖原则。OPA WASM 方式可能，但增加构建复杂度。 |
| **CEL** (google/cel-go) | 轻量级表达式评估，Envoy 内部策略 | **推荐**。Go 原生、无外部进程、评估快（5-15μs），Google 维护。但表达能力有限（无递归规则、有限集合操作）。适合策略引擎的表达式层。 |
| **自建 YAML 规则引擎** | 简单 if-this-then-that 规则 | 对于 V1 推荐。没有表达式语言的学习曲线，直接映射到 Go struct。缺点：规则复杂度增长后难以维护。 |
| **JsonLogic** | 纯 JSON 策略格式 | 可用于跨语言策略分发（JS、Python、Go），但 JSON 的表达能力有限。 |

**推荐 V1 路径：** 自建 YAML 规则引擎 → 若规则复杂度增长，将表达式层迁移到 CEL，保留 YAML 作为策略配置格式。

### 4.2 内省签名密钥管理

| 方案 | 优势 | 劣势 |
|---|---|---|
| 复用现有的 TokenIssuer 密钥 | 无需额外密钥管理 | 违反最小权限原则——发行密钥不应签名内省响应 |
| 独立内省签名密钥（JWK `use: introspection`） | 密钥隔离、可单独轮换 | 新增 JWK Set 端点复杂度 |
| 短期签名的 ephemeral 密钥 | 密钥自动过期 | 验证方需要时钟同步、跨副本一致性 |

**推荐：** 独立内省签名密钥。在现有 JWKS 端点扩展 `use` 字段，资源服务器按 `use=introspection` 筛选。与 token issuance 密钥分离轮换节奏。

### 4.3 批量内省的传输格式

| 格式 | 场景 | 推荐 |
|---|---|---|
| HTTP/1.1 JSON | 简单场景 | V1 实现 |
| gRPC streaming | 高吞吐 sidecar | V2 目标，通过现有 gRPC Server 扩展 |
| HTTP/2 multiplexed | Envoy ext_authz 集成 | 已存在 `/mesh/ext-authz`，批量内省可作为其补充 |

---

## 5. 实施路线图

### 优先级矩阵

| 方向 | 业务价值 | 技术复杂度 | 对其他方向依赖 | 风险 | 优先级 |
|---|---|---|---|---|---|
| **B: Token Exchange 增强** | 高 | 低 | 无 | 低 | **P0** |
| **C: 签名内省** | 高 | 中 | 无 | 中 | **P0** |
| **A: 自适应策略引擎** | 高 | 高 | 依赖 B 的 scope policy | 高 | **P1** |
| **E: FAPI 2.0 深度集成** | 中 | 中 | 无 | 低 | **P1** |
| **D: CAEP 集群集成** | 中 | 高 | 无 | 中 | **P2** |

### 阶段划分

#### 阶段 1（P0）—— Token Exchange 增强 + 签名内省

| Milestone | 交付物 | 验收条件 |
|---|---|---|
| M1.1 | TokenExchangeScopePolicy 字段 + intersect 模式 | `TokenExchangeRequest` 的 scope 测试中 `intersect` 行为通过 |
| M1.2 | act 链循环检测 | 构造的循环链返回 `invalid_grant` |
| M1.3 | may_act 审计事件 | 审计日志中出现 `EventTokenExchangeDelegation` |
| M1.4 | 签名内省 JWT 端点 | `curl -H "Accept: application/jwt" /token/introspect` 返回 JWT |
| M1.5 | 批量内省端点 | `POST /token/introspect/batch` 返回多结果 |

**风险：** 范围收缩的默认 `intersect` 可能破坏现有 exchange 链路。缓解：通过 config 控制默认值，逐个 client opt-out，在审计日志中记录 copymode 的使用。

**预算影响：** `internal/handler/tokengrant/token_exchange_stages.go` 当前约 340 行，新增 intersect 逻辑 + 循环检测 + 审计事件后可能接近 500 行，需在开发过程中注意拆分 `tikExResolveScope` 方向（`scope_policy.go`、`circulation_detector.go`）。

#### 阶段 2（P1）—— 自适应策略引擎 V1 + FAPI 2.0 深度集成

| Milestone | 交付物 |
|---|---|
| M2.1 | `domains/anomaly/strategy/engine.go` YAML 规则引擎 |
| M2.2 | anomaly.Runner 向策略引擎写信号摘要 |
| M2.3 | RiskScorer 装饰器模式——策略引擎驱动认证决策 |
| M2.4 | Client.FAPIProfile 字段 + enforce 模式 |
| M2.5 | Client 级别 PAR/JARM/DPoP 强制 |

**风险：** 策略引擎的评估延迟可能超过 50ms 预算。缓解：V1 只做简单规则（2-3 层嵌套），评估预算 < 5ms。对复杂规则做基准测试，超过阈值的规则降级为异步 advisory（不阻塞请求）。

**预算影响：** 新增 `domains/anomaly/strategy/` 包，预计初始规模 3-5 文件，每文件 < 300 行。无现有文件影响。

#### 阶段 3（P2）—— CAEP 集群集成 + 事件驱动管道

| Milestone | 交付物 |
|---|---|
| M3.1 | cluster.Bus 事件 → CAEP SET 的桥接器 |
| M3.2 | CAEP 发射重试队列（内存） |
| M3.3 | CAEP-to-client 高效映射（预防 O(n) 扫描） |

**风险：** 集群事件的重叠不重复发送语义需要 careful design。缓解：利用 CAEP SET 的 `jti` 做接收方 dedup，发射器侧不做强 exactly-once 保证。

### 分阶段测试策略

| 阶段 | 测试重点 |
|---|---|
| 阶段 1 | 行为等价测试（scope intersect 前后行为比较），循环检测的边界测试 |
| 阶段 2 | 策略评估性能基准（vs 50ms 预算），YAML 规则解析的 fuzz 测试 |
| 阶段 3 | 集群事件重复下的幂等性，CAEP 接收端点不可达的 fallback 行为 |

---

## 6. 关键决策记录

### DEC-1: TokenExchangeScopePolicy 的默认值

| 选项 | 权衡 |
|---|---|
| 默认 `intersect`（最安全） | 现有消费者可能收到 scope 变小的 token，需要明确的 communication |
| 默认 `copy`（向后兼容） | 新部署默认不安全，遗漏scope 收缩 |

**决策：** 默认 `intersect`，但提供全局配置 `oauth.token-exchange.default-scope-policy: copy` 让已存在部署能在迁移期维持旧行为。计划两版后移除全局开关，强制 `intersect`。

### DEC-2: 策略引擎的 DSL 技术栈

| 选项 | 权衡 |
|---|---|
| YAML 配置 + Go struct 映射 | V1 可行，规则复杂度到 ~20 条时难以维护 |
| CEL 表达式 | 需要引入外部依赖（google/cel-go），但评估快、表达能力更强 |
| Rego | 外部依赖过于重 |

**决策：** 分两步：V1 使用 YAML + Go struct（见上文方向 A 示例），在 `domains/anomaly/strategy/` 包中实现。若规则数超过 50 条，V2 迁移至 CEL 表达式作为规则的条件层，YAML 保留为顶层策略配置格式。

### DEC-3: 签名内省密钥管理

| 选项 | 权衡 |
|---|---|
| 复用 token issuance JWK | 密钥轮换不需要分开，更适合小规模部署 |
| 独立 introspection JWK (`use: introspection`) | 密钥隔离更好，轮换灵活。需要扩展 JWKS 端点 |

**决策：** 独立 introspection JWK。在每个 issuer 的 JWKS 响应中新增 `use: introspection` 条目，与 `use: sig`（token issuance）共存。两个密钥集独立轮换。

### DEC-4: 批量内省的传输语义

| 选项 | 权衡 |
|---|---|
| `active` 不活跃的 token 在 batch 中返回完整 `{"active":false}` | 保持与单端点一致，但 batch 的 body 大小增加 |
| `active` 不活跃的 token 在 batch 中仅返回 token_hash + `{"active":false}` | 减少带宽，但破坏与单端点的一致性 |

**决策：** 保持一致性——batch 中每个 token 的响应体与单端点 `?verbose=false` 时输出一致。沉默的 `{"active":false}` 不泄露额外信息（没有 `sub`/`scope`/`exp`），因此无 oracle 泄漏风险。

---

## 附录 A：预算预估

| 文件 | 当前行数 | 阶段 1 增量 | 阶段 1 后行数 | 拆分建议 |
|---|---|---|---|---|
| `internal/handler/tokengrant/token_exchange_stages.go` | ~340 | +80 | ~420 | 安全（< 500） |
| `protocols/oauth/handle_introspect.go` | ~260 | +120 (signed + batch) | ~380 | 安全 |
| `protocols/oauth/introspect_cache.go` | ~35 | — | — | 可扩展签名内省 |
| `shared/core/types_token.go` | ~180 | +20 (scope policy) | ~200 | 安全 |
| `domains/anomaly/types.go` | ~120 | +50 (策略 DSL 类型) | ~170 | 安全 |

无文件在阶段 1 中超出 500 行预算。

## 附录 B：依赖关系检查

```
方向 B（Token Exchange 增强）:
  internal/handler/tokengrant/ → protocols/oauth/ (已有) ✓
  internal/handler/tokengrant/ → shared/core/ (已有) ✓
  internal/handler/tokengrant/ → platform/audit/ (已有) ✓

方向 C（签名内省）:
  protocols/oauth/ → shared/security/ (已有) ✓
  protocols/oauth/ → shared/core/ (已有) ✓

方向 A（策略引擎）:
  domains/anomaly/strategy/ → domains/anomaly/ (同层) ✓
  domains/anomaly/strategy/ → shared/core/ (层 0) ✓
  domains/anomaly/strategy/ → shared/spi/ (层 0) ✓
  domains/anomaly/ → DNE → platform/ (层 1) ✓

方向 D（CAEP 集成）:
  protocols/caep/ → platform/cluster/ (3→1 ✓)
  protocols/caep/ → shared/core/ (3→0 ✓)
  protocols/caep/ → domains/tenant/ (3→2 ✓)
```

无依赖方向违规。
