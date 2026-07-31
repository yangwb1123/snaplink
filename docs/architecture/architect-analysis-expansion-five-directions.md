# 架构分析：五个扩展方向评估与建议

> **分析师：** 架构师代理  
> **依据：** `docs/requirements/architect-expansion-five-directions-2026-07-11.out.md`（评估报告）  
> **日期：** 2026-07-11

---

## 1. 架构评估

### 1.1 当前架构的优势

Snaplink 的架构在开源身份平台中已达到 **行业顶级水平**，核心优势如下：

| 维度 | 现状 | 评价 |
|---|---|---|
| **层隔离** | 六层架构（shared → platform → domains → protocols → interfaces → infrastructure），由 `architecture_layer_test.go` 强制逆向引用检测 | 优于 Keycloak（模块间耦合松散）、优于 Ory Hydra（无显式层契约） |
| **接口优先** | 每个 SPI 都有 memory impl + 可选 SQLite/etcd/Redis/Kafka 后端 | 测试无需 mock，覆盖率高 |
| **维护预算** | 文件 ≤ 500 行、函数 ≤ 50 行、圈复杂度 ≤ 15、目录深度 ≤ 3，由 committed gate 测试严格 enforce | 业界罕见——多数项目在 1000+ 行文件后才开始重构 |
| **安全纵深** | DPoP、mTLS、PKCE、private_key_jwt、FAPI 2.0、anti-enumeration、oracle-leak 防护 | 经过系统性威胁建模 |
| **协议覆盖** | OAuth 2.0 全 grant、OIDC Core + 登出 + 发现、SAML、SCIM、CAEP/SSF、OpenID Federation | 在开源 SSO 中覆盖面最广 |
| **正式工程系统** | AGENTS.md、HARNESS.md、EVALUATION.md、CHECKS_REGISTRY.md | 自动化质量门禁，可证明的正确性 |

### 1.2 当前架构的局限性

这些不是"错误"，而是架构自然演进到高成熟度后才暴露的**集成缝隙**——组件已存在但未连通的路径：

#### 局部性 1：Session Hub 只写不读

`platform/lifecycle/sessionhub/` 是一个设计优雅的跨协议会话协调器，在登录路径上正确写入 `global_sid` 绑定。但**所有登出路径**（OIDC end_session、logout、revoke-all、lifecyclereactions）均不调用 `sessionHub.Logout()`，导致：

- OIDC 登出不终止 SAML 会话
- SAML SLO 不通知 OIDC RP
- revoke-all 只清 OAuth token，遗留 SAML 会话

这是典型的**建了桥但没有把路接到桥上**——架构债务不是缺少组件，而是组件之间缺少调用边。

#### 局部性 2：五种授权模型并行运行却互不知晓

| 模型 | 评估 | 位置 |
|---|---|---|
| Trust Scoring | 写入 `AccessContext.TrustScore` | shared/trust |
| Conditional Access | allow/deny/step-up | domains/conditionalaccess |
| RBAC | 细粒度权限 | domains/permissions |
| ReBAC | 对象级授权 | platform/lifecycle/rebac |
| WASM Authz | 自定义策略 | platform/lifecycle/wasmauthz |

运行时各自独立评估，从不组合成一条决策管道。合规审计需要翻查 3-4 个不同的日志才能回答"为什么这个请求被放行"。

#### 局部性 3：Fuzzing 覆盖单步函数，不覆盖多步状态机

9 个 fuzz target 全部是单输入→单函数解析。OAuth/OIDC 协议的安全风险核心在**多步状态机的时序和交错**（TOCTOU、step-skip、race condition），这些需要 stateful multi-step fuzzing。

#### 局部性 4：配置验证缺少依赖检查 + 自动回滚

`config validate` 做 schema 验证但不做依赖完整性检查（如"启用 FAPI 但未配置 JARM signer"），变更后无健康门禁回滚。

#### 局部性 5：SSO 集成仅限 Go 程序或 Envoy sidecar

`ssoclient/rs` 是 Go library 而非独立二进制。非 Go 服务只能通过远程 `/mesh/ext-authz` 调用，带来延迟 + SSO 实例瓶颈。

### 1.3 关键设计决策的合理性评估

| 决策 | 评估 |
|---|---|
| 六层依赖方向（shared → ... → interfaces） | ✅ 正确。已阻止大量循环依赖 |
| 纯函数在 domain 包 + 薄 Server 包装器 | ✅ 正确。可测试性高，与 HTTP 层解耦 |
| `DELETE RETURNING` 防 read-then-delete 竞态 | ✅ 正确。但仅在 SQL 后端有效——Memory 后端需等效原子操作 |
| 审计 `SetMeta` 禁止直接 map 赋值 | ✅ 正确。防止高基数标签膨胀 |
| Fail-open vs fail-closed 的策略 | ✅ 大部分合理。refresh rotation fail-closed 是正确的（高危操作） |
| 总线（Bus）架构用于跨副本通信 | ✅ 正确。但当前是单区域总线，未做跨区域扩展 |
| 密码学算法白名单（无 `alg=none`） | ✅ 正确。NIST/BSI 合规 |

### 1.4 架构债务总结

| 债务 | 严重程度 | 修复路径 |
|---|---|---|
| Session Hub 只写不读 | 中 | 在 end_session、revoke-all、lifecyclereactions 添加 `sessionHub.Logout()` |
| 授权模型无决策管道 | 中 | 定义 `AuthzPipeline` SPI + 渐进集成各模型 |
| 配置变更无自动回滚 | 低-中 | `SIGHUP` 重载前备份 + 健康观察窗 + 自动 reload |
| 跨区域扩展准备度 | 低 | `cluster.Bus` 扩展为区域感知 + 存储层分类 |
| 非 Go 服务集成路径单一 | 低 | Edge Token Proxy（独立二进制） |

---

## 2. 扩展方向

以下列出 5 个高价值的架构扩展方向，按战略价值从高到低排列。我基于评估报告的新颖性分析和技术深度评价进行了独立判断，不简单复述原文方向。

### 方向 A：授权决策管道（Authz Decision Pipeline）

> **Why now：** 五种授权模型各自成熟，差异化的下一步不是添加第六种模型，而是将它们编排成一条统一的决策管道。

#### 业务/技术价值

- **合规可审计**：单一 `decision_id` 串联所有层级的 verdict，审计日志可直接回答"为什么放行/拒绝"
- **策略叠加**：条件访问的结果可以影响 RBAC 的生效范围（如信任分 ≤ 0.3 时即使 RBAC 放行也触发 step-up）
- **Dry-run 评估**：新策略上线前可以模拟对真实流量的影响，避免"先推后发现问题"

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| 各模型的 verdict 语义不一致 | ★★★ | Trust 输出 `[0,1]` 分数，CA 输出 allow/deny/step-up，RBAC 输出 allow/deny，ReBAC 输出 allow/deny/referral——需要统一的 Verdict 类型 |
| 性能预算 | ★★ | 管道总超时 ≤ 100ms，每层有独立超时和降级策略 |
| 单调安全原则 | ★★★ | 每层只能增加限制（deny/step-up），不能放行上游拒绝的请求。但 TrustScore 的"高信任"可以 override ReBAC 的 deny？需要仔细的安全建模 |
| 现有单模型不受影响 | ★ | 不配置管道时行为不变——要求管道是 opt-in 的 middleware 而非硬编码 |

#### 预期架构变更

```
当前:
  handler → 单模型检查 → 响应

变更后:
  handler → AuthzPipeline.Evaluate(ctx, request) →
    [Trust → CA → RBAC → ReBAC → WASM] →
    AuthzDecision{decision_id, per_layer_verdicts[], final_verdict, reason_chain}
```

- 新增：`domains/authorization/pipeline/` 包（`AuthzPipeline` SPI + 默认实现）
- 修改：`interfaces/sso/` 中的 handler 路径，添加可选的 pipeline 中间件
- 修改：审计记录追加 `decision_id` 字段
- 不修改：各模型内部逻辑（它们各自仍是独立 SPI）

#### 对现有系统的影响

- **低侵入**：pipeline 是 optional middleware，不配置时行为零变化
- **新接触面**：需要为每个模型定义 `Verdict` 类型转换器
- **不破坏**：现有单模型授权路径完全保留

---

### 方向 B：跨协议会话登出协调（Session Hub Consumption）

> **Why now：** Session Hub 是已投入建设的跨协议会话协调器，但登出路径全部绕过了它。在 Session Hub 上修调用边比新建协调器成本低一个数量级。

#### 业务/技术价值

- **安全完整性**：用户在一个协议登出时，其他协议的会话被正确终止（OIDC logout → 终止 SAML session → 触发 SP SLO）
- **合规需求**：GDPR 的"数据主体权利"要求全协议登出——说"我登出了"但 SAML 会话仍活跃有合规风险
- **高 ROI**：Session Hub 基础设施已存在，只需要在 3-4 个登出路径上添加调用

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| Session Hub 数据丢失的降级 | ★ | Session Hub 不可用时降级为"只登出当前协议"，不阻塞登出流程 |
| SAML SLO 部分 SP 超时 | ★★ | 沿用 BCL 的超时模式——单个 SP 超时不阻塞整体登出 |
| OIDC BCL 与 SAML SLO 的时序 | ★ | 先触发 BCL（异步），再触发 SLO（同步），或反之？建议并行触发，各自独立超时 |
| revoke-all 与 Session Hub 的原子性 | ★★ | revoke-all 当前是批量操作，需要确保如果 Session Hub 调用失败，已撤销的 token 不回滚 |

#### 预期架构变更

```
当前登出路径:
  handler → 撤销当前协议 token → 响应

变更后:
  handler → 撤销当前协议 token →
    sessionHub.Logout(ctx, globalSID) →
      [BCL fan-out | SAML SLO fan-out | Core session destroy] →
    响应
```

- 修改：`server_logout.go`、`server_end_session.go`、`server_revoke_all.go`、`lifecyclereactions.go` 添加 `sessionHub.Logout()` 调用
- 新增：`sessionHub.Logout()` 方法的 SAML SLO 触发逻辑（复用 `saml/sp/slo.go`）
- 新增：审计事件增加 `global_sid` 字段
- 新增：指标 `sso_session_hub_logouts_total{protocol}`

#### 对现有系统的影响

- **极低侵入**：仅添加调用边，不修改 Session Hub 内部
- **SAML SLO 触发**：需要从 `globalSID` 反向查出有哪些 SAML SP 会话——这需要 Session Hub 当前是否存储了 SP 列表？如果否，需要扩展 Session Hub 的数据模型
- **无停机风险**：Session Hub 调用失败时降级，行为等同于今天

---

### 方向 C：独立可部署 Edge Token Proxy

> **Why now：** 评估报告确认此方向是 64 份分析中唯一完全新颖的方向。非 Go 服务的 SSO 集成是现实的产品缺口。

#### 业务/技术价值

- **消除语言绑定障碍**：Python/Node/Java/.NET/Rust 服务通过本地 proxy 验证 token，无需远程调用 SSO
- **降低 SSO 实例负载**：token 验证本地完成，introspect 调用从每个请求减少到缓存 miss 时
- **提升可用性**：proxy 本地缓存 JWKS + 决策结果，上游 SSO 短暂不可用时仍可继续服务

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| JWKS 缓存与时序 | ★★★ | 上游密钥轮换 → proxy 缓存旧 JWKS → 短暂验证通过已撤销 token。需要 TTL 被动失效 + Bus 主动失效 |
| DPoP nonce 管理 | ★★★ | 评估报告指出原文方案有设计缺陷：proxy 传递上游 nonce 会引入耦合。正确方案：proxy 自主管理 nonce 空间，DPoP proof 绑定到 proxy 而非上游 |
| introspect 缓存中毒 | ★★ | 上游撤销 token → proxy 仍缓存 active。解决方案：短 TTL（15-30s）+ Bus 订阅 |
| 声明转换的正确性 | ★★ | 路由级别的 claim 映射需要安全审计——不能错误暴露敏感 claim |

#### 预期架构变更

```
部署拓扑（新增独立 Go 模块）:

  服务 → Edge Token Proxy（localhost:9080）→ 上游 SSO
              │
              ├─ 本地 JWKS 缓存
              ├─ 本地 introspect 缓存
              ├─ DPoP nonce 管理
              └─ claim 转换规则
```

- 新增：`cmd/sso-token-proxy/` — 独立可部署的 Go 二进制
- 新增：`protocols/tokenproxy/` — proxy 核心逻辑（验证管道 + 缓存 + 转换）
- 复用：`interfaces/ssoclient/rs/` 的验证逻辑（JWT 验证、DPoP 验证、mTLS 验证）
- 复用：`platform/cluster/` 的 Bus 客户端（JWKS 失效订阅）
- 配置：YAML 配置（路由规则、缓存 TTL、scope 映射）+ SIGHUP 热重载

#### 对现有系统的影响

- **无侵入**：独立模块，不修改核心 SSO
- **验证逻辑同步**：通过与 SSO 共用同一验证代码路径（`ssoclient/rs`），防止 drift
- **DPoP nonce 独立管理**：proxy 维护自己的 nonce 空间，通过 `WWW-Authenticate: DPoP nonce="..."` 与客户端交互，nonce 不传递到上游

---

### 方向 D：状态协议 Fuzzing 框架

> **Why now：** 9 个 stateless fuzz targets 已覆盖单步函数。OAuth 协议的安全风险核心在多步状态机——这正是当前盲区。

#### 业务/技术价值

- **发现协议层安全 bug**：多步状态机 bug（TOCTOU、step-skip、state confusion、race condition）是 OAuth 实现最高危漏洞类别
- **低成本高回报**：~1500 行建模 + 引擎代码，复用现有 chaos test 的 httptest wiring
- **差异化**：目前无主流 OAuth 项目做系统化 stateful fuzzing

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| Fuzzer Oracle 问题 | ★★★ | 评估报告指出原文方向一的最大缺口——"fuzzer oracle 问题未讨论"。判断一个随机状态序列是否产生安全漏洞需要精确定义的 oracle（不变量），而非简单地"没 panic" |
| 状态空间爆炸 | ★★ | 6 步序列 × 10+ grant 类型 × 状态组合 = 海量序列。需要修剪启发式规则 |
| 并发交织注入 | ★★★ | 在 store write、token issue 等关键点注入延迟以暴露竞态，需要 hook 框架 |
| 跨用户/跨客户端混淆检测 | ★★★ | oracle 需要能够区分"同一个 token 被两个用户使用"和"同一个用户使用两次" |

#### 预期架构变更

```
新增文件结构:

test/fuzz/stateful/
├── fsm/              # 状态机定义（每 grant 一个 FSM）
│   ├── authcode.go
│   ├── device.go
│   ├── ciba.go
│   ├── par.go
│   └── refresh.go
├── engine.go         # fuzzer 引擎（随机序列生成 + 回放）
├── oracle.go         # 不变量断言库
├── hook.go           # 并发延迟注入点
└── fuzz_test.go      # go test -fuzz 入口
```

- 新增：`test/fuzz/stateful/` 目录（独立 fuzz 包，不引入生产依赖）
- 复用：`test/chaos/` 的 `httptest.Server` + `*sso.Server` 构造模式
- 新增：不变量断言库（`revoked → active:false`、`consumed → 400`、`family_killed → invalid_grant`）

#### 对现有系统的影响

- **无侵入**：独立测试目录，不修改核心代码
- **CI 集成**：nightly CI 运行（`-fuzz=^FuzzProtocolStateMachine$ -fuzztime=30m`）
- **扩展成本低**：新增 grant 只需添加 FSM 定义

---

### 方向 E：硬件设备 Attestation 验证管道

> **Why now：** WebAuthn attestation policy 框架已存在但只做信任锚检查，未解析 attestation statement 提取设备身份。TPM/Android/Apple attestation 是对 WebAuthn 的自然扩展。

#### 业务/技术价值

- **高安全需求匹配**：金融/医疗/政府客户的"设备合规"采购要求
- **条件访问增强**：设备 attestation 等级作为条件访问的一个高权重信号
- **竞争优势**：主流 OAuth 服务器（Auth0/Okta/Keycloak）均无端到端硬件 attestation

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| 各平台 attestation 格式差异大 | ★★★ | Android KeyStore 使用 certificate chain、Apple App Attest 使用 JSON + signature、TPM 使用 TPM2B_ATTEST + PCR quote、WebAuthn 使用 CBOR——需要统一的 AttestationVerifier SPI |
| MDS 3.0 feed 集成复杂度 | ★★★ | 评估报告指出原文方向五低估了 MDS 3.0 feed 集成复杂度。MDS 3.0 是 FIDO Alliance 的 metadata 服务，包含所有认证器的信任锚、安全等级、撤销状态——需要定期同步 + 缓存 + 增量更新 |
| 隐私保护 | ★★ | 设备唯一标识（AIK、序列号）需要盐值哈希存储，防止跨服务追踪 |
| 降级攻击预防 | ★★ | 策略引擎应该对缺少 attestation 的 session 降低信任，而非只对有 attestation 的提升 |

#### 预期架构变更

```
新增:

shared/deviceattest/
├── verifier.go           # AttestationVerifier SPI
├── androidkey/           # Android KeyStore attestation
├── appleattest/          # Apple App Attest
├── tpm/                  # TPM 2.0 attestation
├── webauthnatstn/        # WebAuthn packed/tpm/android attestation
├── mds/                  # MDS 3.0 feed 同步器
└── truststore.go         # 信任锚管理

修改:
  domains/authenticators/webauthn/attestation_policy.go
    → 扩展为使用 AttestationVerifier SPI
```

- 新增：`shared/deviceattest/` 包（Attestation Verifier SPI + 各平台实现）
- 修改：`domains/authenticators/webauthn/` 扩展 attestation pipeline
- 修改：Session 模型添加 `device_attestation` claim
- 修改：条件访问策略引擎添加 `require_attested_device` 规则
- 新增：Admin API 设备管理端点（`GET /admin/users/:id/devices`、`POST /admin/devices/revoke`）

#### 对现有系统的影响

- **中侵入**：修改 Session 数据模型 + 条件访问策略引擎
- **向外依赖**：MDS 3.0 feed 需要 HTTP 外出请求——需要配置 proxy 和区域
- **存储增长**：设备 attestation 记录持久化
- **安全审计**：新的 attestation 验证失败事件需要审计

---

## 3. 接口设计建议

### 3.1 核心 SPI 设计原则

基于现有架构的经验教训，新 SPI 应遵循以下原则：

| 原则 | 说明 | 示例 |
|---|---|---|
| **单一 Verdict 类型** | 所有授权/评估模型返回统一 `Verdict` 类型，而非原始分数 | `Verdict{Action: Allow|Deny|StepUp|Indeterminate, Reason: string, Confidence: float64}` |
| **Context Propagation** | 使用 `context.Context` 传递决策 ID、父级 verdict、trace 元数据 | `decisionID` 在 `ctx` 中一路传递 |
| **Fail-Open 可配置** | 每个 SPI 方法接受一个 `FallbackPolicy` 参数（fail-open / fail-closed） | `FallbackPolicy(FailOpen|FailClosed)` |
| **Opt-In 而非硬编码** | 新功能默认关闭（no-op），通过配置显式启用 | `WithAuthzPipeline()` / `WithTokenProxy()` |
| **Observability 注入** | SPI 方法的最后一步是写入 metrics + audit，而非由调用方做 | `Verdict` 结构体包含 `MetricsLabels` 字段 |

### 3.2 是否需要新的抽象层

#### 需要：授权决策管道层

当前 5 种授权模型位于不同层（shared/trust → domains/conditionalaccess → domains/permissions → platform/lifecycle/rebac → platform/lifecycle/wasmauthz），需要在它们之上新增一个**管道编排层**：

```
domains/authorization/pipeline/     # 新增层
  ├── pipeline.go                   # AuthzPipeline SPI
  ├── step.go                       # PipelineStep 接口（每个模型包装为一个 Step）
  ├── verdict.go                    # 统一 Verdict 类型
  ├── builder.go                    # Pipeline 构造器（配置步骤顺序 + 超时 + 降级策略）
  └── middleware.go                 # HTTP/gRPC middleware 包装器
```

位置：放在 `domains/authorization/` 下（"domain"层，因为它编排业务能力）。

#### 不需要：额外的"基础设施"抽象层

Edge Token Proxy、状态 Fuzzing、硬件 Attestation 各自是独立模块，不需要新的水平抽象层。它们各自复用现有抽象：

- Token Proxy：复用 `ssoclient/rs` 的验证 SPI
- Stateful Fuzzing：复用 `test/chaos` 的 Server 构造模式
- Device Attestation：扩展 WebAuthn 的 `attestation_policy.go` 框架

### 3.3 向后兼容性策略

| 扩展 | 兼容性策略 |
|---|---|
| 授权决策管道 | 默认不启用（空 pipeline = 原行为），配置启用后仍保持各模型独立可调用 |
| Session Hub 登出调用 | Session Hub 不可用或未配置时降级为原行为 |
| Edge Token Proxy | 不修改 SSO 核心 API，只新增独立模块 |
| 状态 Fuzzing | 独立测试目录，不修改生产代码 |
| 硬件 Attestation | 新的 verifier 是可选扩展；现有 WebAuthn 用户不受影响 |

---

## 4. 技术选型

### 4.1 需要引入的新技术栈

| 方向 | 新依赖 | 评估 |
|---|---|---|
| 授权决策管道 | **无** | 纯 Go 编排逻辑，不需要第三方决策引擎 |
| Edge Token Proxy | **无** | 纯 Go HTTP server，复用现有验证库 |
| 状态 Fuzzing | **无** | 使用标准库 `testing.F` + `httptest.Server` |
| 硬件 Attestation | **可能有** | TPM 需要 `go-tpm` 库；Android/Apple WebAuthn attestation 可能依赖特定解析库 |
| Session Hub 登出 | **无** | 纯调用边添加 |

**关键判断：** 五个方向中，四个方向不需要引入任何新的第三方运行时依赖。硬件 Attestation 方向可能需要：

- `github.com/google/go-tpm`（TPM 2.0 通信）——成熟库，Apache 2.0
- Android KeyStore attestation 验证——纯加密验证，可用 `crypto/x509` 标准库（但 cert chain 解析需要验证 extended key usage）
- Apple App Attest——HTTP API 调用（不直接调用 Apple 硬件），服务端只需验证签名

### 4.2 第三方依赖评估标准

对新依赖引入的门禁标准（应补充到 CHECKS_REGISTRY.md）：

| 标准 | 阈值 | 原因 |
|---|---|---|
| 许可证兼容性 | 仅 MIT / Apache 2.0 / BSD | GPL/AGPL 污染现有 Apache 2.0 项目 |
| 活跃维护 | 最近 12 个月内有 commit | 安全库必须及时响应 CVE |
| CGO 需求 | ❌ 拒绝 | 项目核心原则：Pure Go（纯 Go），不引入 CGO |
| 传递依赖大小 | ≤ 5 个新的传递模块 | 防止依赖膨胀 |
| 测试覆盖率 | ≥ 70%（库自身的测试） | 信任库质量的外部信号 |
| 替代方案评估 | 必须提供"自建 vs 引入"的书面权衡 | 防止"先加再想" |

### 4.3 自建 vs 引入的决策框架

| 方向 | 判断 | 理由 |
|---|---|---|
| **授权管道编排** | ✅ 自建 | 纯编排逻辑，无成熟库；现有模型有自定义接口，适配外部引擎的成本 > 自建 |
| **Edge Token Proxy** | ✅ 自建 | Ory Oathkeeper 和 Pomerium 存在但过重——本项目需要轻量级、与 SSO 紧密集成的 proxy |
| **TPM 通信** | ⚠️ 引入 go-tpm | TPM 命令规范复杂，自建等价于重新实现 TCG 规范，不经济 |
| **MDS 3.0 同步** | ⚠️ 引入 + 封装 | FIDO Alliance 有参考实现，但 Go 生态缺少维护良好的 MDS 客户端——可能需要封装轻量级 HTTP 同步器 |
| **状态 Fuzzing** | ✅ 自建 | 核心是 OAuth FSM 定义，无通用库 |
| **Session Hub 登出** | ✅ 自建 | 纯调用边添加 |

**核心原则：** 当依赖是"协议/硬件通信层"时考虑引入现有库；当依赖是"业务编排"时自建。

---

## 5. 实施路线图

### 5.1 优先级排序

```
P0 (立即)  → 高价值 / 低风险 / 零侵入
P1 (短期)  → 高价值 / 中风险 / 有侵入但可控
P2 (中期)  → 中高价值 / 中高风险 / 影响面较大
P3 (远期)  → 高价值 / 高风险 / 需要前置条件
```

| 优先级 | 方向 | 价值 | 风险 | 架构侵入 | 预估工作量 |
|---|---|---|---|---|---|
| **P0** | 方向 D：状态协议 Fuzzing | ★★★★ | ★ | 无侵入 | ~1500 行 |
| **P0** | 方向 B：Session Hub 登出协调 | ★★★★ | ★ | 低侵入 | ~800 行 |
| **P1** | 方向 C：Edge Token Proxy | ★★★★ | ★★ | 无侵入 | ~3000 行 |
| **P1** | 方向 A：授权决策管道 | ★★★★★ | ★★★ | 中侵入 | ~4000 行 |
| **P2** | 方向 E：硬件设备 Attestation | ★★★★ | ★★★ | 中侵入 | ~4000 行 |

**关键区别：** 与原文优先级（Fuzzing > Proxy > Federation > Active-Active > Attestation）相比，我降级了 Active-Active（与 20 份现有分析重叠、投入最大），提升了 Session Hub 登出（最高 ROI——已建基础设施只差调用边）。

### 5.2 阶段划分

#### 阶段 1：基础设施补齐（2-3 周）

| 里程碑 | 交付物 | 依赖 |
|---|---|---|
| 1a | **状态 Fuzzing 框架**：第一个 FSM（auth code flow）+ 引擎 + oracle 断言库 | 无 |
| 1b | **Session Hub 登出**：end_session + revoke-all + lifecyclereactions 三处调用 | 无 |

**风险点：** 无。两个方向零架构侵入，独立推进。

#### 阶段 2：产品能力扩展（4-6 周）

| 里程碑 | 交付物 | 依赖 |
|---|---|---|
| 2a | **Edge Token Proxy** MVP：JWT 验证 + DPoP + JWKS 缓存 + introspect 回退 | 阶段 1 完成 | 2b | **授权决策管道 Meta-SPI**：定义了 Verdict、PipelineStep 接口、builder、middleware，集成 Trust + CA + RBAC 三层 | 阶段 1 完成 |
| 2c | 决策管道 Dry-Run 模式 | 2b 完成 |

**风险点：**
- Token Proxy 的 DPoP nonce 自主管理模式需要设计评审——这是原文评估报告指出的设计缺陷修复点
- 决策管道的单调安全原则需要安全团队 review

#### 阶段 3：高级能力（6-8 周）

| 里程碑 | 交付物 | 依赖 |
|---|---|---|
| 3a | **硬件 Attestation**：AttestationVerifier SPI + Android KeyStore 验证 + TPM 验证 | 无（但与条件访问集成需要阶段 2） |
| 3b | 决策管道集成 ReBAC + WASM | 阶段 2b 完成 |
| 3c | Token Proxy 生产化（Prometheus metrics、健康检查、热重载） | 阶段 2a 完成 |

**风险点：**
- Attestation 的 MDS 3.0 feed 集成复杂度被低估的风险——需要预留 spike time
- TPM 验证在 CI 中无法测试（无 TPM 硬件）

#### 阶段 4：深化与整合（持续）

- Fuzzing 扩展到 device code、CIBA、PAR+JAR 交错场景
- Token Proxy 扩展到 mTLS 证书验证
- 授权管道扩展到 WASM dry-run 模式
- Attestation 扩展到 Apple App Attest + WebAuthn MDS

### 5.3 风险矩阵

| 风险 | 概率 | 影响 | 缓解策略 |
|---|---|---|---|
| 状态 Fuzzing 的 oracle 定义不完整导致 false positive | 中 | 低 | oracle 库先覆盖最确定的不变量（revoked→active:false），逐步扩展 |
| DPoP nonce 独立管理导致客户端兼容性问题 | 中 | 中 | proxy 发送 `WWW-Authenticate: DPoP` 响应头，标准 OAuth 客户端已支持 |
| MDS 3.0 feed 集成复杂度超预期 | 高 | 中 | 预留 1 周 spike，第一版只支持静态信任锚列表，MDS 同步列为 v2 |
| 授权管道引入过高的性能开销 | 低 | 高 | 每层独立超时 + 可降级；benchmark 在 GA 前必须 < 5% 的延迟增加 |
| Session Hub 的数据模型不包含 SAML SP 列表 | 中 | 中 | 如果当前 Hub 不存储 SP 映射，需要扩展数据模型——与存储层团队协调 |
| TPM 验证无硬件测试覆盖 | 高 | 低 | 使用软件 TPM 模拟器（swtpm）+ 抽象 TPM 接口，CI 运行于模拟器 |
| 授权管的单调安全原则争议 | 中 | 中 | 先实现"每层只能增加限制"的保守模式，高信任覆盖作为可选配置 |

### 5.4 依赖关系图

```
阶段 1                   阶段 2                   阶段 3
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Fuzzing 框架    │    │  Edge Token Proxy│    │  Attestation SPI│
│  (无依赖)         │    │  (依赖: rs + bus) │    │  (无依赖)         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
┌─────────────────┐    ┌─────────────────┐            ├── 集成条件访问
│  Session Hub 登出 │    │  授权管道 Meta-SPI│ ←──────────┘
│  (无依赖)         │    │  (依赖: 审计增强) │
└─────────────────┘    └─────────────────┘
                              │
                              ├── 集成 Trust + CA + RBAC (阶段2)
                              └── 集成 ReBAC + WASM (阶段3)
```

---

## 附录：与原文评估报告的分歧说明

| 评估报告结论 | 本分析立场 | 理由 |
|---|---|---|
| 原文方向四（Active-Active）高度重叠，不应优先 | **赞同** | 与 20 份现有分析重叠；投入最大（~5000 行），性价比不如其他方向 |
| 原文方向三（Workload Federation）部分重叠 | **赞同但保留空间** | 与现有分析有重叠，B2B cross-org 角度有增量价值；但放在 P2 而非 P1 |
| 原文方向二（Token Proxy）DPoP nonce 设计缺陷 | **赞同并升级为关键风险** | 需要在阶段 2 启动前完成 DPoP nonce 独立管理的设计评审 |
| 原文方向一（Fuzzing）缺少 fuzzer oracle 讨论 | **赞同并补充 oracle 设计** | 在方向 D 的核心挑战中作为第一风险列出 |
| 原文方向五（Attestation）低估 MDS 3.0 复杂度 | **赞同并设风险缓解** | MDS 3.0 列在风险矩阵中，阶段 3 第一版只做静态信任锚 |
| 评估报告未提及 Session Hub 登出协调 | **新增为方向 B** | 这是最高 ROI 的架构补充——已建基础设施只缺调用边 |
| 评估报告未提及授权决策管道 | **新增为方向 A** | 这是 3 份独立分析（deep-gaps 方向二 + 本分析 + fresh-scan）共同指向的架构缺口 |
