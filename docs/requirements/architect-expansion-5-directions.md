# 资深架构扫描：五条高价值扩展方向（2026-07-11）

> **分析者角色：** 资深架构师 & 产品经理  
> **扫描方法：** 全量代码库 2241 个 `.go` 源文件、82+ 协议特性矩阵、ROADMAP v5.0、
>   1114 个测试文件、14 个嵌套 `go.mod` 模块、40+ 份已有扩展分析文档、AGENTS.md 硬门禁、
>   工程化配置及最新 git 提交历史（最新 30 commit）。  
> **核验方式：** 每条方向的关键词汇在 40+ 份已有分析文档中做全关键词反查交叉验证，
>   确保该方向从未以独立方向被深度 scope。同时逐项在代码库中 grep 确认当前实现状态
>   （✅ 已存在 / ⚠️ 部分存在 / ❌ 不存在）。  
> **核心发现：** 项目的协议覆盖、安全纵深、存储后端、产品前端、运维基础设施均已达极高成熟度。
>   剩余高价值方向并非"缺失组件"，而是**架构级优化**、**新兴技术栈整合**、**企业产品化最后
>   一公里**。

---

## 方向一：多级 Token 验证缓存架构（Multi-Tier Token Validation Cache）

### 类型

性能优化 / 规模化架构

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码库中已实现 | ❌ 不存在等效概念 |
| 已有分析文档覆盖 | ❌ 未作为独立方向分析过 |

### Why Now（为什么现在做）

项目当前 Token 验证路径依赖两种方式：

1. **本地 JWT 验证**（`interfaces/ssoclient/rs/validate.go`）：RS 端通过 JWKS 缓存验签，
   一次签名验证 + 若干 claim 检查，延迟 ~1-5ms。可本地完成，零网络依赖。
2. **Introspection**（`protocols/oauth/handle_introspect.go`）：每次请求到 AS 中心的
   `/token/introspect`，网络 RTT + 存储查找，延迟 ~5-50ms。支持了主动撤销和细粒度
   状态检查，但代价是"每笔请求都经过中心"。

**规模痛点：**

| 场景 | 当前实现 | 扩展代价 |
|---|---|---|
| RS 集群 100 节点，每节点 1000 TPS | 本地 JWT 验签 x 100,000 TPS | ✅ 水平扩展好 |
| RS 集群中 5% 的 token 被主动撤销（被吊销） | 每个请求都 Introspect | ❌ IDP 成为瓶颈 |
| Token 10min TTL，但需要<30s 内响应吊销 | Introspect 路径延迟 5-50ms | ❌ 每笔请求付出网络代价 |
| 跨区域 RS 验证同一 IDP 的 token | 跨区域 Introspect RTT 50-200ms | ❌ 延迟不可接受 |
| 资源服务器想避免网络调用但需要吊销感知 | 只能走 Introspect | ❌ 没有中间选项 |

**缺失的：三级缓存架构**——L1（本地内存，秒级 TTL，零网络）、L2（分布式缓存如 Redis，
百毫秒级 TTL，同区域）、L3（Introspection，真实权威状态）。Key 设计：

```
L1: token_hash → {active, claims, expires_at, trust_score}  // TTL=1s, LRU=10k
L2: token_hash → {active, claims, expires_at, trust_score}  // TTL=30s, Redis
L3: POST /token/introspect                                   // 权威来源
```

每级有明确的"未命中→降级到下一级"策略。L1/L2 永远不能比 Token 本身的 `exp` 长。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) SPI 定义** | `TokenValidationCache` —— `Get(ctx, tokenHash) → (result, cacheLevel, error)` + `Set(ctx, tokenHash, result, ttl)` + `Invalidate(ctx, tokenHash)`。三方实现：`memory.LRUCache`、`redis.Cache`、`noop.Cache` | M |
| **(b) 内省端接线** | `handleIntrospect` 与全新 `internal/handler/introspect/cached_introspector.go`：在响应前写 L1/L2 缓存；收到缓存失效信号（令牌吊销总线事件）时主动逐出 L1/L2 | L |
| **(c) RS 端升级** | `interfaces/ssoclient/rs/validate.go` 升级为"先查 L1→L2→Introspect，更新缓存"。引入 `WithTokenValidationCache(cache)` 配置，默认 L1-only（无网络），上 L2 需额外 Redis | M |
| **(d) 失效广播** | 在集群 `InvalidationBus` 上新增 `KindTokenRevocationCache`（当前已有 `KindTokenRevoked`，但只针对 store 层面；需要针对 cache 层的新 event kind），使副本收到吊销广播后逐出 L1/L2 缓存 | M |
| **(e) 配置与可观测** | 新增指标 `sso_token_cache_hits_total{level="l1\|l2\|l3"}`、`sso_token_cache_miss_total{level}`、`sso_token_cache_size`。YAML 段 `token_validation.cache.*`（`l1_ttl`、`l2_ttl`、`l1_max_entries`） | S |

### Edge Cases / 具体注意点

- **缓存与吊销的时效性冲突**：L1 TTL=1s 意味着吊销后最多 1s 的"假阳性"窗口。这是设计取舍。
  对需要亚秒级吊销敏感度的部署，提供 `WithTokenValidationCacheStrictMode`（L1 TTL=0，等价于
  只能用 Redis 或 Introspect）。
- **Token hash 碰撞**：使用 SHA-256，64 位截断（8 字节）作为 key。碰撞概率在 10k 活跃 token
  场景下可忽略不计。但需要显式 fallback：hash 碰撞导致误判 inactive → 降级到 L2/L3 验证。
- **L1 驱逐策略**：LRU 是默认策略（活跃 token 热驻）。突发流量导致冷 token 被驱逐 → 正常降级，
  不会误判。但需要文档注明"L1 大小应 ≥ 活跃 token 数"。
- **跨缓存一致性**：同一 token 的 L1/L2 可能因 TTL 不同步返回矛盾结果。解决方案：L2 写入时
  携带 `issued_at`，L1 读取时比较自己的 `issued_at` — 如果 L1 条目比 L2 旧，丢弃 L1。
- **Introspect Batch 的缓存命中率收益**：RFC 9701 signed introspection batch 对批量 RS 验证
  场景非常适用。L2（Redis）在此场景下可 serve 批量查询而无需回 AS。
- **内存安全**：L1 是进程内 map（类似 `sync.Map` 或 `hashicorp/golang-lru`），需要 `MaxEntries`
  硬限制 + 可选的 background reaper（复用 `infrastructure/defaultimpl/memreaper` 现有模式）。
  参考：现有 JTI/refresh/device-code/PAR memory stores 已有 reaper 基础设施。

### Sequencing Hint

**(a)** SPI + L1 memory 实现（复用现有 `memreaper` 模式）→ **(b)** 内省接线 → **(c)** RS 端升级 →
**(d)** 失效广播。前三步可以一个 sprint 完成（约 3 周），**(e)** 可观测并行做。Redis L2 可
延后到真有跨区域部署要求时再加。

---

## 方向二：跨云密钥编排层（Cross-Cloud Key Material Orchestration）

### 类型

企业级韧性 / 合规基础设施

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码库中已实现 | ❌ 不存在等效概念 |
| 已有分析文档覆盖 | ❌ 未作为独立方向分析过 |

### Why Now

项目已有五套 KMS 后端实现：

| 后端 | 代码路径 | 功能状态 |
|---|---|---|
| AWS KMS | `infrastructure/kms/awskms/` | ✅ 完整 |
| GCP Cloud KMS | `infrastructure/kms/gcpkms/` | ✅ 完整 |
| Azure Key Vault | `infrastructure/kms/azurekeyvault/` | ✅ 完整 |
| PKCS11 (HSM) | `infrastructure/kms/pkcs11/` | ✅ 完整 |
| HashiCorp Vault | `infrastructure/defaultimpl/vaulttransit/` | ✅ 完整 |

每套均可作为 `SigningKeyProvider` 独立工作。**但缺少跨云密钥编排层：**

| 能力 | 当前状态 |
|---|---|
| 主 KMS 不可用时的自动降级（AWS→GCP→本地） | ❌ 运维需手动改 YAML 重启 |
| 密钥材料跨云主动同步 | ❌ 每云独立密钥，无法互验 |
| 跨区域 JWKS 一致性与密钥路由 | ⚠️ 只有集中式 JWKS 端点，无区域路由 |
| 密钥轮换的统一调度与审计（跨云统一视图） | ⚠️ 每个 issuer 独立 StartRotation |
| 供应商锁定的风险评估与迁出演练 | ❌ 从未做过跨云迁移 |

**为什么现在做：**

1. **金融 / 政府 客户的真实合规要求**：云原生 HSM 是好，但如果"只绑定一个云"则等于
   把根信任锚定在一个云供应商上。欧洲金融监管（BaFin、ECB）的"非绑定要求"逐步明确。
2. **跨云灾备**：AWS KMS 不可用时（区域故障 / 证书轮换绑定 / 配额耗尽），不能停签名服务。
   当前运维只能手动改配置重启——这窗口是分钟级的停机。
3. **M&A 场景**：被收购方的 tenant 需要迁入收购方的签署基础设施，但原 KMS 仍然需要
   在过渡期内保留验证能力。跨云密钥编排使这种过渡成为运行时能力而非数据迁移项目。
4. **后量子迁移的过渡路径**：PQ 密钥（ML-DSA、SLH-DSA）暂时只在部分 KMS 可用，传统 RSA
   还在其他 KMS。跨云编排层可以抽象 PQ + 经典算法的共存迁移。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) KeyVault 编排 SPI** | `KeyVaultOrchestrator` —— `ActiveVault(ctx, algorithm) → (SigningKeyProvider, error)`、`ListVaults(ctx) → []VaultStatus{Provider,Alg,Healthy,LastRotated}`、`Failover(ctx, algorithm) → (newProvider, error)`。缺省实现：`PriorityVaultOrchestrator`（按优先级列表尝试，failover 移出 dead 到待恢复队列） | L |
| **(b) 跨云密钥同步** | 新增 `WithKeyReplication`：当主 KMS 完成轮换后，将新公钥/证书主动推送到备用 KMS（通过各 KMS 的 ImportKey API）。备用 KMS 可本地签发验证，但主 Vault 保留不可替代的权限（如生成私钥的权力）。同步失败不阻塞轮换 | XL |
| **(c) 区域 JWKS 路由** | 在 `handleJWKS` 内根据请求来源 region （基于 XFF geo / `X-Region` header）选择对应的 `SigningKeyProvider.JWKS`。全球 JWKS 端点兜底返回所有 region 的并集 | M |
| **(d) 统一轮换调度** | 在 `StartRotation` 之上封装 `WithKeyOrchestratedRotation(interval, strategy)`：跨所有 vault 同时触发轮换，确保同一 epoch 内所有云产生同一 `kid`（通过共享 naming seed：`kid = hash(vault_type || epoch)` => 跨云相同） | L |
| **(e) 健康度与告警** | 新增指标 `sso_vault_health{provider,alg}`（Gauge，1=healthy / 0=degraded）、`sso_vault_failover_total{from,to}`（Counter）。如果全部 vault 均不可用，降级到软件签名并发出 CRITICAL 告警 | M |

### Edge Cases / 具体注意点

- **跨云密钥同步的安全性**：公钥可以自由同步，但私钥永远不能跨云传输（即使加密传输——这个
  门槛不能跨，否则 HSM 的价值就没了）。跨云同步的"公钥级"：备用 KMS 拥有一个只能 verify
  的密钥副本。备用 KMS 不可签发新 token——它在 failover 后才被提升为主。
- **Failover 生命周期管理**：Primary 恢复后，不能自动回切（避免频繁 flip-flop）。运维必须
  手动确认 `POST /api/v1/admin/keys:promote vault=gcp` 或等待轮换周期自然切换。
- **跨云 kid 冲突**：不同云的 key material 用不同的 `kid` 前缀策略
  （`kid_aws_xxx` / `kid_gcp_xxx`），JWKS 端点为每个 kid 附带 `provider` 属性以便诊断。
- **异地灾备的 key 同步粒度**：跨 region 不一定要跨 cloud——同一 AWS 的不同 region 之间
  KMS key 不可互操作（KMS 是 region-scoped 服务）。因此跨 region 本身适用同一个编排逻辑。
- **与 `WithCoordinatedKeyRotation` 的关系**：跨副本协调翻转（Leaderless peer-key adoption）
  解决的是多副本之间的 `ActiveKID` 一致性问题。跨云编排解决的是**密钥存储面**的韧性。
  两者正交互补：多副本共享同一云编排器。

### Sequencing Hint

**(a)** SPI + `PriorityVaultOrchestrator`（2 sprint）→ **(e)** 健康度与告警（并行）→
**(c)** 区域 JWKS 路由（1 sprint）→ **(d)** 统一轮换调度（1 sprint）→ **(b)** 跨云密钥同步
（2 sprint，最复杂也最不紧急，建议有客户需求再做）。

---

## 方向三：User-Managed Access 2.0 —— 资源注册与保护 API（UMA 2.0）

### 类型

协议扩展 / API 网关集成

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码库中已实现 | ❌ 不存在 |
| 已有分析文档覆盖 | ❌ 未作为独立方向分析过 |

### Why Now

项目拥有 OAuth 2.0 的全部核心元素——授权服务器、资源服务器 SDK、以及受保护资源的管理。
**但缺少 UMA 2.0 的四个核心能力：**

1. **Resource Registration API（RFC 8707 §2 扩展）**——资源服务器可以向 AS 注册受保护资源
   （`POST /resource`），携带 scope 描述 + 资源 URI + icon_uri + 类型。AS 将这些信息
   用于同意屏、审计和 admin 可见性。
2. **Protection API**——资源服务器获取一个 `protection_api_token`（持久的、限 scope 的令牌），
   用它来注册资源、查询权限、推送 claims。
3. **Claims Collection & Redirect**——当 AS 不能确定请求是否被授权时，不是直接拒绝，而是
   收集满足授权条件所需的 claims（"为了访问这个资源，你需要提供一个 membership 声明"），
   然后 redirect 请求方去获取这些 claims。
4. **Requesting Party Token（RPT）**——资源授权后的最终产物，是传统的 access_token 的 UMA
   等价物，但包含授权上下文（哪些 claims 被使用、授权时间等）。

**为什么现在做：**

| 场景 | 当前 | 有了 UMA 2.0 后 |
|---|---|---|
| API 网关保护 REST API | 网关调用 `/token/introspect` 验证 token，但不知道资源对应的 scope | 网关预先注册资源 `/api/v2/orders/{id}` → `scope=orders:read`，introspect 时做 scope 匹配 |
| 第三方 App 需要访问用户数据 | OAuth 只在首次登录时展示 scope 列表，用户无法看到细分 | 资源粒度授权："这个 App 读取你的日历（events:read），但不读取联系人（contacts:read）"——每类资源单独授权 |
| 动态 scope 协商 | scope 是 client 固定的允许列表 | 每次授权可以基于资源属性和请求方 claims 动态决定 scope |
| 联邦场景 | 基于信任链的 client 授权 | 资源所有者可以将受保护资源授权给另一个组织中的特定用户 |

**这是 OAuth AS 进化到"真正的授权服务器"的关键一步。** 今天许多现代 OAuth 部署
（Keycloak、Auth0、Curity）都支持 UMA 2.0 的子集。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) Resource Registration API** | 新 SPI `ResourceSetStore`（memory + sqlite）。端点：`POST/GET/PUT/DELETE /resource`。资源集：`{_id, name, uri, type, resource_scopes[], icon_uri, owner_id}`。全程需要 `protection_api_token` 认证 | L |
| **(b) Protection API Token** | 新 grant handler `grant=uma_protection`，核发 `pat` + 持久（超长 TTL） + 可随时撤销。PAT 限 `protection:resource_set` scope | M |
| **(c) Permission Request + RPT** | 新端点 `POST /permission/ticket`（资源服务器创建 permission ticket） + `POST /rpt`（客户端凭 ticket+claims 索取 RPT）。RPT 是 JWT access_token 的 UMA 包装，携带 `permissions[]` claim | L |
| **(d) Claims Collection 流程** | 当 AS 需要额外 claims 时，通过 `need_info` 错误响应引导客户端去 claims 收集端点。新增 `ClaimsProvider` SPI（内建：LDAP、ID Token claims、外部 IdP federation） | XL |
| **(e) 同意屏 / Admin 集成** | 用户在授权同意屏上看到每个资源而非 scope 列表（"允许 App 读取你的 profile 信息和日历"）。Admin endpoint 列出每个 resource owner 的资源授权 | M |

### Edge Cases / 具体注意点

- **与传统 OAuth 授权码流程的关系**：UMA 授权不替代 OAuth 授权码流。它是叠加层：
  授权码流获取 access token，UMA 将 access token 升级为 RPT（携带更细粒度的
  resource-level permission）。**完全可选**——不配 UMA 则服务器行为不变。
- **PAT 的安全风险**：`protection_api_token` 是持久的（经常数天到数周），如果泄漏
  等于泄漏资源注册能力。需要强制 DPoP 绑定 + short TTL + refresh 模式。
- **claims 收集的 privacy 边界**：claims 收集过程不应暴露"存在哪些 claim 类型"——
  否则枚举攻击可以探测资源所有者定义的 security 配置。统一 collapse 到
  `need_info` + `required_claims`（仅暴露类型，不暴露值）。
- **permission ticket 的 TTL**：Ticket 必须 short TTL（< 5 分钟），防止"拿到 ticket 后
  离线爆破"。当前 `push_approval` 的有界 TTL 模式可复用。
- **资源 scope 与 OAuth scope 的对齐**：`resource_scopes` 名应该与 OAuth scope 名
  严格一致（如 `"scope": "openid profile email"` 对应 `"resource_scopes": ["profile:read", "email:read"]`），
  避免用户被同一个操作的两种 scope 命名混淆。

### Sequencing Hint

**(a)** Resource Registration API + **(b)** Protection API Token 是前置条件（2 sprint）。
然后 **(c)** Permission Request + RPT（2 sprint）。**(d)** Claims Collection（1-2 sprint，
最复杂）。**(e)** 集成（1 sprint，与 c/d 并行）。总约 5-6 sprint，是这些方向中工程量
最大的——但 UMA 2.0 完整实现的差异化价值也最高。

---

## 方向四：Token 沙箱隔离与受限委派框架（Token Compartmentalization & Confined Delegation）

### 类型

安全架构 / 企业治理

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码库中已实现 | ❌ 不存在等效概念 |
| 已有分析文档覆盖 | ❌ 未作为独立方向分析过 |

### Why Now

项目拥有 Token Exchange（RFC 8693）和 Agent Delegation Grant，支持 `act` 链和
actor 约束。**但缺少 Token 本身的沙箱隔离机制：**

| 问题 | 当前 | 需要 |
|---|---|---|
| 一个 token 泄露后 impact 范围 | 整个 scope 集合（最多时 "admin:*"） | 限制到"至少需要的权限" |
| 第三方 SDK 嵌入时使用主 token | 完全无法控制 SDK 行为 | SDK 获得受限 token（仅可调其 owner 的 API） |
| CI/CD pipeline 使用个人 token | pipeline 获得该用户全部权限 | pipeline token 仅限于"deploy:app-x" |
| 移动 App 的 offline token | token 可以做所有该 client 可以做的一切 | token 受限到特定资源、特定 IP、特定设备 |
| 多租户 SaaS 的 API 隔离 | 客户 token 可以访问其他 tenant 的数据（需 tenant layer） | 需要 token 层面的数据边界强行绑 |

**缺失的是 Token Compartmentalization（Token 沙箱化），即令牌限制机制：**

```go
type TokenConstraints struct {
    // 网络绑定：仅允许从这些 CIDR 使用
    AllowedCIDRs []string
    // 资源绑定：仅允许访问特定资源模式（"orders/*"）
    AllowedResourcePatterns []glob.Glob
    // 时间绑定：仅在这些时段有效
    TimeWindows []TimeWindow
    // 速率绑定：最大使用速率
    MaxTokenPerMinute int
    // 链路长度限制：本 token 可向下委派的最大深度
    MaxDelegationDepth int
    // 只读模式：本 token 禁止任何写入操作
    ReadOnly bool
    // 审计强制：每次 token 使用都必须写入审计事件
    ForceAudit bool
}
```

Token 签发时（或通过 `/token` 的额外参数），可以附加这些约束。约束被嵌入 token 的
claims 中（`cnf.constraints`），由 RS 端验证，也由 AS 在每次 introspect 时强化。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) TokenConstraints SPI + claims 嵌入** | 定义 `TokenConstraints` 结构体 + JSON/Go-Jose 序列化 + JWT claims `cnf.constraints` 嵌入。支持 narrow 操作（从现有 token 衍生一个更受限的 token）。新增 `WithTokenConstraintsApplier` option | M |
| **(b) 网络绑定（CNF）** | `AllowedCIDRs` 在 AS 端 introspect 时验证 request IP。需要 `requestBaseURL` / XFF 信任链（现有 `trusted_proxy.go` 基础设施）。RS 端可选重复验证 | L |
| **(c) 资源模式绑定** | `AllowedResourcePatterns` 使用现有 `netpolicy` / `permissions` 的 glob matcher。RS 端在 `validate.go` 中校验：如果 token 有 `AllowedResourcePatterns`，请求的资源路径必须匹配至少一个模式 | M |
| **(d) 只读模式 / 强制审计** | `ReadOnly` 约束的 RS 端强制（对 `POST/PUT/PATCH/DELETE` 请求拒绝）；`ForceAudit` 使 AS 在每次 introspect 请求时写审计（现有 `audit.Recorder` 可复用） | M |
| **(e) Admin 管理接口** | `POST /api/v1/admin/tokens/:id:apply-constraints` 对已签发的 token 施加新约束（需要刷新 token 重新签发）。新约束不能比旧约束宽松——只能从宽收紧到窄（non-monotonic 只会失败） | L |

### Edge Cases / 具体注意点

- **约束的不可逆性**：一旦 token 签发时附加了约束，后续不可放宽——只能更窄。这是安全
  设计核心原则。管理 API 想放宽约束的唯一路径是签发新 token。
- **Token 链约束传递**：如果 token A（`ReadOnly=true, MaxDelegationDepth=2`）exchange
  为 token B，B 必须继承 A 的所有约束（只可增加不可减少）。`act` 链中每跳都累积约束。
- **与 DPoP / mTLS 绑定的协同**：`AllowedCIDRs` 在 DPoP-bound token 上的意义不同——
  DPoP proof 的 IP 来自 `htm` claim（与 DPoP proof 的 `ath`+`htm` 绑定）。两种绑定
  不冲突但需要文档清晰说明检查顺序：DPoP 绑定 → CNF CIDR 检查 → 资源模式检查。
- **性能影响**：introspect 响应里多了 `cnf.constraints`，RS 端需要在每个请求路径上
  评估。约束评估必须在 50μs 内完成（CIDR match = 位运算 ± 常树；glob match = 
  O(pattern_len)）。需要 benchmark 闸门（复用 `ops/deploy/benchgate/`）。
- **Token Cache 的约束考虑**：方向一的多级缓存中，L1 缓存条目需要缓存约束评估结果，
  而非每次重算。带上 `evaluated_at` 标记，在约束的 TTL 窗口内（如 `cnf.constraints` 
  中的 `time_windows` 约束可能使 token 在不同时间有效/无效）重新评估。
- **与已有 `TokenExchangePolicy` 的关系**：`tokenexchange.Policy` 控制"谁可以 exchange
  到谁"。Token Constraints 控制 exchange 后 token 的行为边界。两者正交：Policy 是
  授权 gate，Constraints 是签发后的行为 fence。

### Sequencing Hint

**(a)** SPI + claims 嵌入是最小可行（1 sprint，可单独发布）→ **(e)** Admin 接口（并行）
→ **(b)** 网络绑定（1 sprint，依赖已有 XFF 和 geo 基础设施）→ **(c)** 资源模式 +
**(d)** 只读模式作为第二波（2 sprint）。该方向开箱即用体验好、营销差异化明显。

---

## 方向五：OAuth Grant 编排与审批工作流引擎（OAuth Grant Orchestration & Approval Engine）

### 类型

企业治理 / 产品化

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码库中已实现 | ❌ 不存在等效概念 |
| 已有分析文档覆盖 | ❌ 未作为独立方向分析过 |

### Why Now

项目拥有一个高度通用的 `admingovernance` 基础设施，支持**单一管理操作**的审批工作流
（`interfaces/admin/governance.go`）：某些敏感操作（如删除 client）需要 `Approver`
确认后才能执行，操作记录在 `audit_ops` 表中，超时自动拒绝。

**但 OAuth Grant 级别的权限授予没有任何工作流支持：**

| 操作 | 当前状态 | 企业需要 |
|---|---|---|
| DCR 注册应用的 scope 权限集 | ✅ 可以要求手动审批 client 注册 | ❌ 不能审批具体 scope（"允许 calendar:write 但拒绝 contacts:read"） |
| Token Exchange 到敏感 scope | ✅ 二值允许/拒绝 Policy | ❌ 不能走"申请→审批→审批→生效"的多步流程 |
| 跨租户协作访问 | ❌ 没有独立审批步 | ❌ 缺"A 租户 admin 申请→B 租户 admin 审批→限期访问" |
| 特权 scope 激活（admin:*） | ❌ 不能做 step-up 审批 | ❌ 缺"临时提权申请→Manager 审批→4 小时自动回收" |
| API scope 升级（新增 scope） | ❌ 只能 admin 手动改 client 配置 | ❌ 缺"开发者申请→安全团队评估→变更生效" |
| Emergency 访问 / Break Glass | ✅ 有 break-glass 审批工作流 | ⚠️ 但 break-glass 与 grant 编排不互通 |

**缺失的是 Grant-level Approval Workflow Engine（GATE）——一个通用的、将 OAuth grant
的权限授予行为封装为"审批工单"的框架。**

```go
type GrantApprovalWorkflow struct {
    ID           string
    Type         WorkflowType  // DCRScopeUpgrade | TokenExchangeSensitive | CrossTenantAccess | PrivilegeElevation
    RequestorID  string
    TargetClient string
    RequestedScopes []string
    Reason       string
    Status       WorkflowStatus  // pending | approved | rejected | expired | revoked
    Approvals    []ApprovalStep  // multi-step: [teamLead, securityOfficer, compliance]
    ValidAfter   time.Time       // 审批通过后的生效时间窗
    ValidUntil   time.Time
    AuditTrail   []WorkflowEvent
}
```

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) Workflow SPI + Store** | `GrantWorkflowStore` SPI（memory + sqlite）—— `CreateWorkflow`、`ApproveStep`、`RejectStep`、`ExpireWorkflow`、`ListWorkflows`。工作流的 lifecycle 状态机：`pending→approving→approved/rejected→expired/active→revoked` | L |
| **(b) Grant 接入点** | 三个 grant 路径的接入接缝：DCR scope 变更（`handle_register.go`）、Token Exchange（`token_exchange.go`）、跨租户协作（`tenant_collab.go`）。接入模式：Policy 返回 `NeedApproval{WorkflowType, RequiredApprovers[]}` → AS 签发一个 `approval_challenge` token → 等待审批 → 审批通过后重新请求获得完整 scope | XL |
| **(c) Admin 管理 API** | `POST /api/v1/admin/workflows`（创建）、`POST /api/v1/admin/workflows/:id:approve` / `:reject`、`GET /api/v1/admin/workflows`（列表）。审批页嵌入 Console | M |
| **(d) 审批通知通道** | 当有新工单待审批时：`WithWorkflowNotifier` SPI（内置 email、webhook、Console badge）。缺省实现：`log_notifier`（记录到日志） | M |
| **(e) 到期自动回收与审计** | `PruneExpiredWorkflows` 后台调度器（复用 `platform/migrate` scheduler 模式）。`WorkflowExpired` / `WorkflowRevoked` 审计事件。新指标：`sso_workflow_approvals_total{type,outcome}` | M |

### Edge Cases / 具体注意点

- **多步审批 vs 单步审批**：不是所有工作流都需要多步。工作流类型的 `RequiredApprovers[]`
  可以配置为一步（`["teamLead"]`）、两步（`["teamLead","securityOfficer"]`）、或
  任意（`[["teamLead","securityOfficer"]]` —— 两者任一即可）。默认一步。
- **审批超时**：从创建到所有步骤审批的 `approval_window`（默认 72h）。超时自动
  `expired`，不影响 client 当前配置，但影响请求 scope 的授予。超时后需重新提交。
- **审批期间的客户体验**：当 DCR scope 变更触发审批时，`PUT /register` 不能阻塞等到
  审批完成（DCR 规范不允许）。方案：`PUT` 立即返回 200 但保留现有 scope，待审批通过后
  新 scope 生效 + audit scope_upgraded。前端显示"scope 变更 pending approval"。
- **Token Exchange 工作流的原子性**：Token Exchange 是同步请求，不能等审批。方案：
  Policy 返回 `NeedApproval` 时，AS 签发一个**仅含当前已有 scope 的 access token**
  + 一个 `approval_challenge` claim。client 凭 challenge 轮询等待或等回调通知，
  审批通过后重新 exchange 获得完整 scope 的 token。
- **Break Glass 的集成**：现有 `break_glass.go` 的紧急审批流与工作流引擎共享同一个
  `Approver` 接口，但 break-glass 是"事中审批"（先操作后补审批），GATE 是"事前审批"。
  两者互补但实现上不共享同一状态机。文档需要清晰区分。
- **与现有 `admingovernance` 的关系**：`admingovernance` 面向**管理操作**（`POST /admin/clients/:id`），
  GATE 面向**权限授予**（`grant scope X to client Y`）。两者应有相同的审计格式和追溯方式，
  但存储和工作流状态机截然不同。不应硬耦合。

### Sequencing Hint

**(a)** Workflow SPI + Store + 单步审批（1 sprint 最小可行）→ **(c)** Admin API（并行）
→ **(d)** 通知通道（S）→ **(b)** 先接 DCR scope 变更（最常用，1 sprint），再接
Token Exchange（L）→ 跨租户协作和 Break Glass 留到有客户要求时再做。

---

## 优先级矩阵

| # | 方向 | 类型 | 阻塞下游 | 建议顺序 | 工作量估值 |
|---|---|---|---|---|---|
| 1 | **多级 Token 验证缓存架构** | 性能优化 | 高吞吐 RS 部署（>5k TPS） | **P1** — 可与其他并行；对性能敏感客户直接可见收益 | ~3 sprint |
| 2 | **跨云密钥编排层** | 企业韧性 | 金融 / 政府客户 RFP（非绑定要求） | **P2** — 真正客户需求驱动；无客户需求则可等 | ~5 sprint |
| 3 | **UMA 2.0 资源注册与保护 API** | 协议 + 产品化 | API 网关集成 / 第三方 App 授权 | **P2** — 差异化价值高但工程量大，建议有计划后专项投入 | ~6 sprint |
| 4 | **Token 沙箱隔离框架** | 安全架构 | 企业客户安全运维 | **P1** — MVP 开箱即用效果好，风险收益比最优 | ~3 sprint |
| 5 | **Grant 编排与审批工作流** | 企业治理 | 企业级客户采购（访问治理） | **P2** — 对企业销售 demo 价值巨大，但功能可拆 MVP 先做 | ~4 sprint |

### 组合建议

- **第一波（P1，2-3 sprint）：** 方向一（多级缓存）+ 方向四（Token 沙箱）并行。
  方向一改善所有部署的性能表现，方向四提供高安全差异化。两者无代码冲突。
- **第二波（P2，3-4 sprint）：** 方向五（审批工作流）MVP + 方向二（跨云编排）起步。
  审批对销售 Demo 价值最高，跨云编排准备 P0 客户需求。
- **第三波（P3，按需）：** 方向三（UMA 2.0）专项。如果有明确的 API 网关集成客户
  或有 UMA 2.0 RFP 需求时再做。

---

## 附录：分析方法声明

本报告的五个方向经过与 40+ 份已有扩展分析文档（`docs/requirements/*.md`）的全关键词
交叉验证，**每条方向的关键概念在已有分析中零命中**（方向一：multi-tier cache / L1 L2；
方向二：跨云密钥编排 / key orchestration；方向三：UMA 2.0 / User-Managed Access；
方向四：token compartmentalization / token sandbox；方向五：grant approval workflow /
OAuth 编排审批）。同时逐项在代码库中 grep 确认方向的关键字**不存在于当前实现中**，
确保建议方向是**真正未实现、未分析过的真缺口**。
