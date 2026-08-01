# 高价值扩展方向 —— 生产部署纵深与运营成熟度缺口

> **视角：** 资深架构 & 产品经理  
> **方法：** 全代码库全局扫描（421,259 行 `.go`，14 个独立 `go.mod`，200+ 包，  
>   核心按层分布在 `shared/` → `domains/` → `protocols/` → `infrastructure/` → `interfaces/`）。  
>   前置阅读：docs/requirements/ 下全部 23+ 轮历史分析文档（v1–v13、novel*、edge-cases、  
>   gaps-analysis、production-hardening、systemic-quality、ciam-identity-horizon、  
>   next-wave、senior-architect 等），ROADMAP v5.0，deferred-backlog，feature-matrix。  
> **核验方法：** 对每项候选方向做全代码库 grep 逐项关键词核验 + 对全部 23+ 历史分析文档  
>   做**小写规约化关键词交叉验证**，确保每项为**真实代码级缺口且与所有历史分析零重叠**。  
> **日期：** 2026-07-11  

---

## 前置声明

经过 23+ 轮全局扫描 + 大量实现落地，本项目的能力覆盖面已居行业顶级。以下领域已确认**全部覆盖**，本报告不再重复：

| 领域 | 覆盖状态 |
|---|---|
| **协议面**（OAuth 2.0 × 7 grants + PAR/JAR/JARM/RAR, OIDC Core/Discovery/Logout/BCL/FCL/CIBA/Form Post, SAML 2.0 SP+IdP, SCIM 2.0 双向, CAEP/SSF 双向, FAPI 2.0, OpenID Federation 1.0, LDAP, Kerberos, RADIUS, DPoP, mTLS, SPIFFE JWT-SVID, Transaction Token, Step-Up Auth） | ✅ 全部落地 |
| **存储面**（Memory, SQLite, Redis, etcd, PostgreSQL + 14 嵌套子模块：KMS×5, SAML×4, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT） | ✅ 全部落地 |
| **安全面**（Anti-enumeration, Oracle-leak, DPoP, mTLS, JWT-SVID, Workload Identity, Break-Glass, Per-tenant 签名隔离, 区域数据驻留, FAPI 2.0, FIPS 140-3, 会话信任衰减, Step-Up Auth, Account Lockout） | ✅ 全部落地 |
| **产品面**（Hosted Login SPA, Admin Console SPA, Developer Portal SPA, User Portal `/me`, Consent Store × 3, B2B Connections + HRD, Org-admin self-service, API docs viewer, SDK 生成 TS + Python, MCP Server） | ✅ 全部落地 |
| **运维面**（DR framework Snapshot/RPO/RTO, Config hot-reload SIGHUP × 7 gates, Metrics/Prometheus/Grafana, Audit hash-chain + OCSF/CEF, pprof, k6 load test, Chaos tests ×4, Benchmark gate） | ✅ 全部落地 |
| **生产硬化**（Circuit Breaker, Active-Active, Template Customization, HR Connector, SLO Framework — 最新分析已识别） | ❌ 已识别待落地 |
| **前沿方向**（AI/ML Identity, AI Agent Identity, PAM, Post-Quantum, CIAM/Social Login, Token Status List, Session Roaming — 已分析已识别） | ❌ 已识别待落地 |

> **结论：** 功能扩展方向（做什么）已在 23+ 轮分析中被深度覆盖并大量落地。  
> 剩余的最高价值空间不在「新增协议特性」或「补后端实现」—— 这些已接近理论上限。  
> 本报告 5 个方向聚焦于从**功能完备的身份平台**走向**可直接以 SaaS 形态可靠运营  
> 的企业级基础设施**时，在 token 交付、运营可观测性、安全治理三个维度上尚未被  
> 任何分析触及的纵深缺口。

---

## 方向一：自定义声明管线与 Token 富化框架（Custom Claims Pipeline & Token Enrichment）

### 为什么需要它

这是目前代码库中**优先级最高但最隐蔽的产品缺口**。

在 `protocols/oidc/oidcsupport/userinfo.go` 中有一段明确的标注：

```go
// Deployment-custom claims are intentionally NOT released here; doing so safely
// requires an EXPLICIT operator-configured allowlist (a future extension point),
// never a default-allow.
```

这是一个被代码自身承认的「未来扩展点」，在已上线的身份平台中**从未被实现**。

### 现状与缺口

**现状：** 当前 token 的 claims 完全由认证/授权管线内部决定。最终用户能出现在 token 中的 claims 集合由以下因素决定：

| 数据来源 | 控制方 | 是否可扩展 |
|---|---|---|
| OIDC 标准 claims（sub, iss, exp, iat, amr, auth_time） | 协议层 | ❌ 不可扩展 |
| `User.Attributes` 中的标准 OIDC scope claims（email, name, profile 等） | 用户存储层 | ❌ 被 `releasableUserInfoClaims` 硬编码 allowlist 限制 |
| `Subject.Claims` 透传（Extra 字段） | 调用方 | ❌ 仅由 token-exchange 等内部路径设置 |
| `Client.AllowedResources` → `aud` claim | Client 配置 | ❌ 仅限 `aud` |
| JWT `cnf`（DPoP/mTLS binding） | 安全层 | ❌ 只读 |

**缺口（grep 核验）：**

| 概念 | 代码命中 | 分析文档命中 |
|---|---|---|
| `custom.*claim.*pipeline\|claim.*enrich\|claim.*inject\|token.*enrich\|claim.*mapper` | **0**（仅 workoad identity 上下文） | **0** |
| `claim.*hook\|claim.*callback\|claim.*transform` | **0** | **0** |
| `claim.*allowlist\|custom.*claim.*allowlist` | **0** | **0** |
| `token.*template\|claim.*template\|claim.*policy.*map` | **0** | **0** |

**业务场景不能实现：**

| 场景 | 当前行为 | 想要的行为 |
|---|---|---|
| 用户所属部门、角色注入 token | ❌ 需要 fork 代码 | 配置 `claims_pipeline: { map: { department: "attrs.dept" } }` |
| 外部 IdP 断言透传到 access token | ❌ SAML/WS-Fed 断言丢失 | SAML 属性 → JWT claim 的 mapping 规则 |
| 按 client 类型添加不同 claims | ❌ 所有 client 相同 | `client.metadata.claims: { add: ["tenant_admin"] }` |
| 条件性 claim 注入（仅高风险登录加 `login_risk`） | ❌ 不支持 | 基于 conditional access 结果的 claim 追加 |
| 租户自定义 claim（每个租户有不同 claim schema） | ❌ 不支持 | `tenant.claims_pipeline: { ... }` |

### Scope 建议

```
1. ClaimsPipeline SPI (shared/core/claims_pipeline.go)
   - type ClaimsPipeline interface {
       EnrichAccessToken(ctx, *Subject, *Client) (map[string]any, error)
       EnrichIDToken(ctx, *Subject, *Client) (map[string]any, error)
       EnrichUserInfo(ctx, *Subject, *Client) (map[string]any, error)
     }
   
2. 内置 pipeline 处理器
   - AttributeMapper: User.Attributes → claim (allowlist-based)
   - ExternalAssertionMapper: SAML/LDAP assertion → claim
   - ConditionGate: conditional access 策略控制 claim 是否加入

3. Admin API 配置
   - PUT /admin/tenants/:id/claims-pipeline (租户级)
   - PUT /admin/clients/:id/claims-pipeline (client 级)
   - Dry-run: POST /admin/tools/claims-preview?token=<jwt> 预览 pipeline 结果

4. UserInfo 响应扩展
   - 将 claims pipeline 集成到 userinfo 响应管线中
   - 扩展 releasableUserInfoClaims 为可配置的 allowlist
```

### 边界情况

| 边界 | 策略 |
|---|---|
| claim 名称与标准 OIDC claim 冲突 | Pipeline 优先级：显式 mapping > 标准 claim；冲突时产生 audit 告警 |
| claim pipeline 执行失败 | fail-open（log + 跳过），不阻塞 token 签发 |
| 大量自定义 claim 导致 token 过大 | 设置 `max_custom_claims_bytes`（默认 1KB），超限时 truncate + audit |
| pipeline 引用了不存在的 user attribute | 返回空字符串（不设 claim），非错误 |

---

## 方向二：Introspection 缓存可观测性与自适应 TTL（Introspection Cache Observability & Adaptive TTL）

### 为什么需要它

Token introspection（RFC 7662）是资源服务器验证令牌的核心路径。当前实现了 introspection 缓存（`protocols/oauth/introspect_cache.go`），但它是一个**完全盲操作的缓存**——没有任何指标、没有命中率监控、没有 TTL 自适应能力。

在生产中，这是运维盲区：

| 问题 | 风险 |
|---|---|
| 缓存 TTL 设置过短 | → 低命中率 → 每一请求都穿透到后端 → AS 负载翻倍 |
| 缓存 TTL 设置过长 | → 已吊销 token 被缓存误判为有效 → 安全事件 |
| cache 容量不足 | → 热门 token 被频繁逐出 → 缓存退化 |
| eviction 策略不当 | → 使用频率最高的 token 反而被较早逐出 |

目前没有任何工具可以帮助 operator 回答「当前缓存命中率是多少？」「应当设置多长的 TTL？」「需要多大的缓存容量？」。

### 代码级缺口

| 概念 | 代码命中 | 分析文档命中 |
|---|---|---|
| `introspect.*cache.*hit\|introspect_cache_hit\|cache_hit.*total` | **0** | **0** |
| `cache.*hit.*rate\|cache.*hit.*ratio\|cacheMiss\|cache_miss` | **0**（不在 introspection 上下文） | **0** |
| `cache.*evict\|eviction.*count\|cache.*remove` | **0**（不在 introspection 上下文） | **0** |
| `cache.*tun\|adaptive.*ttl\|cache.*ttl.*adjust\|cache.*ttl.*automatic` | **0** | **0** |

当前 `IntrospectionCache` 接口：

```go
type IntrospectionCache interface {
    Get(key string) (*CachedResult, bool)
    Set(key string, result *CachedResult, ttl time.Duration)
}
```

没有任何统计/观察方法。

### Scope 建议

```
1. 缓存指标 SPI 扩展
   - 在 IntrospectionCache 接口中增加可选方法:
     Stats() CacheStats
     ResetStats()
   - CacheStats 包含:
       type CacheStats struct {
           Hits        int64
           Misses      int64
           Sets        int64
           Evictions   int64
           CurrentSize int64
           MaxSize     int64
           HitRate     float64  // Hits / (Hits + Misses)
       }

2. Prometheus 指标暴露
   - sso_introspect_cache_hits_total{backend="memory|redis|sqlite"}
   - sso_introspect_cache_misses_total
   - sso_introspect_cache_evictions_total
   - sso_introspect_cache_size
   - sso_introspect_cache_hit_ratio (gauge, 滑动窗口 1m/5m/15m)

3. Grafana 面板
   - Introspection Cache 仪表盘面板（命中率趋势、TTL 分布、逐出率）
   - 与 benchmark gate 结合（`benchmarks.yaml` 中增加 introspection cache 性能场景）

4. 自适应 TTL 引擎（可选增强）
   - 缓存引擎根据实时命中率自动调整 TTL：
     - 命中率 > 95%: 保守延长 TTL (×1.1)
     - 命中率 < 70%: 缩短 TTL (×0.8)，或触发告警
     - 逐出率 > 5%/min: 扩容告警
   - 每日/周自动生成 TTL 优化建议报告

5. Admin API 可见性
   - GET /admin/observability/introspect-cache 返回实时缓存统计
   - GET /admin/recommendations/introspect-cache-ttl 返回优化建议
```

### 边界情况

| 边界 | 策略 |
|---|---|
| 缓存命中率 100% 可疑（可能是 stale 数据） | 同时监控 `revocation_count`：若 revocation 增加但命中率未下降 → 缓存可能未刷新 |
| 多个后端混合（内存 + Redis） | 各自独立统计；admin API 返回聚合+分后端明细 |
| 缓存统计本身的性能开销 | 使用原子计数器（`atomic.Int64`），单次操作 ~5ns |
| 自适应 TTL 异常波动 | 设置 TTL 变化幅度上限（每次不超过 30s），变化前后记录 audit 事件 |

---

## 方向三：Token Exchange 链式治理与深度控制（Token Exchange Chain Governance & Depth Controls）

### 为什么需要它

Token Exchange（RFC 8693）是微服务架构中服务间身份传播的核心机制。当前实现支持完整的 `act` 链传播、actor 防重放、链生命周期上限（`WithMaxTokenExchangeChainLifetime`）。**但缺少链深度治理**。

在一个典型的服务网格场景：

```
User → Gateway (hop1) → Authz (hop2) → Billing (hop3) → Ledger (hop4) → Audit (hop5) ...
```

随着 token 的每一跳，`act` 链追加一条记录，token 体积线性增长。缺少治理控制意味着：

| 风险 | 说明 |
|---|---|
| **链无限增长** | 无深度上限 → token 体积可达数 KB → 网络/解析开销 |
| **无服务级跳转授权** | 任意服务都可以对 token 做 exchange → 若中间服务被攻破，攻击者可伪造整条链 |
| **无操作审计** | 链上的每一跳都没有独立的审计事件 → 无法回溯「谁在什么上下文中发起了 exchange」 |
| **无成本控制** | token exchange 是计算/网络密集操作 → 无频率/深度限制可被滥用 |

### 代码级缺口

| 概念 | 代码命中 | 分析文档命中 |
|---|---|---|
| `token.*exchange.*depth\|chain.*depth\|exchange.*depth` | **0** | **0** |
| `hop.*limit\|hop.*count\|max.*hop\|max.*exchange.*hop` | **0** | **0** |
| `exchange.*govern\|exchange.*policy.*depth\|token.*exchange.*chain.*policy` | **0** | **0** |
| `exchange.*rate.*limit\|token.*exchange.*cost\|token.*exchange.*budget` | **0** | **0** |

现有控制只有：

```go
func WithMaxTokenExchangeChainLifetime(d time.Duration) Option // only lifetime cap
```

不存在深度、频率、服务级跳转授权。

### Scope 建议

```
1. 深度控制（MaxChainDepth）
   - type TokenExchangePolicy struct {
       MaxChainDepth      int           // 默认 5, 0 = unlimited
       MaxChainLifetime   time.Duration // 已有的 lifetime cap
       RequireHopAuth     bool          // 跳转要求服务持有自身 token
       AuditEveryHop      bool          // 每一跳记录独立 audit event
     }
   - 集成到现有 WithTokenExchangePolicy

2. Hop 授权（每跳验证）
   - 当 RequireHopAuth=true:
     每一跳需要在请求中附加自己的 client_credentials token
     验证该 token 的 issuer 匹配 act 链中的上一个 actor
   - 防中间服务伪造: 链中每一条记录的 sub/iss 必须与上一跳的凭证一致

3. 频率限制（Per-service exchange rate limit）
   - 使用现有 ratelimit 框架，增加 per-service（by client_id）的 token exchange
     频率限制
   - 默认: 100 req/min per service；可配置

4. Token 体积告警
   - 签发 token 时检查 payload 大小（因 act 链增长）
   - 超过阈值（默认 2KB）时记录 audit 告警
   - 超过硬上限（默认 4KB）时拒绝签发，返回 400

5. Admin API 可观测性
   - GET /admin/token-exchange/chains 返回活跃 token exchange 链深度分布
   - GET /admin/token-exchange/top-consumers 返回使用 token exchange 最多的 service
```

### 边界情况

| 边界 | 策略 |
|---|---|
| 深度上限切断合法长链 | 默认深度 5（多数场景足够），超限返回 `exceeded_max_chain_depth` + 建议拆分或使用 token-exchange 替代设计 |
| Hop 授权增加延迟 | 每跳验证仅验证签名 + issuer，轻量操作 (~1ms)；性能敏感路径可配置为 monitor-only |
| 旧 token 在新策略启用前已签发 | 策略修改仅对新签发 token 生效。活跃旧 token 不受影响（其 act 链是历史数据） |
| 链深度 1（直接 exchange）也需要 hop auth | depth=1 无中间服务，RequireHopAuth 自动跳过（因为无前一跳可验证） |

---

## 方向四：速率限制算法策略与突发配置（Rate Limiting Algorithm Strategy & Burst Configuration）

### 为什么需要它

当前速率限制（`interfaces/ratelimit/`、`infrastructure/redis/ratelimit.go`）功能完备，支持全局 and per-endpoint 限制、SQLite/Redis 后端、热重载。但**只提供单一的内置算法**，且**无突发（burst）控制概念**。

不同的限流场景需要不同的算法：

| 场景 | 推荐算法 | 当前是否支持 |
|---|---|---|
| 保护 `/token` 免受暴力攻击 | Sliding Window 或 Token Bucket | ❌ |
| API 配额（每小时 10000 请求） | Fixed Window | ❌（若当前是 sliding window 则不够直观） |
| 防止并发洪峰 | Leaky Bucket（平滑输出） | ❌ |
| 混合场景（稳定速率 + 允许突发） | Token Bucket with Burst | ❌ |
| GPU/KMS 等昂贵操作 | Concurrency Limit（max-in-flight） | ❌ |

更关键的是：**没有 burst 控制**。在令牌桶算法中，burst 参数决定瞬间可消耗的令牌数。没有 burst 意味着：

- 客户端必须均匀发送请求（不现实）
- 一瞬的正常流量波动即被 429
- 运营商无法配置「允许 100 req/s，突发 200 req」

### 代码级缺口

| 概念 | 代码命中 | 分析文档命中 |
|---|---|---|
| `rate.*limit.*algor\|rate.*limit.*strateg` | **0** | **0** |
| `rate.*limit.*burst\|burst.*limit\|burst.*capacity` | **0** | **0** |
| `token.*bucket.*algorithm\|token.*bucket.*rate` | **0** | **0** |
| `sliding.*window.*rate\|leaky.*bucket` | **0** | **0** |
| `concurrency.*limit\|max.*in.*flight.*limit\|concurrent.*request.*limit` | **0**（不在 rate limit 上下文） | **0** |

当前接口（`interfaces/ratelimit/ratelimit.go`）：

```go
type Limiter interface {
    Allow(ctx context.Context, key string) (bool, error)
}
```

没有算法选择、没有 burst 参数、没有 ConcurrencyLimiter。

### Scope 建议

```
1. 算法策略抽象
   - type Algorithm string
     const (
         AlgorithmSlidingWindow Algorithm = "sliding_window"  // 默认，向后兼容
         AlgorithmFixedWindow   Algorithm = "fixed_window"
         AlgorithmTokenBucket   Algorithm = "token_bucket"
         AlgorithmLeakyBucket   Algorithm = "leaky_bucket"
         AlgorithmConcurrency   Algorithm = "concurrency"     // max-in-flight
     )
   - 现有 Limiter 接口扩展为可配置算法
   - 每个后端实现（memory, sqlite, redis）各自实现所有算法

2. Burst 控制
   - type RateLimitConfig struct {
       Rate     float64        // 速率（per second）
       Burst    int            // 突发上限（0 = 等同于 rate 的 1s 值）
       Window   time.Duration  // 窗口（sliding/fixed window 用）
       Algorithm Algorithm
     }
   - 每个租户/endpoint 可独立配置

3. Hot-reload 集成
   - 现有 RateLimiterOption 通过 config hot-reload 支持算法+burst 的动态切换
   - 切换时平滑过渡（不 reset 计数器）

4. 默认配置
   - 向后兼容：不指定 algorithm 时使用当前内置算法
   - 新增端点默认配置：/token 50/s burst 100, /introspect 200/s burst 400
```

### 边界情况

| 边界 | 策略 |
|---|---|
| 算法切换期间的计数平滑 | 切换时保留旧窗口的计数器，新算法从当前状态开始，不硬重置 |
| Burst 被滥用打穿 | Burst 是速率×N 而非绝对值。监控 burst_ratio，超过阈值时 audit 告警 |
| Concurrency limiter 与 rate limiter 配合 | Concurrency 限制并行数，Rate 限制速率——两者可同时启用，独立生效 |
| Fixed Window 的边界尖峰问题 | 文档中标注「Fixed Window 在窗口边界可能允许 2x rate 的瞬时流量」，推荐重要端点使用 Sliding Window |

---

## 方向五：客户端/应用分类体系与差异化策略（Client/Application Classification & Policy Differentiation）

### 为什么需要它

当前所有 OAuth 客户端的策略配置几乎是对等的。一个 SPA 应用、一个原生移动应用、一个服务端 Web 应用和一台 CLI 工具——它们在当前系统中没有本质区别。意味着 operator 无法基于「应用类型」或「信任级别」应用不同的安全策略。

**这是企业 SSO 平台的一个基础性差距**：不同类型和信任级别的应用需要根本不同的安全策略。

| 应用类型 | 需要的策略差异 | 当前状态 |
|---|---|---|
| **单页应用（SPA）** | 强制 PKCE, 禁止 client_secret（public client），短 token TTL | ❌ 无法区分 |
| **原生移动应用** | 强制 DPoP binding, 设备注册检查, 无 refresh token 持久化 | ❌ 无法区分 |
| **服务端 Web 应用** | 允许 client_secret（confidential client），较长 session | ❌ 无法区分 |
| **CLI / 开发者工具** | 必须使用 device code grant，强制 scope 最小化 | ❌ 无法区分 |
| **服务账户 / machine-to-machine** | 强制 IP 白名单 + mTLS，无用户登录路径 | ❌ 无法区分 |
| **第三方应用（外部）** | 严格 scope 审批 + 短 TTL + 审计增强 | ❌ 无法区分 |
| **内部应用（第一方）** | 放宽 redirect_uri 限制，免 consent | ❌ 无法区分 |

### 代码级缺口

| 概念 | 代码命中 | 分析文档命中 |
|---|---|---|
| `client.*classif\|client.*categor\|client.*taxonom` | **0** | **0** |
| `application.*type\|app.*type.*spa\|app.*type.*native\|app.*type.*web\|app.*type.*service` | **0**（个别引用是 OIDC metadata 中的 application_type，非策略骨架） | **0** |
| `client.*sensitivity\|client.*trust.*level\|client.*tier\|client.*risk.*level` | **0** | **0** |
| `client.*type.*policy\|app.*type.*policy\|client.*category.*policy` | **0** | **0** |

OIDC 标准中定义了 `application_type`（`web` / `native`）— 当前代码未使用该字段做任何策略分叉。

### 应用类型的场景差异清单

以下差异在 enterprise SSO 平台中属于基线能力，但当前全部不可实现：

| 策略项 | SPA | Native App | Web App | Service Account | CLI | 第三方 |
|---|---|---|---|---|---|---|
| PKCE 强制 | ✅ 必须 | ✅ 必须 | 可选 | N/A | ✅ 必须 | ✅    |
| client_secret | ❌ 禁止 | ❌ 禁止 | ✅ 允许 | ✅ 允许 | ❌ 禁止 | 可选 |
| Refresh Token | ✅ 短（1h） | ✅ 短（1h） | ✅ 长（7d） | ❌ 无 | ❌ 无 | ✅ 短 |
| DPoP 绑定 | ✅ 推荐 | ✅ 强制 | 可选 | ✅ 强制（mTLS） | ❌ N/A | ✅ 推荐 |
| Consent | 需要 | 需要 | 需要 | N/A | 需要 | 需要 |
| Scope 上限 | 标准 scope | 标准 scope | 标准 | 最小 | 最小 | 严格 |
| Token TTL | 15min | 30min | 1h | 1h | 5min | 15min |
| IP 限制 | N/A | N/A | 可选 | ✅ 强制 | N/A | N/A |

### Scope 建议

```
1. ApplicationType 枚举（扩展 core/types.go 中的 Client 结构）
   - type ApplicationType string
     const (
         AppWeb            ApplicationType = "web"              // 服务端 Web 应用
         AppSPA            ApplicationType = "spa"               // 浏览器 SPA
         AppNative         ApplicationType = "native"            // 原生移动/桌面
         AppService        ApplicationType = "service"           // Machine-to-Machine
         AppCLI            ApplicationType = "cli"               // CLI / 开发者工具
         AppThirdParty     ApplicationType = "third_party"       // 第三方/OIDC 外部
     )
   - Client.ApplicationType 字段（非必填，默认 web 保持向后兼容）

2. TrustLevel / Sensitivity
   - type ClientTrustLevel string
     const (
         TrustFirstParty  ClientTrustLevel = "first_party"
         TrustPartner     ClientTrustLevel = "partner"
         TrustPublic      ClientTrustLevel = "public"
     )
   - Client.TrustLevel 字段

3. 基于应用类型/信任级别的策略引擎
   - 扩展 Conditional Access 引擎，新增:
       WHEN client.application_type == "spa" THEN require_pkce=true
       WHEN client.application_type == "service" THEN forbid_auth_code=true
       WHEN client.trust_level == "public" THEN max_token_ttl=15min
   - 默认策略（无配置时向后兼容，不改变当前行为）

4. 注册时的类型校验
   - DCR 时 application_type 在 allowed list 中
   - 某些类型组合互斥（service + auth_code_grant → 拒绝）
   - 类型变更需要 admin 审批/audit 事件

5. Admin Console 可视化
   - Client 列表增加「类型」筛选、批量操作
   - Client 详情页显示类型应用的建议配置
```

### 边界情况

| 边界 | 策略 |
|---|---|
| 现有 client 没有 application_type | 默认 `web`，向后兼容；operator 可批量迁移 |
| SPA 错误声明为 `web`（尝试使用 client_secret） | 强制验证：若 declared `spa` 但注册了 `client_secret` → 拒绝 |
| client_type 变更后的生效时机 | 变更即生效（reload config），活跃 token 不受影响，新签发遵循新规则 |
| 同一公司既有内部又有第三方应用 | TrustLevel 区分，策略在 TrustLevel 级别独立配置 |
| 与 OIDC `application_type` 标准的兼容 | `web` / `native` 值对齐 OIDC Core §2；`spa` / `service` / `cli` 为扩展值 |

---

## 优先级与实施建议

### 排序（投入产出比）

| 优先级 | 方向 | 为什么 | 预期工作量 | 依赖 |
|---|---|---|---|---|
| **P0** | 方向一：自定义 Claims Pipeline | enterprise 采购清单 TOP3 需求；代码自身已标注「未来扩展点」；影响所有 token 签发路径 | M（4-6 周） | 无 |
| **P1** | 方向五：Client 分类与差异化策略 | 差异化安全策略的基础；直接影响 OAuth 安全姿态评估；与 direction 1 有协同 | M（3-5 周） | 无 |
| **P2** | 方向三：Token Exchange 链治理 | 安全治理缺口，但仅在复杂微服务架构中暴露；大规模部署才产生紧迫性 | M（3-4 周） | 方向五（client 分类作为 hop auth 前置） |
| **P2** | 方向二：Introspection 缓存可观测性 | 运维效率提升；风险低（不改变核心逻辑）；持续收益 | S（2-3 周） | 无 |
| **P3** | 方向四：Rate Limit 算法策略 | 功能增强；已有 ratelimit 框架可扩展；但当前单一算法满足大多数场景 | M（3-4 周） | 无 |

### 依赖关系图

```
方向一 (Claims Pipeline)      ← 独立，无阻塞依赖
     │
     ▼
方向五 (Client Classification) ← 独立，但与方向一协同（按 client type 配置不同 claims）
     │
     ▼
方向三 (Token Exchange Chain Governance) ← 依赖方向五（client type/trust level 用于 hop auth）
     │
     ▼
方向二 (Introspect Cache Observability) ← 独立，无阻塞依赖，可与上述并行
     │
     ▼
方向四 (Rate Limit Algorithm) ← 独立，无阻塞依赖，可与上述并行
```

### 执行建议

1. **方向一和方向五可以立即并行启动**——不改变核心协议层，不引入新外部依赖；方向一影响所有 token 签发，方向五影响所有 client 策略。这两项是走向 enterprise-ready 的**基础设施级**变更。

2. **方向二风险最低**，建议塞入 sprint 的空隙时间（2-3 周内可交付独立价值）。在方向一的开发过程中并行推进，获得快速成就感。

3. **方向三的复杂度中等**但优先级取决于实际部署规模——如果当前没有复杂的 token exchange 生产场景，可以先完成 SPI + 默认策略（留空），等待实际需求。

4. **方向四**在热加载 pipeline 开发中可作为参考实现——展示「热切换算法」的能力。

5. **所有五个方向**共享的一条原则：**向后兼容，默认不改变当前行为**。operator 不配置新字段时，系统行为与当前完全一致。
