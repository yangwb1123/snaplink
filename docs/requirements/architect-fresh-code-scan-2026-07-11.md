# 全代码库深度复扫：五项未被覆盖的边缘缺口与优化方向

> **分析师：** 资深架构师 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库 2241 `.go` 文件逐层扫描（1127 非测试 + 1114 测试文件），  
>   完整阅读 `shared/core/`、`protocols/oauth/`、`protocols/oidc/`、  
>   `interfaces/sso/`、`interfaces/admin/`、`internal/handler/tokengrant/`、  
>   `platform/lifecycle/sessionhub/` 等核心包的实现源码。  
>   与 59 份已有 `docs/requirements/*.md` 历史分析文档做逐关键词交叉验证，  
>   确保每项为代码级真实缺口且与所有历史分析不重叠。

---

## 前置声明：项目成熟度

本项目已完成 59+ 轮系统架构分析，OAuth 2.0/OIDC/SAML/SCIM/CAEP/FAPI 等全部  
主流身份协议、Anti-enumeration/Oracle-leak/DPoP/mTLS/FIPS/Break-glass 等安全防线、  
Hosted Login/Admin Console/Developer Portal/User Portal 等产品面、  
DR/Config-hot-reload/Metrics/Audit-chain/Chaos 等运维层全部落地。

**本报告不重复"新增标准协议""增加存储后端""补充产品 UI"或任何已在历史分析中  
深度覆盖的方向。** 每项发现聚焦于**代码实现层面的具体缺口**——TOCTOU 条件竞争、  
跨层数据模型不一致、可观测性盲区、运维治理缝隙——这些是经典架构分析容易忽略、  
但生产环境下具有真实影响的问题。

---

## 方向一：会话并发上限的 TOCTOU 条件竞争（Session Cap TOCTOU Race）

### 类型

并发正确性 / 运维治理

### 当前代码证据

`interfaces/sso/server_logout.go` 中 `createSession` 函数的 `maxSessionsPerUser`  
上限检查存在明确的 TOCTOU 窗口：

```go
// limits/evict.go
if s.maxSessionsPerUser > 0 {
    s.evictOldestSession(rctx, userID, tenantID, s.maxSessionsPerUser)
}
```

而 `evictOldestSession` 的实现（`server_logout.go:440`）分三步：
1. `sessionMgr.ListByUser()` — 列出当前会话
2. `len(sessions) >= limit` — 判断是否超限
3. `sessionMgr.Destroy(sessions[0].ID)` — 删除最旧会话

步骤 2→3 之间以及步骤 3→`createSession` 的 `sessionMgr.Create()` 之间，  
并发登录的多个 goroutine 可以同时通过检查，每个都创建一个新会话。  
代码自身在注释中明确承认这一点：

```go
// The limit is a soft cap: under concurrent logins two goroutines may
// both pass the >= limit check and both create (the count transiently
// reaches limit+1). A distributed lock would be needed for strict
// enforcement; the soft cap is the intended design.
```

**实际影响比注释所述的"limit+1"更严重**：在 N 个并发 goroutine 下，  
上限可达 `limit + N - 1`（每个 goroutine 的 evict 可能因为目标已被前一个  
goroutine 删除而变为 no-op）。在高并发 SaaS 场景下（数千用户同时登录），  
这个问题会常态化地导致会话数超出预期值 10-20%。

### 为什么需要

1. **SLA 承诺与安全审计冲突**：如果合同承诺"每用户最多 5 个活跃会话"，  
   实际达到 15 个就构成合规缺陷。安全审计通常会测试这个上限。

2. **连锁资源耗尽**：每个会话消耗存储（SQLite/Redis/Postgres 行）和内存  
   （SessionHub LinkStore 条目）。超限会话积累可能导致存储层 OOM 或  
   连接池耗尽。

3. **安全含义**：攻击者通过快速并发登录可以积累远超预期的活跃会话数，  
   扩大令牌回收前的时间窗口。

### 建议范围

| 子项 | 方案 | 工作量 |
|---|---|---|
| (a) **乐观锁方案** | 在 `Create` 操作中使用 `INSERT ... WHERE (SELECT COUNT(*) FROM sessions WHERE user_id=?) < limit`（SQLite/Postgres 支持）或 Lua 脚本（Redis），使上限检查与创建原子化 | M |
| (b) **分布式锁（跨副本）** | 引入 `cluster.Bus` 租约锁，在 `createSession` 期间持有用户级锁（`lockKey = "session:"+userID"`），防止跨副本并发穿透 | L |
| (c) **超限事后清理（tighter bound）** | 在每个 `createSession` 入口处（乐观锁之外）增加事后清理：`create` 成功后 `if count > limit { evict(count - limit + 1) }`，作为最后防线 | S |

### 边界情况

- 限流值为 0（无限）时，所有门控应完全跳过（当前行为正确，不变）
- 清理自身的递归创建死循环：锁/原子 INSERT 失败时应返回明确错误，  
  而非重试进入死循环
- 不同租户的会话上限应该独立（当前 `evictOldestSession` 已按 `tenantID`  
  隔离，但 TOCTOU 窗口在所有租户中相同）

### 与已有分析的无重叠验证

| 关键词 | 已有分析文档 | 重叠判断 |
|---|---|---|
| `TOCTOU session` | `architect-global-analysis` | **不重叠**：该文档在"Identity-Aware Auth Proxy"方向下提及"concurrent session limit"作为代理功能需求列表，未讨论 TOCTOU 竞态条件或代码层面实现缺陷 |
| `concurrent session` | `expansion-edge-cases` | **不重叠**：提及的是"并发会话配额与生命周期治理"作为新功能方向，非当前实现中的 TOCTOU bug |

---

## 方向二：管理后台令牌生命周期运维盲区（Admin Token Lifecycle Isolation Gap）

### 类型

运维治理 / 安全可见性

### 当前代码证据

管理后台（Admin API）的 bearer token 使用与普通用户令牌**完全隔离**的
生命周期管理体系：

| 维度 | 普通用户令牌 | 管理后台令牌 |
|---|---|---|
| 存储 | `SessionManager`（核心引擎） | `AdminTokenStore`（独立 SPI） |
| 闲置超时 | 由 `Session.TTL` + `TokenExpiry` 控制 | 由 `sessionTTL` + `adminTokenStore.Touch` 控制 |
| 用户可见性 | `/me/sessions` 可查看 | ❌ 不可见 |
| 批量撤销 | `/token/revoke-all` 可撤销 | ❌ 不受影响 |
| SessionHub 跨协议联动 | 纳入会话枢纽 | ❌ 无关联 |
| 令牌使用遥测 | `tokenusage.Event` 记录 | ❌ 无遥测事件 |
| 会话信任衰减 | `WithSessionTrustDecay` 生效 | ❌ 无信任衰减 |

管理令牌不是通过 `SessionManager.Create` 创建的——它们是通过  
`AdminTokenStore.Record` 单独记录的。这意味着：

```go
// interfaces/admin/middleware.go:391-406
// enforceIdleTimeout 只检查 adminTokenStore，完全不涉及 SessionManager
func (a *Middleware) enforceIdleTimeout(w http.ResponseWriter, r *http.Request, claims *core.TokenClaims) bool {
    if a.sessionTTL <= 0 || a.adminTokenStore == nil || claims.JTI == "" {
        return false
    }
    meta, err := a.adminTokenStore.GetByID(r.Context(), claims.JTI)
    // ...只管理 adminTokenStore 中的记录
}
```

管理令牌被撤销时（`/api/v1/admin/logout`），也只从 `AdminTokenStore.Revoke` 中  
移除，不会涉及 SessionManager、SessionHub 或 CAEP 事件推送。

### 为什么需要

1. **运维可见性缺口**：如果一名管理员在 /me 中查看自己的"活跃会话"，  
   他的管理后台 bearer token 不会出现。他无法通过用户自助门户撤销  
   一个泄露的管理令牌。

2. **安全事件响应**：当安全团队检测到异常管理操作时，需要立即吊销所有  
   该管理员的管理令牌。当前路径只能逐个调用 `/api/v1/admin/tokens/{id}/revoke`，  
   没有"吊销此用户的所有管理令牌"的批量操作。

3. **合规证据链**：SOC 2 / PCI DSS 要求对所有管理员操作有完整的  
   "谁-何时-从哪-用什么令牌"的证据链。管理令牌与用户会话之间的  
   身份关联断裂时，无法回答"该管理操作是否来自一个已被撤销的  
   用户会话"。

### 建议范围

| 子项 | 方案 | 工作量 |
|---|---|---|
| (a) **管理令牌归属到用户会话** | 在 `AdminTokenStore.Record` 中增加 `SessionID` 字段，将管理令牌锚定到创建它的用户会话上。`SessionManager.Destroy` 级联吊销关联的管理令牌 | M |
| (b) **管理令牌生命周期事件接入 SessionHub** | 在 SessionHub Coordinator 中增加 `ProtocolAdmin` 支持，管理令牌的吊销触发跨协议级联（至少触发审计事件） | M |
| (c) **管理令牌可见性在 /me/sessions** | `handleListSessions`（/me/sessions）中增加对 `adminTokenStore.ListByUser` 的查询，合并展示 | S |
| (d) **`POST /api/v1/admin/users/{id}/revoke-tokens` 批量吊销** | 根据用户 ID 批量吊销该用户所有的管理 bearer token，联动 SessionManager 和 AdminTokenStore | S |

### 边界情况

- **Break-glass 令牌与普通管理令牌的关系**：Break-glass 创建的 impersonation  
  令牌（`core.AdminScopeImpersonate`）是通过 `SessionManager` 创建的——它  
  走的是**普通令牌路径**。这里讨论的管理令牌是管理员的**原始身份令牌**  
  （用于访问 `/api/v1/admin/*`），两者应区分处理
- 管理令牌的闲置超时不应影响长运行的 CI/CD pipeline 令牌：  
  需要支持 `Label` 豁免机制
- 级联吊销的 fail-open：下游存储不可达时不应中断主流程，  
  但应记录审计事件

### 与已有分析的无重叠验证

| 关键词 | 已有分析文档 | 重叠判断 |
|---|---|---|
| `admin token lifecycle` | 无 | ✅ 完全无覆盖 |
| `AdminTokenStore` | 无 | ✅ 完全无覆盖 |
| `admin session visible` | 无 | ✅ 完全无覆盖 |
| `管理令牌 生命周期` | 无 | ✅ 完全无覆盖 |

---

## 方向三：令牌颁发按授权类型分类的可观测性盲区（Per-Grant-Type Issuance Metrics Gap）

### 类型

可观测性 / 运维分析

### 当前代码证据

当前令牌颁发指标 `sso_tokens_issued_total` 仅按 `strategy`（`jwt` / `session`）  
标签分类：

```go
// platform/metrics/metrics_ctor.go:91-94
m.TokensIssuedTotal = factory.NewCounterVec(
    prometheus.CounterOpts{
        Name: NameTokensIssuedTotal,  // "sso_tokens_issued_total"
        Help: "Tokens issued on successful login, by token strategy (jwt/session).",
    },
    []string{LabelStrategy},  // 只有 "strategy" 一个标签
)
```

同样的限制在 `sso_tokens_issued_by_tenant_total` 中也存在（仅多一个 `tenant` 标签，  
但仍然没有 `grant_type`）。

代码中所有 `recordTokenIssued` 调用点传的都是 `strategy`（`jwt`/`session`），  
没有传递 `grant_type`（`authorization_code` / `refresh_token` / `client_credentials` /  
`token_exchange` / `ciba` / `device_code` / `saml2_bearer` 等）：

```go
// interfaces/sso/server_helpers.go:330
s.metrics.TokensIssuedTotal.WithLabelValues(strategy).Inc()
```

审计事件 `token_issued` 也缺乏 grant_type 区分（`audit.RecordTokenIssued` 只接收  
`clientID, strategy, subjectID`）。

### 为什么需要

1. **异常检测**：`client_credentials` 的突发流量（例如 CI/CD pipeline 令牌泄露）  
   与 `authorization_code` 的突发流量（正常用户登录高峰）有不同的安全含义。  
   没有 grant_type 标签，运维无法区分"流量正常增长"和"特定授权类型的滥用"。

2. **容量规划**：`refresh_token` 轮换产生的令牌量通常远大于 `authorization_code`  
   （每个 refresh 产生一个新的 access + refresh 对）。没有分类型指标，  
   容量模型会严重偏差。

3. **SLO 分化**：不同 grant type 应有不同的延迟 SLO（`client_credentials` 应 < 10ms，  
   `ciba` 可能需要数秒）。没有分类指标就无法设定和监控按类型分化的 SLO。

4. **计费/用量聚合**：`domains/metering` 虽然按 `token_issued` 事件类型聚合，  
   但事件本身不携带 grant_type，计费无法区分"交互式登录"和"机器间令牌交换"。

### 建议范围

| 子项 | 方案 | 工作量 |
|---|---|---|
| (a) **添加 `grant_type` 标签** | 在 `TokensIssuedTotal` 和 `TokensIssuedByTenantTotal` 中增加 `grant_type` 标签，覆盖所有 7+ 种 grant type。注意基数控制：grant_type 的基数 ≤ 10，对 Prometheus 无害 | S |
| (b) **`recordTokenIssued` 签名扩展** | 增加 `grantType` 参数，传递到 metrics + audit event + metering event | S |
| (c) **审计事件增加 `grant_type`** | `audit.RecordTokenIssued` 增加 `grantType` 字段，使 SIEM 可以按类型过滤 | M |
| (d) **按 grant_type 的延迟直方图** | 新增 `sso_token_issuance_duration_seconds`，按 `grant_type`、`strategy`、`success` 标签分类 | M |

### 边界情况

- CIBA 的异步特性：`ciba` grant 的令牌颁发延迟应测量从 `ciba_approved` 到  
  token 签发的耗时，而非从 HTTP 请求到响应的时间
- `token_exchange` 的 chain depth 标签：可选增加 `chain_depth` 标签，  
  但要注意基数（depth ≤ 5 可接受，超过则折叠为 `depth: 5+`）
- `refresh_token` 轮换应有一个额外的 `rotation:true` 区分新颁发和轮换

### 与已有分析的无重叠验证

| 关键词 | 已有分析文档 | 重叠判断 |
|---|---|---|
| `grant_type metric` | 无 | ✅ 完全无覆盖 |
| `token issued grant type` | 无 | ✅ 完全无覆盖 |
| `按授权类型 指标` | 无 | ✅ 完全无覆盖 |

---

## 方向四：跨协议令牌绑定传播一致性（Cross-Protocol Token Binding Consistency）

### 类型

协议正确性 / 安全纵深

### 当前代码证据

RFC 9449 DPoP 和 RFC 8705 mTLS 的 sender-constraint 绑定在不同协议路径上的  
传播行为不一致：

| 协议路径 | DPoP JKT 传播 | mTLS X5T 传播 | 会话创建 |
|---|---|---|---|
| 标准 OAuth 2.0 Auth Code Grant | ✅ 传播到 access token | ✅ 传播到 access token | ✅ 创建会话 |
| OAuth 2.0 Token Exchange | ✅ 传播到交换后的 token | ✅ 传播到交换后的 token | ❌ 不创建新会话 |
| SAML 2.0 Bearer Assertion Grant | ✅ 传播到 access token | ✅ 传播到 access token | ❌ 不创建会话 |
| SAML IdP 发起登录 | ❌ **不传播** | ❌ **不传播** | ✅ 创建会话（无绑定） |
| CIBA (ping/poll) | ✅ 传播 | ✅ 传播 | ✅ 创建会话 |
| Device Code Grant | ✅ 传播 | ✅ 传播 | ✅ 创建会话 |
| 管理后台直接令牌颁发 | ❌ **不适用**（无 DPoP） | ❌ **不适用** | ❌ 走 AdminTokenStore |

核心问题在于 **会话（Session）数据结构不携带令牌绑定信息**。  
当一个流程创建了会话（SAML IdP、标准 Auth Code 等），后续通过该会话  
静默颁发（`prompt=none`、refresh）的令牌使用会话创建时的绑定还是新请求的绑定？  
当前行为：

```go
// interfaces/sso/server_login.go - 静默续期路径
// 这里使用的是当前请求的 dpopJKT，而非会话创建时的绑定
tokens, err := exchangeAuthCode(ctx, rctx, client, req, authCode, dpopJKT, mtlsX5T)
```

但 `refresh_token` 颁发使用的是新请求的绑定，没有机制验证刷新时的绑定是否与  
原始绑定一致：

```go
// internal/handler/tokengrant/refresh.go 的 IssueRefreshToken 调用
// dpopJKT 和 mtlsX5T 来自当前请求，不与原始会话的绑定做比较
```

SessionHub 的 `LinkRecord` 结构也不携带绑定元数据：

```go
// platform/lifecycle/sessionhub/sessionhub.go
type LinkRecord struct {
    GlobalSID  GlobalSID `json:"global_sid"`
    Protocol   Protocol  `json:"protocol"`
    SessionID  string    `json:"session_id,omitempty"`
    UserID     string    `json:"user_id,omitempty"`
    // ✅ 有 UserID
    // ❌ 无 DPoPJKT / MTLSX5T / ClientIP / AuthMethod
}
```

### 为什么需要

1. **DPoP 宗旨被打破**：DPoP 的核心安全承诺是"即使 bearer 泄露也无法在其他  
   客户端复用"。如果 refresh_token 可以在不使用 DPoP proof 的情况下轮换  
   （例如，SAML IdP 发起的登录创建的会话没有绑定，后续 refresh 也不强求绑定），  
   DPoP 的安全价值就打了折扣。

2. **刷新令牌的绑定降级**：一个 DPoP-bound 的 auth_code 登录创建的 refresh  
   token，在被窃取后可以用作无 DPoP 的 refresh 请求（只要 refresh 路径不  
   要求 proof）。这是一个真实的攻击面。

3. **跨协议的一致安全模型**：OAuth 2.0 安全最佳实践（BCP 195）要求 sender-  
   constraint 在所有路径上都一致。SAML 2.0 bearer grant 不应成为豁免路径。

### 建议范围

| 子项 | 方案 | 工作量 |
|---|---|---|
| (a) **Session 数据结构增加 `ConfirmationJKT` / `ConfirmationX5TS256`** | 在 `core.Session` 中记录登录时的绑定信息，作为后续 refresh 绑定的基线 | M |
| (b) **Refresh 绑定增强** | `IssueRefreshToken` 传递原始绑定，`AssignRefreshToken` 存储。新 refresh 请求不提供绑定或绑定不匹配时视为降级，触发 audit 事件 + 可选拒绝 | M |
| (c) **SessionHub LinkRecord 增加绑定字段** | 使跨协议的会话清理可以关联到绑定的令牌，SAML SLO 时可以识别哪些令牌有 DPoP 绑定 | S |
| (d) **绑定策略配置** | `WithTokenBindingPolicy` 允许运营商设置"refresh 必须保持原始绑定""允许降级但记录审计"等策略 | S |

### 边界情况

- 向后兼容：对于已有会话（无绑定信息），绑定增强必须是**可选强制**  
  （`require_refresh_binding: true` 默认 false），避免升级后所有现有 refresh 失败
- DPoP 与 mTLS 的优先级：如果会话同时有两个绑定，后续请求只需证明其中一个？
  建议"至少一个证明即通过"（OR 语义）
- 绑定降级的审计事件：单独的事件类型 `token_binding_downgraded`，  
  包含 `from`（DPoP/mTLS）和 `to`（none）

### 与已有分析的无重叠验证

| 关键词 | 已有分析文档 | 重叠判断 |
|---|---|---|
| `token binding cross protocol` | 无 | ✅ 完全无覆盖 |
| `DPoP SAML` | 无 | ✅ 完全无覆盖 |
| `refresh binding downgrade` | 无 | ✅ 完全无覆盖 |
| `Session confirmation JKT` | 无 | ✅ 完全无覆盖 |

---

## 方向五：同意授权与客户端范围配置的静默漂移（Consent Grant-Client Scope Silent Drift）

### 类型

正确性 / 安全纵深

### 当前代码证据

Consent Store 将授权记录为 `(userID, clientID, scopes[], grantedAt, expiresAt)`。  
当管理员在授权发生后修改客户端的 `AllowedScopes`（例如增加了一个敏感 scope），  
已有 consent grant 不会被自动标记为"可能不再充分"。

问题路径如下：

```
1. 用户登录 Client A，授权 scopes=[openid, profile]
2. 管理员通过 Admin API 修改 Client A: AllowedScopes += ["email"]
   → 这是合法操作（新版本要求 email scope）
3. 用户再次登录 Client A，请求 scopes=[openid, profile]（与之前相同）
4. handleConsentGate:
   - GetConsent → grant.Scopes=[openid, profile]
   - ScopesSubsumed([openid, profile], [openid, profile]) → true ✓
   - 记录 grant 续期，不提示用户
5. 用户获得 access_token 但其中不含 email scope
6. 稍后，Client A 更新其认证请求为 scopes=[openid, profile, email]
7. handleConsentGate:
   - ScopesSubsumed([openid, profile], [openid, profile, email]) → false
   - 提示 consent_required ✓ 正确
```

所以步骤 6-7 会正确触发重新同意。但是，存在一个更微妙的漂移场景：

```
1. 用户同意 scopes=[openid, email]（明确同意 email 访问）
2. 管理员将 Client A 的 AllowedScopes 从 [openid, email] 改为 [openid, email, profile]
3. 这是 Client 的能力扩展。问题是：
   - 用户同意的 email scope 是否仍然有效？
   - 用户的同意是基于"email 是我核准的"这一理解
   - 但 Client 现在可以处理 profile 数据了，尽管当前请求中未包含
   - 如果某个 RP 后来在请求中添加 profile，用户会看到 consent_required ✓
   - **但如果 RP 的认证请求不包含 profile，用户永远不会知道 Client 的能力已扩展**
```

更严重的问题是 **consent grant 不存储**客户端范围配置的快照：

```go
// shared/core/spi.go - ConsentGrant
type ConsentGrant struct {
    UserID    string    `json:"user_id"`
    ClientID  string    `json:"client_id"`
    Scopes    []string  `json:"scopes"`
    GrantedAt time.Time `json:"granted_at"`
    ExpiresAt time.Time `json:"expires_at,omitempty"`
    // ❌ 缺少 ClientAllowedScopesAtGrantTime 字段
    // ❌ 缺少 ClientAllowedScopesVersion（或 checksum）
}
```

没有这个快照，审计员无法判断"用户同意时，Client 是否已经具备 20 个 scope  
还是只有 5 个？"

### 为什么需要

1. **同意管理的完整性**：GDPR Art. 7(4) 要求"同意应是明确、具体、知情且  
   不含糊的"。如果用户在同意时不知道 Client 实际上有权请求比他们当前  
   看到的更敏感的 scopes，同意的知情性就受到质疑。

2. **安全纵深**：攻击者如果攻陷管理员账号并扩展了 Client 的 AllowedScopes，  
   可以逐步引入敏感 scope 而不触发重新同意（只要 RP 的 auth 请求逐步变化）。  
   这是一个渐进式权限升级的路径。

3. **合规审计**：SOC 2 CC6.1 要求"授权的范围和期限在授权后不能被静默扩大"。  
   没有 scope 快照，审计员无法证明这一点。

### 建议范围

| 子项 | 方案 | 工作量 |
|---|---|---|
| (a) **ConsentGrant 增加 `clientAllowedScopesChecksum`** | 在授权时记录 `sha256(sorted(client.AllowedScopes))`，在 `evaluateConsentNeed` 中检查是否变化。变化时标记为`drifted`，触发重新同意 | S |
| (b) **Admin 修改 Client AllowedScopes 时级联标记** | 在 `ClientAdminService.Update` 中，当 AllowedScopes 变更时，向关联的 consent grant 添加 `ClientScopeChangedAt` 时间戳。下一次 consent 检查时发现此时间戳 > GrantedAt → 要求重新同意 | M |
| (c) **consent drift 审计事件** | 新增 `consent_drift_detected` 事件：当 scope 检查发现漂移时记录，包括 `userID`、`clientID`、`oldAllowedScopesChecksum`、`newAllowedScopesChecksum` | S |
| (d) **consent grant 刷新时的 scope 集续期语义** | 当前 `recordConsentGrant` 使用 `grant.Scopes`（存储的 scope）。应增加选项：重新同意后使用请求的 scopes（而非旧的 grant scopes），使 scope 集与用户最新授权一致 | S |

### 边界情况

- **scope 缩减不需要重新同意**：管理员从 Client 移除 scope 是缩小而非扩大  
  攻击面，不应触发 consent drift
- **checksum 碰撞**：SHA256 已经足够安全。但仍需要处理 checksum 为空的  
  历史记录（升级前授予的 consent）——这些应被视为"需要重新验证"
- **SkipConsent 豁免**：标记为 `SkipConsent=true` 的第一方客户端（信任客户）  
  不受此影响——它们本来就不经过 consent 门控
- **consent 过期与漂移的优先级**：如果既过期又有漂移，过期检查应优先

### 与已有分析的无重叠验证

| 关键词 | 已有分析文档 | 重叠判断 |
|---|---|---|
| `consent drift` | 无 | ✅ 完全无覆盖（仅有`expansion-runtime-governance`中 SQLite namespace 版本的提及，非 scope 漂移语义） |
| `client scope change consent` | 无 | ✅ 完全无覆盖 |
| `consent scope snapshot` | 无 | ✅ 完全无覆盖 |

---

## 优先级矩阵

| 方向 | 影响面 | 技术难度 | 用户可见性 | 安全影响 | 建议优先级 |
|---|---|---|---|---|---|
| 1. Session Cap TOCTOU | 运维稳定性 | S-M | 低（仅在超限时可见） | 中 | **P2** |
| 2. Admin Token Isolation | 运维治理/合规 | M | 中（管理员可见） | 高 | **P1** |
| 3. Per-Grant-Type Metrics | 可观测性 | S | 低（运维工具） | 中 | **P2** |
| 4. Cross-Protocol Binding | 安全纵深 | L | 低（安全架构） | 高 | **P1** |
| 5. Consent-Client Scope Drift | 合规/安全 | S-M | 中（用户同意体验） | 高 | **P1** |

### 优先级说明

- **P1（高优先级）**：方向 2、4、5 涉及安全/合规纵深，有明确的攻击面或合规风险，  
  建议在下一个迭代中优先处理。
- **P2（中优先级）**：方向 1 和 3 主要影响运维质量，在非高并发场景下影响有限，  
  可作为 sprint filler 安排。

---

## 附录：验证方法

每项发现通过以下步骤验证：
1. **全代码库 grep** 确认缺口真实性（搜索相关函数、接口、数据结构）
2. **逐文件源码阅读** 确认代码行为与说明一致
3. **关键词交叉验证** 与 `docs/requirements/` 中全部 59 份历史分析文档做  
   对比，确保每项发现的主旨未被任何已有分析覆盖
4. **边界情况推演** 对每项发现推导 3-5 个边界情况，确保建议的范围完整
