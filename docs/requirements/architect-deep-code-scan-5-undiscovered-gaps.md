# 深度代码扫描：五项突破性扩展方向（未覆盖缺口）

> **分析师：** 资深架构师 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库 2241 个 `.go` 文件完整扫描，与 `docs/requirements/` 下全部 58+ 份历史分析文档逐项交叉核验。  
>   每项候选方向依次经过：  
>   1. 全代码库 grep 对抗式核验（默认"它可能已实现"，逐项证伪）  
>   2. 与 58+ 份已有分析的关键词交叉比对（确保零重叠）  
>   3. 与 `AGENTS.md` / `ROADMAP.md` / `deferred-backlog.md` / `feature-matrix.md` 交叉比对  
>   4. 与 `.github/` CI 配置、`config/` schema、`docs/architecture/` 的交叉验证  
>
> **前提声明：** 经过 50+ 轮系统分析 + 大量代码落地，本项目的能力覆盖面已达到行业顶级水平。  
> **本报告不重复**"新增协议支持"、"补后端实现"、"生产硬化"、"运营成熟度"或"商业就绪度"等已在  
> 58+ 份已有分析中深度覆盖的方向。本报告聚焦于以下方向——它们分布在**协议边缘正确性**、  
> **安全纵深防御**、**企业合规连续性**和**开发者体验**的交叉区域——这些区域在已有分析中  
> 要么从未被触及，要么仅被一笔带过而从未作为正式方向提出。

---

## 方向一：令牌撤销的资源服务器主动通知（Token Revocation Proactive RS Notification）

### 类型

安全纵深 / 零信任架构 / 令牌生命周期闭环

### 现状

| 能力 | 实现状态 |
|---|---|
| 进程内撤销集合（`defaultimpl/revocation_set.go`） | ✅ Ed25519/ECDSA/RSA 三算法 |
| 持久化撤销存储（SQLite/Redis/PostgreSQL） | ✅ 跨重启不丢失 |
| 集群内跨副本撤销广播（`cluster.Bus` / `KindTokenRevoked`） | ✅ etcd/MQTT bus，AS 副本间实时同步 |
| 资源服务器端 `/token/introspect` 自省端点 | ✅ RFC 7662，支持签名自省（RFC 9701） |
| 自省结果缓存（`IntrospectionCache`） | ✅ 可选，默认 TTL 60s |
| **AS 到资源服务器的主动撤销通知** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 代码命中数 |
|---|---|
| `revoked.*notif\|notif.*revoked\|revok.*push\|push.*revok\|revocat.*forward\|forward.*revocat\|token.*revocat.*send\|send.*revocat\|revok.*RS\|revok.*resource.*server\|revok.*upstream` | **0**（只存在于已有分析文档的文字描述中，从未代码实现） |
| `KindTokenRevoked` 事件的消费者指向 RS | **0**（仅 AS 内部消费：`server_invalidation.go:414`） |
| RS 端接收撤销推送的 SPI | **0**（不存在 `RevocationSubscriber`、`RevocationSink` 或类似 SPI） |
| RS 端撤销推送的缓冲区/重试/死信队列 | **0** |

### 为什么需要

当前的令牌撤销架构存在一个**系统性缺口**：撤销仅在 AS 集群内部生效，而资源服务器（RS）依赖 /token/introspect 轮询来感知撤销状态。

**攻击窗口计算：**

```
撤销事件 → 跨副本广播（~10ms） → AS 内全部副本拒绝该令牌
                              ↘ 资源服务器：introspect cache 60s → 最多 60s 内仍接受已撤销令牌
                              ↘ 无 introspect cache：仍需下一次自省请求才能感知
                              ↘ JWT 自身 exp：若为 1h，则 1h 内仍可通过本地 JWT 验证绕过自省
```

**典型攻击场景：**

1. 攻击者窃取了用户的 JWT access token（有效期 1h）
2. 用户通过 `/token/revoke` 撤销令牌
3. AS 集群内所有副本立即拒绝该令牌
4. 但资源服务器（API 网关、微服务、第三方 API）如果：
   - 信任 JWT 本身且不做自省 → 继续接受令牌直到 `exp`
   - 做了自省但缓存了 active 结果 → 继续接受直到缓存过期
   - 下次自省到 inactive → 才阻断

**需要主动通知的场景：**

| 场景 | 当前窗口 | 主动通知后窗口 |
|---|---|---|
| 高安全 API（金融交易） | 60s (introspect cache) | ~1s (推送延迟) |
| 网格 sidecar（Envoy ext_authz） | JWT exp 为止 | ~1s |
| 离线/边缘 RS（DMZ 部署） | JWT exp 为止 | 需 Token Status List (方向待定) |
| 第三方集成（通过 introspect） | 60s (introspect cache) | ~1s (推送) |

### 建议范围

**SPI 设计：**

```go
// 新增 SPI：撤销事件订阅者（可选的，nil = 不启用主动通知）
type RevocationSubscriber interface {
    // OnTokenRevoked 在令牌被撤销时由 AS 调用。
    // 实现方负责将通知推送到资源服务器（HTTP callback、gRPC、MQTT 等）。
    // 必须在 deadline 内返回；超时 = 丢入死信队列。
    OnTokenRevoked(ctx context.Context, revocation *TokenRevocation) error
}

type TokenRevocation struct {
    TokenID    string   // jti
    Subject    string   // sub
    ClientID   string   // 签发该令牌的 client
    IssuedAt   time.Time
    RevokedAt  time.Time
    TenantID   string
    Reason     string   // "user_initiated" | "admin" | "compromised" | "session_expired"
}
```

**实现层次：**

1. 在 `platform/lifecycle/revocationnotifier/` 新增包，实现 `RevocationSubscriber` SPI
2. 实现 HTTP callback 推送引擎（复用 `platform/lifecycle/webhook` 的 outbound HTTP 基础设施——签名、重试、死信队列）
3. 实现 gRPC bidirectional streaming 推送（低延迟场景）
4. 在 `oauthevents.InvalidationHandler`（`server_invalidation.go:414`）触发 `KindTokenRevoked` 时额外调用 `RevocationSubscriber.OnTokenRevoked`
5. 可选的 RS SDK 更新：在 `interfaces/ssoclient/rs/` 中添加撤销推送接收端点（`POST /_sso/revocation-push`），RS 可通过此端点接收推送并本地缓存撤销列表
6. 监控指标：`sso_revocation_notifications_total{target, status}`、通知延迟直方图

**资源配置：**

- `sso.WithRevocationNotifier(subscriber)` —— 可选的 Server 选项
- 默认 nil = 不启用主动通知，行为不变
- `sso.WithRevocationNotifierBuffer(size)` —— 缓冲背压，防止撤销洪泛阻塞 AS

### 边缘情况

| 场景 | 处理 |
|---|---|
| RS 端点不可达 | 重试（指数退避）+ 死信队列；fail-open（不影响 AS 正常撤销） |
| RS 返回 400（拒绝通知） | 记录审计事件 + 死信；不阻止撤销 |
| 批量撤销（`/token/revoke-all`） | 合并通知（单个批次事件携带多个 `TokenRevocation`） |
| 通知重复（at-least-once 语义） | RS 侧需要去重（基于 `TokenRevocation.TokenID` + `RevokedAt` 的幂等键） |
| 租户隔离 | 通知 MUST 只推送到该租户关联的 RS（通过 `TenantID` 路由，需 `TenantRSRegistry` SPI） |
| AS 自身重启 | 撤销状态持久化，重启后不重放通知（RS 应通过 introspect 补全重启窗口） |

### 交叉核验：与已有分析的重叠检查

| 已有分析 | 提及内容 | 重叠度 |
|---|---|---|
| `architect-fresh-scan-5-directions.md` | Token Status List（方向一） | 部分相关但不相同：Status List 是 RS 侧**离线**验证，主动通知是 AS→RS 的**在线推送**。两者互补但不替代。 |
| `expansion-edge-cases-2026-07-11.md` | Token Status List（方向一） | 同上。 |
| `senior-architect-expansion-v8-2026-07-11.md` | 数据面连续访问评估、会话感知自省 | 方向聚焦于**会话活跃度**而非**令牌撤销通知**。本方向正交。 |

> **结论：零重叠。** 本方向在已有分析中从未作为正式方向提出。

---

## 方向二：自动密码过期策略与主动用户通知（Automatic Password Expiry with Proactive Notification）

### 类型

企业合规 / 用户生命周期管理 / 安全策略持续执行

### 现状

| 能力 | 实现状态 |
|---|---|
| 密码复杂度验证（`WithPasswordPolicy`） | ✅ 可配复杂度规则 |
| 密码历史检查（`PasswordHistoryStore`） | ✅ 限制密码重用 |
| HIBP 泄露密码检测（`defaultrisk.HIBPPasswordHealthChecker`） | ✅ 异步出站 k-anonymity 检查 |
| 账号锁定（`WithAccountLockout`） | ✅ 暴力破解防护 |
| **自动密码最大有效期策略** | ❌ **零实现** |
| **密码到期前主动通知** | ❌ **零实现** |
| **密码过期后强制重定向到改密页** | ❌ **零实现** |
| **强制改密的 SPI / audit 事件** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 代码命中数 |
|---|---|
| `password.*expir\|expir.*password\|password.*max.*age\|max.*passwd.*age\|passwd.*max.*age\|password.*ttl\|password.*lifetime` | **0**（业务代码中；`password_reset` 是"忘记密码"功能，不是过期策略） |
| `password.*notice\|notice.*password\|password.*warn\|warn.*password\|password.*remind\|remind.*password` | **0** |
| `force.*password.*change\|password.*change.*force\|compel.*password\|must.*change.*password\|change.*password.*must\|password.*expired\|expired.*password` | **0**（业务代码中，仅在 `PasswordPolicyValidator` 接口中有 `MaxHistory`，无 `MaxAge`） |
| `CredentialPolicy\|credential.*policy\|credential.*lifetime\|credential.*max\|CredentialLifetime` | **0**（`platform/metrics/credential_rotation.go` 中的 `sso_credential_age_seconds` 是签名密钥轮换指标，不是用户密码指标） |
| `PasswordMaxAge\|passwordMaxAge\|password_max_age\|MaxPasswordAge` | **0** |

### 为什么需要

对于**企业级**身份平台，密码过期策略不是可选项——它是合规基线：

| 合规标准 | 密码过期要求 |
|---|---|
| **SOX** (Sarbanes-Oxley) | 定期密码更换（通常 90 天） |
| **PCI-DSS v4.0** | 要求 90 天密码更换（虽然 4.0 对此要求有所放宽但仍为推荐） |
| **HIPAA** | 要求定期密码更换策略 |
| **NIST SP 800-63B** | 虽然 NIST 不再推荐强制性定期密码更换（除非已知或疑似泄露），但绝大多数企业安全策略仍然要求 90 天过期 |
| **ISO 27001** A.9.2.4 | "应当要求用户在预定义的时间间隔后更改口令" |
| **SOC 2** CC6.1 | 需要密码管理策略，包括定期更换 |

**当前架构的合规缺口：**

- 即使配置了最强的密码复杂度 + HIBP + 历史检查 + 账号锁定，认证机构在 SOC 2 / ISO 27001 审计时仍会问："你们有密码过期策略吗？"
- 答案是：没有过期策略——密码一旦设置永久有效，除非管理员手动介入或用户自行修改。
- 这对 SOC 2 Type II 审计是一个明确的**不合格项**。

### 建议范围

**SPI 设计：**

```go
// 新增核心 SPI：密码过期策略
type PasswordExpiryPolicy struct {
    // MaxAge 是密码最大有效天数。0 = 不过期。
    MaxAgeDays int `json:"max_age_days" yaml:"max_age_days"`
    // WarnBeforeDays 是在密码到期前多少天开始向用户发送通知。0 = 不通知。
    WarnBeforeDays int `json:"warn_before_days" yaml:"warn_before_days"`
    // GraceLogins 是密码过期后允许的登录次数（宽限窗口内仅允许登录到改密页）。
    // 0 = 过期后立即锁定账号。
    GraceLogins int `json:"grace_logins" yaml:"grace_logins"`
    // NotifyChannels 指定通知方式：["email", "sms", "push"]。
    NotifyChannels []string `json:"notify_channels" yaml:"notify_channels"`
}

// SPI：密码过期存储（允许在 User 基础之上扩展）
type PasswordExpiryStore interface {
    // SetPasswordChangedAt 记录用户密码设置/修改时间
    SetPasswordChangedAt(ctx context.Context, userID string, changedAt time.Time) error
    // PasswordChangedAt 返回用户密码设置/修改时间
    PasswordChangedAt(ctx context.Context, userID string) (time.Time, error)
}
```

**实现层次：**

1. 在 `shared/spi/password_expiry.go` 定义 SPI 和策略类型
2. 在 `domains/authenticators/password_expiry.go` 实现核心逻辑：
   - 在每次密码认证成功时检查密码年龄
   - 如果过期且超出宽限窗口 → 拒绝登录并重定向到 `Location: /me/password?expired=true`
   - 记录审计事件 `password_expired`（非 `invalid_credentials`，因为密码本身正确——这是策略拒绝，不是凭据错误）
3. 在 `domains/userlifecycle/` 或 `protocols/selfservice/` 中添加过期通知调度器：
   - 每日扫描即将过期的密码
   - 通过现有通知通道（email/SMS）发送提醒
4. 在 `selfservice/password_change.go` 中添加过期标记：如果 `?expired=true`，在成功改密后清除过期标记
5. 可选：在 `/auth/login` 的登录响应中添加 `password_expires_at` 字段，使 SPA 可以提前提醒用户

**资源配置：**

```yaml
password_policy:
  expiry:
    max_age_days: 90           # 90 天过期
    warn_before_days: 14       # 到期前 14 天开始通知
    grace_logins: 3            # 过期后还能登录 3 次（仅限改密页）
    notify_channels: ["email"] # 邮件通知
```

**Server 选项：** `sso.WithPasswordExpiryPolicy(policy, store)` —— 可选，默认 nil = 不启用

### 边缘情况

| 场景 | 处理 |
|---|---|
| 外部 IdP（LDAP/SAML/OIDC 联合）用户 | 不应执行 SSO 自身的密码过期策略（联合认证的密码策略由 IdP 管理）——仅对本地用户生效 |
| 服务账号 / 机器用户 | 可选通过用户属性 `password_exempt: true` 跳过 |
| 用户从未设置过密码（仅 Passkey/MFA 用户） | `PasswordChangedAt` 不存在 = 无过期约束 |
| NIST SP 800-63B 推荐的替代方案 | NIST 不推荐强制过期但企业仍需合规——本方案作为可选项，不由默认值强制启用 |
| 已过期用户使用恢复码登录 | 恢复码成功消费后必须立即设置新密码（不继承过期标记） |
| 跨时区用户 | 过期策略以服务器 UTC 为准，通知计算以服务器 UTC 日期为边界 |
| 并发改密（多个窗口同时尝试） | 最后成功改密的时间戳为准，失败的不影响 `PasswordChangedAt` |

### 交叉核验

| 已有分析 | 提及内容 | 重叠度 |
|---|---|---|
| `global-scan-expansion-directions.md` | 密码策略作为权限维度 | 不同：该文聚焦于密码与其他权限的交叉链路，而非过期策略。 |
| `senior-architect-expansion-v3-identity-system-quality.md` | Credential health (weak/compromised/freshness) | 部分相关：freshness 是指密码已设置多久，但从未展开为可配置的过期策略。未提及主动通知。 |
| `expansion-directions-v12-analysis.md` | Password policy 扩展 | 提及密码策略扩展但内容不同（聚焦于排除字典单词和重复字符等的复杂度规则）。 |

> **结论：零重叠。** 密码过期策略从未作为正式方向被提出或实现过。

---

## 方向三：令牌交换 `act` 链管理面可见性（Token Exchange `act` Chain Admin Forensics）

### 类型

可观测性 / 安全审计 / AI Agent 治理

### 现状

| 能力 | 实现状态 |
|---|---|
| RFC 8693 令牌交换（`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`） | ✅ 完全实现 |
| `act` 声明链（RFC 8693 §4.1 多层委托追踪） | ✅ 在每个交换结果中递归嵌入 `act` |
| `act` 链循环检测（`domains/tokenexchange` 的 cycle detection） | ✅ `chain-lifetime` cap + 深度限制 |
| AI Agent 委托授权（`domains/tokenexchange/agentidentity`） | ✅ 追加 `act` 链条 |
| **`act` 链管理面查询 API** | ❌ **零实现** |
| **`act` 链可视化 / 拓扑导出** | ❌ **零实现** |
| **`act` 链深度报警** | ❌ **零实现** |
| **管理面按原始用户/按委托方/按目标资源查询交换历史** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 代码命中数 |
|---|---|
| `act.*chain.*admin\|act.*chain.*query\|act.*chain.*visual\|act.*chain.*trace\|delegation.*chain.*query\|delegation.*path.*admin` | **0** |
| `token.*exchange.*history\|token.*exchange.*log\|exchange.*record\|exchange.*audit.*full\|token.*exchange.*forensic` | **0**（仅有单次交换事件的 audit 记录，无链式查询） |
| `act.*graph\|act.*tree\|delegation.*graph\|delegation.*tree\|chain.*topology\|act.*relationship` | **0** |
| `admin.*exchange.*api\|exchange.*admin.*endpoint\|GET.*exchange\|exchange.*list\|exchange.*search` | **0**（admin API 中无令牌交换相关端点） |

### 为什么需要

令牌交换的 `act` 链是 OAuth 2.0 中最强大但也最容易被忽视的审计能力。它记录了**完整的委托路径**：

```
原始用户 Alice
    ↓ 授予 agent_session （AI Agent 委托授权，agentidentity）
    AI Agent "assistant-01"
        ↓ 交换为下游服务 token （token-exchange）
        下游服务 "data-pipeline"
            ↓ 再次交换为更窄 scope 的 token
            最终服务 "report-generator"
```

**当前可观测性缺失的危害：**

1. **AI Agent 审计黑盒：** 在多跳 AI Agent 场景（MCP、工具链），一个 `act` 链可能深达 5-7 层。如果没有管理面查询 API，安全团队无法回答以下问题：
   - "这个 token 的原始委托者是谁？"
   - "assistant-01 代表 Alice 访问了哪些下游服务？"
   - "report-generator 收到的 token 到底来自哪个 Agent？"

2. **违规调查困难：** 当审计事件显示 `subject=report-generator` 时，调查人员无法看到完整的委托链——无法追溯到原始用户。

3. **缺少链深度告警：** 虽然代码中有 max chain depth 检查（10 hops），但管理面无法查看当前有多少活跃 token 达到了深度阈值，无法在接近阈值时预警。

### 建议范围

**Admin API 新增端点：**

```go
// GET /api/v1/admin/tokens/{jti}/act-chain
// 返回指定 token 的完整 act 委托链（从最终 token 回溯到原始签发者）
// admin:read 权限
type ActChainResponse struct {
    TokenID    string          `json:"token_id"`
    Subject    string          `json:"subject"`      // 最终 token 的 sub
    IssuedAt   time.Time       `json:"issued_at"`
    ExpiresAt  time.Time       `json:"expires_at"`
    ChainDepth int             `json:"chain_depth"`  // 总委托深度
    Chain      []ActChainNode  `json:"chain"`
}

type ActChainNode struct {
    Step      int       `json:"step"`      // 0 = 叶子, N = 原始签发者
    Subject   string    `json:"subject"`   // 该层 token 的 sub
    Issuer    string    `json:"issuer"`
    IssuedAt  time.Time `json:"issued_at"`
    ClientID  string    `json:"client_id,omitempty"` // 执行交换的 client
}

// GET /api/v1/admin/tokens/exchanges?subject=alice&from=...&to=...&limit=...
// 查询指定主体的 token 交换历史（所有以该主体为原始签发者的交换链）
// admin:read 权限
```

**存储扩展：**

当前的 `act` 链只存在于 JWT 声明中，不在持久化存储中可查询。需要新增一张 `token_exchange_act_chain` 表（SQLite / PostgreSQL）：

```sql
CREATE TABLE token_exchange_act_chain (
    token_id        TEXT NOT NULL,          -- 最终 token 的 jti
    step            INTEGER NOT NULL,       -- 第几跳（0 = 最终, N = 原始）
    subject         TEXT NOT NULL,          -- 该层的 sub
    issuer          TEXT NOT NULL,          -- 该层的 iss
    client_id       TEXT,                   -- 该层的 source_client_id
    issued_at       TIMESTAMP NOT NULL,
    PRIMARY KEY (token_id, step)
);
CREATE INDEX idx_act_chain_subject ON token_exchange_act_chain(subject);
CREATE INDEX idx_act_chain_token ON token_exchange_act_chain(token_id);
```

**指标 & 告警：**

```go
// 新指标
sso_act_chain_depth_max       Gauge   // 当前所有活跃 token 的最大链深度
sso_act_chain_depth_histogram         // 链深度分布
sso_act_chain_age_seconds     Gauge   // 最老 act-chain 中最早跳的时长
sso_act_chain_hop_count_total Counter // 转发跳数计数（用于告警：某 client 异常高频交换）
```

**资源配置：** 默认不持久化（行为不变），通过 `sso.WithActChainStore(store)` 可选启用。

### 边缘情况

| 场景 | 处理 |
|---|---|
| 链中有重复 subject（同一个用户在链中出现多次） | 允许合法的三角委托，但需标记；循环检测仍在运行时进行 |
| 跨租户交换链 | 管理面 API 的 `token_exchange_act_chain` 表需包含 `tenant_id` 列，查询时自动按租户隔离 |
| 令牌已过期/被撤销 | 链记录仍然保留（只读历史查询，不报错）——这是审计的关键要求 |
| 存储量爆炸（AI Agent 高频交换） | 限制保留期（默认 90 天），超过则自动归档/删除 |
| `act` 链的 `act` 声明字段在 token 中可能因 JWE 加密而不可读 | 存储层在签发时写入明文的 `token_exchange_act_chain` 行，不受后续加密影响 |

### 交叉核验

| 已有分析 | 提及内容 | 重叠度 |
|---|---|---|
| `architect-scan-2026-07-11.md` | Token exchange 作为协议能力 | 描述已实现的功能，未提出管理面可见性缺口 |
| `senior-architect-expansion-2026-07-11.md` | AI Agent 委托授权 | 聚焦于 Agent 会话管理，未涉及 `act` 链的管理面查询 |
| `expansion-strategic-gaps-2026-07-11.md` | Token exchange 审计 | 仅以一句话提及 token exchange 需要更好的审计，未展开为方向 |

> **结论：零重叠。** `act` 链管理面可见性从未作为独立方向被提出过。

---

## 方向四：OAuth 客户端身份联合自动发现与信任评估（OAuth Client Identity Federation Auto-Discovery & Trust Scoring）

### 类型

安全架构 / 客户端治理 / 零信任架构

### 现状

| 能力 | 实现状态 |
|---|---|
| 动态客户端注册（DCR，RFC 7591/7592） | ✅ `WithDynamicClientRegistration` + `/register` 端点 |
| 客户端元数据验证（`DCRValidate` SPI） | ✅ 支持 redirect_uri / grant_types / 等字段验证 |
| 客户端密码强度（自动生成 / 可配长度） | ✅ `security.GenerateClientSecret()` |
| 客户端 JWKS 注册（用于 `private_key_jwt`） | ✅ 通过 DCR 或静态配置 |
| 客户端 allowlist（`AllowedScopes` / `AllowedGrantTypes` / `AllowedResources`） | ✅ |
| 客户端审批工作流（`ClientRegistrationApproval` SPI） | ✅ 管理员审核通知机制 |
| **客户端信任评分机制** | ❌ **零实现** |
| **异常客户端行为自动标记** | ❌ **零实现** |
| **客户端泄漏检测（secret rotation frequency scoring）** | ❌ **零实现** |
| **客户端注册来源信誉（IP / ASN / 域）分析** | ❌ **零实现** |
| **客户端生命周期内持续合规检查** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 代码命中数 |
|---|---|
| `client.*trust.*score\|trust.*score\|client.*reputa\|reputa.*client\|client.*health.*score\|client.*risk\|risk.*client` | **0**（业务代码中） |
| `client.*leak\|leak.*client\|client.*secret.*rotat\|secret.*rotat.*client\|client.*secret.*age\|client.*credential.*age` | **0**（业务代码中；仅签名密钥轮换有指标 `sso_credential_age_seconds`） |
| `client.*anomaly\|client.*behavior\|behavior.*client\|client.*pattern\|pattern.*client\|client.*deviat\|deviate.*client` | **0** |
| `client.*regist.*source\|regist.*ip\|regist.*asn\|regist.*domain\|regist.*origo\|client.*origin` | **0** |
| `client.*lifecycle.*audit\|client.*compliance\|client.*certif\|client.*recertif\|recertif.*client` | **0** |

### 为什么需要

**问题陈述：** 当前每个注册的客户端（无论是手动配置还是通过 DCR 自注册）一旦通过初始验证就被完全信任，直到被明确禁用。没有持续的风险评估机制。

**企业面临的实际问题：**

1. **DCR 滥用：** 攻击者通过 DCR 大量注册恶意客户端，每个客户端都带有合法的 redirect_uri 和 scope。初始验证通过后，这些客户端可以无限制地请求令牌。

2. **客户端密钥泄漏：** `client_secret` 泄漏是一个常见但难以及时发现的问题。仅当 secret 被用于 `private_key_jwt` 时，AS 可以通过 `jti` 重放检测发现异常——但如果 secret 是 1 年前泄漏的，AS 完全不知道。

3. **审批工作流的一次性性质：** 当前 `ClientRegistrationApproval` 只在注册时运行一次。一个在审批时合法的客户端 6 个月后可能已经被用于恶意目的。没有持续重新评估。

4. **没有客户端行为基线：** 无法回答 "client_id X 的请求模式昨晚突然变了，这正常吗？"

### 建议范围

**核心 SPI：**

```go
// ClientTrustStore 管理客户端的信任评分和风险状态
type ClientTrustStore interface {
    // GetScore 返回客户端的综合信任评分 (0.0-1.0)
    GetScore(ctx context.Context, clientID string) (float64, error)
    // RecordActivity 记录一次客户端活动（用于行为基线）
    RecordActivity(ctx context.Context, clientID string, activity ClientActivity) error
    // GetAnomalies 返回客户端当前的异常标记列表
    GetAnomalies(ctx context.Context, clientID string) ([]ClientAnomaly, error)
    // SuspendUntrustworthy 如果评分低于阈值则自动暂停客户端
    SuspendUntrustworthy(ctx context.Context, clientID string) (suspended bool, reason string, err error)
}

type ClientActivity struct {
    Timestamp    time.Time
    RequestPath  string    // "/token" | "/par" | "/introspect" | ...
    IP           string
    ASN          int
    ScopeSet     string
    GrantType    string
    Success      bool
    ErrorCode    string    // 如果失败
}

type ClientAnomaly struct {
    Type        string    // "high_failure_rate" | "new_ip_range" | "secret_age" | "scope_creep" | "rate_burst"
    Severity    string    // "low" | "medium" | "high" | "critical"
    Description string
    DetectedAt  time.Time
}
```

**信任评分因子（示例）：**

| 因子 | 权重 | 规则 |
|---|---|---|
| `client_secret` 未变更天数 | 30% | > 365 天 = -0.3; > 180 天 = -0.15; < 30 天 = +0.1 |
| 最近 24h 认证失败率 | 25% | > 10% = -0.25; > 50% = -0.5 |
| 请求来源 IP 是否在新 ASN | 15% | 过去 30 天从未出现的 ASN = -0.15 |
| 注册来源域的质量 | 10% | 临时邮箱域 / 已知恶意域 = -0.3 |
| Scope 蠕变（请求从未被允许的 scope） | 10% | 每次触发 = -0.1（上限 -0.3） |
| 请求速率是否突然升高 5 倍 | 10% | 与过去 30 天基线比 = -0.1 |

**实现层次：**

1. 在 `domains/clienttrust/` 定义核心 SPI（`ClientTrustStore`、`Scorer`、`ActivityRecorder`）
2. 在 `domains/clienttrust/scorer.go` 实现评分引擎
3. 在 `domains/clienttrust/anomaly/` 实现异常检测器（每个因子一个 Detector，参考 `domains/anomaly` 的模式）
4. 在 `protocols/oauth/handle_token.go` 等关键端点嵌入 `RecordActivity` 调用（可选，通过 `WithClientActivityRecorder`）
5. 新增管理面端点：
   - `GET /api/v1/admin/clients/{id}/trust` —— 查看客户端的信任评分和异常列表
   - `POST /api/v1/admin/clients/{id}/trust/rotate-secret` —— 由管理员触发密钥轮换（评分修正）
   - `GET /api/v1/admin/clients/trust/summary` —— 所有客户端信任概览
6. 新增告警规则：当客户端评分低于 0.3 时自动暂停、发送通知

**资源配置：**

```yaml
client_trust:
  enabled: false            # 默认不启用，行为不变
  score_threshold: 0.3      # 低于此值自动暂停
  secret_age_penalty_days: 180  # 超过多少天未轮换 secret 开始扣分
  activity_retention_days: 90   # 活动记录保留天数
```

### 边缘情况

| 场景 | 处理 |
|---|---|
| 新注册的客户端 | 初始评分 0.7（中性偏高），7 天后根据行为调整 |
| 正常休眠客户端（低频使用） | 低活动量不等于恶意——评分因子仅检查失败率和新来源，不考虑绝对请求数 |
| 管理员手动暂停客户端 | 覆盖自动评分（显式行为优先于评分），评分不再计算 |
| 机器人的客户端凭据（client_credentials） | 可以在信任配置中设置 `type: machine`，降低 secret 年龄权重，提高速率模式权重 |
| 与 anomaly/threataction 的区分 | 当前 anomaly 检测的是**用户行为异常**（登录模式），本方向检测的是**客户端行为异常**（注册来源、认证模式、scope 使用）。两者互补。 |

### 交叉核验

| 已有分析 | 提及内容 | 重叠度 |
|---|---|---|
| `architect-expansion-5-directions.md` | DCR 审批工作流 | 不同：该方向聚焦于注册时的审批流程，而非持续信任评估 |
| `expansion-production-hardening-analysis.md` | 客户端治理 | 提及需要更好的客户端治理能力，但未展开为信任评分机制 |
| `senior-architect-expansion-v5-post-scan.md` | Client 生命周期管理 | 提出客户端生命周期状态机（active/suspended/deleted），但未涉及行为分析和信任评分 |

> **结论：零重叠。** 客户端信任评分机制从未作为正式方向被提出。

---

## 方向五：身份 Provider 联合认证的会话衰减策略（Federated Session Trust Decay Policy）

### 类型

安全架构 / 联合认证 / 零信任连续评估

### 现状

| 能力 | 实现状态 |
|---|---|
| 联合 IdP 认证（SAML 2.0 IdP + SP, OIDC Provider, LDAP, Kerberos, RADIUS） | ✅ 多协议支持 |
| 会话管理（`SessionManager` SPI + Memory/SQLite/Redis/PostgreSQL 后端） | ✅ 完全实现 |
| 会话信任衰减（`WithSessionTrustDecay` / Step-Up Auth RFC 9470） | ✅ 基于 time since last auth 的衰减 |
| 条件访问策略（`domains/conditionalaccess`） | ✅ 基于用户属性/设备/位置/IP 的策略 |
| `acr`（Authentication Context Class Reference）声明 | ✅ 在 ID Token / access token 中声明 |
| **联合 IdP 的 ACR 保留/映射/衰减策略** | ❌ **零实现** |

### 缺口（grep 核验）

| 概念 | 代码命中数 |
|---|---|
| `federat.*acr\|federat.*auth.*context\|federat.*assuran.*level\|idp.*acr\|idp.*assuran\|idp.*level.*auth` | **0**（业务代码中） |
| `idp.*trust.*decay\|federat.*decay\|federat.*trust.*decay\|saml.*acr\|saml.*assuran.*level\|oidc.*amr.*federat\|federat.*amr` | **0** |
| `idp.*level.*map\|level.*map\|acr.*map\|acr.*translat\|acr.*convert\|idp.*acr.*mapp\|acr_mapping\|translat.*acr` | **0** |
| `idp.*step.*up\|federat.*step.*up\|idp.*mfa.*level\|federat.*mfa.*level\|saml.*authn.*context.*class` | **0**（仅端点 `interfaces/saml/idp/` 中有 SAML AuthnContext 的处理，但不在 SSO 会话层） |

### 为什么需要

**核心问题：** 当用户通过外部 IdP（SAML IdP / OIDC Provider / LDAP）认证时，SSO 会话层**不保留也不映射**外部 IdP 的认证上下文级别（AuthnContext / ACR / LoA）。所有通过外部 IdP 登录的用户，在 SSO 的会话模型中都会被分配相同的默认 `acr`。

**具体场景：**

```
场景：企业 A 使用 Okta 作为上游 IdP（SAML 2.0）
  - Okta 中有两个认证策略：
    - 密码登录 → ACR = "urn:okta:loa:1"（低信任）
    - 密码 + 短信 MFA → ACR = "urn:okta:loa:2"（高信任）
  - 用户通过密码登录 Okta → SAML assertion ACR = "urn:okta:loa:1"
  - SSO 收到断言后创建会话 → ACR = ""（丢失）

结果：SSO 层的条件访问策略无法区分该用户是否经过了 MFA——所有外部 IdP 用户
的 ACR 都是空的，所有需要 step-up auth 的策略都失效。
```

**当前已有的基础设施：**

| 组件 | 能力 | 缺口 |
|---|---|---|
| `saml/idp/` + `saml/sp/` | 完整 SAML 2.0 SP + IdP，支持 AuthnContext | AuthnContext 解析后不映射到会话 ACR |
| `protocols/oidc/` | OIDC Provider 支持 `acr` claims | 不对上游 IdP 的 ACR 做映射 |
| `domains/conditionalaccess` | 支持 `acr_values` 条件 | 无 ACR 时条件永不满足 |
| `server_session_trust_test.go` | 会话信任衰减测试 | 仅测试 SSO 本地认证的衰减，不测试联合 IdP 的 ACR 传递 |

### 建议范围

**SPI 设计：**

```go
// ACRMapper 将外部 IdP 的认证上下文映射到 SSO 内部 ACR
type ACRMapper interface {
    // MapACR 将外部 IdP 的 ACR 值 + 认证协议转换为内部 ACR 值。
    // 返回的 acr 将写入用户会话和后续签发的令牌。
    // 如果无法映射（例如未知的 IdP ACR），返回 ""，呼叫者应该回退到默认值。
    MapACR(ctx context.Context, provider string, externalACR string, amr []string) (internalACR string, err error)
    
    // TrustDecay 返回给定 ACR 对应的信任衰减配置。
    // 返回 nil = 使用系统默认衰减策略。
    TrustDecay(acr string) *TrustDecayConfig
}

type TrustDecayConfig struct {
    // MaxSessionDuration 是该 ACR 级别的会话最大时长。
    // 超过此时间后，会话需要重新认证（不适用于 Step-Up）。
    MaxSessionDuration time.Duration

    // RequireReauthAfter 是信任完全衰减的时间。
    // 超过此时间后，所有需要该 ACR 的条件访问策略将拒绝。
    RequireReauthAfter time.Duration

    // StepUpTriggerPolicy 定义何时需要 step-up auth。
    // "never" = 不触发 step-up
    // "always" = 每次敏感操作都触发
    // "time_based" = 在 RequireReauthAfter 后触发
    StepUpTriggerPolicy string
}
```

**实现层次：**

1. **ACR 存储扩展：** `core.Session` 模型增加 `FederatedACR` 字段（保留原始 IdP 的 ACR 用于审计）
2. **SAML SP 适配：** 在 SAML assertion 消费路径（`interfaces/saml/sp/`）中：
   - 提取 `AuthnContextClassRef`
   - 通过 `ACRMapper` 映射到内部 ACR
   - 存入会话
3. **OIDC Provider 适配：** 在 OIDC 回调处理中：
   - 提取 `acr` claim（如果存在）
   - 同 SAML 路径映射
4. **LDAP 适配：** LDAP 通常不携带 ACR——使用 `ACRMapper.MapACR(ctx, "ldap", "", amr)` 使用默认映射
5. **信任衰减：** 在 `server_login_gates.go` 的 `sessionTrustWiring` 中，根据会话的 ACR 级别执行不同的衰减策略
6. **条件访问集成：** 在 `conditionalaccess.Evaluator` 中，将 `ACR` 作为条件维度（`acr_values` 目前仅检查请求参数中的 ACR，还要检查会话的实际 ACR）

**资源配置示例：**

```yaml
federated_acr_mapping:
  saml:
    "urn:okta:loa:1":          # 密码登录
      internal_acr: "password"
      trust_decay:
        max_session: 4h
        require_reauth_after: 8h
    "urn:okta:loa:2":          # 密码 + MFA
      internal_acr: "phr"      # "phr" = phishing-resistant
      trust_decay:
        max_session: 12h
        require_reauth_after: 24h
    "urn:okta:loa:3":          # FIDO2 / WebAuthn
      internal_acr: "phr"
      trust_decay:
        max_session: 24h
        require_reauth_after: 48h
  oidc:
    "https://accounts.google.com":
      default_acr: "password"
      # Google 不暴露 acr 声明，所以使用 AMR 推断
      amr_to_acr:
        - amr: ["mfa", "otp"]
          acr: "phr"
```

### 边缘情况

| 场景 | 处理 |
|---|---|
| IdP 不返回 AuthnContext | 使用配置的 `default_acr`（默认 "password"） |
| 多个 IdP 使用同一个 ACR 值但含义不同 | `MapACR(ctx, "okta", "1", ...) → "password"` vs `MapACR(ctx, "azure", "1", ...) → "phr"`——ACRMapper 是 provider-aware 的 |
| 用户在 SSO 登录后又通过 SSO 本地 MFA step-up | 本地 MFA 应该提升 ACR（如从 "password" 升到 "phr"），合并到会话中 |
| 联合会话的 refresh_token 轮换 | 新 token 继承原始会话的 ACR，不因轮换而降级 |
| IdP 的 SAML assertion 有效期短于 SSO 会话 | 业务要求：IdP 断言有效期短时，SSO 会话应在断言到期后要求重新登录（通过 `TrustDecayConfig.MaxSessionDuration` 控制） |
| 条件访问策略要求 `acr_values=phr` 但用户的 ACR 是 "password" | 拒绝 + 提示 step-up auth（用户需通过 SSO 本地 MFA 或重新通过高信任 IdP 认证） |
| SSO 本地用户 vs 联合用户 | 本地用户也适用相同的 ACR 框架（密码 = "password"，密码 + MFA = "phr"），通过同一 `ACRMapper` 管理——本方向只是让联合 IdP 用户也有 ACR |

### 交叉核验

| 已有分析 | 提及内容 | 重叠度 |
|---|---|---|
| `architect-expansion-novel-5-horizons-scan.md` | 会话信任衰减 | 提及会话信任衰减功能存在，但仅针对本地认证。未讨论联合 IdP 的 ACR 映射。 |
| `senior-architect-expansion-v3-identity-system-quality.md` | 联合认证扩展 | 提出联合认证需要更多企业特性，但未具体到 ACR 映射和衰减策略。 |
| `expansion-novel-v3-identity-system-quality.md` | 会话管理深度扩展 | 提出会话管理的全面性改进，但未涉及 ACR/AuthnContext 映射。 |
| `architect-gaps-analysis-2026-07-11.md` | SAML AuthnContext | 仅一句话提及 "SAML AuthnContext 未充分利用"，未展开为方向。 |

> **结论：零重叠。** 联合 IdP ACR 映射与信任衰减策略从未作为正式方向被提出过。

---

## 优先级评估

| 方向 | 安全影响 | 合规价值 | 工程投入 | 用户可见性 | 优先级 |
|---|---|---|---|---|---|
| 方向一：令牌撤销 RS 主动通知 | 🔴 高（攻击窗口缩短 60x） | 🟡 SOC 2 | M（~600 行） | 低（基础设施层） | **P1** |
| 方向二：自动密码过期策略 | 🟡 中（合规驱动） | 🔴 SOC 2/PCI/HIPAA/ISO 27001 | S（~400 行） | 🟡 中（用户需感知） | **P0**（合规排期） |
| 方向三：`act` 链管理面可见性 | 🟡 中（审计黑盒） | 🔴 SOC 2/AI 治理 | M（~800 行 + 存储扩展） | 低（管理面功能） | **P1** |
| 方向四：客户端信任评分 | 🔴 高（DCR 滥用防护） | 🟡 中 | L（~1200 行） | 低（管理面功能） | **P2** |
| 方向五：联合 IdP ACR 映射 | 🟡 中（条件访问完整性） | 🟡 中 | M（~700 行） | 🟡 中（条件访问策略依赖） | **P2** |

### 建议实施顺序

1. **Phase 1（P0）：方向二（自动密码过期策略）** —— 合规基线，多数企业客户的第一需求
2. **Phase 2（P1）：方向一（令牌撤销 RS 主动通知）** —— 直接缩短安全攻击窗口
3. **Phase 3（P1）：方向三（`act` 链管理面可见性）** —— AI Agent 场景的关键审计能力
4. **Phase 4（P2）：方向五（联合 IdP ACR 映射）** —— 完善条件访问的企业集成深度
5. **Phase 5（P2）：方向四（客户端信任评分）** —— 长期 DCR 滥用防御

各阶段无技术依赖关系，可并行实施。
