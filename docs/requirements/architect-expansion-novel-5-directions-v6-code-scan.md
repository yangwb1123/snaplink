# 代码库全局扫描：五项未覆盖的高价值扩展方向

> **分析师：** 资深架构师 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库 2241 个 `.go` 文件、~200 个包、12 个嵌套子模块完整扫描。  
>   与 65+ 份已有 `docs/requirements/*.md` 历史分析文档做交叉验证 + 对抗式 grep 核验，  
>   确保每项为代码级真实缺口、且与历史分析不重叠。

---

## 前置声明：项目成熟度评估

本项目经 50+ 轮系统架构分析，能力覆盖面已达行业顶级水平。现有 `docs/requirements/` 下  
65+ 份分析文档、`docs/ROADMAP.md` v5.0（覆盖 5 大方向 37 子项）、以及  
`docs/deferred-backlog.md`（33 项中 31 项已落地），均已极其详尽。

**核心结论：** 本项目已不存在"缺少某标准协议"或"缺少某存储后端"这类传统缺口。  
剩余高价值方向聚焦于 **全球多活架构**、**外部依赖韧性**、**限流覆盖完备性**、  
**部署验证门禁**、以及 **令牌链式溯源合规**。

---

## 方向一：多区域主动-主动复制架构（Global Active-Active）

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| 租户数据驻留（Tenant Residency） | ✅ | `domains/region/` + `domains/tenant/` — 写入时按 `home_region`/`allowed_regions` 检查 + 拒绝 |
| 集群失效总线（Invalidation Bus） | ✅ | `platform/cluster/` (etcd/redis/mqtt) — 跨副本缓存失效 + 撤销广播 |
| JWT 签名公钥跨副本聚合 | ✅ | `platform/signingkeys/` — 各副本发布自身公钥，采纳对端，JWKS 服务全集 |
| 无领导多副本协调（Leaderless） | ✅ | 签名轮换 deadline 协调 + peer-key adoption |
| **跨区域数据复制（Data Replication）** | ❌ | **不存在** — 没有任何 store 实现了跨 region 的主动数据同步 |
| **全局读本地 + 写转发（Read-Local / Write-Forward）** | ❌ | **不存在** — 每个 region 的存储层完全独立运行 |

### 为什么需要

**全球部署的 SaaS / 企业客户要求数据驻留在指定区域，同时期望平滑的跨区域体验。**  
当前架构中每个 region 是一个完全独立的 SSO 部署实例——`cluster.Bus` 的 pub/sub 仅用于  
缓存失效和令牌撤销广播（`KindTokenRevoked`、`KindSigningKeyRotation` 等），**不承载  
任何用户/客户端/会话/授权码等业务数据的跨区同步**。

这意味着：
1. **用户在 region A 登录 → 授权码仅在 region A 的存储中 → `/token` 请求必须回 region A**  
   （要么通过 DNS/ingress 路由，要么跨区转发——但转发机制不存在）
2. **用户在 region A 注册的 WebAuthn 凭证 → region B 无法认证**（除非共享同一数据库后端）
3. **Region A 的管理员创建新客户端 → region B 几秒内不可见**（无复制，只有可选的缓存失效广播）
4. **数据库后端子类（PostgreSQL）本身支持流复制，但 SSO 应用层不知晓**——  
   在 follower 上执行写入会失败，读请求可能读到过期数据

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| 复制拓扑声明（`ReplicaRole`：Leader / Follower / ReadReplica） | M | 无 |
| 写转发中间件（写操作检测 + 转发到 leader） | L | 拓扑声明 + gRPC 跨区连接 |
| 读一致性级别声明（`ReadConsistency`：Local / Leader / Monotonic） | M | 拓扑声明 |
| Store SPI 扩展（`ConsistentStore` 包裹现有 SPI + 一致性要求） | L | 以上全部 |
| 跨区延迟监控 + 读倾轧断路器 | M | 一致性级别 + metrics |

### 关键设计决策

- **不重新发明复制层：** 对于 PostgreSQL 后端，利用其原生流复制 + SSO 应用层  
  `ReplicaRole` 感知即可。对于内存/SQLite 后端（嵌入式部署），保持单 region 语义。
- **写转发协议：** 当 follower 收到写请求（如 `POST /admin/clients`）时，通过  
  gRPC inter-region 连接将其转发到 leader，等待确认后回复客户端。读请求默认本地。
- **最终一致性窗：** `cluster.Bus` 已提供跨副本即时通知通道——写入 leader 后立刻  
  广播缓存失效，将 follower 的 stale 窗口从 "复制延迟" 压缩到 "网络 RTT + 处理时间"。
- **不碰现有 SPI：** 以上扩展通过新的 `sso.WithReplicationTopology` 选项 +  
  可选的中间件层实现，不影响现有单 region 部署的字节级兼容性。

---

## 方向二：外部依赖韧性工程（Circuit Breaker & Bulkhead Isolation）

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| 指数退避重试（Exponential Backoff） | ✅ | MFA push webhook、CAEP 推送、federation fetch、部分 KMS signer |
| 请求超时（Request Timeout） | ✅ | 大多数 HTTP client 设定了 `Timeout: 5-30s` |
| **熔断器（Circuit Breaker）** | ❌ | **零命中** — `grep -rn "circuit\|CircuitBreaker\|breaker"` 无匹配 |
| **舱壁隔离（Bulkhead / Semaphore）** | ❌ | **零命中** — `grep -rn "bulkhead\|semaphore.*acquire\|Bulkhead` 仅 SAML fanout 有一处（功能不同） |
| **线程池隔离（Thread Pool Isolation）** | ❌ | **不存在** — 所有外部依赖共享同一 goroutine 池 + 连接池 |
| 优雅降级（Graceful Degradation） | ✅ | 部分路径有（JTI replay fail-open、CAEP 发送 best-effort） |

### 为什么需要

**SSO 服务器是身份基础设施的核心节点，其外部依赖面极广且多样：**

| 依赖 | 延迟特征 | 故障模式 | 当前保护 |
|------|---------|---------|---------|
| KMS 签名（AWS KMS / GCP KMS / Azure KeyVault） | 5-50ms | 限频、超时、不可用 | 重试 + LRU 缓存 |
| SAML IdP 断言验证 | 100-500ms | IdP 下线、证书过期 | 重试 |
| Federation fetch（OpenID Federation） | 50-200ms | 目标不可达、DNS 劫持 | 有限缓存 |
| CAEP/SSF webhook 推送 | 20-100ms | RP 接收器不可达 | 重试 + backoff |
| etcd watch / lease | 实时 | 分区、leader 变更 | ROADMAP v5 §4 已识别 |
| 外部 IdP（OIDC Federation） | 200-1000ms | 上游不可达、令牌过期 | 无熔断 |
| 邮件 SMTP 发送 | 100-500ms | SMTP 服务器不可达 | 有限重试 |

**当前状态的问题：** 任何一个外部依赖变慢或挂起，会消耗共享的连接池和 goroutine，  
导致整个服务器吞吐量下降——即"一个慢 KMS 搞垮整个 SSO"的场景。  

具体攻击面：
- **无熔断：** KMS 限频后持续重试 → 请求排队堆积 → 内存增长 → OOM
- **无舱壁：** 慢 SAML IdP 占用所有 HTTP 连接 → 正常 OAuth 登录也被阻塞
- **无 fallback：** KMS 不可用时可降级到进程内本地密钥签名（当前任何签名失败 = 500）

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| `CircuitBreaker` SPI + 通用实现（滑动窗口/失败率） | M | 无 |
| `Bulkhead` 实现（有界信号量 + 等待队列 + 超时） | M | 无 |
| KMS client 接线熔断 + 本地 fallback 签名 | M | 以上 + `cryptosigner` seam |
| SAML IdP federation fetch 熔断 | S | 以上 |
| CAEP webhook 推送熔断 | S | 以上 |
| 熔断状态可观测（prometheus + `/readyz`） | S | `platform/metrics` + `server_health.go` |

### 关键设计决策

- **渐进式采用：** 先接线已有重试/超时的路径（KMS、CAEP webhook），再扩展  
  到尚未保护的路径（federation fetch、SAML SP 出站请求）。
- **fail-open 分层：** 熔断时按路径语义决定是 fail-open（CAEP 推送可丢）还是  
  fail-closed（令牌签名绝不能降级到不安全的本地密钥）。默认 fail-open。
- **复用现有 seam：** `shared/security/upstream_client.go` 已是当前 HTTP client  
  的抽象点——在此之上包裹 `CircuitBreakerRoundTripper` 即可全局生效。
- **不引入新依赖：** 手搓有界滑动窗口熔断器（~100 行），不引入 hystrix-go /  
  resilience4j 等外部库。

---

## 方向三：限流覆盖完备化——填补管理面 / DCR / 用户自助面空白

### 当前状态

现有的限流基础设施（`interfaces/ratelimit/`）功能完整——支持 per-IP、per-client_id、  
per-endpoint 限流，SQLite + Redis + 内存三种后端，且可通过 `WithRateLimit` 选项  
和动态策略热加载配置。但**覆盖面有显著空白**：

| 端点 / 区域 | 有限流？ | 当前保护 |
|-------------|---------|---------|
| `/token` (OAuth 令牌) | ✅ | 完整 per-IP + per-client |
| `/auth/login` | ✅ | 完整 per-IP + per-account lockout |
| `/token/introspect` | ✅ | 完整 |
| `/token/revoke` | ✅ | 完整 |
| `/par` | ✅ | 完整 |
| `/register` (DCR) | ❌ | **完全无保护** — 任何 IP 可无限制注册客户端 |
| `/register/:id` (DCR 管理) | ❌ | **完全无保护** |
| `/admin/*` (gRPC + REST admin) | ❓ | `admin/middleware.go` 有独立的 `rate.NewLimiter`，但**未接入统一限流策略** — 不与 `ratelimit.PolicyStore` 联动，热加载不覆盖 |
| `/me/*` (自助门户) | ❌ | **完全无保护** |
| `/device/*` | ✅ | 完整 |
| `/auth/mfa` | ❓ | 部分 — per-session 有限流但无 IP 级 |
| `/userinfo` | ❓ | 无显式限流（靠整个 server 的全局限流） |
| `/end_session` | ❓ | 无显式限流 |
| `/backchannel-authentication` (CIBA) | ✅ | 完整 |
| `/.well-known/*` (Discovery) | ❌ | **完全无保护** |

### 为什么需要

**限流空白是严重的安全和运维风险：**

1. **DCR（`POST /register`）无限流：** 攻击者可批量注册数千个恶意客户端，
   耗尽存储资源、污染 client 列表、或用于钓鱼重定向。且 DCR 返回 `client_secret`——
   每个 secret 都是潜在的攻击面。当前的唯一保护是 `client_registration.enabled`
   开关（全开或全关），无法对特定 IP 或速率做微调。

2. **管理 API 限流未接入统一策略：** `admin/middleware.go` 的 rate limiter 是
   独立的 `rate.NewLimiter`（Go 标准库的令牌桶），**不与 `WithRateLimit` 的
   动态策略联动**——操作者改 `security.rate_limit.*` 配置不影响管理 API，
   必须重启或手工调用 `SetRateLimit`。默认值也未被设置（`nil` = 无限流）。

3. **自助端点无限流：** `/me` 系列端点（会话列表、授权应用、Passkey 管理）  
   可被用于枚举用户绑定信息。虽非凭证泄漏，但违反了最小信息暴露原则。

4. **Discovery 端点无限流：** `/.well-known/*` 虽只返回公开信息，但响应体大  
   （含完整 JWKS），无保护的频繁请求可放大出站带宽——是 SSRF 放大攻击的候选。

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| DCR 端点限流接线 | S | 现成 `ratelimit.Middleware` |
| Admin API 限流接入统一策略 | M | `config/reload` + `ratelimit.PolicyStore` |
| `/me/*` + `/userinfo` 限流 | S | 现成中间件 |
| `/.well-known/*` 限流 | S | 现成中间件 |
| per-subject 限流（KeyBySubject） | M | `ratelimit` SPI 扩展（已有 IP / client_id key） |
| per-realm 限流文档 + 默认值 | S | 无 |

### 关键设计决策

- **统一策略面：** 将 admin middleware 的独立限流域合并到 `ratelimit.PolicyStore`，  
  使得 `security.rate_limit.*` 的动态热加载覆盖所有端点。
- **DCR 限流默认值：** 默认 10 req/min per IP（比 `/token` 的 100 req/min 更保守），  
  因为 DCR 是创建性操作且返回敏感凭据。
- **per-subject 限流：** 新增 `KeyBySubject(ctx) string` 给 `Policy` SPI，  
  让限流能以用户级别的粒度工作（适用于 `POST /auth/login` 的跨 IP 同账号场景）。
- **不做启发式：** 不引入基于 ML 的行为限流——那是 `domains/anomaly` 的领域，  
  限流层只做清晰、可解释、可配置的速率阈值。

---

## 方向四：部署前配置验证门禁（CI/CD Config Validation Gate）

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| YAML 配置文件解析 + 默认值 | ✅ | `config/` 完整实现 |
| JSON Schema 生成 + CLI 验证 | ✅ | `sso-ctl config validate-schema` |
| 配置热加载（SIGHUP） | ✅ | `config/reload` — rate limit + feature gates |
| 跨集群配置差异比较 | ✅ | `platform/configaudit/` |
| **CI/CD 集成部署前验证** | ❌ | **不存在** |
| **版本-模式校验（Schema Version Pin）** | ❌ | 验证器不检查当前二进制版本的模式版本 |
| **环境差异检测（Config Diff Against Environment）** | ❌ | 无"这份配置 vs 生产环境当前配置"的比较 |
| **破坏性变更检测** | ❌ | 无"从旧配置切换到新配置时哪些字段会丢失数据" |

### 为什么需要

**SSO 是身份关键基础设施，配置错误可导致完全停机或安全绕过。**  
当前 `sso-ctl config validate-schema` 仅检查基础结构（字段类型、必需字段），但：

1. **不检查版本兼容性：** 某字段在 v5.0 是 `string` → v5.1 改为 `[]string`。  
   旧二进制 + 新配置文件会静默出错。Schema 验证器不应只检查"格式正确"，  
   还要检查"此二进制版本支持此模式版本"。

2. **不检查运行时依赖：** 配置声明了 `saml.enabled: true`，但 SAML 子模块  
   未在构建中包含（`infrastructure/saml/` 是嵌套模块，可能在 binary flavor 中省略）。  
   验证器可检查 `buildinfo` 中注册的能力列表。

3. **不检查逻辑一致性：** 配置开启了 `client_registration.enabled` 却未设置  
   `client_registration.default_active` 或未配置 `ClientStore` 后端。  
   当前只在场级别检查（store nil = 501），不发出部署前警告。

4. **无法作为 CI 门禁：** 没有 `sso-ctl config validate --ci --version v5.0 --strict`  
   这类模式——它应：
   - 退出码非零时阻止部署
   - 输出机器可读的 JSON 报告（供 CI 系统解析）
   - 可选择性地比较生产环境当前配置（从 running endpoint 获取）

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| `--ci` 模式 + 严格验证级别 | S | 现有 schema 验证器 |
| `--version` 版本兼容矩阵 | M | `buildinfo` + schema version registry |
| 能力注册表（`sso.WithFeature(name, checker)`） | M | `buildinfo` |
| `--diff-from-url` 比较环境差异 | M | `platform/configaudit` 现有 diff |
| CI 集成文档 + GitHub Actions 示例 | S | 以上全部 |
| 破坏性变更检测（Migration Safety Check） | L | schema version history + field lifecycle |

### 关键设计决策

- **渐进式采用：** 第一阶段（S）只加 `--ci` 模式和退出码；第二阶段（M）加  
  版本兼容检查；第三阶段（L）加破坏性变更检测。
- **不重新发明版本管理：** 利用现有 `config/schema` 的反射式 JSON Schema 生成 +  
  `migrate.CurrentVersion` 的 database schema 版本概念，扩展到配置文件 schema 版本。
- **能力注册：** 每个 `With*` 选项在注册时调用 `buildinfo.RegisterCapability(name)`，  
  验证器查询 `buildinfo.Capabilities()` 检查配置声明的依赖是否已构建。
- **安全性：** `--diff-from-url` 需要管理员 bearer token（复用现有 admin auth），  
  且 diff 结果经过 `RedactOps`（现有功能）过滤，不泄露敏感字段值。

---

## 方向五：令牌链式溯源与全生命周期合规追踪（Token Lineage & Chain of Custody）

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| 审计事件记录（Audit Events） | ✅ | `platform/audit/` 完整事件系统，覆盖 admin / auth / token / session 事件 |
| 令牌用量遥测（Token Usage Telemetry） | ✅ | `domains/tokenusage/` — Off-path、有界队列、按 kind/endpoint 聚合 |
| Token Exchange act 链追踪 | ✅ | RFC 8693 的 `act` claim 链 + `WithMaxTokenExchangeChainLifetime` |
| **通用令牌链式溯源（谁 → 用什么令牌 → 请求了什么新令牌）** | ❌ | **不存在** — `tokenusage` 不记录授权关系，审计事件不关联令牌指纹 |
| **令牌全生命周期视图（令牌从 mint 到 expire/revoke 的完整路径）** | ❌ | **不存在** — 审计事件可独立查询，但无"一枚特定令牌的完整旅程"视图 |
| **合规导出（按令牌、按用户、按客户端的完整图谱）** | ❌ | **不存在** — `auditexport` 按时间范围 + 事件类型导出，不关联令牌链 |

### 为什么需要

**在受监管行业（金融、医疗、政府）中，"谁在何时、用什么授权、获取了什么令牌、  
用于什么目的"的完整证明链是合规审计的核心要求。** 当前架构的局限：

1. **无令牌级关联：** 审计事件记录"用户 X 通过客户端 Y 获得了访问令牌"，  
   但令牌的 `jti` 不记录在事件中。token usage 记录令牌指纹但不记录授权来源。  
   两者无法关联到一个令牌的完整生命周期。

2. **Token Exchange 链只有 act claim：** `act` 链只在令牌本身的 JWT claim 中——  
   一旦令牌过期或被撤销，链信息丢失。审计系统无法重演"应用 A 用会话令牌 S 换取  
   了令牌 T1，然后用 T1 作为 `actor_token` 换取 T2 给下游服务 C"的全过程。

3. **合规导出不完整：** GDPR 的"可携带性"（Article 20）要求导出用户的完整数据——  
   对于 SSO，应包括该用户授权了哪些客户端、获取了哪些令牌、令牌在哪些端点使用过。  
   当前 `selfservice.HandleExport` 只导出用户基本信息 + 已授权应用（consent），  
   不包含令牌使用历史。

4. **没有令牌吊销/过期回告：** 一枚令牌被吊销时，无法追溯它通过 token exchange  
   衍生出的所有下游令牌。当前 `RevokeAcrossIssuers` 只吊销原始令牌，不级联。

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| `TokenEvent` SPI + 持久层（事件 = 令牌生命周期的不可变日志） | L | `platform/audit` 事件模型 |
| 令牌 mint/use/refresh/exchange/revoke 事件注入 | M | 以上 + 所有令牌签发/消费点 |
| `tokenusage.Recorder` 扩展，增加 `AuthorizingTokenJTI` 字段 | S | 以上 |
| 令牌族谱查询 API（`GET /admin/tokens/{jti}/lineage`） | M | 持久层 + gRPC |
| 合规图谱导出（`GET /admin/users/{id}/token-graph`） | M | 族谱 API |
| 级联吊销（Cascade Revoke on Token Exchange Chain） | L | 族谱 API + `RevokeAcrossIssuers` |

### 关键设计决策

- **审计事件作为底层存储：** 不新建数据库表——令牌生命周期事件作为新的事件类型  
  写入现有 `audit.Store`，用 `trace_id` 和令牌 `jti` 做关联键。查询层在其上  
  做聚合和关系构建。
- **不阻塞热路径：** 使用异步事件队列（类似 `tokenusage.Recorder` 的 Offer + drain  
  模式），令牌签发/消费的溯源事件绝对不能增加请求延迟。
- **隐私保护：** 令牌族谱 API 只返回 `jti`、事件类型、时间戳、关联的 `client_id`、  
  `subject`——**绝不返回令牌本身的值或 secret**。
- **级联吊销为可选：** `WithCascadeRevocation(enabled)` 默认关闭。开启时，在  
  `/token/revoke` 或 `SessionManager.Revoke` 后递归查询令牌族谱，吊销所有  
  衍生的下游令牌。这是对当前"只吊销一个令牌"的安全增强，但有性能和正确性成本。

---

## 优先级建议

```
P0 │ 方向一（多区域主动-主动） ── 全球客户的门槛需求，影响架构级决策
   │
P1 ├ 方向二（外部依赖韧性）   ── 防"一个慢依赖搞垮整个 SSO"
   ├ 方向三（限流覆盖完备化） ── 填补 DCR / admin 安全空白
   │
P2 ├ 方向四（配置验证门禁）   ── 提升部署信心，减少人为失误
   └ 方向五（令牌链式溯源）   ── 受监管行业合规刚需，复杂度高
```

- **方向一** 和 **方向二** 是架构级的韧性投资——前者解决全球规模的正确性问题，  
  后者解决外部依赖的弹性问题。两者都应在下一阶段优先启动。
- **方向三** 是安全速赢项——DCR 限流接线仅需 ~50 行改动，但消除了一个显著的  
  攻击面。
- **方向四** 是运维质量提升——CI 门禁是"防患于未然"的投入，回报在避免生产事故。
- **方向五** 复杂度最高，适合作为长期合规工程投入，与现有审计系统协同演进。

---

## 与现有分析不重叠声明

以上五项方向经逐项 grep 核验，与现有 `docs/requirements/` 下 65+ 份分析文档  
无重叠：
- **方向一（多区域主动-主动）** — ROADMAP 的 §④ 聚焦"多副本数据面韧性"（总线  
  健壮性、schema 护栏、签名密钥 lease 死亡），不涉及跨区域数据复制和拓扑感知
- **方向二（外部依赖韧性）** — 未被任何已有分析文档覆盖；ROADMAP 提到 KMS 延迟  
  特征但决策为"进程内 LRU 缓存 + 拉长 TTL"，未讨论熔断/舱壁
- **方向三（限流覆盖完备化）** — ROADMAP 的 §⑤ 性能清单提到 `MemoryLimiter`  
  的 O(N) prune 和 per-subject 限流，但未触及 DCR / admin API / self-service 的  
  限流空白
- **方向四（配置验证门禁）** — 无任何已有分析文档覆盖 CI/CD 集成视角
- **方向五（令牌链式溯源）** — `docs/error-codes.md` 有 `ErrTokenLineageNotFound`  
  占位符但无实现；ROADMAP 的 §③ OIDC 一致性和 `tokenusage` 均不涉及令牌族谱/级联吊销

