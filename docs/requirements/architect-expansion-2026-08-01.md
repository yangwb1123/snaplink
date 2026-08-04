# 架构扩展分析：基于当前代码库的高价值方向

> 分析日期：2026-08-01
> 方法：对当前工作树做一次全局扫描（`interfaces/`、`protocols/`、`domains/`、`infrastructure/`、`platform/`、`shared/`、`test/`、`docs/`），以可执行代码和已提交契约为证据基线。本文只做分析与需求方向论证，不含实现代码。
> 定位：本文是需求/分析意图，不是已实现功能的承诺。功能现状以 [feature-matrix.md](../feature-matrix.md) 与 [deferred-backlog.md](../deferred-backlog.md) 为准。

## 0. 现状基线

当前代码库在协议面（OAuth 2.0 / OIDC / FAPI / CIBA / PAR / JAR / DPoP / mTLS / token-exchange / CAEP-SSF / SAML / SCIM / WebAuthn）与平台面（多租户、条件访问、ITDR、计量、通知、SSE、gRPC 管理面、DR 快照、混沌/HA 测试、k6 负载测试、基准门禁）均已高度成熟。`docs/requirements/` 下已有 150+ 份历史分析文档，其中若干方向（后量子算法迁移、Redis 分布式限流、缓存观测指标等）已被识别。

因此本文刻意选取**历史分析未充分覆盖、且在当前代码中有直接证据**的方向。每个方向均给出：为什么需要、代码证据、边界情况、建议落地形状（设计方向）、优先级与规模估计。

选择标准（四个维度加权）：

1. **正确性/安全影响 × 爆炸半径**：是否会造成静默漂移、越权或计费失真；
2. **运营成本**：是否随租户/会话/副本数量线性恶化；
3. **产品差异化**：是否直接改善终端用户或企业客户的可用价值；
4. **与既有承诺的冲突**：不得与 feature-matrix / deferred-backlog / ROADMAP 中已声明或已规划的能力重复。

---

## 1. 租户配额与计量的持久化、跨副本一致性（治理正确性 + 计费准确性）

### 为什么需要

租户配额是**被强制执行的治理边界**（超限返回 `403 quota_exceeded`），而当前 `core.TenantQuotaStore` 的实现只有内存版 `MemoryTenantQuotaStore`（`infrastructure/defaultimpl/memorystoreidentity/memory_quota.go`）。这意味着：

- 多副本部署（`cluster.ha` 是已支持能力）下，每个进程各持一份配额与用量计数：**N 个副本 = N 倍容量**，且各副本计数器互不收敛；
- `ResetUsage`（计费周期回滚）只在单进程内生效，重启即丢；`SetQuota` 的配置变更无法跨副本传播，也没有像客户端/签名密钥那样的失效广播；
- 计费侧（`domains/metering` 的 SQLite 聚合器）查询的是**本地审计文件**，跨副本汇总依赖审计后端共享，缺少独立的、与审计后端解耦的跨副本用量汇总原语；
- 代码库已有完备的"分布式状态"先例（Redis 的 `account_lockout`/`ciba`/`device_code` 用 Lua 脚本做原子读改写、`jti_replay` 用 `SET NX EX`），实现路径是成熟的，缺的只是配额这一块的接线。

### 代码证据

- `shared/core/tenant_user.go:194` — `TenantQuotaStore` 接口（GetQuota/GetUsage/IncrementUsage/DecrementUsage/SetQuota/ResetUsage）；
- `infrastructure/defaultimpl/memorystoreidentity/memory_quota.go` — 唯一实现，注释自述 "not durable across restarts"；
- `interfaces/sso/quota.go` — 强制语义：`checkQuotaBeforeCreate` 超限即 403，`releaseResourceQuota` 补偿递减（fail-open）；
- `domains/metering/metering.go` + `domains/metering/sqlite/aggregator.go` — 用量聚合绑定本地审计 sink；
- 对比：`infrastructure/redis/ratelimit.go`（分布式限流后端已存在）、`infrastructure/redis/*.go` 的 Lua 原子脚本模式。

### 边界情况

- **计费失真（charge-then-crash）**：`IncrementUsage` 成功后、资源创建失败前的补偿 `DecrementUsage` 之间进程崩溃，计数永久偏高——需要"记账事务"或周期对账（reconciliation）任务；
- **跨副本并发增量**：两个副本同时 `IncrementUsage` 必须原子（Redis Lua / Postgres `UPDATE ... RETURNING` 条件更新），不能 read-modify-write；
- **周期回滚与时钟偏差**：`ResetUsage` 的周期边界若按本地时钟判定，副本间时钟偏差会导致同一租户跨周期双计/漏计；应以数据库时间为准；
- **配额存储故障**：必须沿用 fail-open 契约（超卖但不阻断登录），并打审计与指标——与现有 `ErrQuotaExceeded` fail-open 语义一致；
- **单租户热点**：超大租户的计数 key 会成为 Redis 单点热点，需分片计数或窗口化近似计数。

### 建议落地形状（设计方向）

- 新增 `TenantQuotaStore` 的 Redis 与 Postgres 实现（复用现有 Lua/`DELETE RETURNING` 模式），`Memory` 版保留为单进程部署默认；
- 配额配置变更接入跨副本失效广播（与客户端/签名密钥轮换同一条 bus）；
- 增加周期对账任务：以审计事件为源重算用量，纠正 charge-without-compensation 的漂移；
- 计量聚合增加与审计后端解耦的跨副本 rollup（如按租户+日/月的汇总表）。

**优先级：P1（高）** — 治理边界在多副本下静默失效，属于正确性缺陷而非体验问题。规模：M（新增两个后端 + 对账任务 + 测试）。

---

## 2. 会话/设备数据面的扫描原语规模化（性能 + 运维）

### 为什么需要

会话、设备、令牌的管理与合规路径普遍依赖 `ListAll` 全量物化：

- `interfaces/sso/server_admin_handlers.go:170`（管理员会话列表）
- `interfaces/grpcserver/grpcadmin/admin_tokens.go:86`（gRPC 令牌管理）
- `protocols/compliance/retention.go:158,204`（合规保留扫描，含 SessionTTLSweep）
- `platform/lifecycle/notification/router.go:270`（会话到期预警扫描，按 `session_scan_interval` 周期运行）
- `interfaces/admin/lifecycle.go:190,205,306,376`（设备生命周期四处全量扫描）

而 Postgres 端的实现是**无条件全表扫描 + 全量物化到内存**：

- `infrastructure/postgres/session.go` 的 `ListAll` 是 `SELECT id, user_id, ... FROM sessions`（无 WHERE、无分页、无游标）；
- `ListByTenant` / `DeleteByTenant` 同样是表级扫描；
- 会话表没有周期性清理（内存存储有 `StartReaper`，Postgres 没有等价的过期清理；合规扫描是 opt-in 且默认关闭）。

结果：随会话数增长，每次扫描 O(N) 内存 + O(N) IO；通知到期扫描在百万会话量级会周期性压库；表与索引持续膨胀。

### 代码证据

- `infrastructure/postgres/session.go:201-210`（`ListAll` 无过滤全表查询）、`225-240`（`ListByTenant`）；
- 上述 9 处 `ListAll(` 调用点；
- 对比：代码库已有正确的规模化范式——`infrastructure/postgres/clients_scan.go`、`tenant_scan.go`（游标/键集分页扫描），说明这不是缺少模式，而是会话/设备面未复用。

### 边界情况

- **扫描期间的数据变更**：键集分页在并发写入下可能出现重复/遗漏页，需要稳定排序键（如 `(tenant_id, expires_at, id)`）与幂等消费；
- **长事务与行锁**：批量删除过期会话要分批（`DELETE ... WHERE ctid IN (...)` 或 keyset 分批），避免单条大事务占锁窗口；
- **通知扫描的时效性**：SQL 侧窗口过滤（`expires_at BETWEEN now() AND now()+warning`）比全量拉取后内存过滤更省，但必须与 SessionManager 语义（含滑动/绝对过期）保持一致；
- **后端能力差异**：`ListAll` 在部分后端可能返回 `ErrUnsupportedOperation`（合规扫描已按 Skipped 处理），新扫描原语要保留该降级契约；
- **索引选择**：`(revoked, expires_at)` 部分索引 + 租户维度前缀，避免为一次性扫描建大索引。

### 建议落地形状（设计方向）

- 为 SessionManager/DeviceStore 增加带谓词的扫描 API（按过期窗口、租户、用户），统一键集分页与批次上限；
- 周期任务（通知到期扫描、合规保留、设备生命周期）全部迁移到窗口化扫描，禁止全量物化；
- Postgres 端增加过期会话的批量 GC 与表膨胀指标（`pg_stat_user_tables` 观测或内置计数）；
- 为扫描任务增加时长/批次数指标，纳入现有 metrics 体系。

**优先级：P1（高）** — 这是随规模线性恶化的运维负债，且已有内部范式可复用。规模：M（接口扩展 + 三个周期任务迁移 + 索引/GC）。

---

## 3. 认证热路径的验证结果缓存：mesh ext_authz 与资源服务器（性能）

### 为什么需要

网格鉴权与资源服务器是**每请求全量验证**：

- `interfaces/sso/mesh_authz.go` 的 HTTP/gRPC ext_authz 路径"EXACTLY like /userinfo (validateAnyToken + the DPoP/mTLS sender-constraint)"——每个网格请求都做一次完整 JWS 验签，加上 DPoP proof 的第二次验签与 `htm`/`htu` 绑定检查；
- `interfaces/ssoclient/rs` 的资源服务器中间件只有 JWKS 缓存（ETag 重验证 + singleflight + 后台刷新），没有**验证结果**缓存——每个受保护资源请求都重复完整验签。

服务端 introspection 已有先例：`protocols/oauth/introspect_cache.go` 明确接受"TTL 有界最终一致"（token 哈希做键、绝不存明文、可选 `IntrospectionCacheInvalidator` 即时失效、有命中率指标）。RS/mesh 热路径完全可以沿用同一契约，把"验签结果"而不是"签名密钥"缓存起来。

### 代码证据

- `interfaces/sso/mesh_authz.go:23`（每请求 validateAnyToken + 发送者约束）；
- `interfaces/ssoclient/rs/rs.go:76-94`（仅有 JWKS 缓存与共享 JTI replay 缓存，无验证结果缓存）；
- `protocols/oauth/introspect_cache.go`（可参照的 TTL 有界缓存契约 + 失效扩展 + 指标 `sso_introspect_cache_hits_total`）；
- 代码库已有基准门禁文化（`Makefile` 的 `bench-gate`、`load-test` k6 脚本），可以量化收益再决定是否落地。

### 边界情况（安全护栏）

- **发送者约束永不缓存**：DPoP proof、mTLS 证书绑定、`htm`/`htu` 每次请求现场校验——缓存只覆盖签名/有效期/作用域等静态断言；
- **失效语义**：撤销路径必须能逐项失效（复用 introspection 的 invalidator 模式与 `deny-set` 订阅）；TTL 必须短于令牌剩余寿命；
- **不允许用于步升决策**：step-up（RFC 9470）与条件访问评估必须走实时路径，缓存结果只能服务常规授权；
- **缓存键**：token 哈希 + issuer + 校验参数指纹，避免跨配置串扰；
- **容量有界**：复用现有 `MaxEntries`/reaper 模式，防止令牌洪峰撑爆内存。

### 建议落地形状（设计方向）

- 抽取"验证结果缓存"为一个 SPI（Get/Set/Invalidate，与 `IntrospectionCache` 同构），RS 与 mesh 路径共用；
- 先用现有 k6 脚本与 bench 门禁量化"每请求全量验签 vs 缓存命中"的差距，作为是否默认开启的依据；
- 命中率、失效数、缓存大小指标接入现有观测体系。

**优先级：P2（中高）** — 纯性能优化，收益随网格流量放大；安全护栏使其实现复杂度高于普通缓存。规模：M。

---

## 4. 用户通知通道产品化：移动推送、摘要、多语言模板与投递质量（产品）

### 为什么需要

`core.NotificationSender` 通道 SPI 已存在（`platform/lifecycle/notification/router.go` 的 `senders` map），但**实际通道只有 in_app 与 email 两个**（见 `docs/notifications.md`）。现代身份产品的安全通知面通常包含：

- **移动推送（FCM/APNs）**：消费级 SSO 的登录/新设备/异常告警即时触达；推送令牌同时是设备可信度信号（设备撤销时令牌作废本身就是安全事件）；
- **摘要通道**：`password_expiring`、`session_expiring` 这类低频预警适合日/周摘要，减少通知疲劳（现有 per-{subject,type} 冷却只解决风暴，不解决疲劳）；
- **多语言模板**：`shared/i18n` 已有能力，但通知正文目前是固定文案；
- **邮件投递质量**：现有 SMTP 基于 `net/smtp`，仅 STARTTLS（端口 465 隐式 TLS 不支持，deferred-backlog 已记录），且无退信/回弹处理——企业场景下"密码泄露告警没送达"是安全事件而非体验问题。

通知架构本身是解耦的（审计 sink → 有界队列 → worker → 通道 sender），新增通道是纯增量接线，且已有 webhook 引擎（`platform/lifecycle/webhook`，运行时订阅 + HMAC 签名 + 重试/死信）作为"事件出口"范式可复用。

### 代码证据

- `platform/lifecycle/notification/router.go:98,245-251`（通道 sender map，仅 in_app/email）；
- `docs/notifications.md`（通道、偏好语义、内存收件箱 1000 条/人上限、SMTP 三次重试）；
- `shared/i18n/bundle.go`（i18n 基础设施存在但未接入通知文案）；
- `platform/lifecycle/webhook/engine.go`、`deadletter.go`（可复用的出站投递引擎：订阅、签名、重试、死信）。

### 边界情况

- **推送令牌生命周期**：设备撤销/换机后令牌必须作废并触发安全事件，防止向已丢失设备推送敏感告警；
- **退信与不可达**：邮件回弹（bounce）要有反馈回路，不能静默降级为"永远重试 3 次"；
- **摘要窗口语义**：摘要的聚合窗口（如 UTC 日界）、窗口内重复事件的去重、与 per-type 冷却的叠加；
- **通道故障隔离**：保持 fail-open（通道失败不影响认证与审计），沿用现有 `sso_notifications_delivery_failed_total` 的观测；
- **模板注入与本地化**：模板变量必须转义，避免把审计字段直接拼进通知正文。

### 建议落地形状（设计方向）

- 通道 SPI 增加 push sender（FCM/APNs 适配器）与 digest sender（聚合窗口 + 定时 flush）；
- 通知正文模板接入 i18n bundle，模板随通知类型注册、带版本；
- SMTP 层补隐式 TLS（465）与退信反馈，或明确要求边缘中继承担（现有 deferred 决策需产品拍板）；
- 投递指标扩展：送达率、打开率（如可测）、按通道/类型的分布。

**优先级：P2（中）** — 纯增量产品能力，不触碰认证路径；但对消费级与合规型企业客户是显著卖点。规模：S-M。

---

## 5. 密码凭据哈希的算法敏捷性：argon2id 迁移路径与版本化哈希格式（安全演进）

### 为什么需要

凭据验证是"皇冠明珠"，而当前**哈希算法与格式被硬编码为 bcrypt**，没有任何算法敏捷性：

- `infrastructure/defaultimpl/memorystorecredential/memory_password_credentials.go`、`infrastructure/redis/password_credentials.go`（及 Postgres 同构实现）都直接调用 `bcrypt.GenerateFromPassword(..., bcrypt.DefaultCost)`；
- Redis 版 `SetPasswordHash` 甚至**拒绝非 `$2` 前缀的哈希**——意味着未来迁移 argon2id/PBKDF2 需要改存储契约本身；
- 登录时无"rehash-on-login"升级路径（运营商预播种凭据，见 `shared/spi/password_health.go` 的说明），所以哈希升级只能靠批量迁移或渐进式 rehash；
- 防枚举的时间均衡假哈希（dummy hash）在每个存储里重复实现，算法迁移时必须**保持假哈希与真实哈希的成本/算法一致**，否则登录路径出现可区分的时序侧信道——这是迁移中最高风险的边界情况。

OWASP 与 NIST 方向均指向内存硬算法（argon2id）；且本仓库自己的 FIPS 分析已注明 bcrypt 非 FIPS 验证（历史文档），FIPS 模式下需要 PBKDF2-HMAC-SHA256 备选。

### 代码证据

- `infrastructure/redis/password_credentials.go:13,39,57,76`（bcrypt 硬编码 + `$2` 前缀校验）；
- `infrastructure/defaultimpl/memorystorecredential/memory_password_credentials.go:20-35`（bcrypt + cost-matched dummy）；
- `shared/core/spi.go:308-320`（`PasswordCredentialStore.VerifyPassword` 契约，无算法协商字段）；
- `shared/spi/password_health.go`（登录是唯一接触明文的机会——rehash 只能在登录时或批量任务中做）。

### 边界情况

- **假哈希成本匹配**：未知用户与已知用户必须走同一算法、同一成本参数的验证路径（现有多处 dummy 实现，迁移时是主要回归点）；
- **版本化格式**：哈希字符串自带算法版本（如 `$argon2id$v=19$...`），旧算法哈希在过渡期继续可验证，新登录逐步升级；
- **批量迁移**：运营商播种的哈希格式未知/混合时，迁移任务必须可 dry-run、可限速、可审计；
- **FIPS 模式**：argon2id 与 FIPS 140 的兼容性取舍需产品决策（PBKDF2-HMAC-SHA256 为 FIPS 备选）；
- **时序一致性**：rehash-on-login 不得改变登录响应时间分布（在验证后异步执行或纳入基准门禁）。

### 建议落地形状（设计方向）

- 新增 `PasswordHasher` SPI（Hash/Verify/NeedsRehash），三个存储共用一套实现与 dummy 成本逻辑；
- 哈希格式版本化，兼容读取旧 bcrypt 哈希；登录验证通过后按策略渐进升级；
- 提供运营商批量迁移工具（sso-ctl 命令，dry-run + 审计），并接入现有 benchmark 门禁做时序回归防护。

**优先级：P2（中高）** — 安全演进性投资；当下无迫在眉睫的漏洞，但迁移窗口会随存量哈希数量线性扩大，越早建立格式版本化成本越低。规模：S-M（SPI + 三存储迁移 + 工具）。

---

## 6. 优先级汇总

| # | 方向 | 类别 | 优先级 | 规模 | 主要收益 |
|---|---|---|---|---|---|
| 1 | 租户配额/计量持久化与跨副本一致性 | 正确性/计费 | P1 | M | 多副本下治理边界与计费不失真 |
| 2 | 会话/设备扫描原语规模化 | 性能/运维 | P1 | M | 消除随规模线性恶化的全表扫描与表膨胀 |
| 3 | mesh/RS 验证结果缓存 | 性能 | P2 | M | 网格与资源服务器热路径吞吐 |
| 4 | 通知通道产品化（推送/摘要/i18n/邮件质量） | 产品 | P2 | S-M | 安全触达差异化卖点 |
| 5 | 密码哈希算法敏捷性 | 安全演进 | P2 | S-M | 未来 argon2id/FIPS 迁移的低成本路径 |

## 7. 与既有文档的差异说明

- 后量子算法迁移框架、Redis 分布式限流、缓存观测指标等方向已在历史分析中识别，本文不重复展开；
- 本文的方向 1-5 均以 2026-07-30 之后的工作树为证据（通知/SSE/webhook 引擎、gRPC 管理面、token 生命周期等新子系统），并刻意选择了**治理正确性、数据面扩展性、热路径性能、产品触达、凭据安全演进**五个互不重叠的切面；
- 所有方向均可在现有 SPI/接线点（audit sink、`ListAll` 调用点、`NotificationSender`、`PasswordCredentialStore`）上以增量方式落地，不触碰认证/授权内核的 oracle-safe 契约。
