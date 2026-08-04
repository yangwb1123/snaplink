# 全局扫描：五个高价值扩展方向

- 日期：2026-08-01
- 范围：一次性全局扫描（`shared/` → `domains/` → `protocols/` → `platform/` → `infrastructure/` → `interfaces/` → `cmd/` + 契约文档）
- 方法：以可执行代码为唯一事实来源；每个方向附精确的代码证据（文件:行）。文档、feature-matrix、deferred-backlog 只用于交叉核对"是否已知/是否已实现"。
- 结论概览：本仓库成熟度极高（DPoP、PAR、JARM、CIBA、CAEP、Federation、SCIM、FGA、DR、benchgate 均已落地），多数"显而易见"的缺口已被关闭。以下五个方向是扫描中**确认存在、可被代码证据支持、且未被 backlog 承诺**的真实缺口，按价值排序。

---

## 方向一：Redis 客户端注册表补齐租户索引与廉价指纹（安全语义 + 热路径性能）

### 现状（代码证据）

- `infrastructure/redis/clients.go:38-42` 明确注释：`TenantScopedClientStore` 与 `ClientStoreStats` 两个可选扩展**故意未实现**，Redis 后端回退到 `List()` 后内存过滤。
- 对照：`infrastructure/defaultimpl/sqlite/clients.go:493-494` 与 `infrastructure/defaultimpl/memorystoreidentity/memory_clients.go:265-266` 均已实现这两个接口。**Redis 是三套后端中唯一缺口的那个——而它恰恰是文档推荐的多副本生产后端**。
- 安全语义退化（`interfaces/sso/server_tenant.go:137-140`）：`revokeTenantRefreshTokens` 在 client store 不支持 `TenantScopedClientStore` 时直接 `return 0, nil`——**不清理任何令牌、不发审计事件**，但调用方（`RevokeTenantCredentials`，`server_tenant.go:77-97`）照常返回"成功"。也就是说：租户挂起/吊销流程在 Redis 客户端后端下，对 refresh token 的主动吊销是**静默空操作**，管理员看到 0 条已吊销却不知道后端不支持。
- 性能退化（`interfaces/sso/server_discovery_cache.go:56-112`）：发现文档缓存依赖 `core.ClientStoreStats` 的廉价指纹做 `refreshIfUnchanged`（指纹未变则仅延长 TTL、跳过全量重投影）。Redis 无指纹 → 每次缓存过期都触发 `clientStore.List(ctx)` 全量枚举 + 重投影（`server_discovery_cache.go:104`），客户端规模越大，每个 TTL 周期一次的 O(N) 全表扫描越贵。

### 为什么需要

1. **安全边界**：多副本生产拓扑（Redis 客户端存储）下，租户挂起后的"吊销该租户全部刷新令牌"承诺落空，且失败方式为静默成功——违反本项目"吊销必须可靠、失败必须可见"的既有纪律（对照 `revokeTenantSessions` 的显式 fail-open + 审计设计）。
2. **性能**：修复后，发现文档缓存可从"每次 TTL 全量 List"变为"一条 Stats 指令决定是否重算"，是 discovery/登录首屏链路的直接优化。
3. **一致性**：内存/SQLite 已具备的能力，生产后端缺失，属于后端对等性缺口（同类先例：`HasPassword` 补齐后，Redis/Postgres 不再表现为 `PasswordPresenceChecker` 未实现，`infrastructure/redis/password_credentials.go:115` 注释记录了同类问题的修复模式）。

### 扩展内容

- Redis 侧：`sso:client:bytenant:<tenantID>` SET 索引（写路径同步维护），`Stats` 用计数 + 顺序无关的摘要（可复用 `core.ClientSetFingerprint` 的哈希语义）实现廉价指纹。
- 语义缺口关闭：`revokeTenantRefreshTokens` 在不支持租户枚举的后端上应**返回可辨识的错误/报告**（而不是 `(0, nil)`），并由管理端 API 层呈现为"后端不支持，未执行吊销"，同时落审计——把静默退化改为显式降级。
- 边界情况：索引与主键的事务一致性（Redis MULTI/管道或 Lua）；DCR 更新/删除客户端时的索引维护；指纹与 `List()` 结果必须同源（参照 `computeDiscoverySnapshot` 的"同一批客户端计算指纹"约束，`server_discovery_cache.go:104-115`）。

---

## 方向二：SCIM 目录查找索引化 + 补齐 value-path 过滤器（wire 兼容 + 大规模目录性能）

### 现状（代码证据）

- `protocols/scim/filter.go` 自带注释承认两个限制：
  - **性能**："evaluation runs over a full List scan ... An indexed lookup SPI (e.g. `UserProvider.FindByAttribute`) is a future optimization for SaaS-scale directories"（filter.go:36-42 区域）。
  - **语法**：value-path 过滤器（`emails[type eq "work"]`）、schema-URN 前缀属性、属性路径内复合分组均"NOT implemented (rejected as invalidFilter, never silently honored)"（filter.go:29-32）。
- 语义上是安全的（拒绝而非误答），但 `invalidFilter` 会让连接器（Azure AD/Okta 的目录调和）直接放弃该查询，退化为全量分页拉取——把性能问题转嫁给上游。

### 为什么需要

1. **兼容性边界情况**：SCIM 2.0（RFC 7644 §3.4.2.2）的完整 ABNF 中 value-path 是标准语法，主流 IdP 连接器在按子属性（如 `emails[type eq "work"].value`）或组成员（`members[value eq "..." ]`）调和时会用到。当前实现只覆盖 `eq/ne/co/sw/ew/gt/ge/lt/le/pr` + 布尔组合的"常用子集"。
2. **性能**：目录达到 SaaS 规模（数十万用户）后，每次调和都全量 List + 过滤，与"让连接器用小过滤器精确定位单资源"的设计意图（filter.go 注释明确提到 Azure AD/Okta 依赖 `filter=userName eq "alice"` 避免分页）背道而驰。
3. **架构顺势**：过滤器解析/求值器已经是自包含可复用前端（filter.go 注释），缺的只是后端索引 SPI——扩展成本低、收益确定。

### 扩展内容

- 定义 `UserProvider.FindByAttribute(attr, op, value, ...)` 类 SPI（放在 `shared/core` 或 `shared/spi`，各后端实现索引或退化为扫描），由过滤器求值器在"主属性精确匹配"等可索引形态下短路全表扫描。
- 补齐 value-path 与 schema-URN 前缀语法的解析与求值（保持"不支持即 invalidFilter"的失败模式为兜底）。
- 边界情况：过滤器中的转义（`\`、`\22` 等）与大小写语义（RFC 7644 大小写不敏感比较）；分页与过滤组合时的 `totalResults` 一致性；索引缺失后端的显式降级路径（不可静默返回错误页）。

---

## 方向三：分布式平滑限流与租户公平性（多副本行为一致性）

### 现状（代码证据）

- 三档限流后端（`cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go:48-113`）：
  - `memory`：`ratelimit.NewMemoryLimiter`（`interfaces/ratelimit/ratelimit.go:104`）——进程内分片令牌桶。**多副本部署下每个副本独立计数，有效限额 = 配置值 × 副本数**。
  - `sqlite`：共享令牌桶（文档称"operators who need bucket-exact smoothing across replicas should keep the SQLiteLimiter"）。
  - `redis`：共享**固定窗口**计数器（`infrastructure/redis/ratelimit.go:30-42` 注释明确承认 fixed-window "admits up to limit in a burst at the window edge"；INCR+EXPIRE 原子脚本见 98-106 行）。
- 限流 key 提取器（`interfaces/ratelimit/middleware.go:70-115`）：`KeyByClientIDOrIP` / `KeyByClientIP` / `KeyBySubject`，**均无租户维度**；`TenantKeyFunc` 只用于拒绝路径的指标标签（middleware.go:39-44），不参与限额判定。

### 为什么需要

1. **边界情况——窗口边界突发**：固定窗口在边界处可放行 2× 限额，攻击者可按窗口节奏编排突发；对 `/auth/login` 这类暴力破解防御场景，平滑性直接影响防护上限。
2. **边界情况——多副本放大**：内存令牌桶在多副本下限额被副本数放大，且副本间负载不均时防护不均匀；这是"配置了限额但实际防护弱于预期"的静默退化。
3. **公平性缺口**：共享 IP（NAT/机房出口）会误伤同出口的正常租户；无租户维度的限额意味着一个租户的突发流量可挤占公共预算，与已实现的租户配额（`interfaces/sso/quota.go` 的 `checkQuotaBeforeCreate`）形成"配额有租户维度、限流没有"的不对称。

### 扩展内容

- 新增共享**平滑**限流器（Redis Lua 实现的分布式令牌桶或滑动窗口近似），补齐"跨副本平滑"这一当前只能靠 SQLite 满足、且与 Redis 主拓扑冲突的空档。
- key 维度扩展：可选 `TenantID` 维度（租户级公平份额 + 全局总预算双层校验），复用既有的租户解析中间件上下文。
- 边界情况：时钟漂移下的窗口一致性（参照 `dpop_clock_skew_test.go` 的既有测试思路）；限流器后端切换（SIGHUP 热加载已支持，`main_wiring.go:135-167`）时计数器语义不连续的处理；`Retry-After` 头在共享限流器下的精度。

---

## 方向四：登录全链路的端到端延迟预算（性能工程门禁扩展）

### 现状（代码证据）

- 微基准门禁已存在且质量高：`ops/deploy/benchgate/benchmarks.yaml` 覆盖 JWT 签发/校验、JWS 验签、参数绑定、内存 OAuth 存储并发、内存限流器——阈值 10%、`benchstat` 显著性判定。
- k6 负载测试**只覆盖 `/token`**（`Makefile:49`："Load-test /token (requires k6)"，脚本 `ops/deploy/loadtest/token.js`）。
- 未被任何预算门禁覆盖的链路：`/auth/login` 全流程（登录页加载 → 认证 → 授权码签发）、`/userinfo`、**冷缓存** introspection、PAR 消耗、发现文档缓存 miss 路径、设备码轮询、Redis/Postgres 后端下的端到端往返（store 调用放大——正是方向一里 `List()` 全表扫描这类回归的藏身之处）。

### 为什么需要

1. **回归防护盲区**：现有门禁证明"单次加密/单次存储操作"不退化，但证明不了"一次登录请求的总延迟"不退化——而后者才是用户可感知的 SLO。方向一修复的正是这类"微基准看不出来、端到端立刻暴露"的问题。
2. **多后端对等性**：Redis/Postgres 拓扑的延迟特征与内存后端差异巨大，目前没有任何门禁约束"生产后端不得比内存后端慢出数量级"。
3. **边界情况**：冷/热缓存、缓存失效风暴（全量 invalidation 广播后）、单副本 vs 多副本下的 p99 差异，都是需要显式预算的边界。

### 扩展内容

- 把 k6 场景从 `/token` 扩展到：完整授权码登录、`/userinfo`、冷/热 introspection、PAR+授权码、发现文档缓存 miss；对每个场景在 `ops/deploy/loadtest/` 下记录基线并接入 `load-test-ci`（现成机制，仅扩场景）。
- 为"内存/Redis/Postgres 三后端"各建立一组延迟基线，`load-test-compare` 按后端分档比较（阈值沿用 20% 机制）。
- 边界情况：预算门禁必须容忍 CI 机器噪声（沿用 benchgate 的显著性判定思路），并允许显式标注"已知慢路径"（如 bcrypt 校验、冷 introspection 无缓存）。

---

## 方向五：密码哈希策略治理——持久化 dummy 成本与可配置重哈希目标（边界情况）

### 现状（代码证据）

- `infrastructure/postgres/password_credentials.go:48` 注释明确承认：**dummy 哈希成本是进程本地的，重启后重置为 `bcrypt.DefaultCost`**；只有导入更高成本哈希时才 `raiseDummyCost`。
- 重哈希机制已存在（`domains/authenticators/rehash.go` 的 `LazyRehashVerifier`，`cmd/sso-server/serverbuildauthn/build_authenticators_helpers.go:77-95` 已接线），但升级目标是**写死的** `bcrypt.DefaultCost`（`domains/authenticators/password_hash.go` 的 `HashPassword`），而代码库本身已支持 argon2id/pbkdf2-sha256/sha512（`password_hash.go:10-15`），却没有"按策略把存量 bcrypt 渐进迁移到 argon2id"的路径。

### 为什么需要

1. **边界情况——重启后的计时 oracle 窗口**：若存量导入哈希为 cost-12，重启后到下一次导入前，未知用户的 miss 路径按 cost-10 计算，比命中路径快——正是本项目在 `raiseDummyCost` 注释里明确要防的"timing oracle"，但该防护在重启后存在空窗。
2. **策略漂移**：NIST 800-63B 类合规要求哈希参数随算力提升而演进；当前"升级=改代码、改默认常量"没有运营路径，也没有"全库哈希画像"（各成本分布）的可见性。
3. **架构顺势**：多格式校验、`NeedsRehash` 判定、异步升级钩子均已存在，缺的只是"策略配置 + dummy 持久化"两端。

### 扩展内容

- dummy 成本持久化：跟随最高存量哈希成本持久化（或启动时扫描 `MAX(bcrypt_cost)` 预热），关闭重启空窗。
- 可配置的哈希策略：目标算法（bcrypt/argon2id/pbkdf2）、目标成本/参数、`NeedsRehash` 阈值；`LazyRehashVerifier` 的升级目标从常量改为策略。
- 边界情况：升级写放大（全库渐进迁移的节流）、升级失败回滚（fail-open 保持登录可用，与现有 `needsLazyRehash` 的 fail-open 语义一致）、导入哈希成本高于策略上限时的拒绝策略、审计事件（每次渐进升级应可审计）。

---

## 附录：已扫描但未入选的候选（含排除理由）

| 候选 | 排除理由 |
|---|---|
| OIDC Session Management / `check_session_iframe` | 已实现（`interfaces/sso/options_grants.go:296-304`，gate 默认关闭） |
| 密码渐进重哈希 | 已实现（`LazyRehashVerifier`），仅目标成本不可配置——故并入方向五 |
| CIBA `user_code` 模式 | 已知限制，已在 `docs/deferred-backlog.md` 登记 |
| 设备码轮询 `slow_down` | 已实现（`interfaces/sso/server_device.go:314`） |
| JTI replay 内存存储无界增长 | 已有 `MaxEntries` + `StartReaper` 防御（`memory_jti_replay.go`） |
| 签名 JWT introspection（RFC 9701） | 已实现（`protocols/oauth/handle_introspect.go`） |
| 无效果的 SDK 选项（`WithSessionTTL`/`WithTokenTTL`） | 真实存在（`interfaces/sso/options_security.go:379-390`）但属于 API 卫生、非高价值；建议作为随手清理项 |
| 多集群配置自动应用（GitOps） | 已在 deferred-backlog 登记为"需权威模型"的延迟决策 |

---

## 落地建议（与既有工程门禁对齐）

1. 每个方向先落**测试**再落实现：方向一补 `backendsemantics` 级后端对等测试（参照 `test/backendsemantics/` 模式）；方向二补过滤器解析器表驱动用例（现有 `filter.go` 已有解析器，直接扩用例）；方向三补窗口边界/多副本一致性测试（参照 `chaos` 目录风格）；方向四扩 `ops/deploy/loadtest/` 场景与基线；方向五补重启空窗回归测试。
2. 契约同步：任何新端点/配置键按 AGENTS.md §5 同步 `docs/openapi.yaml` / `docs/config-reference.md` / `docs/error-codes.md` / feature-matrix。
3. 预算检查：方向一、三、四的实现不得触碰 `interfaces/sso` 60 文件上限与目录扇出上限；新 SPI 归类进既有层（`shared/core` 或 `shared/spi`），无需新增 `layerExemptions`。
