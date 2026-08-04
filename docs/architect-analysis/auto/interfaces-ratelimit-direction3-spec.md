# 需求规格：interfaces/ratelimit 方向三——限流实现碎片化收敛（五套平行限流机制统一到同一 SPI 与同一 429 契约）

> 依据 `docs/auto/interfaces-ratelimit-analysis.md` 方向三展开。本规格收敛五套互不通用的
> 限流机制（grant 级、admin 级、self-service 注册、threaaction 动作门、Redis 后端）到
> 同一 `Limiter` SPI、同一 `rate_limited` 429 契约、同一语义/度量/生命周期约定。不在
> 本规格内：认证后按客户端/按用户分桶（方向一）、X-RateLimit-* 额度头与允许路径指标
> （方向二）、admin 常量键 `admin` 的按管理员分桶改造（方向一）、写配额语义本身
> （`admin_write_quota_exceeded` 是文档化的独立配额契约，保持独立，见决策二）。
>
> 三条决策呈依赖链：决策一下沉 SPI 到 shared 内核（地基，消灭接口复制与第四套窗口实现）
> → 决策二把五个限流点的 429 响应收敛到 `rate_limited` + `Retry-After` 唯一契约（对外
> 契约，复用 `interfaces/sso/quota.go` 的 DCR 先例）→ 决策三用一致性套件钉住三后端的
> 同一语义，并把拒绝度量路径统一进 `sso_rate_limit_hits_total`（运维契约）。三条均需
> 同步更新 `docs/error-codes.md`、`docs/observability.md`（AGENTS.md §5 规则 6）。

## 决策一：Limiter SPI 下沉 shared 内核——删除 selfservice 接口复制与 threaaction 第四套窗口实现

### 问题

`interfaces/ratelimit.Limiter` 是唯一 SPI，但受分层约束（`protocols/`、`domains/` 不能
import `interfaces/`），两个下层消费方各自复制/自建：`protocols/selfservice` 复制了
`RateLimiter` 子集接口与 `HeaderRetryAfter` 常量；`domains/threataction` 自建了第四套
内存固定窗口实现（私有 map + 借锁清扫 + 1024 条上限），无指标、无 TTL 租赁、无
memreaper 生命周期。每新增一个限流点就重写一次窗口/桶与清扫，长期必然继续漂移。

### 证据

- `protocols/selfservice/selfservicecore/deps.go:17-25` — `RateLimiter` 接口（17-22 行，
  注释自述 "Defined locally so protocols/selfservice does not depend on
  interfaces/ratelimit (which would violate the layer boundary)"）与
  `HeaderRetryAfter` 常量（25 行，注释自述 "duplicated here to avoid importing
  interfaces/ratelimit"）；`Deps.SignupRateLimiter()`（56 行）返回该复制接口。
- `protocols/selfservice/signup.go:91-104` — `rejectSignupRateLimit` 用复制常量重写
  Retry-After 的 ceil 取整逻辑。
- `domains/threataction/registry.go:29`（`rateLimit map[string]*rateLimitEntry` 字段）、
  `164-183`（`rateLimitSweepThreshold`，注释 169-181 明确解释不能复用 memreaper 的
  根因：architecture_layer_test 禁止 domains → infrastructure 向上 import，且
  layerExemptions 只减不增）、`187-216`（`allow` 固定窗口计数）、`219-225`
  （`evictExpiredLocked` 借锁清扫）；`domains/threataction/threataction.go:127-134`
  （`rateLimitEntry`/`RateLimitKey`）。
- `docs/architecture/DIRECTORY_MAP.md:90` — "abstraction belongs lower (move the
  interface to `shared/core` / `shared/spi`)"，即架构文档已规定此类问题的正解。
- `domains/threataction/registry.go:10` 已 import `shared/spi`（Logger）——
  `shared/spi` 下沉不引入任何新 import 边。
- `interfaces/ratelimit/ratelimit.go:38-43` — 现有 `Limiter` 接口定义（唯一权威副本）。

### 提议行为

1. **SPI 下沉**：在 `shared/spi` 新增 `RateLimiter` 接口，签名与现有一致：
   `Allow(key string) (ok bool, retryAfter time.Duration)`（纯接口，零依赖，符合
   shared 内核约束）。`interfaces/ratelimit` 的 `Limiter` 改为类型别名
   `type Limiter = spi.RateLimiter`——SDK 用户自定义 limiter（`WithRateLimit`、
   `WithClientRegistrationRateLimit`）与三个后端（`MemoryLimiter`、
   `SQLiteLimiter`、`redis.Limiter`）的 `var _ Limiter` 断言全部无感兼容，零 API
   破坏。
2. **shared 固定窗口参考实现**：`shared/spi`（或 shared 层内新包）提供
   `NewMemoryFixedWindow(limit, window)`——dependency-free 的内存固定窗口，含
   与 `MemoryLimiter` 相同的惰性清理约定（空闲超时回收 + `StartPruner`/`Close`
   memreaper 生命周期，`interfaces/ratelimit/ratelimit.go:155-198` 的既有惯例）。
   固定窗口语义从此只有一份实现 + 一份文档，Redis 后端与 threaaction 共用同一语义
   定义（决策三的一致性套件负责钉住）。
3. **selfservice 去复制**：删除 `selfservicecore.RateLimiter` 与
   `selfservicecore.HeaderRetryAfter`；`Deps.SignupRateLimiter()` 返回
   `spi.RateLimiter`；`signup.go` 改用 `shared/spi` 的头名常量（或经 accessor 复用
   `interfaces/ratelimit.HeaderRetryAfter`——由接线层提供，不新增协议层 import）。
4. **threaaction 去私有实现**：删除 `rateLimit` map 字段、`rateLimitEntry`、
   `rateLimitSweepThreshold`、`evictExpiredLocked`；`allow()`（registry.go:187-216）
   改为委托给一个按 `RateLimitPolicy{Max, PerWindow}` 构造的 shared 固定窗口 limiter
   实例（`ThreatExecutors` 持有，`NewThreatExecutors` 构造时按需创建）。窗口语义保持
   固定窗口（`Max` 次/`PerWindow`，窗口翻转整体重置），行为与现状字节等价。
5. 本决策不新增 `interfaces/sso` 文件（该目录处于 60 文件上限），只改动既有文件。

### 验收标准

1. `go build ./... && go vet ./...` 与 `go test -run 'TestMaintainability_|TestArchitecture_' .`
   全绿；`architecture_layer_test.go` 的 `layerName` 覆盖任何新增 shared 包。
2. 全库 `grep -rn "selfservicecore.RateLimiter\|selfservicecore.HeaderRetryAfter"` 为空；
   `domains/threataction` 中 `rateLimit` map 字段、`evictExpiredLocked`、
   `rateLimitSweepThreshold` 符号全部删除。
3. `interfaces/ratelimit` 的 `var _ Limiter = (*MemoryLimiter)(nil)` /
   `(*SQLiteLimiter)(nil)` 断言与 `infrastructure/redis` 的 `var _ ratelimit.Limiter`
   断言在新别名下编译通过；`WithClientRegistrationRateLimit(ratelimit.Limiter)` 等
   SDK 签名不变。
4. `domains/threataction` 既有行为测试（固定窗口计数、窗口翻转、上限拒绝）不改断言
   全绿——证明行为等价迁移；新增测试：同一 `(Max, PerWindow)` 下 shared 固定窗口与
   旧实现的决策序列一致。
5. `protocols/selfservice` signup 限流测试全绿，429 响应与改造前字节一致（头 + 体）。

## 决策二：统一 429 契约——唯一错误码 `rate_limited`、统一 Retry-After 与 deny-all 语义

### 问题

同一"请求被限流"条件在五个限流点上有三种互斥的线契约：(a) grant 级限流拒绝时返回
**429 却带 `unsupported_grant_type` 错误码、无 Retry-After**——`unsupported_grant_type`
在 `docs/error-codes.md:99` 是 400 码，SPA 按 `rate_limited` 分支会误判为自己的
grant_type 非法；(b) admin 限流拒绝时写 `{"error":"rate_limit_exceeded"}`（该错误串
在 error-codes.md 中无任何登记），且经 `http.Error` 写出 `text/plain` 而非 JSON 体；
(c) deny-all 配置的 Retry-After 三后端漂移：Memory/SQLite 返回 retry=0 → 不写
Retry-After 头，Redis 是 365 天窗口 → 写一年退避。同一份 `security.rate_limit.*`
配置在不同后端下对外行为不一致。对照：`interfaces/sso/quota.go` 的 DCR 限流已是
正确范式（复用 `ratelimit.Limiter` + `ratelimit.ErrRateLimited` + no-store + 头），
本决策就是把其余限流点拉平到这个范式。

### 证据

- `interfaces/sso/server_token.go:365-375` — `checkGrantRateLimit`：371 行
  `ctx.JSON(http.StatusTooManyRequests, errorBody(ctx, ErrUnsupportedGrantType))`，
  无 Retry-After、无 no-store。
- `interfaces/sso/options_grants.go:107-143` — `rateLimiterEntry`（109 行）与
  `WithGrantTypeRateLimit`（113-143 行）：裸 `golang.org/x/time/rate.Limiter`，不经过
  `ratelimit` SPI，无指标无头。
- `interfaces/admin/governance.go:244`（`errAdminRateLimitExceeded = "rate_limit_exceeded"`）、
  `280`（`adminRateLimitKey`）、`306-328`（`checkRateLimit`，328 行
  `http.Error(w, ...)` 写 text/plain 429）。
- `docs/error-codes.md:917-921` — "Rate limiting + payload" 表：`rate_limited` 是
  **唯一**的限流 429 码，带 `Retry-After: <seconds>`；`docs/error-codes.md:99` —
  `unsupported_grant_type` 登记为 400。
- `interfaces/ratelimit/ratelimit.go` `reserve`（117-148 行）— `perSecond<=0` 分支返回
  `(false, 0)`；`interfaces/ratelimit/sqlite_limiter.go` `consumeToken` — `denyAll`
  分支返回 `(false, 0, true)`；`infrastructure/redis/ratelimit.go:67-75` —
  `NewLimiterFromRate` 的 deny-all = `NewLimiter(rdb, 1, 365*24*time.Hour, ...)`。
- `interfaces/sso/quota.go` — `checkClientRegistrationRateLimit`：`ratelimit.Limiter`
  + `middleware.TokenNoStoreHeaders` + ceil Retry-After + `ratelimit.ErrRateLimited`
  的正确范式（本规格的对照基准）。

### 提议行为

1. **grant 限流迁到 SPI 并修正契约**：`WithGrantTypeRateLimit` 内部改用
   `ratelimit.NewMemoryLimiter(tokensPerSec, burst)`（保留签名 `(grantType, tokensPerSec,
   burst)` 与 `0 = 全拒 / 负数 = 不限` 语义）；`checkGrantRateLimit` 拒绝路径改为：
   `middleware.TokenNoStoreHeaders(ctx)`（/token 是 credential 端点，AGENTS.md
   "Credential Endpoints"）+ ceil 秒 `Retry-After` 头（沿用 quota.go 的取整写法）+
   `ctx.JSON(http.StatusTooManyRequests, errorBody(ctx, ratelimit.ErrRateLimited))`。
   删除裸 `x/time/rate` 依赖与 `rateLimiterEntry` 包装（若该文件预算吃紧，迁移到
   现有 `quota.go`——错误码/头/取整逻辑与其 DCR 先例完全同构）。
2. **admin 限流收敛到同一 429 体**：`checkRateLimit` 删除 `errAdminRateLimitExceeded`
   与 `http.Error`，改为复用 `ratelimit` 的 canonical 体（`Content-Type:
   application/json` + `{"error":"rate_limited"}` + ceil `Retry-After`，与
   `writeTooManyRequests` 字节一致）。`admin_write_quota_exceeded` 保持不动——它是
   文档化的独立配额契约（error-codes.md:581），收敛不改变配额/速率的语义区分。
3. **deny-all 语义三后端一致**：统一为 `(ok=false, retryAfter=0)`——即 429 体照写、
   **不写 Retry-After 头**（Memory/SQLite 现状）。`redis.NewLimiterFromRate` 的
   `perSecond<=0` 分支删除 365 天窗口：拒绝路径返回 `(false, 0)`，不再把荒谬的一年
   退避泄漏给客户端（键空间卫生与窗口模型无关）。
4. **契约文档同步**：`docs/error-codes.md` "Rate limiting + payload" 表把 `rate_limited`
   的触发面扩为「全局中间件、`POST /register` 限流、grant 级限流、admin 限流」；
   删除/不新增任何其他限流 429 错误串。

### 验收标准

1. 新测试（`interfaces/sso`）：grant 限流拒绝响应体字节等于 `{"error":"rate_limited"}`、
   `Retry-After` 存在且为 ceil 秒、`Cache-Control: no-store` 存在；`grant_type` 本身
   非法（未注册）时仍返回 400 `unsupported_grant_type`——限流与非法参数不再混码。
2. 新测试（`interfaces/admin`）：admin 429 的体、`Content-Type`、`Retry-After` 与
   `interfaces/ratelimit` 的 `writeTooManyRequests` 输出字节一致。
3. 新测试（`infrastructure/redis`，miniredis）：`NewLimiterFromRate(perSecond<=0)` 的
   `Allow` 返回 `(false, 0)`；Memory/SQLite/Redis 三后端的 deny-all 行为断言为同一
   三元组（拒绝、retry=0）。
4. `docs/error-codes.md` 更新随本变更提交，`docs/docscheck` 类漂移检查（`make ci`）
   通过；全库 grep 无新增限流 429 错误串。
5. 既有测试全绿：`WithGrantTypeRateLimit(0, ...)` 的全拒语义、负数不限语义在 SPI
   迁移后保持（迁移前后决策序列一致）。

## 决策三：语义与度量收敛——三后端一致性 conformance 套件 + 拒绝度量统一进 `sso_rate_limit_hits_total`

### 问题

(a) **语义漂移**：同一份 `(per_sec, burst)` 配置，memory/sqlite 后端是 token-bucket，
Redis 后端是 fixed-window（`infrastructure/redis/ratelimit.go:25-35` 文档自述），窗口
边缘的突发行为不同，且没有任何测试钉住"同一配置 = 同一对外决策"。(b) **度量漂移**：
`sso_rate_limit_hits_total`（`platform/metrics/consts.go:110`）只在中间件拒绝路径
`recordRejection`（`interfaces/ratelimit/middleware.go:191-208`）计数；grant、admin、
signup 三个限流点的拒绝零指标，撞库事故中运维无法判断是哪个限流面在生效。
(c) **生命周期漂移**：memory 后端有 memreaper 惯例（`StartPruner`/`Close`，
`ratelimit.go:155-198`），threaaction 是借锁清扫，Redis 靠 TTL——清理策略三套并存
（threaaction 一套在决策一删除，本决策收尾语义统一）。

### 证据

- `infrastructure/redis/ratelimit.go:25-35` — "This is a FIXED-WINDOW counter ...
  not the token-bucket the MemoryLimiter / SQLiteLimiter peers use"。
- `cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go:51-135` —
  `BuildRateLimitPolicy` 把同一 `config.RateLimitConfig` 分别映射到
  `NewMemoryLimiter`（85 行）、`redisbackend.NewLimiterFromRate`（108-120 行）、
  `NewSQLiteLimiter`（121-135 行）——配置层看不出算法差异。
- `interfaces/ratelimit/middleware.go:191-208` — `recordRejection`：唯一计数点，仅
  中间件路径；`Policy.Metrics`/`TenantKeyFunc` 注释 "Called ONLY on the reject path"。
- `platform/metrics/consts.go:110` — `NameRateLimitHitsTotal`；`platform/metrics/
  conditional_access.go:56-64` — `ObserveRateLimitHit` 的 nil-safe 注册模式。
- `interfaces/sso/accessors.go:127` — `func (s *Server) Metrics() *metrics.Metrics`，
  grant/admin/signup 三个限流点的接线方（`*sso.Server`/`AdminMiddleware`）均已持有
  Metrics，收敛零新增 DI。
- `interfaces/ratelimit/ratelimit.go:240-247` — `MemoryLimiter.Buckets()` 自述
  "Test-only"（桶规模无生产观测；方向二已另行处理额度指标，本决策不重复）。

### 提议行为

1. **一致性 conformance 套件**（先例：`permissionstest.ConformanceSuite`，AGENTS.md
   §4）：新增 `interfaces/ratelimit/ratelimitconformance`（或同包 `_test.go`），跑一段
   固定的 Allow 序列（填满→耗尽→refill 时序→deny-all→窗口边界）对 Memory、SQLite、
   Redis（miniredis）三后端断言 `(ok, retryAfter)` **逐调用一致**。为通过该套件，Redis
   后端把固定窗口升级为 Lua token-bucket（refill = elapsed × per_sec、cap burst、单
   slot 原子，保留现有 INCR/EXPIRE 脚本的原子性与 TTL 卫生）——"窗口 vs 桶"从此只有
   一个语义。套件同时断言三后端的 deny-all 与 fail-open 契约一致（决策二已收敛
   deny-all）。
2. **度量路径统一**：把 `recordRejection` 提炼为包级 nil-safe 辅助
   `ObserveRateLimitRejection(m *metrics.Metrics, tenant string)`（tenant 由调用方在
   拒绝路径解析，热路径零成本），`sso_rate_limit_hits_total{tenant}` 的名字与标签集
   保持不变（沿用方向二规格"不破坏既有面板"的先例）。grant 限流（`checkGrantRateLimit`
   拒绝分支，经 `s.Server.Metrics()`，`interfaces/sso/accessors.go:127`）、admin 限流
   （`checkRateLimit` 拒绝分支，经 `AdminMiddleware.Deps.Metrics()`，
   `interfaces/admin/deps.go:63`）、signup 限流（`rejectSignupRateLimit` 拒绝分支，
   经 `Deps` 的 server accessor）三处全部接入该计数——运维在撞库事故中至少能看到
   限流拒绝总量，而不再只看到中间件那一层。threaaction 的 `allow()` 是内部动作决策
   门（非 HTTP 429 面，拒绝已走 `recordAudit` 审计），明确列为非目标，不做指标接线。
3. **生命周期收敛**：决策一的 shared 固定窗口实现与 `MemoryLimiter` 共用同一
   memreaper `StartPruner`/`Close` 惯例与空闲回收阈值常量（`defaultStalePruneAfter`）；
   Redis 后端维持 TTL 租赁并在包文档中写明与 memreaper 惯例的对应关系。三处清理逻辑
   各有一份文档化语义。
4. `docs/observability.md` 同步：`sso_rate_limit_hits_total` 的触发面从「中间件拒绝」
   扩为「全部 HTTP 限流面拒绝（中间件、DCR、grant、admin、signup）」。

### 验收标准

1. conformance 套件对三后端全绿：同一 `(per_sec, burst)` 下逐调用 `(ok, retryAfter)`
   一致（含 deny-all、fail-open 注入、窗口边界）；套件接入 `go test ./...` 而非仅
   `_test.go` 单包（Redis 后端经 miniredis）。
2. 指标测试：grant/admin/signup 各构造一次拒绝，断言 `sso_rate_limit_hits_total`
   各 +1 且 tenant 标签按各自拒绝路径解析；未接 Metrics（nil）时全部 no-op（沿用
   nil-safe 模式）；`ratelimit_bench_test.go` 允许路径基准无显著回归。
3. Redis Lua token-bucket 的原子性测试：并发 INCR 下不超发、TTL 首击设置不丢失
   （沿用现有 allowScript 测试模式）；既有 Redis 固定窗口语义变更在包文档中记录。
4. threaaction 在决策一迁移后无私有清理代码残留（`evictExpiredLocked` 等符号为空），
   其生命周期即 shared 实现的 memreaper 惯例。
5. `docs/observability.md` 与 `docs/error-codes.md` 更新随变更提交，`make ci`
   （含 docscheck、嵌套模块、config 校验）全绿；`go test ./... -race` 全绿。
