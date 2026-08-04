# 需求规格：interfaces/ratelimit 方向二——限流剩余额度可见性（X-RateLimit-* 信息头与额度指标）

> 依据 `docs/auto/interfaces-ratelimit-analysis.md` 方向二展开。本规格只做加法式改造，
> 不改键语义、不动中间件在链中的位置（认证后限流属方向一，不在本规格内）、不收敛
> 五套平行限流机制（方向三，不在本规格内）。429 响应体 `{"error":"rate_limited"}`
> 契约（`docs/error-codes.md`）保持不变，不新增错误码。
>
> 三条改进呈依赖链：决策一扩展 SPI（地基）→ 决策二消费额度状态输出信息头（对外契约）
> → 决策三把同一状态接到可观测性（运维契约）。三条均需同步更新 `docs/observability.md`
> 等契约文档（AGENTS.md §5 规则 6）。

## 决策一：扩展 Limiter SPI——`Allow` 返回额度状态（remaining/limit/reset），替代丢弃额度的二元组

### 问题

`Limiter` 契约 `Allow(key) (ok bool, retryAfter time.Duration)`
（`interfaces/ratelimit/ratelimit.go:38-43`）只回传"是否放行 + 重试等待"，把剩余额度
整个丢弃：`reserve()`（`ratelimit.go:117-148`）在拒绝路径直接 `reservation.Cancel()`，
请求被拒绝后桶里还剩多少 token 无从得知；允许路径同样拿不到余量。三个后端其实都在
内部持有或已经取到这些数据（见证据），只是 SPI 没有出口，导致任何消费方（中间件、
指标、运维）都无法表达"还剩多少额度"。

### 证据

- `interfaces/ratelimit/ratelimit.go` — `Limiter` 接口定义（38-43 行）；`reserve`（117-148 行）
  拒绝时 `reservation.Cancel()` 后丢弃状态，`perSecond<=0` 分支直接 `return false, 0`；
  `MemoryLimiter.Buckets`（200-210 行）自述 "Test-only"。
- 底层库已提供取数能力：`golang.org/x/time/rate.Limiter.Tokens()`（模块缓存
  `x/time@v0.15.0/rate/rate.go:94`）可在 Reserve/Cancel 后读取当前 token 数——Memory
  后端无需新增状态即可计算 remaining。
- `interfaces/ratelimit/sqlite_limiter.go` — `loadBucketTokens`/`consumeToken` 已持有
  refill 后的 `tokens` 浮点值（refill 封顶 `burst`），拒绝路径只因 SPI 无出口而丢弃。
- `infrastructure/redis/ratelimit.go` — `allowScript` 一次原子往返已返回
  `{count, pttl}`，`Allow` 只消费了 pttl 计算 Retry-After，`count`（= 本窗口已用额度）
  被丢弃。

### 提议行为

把二元组返回值替换为额度结构体，三个后端（Memory/SQLite/Redis）在同一提交内同步实现：

```go
// Allowance 是一次 Allow 决策的完整额度状态。OK=false 时 RetryAfter 为
// 下一次放行前的等待；Remaining/Limit/ResetIn 在 OK 与 !OK 时都有效
// （fail-open 除外，见下）。
type Allowance struct {
    OK         bool
    RetryAfter time.Duration // !OK 时 >0；deny-all 配置恒为 0（无重置语义）
    Remaining  int           // 本次请求消耗/拒绝后桶内剩余（下限 0）
    Limit      int           // 桶容量（burst 或固定窗口 limit）
    ResetIn    time.Duration // 距回满/窗口重置的时长；deny-all 恒为 0
}

type Limiter interface {
    Allow(key string) Allowance
}
```

各后端映射（一次 Allow 内完成，零额外往返）：

- `MemoryLimiter`：`Remaining = int(floor(lim.Tokens()))`（拒绝路径在
  `Cancel()` 之后读取），`Limit = burst`，`ResetIn = (burst - tokens) / perSecond`。
- `SQLiteLimiter`：`Remaining = int(floor(tokens))`（`consumeToken` 已有该值），
  `Limit = burst`，`ResetIn = (burst - tokens) / perSecond`；`denyAll` 分支返回
  `{OK:false, RetryAfter:0, Remaining:0, ResetIn:0}`。
- `redis.Limiter`：`Remaining = max(limit - count, 0)`，`Limit = limit`，
  `ResetIn = pttl`；deny-all 配置（`NewLimiterFromRate` 的 365 天窗口）拒绝路径改为
  返回 `RetryAfter:0`，与 Memory/SQLite 的 deny-all 契约对齐（365 天仅保留为键空间
  TTL，不再泄漏为客户端退避信号）。
- fail-open（Redis/SQLite 错误、键形状异常）：返回 `{OK:true}`，Remaining/Limit/ResetIn
  置零，消费方据此不写额度头（见决策二），避免误导客户端自限速。

### 验收标准

1. `go build ./... && go vet ./...` 与 `TestMaintainability_|TestArchitecture_` 全绿；
   三个 `var _ Limiter = (*X)(nil)` 断言与全部实现更新完毕，无残留旧签名调用点。
2. `interfaces/ratelimit/ratelimit_test.go`（Memory）：连续调用后 `Remaining` 单调递减
   至 0；refill 后 `ResetIn` 缩短、`Remaining` 回升且封顶 `Limit == burst`；
   `perSecond<=0` 时恒 `{OK:false, Remaining:0, RetryAfter:0, ResetIn:0}`。
3. `sqlite_limiter_test.go`：同一 DB 两个实例（跨 replica 模拟）读取到一致的
   Remaining；拒绝后不持久化（tokens 回滚）但返回值正确。
4. `infrastructure/redis` 测试（miniredis）：固定窗口下 `Remaining = limit - count`
   递减、窗口翻转后恢复为 `Limit`；deny-all 配置拒绝路径 `RetryAfter == 0`。
5. fail-open 路径（注入 SQL/Redis 错误）返回 `{OK:true}`，不 panic、不误报额度。
6. 新 `Allowance` 字段与映射规则同步写入 `ratelimit.go` 包级文档注释。

## 决策二：中间件输出 X-RateLimit-Limit/Remaining/Reset 信息头，并统一三后端 429 的 Retry-After 语义

### 问题

SPA/前端没有主动自限速的手段：只能撞到 429 才退避，无法按剩余额度提前降速。
`writeTooManyRequests`（`interfaces/ratelimit/middleware.go:216-233`）只写
`Retry-After`，允许路径不写任何额度头。且 Retry-After 语义三后端漂移：Memory 与
SQLite 的 deny-all 配置返回 retry=0 → 中间件**不写 Retry-After 头**
（`ratelimit.go` `reserve` 的 `perSecond<=0` 分支、`sqlite_limiter.go` `consumeToken`
的 `denyAll` 分支），而 Redis 的 deny-all 是 365 天窗口
（`infrastructure/redis/ratelimit.go` `NewLimiterFromRate`），客户端拿到的退避信号
要么缺失、要么荒谬——同一份 `security.rate_limit.*` 配置在不同后端下对外行为不一致。

### 证据

- `interfaces/ratelimit/middleware.go` — `writeTooManyRequests`（216-233 行）：仅
  `HeaderRetryAfter`，`retry==0` 时不写任何头；`Middleware`/`DynamicMiddleware` 的
  Allow 调用点只消费 `ok, retry`。
- `interfaces/ratelimit/consts.go` — 头名常量块（`HeaderRetryAfter` 等），新增头名
  应在此登记（sso 无法 import ratelimit，循环依赖约束已在此注释说明）。
- `interfaces/ratelimit/ratelimit.go` `reserve` — `perSecond<=0` 拒绝返回 `(false, 0)`。
- `interfaces/ratelimit/sqlite_limiter.go` `consumeToken` — `denyAll → (false, 0, true)`。
- `infrastructure/redis/ratelimit.go` `NewLimiterFromRate` — deny-all = `1` 次/365 天窗口。

### 提议行为

- `consts.go` 新增三个头名常量：
  `HeaderRateLimitLimit = "X-RateLimit-Limit"`、
  `HeaderRateLimitRemaining = "X-RateLimit-Remaining"`、
  `HeaderRateLimitReset = "X-RateLimit-Reset"`（Unix epoch 秒，IETF draft 惯例）。
- 中间件（`Middleware` 与 `DynamicMiddleware` 两处 Allow 调用点，逻辑收敛为一个
  `writeRateLimitHeaders(w, a Allowance)` 辅助函数）：凡请求命中某个 limiter 规则，
  **允许与拒绝两条路径都写三头**，数值来自同一次 `Allow` 返回的 `Allowance`——
  零额外后端往返。fail-open 的 `{OK:true, Remaining:0, Limit:0}` 不写额度头
  （避免以 0 额度误导客户端）。
- 429 路径：`Retry-After` 维持现有 ceil 逻辑（`writeTooManyRequests`），仅当
  `RetryAfter > 0` 时写入；deny-all 统一为**不写 Retry-After**（三后端一致），但
  `X-RateLimit-Remaining: 0`、`X-RateLimit-Reset` 不写（无重置语义），客户端凭
  `Remaining: 0` 即可识别"永久额度"。
- 429 响应体 `{"error":"rate_limited"}` 与 `Cache-Control` 语义不变；
  `Retry-After` 与 `X-RateLimit-Reset` 并存时以 `Retry-After` 为准（HTTP 标准优先）。

### 验收标准

1. `interfaces/ratelimit/ratelimit_test.go`（或新增 middleware 测试）：命中规则且
   放行的响应带 `X-RateLimit-Limit == burst`、`X-RateLimit-Remaining` 与桶状态一致、
   `X-RateLimit-Reset` 为合理未来 epoch 秒；未命中规则（`limiterFor` 返回 nil）不写任何
   X-RateLimit-* 头。
2. 429 响应同时携带 `Retry-After`（ceil 秒）与三头；`Remaining` 递减到 0 时下一次
   请求必 429（剩余额度与放行决策互洽）。
3. deny-all（`perSecond<=0`）：Memory、SQLite、Redis 三后端行为**字节一致**——429 体
   + `X-RateLimit-Remaining: 0`，无 `Retry-After`、无 `X-RateLimit-Reset`；
   `redis.NewLimiterFromRate` 的拒绝路径测试断言 `RetryAfter == 0`。
4. fail-open 注入测试：额度头不出现，请求放行。
5. `DynamicMiddleware` 热更测试（现有 PolicyStore 测试模式）：`PolicyStore.Set`
   更换 limiter 后新响应头反映新桶参数。

## 决策三：额度可观测性——允许路径计数、剩余额度采样 gauge 与活动桶规模指标

### 问题

指标面只有拒绝计数 `sso_rate_limit_hits_total`
（`platform/metrics/consts.go:110` `NameRateLimitHitsTotal`），且仅在拒绝路径
`recordRejection`（`interfaces/ratelimit/middleware.go:195-213`）计数——允许路径
零指标，运维无法在撞库/突发事故**前**看到"距阈值还剩多少余量"来调
`security.rate_limit.*`（该配置已支持 SIGHUP 热更，但调参靠猜）。桶规模
（`MemoryLimiter.Buckets()`，`ratelimit.go:200-210`）被注释为 test-only，IP 喷洒
攻击下桶数暴涨也无从观察。`docs/observability.md:43` 的指标清单只有一行。

### 证据

- `platform/metrics/consts.go:110` — `NameRateLimitHitsTotal`（唯一限流指标）。
- `interfaces/ratelimit/middleware.go` — `recordRejection`（195-213 行）：仅拒绝路径
  调用；`Policy.TenantKeyFunc` 文档明确 "Called ONLY on the reject path"——任何允许
  路径的 tenant 解析都必须遵守此热路径约束（store-backed 解析不得进入正常流量）。
- `platform/metrics/conditional_access.go:56-64` — `ObserveRateLimitHit` 的 nil-safe
  注册模式，新指标的观测辅助函数沿用此模式。
- `interfaces/ratelimit/ratelimit.go:200-210` — `Buckets()` 自述 "Test-only"。
- `interfaces/ratelimit/ratelimit_bench_test.go` — 允许路径热路径基准，作为回归基线。
- `docs/observability.md:43` — 唯一指标行，契约文档需同步。

### 提议行为

新增三个有界基数指标（`platform/metrics/consts.go` 登记名字、
`conditional_access.go` 模式新增 nil-safe 观测辅助函数）：

1. `sso_rate_limit_requests_total{result, tenant}`（Counter，`result ∈ {allowed, rejected}`）：
   允许路径与拒绝路径都计数；**tenant 标签只在拒绝路径解析**（沿用
   `TenantKeyFunc` 的现有约束），允许路径一律 `TenantLabelUnknown`——文档注释相应
   更新为 "resolved on the reject path; allowed-path rows carry
   TenantLabelUnknown"。不修改既有 `sso_rate_limit_hits_total` 的名字/标签集
   （避免破坏现有面板），新计数与旧拒绝计数并存。
2. `sso_rate_limit_remaining`（Gauge，标签 `{policy}`，policy 取前缀规则或 `default`）：
   采样更新，复用 `Allow` 的 1/64 采样点（与 prune 同比例，`calls.Add(1)%64 == 0`），
   采样命中时用本次 `Allowance.Remaining/Limit` 记录当前余量（桶满时记录 `Limit`）。
   采样保证允许路径的每请求成本仅一次原子自增，不引入 tenant 解析。
3. `sso_rate_limit_buckets`（Gauge）：把 `MemoryLimiter.Buckets()` 从 test-only 接入
   生产观测——`StartPruner` 的周期清扫回调内上报当前活动桶数（已在后台 goroutine，
   零热路径成本）；SQLite 后端以采样 `SELECT COUNT(*)` 上报（复用 1/64 采样）；
   Redis 后端文档注明不支持（无低成本 COUNT），指标缺省不注册。

`docs/observability.md` 在本次变更中新增三行指标说明（名字、类型、标签、更新时机）。

### 验收标准

1. `ratelimit_metrics_test.go` 扩展：允许请求后 `sso_rate_limit_requests_total{result="allowed"}`
   递增、拒绝后 `{result="rejected"}` 递增且 `tenant` 标签按 `TenantKeyFunc` 解析；
   未接 `Metrics`（nil）时全部 no-op（沿用 nil-safe 模式）。
2. 采样测试（短间隔构造 64 次调用）：`sso_rate_limit_remaining` 在采样点更新、数值与
   `Allowance.Remaining` 一致；未接 `TenantKeyFunc` 时拒绝路径标签为
   `TenantLabelUnknown`（保持现有行为）。
3. `sso_rate_limit_buckets`：构造后创建/超时回收 key，gauge 随之涨落（Memory 后端
   用 `NewMemoryLimiterWithStalePrune` 缩短老化窗口）。
4. `ratelimit_bench_test.go` 允许路径基准无显著回归（允许路径成本 = 一次原子自增 +
   既有 reserve）；`go test ./... -race` 全绿。
5. `docs/observability.md` 三行新指标与实现一致（契约文档随变更提交）。
6. 既有 `sso_rate_limit_hits_total` 定义与行为不变（名字、标签集、拒绝路径语义）。
