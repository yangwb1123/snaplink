# 设计文档：方向二——限流剩余额度可见性（X-RateLimit-* 信息头与额度指标）

> 来源：[需求规格](interfaces-ratelimit-direction2-spec.md)（三条改进：SPI 地基 → 对外头契约 → 可观测性）。
> 本文回答规格未覆盖的四个问题：**API 表面**（符号级签名与字段）、**存储模型**（各后端状态如何
> 导出，是否需要 schema/脚本变更）、**失败模式**（fail-open/deny-all/除零/时钟边界）、
> **破坏面**（哪些既有契约会断、谁必须在同一次提交内迁移）。
>
> 范围与规格一致：只做加法；不改键语义、不动中间件链位置、不收敛五套限流机制；429 体
> `{"error":"rate_limited"}`（`docs/error-codes.md`）不变，不新增错误码。

## 0. 全局破坏面清单（三个决策共用的迁移面）

决策一的 SPI 签名变更在 Go 里是编译期强制原子变更：任何只改实现不改调用方的提交都过不了
`go build`。以下是完整迁移面（规格只列了 `ratelimit.go`/`middleware.go`/三后端，本设计补全
**规格未覆盖的两处**）：

| 表面 | 位置 | 迁移内容 |
|---|---|---|
| `Limiter` 接口 | `interfaces/ratelimit/ratelimit.go:38-43` | `Allow(key) (bool, time.Duration)` → `Allow(key) Allowance` |
| Memory 实现 | `ratelimit.go:140`（`Allow`）、117-148（`reserve`） | 返回值迁移 + Cancel 后读 `Tokens()` |
| SQLite 实现 | `sqlite_limiter.go:145`（`Allow`）、`consumeToken` | 返回值迁移（tokens 值已有） |
| Redis 实现 | `infrastructure/redis/ratelimit.go:133`（`Allow`） | 返回值迁移 + deny-all 标记 |
| 中间件调用点 | `middleware.go` `Middleware`/`DynamicMiddleware` | 消费 `Allowance`（决策二一并做） |
| **sso 直调点** | `interfaces/sso/quota.go:154`（`checkClientRegistrationRateLimit`） | `ok, retry` → `a.OK, a.RetryAfter` |
| **admin 直调点** | `interfaces/admin/governance.go:314`（`checkRateLimit`） | 同上，机械迁移 |
| **selfservice 子集接口（规格未覆盖）** | `protocols/selfservice/selfservicecore/deps.go:21` + `protocols/selfservice/signup.go:96` | 见决策一 §"破坏面"——Go 无协变，必须同型迁移 |
| 测试双 | `cmd/sso-server/readycheck_test.go:150`（`pingerLimiter`）、`rate_limit_reload_test.go:27`（`closeCountingLimiter`） | 实现新签名 |
| 测试直调 | `cmd/sso-server/security_test.go:157,160`、`interfaces/ratelimit/` 全部单测/fuzz/bench | 新签名 + 新断言 |
| 契约文档 | `docs/observability.md:43`、`docs/openapi.yaml`（429/限流响应头若已记录） | 决策二/三同步更新（AGENTS.md §5 规则 6） |

不需要迁移的表面：`interfaces/sso/server_token.go:370` 的 `entry.limiter.Allow()` 是
`golang.org/x/time/rate.Limiter`（无 key 参数），与 `ratelimit.Limiter` 无关；
`interfaces/middleware/degradation.go:57` 的 `cfg.Policy.Allow(mode, ...)` 是降级策略的
自有 Policy，无关；`WithRateLimit`/`WithClientRegistrationRateLimit`/`SetRateLimitPolicy`
等以 `ratelimit.Limiter` 为参数类型的公开 API **签名不变**（接口名没变，只是方法返回类型
变了，实现类自动跟随），调用方零改动。

---

## 决策一：扩展 Limiter SPI——`Allow` 返回 `Allowance` 额度状态

### API 表面

`Allowance` 值类型放在 **`shared/spi`**（新增 `shared/spi/ratelimit.go`），不放在
`interfaces/ratelimit`——这是本设计对规格的关键补充，理由见 §"破坏面"。

```go
// package spi
// RateAllowance 是一次限流 Allow 决策的完整额度状态。三个后端（Memory/SQLite/Redis）
// 在同一提交内同步实现；ratelimit.Limiter 与 selfservicecore.RateLimiter 共享此类型，
// 使 *MemoryLimiter 等实现同时满足两个接口（Go 结构类型无协变，类型必须同一）。
type RateAllowance struct {
    OK         bool          // 是否放行
    RetryAfter time.Duration // !OK 时 >0；deny-all 恒为 0（无重置语义）
    Remaining  int           // 本次消耗/拒绝后桶内剩余（下限 0）
    Limit      int           // 桶容量（burst 或固定窗口 limit）
    ResetIn    time.Duration // 距回满/窗口重置时长；deny-all 恒为 0
}
```

```go
// interfaces/ratelimit/ratelimit.go
type Limiter interface {
    Allow(key string) spi.RateAllowance
}
```

```go
// protocols/selfservice/selfservicecore/deps.go —— 同型迁移，注释同步更新
type RateLimiter interface {
    Allow(key string) spi.RateAllowance
}
```

`sso.allowanceToTuple` 之类适配器**不需要**：四个消费方（中间件、quota.go、governance.go、
signup.go）都只用 `OK`/`RetryAfter`，迁移是字段改名，无逻辑变化。

### 存储模型（零 schema / 零脚本变更——这是本决策最重要的性质）

| 后端 | 数据来源 | 映射 |
|---|---|---|
| Memory | 无新状态。`x/time/rate.Limiter.Tokens()`（v0.15.0 rate.go:94）在 `reserve()` 的 `Reserve()`/`Cancel()` 之后读取 | `Remaining = int(floor(Tokens()))`；`Limit = burst`；`ResetIn = (burst - Tokens()) / perSecond` |
| SQLite | `consumeToken` 已持有 refill 后封顶的 `tokens` 浮点值；拒绝路径**不持久化**（事务回滚），返回的是本地计算值 | 允许路径 `Remaining = int(floor(tokens))`；拒绝路径 `tokens < 1 → Remaining = 0`；`ResetIn = (burst - tokens) / perSecond` |
| Redis | `allowScript` 已原子返回 `{count, pttl}`（`infrastructure/redis/ratelimit.go:96-110`），`Allow` 现丢弃 count | `Remaining = max(limit - count, 0)`（count 为本次 INCR 后值，语义与 Memory 的"消耗后余量"一致）；`Limit = limit`；`ResetIn = pttl` |

三层都不需要新增状态或往返：Memory 的 `Tokens()` 在 shard 锁内读取（`rate.Limiter` 自带锁是
叶子锁，无锁序问题）；SQLite 的 tokens 已在事务内；Redis 的 count/pttl 是同一次脚本调用的
返回值。SQLite 表结构（`rate_limit_buckets`）、Redis Lua 脚本、键 TTL 语义全部不动。

### 失败模式

1. **fail-open**（SQL/Redis 错误、键形状异常）：`{OK:true, 其余零}`——与现行为
   `(true, 0)` 等价，但明确要求 `Remaining/Limit/ResetIn` 置零，消费方据此**不写额度头**
   （决策二），避免以 0 额度误导客户端自限速。
2. **deny-all**（`perSecond <= 0`）：三后端统一 `{false, 0, 0, 0, 0}`。Memory 侧
   `reserve` 的 `perSecond<=0` 分支（ratelimit.go:140-147）在 `Cancel()` 后返回全零——
   现有 `~292 年 InfDuration` 哨兵防护保留并前移；`ResetIn` 必须显式防除零
   （`(burst-tokens)/perSecond` 在 perSecond<=0 时是 Inf/NaN，不能进入 Duration）。
   SQLite 的 `consumeToken` denyAll 分支同理。**Redis 是行为变更**：`NewLimiterFromRate`
   的 deny-all（limit=1 / 365 天窗）拒绝路径从 `RetryAfter=365d` 改为 0。
3. **Redis deny-all 需要显式标记**：`NewLimiterFromRate(perSecond<=0)` 产出的
   `{limit:1, window:365d}` 与合法配置（limit=1 长窗口）**值上不可区分**，不能靠数值推断。
   在 `redis.Limiter` 增加未导出字段 `denyAll bool`（`NewLimiterFromRate` 构造时置位），
   `Allow` 拒绝分支遇 `denyAll` 返回全零；`NewLimiter` 直连构造的 365 天窗口保持旧语义
   （那是操作者的显式选择，不在统一范围内）。
4. **`reservation.OK()==false`**（n>burst，实践中不可达）：返回
   `{false, 0, 全零}`——deny 形状，安全。
5. **Redis `pttl < 0`**（-1/-2，脚本内理论上不出现）：`ResetIn` 回退整窗 `window`，
   与现有 `RetryAfter` 回退逻辑一致；`denyAll` 分支不受影响（全零优先）。

### 破坏面与缓解（规格未覆盖的关键发现）

**`selfservicecore.RateLimiter` 是并行 SPI 表面，必须同型迁移。** 今天
`*MemoryLimiter` 同时结构性满足 `ratelimit.Limiter` 和 `selfservicecore.RateLimiter`
（deps.go:21，签名逐字相同）。`Allow` 返回类型一改，`*MemoryLimiter` 不再满足后者，
**`WithSelfServiceSignupRateLimiter(ratelimit.NewMemoryLimiter(...))` 编译即断**——这是
`interfaces/sso/options_passwd.go:139` 的公开 API 且文档示例（options_passwd.go:125-137）
就写了这个用法。Go 无协变，无适配器可救（适配器只能改 `interfaces/sso` 的签名，救不了
操作者调用点）。

缓解：`RateAllowance` 提升到 `shared/spi`（层秩 0，`interfaces/ratelimit` 与
`protocols/selfservice` 都可导入，`spi` 已承载 `Logger`/`RegistrationGate` 等小 SPI 类型，
先例一致）。两个接口返回同一个类型 → `*MemoryLimiter` 同时满足两者，公开用法零改动。
**备选已否决**：在 `selfservicecore` 复制一份 `Allowance`（结构性满足被破坏，公开用法断裂）；
把 option 参数改为 `ratelimit.Limiter`（`selfservicecore.Deps` 无法命名 `interfaces` 类型，
违反层边界，deps.go:16-19 的注释明确禁止）。

其余破坏面（全部编译期兜底，无运行时风险）：测试双 `pingerLimiter`/`closeCountingLimiter`、
`security_test.go` 直调、`fuzz_test.go`/`ratelimit_test.go`/`sqlite_limiter_test.go`/
`ratelimit_bench_test.go` 的元组解构、`ratelimit_metrics_test.go` 经中间件间接调用（随
中间件迁移自动跟随）。`ratelimit_test.go` 的 `var _ Limiter` 断言保持，另补
`selfservicecore` 侧 `var _ selfservicecore.RateLimiter = (*MemoryLimiter)(nil)` 防回归。

---

## 决策二：中间件输出 X-RateLimit-Limit/Remaining/Reset，统一三后端 429 的 Retry-After 语义

### API 表面

`interfaces/ratelimit/consts.go` 头名常量块新增（循环依赖注释原样保留，sso 不 import
ratelimit 的约束不变）：

```go
HeaderRateLimitLimit     = "X-RateLimit-Limit"
HeaderRateLimitRemaining = "X-RateLimit-Remaining"
HeaderRateLimitReset     = "X-RateLimit-Reset" // Unix epoch 秒（IETF draft 惯例，见"破坏面"）
```

中间件收敛为一个辅助函数（`middleware.go` 新增，两个 Allow 调用点共用；函数长度预算内）：

```go
// writeRateLimitHeaders 把同一次 Allow 的 Allowance 写成 X-RateLimit-* 头。
// 调用点保证在 WriteHeader 之前执行。
func writeRateLimitHeaders(w http.ResponseWriter, a spi.RateAllowance)
```

**头写入规则**（本设计对规格的精确化——fail-open 与 deny-all 在 Allowance 上都表现为
`Limit==0`，必须用 `OK` 区分）：

| 条件 | 写什么 |
|---|---|
| `a.Limit > 0`（正常放行/拒绝） | 三头全写：`Limit`、`Remaining`、`Reset = now.Add(a.ResetIn).Unix()` |
| `!a.OK && a.Limit == 0`（deny-all） | 只写 `X-RateLimit-Remaining: 0`；无 `Retry-After`、无 `Reset`、无 `Limit` |
| `a.OK && a.Limit == 0`（fail-open） | 什么都不写 |
| 未命中规则（`limiterFor` 返回 nil） | 什么都不写（现有短路保持） |

429 路径流程：`writeRateLimitHeaders(w, a)` → `writeTooManyRequests(w, a.RetryAfter)`
（后者**原样保留**：ceil 逻辑、`retry>0` 才写、`Content-Type`、`rateLimitedBody`——
体字节不变）。允许路径流程：`writeRateLimitHeaders(w, a)` → `next.ServeHTTP`。
`Retry-After` 与 `X-RateLimit-Reset` 并存时以 `Retry-After` 为准（HTTP 标准优先，规格已定）。

`Reset` 语义（记录为契约，写进 consts.go 注释）：桶后端 = 距**回满**的时长
（`(burst-tokens)/perSecond`），窗口后端 = 距**窗口重置**的时长（pttl）——对 token 桶，
"回满"是"窗口重置"的自然类比，两者在 `X-RateLimit-Reset` 头里统一为 epoch 秒。桶恰好满时
`ResetIn==0` → `Reset` 为当前秒（真实语义："此刻已满"），不特殊处理。

### 失败模式

1. **写头顺序**：头必须在 `WriteHeader` 之前 set。允许路径在 `next.ServeHTTP` 前写——
   若下游 handler 自行写状态码，头已就位，安全；429 路径在 `writeTooManyRequests` 内部
   `WriteHeader` 之前。这是调用点唯一的新增约束，测试断言覆盖。
2. **头注入**：三个头值全部来自 `strconv.Itoa`/`strconv.FormatInt` 数值，无字符串回显，
   无注入面。`Reset` 的 epoch 来自服务器时钟（`time.Now`），非请求输入。
3. **deny-all 字节一致性**：三后端 Allowance 全零 → 中间件路径一致 → 429 体 +
   `X-RateLimit-Remaining: 0`，无 `Retry-After`/`Reset`/`Limit`。Redis 的 365 天窗口仅保留
   为键空间 TTL（防键堆积），不再泄漏为客户端退避信号。
4. **fail-open 不写头**：`{OK:true, Limit:0}` 规则保证故障期间客户端拿不到
   `Remaining: 0`，不会据错误数据自限速。

### 破坏面与缓解

1. **e2e 契约**：`test/ratelimit_e2e_test.go:111` 断言正常 limiter 的 429 携带
   `Retry-After`——正常桶路径 `RetryAfter>0`，行为不变，测试不破；新增断言可顺带补
   X-RateLimit-* 头。
2. **`DynamicMiddleware` 热更**：Allowance 来自当次请求从 `PolicyStore.Get()` 读到的
   当前 limiter，`PolicyStore.Set` 换桶后新头自然反映新参数——无需额外机制；验收测试用现有
   PolicyStore 测试模式覆盖。闭包内采样计数器（决策三）跨热更持续计数，无状态残留问题。
3. **文档契约**：`docs/openapi.yaml` 目前只在 503 降级路径记录 `Retry-After`
   （6151 行附近），限流 429 未记录响应头——本变更在 openapi.yaml 的 429 响应（若存在）
   或限流中间件说明处补 X-RateLimit-* 三头 + `Retry-After`；`docs/error-codes.md` 无新
   错误码，不动。
4. **Reset 语义歧义（记录在案的风险）**：IETF `draft-ietf-httpapi-ratelimit-headers`
   的 `Reset` 字段在演进中从 Unix epoch 改为 delta-seconds，而 GitHub 的部署事实标准是
   epoch。规格已定 epoch，本设计照办并写入 consts.go 注释；若未来客户端生态要求 delta，
   是头值格式的单点变更（writeRateLimitHeaders 一处），不扩散。

---

## 决策三：额度可观测性——允许路径计数、剩余额度采样 gauge、活动桶规模指标

### API 表面

`platform/metrics/consts.go` 常量块新增（`NameRateLimitHitsTotal` 名字/注释原样保留）：

```go
NameRateLimitRequestsTotal = "sso_rate_limit_requests_total" // Counter, labels: result, tenant
NameRateLimitRemaining     = "sso_rate_limit_remaining"      // Gauge,   labels: policy
NameRateLimitBuckets       = "sso_rate_limit_buckets"        // Gauge,   无标签
// 新标签常量：LabelResult = "result"（bounded: allowed | rejected）；LabelPolicy = "policy"
// （bounded: 前缀规则串或 "default"，全部来自操作者 YAML，非请求输入）
```

`metrics.Metrics` 结构体（metrics.go:403 附近）新增三字段 + 文档注释；注册与观测沿用
`conditional_access.go:56-64` 的 split-file + nil-safe 模式——新增
`registerRateLimitQuotaMetrics`（`metrics_ctor.go:54-56` 注册调用处追加一行；文件预算不够则
新开 `platform/metrics/ratelimit_quota.go`，`interfaces/ratelimit` 目录同理：现 4 个非测试
文件，新开 `middleware_metrics.go` 仍在 10 文件预算内）：

```go
func (m *Metrics) ObserveRateLimitRequest(result, tenant string) // nil-safe
func (m *Metrics) ObserveRateLimitRemaining(policy string, remaining float64) // nil-safe
func (m *Metrics) ObserveRateLimitBuckets(count float64) // nil-safe
```

### 存储模型（采样点与上报路径——本设计对规格的精确化）

**① `sso_rate_limit_requests_total`**：中间件每命中规则一次计数（两路径都计），全量不采样
（计数器必须精确）。允许路径 `tenant` 恒为 `TenantLabelUnknown`（不触碰 `TenantKeyFunc`，
遵守 "Called ONLY on the reject path" 热路径约束）；拒绝路径复用 `recordRejection`
（middleware.go:195-213）已解析的 tenant，同处追加 `result="rejected"` 计数。允许路径成本
= 一次 `CounterVec.WithLabelValues` 命中缓存后的 map 查找 + Inc（首次后无分配），bench 把关。

**② `sso_rate_limit_remaining{policy}`**：采样更新。**采样计数器放中间件闭包**（每实例一个
`*atomic.Uint64`），不放进 limiter——规格写"复用 Allow 的 1/64 采样点"，但 `calls` 是
`MemoryLimiter` 未导出字段且无 Metrics 引用，`{policy}` 标签只有中间件层可知，且 SQLite 的
prune 采样是按毫秒时钟而非调用计数（`sqlite_limiter.go` `pruneStale`）。中间件级 1/64 计数器
给三后端**统一**的采样语义：每命中规则一次原子自增，`%64==0` 时用本次 `Allowance` 的
`Remaining` 调 `ObserveRateLimitRemaining(policy, ...)`（policy 标签取自 `limiterFor` 的
匹配结果：命中前缀 → 前缀串，否则 `"default"`）。为此 `limiterFor` 返回 `(Limiter, label)`
二元组（小重构，`Middleware`/`DynamicMiddleware` 共用）。

**③ `sso_rate_limit_buckets`**：三后端各自的低成本上报路径（零热路径成本）：

| 后端 | 上报路径 | 说明 |
|---|---|---|
| Memory | `StartPruner` 周期清扫回调内 | limiter 不知 Metrics，需要新钩子：`MemoryLimiter` 增加未导出 `bucketObserver func(int)` + `SetBucketObserver` 导出 setter（nil-safe）；`StartPruner` 的 sweep 回调在 shard 循环后调 `Buckets()` 一次并触发钩子（后台 goroutine，每周期一次额外锁遍历，可忽略）。**注意**：钩子不能在 Allow 的内联采样 prune 路径触发——那在 shard 锁内，`Buckets()` 会锁所有 shard，自死锁。因此**未启用 `StartPruner`（config `prune_interval` 未设）时该 gauge 不更新**，文档注明 |
| SQLite | 复用 `pruneStale` 的 1/64 毫秒时钟采样点 | 同采样点执行 `SELECT COUNT(*) FROM rate_limit_buckets WHERE bucket_name = ?`。必须在**同一事务内**执行——`SetMaxOpenConns(1)` 下开第二个事务会自死锁；1/64 概率下延长写锁可接受 |
| Redis | 不支持（无低成本 COUNT） | gauge 注册但永不更新（恒 0）。见"破坏面"第 2 条 |

### 失败模式

1. **nil `Metrics`**：三个 observe 辅助全 nil-safe，`Policy.Metrics == nil` 时零操作
   （现有 `ObserveRateLimitHit` 模式，`ratelimit_metrics_test.go` 的 no-op 测试扩展覆盖）。
2. **基数约束**：`result` ∈ {allowed, rejected}；`tenant` 沿用现有 allowlist + other 约束
   （consts.go:143 注释）；`policy` 来自操作者 YAML 前缀串，配置有界——三者都不接受请求
   输入，符合 observability.md 的 bounded-cardinality 声明。
3. **并发**：采样计数器 atomic；`GaugeVec.Set`/`CounterVec.Inc` 由 prometheus 保证
   线程安全；`SetBucketObserver` 与 `StartPruner` 的竞态——钩子字段在 `StartPruner` 启动
   前设置（builder 顺序：`newMemoryLimiterPruned` 内 StartPruner 后接 setter），`-race`
   把关；热更 `closePolicyLimiters` 关 pruner 时钩子随 limiter 一起弃用，无泄漏。
4. **热路径成本**：允许路径 = 一次原子自增 + 一次计数 Inc + （1/64）一次 Gauge Set。
   `ratelimit_bench_test.go` 允许路径基准是回归闸（limiter 层基准：`Allowance` 为
   6 字段小结构体，amd64 寄存器传递，无堆逃逸，预期无分配变化）。
5. **既有指标不变**：`sso_rate_limit_hits_total` 名字/标签集/拒绝路径语义零改动，现有
   面板不破；新 `requests_total` 与旧计数并存（重复计数是设计使然，文档注明两者区别）。

### 破坏面与缓解

1. **规格措辞"指标缺省不注册"（Redis）与仓库模式的冲突**：`registerRateLimitMetrics`
   在 `metrics_ctor.go` 无条件调用，仓库惯例是"注册但零流量"（hits_total 在未接
   WithRateLimit 时也是零流量）。本设计选择**无条件注册 + 文档注明 Redis 后端恒 0**
   （`ObserveRateLimitBuckets` 永不触发）；若严格执行"不注册"，需把后端类型穿透进
   metrics 构造——新机制换零收益，否决。风险等级：低，纯文档差异。
2. **Memory 桶 gauge 依赖 `prune_interval`**：默认（无 StartPruner）下 gauge 不更新。
   记录进 observability.md 的指标说明行（"仅当 prune_interval 启用时更新"），不引入额外
   后台 goroutine（规格明确要求复用 StartPruner 回调）。
3. **`limiterFor` 签名变更**：返回 `(Limiter, string)`，两个中间件 + 可能的外部调用点
   （grep 确认无包外调用）同步；nil-Limiter 规则（零值 PrefixRule）保持短路，不计数不写头。
4. **允许路径计数与既有"允许路径零指标"文档冲突**：`Policy.TenantKeyFunc` 注释（
   middleware.go:200-206）说 "Called ONLY on the reject path"——本变更**不违反**：
   tenant 解析仍在拒绝路径，允许路径只写常量 `TenantLabelUnknown`；注释同步更新为
   "resolved on the reject path; allowed-path rows carry TenantLabelUnknown"。
5. **bench 回归风险**：允许路径新增一次原子自增 + 一次计数。基准对比基线为现提交的
   `BenchmarkMemoryLimiterAllow*` 数值；若计数导致显著回归（预期不应有），退路是
   `requests_total` 允许路径也走 1/64 采样——**否决**（计数器必须精确），改为优化
   `WithLabelValues` 热路径（预取 `prometheus.Counter` 句柄缓存）。

---

## 实施顺序、提交切分与验证门

依赖链：决策一（SPI）→ 决策二（头值来源）→ 决策三（同源状态接指标）。提交切分与规格
一致，每个提交独立过 `go build ./... && go vet ./...` + `TestMaintainability_|TestArchitecture_`：

1. **提交 1（地基，最大破坏面）**：`shared/spi` 新增 `RateAllowance`；`ratelimit.Limiter`
   三后端迁移；`selfservicecore.RateLimiter` 同型迁移；四个消费方（middleware 两处、
   quota.go、governance.go、signup.go）字段改名；测试双 + 全部单测/fuzz/bench 迁移；
   新增 `selfservicecore` 侧 `var _` 断言。验收 = 规格决策一 1-6 条。
2. **提交 2（对外头契约）**：consts.go 三头名；`writeRateLimitHeaders` + 两调用点；
   Redis `denyAll` 标记；middleware 测试（放行/429/deny-all 字节一致/fail-open/热更/
   未命中）；openapi.yaml 同步。
3. **提交 3（可观测性）**：metrics 常量/字段/注册/observe 辅助；中间件采样计数器 +
   `limiterFor` 二元组；`MemoryLimiter.SetBucketObserver`；SQLite 采样 COUNT；builder
   接线（`newMemoryLimiterPruned` 接收 Metrics 并挂钩子——与 `Policy.Metrics` 同源实例）；
   metrics 测试 + `docs/observability.md` 三行指标。

收尾全量门：`go test ./... -race`、`go test ./test/ -run TestE2E -v`（e2e 断言
Retry-After 存在，正常桶不受影响）、`make ci`。`ratelimit_bench_test.go` 允许路径基准
与提交前基线对比记录在提交 3 说明中。

## 风险登记与未决问题

| # | 风险 | 等级 | 缓解/决定 |
|---|---|---|---|
| 1 | `selfservicecore.RateLimiter` 结构性耦合断公开 API（规格未覆盖） | 高 | `RateAllowance` 提升 `shared/spi`，两个接口同型；编译期兜底 |
| 2 | `Reset` 头 epoch vs delta-seconds 歧义 | 中 | 规格定 epoch，consts.go 注释记录；单点可改 |
| 3 | fail-open 与 deny-all 在 `Limit==0` 上混淆 | 中 | 头写入规则用 `OK` 区分；测试三后端字节一致 |
| 4 | Redis deny-all 365 天窗口泄漏为退避信号 | 中 | `denyAll` 标记 + 拒绝路径全零；`NewLimiter` 直连路径保留旧语义（文档注明） |
| 5 | Memory 桶 gauge 依赖 `prune_interval`；Redis 恒 0 | 低 | observability.md 注明；无条件注册 |
| 6 | 允许路径计数成本 | 低 | bench 闸；退路已否决（计数器须精确），备选为句柄缓存 |
| 7 | SQLite COUNT 延长写锁 | 低 | 1/64 采样内、同事务执行，文档注明 |
| 8 | `DynamicMiddleware` 采样计数器跨热更 | 无 | 闭包级原子计数，热更后标签来自新 Policy，行为正确 |

未决问题（实施时定夺，均不阻塞）：`RateAllowance` 命名（`spi.RateAllowance` vs
`spi.Allowance`——后者过于泛化，倾向前者）；`ObserveRateLimitRequest` 的 result 常量
（`metrics.ResultAllowed`/`ResultRejected` vs 字符串直传）；openapi.yaml 补头的位置
（429 响应定义 vs 限流中间件章节）。
