# 分布式系统工程师评审：方向二——限流剩余额度可见性（X-RateLimit-* 头与额度指标）

> 输入：[方向二设计](interfaces-ratelimit-direction2-design.md)、[方向二规格](interfaces-ratelimit-direction2-spec.md)、
> [分析](interfaces-ratelimit-analysis.md)，以及当前树的全部相关代码。
> 角色：分布式系统工程师——按副本、重试、部分失败、分区、故障转移、时钟异常假设审查。
>
> **本次会话实际运行的检查**：只读核查（未改任何代码、未触发任何 gate）：
> `interfaces/ratelimit/{ratelimit,middleware,sqlite_limiter,consts}.go`、
> `infrastructure/redis/ratelimit.go`、`interfaces/sso/{options_passwd,quota}.go`、
> `interfaces/admin/governance.go`、`protocols/selfservice/{signup,selfservicecore/deps}.go`、
> `config/{config_load,config_admin}.go`、`cmd/sso-server/{main_wiring,main_shutdown,
> serverbuildplatform/build_ratelimit_cluster,build_app_security}.go`、
> `platform/metrics/{consts,metrics,metrics_ctor,conditional_access}.go`、
> `platform/migrate/migrate.go`、`interfaces/cors/cors.go`、`infrastructure/defaultimpl/memreaper/`、
> `golang.org/x/time@v0.15.0/rate/rate.go`（模块缓存）、`test/ratelimit_e2e_test.go`、
> `docs/{observability,config-reference,error-codes,openapi.yaml}` 相关章节。
>
> 证据标注：**Verified** = 本会话从可执行代码读到；**Partial** = 有保留地核实；
> **Missing** = 设计中缺失；**Proposed** = 设计意图、尚无代码。设计与树冲突时以树为准。

## 0. 结论

设计的三条决策在分布式语义上是**加法且自洽**的：不新增跨副本状态、不改变键语义、
不触碰任何 OAuth/会话/JTI/撤销/失效总线状态（§1.3 逐项追踪确认），fail-open 边界完整保留。
**无发布阻塞项。** 但存在两类必须在本变更内处理的问题：

1. **一个 High 的既有相邻缺陷**（非本设计引入，但提交 3 恰好改写同一接线）：SIGHUP 热更
   关闭旧 Policy 的 `SQLiteLimiter` 与在途请求存在 TOCTOU，`Allow` 对 nil `*sql.DB` 无防护，
   可导致进程崩溃（§2-F1）。`main_wiring.go` 声称 "SQLiteLimiter 不实现 io.Closer" 的注释是错的。
2. **四个 Medium 级设计缺口**：SQLite 拒绝路径持久化描述与代码不符（§2-F2，照文档实现会改变
   跨副本 refill 行为）；deny-all 的**允许路径**不在三路头写入表内且 `ResetIn` 有除零风险
   （§2-F3）；`per_sec: 0` 在 memory 后端被静默丢弃、在 sqlite/redis 后端是 deny-all 的
   配置级不对称（§2-F4）；`sso_rate_limit_buckets` 无标签 gauge 在多 limiter 下是
   last-writer-wins 语义未定义（§2-F5）。另有 CORS 暴露面缺失（§2-F6，SPA 读不到新头）。

其余为文档级、语义记录级和残余风险级问题（§2-F7~F11、§4）。

---

## 1. 状态图：owner / store / durability / consistency / replication / failover

### 1.1 限流桶状态（既有，本设计不改存储）

| 后端 | 状态 | Owner | 存储 | 持久性 | 一致性 | 复制/故障转移 |
|---|---|---|---|---|---|---|
| Memory | `shards[16]` 内 `map[key]*rate.Limiter`（`ratelimit.go:67-88`） | 本进程（每副本独立） | 进程内存 | 崩溃即失 | 进程内互斥串行；跨副本**无**一致性（有效限额 = N×配置，已文档化） | 无；崩溃后桶清空，每副本重新计 |
| SQLite | `rate_limit_buckets(bucket_name,key,tokens,last_refill_at_ns,last_seen_at_ns)` | 共享 DSN 的所有副本 | SQLite 文件（跨副本共享文件） | WAL/事务提交即持久（`persistBucket`+`Commit`，`sqlite_limiter.go:230-244`） | `SetMaxOpenConns(1)` 进程内全串行；跨进程由 SQLite 文件锁串行化写；refill 数学依赖**各副本本地墙钟**（§2-F8） | 无主动故障转移：DB 文件不可用 → `BeginTx`/`persistBucket` 失败 → **fail-open**（放行不持久化） |
| Redis | `sso:ratelimit:<bucket>:<key>` 计数器 + TTL | 所有副本 | Redis（单 key） | 键 TTL 内持久；`allowScript` 原子 INCR+EXPIRE+PTTL（`infrastructure/redis/ratelimit.go:96-120`） | 单 key 单脚本 → 每 key 全序、线性化；跨副本共享同一计数器 | Sentinel/Cluster 故障转移期间新主可能丢失最近 INCR → 窗口计数器回退 → **临时过放行**（§2-F10）；Lua 单 key 保证 Cluster 单槽 |

三后端的 `Allow` 均**非幂等**（INCR/消费 token 是副作用）：客户端重试同一请求会重复计费
——这是计数型限流的标准语义，本设计不改变，也无需改变（§3 场景表）。

### 1.2 本设计新增的状态（全部进程内、无跨副本传播）

| 状态 | 位置 | 一致性/并发 | 生命周期 | 备注 |
|---|---|---|---|---|
| `RateAllowance` 值类型（shared/spi） | 无状态，纯值 | — | 编译期 | 解决 `selfservicecore.RateLimiter` 结构性耦合（决策一 §破坏面，Verified：`deps.go:21` 与 `ratelimit.go:38-43` 签名逐字相同；`options_passwd.go:139` 公开 API 依赖此耦合） |
| Redis `denyAll` 未导出标记 | `redis.Limiter` 字段 | 构造后只读 | limiter 生命周期 | 仅 `NewLimiterFromRate(perSecond<=0)` 置位（`ratelimit.go:67-80`）；`NewLimiter` 直连的 365 天窗保持旧语义 |
| 中间件 1/64 采样计数器 | 每中间件实例闭包内 `*atomic.Uint64` | 原子 | 进程生命周期，跨热更持续 | 三后端统一采样语义（`calls` 未导出、`{policy}` 仅中间件可知、SQLite prune 采样是时钟型——设计决策三 ② 的三个理由均 Verified） |
| Memory `bucketObserver` 钩子 | `MemoryLimiter` 未导出字段 + `SetBucketObserver` | 见 §2-F5 | 随 limiter（热更时随旧 limiter 弃用） | **只允许在 `StartPruner` 后台清扫触发**：内联 prune 在 shard 锁内，`Buckets()` 锁全部 shard，自死锁（Verified：`Allow` 持有 `sh.mu` 调 `pruneLocked`，`ratelimit.go:160-166`；`Buckets` 逐个 `sh.mu.Lock()`，242-252） |
| 三个指标序列 | `platform/metrics` | Prometheus 线程安全 | 进程 | `requests_total`/`remaining`/`buckets`，有界基数（§2-F5/F7） |

### 1.3 与 OAuth/会话/JTI/撤销/失效总线的交叉追踪（本设计的隔离声明）

逐项核查结论：**限流桶是唯一状态，且与下列状态完全不相交**——

- **授权码/刷新令牌族/设备码/PAR**：`interfaces/sso/server_token.go:370` 的 `entry.limiter.Allow()`
  是裸 `golang.org/x/time/rate.Limiter`（grant 级限流，无 key），与本设计无关（设计已列，Verified）。
  本设计不触碰 token 存储、消费、轮换的任何代码。
- **JTI replay / 撤销集**：限流中间件在认证前运行（`server_routes.go` 链序：trustedProxies →
  ratelimit → degradation → bodylimit → router），与 JTI/撤销读取不在同层；本设计不新增任何
  撤销/回放交互。**失效总线、撤销重播种、就绪态均不受影响**——限流器没有需要失效传播的缓存。
- **就绪检查**：`SQLiteLimiter.Ping`/`redis.Limiter.Ping` 已接入 `AppendRateLimitReadyChecks`
  （Verified：`build_app_security.go:39`）；设计不新增就绪耦合。DB 故障时 `/readyz` 可 503
  而中间件仍 fail-open——这是既有文档化姿态，设计保持。
- **热更**：`DynamicMiddleware` + `PolicyStore` + `closePolicyLimiters` 是唯一与本设计状态
  交织的生命周期路径（采样计数器跨热更、observer 随 limiter 弃用）——见 §2-F1/F5。

结论：**无需失效总线扩展、无需就绪语义变更、无跨副本新状态需要恢复顺序编排。**

---

## 2. 发现（按严重度排序）

### F1 — High（既有、相邻）｜SIGHUP 热更关闭 SQLiteLimiter 与在途请求的 TOCTOU → 进程崩溃

- **证据（Verified）**：`main_wiring.go:156-170` `closePolicyLimiters` 对旧 Policy 的
  `Default`/`Prefixes` 逐项 `closeIfCloser`；`closeIfCloser` 是 `io.Closer` 断言
  （`main_shutdown.go:234-238`）；`*SQLiteLimiter` **实现了** `Close() error` 且置 `s.db = nil`
  （`sqlite_limiter.go:122-130`）；`Allow` 无 nil 防护直接 `s.db.BeginTx`
  （`sqlite_limiter.go:148`）。热更窗口：在途请求已 `store.Get()` 旧 Policy 并取得旧
  `SQLiteLimiter`，热更线程 `SetRateLimitPolicy` 换新 + `closePolicyLimiters(prev)` 关旧，
  请求随后调 `Allow` → nil `*sql.DB` 方法调用 → panic（同时 `s.db` 指针读写无同步，是数据竞争）。
  `main_wiring.go:163-166` 注释声称 "SQLiteLimiter … 不实现 io.Closer"，与 `sqlite_limiter.go:122`
  矛盾——注释错误。
- **触发**：`backend=sqlite` + 流量中 SIGHUP 重载 `security.rate_limit.*`。
- **影响**：handler goroutine 未恢复 panic → **整个进程崩溃**（可用性事故）；窗口窄但真实。
- **恢复**：进程重启（限流桶在 SQLite 中，崩溃不丢桶）。
- **纠正模式**：`Allow` 首行加 `s == nil || s.db == nil → return true, 0`（fail-open，与
  `Ping` 的防护一致，`sqlite_limiter.go:133-135`）；修正 `main_wiring.go` 注释；补
  Close-后-Allow 单测。本设计提交 3 改写 `newMemoryLimiterPruned` 接线时顺带修掉最便宜。
  **注意**：这是既有缺陷，不是本设计引入——但设计风险表讨论了热更 close 语义，属同一变更面，
  必须同批处理（AGENTS.md：不把相邻缺陷留成 deferred TODO）。

### F2 — Medium｜设计/规格声称 "SQLite 拒绝路径不持久化（事务回滚）"，与代码不符

- **证据（Verified）**：`sqlite_limiter.go:162-179`——正常拒绝（`allowed=false, retryAfter>0,
  denyAll=false`）**同样执行** `persistBucket` + `Commit`：持久化的是 refill 后未扣减的
  `tokens` 与 `last_refill_at_ns = now`。只有 `denyAll` 分支提前返回（deferred Rollback）。
  设计（存储模型表 "拒绝路径**不持久化**（事务回滚）"）与规格（验收标准 3 "拒绝后不持久化
  （tokens 回滚）"）都写反了。
- **触发**：实现者按文档字面"修正"代码让拒绝路径回滚——`last_refill_at_ns` 不推进 →
  下一次请求从**更早**的时间点 refill → 跨副本实际限额变宽（更慷慨），且与 Memory 后端
  （`CancelAt` 恢复到拒绝时刻，x/time rate.go:169-197）分叉。
- **影响**：当前代码行为与 Memory 等价（拒绝推进 refill 点），正确；风险在文档驱动的实现漂移。
- **恢复**：无运行时恢复问题（现状正确）。
- **纠正模式**：改文档不改代码。设计存储模型表改为 "拒绝路径**持久化 refill 状态**并提交
  （与 Memory 的 Cancel-恢复语义等价）；仅 denyAll 分支回滚"；规格验收标准 3 同步。语义差异
  用一个跨实例测试钉住（同 DSN 两个 limiter，拒绝后第三实例读到一致的 Remaining）。

### F3 — Medium｜deny-all 的**允许路径**不在三路头写入表内；且该路径 `ResetIn` 有除零风险

- **证据（Verified）**：三后端 deny-all 都**先放行初始 burst**：Memory 桶初始满
  （x/time `NewLimiter` 初始 `tokens=burst`），`perSecond<=0` 时前 `burst` 次 `wait==0` →
  `return true`（`ratelimit.go:192-200`）；SQLite 同（`loadBucketTokens` 首次满桶 + `consumeToken`
  `tokens>=1` 放行，`sqlite_limiter.go:215-221`）；Redis `NewLimiterFromRate(0,...)` =
  limit=1/365 天 → **每 365 天放行 1 次**（`infrastructure/redis/ratelimit.go:67-80`）。
  设计的三路头写入表只覆盖 `!a.OK && a.Limit==0`（拒绝形状）与 `a.OK && a.Limit==0`（fail-open），
  没有覆盖 `a.OK && a.Limit>0 && perSecond<=0`（deny-all 放行路径）——该路径 `Limit=burst>0`，
  落入第一行规则 → 写三头；而 `ResetIn=(burst-tokens)/perSecond` 是 **1/0 = +Inf**，进
  `time.Duration` 是未定义值，`Reset = now.Add(Inf)` 产生垃圾 epoch。设计的防除零要求只写在
  拒绝分支（决策一失败模式 2），映射公式本身是路径无关的。
- **触发**：SDK 直连 `WithRateLimit(Policy{Default: NewMemoryLimiter(0, 5)})` 等 deny-all
  配置的前 5 次请求。
- **影响**：客户端在 deny-all 放行路径上看到 `Limit>0` + 荒谬 `Reset`，与设计声称的
  "deny-all 无重置语义、恒 0" 契约矛盾；`Reset` 头值可能是垃圾年份。
- **恢复**：无持久影响；错误的头值随响应消失。
- **纠正模式**：映射层对 `perSecond<=0` **无条件**置 `ResetIn=0`（放行与拒绝两路）；头写入表
  增加第四行：`a.OK && a.Limit>0 && a.ResetIn==0`（deny-all 放行）→ 写 `Limit`/`Remaining`，
  `Reset` 写当前秒或不写（与设计 "桶恰好满时 Reset=当前秒" 先例一致，任选其一但必须写进
  consts.go 注释与测试）。同时把 "deny-all = 先放行 burst 次，此后永久拒绝" 的三后端边界差异
  （Redis 是每 365 天 1 次）写进 `RateAllowance` 文档——本设计统一的是**拒绝形状**，不是
  **准入边界**。

### F4 — Medium｜`per_sec: 0`（deny-all 的配置形态）在后端间不对称：memory 静默丢规则，sqlite/redis 构建 deny-all

- **证据（Verified）**：`config/config_load.go:410-419`（SDK 路径 `memoryRateLimitPolicy`）
  对 `PerSec <= 0` 的规则 `continue`（**丢弃**，无任何限流）；而 stock 二进制路径
  `serverbuildplatform.BuildRateLimitPolicy`（`build_app_security.go:34-39` 接线）的
  `redisRateLimitPolicy`（`build_ratelimit_cluster.go:95-105`）与 `sqliteRateLimitPolicy`
  （107-127 行）**无此过滤**，`per_sec: 0` 直通 `NewLimiterFromRate(0,...)`/`NewSQLiteLimiter(0,...)`
  → deny-all。全库无其他校验拒绝 `per_sec<=0`（`config/config_load.go` 的 validate 函数群不含
  此检查）。
- **触发**：操作者写 `security.rate_limit.prefixes: [{prefix: /auth/login, per_sec: 0}]`——
  memory 后端 = **该规则不存在（完全不限流）**；sqlite/redis 后端 = **永久拒绝**。同一份配置，
  相反的两个失败方向（无限流 vs 全锁死）。分析文档方向二抱怨的"同一份配置跨后端行为不一致"
  在 deny-all 上**今天就是现实**，且方向二只统一 429 形状、不统一规则资格。
- **影响**：误配置（把 per_sec 填 0 当"禁用"）在 memory 部署上静默关掉限流；在 sqlite/redis
  部署上把登录路径锁死。安全相关。
- **恢复**：改配置重载（sqlite/redis 热更；memory 规则本来就不存在，无需恢复）。
- **纠正模式**（二选一，需在设计中明确）：(a) 在 `BuildRateLimitPolicy` 对三后端统一
  `PerSec <= 0 → 跳过规则`（与 SDK 路径一致，零行为变化于合法配置）；或 (b) 保持现状但把
  三后端差异写进 `docs/config-reference.md` 的 `security.rate_limit.*` 行 + 一个跨后端
  `per_sec: 0` 行为测试。推荐 (a)——它让"deny-all"变成纯 SDK 直连能力，与 F3 的修复
  （deny-all 只存在于直连构造）互相印证，也消掉设计里"三后端字节一致"的隐含前提
  （该前提目前只有直连构造才成立）。

### F5 — Medium｜`sso_rate_limit_buckets` 无标签 gauge 存在多个写入者，last-writer-wins 语义未定义

- **证据（Verified）**：设计决策三 ③——Memory 每 limiter 一个 `SetBucketObserver` 钩子、
  SQLite 每 limiter 各自的 1/64 采样 COUNT，而 gauge 常量"无标签"。一个 Policy 有
  Default + N 个前缀规则 = N+1 个 limiter、N+1 个写入者，全部写**同一个无标签序列**：
  值在"任意一个 limiter 最近一次清扫的桶数"之间跳变；Memory 各 pruner 同频启动近似同步，
  值随清扫轮换。Redis 注册但永不更新（恒 0，与既有 `hits_total` 的"零流量"惯例并存，
  设计已记录）。
- **触发**：多于一个限流规则（默认配置就有 Default + /auth/login + /auth/send-code 等前缀）。
- **影响**：该 gauge 无法回答任何具体问题（"谁的桶规模？"）；告警会误报/漏报。
- **恢复**：无运行时影响，纯观测错误。
- **纠正模式**：给 gauge 加 `{policy}` 标签（复用决策三已为 `remaining` 引入的同一标签源，
  `limiterFor` 二元组）——每 limiter 一条序列，语义明确；或在设计里明确定义为
  "各 limiter 计数之和"并在 `ObserveRateLimitBuckets` 上做聚合（累加需要额外状态，不如标签）。
  推荐标签方案，成本与 `remaining` 相同。

### F6 — Medium｜CORS 暴露面缺失：跨源 SPA 默认读不到 `X-RateLimit-Limit/Reset`

- **证据（Verified）**：`interfaces/cors/cors.go:44` 与 `cors_test.go:193-202` 只把
  `X-RateLimit-Remaining` 列为暴露示例；`ExposedHeaders` 是操作者 YAML
  （`config/config_admin.go:108`，`build_app_security.go:175` 接线）。新头
  `X-RateLimit-Limit`/`X-RateLimit-Reset` 不在 CORS safelist 内，跨源 SPA 的 JS 读不到
  （设计决策二的头条用例就是"SPA 主动自限速"）。
- **触发**：跨源前端 + 未配置 `security.cors.exposed_headers`。
- **影响**：决策二的核心消费者（浏览器 SPA）拿不到新头；头契约对同源/非浏览器客户端仍有效。
- **恢复**：操作者补配置即可，无需重启（CORS 随配置加载）。
- **纠正模式**：同变更内更新 `docs/config-reference.md` CORS 行 + `cors.go:44` 注释
  （三头全列）；openapi.yaml 429/限流章节注明 CORS 依赖。纯文档，零代码。

### F7 — Low｜fail-open 在新增指标上无法与"合法耗尽"区分

- **证据（Verified）**：fail-open 返回 `{OK:true, 其余零}`（三后端 `return true, 0` 路径）；
  按设计，中间件放行、不写头、`requests_total{result="allowed"}` 照常 +1，且 1/64 采样会以
  `Remaining=0` 更新 `remaining` gauge——**故障期间该 gauge 跌到 0，与桶真的耗尽值上不可区分**；
  而 `hits_total` 不涨。可观测签名是"全部 allowed + remaining=0"，需要文档化才能被识别。
- **纠正模式**：在 `docs/observability.md` 三行新指标的说明里写明该签名
  （"remaining=0 且 allowed 流量持续时先怀疑 fail-open 而非耗尽"）；可选（非本变更范围）：
  增加 `result="failopen"` 标签值。与设计决策三失败模式 1（nil-safe）不冲突。

### F8 — Low｜时钟假设：SQLite refill 数学与 `Reset` 头依赖各副本墙钟

- **证据（Verified）**：`sqlite_limiter.go:190-212` 用 `now()`（墙钟）计算 `elapsedSec`；
  `Reset` 头 = `now.Add(ResetIn).Unix()`（服务器墙钟）。单副本时钟**回拨**：写出的
  `last_refill_at_ns` 变小 → 其他副本读到的 elapsed 变大 → **过度 refill（过放行）**；
  前拨 → 欠放行。同副本内回拨方向安全（elapsed<=0 不 refill）。Memory/Redis 无此问题
  （Redis PTTL 是服务端 TTL，与客户端时钟无关——唯一时钟免疫后端）。
- **影响**：跨副本共享 SQLite 时，一台时钟异常的副本会短暂放宽全集群限额；`Reset` 头值随
  副本漂移（DNS 轮询下客户端会看到不同 Reset）。
- **纠正模式**：文档注明（config-reference 的 rate_limit 行 + consts.go 注释）"SQLite 后端
  跨副本 refill 以各副本墙钟为准，生产须 NTP 同步"；`sso_rate_limit_remaining`/`Reset` 的
  per-replica 语义写进 observability.md。无代码变更。

### F9 — Low｜`sso_rate_limit_remaining` 的采样空洞与热更后陈旧序列

- **证据（Verified，推断）**：采样只在命中规则且 1/64 命中时发生（设计决策三 ②）。零流量
  的规则永不更新该序列；热更删除某前缀后，其 `{policy}` 序列停止更新（Prometheus 5 分钟
  staleness 处理）；热更改参数后同标签序列继续（值来自新 limiter，正确）。Memory 后端下
  该 gauge 是**每副本视图**——多副本求和无意义，只能按副本看。
- **纠正模式**：observability.md 注明"仅在有流量时更新、per-replica 视图"。

### F10 — Low｜Redis 故障转移期间的计数器回退 = 临时过放行窗口

- **证据（Verified，推断）**：哨兵/Cluster 故障转移丢最近 INCR（主从复制异步）；新主上任后
  计数器低于真实消耗，窗口剩余额度变宽，直到 TTL 重置。无 fencing/quorum 可言——限流器
  不需要也不应有（fail-open 教义）。
- **纠正模式**：文档注明（config-reference rate_limit 行）"Redis 故障转移后窗口计数器可能
  回退，产生一次窗口宽度的过放行；可接受（限流是防御层非正确性层）"。

### F11 — Info｜`Allow` 无请求级超时：分区时延受客户端 ReadTimeout 上界约束

- **证据（Verified）**：三后端 `Allow` 均用 `context.Background()`（`sqlite_limiter.go:146`、
  `infrastructure/redis/ratelimit.go:134`）；go-redis 超时来自 `redis.*` 配置块
  （`infrastructure/redis/universal.go:34-37`）。Redis 黑洞分区下每请求阻塞至 ReadTimeout
  才 fail-open → 请求堆积、延迟尖峰。
- **纠正模式**：文档注明（"fail-open 的响应时间上界 = Redis 客户端 ReadTimeout"）；可选优化
  （非本变更）：给 `Allow` 注入短超时 ctx。

---

## 3. 场景表

| 场景 | 后端 | 行为 | 一致性/可用性后果 | 恢复 | 本设计的处置 |
|---|---|---|---|---|---|
| **Redis 分区**（读写失败） | redis | 脚本错误 → `return true, 0` fail-open（`ratelimit.go:147-149`） | 限流关闭（攻击面回到无限制状态）；429 消失；`remaining` gauge 采样跌 0（§2-F7 签名） | Redis 恢复后自动；计数器按 TTL 延续（分区期间丢失的 INCR 永久丢失） | 保留 fail-open；头规则 `OK && Limit==0` 不写头；文档化故障签名（F7） |
| **SQLite 文件不可用/锁竞争** | sqlite | `BeginTx`/`persistBucket` 失败 → fail-open（`sqlite_limiter.go:148-149,167-172`）；跨进程写竞争（runtime 连接未设 busy_timeout，只有 migrate 连接设了，`migrate.go:197-203`）→ SQLITE_BUSY → fail-open | 限流关闭；/readyz 可能 503（Ping 失败）但流量仍放行——文档化姿态 | 文件恢复后自动；未持久化的拒绝无残留 | 无变更；残余风险记录（§4） |
| **副本崩溃**（Memory） | memory | 桶全失，重启后每副本重新计满 | 有效限额 = N×配置（已文档）；崩溃副本恢复后从满桶开始 | 自动 | 无变更 |
| **副本崩溃**（SQLite/Redis） | sqlite/redis | 桶在共享存储，崩溃副本恢复后继续共享计数 | 无丢失（提交后持久/TTL 内） | 自动 | 无变更 |
| **客户端重试**（响应丢失） | 三后端 | 重试请求再次 INCR/消费 | 双重计费（标准计数语义）；**不会**绕过限流 | — | 无变更；文档注明非幂等 |
| **时钟回拨**（单副本） | sqlite | 该副本 elapsed<=0 不 refill（安全方向）；写出的回拨 `last_refill_at_ns` 使**其他副本**过度 refill | 短时过放行（跨副本）；`Reset` 头随副本漂移 | 时钟校准后自动 | F8：文档 + NTP 要求 |
| **时钟前拨** | sqlite | elapsed 变大 → 立即 refill 至满桶 | 短时过放行（单副本视角） | 自动 | F8 |
| **时钟异常** | redis | PTTL 服务端计时，免疫 | 无 | — | 唯一时钟免疫后端（F8 注明） |
| **热更竞态**（SQLite 后端 + SIGHUP） | sqlite | 旧 limiter 被 Close 后仍在途请求调 `Allow` → nil-db panic（F1） | **进程崩溃** | 重启（桶不丢） | 必须在同批修复（F1） |
| **热更换参**（正常） | 三后端 | 新 Policy 的 limiter 供新请求；旧 limiter 关 pruner；采样计数器跨热更持续 | 新头/新指标反映新参数；被删前缀的 gauge 序列陈旧（F9） | — | 设计已覆盖（决策二破坏面 2、决策三并发 3） |
| **Redis 故障转移** | redis | 新主计数器回退 → 窗口剩余变宽 | 一次窗口宽度的过放行 | 自动 | F10 文档 |
| **陈旧读**（跨副本） | sqlite/redis | 无缓存层；SQLite 读本事务最新提交、Redis 读脚本返回值——无陈旧读路径 | — | — | 设计零存储变更，此性质继承 |
| **split-brain / 双主** | redis/sqlite | 限流器无领导权、无 quorum；Redis 双主 = 两个独立计数器（等效 N× 限额）；SQLite 共享文件双写由文件锁串行 | 双主拓扑下限流退化为 per-主 | 运维收敛拓扑 | 不支持拓扑（§4） |

---

## 4. 明确保证、不支持拓扑、验证测试、残余风险

### 4.1 设计应声明的保证（建议原样写进实现注释与契约文档）

1. **fail-open 边界不变**：任何后端错误 → 放行 + 不写额度头 + 不新增错误码；429 体
   `{"error":"rate_limited"}` 与 `Retry-After`（>0 时）不变（Verified：三后端 `return true, 0`
   路径与 `writeTooManyRequests` 现状）。
2. **零存储变更**：SQLite 表/索引、Redis Lua 脚本/TTL、键语义全不动（Verified：设计 §决策一
   存储模型逐项对照代码成立，除 F2 的文档措辞外）。
3. **原子性**：一次 `Allow` = 一次原子决策（Memory shard 锁 / SQLite 单连接事务 / Redis 单
   脚本单 key）；`Remaining`/`Limit`/`ResetIn` 与放行决策来自**同一次**决策（无二次读取）。
4. **有界基数**：三个新指标标签全部来自配置（result 双值、tenant 沿用 allowlist、policy 前缀
   串），无请求输入（Verified：`limiterFor` 只读 `PrefixRule`，`config_load.go` 校验前缀串）。
5. **非幂等**：`Allow` 有消耗副作用，重试重复计费（标准计数语义）。
6. **deny-all 语义（修正后）**：放行初始 burst（Memory/SQLite = burst 次；Redis = 每 365 天
   1 次），此后拒绝且 `RetryAfter/ResetIn` 恒 0；拒绝形状三后端字节一致（F3 补上允许路径）。
7. **Reset 语义**：桶后端 = 距回满时长、窗口后端 = 距窗口重置时长，统一为 epoch 秒；与
   `Retry-After` 并存时以 `Retry-After` 为准；`ResetIn==0` 时 Reset = 当前秒。

### 4.2 不支持/不保证的拓扑（写进 config-reference 或 limiter 包文档）

- **Memory 后端多副本**：不提供跨副本限额（有效 N×），不保证客户端跨副本看到单调的
  `Remaining`/`Reset`。
- **Redis 双主/split-brain**：两个独立计数器，限额翻倍；无 quorum 机制。
- **SQLite 共享文件于网络文件系统（NFS 类）**：文件锁语义脆弱；运行时连接未设 busy_timeout，
  锁竞争直接 fail-open（限流关闭）。SQLite 跨副本仅适合低写率 + 受控共享存储。
- **Redis 只读副本路由**：`RouteByLatency/RouteRandomly/ReadOnly` 必须关闭
  （`universal.go:44-52` 已对 replay 类存储声明同样约束；限流 INCR 必须钉主）。
- **Redis Cluster 多 key**：脚本单 key 是 Cluster 兼容的硬约束，不得扩展。

### 4.3 验证测试（按发现对应，全部应落在本变更的提交内）

| 测试 | 对应 | 形式 |
|---|---|---|
| Close 后 `Allow` → `{OK:true}` 不 panic；热更 + 并发请求 -race | F1 | `sqlite_limiter_test.go` 新增；`rate_limit_reload_test.go` 扩展 |
| 同 DSN 两实例：拒绝路径后第三实例 Remaining 一致（钉住 refill 推进语义） | F2 | `sqlite_limiter_test.go`（规格验收 3 已要求，补充"拒绝后 refill 点推进"断言） |
| `NewMemoryLimiter(0, 5)`/`NewSQLiteLimiter(0,5)`/`NewLimiterFromRate(0,...)`：前 burst 次放行路径头形状（Limit/Remaining 写、Reset 不写或=now）、拒绝路径字节一致 | F3 | middleware 测试四行表全测；`infrastructure/redis` miniredis 测 `denyAll` 标记 |
| `per_sec: 0` 三后端规则资格测试（memory 跳过 / sqlite+redis deny-all），+ config-reference 文档 | F4 | `build_ratelimit_cluster_test.go` + `config` 测试 |
| 双前缀 limiter：`sso_rate_limit_buckets{policy}` 两序列独立更新（若采纳标签方案） | F5 | `ratelimit_metrics_test.go` |
| 采样：64 次调用后 `remaining` 更新且等于 Allowance.Remaining；热更后标签来自新 Policy | F9/设计验收 | `ratelimit_metrics_test.go` + `rate_limit_reload_test.go` |
| 时钟回拨：注入 `now`（`SQLiteLimiter.now` 是现成测试缝）：回拨后不 refill、跨实例 refill 数学 | F8 | `sqlite_limiter_test.go` |
| 既有 `hits_total` 名字/标签不变；允许路径 `tenant=TenantLabelUnknown` | 设计验收 | `ratelimit_metrics_test.go` |
| 允许路径 bench 无回归（新增原子自增 + 一次 Inc 的上界） | 设计验收 | `ratelimit_bench_test.go` 基线对比 |

### 4.4 残余风险（接受并记录）

1. **fail-open 不可观测**（F7）：故障期间新指标给出"全部放行 + remaining=0"签名，需要
   文档化识别；`result="failopen"` 标签是可选后续。
2. **Redis 故障转移过放行窗口**（F10）：一次窗口宽度，接受。
3. **`sso_rate_limit_buckets` 在 Redis 后端恒 0**（设计已记录）：注册但无数据——与既有
   "注册但零流量"惯例一致。
4. **`sso_rate_limit_remaining` 采样粒度**：1/64 × 命中流量；零流量规则序列陈旧（F9）。
5. **`Reset` epoch 格式 + 客户端时钟依赖**：设计已记录为单点可改（决策二破坏面 4）。
6. **SQLite 跨副本锁竞争 → fail-open**：写入速率高时限流可能静默关闭——SQLite 后端的
   部署上限需在 config-reference 注明（低千级写/秒量级，包文档已声明）。
7. **`Allow` 无请求级超时**（F11）：分区下延迟尖峰上界 = 客户端 ReadTimeout。

### 4.5 对提交切分的调整建议

- **提交 1（SPI）**：附 F2 文档修正（存储模型表 + 规格验收 3 措辞）与 F3 的
  `ResetIn` 无条件防除零（映射层，路径无关）。
- **提交 2（头契约）**：附 F3 第四行头写入规则、F6 文档（config-reference + cors.go 注释）、
  F4 决策（规则资格统一或文档化）——F4 若选方案 (a)（`BuildRateLimitPolicy` 统一过滤）
  属"只做加法"边界内的一行守卫，建议同批。
- **提交 3（可观测性）**：附 F1 修复（`Allow` nil 防护 + 注释修正，与 `newMemoryLimiterPruned`
  接线同文件）、F5 标签方案（与 `limiterFor` 二元组同源）、F7/F9 的 observability.md 措辞。
