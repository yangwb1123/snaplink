# Principal Review: 方向二——限流剩余额度可见性（X-RateLimit-* 头与额度指标）

> Reviewed revision: `62b6f142` "Stage: design"（设计与规格已提交，三个决策零实现）。
> 输入：方向二设计/规格、六份评审交付物（security、protocol、performance 内联；
> ds-review、qa-review 落盘）、以及本人对冲突/承重主张的代码复核。
> 本评审为 advisory：不批准发布、不绑定维护者；只做综合与决策清单。
> 证据标注沿用各评审的 Verified/Partial/Missing/Proposed/Unknown；我复核过的主张标 ★。

## 0. 结论

**有条件的准备就绪（Conditionally Ready）**——架构层面（`shared/spi` 提升解决
`selfservicecore.RateLimiter` 结构耦合、零存储变更、三路头写入规则、中间件级 1/64 采样、
`Buckets()` 自死锁分析、denyAll 标记）六份评审全部 **Verified**，且我独立复核一致。
当前树内**没有**本设计引入的运行时缺陷；但存在 **1 个在树的 High 级相邻缺陷**（H1，热更崩溃）
和 **1 个文档驱动的安全回归风险**（H2，SQLite 拒绝路径被设计文写反），二者必须在同一变更内
处理，故不能无条件放行。证据置信度：H1/H2/M1/M2 为高（多评审独立发现 + 直接复核）；其余为中
（单评审、代码阅读级）。

## 1. 合并后发现（按严重度，标注来源与去重）

### High

**H1 — SIGHUP 热更 + SQLite 后端 → 在途请求 nil-db panic，进程崩溃**（来源：DS F1；★已复核）
- 证据：`main_wiring.go:163-166` 注释声称 "SQLiteLimiter 不实现 io.Closer" 是**错的**——
  `sqlite_limiter.go:122` 有 `Close()` 且置 `s.db = nil`；`Allow`（sqlite_limiter.go:148）无
  nil 防护直接 `s.db.BeginTx`；`closeIfCloser`（main_shutdown.go:234-238）是 io.Closer 断言。
  热更窗口：在途请求已 `PolicyStore.Get()` 旧 Policy，热更线程 `closePolicyLimiters(prev)` 关旧
  limiter 后请求才调 `Allow` → nil 指针 panic；`s.db` 读写无同步，同时是数据竞争。
- 影响：handler goroutine panic 未恢复 → 整个进程崩溃（可用性事故）。窗口窄但真实
  （backend=sqlite + 流量中 SIGHUP 重载 `security.rate_limit.*`）。
- 修复（同批，不得 deferred）：`Allow` 首行 `s == nil || s.db == nil → return true, 0`
  （与 `Ping` 的防护一致，sqlite_limiter.go:133-135）；修正 `main_wiring.go` 注释；补
  Close-后-Allow 单测 + 热更并发 `-race` 测试。提交 3 改写 `newMemoryLimiterPruned` 接线时
  顺带落地最便宜。AGENTS.md 禁止把相邻缺陷留成 deferred TODO。

**H2 — 设计/规格把 SQLite 拒绝路径写成"不持久化（事务回滚）"，代码事实相反**（来源：security F1、
protocol F1、DS F2、QA §2.3 —— 四方独立；★已复核 sqlite_limiter.go:145-171）
- 证据：正常拒绝（`allowed=false, denyAll=false`）**无条件**执行 `persistBucket` + `tx.Commit()`，
  持久化 refill 后未扣减的 tokens 与 `last_refill_at_ns = now`；只有 denyAll 分支提前返回
  （deferred Rollback）。设计与规格验收标准 3 都写反。
- 影响：照文档字面"优化"实现（拒绝路径回滚）会让被攻击中的键（全拒绝）`last_seen_at_ns`
  不推进 → 被剪除 → 重置满桶 → **攻击中途复活暴力破解预算**；同时与 Memory 的
  Cancel-恢复语义（x/time rate.go:169-197）分叉。当前代码行为正确，风险全在文档驱动的实现漂移。
- 修复：**改文档不改代码**。设计存储模型表与规格验收 3 改为"拒绝路径持久化 refill 状态并提交
  （与 Memory Cancel 语义等价）；仅 denyAll 回滚"。补回归测试钉住：同 DSN 两实例，拒绝后
  第三实例读到一致的 Remaining 且 `last_seen_at_ns` 刷新。

**H3 — fail-open 的 0 额度会被 1/64 采样写进 `sso_rate_limit_remaining`**（来源：QA F2 High 与
DS F7 Low 为同一发现，补救分歧：guard vs 文档；合并为 High）
- 证据：决策三 ② 采样"每命中规则一次"，记录 `Allowance.Remaining`；fail-open =
  `{OK:true, Remaining:0, Limit:0}` → 后端分区期间 gauge 跌 0，与桶真耗尽值上不可区分。
  决策二为头制定了"fail-open 不写头"原则（拒绝误导客户端自限速），决策三却把同一误导
  放回了运维侧；告警会在故障期间误报。
- 修复：采样条件加 `a.Limit > 0`（与头写入规则同源，一行）；`sso_rate_limit_remaining` 与
  `sso_rate_limit_requests_total{result="allowed"}` 的组合签名写进 observability.md
  （"全 allowed + remaining=0 → 先怀疑 fail-open"）。DS 的"仅文档化"方案不足以满足
  决策二已确立的原则。测试：`TestMiddleware_RemainingGaugeSkipsFailOpen`（downClient 模式
  已存在，infrastructure/redis/coverage_test.go）。

### Medium

**M1 — deny-all 的允许路径不在三路头写入表内，且 `ResetIn = (burst-tokens)/perSecond` 除零**
（来源：security F3、protocol F3、DS F3、QA F3 —— 四方独立；★已复核 ratelimit.go:185-200）
- 证据：三后端 deny-all 都先放行初始 burst（Memory/SQLite = burst 次；Redis = 每 365 天 1 次），
  该路径 `OK:true, Limit=burst>0` → 落入头写入表第一行；`perSecond<=0` 时商为 +Inf，进
  `time.Duration` 是未定义值 → `X-RateLimit-Reset` 垃圾年份。设计只把防除零写在拒绝分支。
- 修复：映射层对 `perSecond<=0` **无条件**置 `ResetIn=0`（路径无关）；头写入表加第四行
  （`OK && Limit>0 && ResetIn==0` → 写 Limit/Remaining，Reset 写当前秒或不写，写进 consts.go
  注释与测试）；把"deny-all 准入边界三后端不同（burst 次 vs 每年 1 次）"写进 `RateAllowance`
  文档——本设计统一的是拒绝形状，不是准入边界。

**M2 — `per_sec: 0` 配置在 SDK 路径与 stock 二进制之间方向相反**（来源：DS F4；★已复核，
DS 的后端归类不准，实为路径归类）
- 证据：SDK/配置校验路径 `config_load.go:408-419`（memory）与 444-471（sqlite）对
  `PerSec <= 0` **丢弃规则**（不限流）；stock 二进制 `BuildRateLimitPolicy`
  （build_ratelimit_cluster.go:67-130）对 memory/sqlite/redis **无条件构建 deny-all**。
  同一份 YAML：SDK 嵌入 = 静默关掉限流，stock = 锁死登录路径。config_load.go:443 的
  "mirrors serverbuildplatform.sqliteRateLimitPolicy's shape exactly" 注释在
  per_sec<=0 维度上已不成立。全库无校验拒绝 `per_sec<=0`。
- 选项与冲突：DS 推荐 (a) `BuildRateLimitPolicy` 统一跳过（与 SDK 一致，fail-open 方向）；
  security F4/protocol F4 要求 deny-all 测试必须含 config-built 变体（依赖 stock deny-all
  保留，fail-closed 方向）。两案直接冲突。我推荐 (b)：**保留 stock deny-all + 文档写明
  差异 + 跨后端 `per_sec:0` 行为测试**（限流是防御层，静默丢规则比全锁死更糟），并把
  (c) 配置校验拒绝 `per_sec<=0`（启动即报错）作为独立契约变更交维护者决定——它改变现有
  配置的接受性，不在"只做加法"边界内。(b) 同时满足 security F4 的测试要求，且 deny-all
  的三后端字节一致性测试仍可覆盖 config-built 路径（其资格本身就是 stock 现状）。
- 决策所有者：维护者 + 安全。

**M3 — `sso_rate_limit_buckets` 无标签 gauge 有 N+1 个写入者，last-writer-wins 未定义**
（来源：security F2、DS F5 —— 去重合并）
- 证据：一个 Policy = Default + N 前缀 = N+1 个 limiter，每个都写同一无标签序列；默认配置
  （Default + /auth/login + /auth/send-code）即触发；IP 扫描攻击期间值在任意 limiter 的
  桶数间跳变（假低）。Redis 注册但恒 0（已文档化）。
- 修复：加 `{policy}` 标签（复用 `limiterFor` 二元组的同一标签源，与 `remaining` 同成本）；
  或定义为"各 limiter 之和"（需聚合状态，不如标签）。推荐标签方案。

**M4 — `platform/metrics/metrics.go` 494/500 行：提交 3 加三个结构体字段必撞行数闸**
（来源：QA F5；★已复核 wc -l = 494）
- 证据：设计"文件预算不够则新开 ratelimit_quota.go"无法承载结构体字段（Go 结构体是单一声明）；
  `metrics_ctor.go` 497 行，只余 3 行。提交 3 必须把 `Metrics` 结构体（或字段块）移入新文件
  （如 `metrics_types.go`）。验收：提交 3 后 `TestMaintainability_` 绿。

**M5 — SQLite 桶 gauge 上报机制未指定，提交 3 按文档不可实现**（来源：QA F4）
- 证据：设计决策三 ③ 说 SQLite "复用 pruneStale 采样点执行 COUNT"，但提交 3 变更清单只列了
  `MemoryLimiter.SetBucketObserver`；`SQLiteLimiter` 无任何触达 Metrics 的机制（limiter 不知
  metrics），结果不是"文档化不更新"而是"静默永不更新"。
- 修复：给 `SQLiteLimiter` 同样的未导出 observer + 导出 nil-safe setter，在采样事务内触发，
  由 `serverbuildplatform.sqliteRateLimitPolicy` 接线；测试用可控时钟 `s.now` 落在
  `(nowNs/ms)%64==0` 边界。

**M6 — CORS 默认读不到 `X-RateLimit-Limit/Reset`，头条用例（SPA 自限速）默认失效**
（来源：DS F6；★已复核 cors.go:44 注释只列 X-RateLimit-Remaining，ExposedHeaders 为操作者
YAML）
- 修复：同变更更新 config-reference CORS 行 + cors.go:44 注释（三头全列）+ openapi 注明
  CORS 依赖。纯文档零代码。

**M7 — 唯一新增每请求成本所在的中间件层没有任何基准，设计点名的回归闸看不见它**
（来源：perf M1）
- 证据：允许路径新增闭包级原子自增（16 shard 共享一条缓存行，是并行设计里唯一新的共享争用点）、
  `CounterVec.WithLabelValues` Inc、1/64 Gauge Set、3×Itoa、`time.Now()`；而
  `ops/deploy/benchgate/benchmarks.yaml` 只闸 `^BenchmarkMemoryLimiterAllow`（limiter 层，
  不含上述任何成本）。"预期不应有回归"按现有计划不可证伪。
- 修复：提交 2 前新增 `BenchmarkMiddlewareAllow*`（httptest + MemoryLimiter；变体：metrics-nil、
  metrics-wired、headers、parallel + 小 key 池；parallel 变体必做）；提交 3 前后 benchstat。

**M8 — metrics-nil（默认接线）下允许路径无条件原子自增，破坏"无指标零成本"契约**
（来源：perf M2）
- 证据：`Policy.Metrics == nil` 是默认；既有 `recordRejection` 恰在此 nil 检查短路
  （middleware.go:195-197）。无条件 `LOCK ADD` 是默认部署上的纯浪费。
- 修复：自增与 1/64 采样都 guard 在 `p.Metrics != nil` 之后（分支 vs 锁 RMW，更便宜）；
  metrics-nil 中间件基准变体必须与无功能对照统计等价——一个廉价且强的回归断言。

**M9 — 迁移表不完整：漏两个 `selfservicecore.RateLimiter` 测试双**（来源：QA F1、security F3
—— 去重合并；★已复核 testhelpers_test.go:393、test/auth_signup_test.go:235）
- 证据：`stubRateLimiter` 与 `stubSignupRateLimiter` 实现 `Allow(string) (bool, time.Duration)`，
  与设计自己的头条发现（risk #1）同形；"完整迁移面清单"只列了 pingerLimiter/closeCountingLimiter。
- 影响：提交 1 低估迁移面；编译门兜底，无运行时风险——计划/评审缺陷。QA 标 High，security 标
  Low；合并为 Medium（文档完整性承诺为假，但不产生线上风险）。

### Low

- **L1**（protocol F5）`docs/error-codes.md:921` 无条件写 `Retry-After: <seconds>`；决策二落地后
  deny-all 429 无 Retry-After（Redis 后端是新扩展）——同提交补"当重置有意义时"措辞（AGENTS.md §5 规则 6）。
- **L2**（protocol F6；★已复核）`security.rate_limit.prune_interval` 已接线
  （config_admin.go:60-62、build_ratelimit_cluster.go:80-88）但 config-reference.md 缺失——
  决策三"gauge 仅当 prune_interval 启用时更新"的文档依赖此行；同提交补。
- **L3**（QA F8、protocol F3、security F3；★已复核）设计两处事实错误："ratelimit_test.go 的
  `var _ Limiter` 断言保持"——不存在（只有 sqlite_limiter.go:255 与 redis ratelimit.go:168）；
  提交 1 应**新增** `var _ Limiter = (*MemoryLimiter)(nil)` + `var _
  selfservicecore.RateLimiter = (*MemoryLimiter)(nil)`。"sso 不 import ratelimit"——方向反了
  （sso 确实 import ratelimit，quota.go:10；约束是 ratelimit 不 import sso）。无放置影响。
- **L4**（QA F10）fuzz 只断言不 panic；提交 1 顺手加廉价不变量 oracle：`Remaining ∈ [0, Limit]`、
  `ResetIn` 有限且 >= 0、deny-all 全零形状。
- **L5**（security F5，既有、范围外）中间件 429 无 `Cache-Control: no-store`（quota.go:157-160
  的 DCR 门手动补偿）；429 按 RFC 9111 不可启发式缓存，非缓存洞——单独跟踪，不在本变更内改。
- **L6**（DS F7/F8/F9/F10/F11）观测签名、时钟假设（SQLite refill 与 Reset 依赖副本墙钟，生产须
  NTP）、`remaining` 采样空洞与热更陈旧序列、Redis 故障转移过放行窗口、`Allow` 无请求级超时
  （fail-open 响应时间上界 = Redis ReadTimeout）——全部写进 observability/config-reference
  说明行；无代码变更。
- **L7**（protocol F2）`X-` 前缀 + epoch Reset 是对 draft-ietf-httpapi-ratelimit-headers 的
  明确偏离（I-D 现名 `RateLimit-*` 且 Reset 为 delta）；与 GitHub 部署事实标准一致，可辩护——
  consts.go/openapi 注明偏离；可选双发 `RateLimit-*`（仍属加法）交产品定。
- **L8**（protocol F7）记录：桶后端 `X-RateLimit-Reset`（回满）≠ `Retry-After`（下一 token），
  Redis 相等；允许路径可出现 `Remaining: 0`（最后 token 已耗）。写进 consts.go 契约注释防假 bug。
- **L9**（QA F9、perf I6）ABI 说法不准（40 字节结构体经栈返回，amd64 >32 字节不走寄存器）但
  零分配结论成立——用 benchmem 验证（保持 1 alloc/op、64 B/op），别用 ABI 推理。
- **L10**（perf L4/L5、I7/I8）SQLite 1/64 COUNT 在单连接临界区内（分析可接受，可选负载腿验证）；
  Redis deny-all 短路是真优化但改变 fail-open 语义，需显式决策（见 §3）；Redis/SQLite 无需
  新基准（零 RTT 由构造保证）；`time.Now()` 是 vDSO 读，并入 M7 基准。

## 2. 评审间冲突裁定（trade-off ledger）

| # | 冲突 | 选项 | 裁定 | 后果 | 决策所有者 |
|---|---|---|---|---|---|
| T1 | 设计 vs 四方评审：SQLite 拒绝路径是否持久化 | (a) 按设计"修"代码；(b) 改文档 | **(b) 改文档**（★代码复核确认拒绝路径 persist+commit） | 照 (a) 实现 = 攻击中键被剪除重置满桶 | 实现者 + 评审（无需上提） |
| T2 | deny-all 允许路径头形状 | 除零进 Duration vs 无条件 `ResetIn=0` + 第四行规则 | **无条件防除零，路径无关**（四方一致） | Reset 头不再出垃圾年份；准入边界差异入文档 | 实现者（设计已定原则） |
| T3 | `per_sec:0` 语义：SDK 丢规则 vs stock deny-all | (a) 统一跳过（DS）；(b) 文档+测试（security F4 要求 config-built deny-all 测试）；(c) 校验拒绝 | **(b) 现在 + (c) 独立决策**；拒绝 (a)（fail-open 方向，且摧毁 config-built deny-all 测试面） | 同一 YAML 跨路径行为差异有文档、有测试钉住；全锁死/无限流二选一仍是操作者风险 | **维护者 + 安全** |
| T4 | 采样计数无条件 vs metrics-nil guard（perf M2） | 无条件（设计）；guard | **guard**（与 recordRejection nil 短路先例一致；保住默认部署零成本契约） | metrics-nil 基准变体成为强回归断言 | 性能 + 维护者 |
| T5 | fail-open 的 remaining gauge：guard vs 仅文档（QA High vs DS Low） | 采样 guard；文档；两者 | **guard + 文档**（决策二原则一致性） | 故障期间 gauge 不再假 0；告警不误报 | QA + 维护者 |
| T6 | buckets gauge 无标签 vs `{policy}` | 标签；聚合；无标签+文档 | **`{policy}` 标签**（与 remaining 同源，成本相同） | 每 limiter 一条语义明确的序列 | 维护者 |
| T7 | 头名/Reset 格式偏离 I-D | 保持 GitHub 惯例 + 注明；双发 `RateLimit-*` | **保持 + 注明**；双发为可选后续 | 草案客户端读不到；epoch 被当 delta 会算出多年退避（文档警告） | **产品/API** |
| T8 | 直调 429（quota/governance/signup）无 X-RateLimit-* | 扩展 vs 记录非目标 | **记录为非目标**（规格"不收敛五套限流"一致）；写进 openapi/observability | 凭据类端点 429 永远无额度头，客户端须知 | **产品** |
| T9 | Redis deny-all 短路（perf L5） | 短路（静态 deny-all 免 RTT）vs 保留 | **范围外，明确不采纳**：短路 = Redis 故障时 deny-all 从"放行"变"拒绝"，改变 fail-open 教义 | 每次 deny-all 请求仍付一脚本 RTT；安全语义不变 | **维护者 + 安全**（显式决定） |
| T10 | DS F1 修复时机 | 本变更内 vs 单独跟踪 | **本变更内**（提交 3 改写同一接线；AGENTS.md 禁 deferred TODO） | 热更崩溃风险随提交 3 消除 | 实现者 + 维护者 |
| T11 | `RateAllowance` 命名、result 常量、openapi 位置 | 设计已列未决项 | 不阻塞；实施时定夺 | — | 实现者 |

## 3. 前置条件、验收、回滚、监控、排除项、残余风险

### 前置条件（提交 1 之前必须完成）
1. **基线落地**：QA 已捕获基准（SingleKey 178.3、ManyKeys 191.2/222.1/447.1、Parallel 89.3
   ns/op，均 64 B/op、1 alloc/op）——以 benchstat 表存 `docs/auto/`（基准是证据不是提交说明）；
   提交 1 之前在同一机器重录基线。**这是整个验证故事的关键依赖**：基线在提交 1 之后捕获则
   "无回归"门作废。
2. **设计/规格勘误**：H2（SQLite 拒绝路径措辞 + 规格验收 3）、L3（var _ 断言与 import 方向）、
   M9（迁移表补两个测试双）。
3. **M7 中间件基准矩阵设计定稿**（metrics-nil / metrics-wired / headers / parallel 变体）。

### 可执行验收（按提交）
- **提交 1（SPI）**：`go build ./... && go vet ./...` + `TestMaintainability_|TestArchitecture_`
  绿；grep 证明旧签名实现者清零（恰余三后端 + 无关的 degradation/tokenexchange 类型）；
  新增两侧 `var _` 断言（L3）；两个 stub 迁移（M9）；fuzz 不变量（L4）；
  `TestMemoryLimiter_DenyAll_AllowedPathFinite`（M1，Memory+SQLite）；SQLite 拒绝路径持久化
  回归测试（H2）；benchstat vs 基线无显著变化（perf M3：`Tokens()` 新增叶子锁的成本在此测量）。
- **提交 2（头契约）**：后端参数化中间件套件（QA F6 空位：`middleware_backends_test.go`，
  外部测试包可 import `infrastructure/redis` 不破环）；四行头写入表 + deny-all 允许路径
  （M1）；denyAll 标记 miniredis 测试（拒绝 `RetryAfter==0`、`Limit==0`）；fail-open 无头测试
  （H3 的头侧）；热更换桶后 Limit 头变化；`error-codes.md` 补语（L1）、openapi 429 头 + CORS
  注明（M6）、config-reference CORS 行（M6）；`Reset >= now + Retry-After` 不变式 + `Reset ==
  Retry-After`（Redis）（L8）；M7 基准矩阵落地并 -race。
- **提交 3（可观测性）**：`Metrics` 结构体移入新文件（M4，`TestMaintainability_` 必须绿）；
  SQLite observer 机制（M5）；`a.Limit>0` 采样 guard（H3）；`{policy}` 标签（M3）；
  metrics-nil guard（M8）；**H1 修复**（nil 防护 + 注释 + Close-后-Allow 单测 + 热更并发
  -race）；observability.md 三行 + fail-open 签名 + per-replica 视图 + Redis 恒 0 +
  prune_interval 依赖（L2/L6）；bench 前后对比记录（1 alloc/op、64 B/op 不变）。
- **收尾门**：`go test ./... -race`、`go test ./test/ -run TestE2E -v`（Retry-After e2e
  ratelimit_e2e_test.go:111 不变）、`make ci`、`make bench-gate`（同一机器重录基线后绿）；
  可选：`make backend-semantics` 增补 ratelimit 条目（QA F6 建议的家）、SQLite/Redis 负载腿
  （perf L4/L5）。

### 回滚触发
- benchstat 显示允许路径显著回归（>10% bench-gate 阈值）且优化（句柄缓存）无效 → 回退决策三
  的允许路径计数，或整体回退提交 3（头契约与 SPI 可独立保留）。
- `-race` 在采样计数器/observer 接线发现新竞争 → 提交 3 回退重做。
- e2e Retry-After 断言或 429 体字节变化 → 提交 2 回退（字节一致性是硬契约）。

### 监控
- 新指标：`sso_rate_limit_requests_total{result,tenant}`、
  `sso_rate_limit_remaining{policy}`、`sso_rate_limit_buckets{policy}`；既有
  `hits_total` 不动（重复计数是设计使然，文档注明）。
- 故障签名：全 allowed + remaining=0 → 先怀疑 fail-open（H3 文档化）。
- 部署后观察：SQLite 后端 SIGHUP 热更演练（H1 修复验证）；Redis 故障转移演练记录过放行窗口
  （L6）。

### 显式排除项（非目标，需在契约文档声明）
- 不收敛五套限流机制；quota.go/governance.go/signup.go 的 429 不携带 X-RateLimit-*
  （T8）；429 体 `{"error":"rate_limited"}` 与错误码集不变；键语义与中间件链位置不变；
  discovery 无速率限制元数据（无标准定义）；Redis 后端永不更新 buckets gauge；不新增
  Redis/SQLite 基准（零 RTT 由构造保证）；不引入 `result="failopen"` 标签（可选后续）。

### 残余风险（接受并记录）
- Memory 多副本有效限额 = N×配置（既有文档化）；Redis 双主 = 双计数器；SQLite 共享文件于
  NFS 类网络文件系统不支持（文件锁语义脆弱）；Redis 只读副本路由必须关闭；Cluster 脚本单 key
  硬约束不得扩展（DS §4.2）。
- `sso_rate_limit_remaining` 为流量加权采样（1/64），低流量更新稀疏、热更删前缀后序列陈旧
  （Prometheus staleness 处理）；per-replica 视图，跨副本求和无意义。
- `Reset` epoch 依赖客户端时钟；SQLite refill 依赖副本墙钟（生产须 NTP）。
- 中间件基准是回归相对而非绝对（仓库无 SLO）；允许路径新成本上界由 M7/M8 钉住。

## 4. 缺失的评审/证据与下一步

**已运行的证据**：QA 跑了 build/vet/gates、三后端单测 -race、全部 test/ 包、fuzz ×2（~850k
execs）与基准捕获；security/protocol/DS 为代码阅读级（无构建，设计阶段可接受）；protocol 跑过
build/vet + 维护性/架构门。**未运行**：`make ci`、`make chaos-test`、`make load-test`
（QA 明确延后——设计阶段合理，但提交 3 收尾门必须全跑）。

**缺失/未知**：
1. 中间件层基准不存在（M7）——提交 2 前必须设计并落地；这是设计盲区的唯一解。
2. 无跨后端中间件一致性测试（QA F6）——提交 2 的 P1 项。
3. SQLite/Redis 后端无负载腿（perf L4/L5）——可选，非阻塞。
4. `make ci` 未对评审版本运行——设计阶段无实现，接受；收尾时必须全绿。
5. 基线数值已捕获但未入库（docs/auto/）——提交 1 前落地。
6. T3（per_sec:0 语义）、T7（双发 RateLimit-*）、T9（deny-all 短路）三个决策需要
   **维护者/安全/产品的显式决定**，评审不能代签。

**下一步（按序）**：
1. 设计/规格勘误 + 基线入库 + M7 基准矩阵定稿（前置条件，1 个会话）。
2. 维护者裁定 T3/T9（安全）、T7/T8（产品）——其余裁定无需上提。
3. 提交 1 落地并过全部验收；之后每提交独立过门。
4. 提交 3 内落地 H1 修复；收尾全量门 + bench-gate。

无任何 sign-off、deadline、owner 授权在本评审中虚构；上述"决策所有者"为需要被咨询/授权的
角色建议，最终以维护者确认为准。
