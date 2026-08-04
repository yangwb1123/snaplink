已完成全局扫描。核心事实:redis 包是根模块下的一个包(非嵌套模块,`go-redis` 在根 `go.mod`,`infrastructure/redis/` 下无 `go.mod`),现有 24 个 store(会话、refresh 族、auth-code、PAR、JTI、CIBA、MFA、设备码、限流、锁定、权限、consent 等),通过 `NewUniversalClient` 支持 single/sentinel/cluster 三种拓扑,并有 `cluster.go` 的 hash-tag/CROSSSLOT 处理;集群协调层(cluster.Bus)目前只有 memory/etcd/mqtt(库),存储层零指标。以下是最有价值的 3 个方向:

## 1. 让 Redis 从"热路径存储层"升级为集群协调层:增加 cluster.Bus 的 Redis pub/sub 实现

**问题:** 选择 Redis 作为热路径存储的部署(README 定位的 >1k QPS 多副本场景),要支撑 AGENTS.md §4 要求的跨副本失效(令牌吊销、签名密钥轮换、client/authz 变更、租户挂起),必须额外引入一套 etcd 或 MQTT 协调系统。`cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go` 的 `BuildInvalidationBus` 只支持 `memory`/`etcd` 两个分支;`infrastructure/mqtt/bus.go` 虽实现了 `cluster.Bus`(platform/cluster),但未接入 sso-server 且依赖独立 MQTT broker。而 Redis 已在同一拓扑中——`build_bootstrap.go:222` 的 redis readycheck 表明其可用性已被运维接受。这是明显的架构不对称:同一份部署里,存储用 Redis,协调却要另起炉灶。

**证据:** `platform/cluster` 的 `Bus` SPI + `interfaces/sso/server_invalidation.go` 的 `runInvalidationBus`(重订阅退避、`invalidation_bus_degraded` audit 事件、`InvalidationBusReady` 就绪门);`infrastructure/mqtt/bus.go` 证明该 SPI 可被消息中间件实现;AGENTS.md §3 "失效总线恢复:重订阅、刷新缓存、重播种吊销 deny-set 后再清除 degraded 就绪"——该恢复语义天然适配 pub/sub 的"断线丢事件后从源重播种"模型,失败关闭的语义(`server_invalidation.go` 的 applyInvalidation)不依赖事件持久化。

**为什么需要:** 产品上,Redis 选型客户当前被迫接受"Redis + etcd/MQTT"双系统运维面(两套高可用、两套监控、两套故障演练);这是从"吞吐层"走向"多副本集群"的最短路径补全。业务上,令牌吊销/密钥轮换/租户挂起是安全关键事件,跨副本传播延迟直接决定吊销生效时间——用已有的同一连接、同一 TTL/lease 语义实现,部署心智模型从"三套系统"收敛为"一套 Redis"。风险可控:Redis 已是 fail-closed 语义的既有载体(README §Failover),且 pub/sub 无需持久化(恢复靠重播种)。

## 2. 存储层可观测性为零:为 Redis stores 注入延迟/错误/命中率指标

**问题:** 整个 `infrastructure/redis/` 包(`ratelimit.go`、`session.go`、`refresh_token.go` 等 24 个 store)没有任何 prometheus 指标注册;包内唯一的健康信号是每个 store 的 `Ping(ctx)`(仅作 `/readyz`)。平台侧 `platform/metrics/` 已提供 `sso.WithMetrics(metrics.New())` 接入和 `sso_*` 指标族,`docs/observability.md` 声称"所有指标有界基数",但 Redis 后端是黑盒:没有每个 store 的操作延迟直方图、错误计数、JTI/session 的命中率、`sso:session:all` 等键的规模,也没有连接池/驱逐(`maxmemory` eviction)暴露。

**证据:** `grep -rn "prometheus\|metrics" infrastructure/redis/*.go` 无任何命中;`platform/metrics/metrics.go:20` 的 `WithMetrics` 机制存在且被 server 广泛使用(`platform/metrics/middleware.go` 的 HTTP 层指标),但存储层未接入;`docs/observability.md` 只覆盖 HTTP/审计/网关,无 redis store 章节。对比:限流器文档自述"consulted on EVERY middleware-gated request"(ratelimit.go:18),JTI 存储决定 replay 检测,这些恰恰是最需要 SLO 监控的路径。

**为什么需要:** 产品上,"backend: redis" 是面向性能选型客户的卖点,但运维侧无法回答最基本的问题:令牌消耗延迟是否劣化、JTI 命中率是否异常(可能预示 replay 扫描)、限流窗口竞争是否导致误伤。没有指标,`/token` fail-closed 的 500 风暴(README §Failover 描述的 Redis 中断场景)只能靠客户报障发现,而不是告警前置。实施面小(store 构造器统一注入带 label 的计时/计数钩子,`store=<name>` 有界基数),但价值贯穿所有 redis 后端特性。这也是把 redis 包从"功能正确"推向"可运维"的必由之路。

## 3. Session 枚举的 N+1 与全局单键索引热点:登录路径上的线性延迟

**问题:** `SessionManager.ListByUser`/`ListAll` 是"一次 `SMembers` 拿全部 id + 对每个 id 串行一次 `HGetAll`"(`infrastructure/redis/session.go` 的 `collect`,`s.load` 逐 id 单次往返),而 `ListByUser` 并非管理端专用:`interfaces/sso/server_oauth.go:196` 的 `sessionPolicyCapExceeded`(token-policy `max_active_sessions` 治理)在**登录路径上**调用它,`server_mfa_trust.go:470`、`server_tenant.go:285` 也走同一枚举。即:启用 `max_active_sessions` 策略后,每次登录的延迟随该用户活跃会话数线性增长(每个会话一次网络往返),高活用户登录直接受害。此外 `sessionAllKey = "sso:session:all"`(session.go:28)是**单个无界 SET**,`ListAll` 的 `SMembers` 是 O(N) 且单键热点,管理端 `handleAdminListAllDevices`(handlers.go:463)在万级会话下必然超时。

**证据:** `infrastructure/redis/session.go` 的 `ListByUser`(233 行)→ `collect`(241 行)逐 id `s.load`;`server_oauth.go:196` 登录路径调用;`sessionAllKey` 单键设计(session.go:28,Create 时 `SAdd`);对比 SQLite 同接口的 `SELECT ... WHERE user_id=?`(单次查询),Redis 端缺少等价物(如 pipeline 批量加载、按用户分片键、或 ZSET 按过期时间排序以支持 GC)。

**为什么需要:** 这是当前 redis 后端唯一的"功能正确但复杂度随规模线性恶化"的路径,且恶化的位置恰好在登录热路径上——与模块"吞吐层 >1k QPS"的定位直接冲突。修复方向明确(单次 pipeline 批量 HGetAll、按用户分片索引、`sso:session:all` 改为分片或 ZSET),收益可量化:百会话用户登录延迟从 ~100 次往返降到 1 次往返。这也解锁后续的"空闲会话 GC"和配额计数的 O(1) 化。

---

补充说明(非独立方向,供参考):`infrastructure/redis/doc.go` 声称该包是"独立嵌套模块",但实际它是根模块包(无 `go.mod`,`go-redis` 在根 `go.mod`,且 AGENTS.md 嵌套模块清单不含 redis);README.md 描述的是真实状态。这是文档与实现漂移,建议在任一方向落地时顺带修正,避免后续模块化改造时误导决策。
