扫描完成。基于对 `interfaces/ratelimit/` 全部源码（SPI、中间件、SQLite/Redis 后端、fuzz/bench 测试）以及全库消费方（`interfaces/sso`、`interfaces/admin`、`config`、`domains/threataction`、`protocols/selfservice`、`infrastructure/redis`、`platform/metrics`）的全局核查，给出以下分析。

## 方向一：补齐"认证后"限流——按客户端/按用户分桶的安全落点（第二阶段限流）

**问题**：标准中间件链运行在认证之前（`interfaces/sso/server_routes.go` 的 `buildMiddlewareChain`：trustedProxies → ratelimit → degradation → bodylimit → router），因此整条链上**唯一安全的键只有 IP**。`KeyByClientIDOrIP`（`interfaces/ratelimit/middleware.go:57-71`）被文档明确标注 UNSAFE——HTTP Basic 用户名是攻击者可控输入，逐请求轮换即可无限开新桶逃逸全部节流；`KeyBySubject`（`middleware.go:94-105`）虽然已实现，但其文档自述"middleware ran before auth"时回退到 IP，全库检索显示它除单元测试外**无任何生产接线**。后果是双向失效：共享出口 NAT/代理 IP 下，一个滥用客户端会耗尽整桶额度连累无辜用户；而分布在不同 IP 上的撞库（credential stuffing）又完全绕开按 IP 的桶。现有的替代品都不解决此问题：grant 级限流（`interfaces/sso/options_grants.go` 的 `WithGrantTypeRateLimit`/`rateLimiterEntry`）只按 grant type URN 分桶，不按 client；admin 限流退化为常量键 `admin`（`interfaces/admin/governance.go:275-310`），一个管理员即可耗尽全管理员共享桶（管理员间互相 DoS）。

**证据**：`interfaces/ratelimit/middleware.go`（KeyByClientIDOrIP/KeyBySubject 的警告与回退注释）、`interfaces/sso/server_routes.go:345-392`（中间件顺序）、`interfaces/sso/options_grants.go:108-143`、`interfaces/admin/governance.go:275-310`、`interfaces/middleware/context.go`（`SubjectFromContext` 已可用）。

**为什么需要**：多租户 SaaS SSO 的核心公平性诉求是按 OAuth client 与按用户（如 `/userinfo` 爬取防护）限流；代码库已具备全部原料（认证中间件把 subject 写入 context），只缺一个安全的组合点——在认证之后挂载同 SPI 的第二段限流（或 `KeyBySubject` 的两段式键：IP + 认证主体），并顺带修复 admin 常量键的串扰缺陷。这是当前限流体系中最显著的能力空洞。

## 方向二：限流剩余额度可见性——信息头（X-RateLimit-*）与额度指标

**问题**：SPI 契约 `Allow(key) (ok, retryAfter)`（`interfaces/ratelimit/ratelimit.go:38-43`）只回传"是否放行 + 重试等待"，**丢弃了剩余额度**；`reserve()`（`ratelimit.go:117-148`）在拒绝路径直接 `Cancel()` 掉预留，剩余 token 数无从得知。中间件 429 响应只带 `Retry-After`（`middleware.go:216-233` `writeTooManyRequests`），无 `X-RateLimit-Limit/Remaining/Reset`；指标只有拒绝计数 `sso_rate_limit_hits_total`（`platform/metrics/consts.go:110`，且仅在 reject 路径 `recordRejection` 计数，`middleware.go:195-213`）；`MemoryLimiter.Buckets()`（`ratelimit.go:200-210`）被注释为 test-only，运维无法观察桶规模。此外 Retry-After 语义三后端不一致：Memory/SQLite 的 deny-all 配置返回 retry=0 → **不写 Retry-After 头**（`ratelimit.go` reserve 与 `sqlite_limiter.go` consumeToken 的 denyAll），而 Redis 的 deny-all 是 365 天窗口（`infrastructure/redis/ratelimit.go` `NewLimiterFromRate`），客户端拿到的退避信号要么缺失、要么荒谬。

**证据**：`interfaces/ratelimit/ratelimit.go`（`Limiter` 接口、`reserve`、`Buckets`）、`interfaces/ratelimit/middleware.go`（`writeTooManyRequests`、`recordRejection`、`Policy.Metrics`/`TenantKeyFunc`）、`platform/metrics/consts.go:110`、`infrastructure/redis/ratelimit.go`（deny-all 窗口）、`docs/observability.md:43`（唯一指标行）。

**为什么需要**：SaaS 前端/SPA 需要按剩余额度**主动自限速**而非撞到 429 才退避；运维需要"距阈值还有多少余量"的预判指标来在撞库事故前调 `security.rate_limit.*`（该配置已支持 SIGHUP 热更，但调参靠猜）。SPI 扩展是加法式的小改动（Allow 多返回 remaining），却能同时统一三后端的 Retry-After 语义、打通额度可观测性——投入产出比最高。

## 方向三：限流实现碎片化收敛——五套平行限流机制统一到同一 SPI 与同一 429 契约

**问题**：全库存在至少五套互不通用的限流实现，语义与错误契约各自漂移：(1) grant 级限流用裸 `golang.org/x/time/rate.Limiter`（`interfaces/sso/options_grants.go:113-143` + `server_token.go:365-375` `checkGrantRateLimit`），拒绝时返回 **429 却带 `unsupported_grant_type` 错误码、无 Retry-After**——与 `docs/error-codes.md:921` 规定的 `rate_limited` 稳定契约（"SPAs branch on this string"）直接冲突，客户端会误判为自己的 grant_type 非法；(2) admin 限流复用 `PolicyStore` 但常量键 `admin`（`interfaces/admin/governance.go`）；(3) self-service 注册限流被迫复制子集接口 `selfservicecore.RateLimiter`（`protocols/selfservice/selfservicecore/deps.go:17-24`），只因 domains 层无法 import interfaces 层；(4) `domains/threataction` 自建内存固定窗口 map + 1024 条上限的借锁清扫（`domains/threataction/registry.go:29,164-219`），第四套窗口实现、无指标无 TTL 租赁；(5) admin 写配额是另一套固定窗口预算（`interfaces/sso/quota.go`）。加上 Redis 后端是 fixed-window 而 memory/SQLite 是 token-bucket（`infrastructure/redis/ratelimit.go` 文档自述），同一份配置在不同后端下行为不同。

**证据**：`interfaces/sso/server_token.go:363-377`（错误码漂移）、`interfaces/sso/options_grants.go:108-143`、`interfaces/admin/governance.go:275-310`、`protocols/selfservice/selfservicecore/deps.go:17-24`、`domains/threataction/registry.go:164-219`、`infrastructure/redis/ratelimit.go`（窗口模型差异）、`docs/error-codes.md:917-921`（契约基准）。

**为什么需要**：每新增一个限流点就重写一次窗口/桶、清扫、fail-open 与指标，长期必然继续漂移（grant 限流的错误码漂移已是既成事实的契约破坏）。收敛到 `Limiter` SPI 后，语义（0/负数、窗口 vs 桶）、度量路径（`sso_rate_limit_hits_total`）、生命周期（`memreaper` 惯例）各得一份唯一实现。注意关键架构约束：`domains/` 与 `protocols/` 不能 import `interfaces/ratelimit`（`docs/architecture/DIRECTORY_MAP.md` 分层，threataction 注释明确说明不能复用 memreaper 的根因），因此收敛方案需要把 SPI 下沉到 `shared/` 内核层——这本身符合"imports flow toward the shared kernel"的架构方向，是收益最大的技术债清偿点。
