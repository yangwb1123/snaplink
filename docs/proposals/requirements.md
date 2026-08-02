规格已产出并保存至 `docs/auto/interfaces-ratelimit-direction2-spec.md`。三条改进按依赖链组织（SPI 地基 → 对外头契约 → 可观测性），每条均带文件/符号级证据。

---

# 需求规格：方向二——限流剩余额度可见性（X-RateLimit-* 信息头与额度指标）

范围：只做加法式改造；不改键语义、不动中间件链位置（方向一）、不收敛五套限流机制（方向三）；429 体 `{"error":"rate_limited"}` 契约不变。

## 决策一：扩展 Limiter SPI——`Allow` 返回额度状态（remaining/limit/reset）

**问题**：`Allow(key) (ok, retryAfter)` 只回传放行与重试等待，丢弃剩余额度；`reserve()` 拒绝路径 `reservation.Cancel()` 后剩余 token 无从得知；三后端内部都持有或已取到该数据，SPI 却无出口。

**证据**：
- `interfaces/ratelimit/ratelimit.go:38-43`（`Limiter` 接口）、`reserve`（117-148，拒绝时 Cancel）、`Buckets`（200-210，"Test-only"）
- `golang.org/x/time/rate.Limiter.Tokens()`（x/time@v0.15.0/rate/rate.go:94）——Memory 后端无需新增状态即可取余量
- `interfaces/ratelimit/sqlite_limiter.go`（`loadBucketTokens`/`consumeToken` 已持有 tokens 值）
- `infrastructure/redis/ratelimit.go`（`allowScript` 已返回 `{count, pttl}`，`Allow` 丢弃 count）

**提议行为**：`Allow(key) Allowance`，`Allowance{OK, RetryAfter, Remaining, Limit, ResetIn}`。Memory：`Remaining = floor(lim.Tokens())`（Cancel 后读）、`ResetIn = (burst-tokens)/perSecond`；SQLite：直接用 `consumeToken` 的 tokens 值；Redis：`Remaining = max(limit-count, 0)`、`ResetIn = pttl`。deny-all 三后端统一 `{false, 0, 0, 0, 0}`（Redis 365 天窗口仅保留为键 TTL，不再泄漏为退避信号）；fail-open 返回 `{OK:true}` 零额度。

**验收**：三后端 `var _ Limiter` 断言与全部调用点同提交更新；Memory/SQLite/Redis 单测验证 Remaining 单调递减、refill 回升封顶、跨 replica 一致、deny-all 恒 `RetryAfter==0`、fail-open 注入不 panic。

## 决策二：中间件输出 X-RateLimit-Limit/Remaining/Reset，统一三后端 429 的 Retry-After 语义

**问题**：`writeTooManyRequests`（`middleware.go:216-233`）只写 Retry-After，允许路径零额度头，SPA 无法主动自限速；deny-all 下 Memory/SQLite 不写 Retry-After（`reserve` 的 `perSecond<=0` 分支、`consumeToken` 的 denyAll 分支），Redis 却给 365 天窗口（`NewLimiterFromRate`）——同一配置跨后端行为漂移。

**证据**：`middleware.go` `writeTooManyRequests`/`Middleware`/`DynamicMiddleware` 调用点；`consts.go` 头名常量块（sso→ratelimit 循环依赖约束已注明）；`ratelimit.go` `reserve`；`sqlite_limiter.go` `consumeToken`；`infrastructure/redis/ratelimit.go` `NewLimiterFromRate`。

**提议行为**：`consts.go` 新增 `HeaderRateLimitLimit/Remaining/Reset`（Reset 为 Unix epoch 秒）；允许与拒绝两条路径都写三头，数值取自同一次 `Allow` 的 `Allowance`（零额外往返）；fail-open 不写额度头；429 的 Retry-After 维持 ceil 逻辑但仅当 `RetryAfter>0` 写入，deny-all 统一为"无 Retry-After + `X-RateLimit-Remaining: 0`"。

**验收**：放行/429 两路径头值与桶状态互洽（Remaining 归零后下一请求必 429）；deny-all 三后端响应字节一致；`DynamicMiddleware` 热更后新头反映新桶参数；未命中规则不写任何 X-RateLimit-* 头。

## 决策三：额度可观测性——允许路径计数、剩余额度采样 gauge、活动桶规模指标

**问题**：指标只有拒绝计数 `sso_rate_limit_hits_total`（`platform/metrics/consts.go:110`），且仅在 `recordRejection`（`middleware.go:195-213`）拒绝路径计数；运维无法在撞库前预判余量调参（`security.rate_limit.*` 已支持 SIGHUP 热更但调参靠猜）；`Buckets()` 是 test-only；`docs/observability.md:43` 仅一行指标。

**证据**：`platform/metrics/consts.go:110`、`conditional_access.go:56-64`（`ObserveRateLimitHit` nil-safe 模式）、`middleware.go` `recordRejection` + `Policy.TenantKeyFunc` 文档（"Called ONLY on the reject path"）、`ratelimit.go` `Buckets`、`ratelimit_bench_test.go`。

**提议行为**：① `sso_rate_limit_requests_total{result, tenant}`——允许路径也计数，tenant 仅在拒绝路径解析（允许路径用 `TenantLabelUnknown`，遵守热路径约束），不修改既有指标的名字/标签集；② `sso_rate_limit_remaining{policy}` gauge——复用 1/64 采样点（与 prune 同比例），采样命中时记录余量，允许路径成本仅一次原子自增；③ `sso_rate_limit_buckets` gauge——`StartPruner` 清扫回调内上报 `Buckets()`，SQLite 采样 COUNT，Redis 文档注明不支持。同步更新 `docs/observability.md`。

**验收**：metrics 测试覆盖 allowed/rejected 计数与 tenant 标签、采样数值与 `Allowance.Remaining` 一致、nil Metrics 全 no-op、桶 gauge 随 key 生命周期涨落；`ratelimit_bench_test.go` 允许路径无回归；`-race` 全绿；既有 `sso_rate_limit_hits_total` 行为不变。

---

依赖关系：决策一 → 决策二（头值来源）→ 决策三（同源状态接指标）。若要继续，下一步可按此顺序实施，首个提交落在 `interfaces/ratelimit/ratelimit.go` + 三个后端的 SPI 迁移。
