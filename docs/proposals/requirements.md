# 需求规格：interfaces/middleware 统一可观测性（方向 3）

范围：`interfaces/middleware` 及其消费者（`interfaces/sso` 装配、`cmd/sso-server`、`platform/tracing`、`platform/audit`）。目标：以"常开结构化访问日志 + 单一 trace/audit 关联点"替代当前"全有或全无的 DEBUG 日志 + 双追踪"。以下 3 项改进均有代码证据，按依赖顺序排列（1、2 是日志侧，3 是关联侧）。

## 改进 1：常开的结构化访问日志（INFO 级、低基数、默认开启）

**问题**：当前唯一会输出 method/path/status/duration 的日志中间件 `RequestLogger` 是 DEBUG 级、默认关闭的——生产事故发生时操作者拿不到任何访问日志，只能临时开 DEBUG 或靠 `metrics` 聚合猜测。`middleware.Logger` 虽然 INFO 级，但只记录 method/path 两个字段，无 status/duration/IP/request-ID，无法支撑事件响应。安全产品在事故/取证场景下"默认无访问日志"与 AGENTS.md "fail open with audit/logging" 不变量直接冲突。

**证据**：
- `interfaces/middleware/request_log.go:25-30` — `RequestLogger` 注释自认 "the log volume may be high, so only enable when actively investigating"；`l.Debug("request", fields...)`（`:88`）。
- `interfaces/sso/options_httpstack.go:224-230` — `WithRequestLogging(logBodies bool)`，注释 "Default is disabled (zero overhead)"，仅一个布尔开关。
- `interfaces/sso/server_routes.go:445-446` — 装配点 `if s.debugRequestLogging { inner = middleware.RequestLogger(...) }`，默认不装。
- `interfaces/middleware/middleware.go:87-92` — `Logger` 仅 `method`/`path` 两字段。
- `interfaces/sso/server_routes.go:347-356` — `buildProbeMux` 使 `/livez`/`/readyz`/`/metrics` 天然绕开链，访问日志可沿用该豁免。

**建议行为**：在 `interfaces/middleware` 新增 `AccessLogger(l spi.Logger)`，INFO 级、默认在 `cmd/sso-server` 安装（`buildMiddlewareChain` 中新增固定槽位，位于 trustedProxies 内侧、ratelimit 外侧以便记录真实 client IP）。字段固定为低基数集合：`method`、`path`、`status`、`duration_ms`、`client_ip`（经 `peertrust.RequestInfoFrom` 取真实 IP，非原始 XFF）、`request_id`、`trace_id`——不含任何 body。探针沿用 probe-mux 豁免。新增配置项（如 `logging.access_log.enabled`）写入 `docs/config-reference.md`，默认开启、可关闭；`WithRequestLogging` 保留为仅调试用、标记 deprecated。兼容性：记录字段是新增输出，不改变任何现有响应/审计行为。

**验收检查**：
1. 新单测：经完整链（含 trustedProxies）的一次请求产生恰好一条 INFO 记录，含 `status`/`duration_ms`/`client_ip`/`request_id`，且默认无 `request_body`/`response_body` 字段。
2. `sso-server` 默认配置（无任何 logging 选项）下 `/token` 请求产生访问日志；`/livez`、`/readyz`、`/metrics` 不产生（探针豁免断言）。
3. 配置关闭后链上零额外开销（`AccessLogger` 不安装）；`docs/config-reference.md` 与 `docs/observability.md` 同步更新。
4. `go build ./... && go vet ./...`、`go test -run 'TestMaintainability_|TestArchitecture_' .`、`make ci` 全绿。

## 改进 2：body 日志改为"路径白名单 + 字段级脱敏 + 采样"，凭据从设计上不可能落盘

**问题**：`logBodies` 是一个全有或全无的布尔开关，一旦打开就把请求/响应 body 原样写入日志——注释自己承认 "bodies may contain secrets such as passwords, tokens, or MFA codes"，但代码没有任何脱敏、路径限制或采样。`/token` 的 form body 含 `client_secret`、`password` 授权流含明文口令、MFA 含验证码；开着 `logBodies` 排障等于把凭据批量倒入日志/采集管道。这是"排障能力"与"泄密风险"之间的错误二元选择。

**证据**：
- `interfaces/middleware/request_log.go:29-33` — "logBodies controls whether ... bodies may contain secrets such as passwords, tokens, or MFA codes"（仅有注释，无机制）。
- `request_log.go:44-53` — `io.ReadAll(r.Body)` 后 `string(b)` 原样存入 `reqBody`；`:66-90` 将 `request_body`/`response_body` 原样 append 进日志字段。
- `interfaces/sso/options_httpstack.go:224-230` — `WithRequestLogging(logBodies bool)`，布尔值是该策略的全部表达力。
- `interfaces/sso/request_logging_test.go:113` — 现有测试只验证"开了就记"，无任何脱敏断言。

**建议行为**：用结构化策略替换布尔开关：`WithRequestLogging(opt BodyLogPolicy)`，其中 `BodyLogPolicy` 含三要素——(a) 路径白名单（默认空 = 任何路径都不记 body，仅审计/低敏端点如 `/health` 可加入）；(b) 字段级脱敏：对 form/JSON body 按 key 名（`password`、`client_secret`、`code`、`token`、`assertion`、`id_token_hint` 等，见 `shared/core/consts.go` 既有命名）替换为 `[redacted]`，未知字段保留但受大小上限（如 4KB）约束；(c) 采样率（默认 0，显式配置才开启）。脱敏逻辑必须在 `interfaces/middleware` 内实现（不依赖 handler 配合），且保持与改进 1 的 `AccessLogger` 共用捕获栈。`logBodies=true` 的旧签名经 `BodyLogPolicy{AllowAllPaths: true}` 兼容但标记 deprecated，并在文档中警告。

**验收检查**：
1. 表驱动测试：`password=topsecret`、`client_secret=xxx`、JSON `{"code":"123456"}` 等输入在"记录 body"策略下，日志行仅含 `[redacted]`，原始值在输出中不可检索（grep 断言）。
2. 白名单外路径（如 `/token`）即使策略开启也永不记录 body；白名单内路径超 4KB 的 body 被截断。
3. 采样率 0.25 时统计 1000 次请求，记录数落在置信区间内。
4. `docs/config-reference.md` 记录新策略字段；`make ci` 全绿。

## 改进 3：单一 trace/audit 关联点——OTel 传播源唯一化，审计不再依赖 legacy 头反读

**问题**：当前存在两条互不连通的传播链和两个开关：legacy `Tracing`（W3C traceparent + X-Request-Id，`core.MiddlewareFunc`）与 OTel `platform/tracing.Middleware` 同时默认安装；而审计事件 `EventFromRequest` 是从请求头反读 TraceID/SpanID 的——审计保真度取决于 legacy 中间件是否运行，与 OTel span 树完全脱节。一个部署可以只装 OTel（span 有了、审计无 trace）、只装 legacy（审计有 trace、无 span 树）、或两者都装（同一请求两条传播链），三种形态的取证价值各不相同且难以预判，正是"双追踪"割裂。

**证据**：
- `cmd/sso-server/build_app_core.go:157-158` — `sso.WithTracingMiddleware(), // legacy request-id middleware (not OTel)` 与 `sso.WithTracing("sso-server")` 相邻安装，注释自认 legacy。
- `interfaces/middleware/middleware.go:90-165` — `Tracing()`/`RequestID()` 自建 `audit.NewTracer()` 解析/生成 traceparent，`core.WithTraceID` 与响应头 `X-Trace-Id`/`Traceparent` 均由此中间件写入。
- `platform/audit/handler_helpers.go:37-60` — `EventFromRequest` 读 `r.Header.Get(core.HeaderTraceparent)`/`HeaderRequestID` 反解 `e.TraceID`/`e.SpanID`，注释明言 "without that middleware installed, RequestID/TraceID/SpanID stay empty"。
- `interfaces/sso/options_security.go:484-497` — `WithTracingMiddleware` + `WithRequestIDMiddleware` deprecated 别名；`options_httpstack.go:24-38` — `WithTracing(operation)` 独立开关；`server_routes.go:113` — `router.Use(TracingMiddleware())` 与 `buildMiddlewareChain` 中的 `tracing.Middleware`（`server_routes.go:400-407`）双点安装。
- `docs/observability.md:103-109` — 既有线契约：`X-Trace-Id` 响应头 + 错误体 `trace_id`（经 `core.WithTraceID`）。

**建议行为**：让 OTel 成为唯一传播源，legacy 中间件降级为纯 `X-Request-Id` 单跳生成器（不再解析/改写 traceparent、不再自建 `audit.NewTracer`），最终移除 `WithTracingMiddleware`/`RequestID` 表面。具体：`platform/tracing.Middleware` 的包装器在开 span 后把 span 的 TraceID/SpanID 写入请求上下文（`core.WithTraceID`）并回写响应头 `X-Trace-Id`/`Traceparent`（保住 observability.md 契约与错误体 `trace_id`）；`EventFromRequest` 改为优先从 OTel span 上下文（`trace.SpanFromContext`）取 TraceID/SpanID，头反读仅作外部调用兜底——审计事件与 span 树共享同一 trace ID，两个开关合一（`WithTracing` 一个选项同时决定 span 与审计关联）。`platform/tracing` 已提供 `StartSpan`/`ParentFromIDs` 等 seam（`docs/observability.md` 异步路径表），关联点统一后异步审计子 span 的父子关系（`audit.sink.deliver` 等）自然衔接。

**验收检查**：
1. 集成测试（`test/`，`package ssotest`）：仅安装 `WithTracing`（不装 legacy）的服务器处理一次 `/token` 请求，断言 (a) 审计事件 `TraceID` == 该请求 OTel span 的 trace ID，(b) 响应头 `X-Trace-Id` 与错误体 `trace_id`（构造一次失败请求）与之一致。
2. 单元测试：`EventFromRequest` 在无任何头的情况下，从 OTel span 上下文仍能填出 `TraceID`/`SpanID`。
3. 删除 `WithTracingMiddleware`/`RequestID` 后 `go build ./...` 无残留引用（`cmd/sso-minimal/app.go:102` 一并迁移）；`docs/observability.md` 的中间件栈图与配置文档更新为单一传播点。
4. `go test ./... -race`、`go test ./test/ -run TestE2E -v`、`make ci` 全绿；无任何响应头/审计字段回归（对比 `interfaces/sso` 现有 tracing 相关测试）。

三项改进共同把 `interfaces/middleware` 的可观测性从"事故时才临时开启的 DEBUG 日志 + 两条传播链"收敛为"默认常开、结构固定、凭据不可入日志的访问日志 + 单一 OTel trace 源同时喂 span 树与审计事件"，直接兑现 `docs/observability.md` 与 AGENTS.md "fail open with audit/logging" 契约。
