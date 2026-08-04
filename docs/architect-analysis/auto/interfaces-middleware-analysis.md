# interfaces/middleware 模块分析

已完成全局扫描：`interfaces/middleware/`（约 2600 行，17 个文件）及其消费者——`interfaces/sso`（`server_routes.go`、`sso_wiring.go`、`options_httpstack.go`、`aliases.go`）、`interfaces/ratelimit`、`interfaces/ssoclient/rs`、`interfaces/admin`、`cmd/sso-server`、`cmd/sso-minimal`，以及相关的 `shared/core/router.go`、`platform/tracing`、`platform/audit`、`platform/metrics`、`shared/security/peertrust`、`domains/{tenant,region}`、`platform/geo` 等域中间件。

模块现状：混合了两种中间件签名（`core.MiddlewareFunc` 与 `func(http.Handler) http.Handler`），安全不变量（代理信任、限流、降级、探针豁免）靠注释维护，上下文/响应捕获机制在每个包中重复发明，可观测性存在"双追踪 + 全有或全无调试日志"的割裂。

---

## 1. 将中间件链形式化为带命名槽位的类型化管道（构建期强制排序不变量）

**问题**：`interfaces/middleware` 是安全边界，但链的排序不变量只存在于散落的注释里。包内同时存在两套中间件签名——`core.MiddlewareFunc`（`Auth`/`CORS`/`Logger`/`Tracing`/`Idempotency`）和 `func(http.Handler) http.Handler`（`Recover`/`Compress`/`AcceptVersion`/`Deprecation`/`Degradation`/`RequestLogger`/`TrustedProxies`）——导致 `interfaces/sso` 必须用散落在三个文件里的手写 `wrap*` 适配器拼接：`server_routes.go` 的 `buildMiddlewareChain`/`wrapInnerMiddlewares`、`sso_wiring.go` 的 `wrapPanicRecovery`/`wrapCompression`/`wrapAPIVersioning`、`server_health.go` 的 `degradationGate`。关键安全不变量目前全部是"注释契约"：

- "trustedProxies MUST wrap before rate limiting"（`server_routes.go:364`，否则限流器按可伪造的 XFF 分桶；`ratelimit/middleware.go` 的 `KeyByClientIDOrIP` 文档也警告未认证用户名做 key 可被绕过）；
- DR 门禁在限流内侧、body-limit 外侧（`server_routes.go:372` 注释）；
- 探针 `/livez` `/readyz` `/metrics` 完全绕开中间件栈（`buildProbeMux`）；
- `Idempotency` 的"必须在认证之后"位置不变量（`idempotency.go` 的 ORACLE-SAFE POSITION INVARIANT 注释）。

**证据**：`server_routes.go:360-400`、`sso_wiring.go:390-440`、`server_health.go:347-370`、`middleware.go`（双签名并存）、`ratelimit/middleware.go:50-116`。另外 `middleware.Auth` 在服务端实际未被使用（仅 `aliases.go` 后向兼容别名 + `test/middleware_test.go`），`middleware.CORS` 已被 `interfaces/cors` 取代（`interfaces/cors/cors.go:5` 明言 legacy）——这些遗留表面进一步说明缺少一个"链即声明"的归口。

**为什么需要**：这是回归风险最高的区域——任何一个未来中间件（如条件访问、geo、tenant）若被放进错误槽位，都会静默破坏 Oracle 安全或限流逃逸，且只在代码评审时被发现。一个带命名槽位（`trust → ratelimit → degradation → bodylimit → versioning → router`）的链构建器 + 构建期/测试期排序断言，能把 AGENTS.md "保留文档化中间件顺序" 的不变量从注释变成可执行的单测资产，同时消灭 `core.MiddlewareFunc`/`http.Handler` 双签名带来的适配器税。产品价值：SDK 消费者（`cmd/sso-minimal`、`cmd/sso-server`）无需阅读注释即可安全组合链。

## 2. 在 core 层标准化"请求级状态注册表 + 响应捕获栈"，消灭各包自建上下文管道的重复与脆弱性

**问题**：每个中间件都在重新发明请求级状态传递，机制互不兼容，且捕获机制已被证明出过真实事故：

- `context.go` 用未导出 struct key 存 subject（`subjectKey`）；
- `idempotency.go` 用另一个未导出 struct key 存 `idempotencyState`，并依赖 `SetResponseWriter` 换装捕获 writer——其注释自述"a concrete assertion on ctx.ResponseWriter() cannot locate it (this is exactly what silently broke capture under the adapters before)"，为此专门造了 `idempotency_capture_missing` 审计事件作为回归金丝雀（`recordCaptureMissing`）；
- `trusted_proxy.go` 用 `peertrust.WithRequestInfo` 走独立的第三方 context；
- `domains/tenant/middleware.go` 用**未类型化的字符串 key** `HandlerContextKey = "tenant:resolved"` 存在 `ctx.Get` 值袋里——与其他包的 key 存在碰撞类风险；
- `interfaces/ssoclient/rs/middleware.go` 又用 `claimsCtxKey`；
- `core/router.go` 的 `trackingResponseWriter` + `SetResponseWriter` 双包装机制是为了让 `Written()` 在捕获换装后仍真实。

**证据**：`idempotency.go:20-190`、`context.go:10-27`、`trusted_proxy.go:140-165`、`domains/tenant/middleware.go:20-60`、`interfaces/ssoclient/rs/middleware.go:20-40`、`core/router.go:66-110`。

**为什么需要**：新增中间件（subject、tenant、geo、region、claims、idempotency 已各搞一套）都要重复解决三个问题：类型安全 key、writer 捕获正确性、适配器（gin facade/echo Response 对象）透明性。三个问题中捕获最致命——多个中间件同时想捕获 body（idempotency + request logger + metrics）时，writer 换装顺序的脆弱性正是 `capture_missing` 金丝雀存在的理由。在 core 层提供统一的请求级类型化状态注册表 + 捕获栈（顺序无关、可组合）后，能：(a) 消除未类型化字符串 key 的碰撞类别；(b) 让捕获从"运行时发现缺失"变成"结构上不可能错"；(c) 删掉 `recordCaptureMissing` 这种为掩盖框架缺陷而设计的审计事件。这是把"框架该干的活"从业务包里收回来，长期降低每个新中间件的实现成本。

## 3. 统一可观测性：常开的结构化访问日志 + 单一 trace/audit 关联点（替代全有或全无的调试日志与双追踪）

**问题**：当前三套机制并存且互不打通，作为安全产品这直接削弱审计/事件响应能力：

- `middleware.Tracing`（W3C traceparent + X-Request-Id）被 `cmd/sso-server/build_app_core.go:157` 注释明言为 "legacy request-id middleware (not OTel)"，而 `platform/tracing.Middleware`（OTel span）同时默认安装（`build_app_core.go:158`）——两条传播链、两个开关（`WithTracingMiddleware` vs `WithTracing`）；
- `audit.EventFromRequest` 的关联 ID 是从请求头反读的（`platform/audit/handler_helpers.go:37-60`），即审计保真度取决于 legacy 中间件是否运行，与 OTel span 树完全脱节；
- `RequestLogger`（`request_log.go`）是全有或全无的 DEBUG 日志：`logBodies` 布尔开关一旦打开，就把 password/token/MFA code 原样写日志（注释自认"bodies may contain secrets"），无字段级脱敏、无路径白名单、无采样，注释还承认"log volume may be high, so only enable when actively investigating"——即生产事故时默认没有可用的访问日志。

**证据**：`request_log.go:25-90`、`middleware.go:90-165`（`Tracing`/`RequestID`）、`platform/tracing/tracing.go:226-243`、`platform/audit/handler_helpers.go:37-70`、`build_app_core.go:157-158`、`options_security.go:484-491`。

**为什么需要**：OAuth/OIDC 产品的审计流是合规面，但当前缺少常开的、低基数的结构化访问日志（method/path/status/duration/client-IP/request-ID 以 INFO 级默认开启，敏感字段脱敏，按路径 + 采样控量）——事故响应时操作者只能临时开 DEBUG 或冒着泄密风险开 `logBodies`。统一方向是：单一传播点（W3C traceparent）同时喂 OTel span 与审计事件（同一 trace ID），使审计轨迹与追踪树可交叉检索；访问日志字段级脱敏 + 路径级开关，使"密码进日志"从设计上不可能。这与 AGENTS.md "fail open with audit/logging" 不变量及 `docs/observability.md` 契约直接对齐，是产品可观测性成熟度的最高杠杆点。
