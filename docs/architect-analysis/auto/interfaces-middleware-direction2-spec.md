# Requirements Specification: interfaces/middleware — core 层「请求级状态注册表 + 响应捕获栈」

Source: expansion direction 2 of `docs/auto/interfaces-middleware-analysis.md`
(「在 core 层标准化"请求级状态注册表 + 响应捕获栈"，消灭各包自建上下文管道的重复与脆弱性」).
Scope is the request-state and response-capture plumbing spread across
`interfaces/middleware`, `shared/core`, `shared/security/peertrust`,
`platform/geo`, `interfaces/admin`, `interfaces/ssoclient/rs`,
`domains/tenant`, and `interfaces/sso`. Exactly three evidence-backed
improvements; each carries name, problem, evidence, proposed behavior,
acceptance check.

## 0. Scope and hard constraints

- **Budgets that bind the design**: `shared/core` is at its frozen 23-file
  ceiling (`directory_fanout_test.go:63`) — the registry/capture code must be
  net-new-file-neutral: carve the `Context`/`trackingResponseWriter`/`values`
  bag out of `shared/core/router.go` (456 lines, under the 500-line file
  budget) into a new `shared/core/request_state.go` so the directory count
  stays 23 and `router.go` shrinks. `interfaces/sso` is at its 60-file
  ceiling (`directory_fanout_test.go:59`) — all SSO-side edits are
  modifications to existing files (`server_token.go`, `server_login_auth.go`,
  `server_finish_login.go`, `accessors_threat.go`). No new `layerExemptions`
  entries, ever (AGENTS.md §2).
- **Kernel purity**: `shared/core` imports no Snaplink package (AGENTS.md §4).
  Typed registry keys are *handles instantiated by owning packages*
  (`tenant`, `sso`, `middleware`, `peertrust`), never core types carrying
  domain data.
- **Non-goals (out of scope for this direction)**: the typed named-slot chain
  builder (direction 1, `docs/auto/interfaces-middleware-spec.md`) and the
  observability unification (direction 3). The `HandlerContext` interface
  change (dropping `SetResponseWriter`) is deliberate and lands together with
  all three adapters (`shared/core/router.go`, `interfaces/adapters/gin`,
  `interfaces/adapters/echo`) and `backgroundHandlerContext`
  (`interfaces/sso/sso_wiring.go`) in the same change, so no intermediate
  state is ever broken.

---

## 1. 类型化请求级状态注册表：消灭未类型化字符串 key 与 11 个重复的私有 context key

**名称**: Typed request-state registry (`core.RequestKey[T]` + 注册表取代
`sync.Map` 值袋与全部 `type XKey struct{}` 私有 key).

**问题**: 请求级状态散落在两套互不兼容的机制里，新中间件必须二选一、猜
数据写在哪一边、再手搓一个新 key：

1. `r.Context()` + 未导出 struct key（每包一个，全库至少 11 个）：
   `subjectKey`、`idempotencyKey`、`requestInfoKey`、`traceIDContextKey`、
   `cspNonceContextKey`、geo `ctxKey`、`breakGlassActorKey`、
   `actorContextKey`、`claimsCtxKey` 等；
2. `HandlerContext` 未类型化字符串值袋（`sync.Map`），生产代码里的字符串
   key 已有四个：`"tenant:resolved"`、`"auth_hook_skip_mfa"`、
   `"device_ctx"`，以及跨包裸读的 `"extensions"`。

字符串 key 是运行时碰撞类别（`tenant:resolved` 与 `auth_hook_skip_mfa`
同袋共存，拼错即静默 nil），值袋 `Get` 返回 `any`，消费者每次都要
`.(*T)` 类型断言，错配在运行时才炸。

**证据**:
- `interfaces/middleware/context.go:11` — `type subjectKey struct{}`
  （`interfaces/ratelimit/middleware.go:105` `KeyBySubject` 消费）；
- `interfaces/middleware/idempotency.go:14` — `type idempotencyKey struct{}`；
- `shared/security/peertrust/request.go:16` — `type requestInfoKey struct{}`；
- `shared/core/trace_context.go:6,22` — `traceIDContextKey` + `cspNonceContextKey`；
- `platform/geo/context.go:8` — `type ctxKey struct{}`；
- `shared/core/admin_token.go:152` — `breakGlassActorKey`；
- `interfaces/admin/middleware.go:477` — `actorContextKey`；
- `interfaces/ssoclient/rs/middleware.go:16` — `claimsCtxKey`；
- `domains/tenant/middleware.go:17` — `const HandlerContextKey = "tenant:resolved"`（字符串）；
- `interfaces/sso/accessors_threat.go:20,260,303` —
  `ctxKeyAuthHookSkipMFA = "auth_hook_skip_mfa"`（字符串）；
- `interfaces/sso/server_finish_login.go:140` `ctx.Set("device_ctx", …)` /
  `server_login_auth.go:329` `ctx.Get("device_ctx")`（字符串）；
- `protocols/selfservice/loginui.go:31` — `ctx.Get("extensions")`（跨包裸读字符串 key）；
- 值袋本体：`shared/core/router.go:99` `values sync.Map` + `Set/Get`
  （router.go:149-154），并在 `interfaces/adapters/gin/adapter.go:211-217`、
  `interfaces/adapters/echo/adapter.go:241-247`、
  `interfaces/sso/sso_wiring.go:291-295`（`backgroundHandlerContext` 的
  `map[string]any`）各复制一份实现。

**拟议行为**: `shared/core` 提供单一注册表 API：

- `type RequestKey[T any] struct{ name string }` + `NewRequestKey[T](name)`
  —— key 按类型唯一，跨类型使用在编译期失败；key 实例由属主包构造
  （`tenant.ResolvedKey`、`sso.DeviceCtxKey`、`middleware.SubjectKey`、
  `peertrust.RequestInfoKey`…），core 不 import 任何 Snaplink 包；
- `HandlerContext` 增加 `Get[T](RequestKey[T]) (T, bool)` / `Set[T](RequestKey[T], T)`；
- 值袋的四个生产字符串 key 全部迁移到注册表；`Set(string, any)` /
  `Get(string)` 降级为迁移期 shim，生产代码清零后删除；
- 实现随 `Context` 一起从 `router.go` 拆到新文件 `shared/core/request_state.go`
  （净文件数保持 23，`router.go` 收缩到 500 行内）。

**验收检查**:
- `go test -run 'TestMaintainability_|TestArchitecture_' .` 通过；
  `directory_fanout_test.go` 中 `shared/core: 23` 不变，无新增豁免；
- `rg -n 'ctx\.Set\("|ctx\.Get\("' --type go -g '!*_test.go'` 在生产代码中
  零命中（`tenant:resolved` / `auth_hook_skip_mfa` / `device_ctx` /
  `extensions` 全部迁移）；
- 编译期类型安全有测试证明：对 `RequestKey[tenant.Resolved]` 调
  `Get[tenant.Resolved]` 通过，跨类型（如 `Get[oauth.Client]`）编译失败；
- 全库新增 context key 冻结：`rg 'type \w+Key struct\{\}'` 在迁移后
  不再出现新条目（现存 11 个私有 key 中，跨包共享的收敛进注册表，
  纯包内一次性数据可保留但不得新增）。

---

## 2. core 层响应捕获栈：捕获从「运行时发现缺失」变为「结构上不可能错」

**名称**: Composable response-capture stack（顺序无关、可组合的捕获层栈，
取代 `SetResponseWriter` 换装 + 各包自造 wrapper + `capture_missing` 金丝雀）。

**问题**: 捕获正确性是方向 2 三个问题中最致命的。每个捕获者重造 wrapper，
换装顺序脆弱且只在运行时暴露：

- `idempotency.go:16-25` 注释自述：`SetResponseWriter` 之后捕获器位于 gin
  facade / echo Response 对象背后，「a concrete assertion on
  ctx.ResponseWriter() cannot locate it (this is exactly what silently broke
  capture under the adapters before)」——框架缺陷曾真实造成捕获静默失效；
- `shared/core/router.go:60-90` 的 `trackingResponseWriter` 双包装
  （`tracking → capture → tracking' → original`）完全是为 `Written()` 在换装后
  仍真实而存在（`Written()` 的类型断言在 router.go:119-121）——一接口调用 +
  每写一 flag 翻转的税；
- `interfaces/adapters/gin/adapter.go:226-250` 需要专用 `ginCaptureWriter`
  facade（`gin.Context.Writer` 是 `gin.ResponseWriter` 类型），
  `interfaces/adapters/echo/adapter.go:255-258` 换 `Response().Writer`——
  每个适配器手写换装语义，文档还承认 WriteHeaderNow-only 路径状态不进捕获；
- `interfaces/middleware/request_log.go:10-28` 的 `requestLogResponseWriter`
  是 http.Handler 级独立捕获，根本看不到 `HandlerContext` 换装——同一请求上
  idempotency + request logger + metrics 三个捕获者之间**没有定义组合顺序**；
- 失效只在运行时经 `idempotency_capture_missing` 审计金丝雀暴露
  （`recordCaptureMissing` idempotency.go:212、
  `EventIdempotencyCaptureMissing` platform/audit/aliases_spi.go:127）——
  框架缺陷以安全审计事件的形式呈现，还占着审计基数；
- `interfaces/sso/sso_wiring.go:304` —
  `func (b *backgroundHandlerContext) SetResponseWriter(http.ResponseWriter) {}`
  在后台路径静默吞掉换装。

**证据**: 见上——`interfaces/middleware/idempotency.go:16-25,52-106,212`、
`shared/core/router.go:60-90,119-130`、`interfaces/adapters/gin/adapter.go:226-250`、
`interfaces/adapters/echo/adapter.go:255-258`、
`interfaces/middleware/request_log.go:10-28`、
`platform/audit/aliases_spi.go:127`、`interfaces/sso/sso_wiring.go:304`。

**拟议行为**: core 拥有捕获栈：

- `NewContext` 在 `trackingResponseWriter`（只装一次，位于栈底）之上创建
  `CaptureStack`；`HandlerContext.Capture() *CaptureStack` 提供
  `Add(CaptureLayer)`——每个 layer 独立收到完整 status + body，与注册顺序、
  适配器无关；多捕获者（idempotency、request logger、metrics）并发注册互不覆盖；
- 提交路径（`CommitIdempotentResponse`、`finishTokenIdempotency`）读自己在
  **安装时拿到的 layer 句柄**，而非对 `ctx.ResponseWriter()` 做类型断言——
  捕获缺失从结构上不可能；
- 适配器实现一个原语（把自身 writer 挂到栈上），删除
  `SetResponseWriter`（接口方法）与全部 `ginCaptureWriter` 类 facade；
- `InstallCapture`、`recordCaptureMissing`、
  `EventIdempotencyCaptureMissing` 一并删除——审计事件类型是"为掩盖框架
  缺陷而设计"的（AGENTS.md 审计基数纪律：事件类型只减不增）；
- 后台路径（`backgroundHandlerContext`）的捕获注册保持定义但惰性
  （no-op layer），提交无 panic。

**验收检查**:
- `interfaces/adapters/routertest`（conformance 套件）在 std / gin / echo
  三适配器上新增用例：同一请求上两个捕获层同时注册，二者观察到的
  status + body 逐字节一致；gin facade 与 echo `Response.Writer` 路径捕获
  完整；捕获后 `Written()` 仍真实；
- `rg 'SetResponseWriter|InstallCapture|requestLogResponseWriter' --type go
  -g '!*_test.go'` 在 core 之外零命中（含 `sso_wiring.go` 的 no-op）；
- `EventIdempotencyCaptureMissing` 从 `platform/audit` 与
  `docs/observability.md` 事件表同时移除（同变更提交，不留文档漂移）；
- `go test ./... -race` 与 `make ci` 通过；后台 Coordinator 路径测试证明
  capture 注册/提交无 panic、无审计噪音。

---

## 3. 统一请求状态表面：http.Handler 级与 HandlerContext 级中间件共用同一注册表

**名称**: Single request-state surface（两种中间件签名读写同一份注册表；
消灭第二份解析逻辑与第三方私有 context）。

**问题**: 状态表面按中间件签名分裂成两侧，消费者必须知道数据写在哪一边，
同一数据存在双份实现与漂移风险：

- http.Handler 级中间件（`TrustedProxies.Middleware`、
  `rs.HTTPMiddleware`、`RequestLogger`）只能写 `r.Context()`，且
  `trusted_proxy.go:141-163` 走的是**第三方包** `peertrust.WithRequestInfo`
  的私有 key——`request_url.go:22` 的 `BaseURL` 经
  `ForwardedHeadersTrusted` 读同一份数据，与其它状态完全不同的通道；
- HandlerContext 级中间件（tenant、idempotency）写值袋/换 writer；
- 最典型的分裂后果：`domains/tenant/middleware.go:137-149` 的
  `ResolveTenantID` 是 Host→Domain→Tenant 查询的**第二份完整副本**
  ——注释自述「the rate-limit rejection metric, which runs BEFORE Middleware
  … and so cannot read FromHandlerContext」，连 `Timeout/HostExtractor/
  IncludeSuspended` 旋钮都复制了一份；即使主链已解析过 tenant，拒绝路径
  仍会无条件再打两次存储查询。

**证据**: `interfaces/middleware/trusted_proxy.go:141-163`（http.Handler 级 +
  `peertrust.WithRequestInfo`）、`shared/security/peertrust/request.go:8-31`、
  `interfaces/ssoclient/rs/middleware.go:32-50`（`HTTPMiddleware` 写
  `claimsCtxKey`）、`interfaces/middleware/request_log.go:31-46`（http.Handler 级）、
  `interfaces/middleware/request_url.go:22`（经 peertrust 读）、
  `domains/tenant/middleware.go:104-131`（`ResolveTenantID` 重复查询，
  注释即证据）。

**拟议行为**: 改进 1 的注册表成为两侧共用的单一真相：

- 每请求的注册表实体挂在 `r.Context()` 上（`core.RequestStateOf(r)` 懒
  创建）；路由器的 `NewContext` 采纳同一实体，`HandlerContext` 的
  `Get/Set[T]` 只是它的视图——http.Handler 级中间件写入、
  HandlerContext 级中间件/处理器读取，同一类型化 key，无第二存储；
- `TrustedProxies`、`rs.HTTPMiddleware`、`RequestLogger` 改写注册表；
  `peertrust.RequestInfo` 的类型保留在 `peertrust`，私有 key
  （`requestInfoKey`）删除，`RealClientIP`/`ForwardedHeadersTrusted` 改为
  注册表读取（行为字节不变：未安装中间件时仍回落 RemoteAddr / 首跳信任）；
- tenant 解析收敛为单一实现：中间件解析结果写入注册表
  （`tenant.ResolvedKey`）；拒绝路径经注册表先查已解析结果，未解析才执行
  同一次查询——`ResolveTenantID` 的独立副本删除，旋钮单例化。

**验收检查**:
- 跨签名测试：http.Handler 级中间件写入 claims/peer-trust，
  HandlerContext 级处理器经同一 key 读到；反向（tenant 中间件写入、
  http.Handler 级拒绝路径经 `RequestStateOf(r)` 读到）同样成立；
- `domains/tenant/middleware.go` 中 `ResolveTenantID` 删除（或降为一行
  适配器）；测试证明拒绝路径在注册表已含解析结果时零存储调用（mock
  Store 计数断言），未含时才查询一次；
- `rg 'type requestInfoKey struct\{\}|ResolveTenantID' --type go` 零命中
  （保留的导出函数除外，如有）；
- `interfaces/adapters/routertest` 三适配器 conformance 全绿；
  `go test ./... -race` 与 `make ci` 通过；`docs/observability.md` /
  `docs/architecture/DIRECTORY_MAP.md` 中 `shared/core` 职责描述同步更新
  （"request-state registry + capture stack"）。

---

## 4. 交付顺序与回归边界

1. **改进 1**（注册表 + 迁移四个字符串 key）先行落地——纯增量，行为
   字节不变，单独提交；
2. **改进 3**（统一表面）依赖改进 1，先于改进 2——`SetResponseWriter`
   仍存在时迁移 http.Handler 级写入方；
3. **改进 2**（捕获栈）最后——删除 `SetResponseWriter` 接口方法、
   `InstallCapture`、`recordCaptureMissing` 与 `EventIdempotencyCaptureMissing`
   在同一提交内完成，三适配器 + `backgroundHandlerContext` 同步更新，
   无中间态。
4. 每一改进独立跑 `go build ./... && go vet ./...`、
   `go test -run 'TestMaintainability_|TestArchitecture_' .`，合入前
   `go test ./... -race` + `make ci`；审计事件删除同步更新
   `docs/observability.md`（AGENTS.md §5 合同同变更原则）。
