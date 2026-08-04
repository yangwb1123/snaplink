# Requirements Spec: Router 后端行为一致性测试门（Conformance Suite）

> Scope: module `interfaces/adapters` (gin/echo), interface owner `shared/core`
> (`Router`/`HandlerContext`), expansion direction 2 of
> [interfaces-adapters-analysis.md](interfaces-adapters-analysis.md).
> Goal: make cross-backend byte consistency an executable constraint, mirroring
> the `permissionstest.ConformanceSuite` precedent
> (`domains/permissions/permissionstest/conformance.go`).
> Non-goals: Direction 1 (HandlerContext 短路/响应捕获原语) and Direction 3
> (e2e 嵌入验证) are separate specs; this suite must be written so it does not
> depend on them, but must fail loudly if an adapter regresses them (e.g.
> `Abort()` semantics are part of the suite's middleware-order scenarios).

## 1. 建立 `routertest.ConformanceSuite`：同一路由表跑三个后端，断言字节级一致

**Name**: `routertest.ConformanceSuite` — shared behavioral suite for every
`Router` backend.

**Problem**: 没有任何机制约束"同一套 handler 挂在不同后端产生相同线上行为"。
StdRouter 的行为只有 `shared/core/router_test.go` 的单后端测试锁定；gin/echo
适配器的测试全是 happy path（`interfaces/adapters/gin/adapter_test.go`、
`interfaces/adapters/echo/adapter_test.go` 各 11 个用例，全部是
GET/POST/DELETE/PATCH/Query/Redirect/SetGet/Group/计数类，无一覆盖
404/405/方法不匹配/门控/中间件顺序）。路由面约 200 条路由，任何
405/HEAD/OPTIONS/尾部斜杠行为的改动都会无人值守地放大三端差异。

**Evidence**:
- `shared/core/router.go` — `Router` 接口族；`StdRouter.ServeHTTP` 对未匹配
  路由（含方法不匹配）统一 `http.NotFound(w, req)`（纯文本 404）。
- `shared/core/router_test.go:188` `TestStdRouterMethodMismatchFallsThrough`、
  `:204` `TestStdRouterNotFound` — 单后端锁定，无跨后端对比。
- `interfaces/adapters/gin/adapter_test.go`、`interfaces/adapters/echo/adapter_test.go`
  — 11+11 个用例，无一处断言 404/405/绑定/门控/中间件顺序。
- 先例：`domains/permissions/permissionstest/conformance.go` `ConformanceSuite`
  （"Backend authors … hook their factory into ConformanceSuite to lock the
  equivalence operators rely on"），已由 memory/sqlite/postgres/redis 四后端接入
  （`domains/permissions/memory_conformance_test.go:16` 等）。AGENTS.md §3
  把"代码/门与文档/契约不一致时满足更严格契约"定为回归边界。

**Proposed behavior**:
- 新增测试专用包 `shared/core/routertest`（与 `permissionstest` 同构；
  `shared/core` 不 import 任何 Snaplink 包，故该包可被适配器测试合法导入，
  且不污染生产包）：`ConformanceSuite{Factory func(*testing.T) Router}.Run(t)`。
- 套件内部使用固定路由表 + 场景矩阵，对每个后端断言**响应字节**（状态码、
  body 逐字节、关键 header），而非仅状态码：
  - 五种方法的路由分发、路径参数、Query；
  - 未知路径 → 与 `http.NotFound` 字节一致（`text/plain`、"404 page not found"）；
  - 方法不匹配 → 404（锁定 StdRouter 语义，见决策 2）；
  - HEAD 请求打到 GET 路由 → 不自动降级为 GET，与 StdRouter 一致返回 404；
  - 中间件执行顺序 + `Abort()` 语义（中间件写 401 后 `Abort()`，handler 不得
    执行、响应不得双重写入）；
  - `Group` 前缀与中间件继承；
  - 门控关闭的路由 → 与"从未注册"字节一致（见决策 3）。
- 接入点：`shared/core/router_test.go`（StdRouter 自身）、
  `interfaces/adapters/gin/conformance_test.go`、`interfaces/adapters/echo/conformance_test.go`
  各一个 `TestXxxRouter_Conformance` 调用。

**Acceptance check**:
- `routertest.ConformanceSuite` 存在且 `go test ./...` 跑通；StdRouter、gin、
  echo 三后端全部通过，任何新后端（chi/fiber/httprouter）不接套件即无法声称
  支持 `sso.WithRouter`。
- 场景断言为字节相等（`rec.Body.String()` 全等 + header 比对），不是
  `strings.Contains` 或状态码单独比对。
- 基线验证：套件先于修复落地，echo 的"方法不匹配"与"未知路径"场景当前
  必须失败（证明门有效），修复后转绿。

## 2. 锁定 404/405/未匹配语义：适配器默认输出与 `http.NotFound` 字节一致

**Name**: 未匹配响应归一化 — adapters 显式安装 not-found/method-not-allowed
处理，使三端字节一致成为默认而非巧合。

**Problem**: 同一路由表在三个后端上产生不同 wire 字节：方法不匹配时
StdRouter 与 gin 是 404，echo 是 405；404 body 上 StdRouter/gin 是纯文本
"404 page not found"，echo 默认返回 JSON `{"message":"Not Found"}`。当前
gin 与 StdRouter 的一致是框架默认值巧合（gin `HandleMethodNotAllowed=false`），
echo 则直接违反；没有任何代码或测试把"未匹配 = 404 纯文本"钉成契约。

**Evidence**:
- `shared/core/router.go` `StdRouter.ServeHTTP` — 未匹配（含方法不匹配）统一
  `http.NotFound`；`shared/core/router_test.go:188` `TestStdRouterMethodMismatchFallsThrough`
  注释 "A POST to a GET-only route matches no route → 404"。
- `interfaces/adapters/echo/adapter.go:20` `NewEchoRouter` — `echo.New()`
  默认 `HTTPErrorHandler` 输出 JSON `{"message":"Not Found"}`，且方法不匹配
  返回 405 `{"message":"Method Not Allowed"}`（echo 默认
  `MethodNotAllowedHandler`）；构造函数未安装任何
  not-found/method-not-allowed 覆盖。
- `interfaces/adapters/gin/adapter.go:20` `NewGinRouter` — `gin.Default()` 默认
  404 body "404 page not found"、方法不匹配 404，与 StdRouter 恰好一致，但
  无显式配置/测试锁定，换 gin 版本即可能漂移。
- `interfaces/adapters/gin/adapter_test.go`、`interfaces/adapters/echo/adapter_test.go`
  — 无任何未匹配路径用例。

**Proposed behavior**:
- 两个适配器的构造函数默认安装显式 not-found handler：输出与
  `http.NotFound` 字节一致（状态 404、`Content-Type: text/plain`、body
  "404 page not found"），并覆盖方法不匹配路径使其同为 404（echo 侧安装
  `MethodNotAllowedHandler` 返回 404 而非 405；gin 侧保留默认并加测试钉住）。
- 提供构造函数选项（如 `WithFrameworkNotFound()`）供嵌入既有应用、需要框架
  原生 404 的场景显式退出；默认必须是字节一致版本，保证
  `sso.WithRouter(adapter)` 与 `NewStdRouter()` 的线上响应可互换。
- 该语义由决策 1 的套件场景"未知路径/方法不匹配/HEAD"强制，任何新后端
  必须在套件中证明同一性质。

**Acceptance check**:
- 决策 1 套件中"未知路径""方法不匹配""HEAD on GET route"三个场景在 echo
  后端当前失败、修复后与 StdRouter/gin 字节全等。
- `go test ./interfaces/adapters/... ./shared/core/...` 全绿；`go vet ./...`
  干净。
- 回归门：删除适配器中的 not-found 安装代码，套件立即红（证明该行为是
  被测试强制而非依赖框架默认）。

## 3. 钉住中间件快照语义 + 竞态安全，并把门控提升为适配器可实现的第一类能力

**Name**: 注册期中间件快照 + 公开门控注册接口，恢复适配器下
"gate-off = 从未注册"的字节一致性质。

**Problem**: 两个适配器的 `wrapHandler` 在**请求时**读取 `g.middlewares`，
而 StdRouter 在**注册时**快照（`registerGated` 里
`middlewares: append([]MiddlewareFunc{}, r.middlewares...)`）——于是：
(a) 适配器上注册路由后调用 `Use()` 会改变已注册路由行为，与 StdRouter 语义
不一致；(b) 并发 `Use()`/`ServeHTTP` 对裸 slice 是数据竞争；(c) 门控在
适配器下退化为 handler 包装（`GatedRouter` 对非 `gatedRegistrar` 后端走
`GateHandler` 分支），全局中间件（如 Tracing）仍会在被门控关闭的请求上运行
并盖 header，破坏"与从未注册字节一致"性质——该性质对 StdRouter 有专门测试，
对适配器既无实现也无测试。

**Evidence**:
- `interfaces/adapters/gin/adapter.go` `wrapHandler`（:74）与 `Use`（:55）—
  `for _, mw := range g.middlewares` 在请求时迭代；`g.middlewares = append(...)`
  无锁。
- `interfaces/adapters/echo/adapter.go` `wrapHandler`（:88）与 `Use`（:66）—
  同上。
- `shared/core/router.go` `StdRouter.registerGated`（:224 附近）— 注册时快照
  中间件；`gatedRegistrar`（:368）— 未导出接口，文档明言 "a custom Router
  (wired via sso.WithRouter, e.g. an echo/gin adapter) never implements this,
  and GatedRouter falls back to handler-wrapping for it"；`GatedRouter.register`
  （:416）— `if gr, ok := g.inner.(gatedRegistrar); ok {…}` 否则 `GateHandler`
  包装。
- `shared/core/router_test.go:443` `TestGatedRouter_LiveToggleControlsReachabilityByteIdenticalTo404`
  与 `:500` `TestGatedRouter_GateOffSkipsGlobalMiddleware_NoHeaderLeak` —
  性质测试目前只对 StdRouter 成立。

**Proposed behavior**:
- 两个适配器改为注册期快照：`wrapHandler` 创建时复制当前 `g.middlewares`
  切片（与 StdRouter 语义对齐：注册后 `Use()` 不影响已注册路由）。
- 消除数据竞争：`Use`/注册/ServeHTTP 对中间件切片加互斥或写时复制；
  `go test -race` 下并发 `Use()` + `ServeHTTP` 无报告。
- 将门控注册提升为公开契约：在 `shared/core` 导出等价能力（如公开
  `GatedRegistrar` 接口：`RegisterGated(method, path string, handler HandlerFunc,
  live func() bool)`），gin/echo 适配器实现之——在各自的路由包装里把
  `live()` 求值放在**该路由自身中间件之前**（gin 用路由级 handler 前置判断；
  echo 用路由级 middleware 前置判断），使门控关闭时全局中间件不再运行。
- `GatedRouter` 改为断言公开接口；套件增加门控场景：gate-off 请求的响应与
  `http.NotFound` 字节一致，且 `Use()` 注册的"打 header"中间件在该请求上
  零副作用（复刻 `TestGatedRouter_GateOffSkipsGlobalMiddleware_NoHeaderLeak`
  于三个后端）。

**Acceptance check**:
- 新增测试：注册路由后 `Use()`，已注册路由行为不变（三后端一致）；该测试
  当前在 gin/echo 上失败、修复后通过。
- `go test -race ./interfaces/adapters/... ./shared/core/...` 通过，含一个
  并发 `Use()`+`ServeHTTP` 用例（race detector 干净）。
- 门控场景三后端字节全等（gate-off = 404 纯文本、无全局中间件 header）；
  当前 gin/echo 失败（中间件 header 泄漏）、修复后通过。
- `go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' .`
  全绿；`make ci` 通过（新增包不超过文件/目录/扇出预算，`routertest` 归入
  `shared` 层，`layerName()` 无需新增豁免）。

## 文件与验证计划

### Create
```text
shared/core/routertest/conformance.go — 共享行为套件（Factory + Run，场景矩阵）
shared/core/routertest/conformance_test.go — 套件自身冒烟（用 StdRouter 验证套件有效）
interfaces/adapters/gin/conformance_test.go — gin 后端接入
interfaces/adapters/echo/conformance_test.go — echo 后端接入
```

### Modify
```text
interfaces/adapters/gin/adapter.go — not-found 归一化；注册期快照 + 锁；实现公开门控注册
interfaces/adapters/echo/adapter.go — 同上
shared/core/router.go — gatedRegistrar 提升为公开接口，GatedRouter 断言之
interfaces/adapters/gin/adapter_test.go — 补 Use-after-register 语义与并发用例
interfaces/adapters/echo/adapter_test.go — 同上
```

### Verification
```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./shared/core/... ./interfaces/adapters/... -race
go test ./... -race
make ci
```
