全局扫描完成。先说结论性上下文：`interfaces/adapters/` 只有两个薄适配器（`gin/adapter.go` 113 行、`echo/adapter.go` 116 行），实现的是 `shared/core/router.go` 中定义的 `Router` / `HandlerContext` / `MiddlewareFunc`（经 `interfaces/sso/aliases.go` 以 `sso.Router` 等别名暴露）。关键事实：**整个代码库没有任何生产代码使用这两个适配器**——`WithRouter` 的所有调用点（`cmd/sso-server/build_app_core.go:155`、`test/*` 若干处）都只传 `sso.NewStdRouter()`，适配器仅被自己的单元测试覆盖。在此基础上，以下 3 个方向是最高价值的：

## 方向一：补齐 HandlerContext 的"短路 + 响应捕获"能力，消除适配器下的安全功能静默失效

**问题**：`core.Router` 的中间件模型没有 abort 语义，且部分安全能力依赖对 `*core.Context` 具体类型的断言——一旦换用 gin/echo 适配器，这些能力**静默降级**，没有任何报错。

**证据**：
- `shared/core/router.go` 的 `ServeHTTP`：`for _, mw := range route.middlewares { mw(ctx) }; route.handler(ctx)`——中间件运行后**无条件**执行 handler，接口层面不存在 `Abort()`/"响应已写出"的查询原语。gin/echo 原生都支持 `c.Abort()`，但适配器无法映射。
- `interfaces/middleware/idempotency.go:74` 与 `interfaces/sso/server_token.go:125`：`if c, ok := ctx.(*core.Context); ok { c.SetResponseWriter(...) }`——token 幂等响应的捕获包装只在 StdRouter 下生效；在 `ginContext`/`echoContext` 下断言失败，**/token 的幂等重放捕获静默失效**。
- `interfaces/middleware/idempotency.go` 自身注释："because StdRouter runs all middlewares then the handler, middleware cannot prevent the handler from executing"——这是已知缺陷的自述。
- 附带症状：`middleware.Auth`（`interfaces/middleware/middleware.go`）写 401 后 handler 仍会执行，存在双重写响应风险。

**为什么需要**：AGENTS.md 明确把"并发重试在宽限窗口内幂等"列为 wire 契约，且整个安全模型建立在"错误响应字节一致"（oracle-safe）之上。当前接口把响应捕获、短路拒绝这类安全原语漏在 `HandlerContext` 之外，导致"同一 SDK 换一个路由后端就丢失安全能力且无感知"。补齐（如 `SetResponseWriter` 入接口、`Aborted()/Written()` 查询、中间件短路返回约定）是适配器与 StdRouter 安全等价的前提，也是未来写"拒绝型"中间件（401/403 前置拦截）的基础设施。

## 方向二：建立 Router 后端的"行为一致性"测试门（conformance suite），让跨后端字节一致成为可执行约束

**问题**：同一套 handler 挂在三个后端上会得到不同的线上行为，且目前没有任何测试或文档约束这些差异；随着路由面扩张（当前约 200 条路由），差异只会扩大。

**证据**：
- 404 语义：`StdRouter` 用 `http.NotFound`（纯文本）；gin 默认 404 文本/JSON 均不同；echo 返回 `{"message":"Not Found"}` JSON——方法不匹配时 StdRouter 与 gin 是 404、echo 是 405。
- Bind 语义：`core.Context.Bind` 仅 JSON（`shared/core/router.go`）；gin 适配器用 `ShouldBindJSON`；echo 用 content-type 感知的 `Context.Bind`——`interfaces/sso/server_login.go`、`server_setup.go`、`interfaces/admin/lifecycle.go` 等 9 处 `ctx.Bind` 调用点在换后端后解析行为不一致（OAuth 绑定走 `oauthwire.BindParams` 读裸请求所以幸免，但这更说明其余 handler 是漏网的）。
- 中间件时序：`StdRouter` 在注册时快照中间件；两个适配器的 `wrapHandler` 在**请求时**读取 `g.middlewares`——注册后调用 `Use()` 会影响已注册路由，且并发 `Use()`/`ServeHTTP` 对裸 slice 是数据竞争。
- 门控弱化：`shared/core/router.go` 中 `GatedRouter` 文档自述——非 StdRouter 后端退回 handler 包装，"a global middleware on THAT router could still observe a gated-off request"，即 CIBA/CAEP/federation/admin/branding 热重载门控在适配器下丢失"与从未注册字节一致"的性质。
- 适配器测试（`adapter_test.go` 各 12/11 个用例）全是 happy path，无一处校验 404/405/绑定/门控/中间件顺序。

**为什么需要**：AGENTS.md 把"代码/门与文档/契约不一致时满足更严格契约"和 wire 契约当作回归边界；仓库已有先例——`permissionstest.ConformanceSuite` 强制每个权限后端通过。Router 后端是同一性质的接口族，应当有 `routertest` 级别的对照套件（同一路由表跑三个后端断言响应字节、状态码、中间件执行序、门控行为），否则适配器的存在本身就是持续漂移源，且任何"新增 405/HEAD/OPTIONS/尾部斜杠"的路由行为改动都会无人值守地放大三端差异。

## 方向三：把适配器从"演示代码"升级为正式交付路径——真实嵌入集成与端到端验证

**问题**：适配器是 SDK"可嵌入"核心卖点（AGENTS.md §1：embeddable OAuth 2.0/OIDC SSO SDK）的载体，但现状是零生产引用、零 e2e 覆盖、无嵌入示例，属于"有接口无交付路径"的状态；`interfaces/ssoclient` 等 SDK 面已有多层集成测试，唯独适配器层没有。

**证据**：
- `grep NewGinRouter/NewEchoRouter` 全库仅命中 `interfaces/adapters/` 自身及测试；`WithRouter` 的生产调用点（`cmd/sso-server/build_app_core.go:155`）只传 `NewStdRouter()`。
- `docs/architecture/DIRECTORY_MAP.md` 将 `adapters` 与 `grpcserver`、`interfaces/sso` 并列为 Server API 组成部分，但 `test/`（`package ssotest`）的 e2e 套件（`TestE2E`、region/fapi/geo 等）全部基于 StdRouter 构建，从未有 `sso.NewServer(WithRouter(ginadapter.NewGinRouter()))` 跑通完整流程的用例。
- 上文方向一/二指出的所有问题（幂等捕获失效、404 差异、门控弱化）正是因为没有一条真实使用路径迫使它们被暴露和修复。

**为什么需要**：作为产品，"嵌入任意 Web 框架"是 SDK 相对独立 sso-server 的差异化价值；当前任何宣称"支持 gin/echo 嵌入"的文档/营销都无验证支撑。高价值动作是：至少把一个适配器接入 `test/` 的 e2e 流程（同一路由表、同一断言跑通授权码/刷新/DPoP 等核心流程），补一个最小可运行的嵌入示例（gin 与 echo 各一），并让 CI 覆盖它——这一步会立刻暴露方向一、二的真实缺陷，把适配器从"可能漂移的死代码"变成"被契约约束的正式能力"，同时为后续扩展适配器家族（chi/fiber/httprouter 等）或 HTTP 中间件生态（OAuth2 资源服务器中间件）建立可复用的验证基线。

三个方向的依赖关系：方向一是安全底线（先修静默失效），方向二是回归约束（防止再漂移），方向三是产品化验证（让前两者有真实抓手）。若只做一件，优先方向一——它是当前唯一会造成"生产环境安全功能无提示失效"的缺陷。
