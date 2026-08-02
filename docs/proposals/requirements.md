All evidence gathered. Note: the analysis doc's directions 1 and 2 are already largely implemented (the adapters now have `Abort/Aborted/Written/SetResponseWriter`, `RegisterGated` + `GatedRegistrar`, and a 474-line `routertest` conformance suite wired into all three backends). Direction 3 — the formal delivery path — remains completely unaddressed. Here is the requirements specification.

# interfaces/adapters 需求规格：方向三——从演示代码升级为正式交付路径

> 前置事实核对（2025 扫描）：方向一（`Abort/Aborted/Written/SetResponseWriter` 入 `HandlerContext` 门面，见 `interfaces/adapters/gin/adapter.go:158-186`、`echo/adapter.go:172-190`）与方向二（`routertest.ConformanceSuite`，474 行，`gin/conformance_test.go:12-17`、`echo/conformance_test.go:12-17` 已挂钩）**均已落地**。方向三仍是空白：全库零生产引用、零 e2e 覆盖、无嵌入示例、无 CI 门。以下 3 项改进均针对该空白。

## 改进一：testkit 增加 router 后端参数，建立"同一 e2e 断言 × 三后端"矩阵

**名称**：适配器矩阵端到端验证（router-backend e2e matrix）

**问题**：适配器是 SDK 可嵌入卖点的载体，但整个 `test/`（`package ssotest`，200+ e2e 文件）没有任何用例在 gin/echo 后端下跑通过完整协议流程。测试基建连注入路由后端的入口都不存在——适配器路径的"可用性"完全没有验证，任何宣称支持 gin/echo 嵌入的说法都无测试支撑。

**证据**：
- `test/testkit/testkit.go:105-127`：`NewServer(opts ...Option)` 构造 `sso.NewServer(...)` 时**没有** `WithRouter`；option 类型全集仅为 `WithIssuerName/WithClient/WithUser`（`testkit.go:69-89`）。
- `interfaces/sso/server_routes.go:109-110`：`mountMiddleware()` 中 `if s.router == nil { s.router = NewStdRouter() }`——即使调用方传了适配器，也没有任何断言/校验强制该路径被验证；不传则**静默回退**。
- `test/` 中全部 16 处 `WithRouter` 调用（`region_residency_access_test.go:87`、`fapi_profile_test.go:53`、`geo_login_test.go:52`、`netpolicy_handler_test.go:42/220` 等）无一例外传 `sso.NewStdRouter()`。
- 仓库已有现成先例：`test/backendsemantics/backends_test.go` 的"同一语义套件循环跑多后端"模式（`for _, b := range authCodeBackends`），可原样复用为矩阵结构。

**预期行为**：
1. `test/testkit/testkit.go` 新增 `WithRouter(r sso.Router) Option`，`NewServer` 将其透传给 `sso.NewServer`。
2. 新增 `test/router_backend_matrix_test.go`：抽取核心协议流程断言（authorization code + PKCE 全流程、refresh rotation、DPoP bound token、未知路径 404 字节），对 `StdRouter` / `NewGinRouter()` / `NewEchoRouter()` 三个后端分别构建 harness 执行，断言响应字节一致。
3. 矩阵测试挂在 `TestE2E` 同级，纳入 `make test-e2e`（`Makefile:259-260`）。

**验收标准**：
- `go test ./test/ -run 'TestRouterBackendMatrix' -v` 三后端全绿，且 404/`token` 错误响应字节与 StdRouter 后端逐字节相同。
- `go test ./test/ -race -run 'TestRouterBackendMatrix'` 无数据竞争（含并发 `Use()` 场景）。
- `make ci` 通过；`testkit.go` 的 `WithRouter` 已有至少一个适配器调用点（矩阵测试本身）。

## 改进二：新增 gin/echo 框架嵌入示例，成为可运行、可编译的正式交付物

**名称**：框架嵌入示例（embed-gin / embed-echo）

**问题**："嵌入任意 Web 框架"是 SDK 相对独立 sso-server 的差异化价值，但 `docs/examples/` 下没有任何一个示例通过 `WithRouter` 挂载 gin/echo——嵌入者没有任何可抄写的真实代码路径，且 `go build ./docs/examples/...`（`Makefile:145-146`）对适配器零覆盖，适配器一旦在真实用法中暴露问题（如与 embedder 自有路由/中间件冲突）将无人发现。

**证据**：
- `grep -rn "NewGinRouter\|NewEchoRouter" --include="*.go"` 全库仅命中 `interfaces/adapters/` 自身（含测试）；无任何 `docs/examples/` 或 `cmd/` 引用。
- `docs/examples/basic/main.go:79` 与 `docs/examples/playground/main.go:183`：仅有的两个显式 `WithRouter` 示例均传 `sso.NewStdRouter()`。
- `docs/examples/embedded-app/main.go`：唯一"嵌入"示例走的是 `ssoclient/local` 进程内模式，自建 `http.ServeMux`（`main.go:68`），**完全不经过** `WithRouter`/适配器——"嵌入"概念与"框架路由适配"两条路径在示例层面脱节。
- 适配器单元测试（`gin/adapter_test.go`、`echo/adapter_test.go`）仅验证接口行为，从未验证"与 embedder 自有 gin 路由共存于同一 engine"这一真实嵌入场景。

**预期行为**：
1. 新增 `docs/examples/embed-gin/main.go` 与 `docs/examples/embed-echo/main.go`（复用 `docs/examples/appcore` 的配置组装）：embedder 自有 `gin.Engine`/`echo.Echo` 上同时挂 `sso.NewServer(sso.WithRouter(adapter))` 与至少一条 embedder 业务路由（如 `/hello`）。
2. 每个示例含注释说明：适配器默认的 404 归一化保证、`RegisterGated` 门控语义、以及 embedder 在构造后覆写 `engine.NoRoute`/`HTTPErrorHandler` 的后果（对应 `gin/adapter.go:30-40`、`echo/adapter.go:40-55` 的文档化行为）。
3. `docs/architecture/DIRECTORY_MAP.md:17`（adapters 与 grpcserver、interfaces/sso 并列的 Server API 行）补一句交付语义：受支持后端 = std/gin/echo，见新示例。

**验收标准**：
- `make examples`（`go build ./docs/examples/...`）编译通过——新增示例自动纳入该门。
- 示例可运行：手动冒烟（或示例自带 `Example*` 测试）跑通一次 authorization-code 流程 + embedder 自有路由 200 响应。
- 代码审查确认示例使用公共构造器 `NewGinRouter()`/`NewEchoRouter()`（非内部 API），且未使用 `WithFrameworkNotFound`（保持字节一致默认）。

## 改进三：建立适配器交付契约文档 + CI 检查门，防止能力声明与验证脱节

**名称**：适配器交付契约与防退化检查（adapters contract + CI gate）

**问题**：适配器被声明为 Server API 的正式组成部分，但"支持 gin/echo 嵌入"这一声明没有文档化契约、没有 feature-matrix 条目、没有独立 CI 检查——它是"有接口无交付路径"的状态：conformance 套件与示例是否在 CI 中运行、适配器 API 面是否被回退，全靠 `go test ./...` 顺带兜底，无人强制。

**证据**：
- `docs/architecture/DIRECTORY_MAP.md:17` 将 `adapters` 与 `grpcserver`、`interfaces/sso` 并列为 Server API，但全文无一处说明受支持后端、一致性保证或退出选项。
- `docs/feature-matrix.md`（能力矩阵表，`feature-matrix.md:45-63` 的 `sdk` 列）无任何"框架嵌入"能力行；`docs/agent-os/CHECKS_REGISTRY.md` 无 adapters 条目。
- `Makefile:244` 的 `ci` 目标（`fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract capabilities-check sdk-surface-check profiles-evidence`）无任何适配器专属检查；`checks/` 下 `route_contract.py` 等 14 个检查无一涉及 `interfaces/adapters/`。
- 对比项：`permissions.Provider` 有 `permissionstest.ConformanceSuite` 且被 AGENTS.md §4 明文强制；`Router` 后端的 `routertest` 套件已存在（`interfaces/adapters/routertest/conformance.go`）但**无任何文档或检查把它列为契约**。

**预期行为**：
1. 新增 `docs/adapters.md`（或并入 config-reference 的 SDK 章节），定义正式交付契约：受支持后端清单（std/gin/echo）、404/405/尾部斜杠的字节一致归一化、`WithFrameworkNotFound` 的退出语义（"放弃字节一致保证"）、`GatedRegistrar` 门控行为、`SetResponseWriter/Aborted/Written` 捕获原语。
2. `docs/feature-matrix.md` 新增一行"框架嵌入（gin/echo）"（`sdk` 列），链接该契约文档与两个示例。
3. `checks/` 新增 `adapters_check.py` 并注册进 `CHECKS_REGISTRY.md`，纳入 `Makefile` 的 `ci` 目标：验证 (a) `routertest` conformance 套件与改进一的矩阵 e2e 存在且可运行；(b) `docs/examples/embed-*` 可编译；(c) `docs/adapters.md` 存在且列出全部三个受支持后端——任一缺失即 CI 失败。

**验收标准**：
- `make ci` 全绿且输出包含 adapters 检查条目（`python cli.py adapters` 可独立运行）。
- `docs/adapters.md` 覆盖上述 5 项契约；feature-matrix 有对应能力行。
- 回归演示：人为从 `gin/adapter.go` 删除 `RegisterGated`（或从 `routertest` 移除一个场景）后 `make ci` 失败——证明该门是防退化的，而非纸面声明。

三项改进的依赖关系：改进一提供验证抓手（矩阵 e2e 立即暴露方向一/二遗留差异），改进二提供真实用法路径（embedder 场景），改进三把前两者固化为契约与门。若按优先级只做一项，改进一——它是当前唯一能把适配器从"死代码"变成"被测试约束的正式能力"的动作。
