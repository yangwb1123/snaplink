# interfaces/cors 需求规格：方向一（CORS 策略热更新 + origin 判定单一事实来源）

> 来源：[docs/auto/interfaces-cors-analysis.md](interfaces-cors-analysis.md) 方向一。
> 范围：`interfaces/cors`、`interfaces/sso` 的接线（`corsPolicy`、登录 CSRF 门）、
> `config`/`config/reload` 的 `security.cors` 热更新、契约文档。方向二（配置面完整性）
> 与方向三（可观测性）不在本规格范围内，另行立项。
> 约束：`interfaces/sso` 处于 60 文件上限，新增代码并入既有文件；`interfaces/cors`
> 位于 `interfaces` 层，只允许 import `infrastructure` 及以下层级。

## Decision 1：`interfaces/cors` 提供可热替换的策略载体（PolicyStore + DynamicMiddleware）

**问题**：CORS 策略在 `Middleware()` 构造时被一次性烘焙进闭包（`buildConfig` 预计算
全部头字符串与 origin map），运行期完全不可变；`sso.Server.corsPolicy` 是 boot-only
指针、无 setter。SPA 域名轮换、新增 staging 前端域都必须整机重启——而同一中间件栈里
的 rate_limit 早已支持运行期替换，CORS 是"改错代价高"（放行过宽扩 CSRF 面、过窄即
线上故障）的配置，却独缺热更新通道。

**证据**：
- `interfaces/cors/cors.go:84` `buildConfig`（注释明言 "built once at Middleware
  construction"）；`interfaces/cors/cors.go:172` `Middleware(p Policy)` 构造时闭包
  捕获 `defaultCfg`/`overrideCfgs`，逐请求无重算机会。
- `interfaces/sso/sso_protocol.go:139` `corsPolicy *cors.Policy`——boot-only，无
  setter；`interfaces/sso/origin_validation.go:21-22` `WithCORS` 是唯一写入点。
- `interfaces/sso/server_routes.go:451-452` `cors.Middleware(*s.corsPolicy)(inner)`
  在 `Handler()` 挂载时一次成型。
- 对照组：`interfaces/ratelimit/middleware.go:145-167` `PolicyStore`
  （`atomic.Pointer` 的 `Set`）+ `DynamicMiddleware`（逐请求读活策略），
  `interfaces/sso/server_routes.go:415` `SetRateLimitPolicy` 即"config/reload
  SIGHUP 热替换"的挂点（server_routes.go:374 注释）。

**拟议行为**：
1. 在 `interfaces/cors` 新增 `PolicyStore`（`NewPolicyStore(initial Policy)` +
   `Set(p Policy)`，原子替换）与 `DynamicMiddleware(store)`；逐请求经
   `resolveCORSConfig` 解析路径覆盖并取活策略，行为与静态 `Middleware` 完全一致。
2. 静态 `Middleware(p Policy)` 保留为薄封装（内部等价于
   `DynamicMiddleware(NewPolicyStore(p))`），向后兼容，SDK 直连调用方零改动。
3. 空策略（无 `AllowedOrigins` 且无 `PathOverrides`）仍是 identity 中间件——
   "未启用即零开销"的既有契约不因热更新而改变。

**验收检查**：
- `interfaces/sso` 新增镜像 `rate_limit_hotreload_test.go` 的测试：
  `SetCORSPolicy`（Decision 2）替换后，下一次请求立即使用新 origin 集合/新头列表；
  启动时未 `WithCORS` 的服务器调用返回 `false` 且不 panic。
- `go test -run 'TestCORSE2E_|TestCORS_' ./interfaces/... ./test/` 全部通过
  （既有静态路径语义不变）。
- `go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' .`
  通过（`interfaces/cors` 与 `interfaces/sso` 不超文件/函数预算）。

## Decision 2：`Server.SetCORSPolicy` 接入 SIGHUP 热重载，`security.cors` 入契约文档

**问题**：`config/reload.Reloader` 的 SAFE 子集只有 `logging.level`、
`security.rate_limit.*`、`feature_gates.*` 三项；`security.cors` 的变更只会落进
`ignored_requires_restart` 被静默搁置。`CORSConfig.toPolicy()` 是纯函数、无状态
（不持有 limiter 等资源），热替换成本与 rate_limit 同构却未接线。同时
`docs/config-reference.md` 的 Security 表与 Hot Reload 表均无 `security.cors` 行，
违反 AGENTS.md "config knob → docs/config-reference.md" 契约。

**证据**：
- `config/reload/reload.go:98-102` 可热应用块集合只含 `"/security/rate_limit"`；
  `config/reload/reload.go:149-190` `setRateLimitPolicy` hook 是唯一的策略类
  热替换通道；`config/reload/reload.go:290-302` 未登记的变更走
  `Res.Ignored`。
- `config/config_load.go:472` `CORSConfig.toPolicy()`——无副作用纯映射，天然可重放。
- `docs/config-reference.md:433` 起 Hot Reload (SIGHUP) 表：仅
  `logging.level` / `security.rate_limit.*` / `feature_gates.*` 三行；Security 表
  （63-70 行）列了 mtls/trusted_proxies/security_headers/rar_limits/scope_limit/
  max_token_bytes/client_registration_rate_limit，唯独缺 `security.cors`。

**拟议行为**：
1. `interfaces/sso` 新增 `SetCORSPolicy(p cors.Policy) bool`，语义镜像
   `SetRateLimitPolicy`：启动时未启用 CORS（`corsPolicy == nil`，无已挂载的
   中间件槽位）返回 `false`，变更落入 `ignored_requires_restart`；已启用则原子
   替换 Decision 1 的 `PolicyStore`。只允许"已启用策略内的数字/列表"热变，
   开/关 CORS 整体仍需重启（与 rate_limit 同契约）。
2. `config/reload` 将 `"/security/cors"` 加入可应用块：检测到
   `security.cors.*` 任一叶子变化即用 `toPolicy()` 重建一次并调用
   `SetCORSPolicy`（沿用 rate_limit 的"整块一次重建、diff 驱动"语义）。
3. 契约文档同步：`docs/config-reference.md` Security 表加 `security.cors.*` 行
   （逐字段映射到 `cors.Policy`，说明空 `allowed_origins` = 禁用、空字段回退
   默认头/方法列表），Hot Reload 表加 `security.cors.*` 行（注明整体
   enabled 开关仍需重启）。

**验收检查**：
- `config/reload/reload_test.go` 模式新增用例：改 `security.cors.allowed_origins`
  后 reload，结果 `applied` 含该键且后续请求按新策略发 CORS 头；未启用 CORS 的
  构建中同变更出现在 `ignored_requires_restart`。
- `docs/config-reference.md` 两处表格行存在且字段与 `CORSConfig`
  （config_admin.go:103）一一对应。
- `make ci`（含 config 校验）通过。

## Decision 3：origin 判定收敛为 `cors` 包单一实现，登录 CSRF 门复用同一判定

**问题**："某 origin 是否被允许"存在两套独立实现，安全语义可漂移：
`sso.isOriginAllowed` 用线性扫描 + 硬编码 `"*"` 字面量重写了一遍
`corsConfig.originAllowed`（map + `cors.OriginWildcard` 常量）；更关键的是
`rejectDisallowedLoginOrigin` 只查默认策略的 `AllowedOrigins`，完全无视
`PathOverrides`——若运维用 path override 放宽 `/.well-known/*`，中间件放行但登录门
仍 403（或未来任何通配语义调整：子域匹配、`null` origin 处理），两处执行点行为
分叉且无文档声明这是有意的纵深防御。CSRF 防护与 CORS 放行不一致是安全回归的
漂移点。

**证据**：
- `interfaces/sso/origin_validation.go:103-124` `isOriginAllowed`：for 循环线性
  扫描 + `allowed == "*"` 硬编码字面量，与
  `interfaces/cors/cors.go:112-117` `corsConfig.originAllowed`
  （map 查找 + `c.allowsWildcard`）实现分叉；`"*"` 在
  `interfaces/cors/consts.go:20` 已有 `OriginWildcard` 常量。
- `interfaces/sso/server_login.go:166-181` `rejectDisallowedLoginOrigin` 调
  `s.isOriginAllowed`，只触达默认策略，`PathOverrides` 不可见；全局 grep
  `origin_blocked` 仅此一处（server_login.go:174），无测试覆盖
  PathOverrides × 登录门联动（`test/cors_e2e_test.go` 无 override 用例）。

**拟议行为**：
1. `interfaces/cors` 导出一个判定入口，例如 `Policy.OriginAllowed(origin, path string) bool`
   （值接收者，内部复用 `buildConfig` + `resolveCORSConfig` 的最长前缀优先语义），
   中间件与所有调用方共用；`corsConfig.originAllowed` 降为其内部实现。
2. `interfaces/sso` 删除 `isOriginAllowed` 的线性扫描实现，改为委托
   `s.corsPolicy.OriginAllowed(origin, reqPath)`；`rejectDisallowedLoginOrigin`
   传入请求路径，并在 doc comment 显式声明语义："登录门与中间件共享同一判定；
   `/auth/login` 当前无 path override，因此等价于仅默认策略——若运维为登录路径
   配置 override，两处一致生效"。行为上登录 POST 路径（`/auth/login`）不受
   其他路径 override 影响，与现状兼容。
3. `interfaces/sso` 侧不再出现 `"*"` 字面量；通配语义（含未来子域匹配、`null`
   origin）只在一处演进。

**验收检查**：
- `interfaces/cors/cors_test.go` 新增 `OriginAllowed` 单测：精确匹配、通配、
  通配+凭据、路径 override 命中/未命中（最长前缀优先）。
- `interfaces/sso/origin_validation_test.go` 既有用例（含
  `non_matching_origin_blocked`）全部改走共享判定后原样通过；
  `login_early_gate_headers_test.go` 的 403 + no-store + `iss` 契约不变。
- `test/` 层新增联动集成测试（并入 `test/cors_e2e_test.go`）：默认策略仅放行 A、
  `PathOverrides["/auth/login"]` 放行 B 时——B 的 `POST /auth/login` 同时拿到
  CORS 头且不被 403；C（均未放行）无 CORS 头且 403；`GET /.well-known/jwks.json`
  from B 拿到 override 头（门不介入）。
- `go test ./... -race` 通过。

## 验证计划

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/cors/ ./interfaces/sso/ -run 'TestCORS|TestOrigin|TestLogin|TestSetCORS' -count=1
go test ./config/reload/ -run TestReload -v
go test ./test/ -run TestE2E -v
make ci
```

实施前置检查：`interfaces/sso` 文件数冻结在 60，新增 setter/测试并入既有文件
（如 `server_routes.go`/`origin_validation.go`）；`config/` 目录文件数亦冻结，
`security.cors` 热重载逻辑并入 `config/reload/reload.go` 既有 hook 结构。
