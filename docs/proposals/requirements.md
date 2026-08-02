需求规格已产出：`docs/auto/interfaces-cors-requirements.md`（全部证据已对照源码逐条核实）。

## 三个改进决策（均为证据背书）

**## Decision 1 — `interfaces/cors` 可热替换策略载体（PolicyStore + DynamicMiddleware）**
- 问题：`Middleware()` 构造时经 `buildConfig` 把策略烘焙进闭包（cors.go:84/172），`sso.corsPolicy` 是 boot-only 指针（sso_protocol.go:139），SPA 域名变更必须重启
- 证据对照：`ratelimit.PolicyStore` + `DynamicMiddleware`（middleware.go:145-167）与 `SetRateLimitPolicy`（server_routes.go:415）已是现成范式
- 验收：镜像 `rate_limit_hotreload_test.go` 的即时替换 + 未启用返回 `false` 测试

**## Decision 2 — `SetCORSPolicy` 接入 SIGHUP 热重载，`security.cors` 入契约文档**
- 问题：`config/reload/reload.go:98-102` 可热应用块只有 rate_limit 一类；`toPolicy()`（config_load.go:472）是纯函数却未接线；Hot Reload 表（config-reference.md:433）与 Security 表均无 CORS 行
- 行为：沿用"整块一次重建、diff 驱动、未启用落入 `ignored_requires_restart`"的 rate_limit 契约
- 验收：reload_test.go 模式用例 + 两处表格行存在

**## Decision 3 — origin 判定收敛为单一实现，登录 CSRF 门复用**
- 问题：`isOriginAllowed`（origin_validation.go:103-124）线性扫描 + 硬编码 `"*"`，重写 `corsConfig.originAllowed`（cors.go:112，map + `OriginWildcard`）；`rejectDisallowedLoginOrigin`（server_login.go:166）无视 `PathOverrides`——两个执行点可分叉
- 行为：导出 `Policy.OriginAllowed(origin, path)`（含最长前缀 override 语义），删除 sso 侧重复实现，门显式声明"共享判定、默认策略语义"并补 `test/` 联动集成测试
- 验收：cors 包单测 + sso 既有用例改走共享判定原样通过 + 新 e2e 覆盖 PathOverrides×登录门一致性

规格内注明约束：`interfaces/sso` 60 文件上限（新代码并入既有文件）、`config/` 文件数冻结，方向二/三明确列为非目标。
