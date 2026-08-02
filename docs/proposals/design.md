设计文档已产出：`docs/auto/interfaces-cors-design.md`。三个 `##` 决策节各含 API surface、存储模型、失败模式、可击穿点，外加约束基线、跨决策组合契约、验收映射与风险清单。

核实源码后，设计在规格之上做了几处证据强制的修正，均已在文档第 0 节和对应决策中标注：

1. **字段必须替换而非新增** — `sso_protocol.go` 实测 499 行（门限 `>500` 即失败，仅 1 行余量），`corsPolicy *cors.Policy` 必须换成 `corsStore *cors.PolicyStore`（净 0 行变化）。已确认 `corsPolicy` 只有 2 个生产读取点、无任何测试直接引用，替换安全。
2. **登录门必须读活策略**（D1×D3 组合契约）— 规格字面写 `s.corsPolicy.OriginAllowed(...)`；若门读 boot 指针，SIGHUP 热替换后中间件与门重新分叉——正是 D3 要消灭的漂移。设计落为 `s.corsStore.Get().OriginAllowed(origin, path)`，并新增组合测试锚。
3. **`enabled` 检查固定在 `applyCORS`**（reload 包）而非 cmd hook — 否则 `enabled:false` 时 store 存在、`SetCORSPolicy` 会成功 swap，"整体开关需重启"契约被击穿。
4. **`SetCORSPolicy` 落 `origin_validation.go`**（242 行，紧邻 `WithCORS`）而非规格示例的 `server_routes.go`（488 行，放不下）。
5. **附带修复一个潜在别名 bug** — 原 `WithCORS` 持有调用方 `&policy` 指针；store 按值拷贝后，调用方事后改自己的 Policy 变量不再静默改服务器策略。

其余关键设计点：`Middleware` 保留空策略 identity 提前分支（零开销契约不回归）；`OriginAllowed` 值接收者按需重建（O(n)，仅登录门路径，中间件热路径仍走预计算 config）；`applyCORS` 成功才推进 `r.current`（失败后重试基线不漂移）；退化策略（enabled 但零 origins）全链路 fail closed，行为表写入 Hot Reload 文档行。

验收映射表把规格的每项验收落到具体文件与断言，另补了规格未覆盖的组合用例（热替换后登录门跟随、仅 `enabled` 变化 → `Ignored`、失败后 `Current()` 不变）。
