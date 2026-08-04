# interfaces/cors 设计文档：策略热更新 + origin 判定单一事实来源

> 输入：[interfaces-cors-requirements.md](interfaces-cors-requirements.md)（需求规格，证据已逐条核实）。
> 本文档只做设计：API surface、存储模型、失败模式、以及可能击穿设计的地方。
> 非目标（与规格一致）：配置面完整性（方向二）、可观测性（方向三）不在本文范围。

## 0. 约束基线（设计前核实的事实）

| 事实 | 数值 | 对设计的影响 |
|---|---|---|
| `interfaces/sso` 生产文件数 | 60（冻结上限，`_test.go` 不计） | 新生产代码并入既有文件 |
| `interfaces/sso/sso_protocol.go` | 499 行（`>500` 即失败） | **只有 1 行余量** —— 不能"新增字段"，只能"字段替换" |
| `interfaces/sso/server_routes.go` | 488 行 | `SetCORSPolicy` 放这里会超 500；规格示例也给了 `origin_validation.go` |
| `interfaces/sso/origin_validation.go` | 242 行 | `SetCORSPolicy` + 门改写的落脚点（`WithCORS` 已在此文件） |
| `interfaces/cors/cors.go` | 242 行 | PolicyStore/DynamicMiddleware/OriginAllowed 全放得下（约 +70 行） |
| `config/reload/reload.go` | 395 行 | `SetCORSHook` + `applyCORS` + 前缀登记共约 +45 行，安全 |
| `config/` 目录文件数 | 冻结 | 热重载逻辑并入 `reload.go`，不开新文件 |
| `corsPolicy` 字段的读取点 | 仅 2 处（`wrapInnerMiddlewares`、`isOriginAllowed`），**无任何测试直接引用** | 字段可安全替换 |
| `cors.Middleware` 生产调用方 | 仅 `interfaces/sso/server_routes.go` | 静态入口可改为薄封装，SDK 零改动 |

**关键推论（行预算强制）**：`sso_protocol.go` 只有 1 行余量，因此 `corsPolicy *cors.Policy`
字段**必须被替换**为 `corsStore *cors.PolicyStore`（净行数不变），而不是新增字段。这同时
消除了"boot 指针 vs 活策略"双源并存的隐患——见 Decision 3 的组合契约。这偏离规格文本中
"s.corsPolicy.OriginAllowed(...)"的字面写法，但判定入口（`Policy.OriginAllowed`）与验收
语义完全不变，且 `corsPolicy` 无测试引用、只有 2 个生产读取点，替换是安全的。

---

## Decision 1 — `interfaces/cors` 可热替换策略载体（PolicyStore + DynamicMiddleware）

### API surface

`interfaces/cors`（全部为既有包的增量，不新增文件）：

```go
// PolicyStore 持有一个可原子替换的 Policy。镜像 ratelimit.PolicyStore。
func NewPolicyStore(initial Policy) *PolicyStore
func (s *PolicyStore) Set(p Policy)      // atomic.Pointer 整体替换
func (s *PolicyStore) Get() Policy       // 返回当前 Policy 的值拷贝

// DynamicMiddleware 逐请求从 store 读取活策略，行为与静态 Middleware 完全一致
// （同一条 resolveCORSConfig 最长前缀优先语义）。空策略 = identity。
func DynamicMiddleware(store *PolicyStore) func(http.Handler) http.Handler

// Middleware 保留为薄封装：等价于 DynamicMiddleware(NewPolicyStore(p))，
// 但保留"空策略直接返回 identity 闭包"的提前分支——未启用即零开销契约不回归。
func Middleware(p Policy) func(http.Handler) http.Handler
```

`interfaces/sso`（并入既有文件）：

- `sso_protocol.go`：字段 `corsPolicy *cors.Policy` → `corsStore *cors.PolicyStore`
  （行数替换，净 0 变化；`corsStore == nil` ⇔ "CORS 从未启用"，与原 `corsPolicy == nil` 语义一致）。
- `origin_validation.go`：`WithCORS(policy)` 改为 `s.corsStore = cors.NewPolicyStore(policy)`
  —— **按值拷贝进 store**，顺带修复一个潜在别名 bug：原实现 `s.corsPolicy = &policy`
  持有调用方指针，调用方事后改自己的 `Policy` 变量会静默改服务器策略；store 化后不可能。
- `server_routes.go` `wrapInnerMiddlewares`：`cors.Middleware(*s.corsPolicy)` →
  `cors.DynamicMiddleware(s.corsStore)`（`s.corsStore != nil` 分支不变）。

### Storage model

- 纯内存：一个 `atomic.Pointer[Policy]`，无持久化、无副本、无序列化。
- **不可变性不变式**：`Policy` 视为不可变值。`Set` 整体替换指针；`buildConfig` 每次从
  Policy 值新建 `exactOrigins` map；`PathOverrides` 的 map 在替换后只读。读者永远不会
  观察到"头列表来自新策略、origin 集合来自旧策略"的撕裂状态。
- 持久事实来源仍是配置文件/Source 链——store 只是运行期影子；SIGHUP 重载（Decision 2）
  是唯一写入口，SDK 直连调用方只能通过 `WithCORS` 在 boot 时初始化。
- 生命周期：旧 Policy 无活跃引用后由 GC 回收；`Middleware` 薄封装的 store 不可达即回收。

### Failure modes

| 模式 | 行为 | 判定 |
|---|---|---|
| `DynamicMiddleware(nil)` | 首请求 `Get()` 解引用 nil → panic | 编程错误，fail loud（与 `ratelimit.DynamicMiddleware` 同契约）；生产路径不可能——store 只在 `WithCORS` 时创建 |
| `Set` 与请求并发 | 原子指针，每请求看到完整一致的 Policy | 安全，无锁 |
| 空策略经 `Set` 换上（enabled 但零 origins） | 中间件照常挂载但任何 origin 都拿不到头（pass-through 无头）；登录门 403 | fail closed，见 Decision 3 的退化策略表 |
| SIGHUP 抖动导致频繁 `Set` | 每次替换分配新 Policy/configs，旧值 GC | 运维频率，非攻击面，可忽略 |
| 无 `WithCORS` 的构建调 `SetCORSPolicy` | 返回 `false`，store 不创建 | 与 rate_limit 同契约，见 Decision 2 |

### What could break

1. **identity 快速路径回归**：若 `Middleware` 被朴素重写为 `DynamicMiddleware(NewPolicyStore(p))`
   且丢掉空策略提前分支，"未启用即零开销"契约破坏（每请求多一次原子 load + origin 探测，
   虽然行为等价）。缓解：保留显式分支 + 既有 `TestCORS_*` 单测原样通过作为回归锚。
2. **双源并存**：若保留 `corsPolicy` 又新增 store，两个"当前策略"必有一个会在热替换后过期
   ——这正是 Decision 3 要消灭的分叉。缓解：字段替换而非新增（行预算也强制如此），
   唯一写入点是 `WithCORS`，唯一读入口是 `corsStore.Get()`。
3. **调用方指针别名**（既有隐患，非新引入）：`WithCORS(&policy)` 持有调用方变量。
   store 按值拷贝后此隐患消除，但要注意 `NewPolicyStore(initial)` 本身也是按值存——
   契约要在 doc comment 写明"Policy 及其 map 不得在 Set 后原地修改"。
4. **文件预算**：`cors.go` +~70 行到 ~310，安全；`sso_protocol.go` 净 0 变化。
   风险在"以为能新增字段"——设计已把字段替换定为硬约束，实施时不得回退。

---

## Decision 2 — `Server.SetCORSPolicy` 接入 SIGHUP 热重载，`security.cors` 入契约文档

### API surface

`interfaces/sso`（`origin_validation.go`，紧邻 `WithCORS`）：

```go
// SetCORSPolicy 原子替换活 CORS 策略，语义镜像 SetRateLimitPolicy：
// 启动时未 WithCORS（corsStore == nil，无已挂载中间件槽位）返回 false；
// 只允许已启用策略内的数字/列表热变，开/关 CORS 整体仍需重启。
func (s *Server) SetCORSPolicy(p cors.Policy) bool {
    if s.corsStore == nil { return false }
    s.corsStore.Set(p)
    return true
}
```

`config/reload/reload.go`（全部并入既有文件）：

- 新字段 `setCORSPolicy func(config.CORSConfig) error` + `SetCORSHook(fn)`，
  镜像 `SetRateLimitHook` 的 unwired-hook → `Ignored` 契约。
- `safeReloadPrefixes` 追加 `"/security/cors"`（块前缀匹配，与 `"/security/rate_limit"` 并列）。
- `applyOps`：新增 `corsChanged` 标志，循环后调用一次 `applyCORS(newCfg)`：

```go
func (r *Reloader) applyCORS(newCfg *config.Config) string {
    if r.setCORSPolicy == nil { return "" }              // 未接线 → Ignored
    if !newCfg.Security.CORS.Enabled { return "" }       // enabled 开关是 restart-only → Ignored
    if err := r.setCORSPolicy(newCfg.Security.CORS); err != nil { return "" }
    r.current.Security.CORS = newCfg.Security.CORS       // 成功才推进 tracked state
    return "security.cors: policy rebuilt"
}
```

`cmd/sso-server/main_wiring.go`：`wireCORSReload`（紧邻 `wireRateLimitReload`）：

```go
reloader.SetCORSHook(func(c config.CORSConfig) error {
    if !srv.SetCORSPolicy(c.toPolicy()) {
        return errors.New("cors hot-reload: not enabled at boot (no WithCORS)")
    }
    return nil
})
```

契约文档（同一 change 内完成）：
- `docs/config-reference.md` Security 表新增 `security.cors.*` 行：逐字段映射到
  `cors.Policy`（`allowed_origins` 空 = 禁用、空 `allowed_methods`/`allowed_headers`
  回退 `cors.DefaultAllowedMethods`/`DefaultAllowedHeaders`、`path_overrides` 说明
  最长前缀优先），注明映射到 `sso.WithCORS` 且 `enabled` 整体开关需重启。
- Hot Reload (SIGHUP) 表新增 `security.cors.*` 行：整块一次重建、diff 驱动、未启用
  落入 `ignored_requires_restart`。
- `config/reload` 包 doc 的 "Currently wired safe fields" 枚举同步追加 `security.cors.*`
  条目（该枚举是手工维护的，漏改即文档漂移——列入验收）。

### Storage model

- 无新增持久化。事实来源 = Source 链（文件/env/etcd/flag），`Reloader.current` 是追踪副本，
  `corsStore` 是运行期影子。
- 一次 reload 的写入路径：`configaudit.Diff` 产出叶子 op → `hasSafePrefix("/security/cors")`
  命中任意叶子 → **恰好一次**整块重建（`toPolicy()` 纯函数，无副作用、可重放）→
  `SetCORSPolicy` 原子替换。多个叶子同时变也只重建一次（镜像 rate_limit 的
  "整块一次重建、diff 驱动"语义）。
- `r.current.Security.CORS` 只在 hook 成功后才推进；失败则 tracked state 停留在
  last-good，下一次 reload 仍按旧基线 diff。

### Failure modes

| 模式 | 行为 | 判定 |
|---|---|---|
| 未 `SetCORSHook`（旧构建/第三方调用方） | `applyCORS` 返回 `""` → `/security/cors` 进 `Ignored` | 安全默认，与 rate_limit 完全一致 |
| 配置文件被改坏（SIGHUP 时解析失败） | `Reload` 返回错误，不触碰 tracked state，进程继续用 last-good | 既有契约：SIGHUP 永远不能 crash 运行中的服务 |
| `security.cors.enabled` 变 `false` | `applyCORS` 的 Enabled 检查返回 `""` → `Ignored`（整体开关需重启） | 与 rate_limit 的 enabled 契约一致 |
| boot 未启用（无 `WithCORS`），reload 尝试开 CORS | `SetCORSPolicy` 返回 false → hook 报错 → `Ignored` | 无中间件槽位可换入，永不假装 Applied |
| `enabled=true` 但 `allowed_origins` 被清空 | 视为"已启用策略内的列表热变"，换入零 origins 策略：中间件 pass-through 无头、门 403 | fail closed；与 boot 语义的不对称（boot 要求 len>0 才启用）要在 Hot Reload 表注明 |
| hook 返回错误 | `Ignored` + `config reload applied` 日志如实呈现；store 保持 last-good | 永不部分应用 |

### What could break

1. **`enabled` 检查放错层**：若把 Enabled 检查放在 cmd 的 hook 闭包里，`applyCORS` 会
   在 `enabled:false` 时也调用 hook 并成功 swap（store 存在时 `SetCORSPolicy` 会返回 true），
   "整体开关需重启"契约被击穿。设计强制：Enabled 检查在 `applyCORS`（reload 包看得到
   `newCfg`），hook 保持哑。reload 单测必须覆盖"仅 `enabled` 变化 → `Ignored`"用例。
2. **包 doc 枚举漂移**：`reload.go` 包 doc 手工枚举 safe 字段，漏加 `security.cors.*`
   会让"为什么这个字段能热更"的推理失锚。列入验收（doc 断言或人工 checklist）。
3. **行预算**：`reload.go` 395 → ~440 行，安全；但 `applyCORS` 若再加 Enabled 之外
   的防御逻辑（如校验 origins 非空才允许 swap）会膨胀——**不要加**，退化策略本来就
   fail closed，校验属于过度设计。
4. **`toPolicy()` 与 `CORSConfig` 演进脱钩**：未来给 `CORSConfig` 加字段（如
   `path_overrides`），`toPolicy()` 漏映射 → reload 静默丢配置。缓解：`toPolicy` 的
   doc comment 声明"与 CORSConfig 字段一一对应"，Security 表行与
   `config_admin.go:103` 字段清单共同构成验收锚。
5. **`r.current` 推进与失败原子性**：`applyCORS` 必须在 hook 成功后才写
   `r.current.Security.CORS`，否则失败后重试会基于错误基线 diff。镜像 `applyRateLimit`
   的既有写法，reload_test 需断言失败后 `Current()` 不变。

---

## Decision 3 — origin 判定收敛为 `cors` 包单一实现，登录 CSRF 门复用

### API surface

`interfaces/cors/cors.go`（`corsConfig.originAllowed` 降为内部实现）：

```go
// OriginAllowed 报告 origin 是否被 p 允许访问 path。path 为空或未命中任何
// PathOverrides 时按默认策略判定（resolveCORSConfig 的最长前缀优先语义）。
// origin 为空串时恒为 false（调用方应先行跳过空 Origin——中间件与登录门都如此）。
// 值接收者：每次调用按需 buildConfig + buildOverrideConfigs，O(总 origins +
// 总 override 条目)；只用于登录门（每 POST 一次）与外部调用方，中间件热路径
// 仍走预计算的 corsConfig，不受影响。
func (p Policy) OriginAllowed(origin, path string) bool
```

`interfaces/sso`（`origin_validation.go` + `server_login.go`）：

- **删除** `isOriginAllowed`（线性扫描 + 硬编码 `"*"` 字面量一并消失；通配语义只剩
  `cors.OriginWildcard` 一处演进）。
- `rejectDisallowedLoginOrigin` 改为：

```go
origin := ctx.Request().Header.Get(core.HeaderOrigin)   // 顺带替换硬编码 "Origin" 字面量
if origin == "" || s.corsStore == nil {
    return false
}
if s.corsStore.Get().OriginAllowed(origin, ctx.Request().URL.Path) {
    return false
}
// ...403 + origin_blocked audit 不变
```

- doc comment 显式声明："登录门与中间件共享同一判定（`Policy.OriginAllowed`）；
  `/auth/login` 当前无 path override，等价于仅默认策略——若运维为登录路径配置
  override，两处一致生效"。`origin_blocked` 日志、403 + no-store + `iss` 契约不变。

**组合契约（本文档的关键补充）**：门必须读**活策略**（`corsStore.Get()`），而不是
boot 指针——否则 Decision 1 热替换后中间件用新策略、门用旧策略，重新制造 Decision 3
要消灭的分叉。规格文本的 "s.corsPolicy.OriginAllowed" 因字段替换（见第 0 节）落为
`corsStore.Get().OriginAllowed`，语义等价且防漂移。

### Storage model

- 判定本身无状态：`OriginAllowed` 是 Policy 值上的纯函数，每次调用重建 config。
  中间件与门共享同一函数、同一 `resolveCORSConfig` 前缀语义，但各自持有不同的
  config 生命周期（中间件预计算缓存 vs 门按需重建）——**判定结果必然一致**，
  因为两者读同一个 store 值。
- "空 origin / 无策略"的短路逻辑留在调用方（门与中间件各自短路），`OriginAllowed`
  只回答"这个非空 origin 在这个 path 上是否被放行"。

### Failure modes

| 模式 | 行为 | 判定 |
|---|---|---|
| 门在 `corsStore` 为 nil（未启用） | 短路放行——与现状 `corsPolicy == nil → 放行` 完全一致 | back-compat 保留 |
| 退化策略（enabled 但零 origins，含 reload 换入） | `OriginAllowed` 恒 false：中间件 pass-through 无头（浏览器侧阻断），门 403 | fail closed；与现状 SDK 直传空 `cors.Policy{}` 时门 403 的行为一致 |
| 请求 path 命中 override（如 `/auth/login` 配了 override） | 门与中间件同判：override 放行则两处都放行，拒绝则两处都拒 | 本次设计要消除的旧分叉（原门无视 override） |
| `origin == ""` | 两处都短路，不调 `OriginAllowed` | 无状态变化（GET/健康检查等无 Origin 请求不受门影响） |
| 热替换与登录并发 | `Get()` 取一致 Policy 值再判定 | 原子，无撕裂 |

### What could break

1. **门读 boot 指针而非活策略**：这是本决策最大的坑。若实现按规格字面写
   `s.corsPolicy.OriginAllowed(...)` 且 `corsPolicy` 仍是 boot 快照，则 SIGHUP 换策略后
   中间件放行新 origin、门仍 403——分叉以更难查的形式复活。缓解：字段替换为 store
   （第 0 节强制）+ sso 级测试覆盖"`SetCORSPolicy` 后登录门立即跟随新策略"。
2. **`OriginAllowed` 的 O(n) 重建被误用进热路径**：doc comment 写明成本与适用场景；
   中间件继续用预计算 config，不允许重构中间件去调 `OriginAllowed`（每请求重建 map
   会引入可测的分配开销）。
3. **path 语义分叉**：门用 `ctx.Request().URL.Path`、中间件用 `r.URL.Path`——同一请求
   同一值；但若未来某处传入不带前缀归一化的路径（如 `//auth/login` 或带 query），
   前缀匹配结果可能不同。缓解：e2e 断言 + 在 `OriginAllowed` doc 写明"path 必须是
   ​​URL 的 Path 分量（不含 query），与中间件一致"。
4. **`"*"` 字面量回归**：sso 侧删除后若有人重新内联通配判断，单一事实来源失效。
   缓解：验收含 grep 断言（`interfaces/sso` 无 `"*"` 字面量）——实施时以
   `cors.OriginWildcard` 引用为准。
5. **行为回归面**：`non_matching_origin_blocked` 等既有用例改走共享判定后必须原样
   通过；`login_early_gate_headers_test.go` 的 403 + no-store + `iss` 契约不变——
   这两组测试是"共享判定无行为漂移"的回归锚。

---

## 跨决策验收映射

| 验收（规格） | 落点 | 关键断言 |
|---|---|---|
| D1 即时替换 + 未启用返回 false | 新文件 `interfaces/sso/cors_hotreload_test.go`（测试文件不计 60 上限），镜像 `rate_limit_hotreload_test.go` | `SetCORSPolicy` 后下一请求即用新 origin/头；无 `WithCORS` 的 server 返回 false 且不 panic |
| D2 reload 模式用例 | `config/reload/reload_test.go` 追加 | 改 `allowed_origins` → `applied` 含该块且请求按新策略发头；未启用构建 → `ignored_requires_restart`；仅 `enabled` 变 → `Ignored`；失败后 `Current()` 不变 |
| D2 文档行 | `docs/config-reference.md` Security 表 + Hot Reload 表 | 字段与 `CORSConfig`（config_admin.go:103）一一对应；`reload.go` 包 doc 枚举同步 |
| D3 单测 | `interfaces/cors/cors_test.go` | 精确、通配、通配+凭据、override 命中/未命中（最长前缀优先） |
| D3 既有用例 | `origin_validation_test.go`、`login_early_gate_headers_test.go` | 改走共享判定后原样通过；403 + no-store + `iss` 不变 |
| D3 联动 e2e | `test/cors_e2e_test.go` 追加 | 默认放行 A + `PathOverrides["/auth/login"]` 放行 B：B 的 `POST /auth/login` 有 CORS 头且非 403；C 无头且 403；`GET /.well-known/jwks.json` from B 拿到 override 头 |
| 组合（本设计新增） | `cors_hotreload_test.go` | 热替换后登录门立即跟随新策略（门读活 store 的防漂移锚） |

验证顺序沿用规格的验证计划；`make ci` 为最终门。

## 风险清单（按击穿概率排序）

1. **门读 boot 快照**（D1×D3 组合漂移）——字段替换 + 组合测试双保险。
2. **`enabled` 检查错层**（D2 契约击穿）——Enabled 检查固定在 `applyCORS`。
3. **`sso_protocol.go` 行预算**——字段替换是唯一允许的形态；实施若"顺手"加注释即越线。
4. **identity 快速路径回归**（D1 零开销契约）——保留提前分支 + 既有单测锚。
5. **包 doc / 文档漂移**（D2 手工枚举）——两处表格行 + 包 doc 枚举进同一 change。
6. **退化策略语义含糊**（enabled 且零 origins）——fail closed，行为表写入 Hot Reload 行。
