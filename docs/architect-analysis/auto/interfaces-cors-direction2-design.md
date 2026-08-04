# interfaces/cors 方向二 设计文档：配置面完整性

> 输入：[interfaces-cors-direction2-spec.md](interfaces-cors-direction2-spec.md)（规格，证据已逐条核实）。
> 本文档只做设计：API surface、存储模型、失败模式、以及可能击穿设计的地方。
> 范围与规格一致：恰好三个配置面改进，无中间件语义 / origin 匹配 / 安全行为变更。

## 0. 约束基线（设计前核实的事实）

| 事实 | 数值 / 位置 | 对设计的影响 |
|---|---|---|
| `config/` 目录文件数 | 冻结 | 全部配置改动并入 `config_admin.go` / `config_load.go` / `security_test.go`，零新文件 |
| `config_load.go` CORS 接线门 | `:315-316` `Enabled && len(AllowedOrigins) > 0` | 必须与 cmd 侧门同步放宽，否则 SDK 与 stock binary 行为分裂 |
| `config_load.go` `toPolicy()` | `:469-480`，六字段映射 | 提取映射 helper；新字段 `PathOverrides` + `AllowedHeadersExclusive` 走同一 helper |
| `cmd/sso-server/build_app_security.go` | `:170-179` 内联 `cors.Policy{...}`，`wireMTLSLockoutProxiesCORS` 已贴函数长度预算 | 内联体替换为 `toPolicy()` 调用（净减行数）；日志加 override 计数 |
| `WithCORS` 语义 | `interfaces/sso/origin_validation.go:21-23` 存**指针**，后 append 覆盖 | `build_app_core.go:154` 先 `ServerOptions()`，`build_stores.go:259` 后 `wireMTLSLockoutProxiesCORS()` —— 内联点是 stock binary 的生效点；只修 `toPolicy()` 投递不出去（已核实调用顺序） |
| `cors.Middleware` 生产挂载点 | 仅 `server_routes.go:452` | 单一挂载点；策略值在 Middleware 构造时一次性预计算 |
| `shared/core` 依赖 | `go list` 实测仅 stdlib（context/net/http/…），零 Snaplink 包 | `interfaces/cors` → `shared/core` 无环；`sso` 已 import `core`，层级向下 |
| 常量命名差异 | `core` 为 `HeaderAccessControl{Origin,Methods,Headers}`，`cors` 为 `HeaderAccessControlAllow{Origin,Methods,Headers}` | 同字符串值、不同 Go 标识符；删除 cors 侧三常量 = `cors.go` 内机械改名，`go build` 兜底 |
| `cors_test.go:140` `TestPreflight_EmitsAllowMethodsAndHeaders` | 断言 `"X-Custom, Authorization"`（整体替换语义） | **全库唯一编码旧契约的测试**，D3 必须同步改期望（合并后 `"Authorization, Content-Type, X-Custom"`）或改写为 exclusive 用例 |
| `X-RateLimit-Remaining` 现存出现 | `cors.go:44`、`cors_test.go:193,202` + 历史文档（`docs/requirements/*`、`docs/results/*`、`docs/architect-analysis/*`、`docs/proposals/requirements.md`） | 验收 grep 的"零残留"必须限定可执行范围（见 D2 失败模式），否则规格验收本身不可满足 |
| `buildOverrideConfigs` 排序 | `cors.go:180-196` 仅按 prefix 长度冒泡排序，等长前缀顺序取决于 map 迭代序 | **预存在的不确定性**；D1 使等长前缀冲突从"不可达"变为"运维可达"，建议顺带确定性化（见 D1） |
| `HeaderDPoP` 定义处 | `interfaces/sso/server_pairwise.go:343`（不在 `shared/core`） | 配置测试用字面量 `"DPoP"`；`cors` 不可反向 import `sso`（环） |
| `interfaces/sso` 文件数 | 60 冻结 | 本方向在 sso 侧**零生产改动**（`WithCORS`/挂载点不动）；`test/` 集成测试为 `package ssotest`，不计入 |

---

## Decision 1 — `security.cors.path_overrides` YAML 映射：让 `PathOverrides` 对运维可达

### API surface

配置 schema（`config/config_admin.go`，扩展现有 `CORSConfig`，不开新文件）：

```yaml
security:
  cors:
    enabled: true
    allowed_origins: ["https://app.example.com"]
    path_overrides:
      "/.well-known/jwks.json":
        allowed_origins: ["*"]
      "/token":
        allowed_origins: []          # 该路径不发任何 CORS 头（浏览器视为 blocked）
```

- `CORSConfig.PathOverrides map[string]CORSConfig yaml:"path_overrides"`。值类型复用 `CORSConfig`；条目自身的 `enabled` 字段**按构造即忽略**——`toPolicy()` 不把 `Enabled` 带进 `cors.Policy`，条目凭非空 `allowed_origins` 生效。此语义写入 D2 文档行。
- `toPolicy()`（`config_load.go`）重构为：六字段映射提取为包级 helper（供顶层与每个 override 条目共用），顶层 `cors.Policy.PathOverrides` 为逐 key 调用同一 helper 的 `map[string]cors.Policy`。**不递归映射**嵌套 `path_overrides`（中间件模型本身是扁平的，`buildOverrideConfigs` 只吃一层）。
- 校验（fail loud at load，`LoadFromSources` 即报错，而非等到 `ServerOptions`）：
  1. 每个 key 必须以 `/` 开头 —— 非 `/` 前缀是配置错误，不再是静默截断；
  2. **设计裁定**：override 条目内出现嵌套 `path_overrides` 一律拒绝（"path_overrides 不能嵌套"），与本方向"反对静默丢弃"的原则一致——若实现上想省校验，宁可丢弃也要写进文档；推荐前者。
- 接线门（**两处同改**）：`config_load.go:315` 与 `build_app_security.go:170` 统一放宽为
  `Enabled && (len(AllowedOrigins) > 0 || len(PathOverrides) > 0)`，镜像 `cors.go:173` 的 identity 判定。
- `cmd/sso-server/build_app_security.go:170-179`：内联 `cors.Policy{...}` 字面量整块替换为 `c.Security.CORS.toPolicy()`；引导日志扩展 `"path_overrides", len(c.PathOverrides)`。若 `cors` import 因此不再被使用，同 commit 移除。
- 对外的行为契约（运维可见面）：`/` 前缀校验失败 = 启动失败；override 条目空 `allowed_origins` = 该路径无 CORS 头；两者都进 D2 文档行。

### 存储模型 / 状态生命周期

本方向**无持久化存储**。状态是一条纯内存链，全部在启动时定型：

```text
YAML → CORSConfig（LoadFromSources，含 / 校验）→ cors.Policy（toPolicy，每个 override 子策略）
     → sso.Server.corsPolicy 指针（WithCORS，两个 append 站点）→ corsConfig 预计算值
     （cors.Middleware 构造于 server_routes.go:452，一次性 join/查表）
```

- 无跨副本状态、无 cluster bus、无 invalidation：改配置 = 重启，热更新明确非目标（D2 文档行落"需重启"）。
- 唯一的"写"是 `corsPolicy` 指针被两个站点先后赋值；修复后两站点写**同一来源**的相同值，指针覆盖隐患从"双源漂移"降为"同一函数的两次调用"。

### 失败模式

| 模式 | 行为 | 处置 |
|---|---|---|
| key 不以 `/` 开头 | `LoadFromSources` 报错，进程拒绝启动 | fail loud，符合方向原则 |
| 嵌套 `path_overrides` | 校验报错（推荐）或文档声明忽略（次选） | 设计裁定见上 |
| override 条目空 `allowed_origins` | `resolveCORSConfig` 命中该条目 → `originAllowed=false` → 不写任何 CORS 头，请求**继续**走栈；预检 OPTIONS 落到路由层可能得 405/404 | 浏览器端等同 blocked，符合规格；文档写明"该路径无 CORS 头"，并说明不短路预检 |
| `enabled: false` 的 override 条目 | 仍生效（`Enabled` 不进 Policy） | 文档高亮，防止运维误以为能用来关单条 |
| 前缀无尾斜杠 | `/token` 匹配 `/tokenizer`（最长前缀优先是既有语义，本次不改匹配只改可达性） | 文档建议：整路径或带尾斜杠的 key |
| 等长前缀同时命中 | `buildOverrideConfigs` 等长不交换 → 首胜者取决于 map 迭代序，**不确定** | **设计裁定（推荐顺手修复）**：排序加二级键（前缀字符串降序），把"最长优先、等长确定"写进中间件测试；代价 ~4 行，消除 D1 引入的运维级不确定性。若不动，必须在文档行写明"等长前缀命中未定义" |
| 顶层 `allowed_origins` 与 overrides 皆空 | 中间件 identity（`cors.go:173`），门也拒绝接线 | 行为不变，零开销 |
| 只放宽一处门 | SDK（`ServerOptions`）与 stock binary（cmd 内联点）行为分裂 | 两处同一 commit 改；config 侧单测捕获 `WithCORS` 策略 + ssotest 集成测试覆盖 stock 路径 |

### 什么会击穿这个设计

1. **`wireMTLSLockoutProxiesCORS` 贴函数长度预算**：替换是"结构体字面量 → 函数调用"（净减行），加一行日志；维护性门（`TestMaintainability_`）兜底。若超限，把 CORS 段提取为 `wireCORS()`（沿用 `wireSecurityHeaders` 先例）。
2. **`cmd/sso-server` 的 `cors` import 变孤儿**：删除内联字面量后 `goimports`/`go build` 会报未使用，同 commit 清理。
3. **`config/` 文件冻结**：测试只能扩 `security_test.go`（既有模式），不能新建 `config/*_test.go`。
4. **`toPolicy()` 撞 50 行函数预算**：helper 提取后顶层函数只剩字段搬运 + 循环，安全。
5. **指针覆盖在修复后重新出现**：任何未来第三个 `WithCORS` append 站点都会静默赢过前两个。缓解：测试断言捕获策略（`TestSecurityConfig_ServerOptionsWires*` 模式）而非依赖调用顺序；规格验收已覆盖。
6. **集成测试的预检路径**：`OPTIONS /.well-known/jwks.json` 必须带 `Origin` 头且命中默认策略之外 origin，才能观察到 override 生效；默认策略与 override 的 `allow_credentials` 不能混用（wildcard+credentials 会触发 echo-origin 分支，`*` 断言失败）。

---

## Decision 2 — `security.cors` 入契约文档：消除配置键文档缺口与 ExposedHeaders 示例漂移

### API surface

- `docs/config-reference.md` Security 表新增一行 `security.cors.*`，覆盖 `CORSConfig` **全部 leaf**：`enabled`、`allowed_origins`、`allowed_methods`、`allowed_headers`、`allowed_headers_exclusive`（D3）、`exposed_headers`、`allow_credentials`、`max_age`、`path_overrides`（D1）。三个语义点必须写死：
  - 空 `allowed_origins` 即使 `enabled: true` 也禁用 CORS（中间件 identity）；
  - `allow_credentials` + `*` 的 echo-origin 交互（`cors.go:112-124`）；
  - 改动需重启，不在 SIGHUP 热更新子集内（与 `:444` Hot Reload 表措辞一致）。
- 示例漂移修复（同一 commit、三处一致）：`cors.go:44` 文档注释与 `cors_test.go:193,202` 固件的 `X-RateLimit-Remaining` → 真实存在的 `X-Request-Id`（`shared/core/consts_wire.go:21`）与 `Retry-After`（`shared/core/consts_wire.go:24`；`interfaces/ratelimit` 全包只发此头，已核实）。
- 契约闭环：`toPolicy()` 是 `config_load.go` 既有导出面，文档行与 `CORSConfig` 字段一一对应；`docs/config-reference.md` 是唯一需要更新的契约文档（无新 Err*/端点/包）。

### 存储模型

无。纯文档契约变更：一行表格 + 两个注释/固件字符串。校验手段是 grep 与 `make ci` 的 docs 校验（若存在）；无运行时状态。

### 失败模式

- **验收 grep 范围不可满足（规格歧义，设计裁定）**：`X-RateLimit-Remaining` 还存在于历史分析文档（`docs/requirements/expansion-*.md`、`docs/results/PEER_REVIEW_*.md`、`docs/architect-analysis/`、`docs/proposals/requirements.md`、`docs/auto/` 规格本身）——这些是记录漂移本身的审计痕迹，改写等于伪造历史。**可执行验收范围**：`--include='*.go'`（排除 `dist/`）+ 契约文档集（`docs/config-reference.md`、`docs/error-codes.md`、`docs/openapi.yaml`、`docs/feature-matrix.md`、`docs/observability.md`）。实现时按此范围跑 grep，并在 commit 说明里注明裁定。
- **leaf 漂移**：D1/D3 的新字段与文档行同 change 落地，行必须最后写、一次写全，避免"文档先行/滞后"的半同步态。
- **表格格式**：若 `make ci` 有 markdown/config 校验，行格式必须与既有 Security 行一致（`| key | effect |`）；"需重启"措辞对齐 Hot Reload 表既有表述。
- **文档行与代码再次漂移**：未来给 `CORSConfig` 加 leaf 而漏改文档行——AGENTS.md §5 的既有门，无新机制。

### 什么会击穿这个设计

- 实现者按规格字面跑全库 grep，被历史文档卡住而"顺手改历史文档"或"放弃验收"——本设计已给裁定，按裁定范围执行即可。
- `cors_test.go:193` 的断言字符串（`Access-Control-Expose-Headers` 值）依赖暴露头列表按序 join；换成 `Retry-After` 后期望串必须同步，且 `X-Request-Id` 保留原样（该头真实存在，`consts_wire.go:21`）。

---

## Decision 3 — 允许头"追加到默认值"语义 + 头常量单一来源

### API surface

- `cors.Policy.AllowedHeadersExclusive bool`（新字段，零值 = 追加语义）与 `config.CORSConfig.AllowedHeadersExclusive bool yaml:"allowed_headers_exclusive"`；`toPolicy()` 映射之；D2 文档行含此 leaf。
- `buildConfig`（`cors.go:78-90`）合并规则：
  - `AllowedHeaders` 空 → 仅默认值（不变）；
  - 非空且非 exclusive → `defaults ∪ configured`，**默认值在前、配置增量按配置顺序在后、去重**（设计裁定：**大小写不敏感去重**——HTTP 头名大小写不敏感，`allowed_headers: [authorization]` 不得产出 `"Authorization, Content-Type, authorization"`；保留首次出现的写法，即默认值写法优先）。`[DPoP]` ⇒ `Authorization, Content-Type, DPoP`；
  - `AllowedHeadersExclusive: true` 且非空 → 整体替换（逃生舱，恢复旧语义）；
  - 同一规则经共享 `buildConfig` 自动作用于 `PathOverrides` 子策略；exclusive 标志按条目独立携带（每个 `CORSConfig` 有自己的字段）。
- `interfaces/cors/consts.go`：删除与 `shared/core/consts_wire.go:25-27` 重复的三个 `HeaderAccessControl{Origin,Methods,Headers}`，import `shared/core` 并改名 `cors.go` 内全部引用；保留 cors 专属名（`HeaderOrigin`、`HeaderVary`、`HeaderAccessControlAllowCreds/ExposeHeaders/MaxAge/RequestMethod`、`OriginWildcard`、`TrueLiteral`）。**设计裁定（推荐）**：`DefaultAllowedHeaders` 改为 `[]string{core.HeaderAuthorization, core.HeaderContentType}`，把默认列表也从字面量变成单一来源——这正是本决定要消除的漂移类型。
- **语义变更面（本方向唯一的行为变更，必须显式声明）**：`buildConfig` 是配置路径与 SDK 直连路径（`sso.WithCORS(cors.Policy{...})`）的共享函数。因此**直接使用 SDK 且传入非空 `AllowedHeaders` 的调用方**会从"整体替换"变为"合并"——这是有意的、文档化的语义变化，逃生舱恢复旧行为。库内核实：`cors.Middleware`/`WithCORS` 的生产调用方只有 `sso`（挂载）与两个配置生产点（config、cmd），无第三方库内直连调用方，影响面可控。

### 存储模型

无持久化。合并发生在 `buildConfig` 预计算阶段（Middleware 构造时一次），产出 `corsConfig.headersHdr` 字符串；每请求零合并开销。与 D1 同链：`CORSConfig → Policy → corsConfig`。

### 失败模式

- **去重必须确定性**：用 seen-set + 切片（保序），禁止 map 迭代拼串——否则 `headersHdr` 在等值输入下随机抖动，测试 flake。
- **大小写**：去重大小写不敏感（见上）；输出 casing 以首次出现为准（默认值 `Authorization`/`Content-Type` 恒为首）。
- **空串/空白条目**：设计裁定——trim 后跳过空条目，保证确定性输出；不额外校验（非法头名由浏览器侧拒绝，非服务器职责）。
- **exclusive 与 override 的交互**：条目级标志，不会"顶层 exclusive 意外锁死子策略"（每策略独立走 `buildConfig`）。
- **改名遗漏**：删除常量后 `cors.go` 内残留 `HeaderAccessControlAllowOrigin` 等引用 → `go build` 编译错误兜底，无静默路径。
- **既有测试编码旧契约**：`cors_test.go:140` 断言 `"X-Custom, Authorization"` 必炸——**必须同 change 更新**：改为断言合并值 `"Authorization, Content-Type, X-Custom"`，或改写为 exclusive 用例断言 `"X-Custom, Authorization"`（后者顺便覆盖逃生舱，推荐两者都要：一个合并用例 + 一个 exclusive 用例，即规格验收单元测试）。

### 什么会击穿这个设计

1. **import 环**：实测 `shared/core` 零 Snaplink 依赖（`go list` 输出仅 stdlib），`cors → core` 是纯向下依赖；架构层测试（`TestArchitecture_`）验证 cors 仍在 interfaces 层、core 在 shared 层，无需 `layerExemptions`。
2. **`cors.go` 预算**：+30 行内（合并逻辑 + 文档注释），距 500 行远；`buildConfig` 复杂度不破 15。
3. **SDK 行为兼容**：这是唯一会改变既有 SDK 用户预检输出的决定；规格与本文档都把它列为**有意变更**。若后续发现"必须零行为变更"，唯一退路是让追加语义只作用于配置路径（`toPolicy` 预合并），不动 `buildConfig`——但那会让配置与 SDK 两套语义，违反"单一来源"原则，本设计不推荐。
4. **配置测试的合并断言**：`security_test.go` 现有 YAML 已含 `allowed_headers: ["Authorization", "X-Custom"]`，且现有断言**不**检查 `AllowedHeaders`（只查 origins/max_age）——不受影响；新增 `allowed_headers: [DPoP]` 的往返用例断言合并串（或捕获的 `WithCORS` 策略经中间件后的头值）。

---

## 交叉约束与验收裁定汇总

| 项 | 裁定 |
|---|---|
| 门序列 | 每次 `.go` 编辑后 `go build ./... && go vet ./...` + `go test -run 'TestMaintainability_|TestArchitecture_' .`；handoff 前 `go test ./... -race`、`go test ./test/ -run TestE2E -v`、`make ci` |
| `X-RateLimit-Remaining` 零残留 | 范围为代码（除 `dist/`）+ 契约文档集；历史分析/结果文档豁免（见 D2） |
| 等长前缀确定性 | 推荐随 D1 加二级排序键（~4 行 + 1 测试）；实现若不做，文档行必须写明"等长前缀命中未定义" |
| 嵌套 `path_overrides` | 推荐校验期拒绝（fail loud）；次选：文档声明忽略 |
| 追加去重 | 大小写不敏感、保序、首次写法优先 |
| 预算 | `config/` 零新文件；`interfaces/cors` 新增 <30 行；`interfaces/sso` 零生产改动；`test/` 新集成文件不计 ceiling |

非目标（与规格一致，方向一/三领地）：CORS 热更新、origin 判定单一事实来源、CORS 可观测性。三者若日后推进，本方向修复的配置面是前置条件。

无安全语义变更：origin 匹配、预检 204、凭据处理、`Authorization` 优先回退全部不动；D1/D3 只改变配置面能表达的 policy/头值。无新 `Err*`、无新端点、无新包：`docs/error-codes.md` 与 `docs/openapi.yaml` 零改动。
