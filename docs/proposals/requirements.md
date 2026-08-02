All evidence verified against the code. Here is the specification.

---

# Requirements Specification — `domains/tokenexchange` 跳授权策略运营闭环

方向：docs/auto/domains-tokenexchange-analysis.md 第 2 项「管理 API + 持久化 + 匹配维度扩展」。三个改进为同一闭环的三个面：操作面（管理 API）、状态面（持久化）、表达面（匹配维度）。全部证据已对照代码核实；其中分析文档称 `domains/tokenpolicy` 有 "sqlite 后端" 一处与代码不符（`domains/tokenpolicy/` 仅有 memory 实现），本规范的持久化先例改为模块自有的 `domains/tokenexchange/sqlite` chain store。

## 1. 管理 API：token-exchange 策略的读写端点

**Name**: Add admin read/write API for the active token-exchange hop-policy rule set.

**Problem**: `memory.Store.Replace` 的文档自称是 "the dynamic-update path (e.g. an admin API or config reload)"，但全库生产代码对该方法与 `Rules()` **零调用**——没有管理端点、没有配置重载、cmd 无装配，策略只能构造期 `WithTokenExchangePolicy` 硬编码注入。管理员无法查看当前生效的跳授权规则（连 tokenpolicy 已有的只读治理视图都没有），更无法在应急场景（封禁某 client-subject 组合）下运行时放行/阻断。此外 `Rule` 结构体没有任何 `json`/`yaml` tag，即使有端点也无法序列化。

**Evidence**:
- `domains/tokenexchange/memory/store.go:45`（`Replace` 的 "dynamic-update path" 自述；grep 证实零生产调用方）
- `domains/tokenexchange/tokenexchange.go`（`Rule` 无序列化 tag，无法进入 JSON 管理 API）
- `interfaces/sso/accessors_threat.go:197`（`mountAdminTokenExchangeChainRoutes` 只挂 `GET PathAdminTokenExchangeChain`，纯观测）
- `interfaces/admin/lifecycle.go:109`（`HandleTokenExchangeChain` 仅祖先查询）
- 先例：`domains/tokenpolicy/admin.go` + `interfaces/sso/sso.go:349`（`handleAdminTokenPolicies`，`admin:read` 门控的治理只读端点）

**Proposed behavior**:
1. 在模块内定义最小可变接口（如 `MutablePolicy`：`Replace([]Rule)` + `Rules() []Rule`，由 `memory.Store` 满足），`*sso.Server` 持有时对 `tokenExchangePolicy`（`interfaces/sso/accessors.go:90` 已有 accessor）做类型断言；非可变实现不挂端点（byte-identical）。
2. 新端点（沿用 `core.PathAdmin*` 常量模式，consts.go 新增路径）：
   - `GET /api/v1/admin/tokenexchange/policies`（`admin:read`）：返回 `{default_allow, rules[], total}`，规则按求值顺序排列；治理数据无机密，可原样序列化（对照 `PathAdminTokenPolicies` 注释）。
   - `PUT` 同路径（`admin:write`）：body 为完整规则集，校验（Name 非空、规则数上限、deny/allow 合法）后经 `Replace` 原子生效；校验失败 `400` 且不产生任何变更。
3. 变更即审计：mutation 写 `token_exchange_policy_updated` 类 audit 事件（经 `audit.SetMeta`，含 actor、规则名列表、变更前后数量）——admin API 是内部面，不违反 oracle-safe 坍缩纪律（wire 面 `/token` 行为不变）。
4. 挂载点：扩展 `mountAdminTokenExchangeChainRoutes`（同文件新增 mount，遵循 interfaces/sso 60 文件上限——不新建文件；`server_routes_admin.go` 当前 332 行，低于 500 行预算）。`cmd/sso-server` 在 wired Policy 为可变实现时挂载。

**Acceptance check**:
- 新增 handler 单元测试：GET 返回当前快照；PUT 原子替换（并发 `Allow` 只观察到替换前或替换后，无撕裂状态）；非法 payload `400` 且 `Rules()` 不变；mutation 产生含 actor 的 audit 事件。
- `domains/tokenexchange/...` 与 `interfaces/sso/...` 表驱动测试通过；`go build ./... && go vet ./...`、`go test -run 'TestMaintainability_|TestArchitecture_' .` 通过（函数 <50 行、无新顶层包）。
- 未 wire Policy 的构建与未 wire 前 byte-identical（nil no-op，端点不挂载）。
- `docs/openapi.yaml` 新增两端点定义；E2E：`go test ./test/ -run TestE2E` 中 admin PUT deny 规则后交换返回 `invalid_grant`。

## 2. 持久化：sqlite 策略后端 + 配置装配

**Name**: Durable policy store (sqlite) with config-driven assembly, closing the restart/multi-replica gap.

**Problem**: 规则只存在于进程内存：重启即丢失，多副本各自持有分歧的规则集，`Replace` 文档提到的 "config reload" 路径不存在。配置面 `OAuthTokenExchangeConfig` 只有 `MaxChainLifetime` 一个旋钮，且注释明确宣称 Policy SPI "deliberately NOT YAML-driven"；`cmd/sso-server/build_app_oauth.go:276` 的 `wireTokenExchangeChainLifetime` 只装配链龄，从不装配规则。模块内已有 sqlite 持久化先例（chain store），但策略数据面完全空白。

**Evidence**:
- `config/config_oauth2.go:26-32`（`OAuthTokenExchangeConfig` 单字段 + "NOT YAML-driven" 自限）
- `cmd/sso-server/build_app_oauth.go:276`（`wireTokenExchangeChainLifetime`，无规则装配；grep 证实 `WithTokenExchangePolicy` 在 cmd 层零调用）
- 模块内持久化先例：`domains/tokenexchange/sqlite/chain_store.go:31,40`（`tokenexchange_chain_hops` 表 + `idx_tokenexchange_chain_hops_parent` 索引，root-module 包）
- 配置装配先例：`cmd/sso-server/serverbuildplatform/build_governance.go:197`（`BuildTokenPolicyStore`：file/inline 二选一 → store；file+inline 互斥报错）

**Proposed behavior**:
1. 新增 `domains/tokenexchange/sqlite/policy_store.go`：实现与第 1 点相同的可变接口。表 `tokenexchange_policy_rules`（`position` 保序、name/subject/actor/client/requested_token_type/deny 列 + `scopes`、`resources` 以 JSON 列存，规则为治理元数据无机密）。启动时全量载入内存快照；`Replace` 在单事务内 delete+reinsert 并原子换入快照（读路径零 I/O，保持 `Evaluate` 纯函数语义）；失败回滚且内存快照不变（fail-closed 于持久化错误）。
2. 配置扩展（`config/config_oauth2.go` 的 `OAuthTokenExchangeConfig`）：`backend`（`memory`/`sqlite`，跟随 `OAuthConfig.Backend` 先例）、`policies`（inline 规则列表）、`policies_file`（严格 YAML，互斥校验对照 `BuildTokenPolicyStore`）、sqlite 复用 `OAuthSQLiteConfig` 的 DSN。新增 `tokenexchange` 规则 YAML 解析器（对照 `domains/tokenpolicy/yaml.go`）。
3. cmd 装配：`build_app_oauth.go` 新增 `wireTokenExchangePolicy`（经 `serverbuildplatform` 新增 `BuildTokenExchangePolicyStore`，模式对照 `BuildTokenPolicyStore`），装配 `sso.WithTokenExchangePolicy` 并驱动第 1 点的管理端点挂载。
4. 契约同更：`docs/config-reference.md` 新增配置节；`docs/openapi.yaml` 的 admin 端点注明持久化语义。

**Acceptance check**:
- `domains/tokenexchange/sqlite` 新增测试：临时 DSN 下写入 → 关闭重开 → 规则集完整恢复且保序；`Replace` 事务中途失败（如注入约束冲突）时磁盘与内存均保持旧集；并发 `Allow` 在 Replace 期间无撕裂。
- 配置解析测试：inline 与 file 互斥、非法规则（空 Name / 未知字段）拒绝启动；`memory` backend 行为与现状 byte-identical。
- `make ci`（含嵌套模块、config、module 校验）通过；`docs/config-reference.md` 与 `docs/openapi.yaml` 更新随同一变更提交。

## 3. 匹配维度扩展：`Rule` 支持 scope/resource/requested_token_type

**Name**: Extend `Rule` matching dimensions to Scopes / Resources / RequestedTokenType.

**Problem**: `Hop` 上已解析好的最终维度——`Scopes`（"FINAL narrowed scope set"）、`Resources`（"FINAL merged resource/audience target list"）、`RequestedTokenType`——在 `ruleMatches` 中被**直接忽略**，规则只能用 subject/actor/client 三元组表达。最小权限治理最常用的表达「service A 不得以 scope X 冒用 service B」「不得交换到资源 Y」无法书写；管理员只能做粗粒度全量封禁或全量放行。这是第 1、2 点落地后策略表达力的硬缺口。

**Evidence**:
- `domains/tokenexchange/tokenexchange.go`（`Hop` 携带 Scopes/Resources/RequestedTokenType，注释明示 "FINAL narrowed scope set" / "FINAL merged resource/audience target list"；`ruleMatches` 仅比较 SubjectID/ActorSubject/ClientID 三字段）
- `Evaluate` 为 first-match-wins 纯函数（无 I/O 无时钟，全真值表可表驱动测试）
- 通配符语义先例：`domains/tokenpolicy/tokenpolicy.go`（selector `Scopes []string`，ALL 必须在场，尾部 `"*"` 前缀通配）

**Proposed behavior**:
1. `Rule` 新增三字段：`Scopes []string`、`Resources []string`、`RequestedTokenType string`（空 = 任意维度，与现有空字段通配语义一致；`Rule` 同时补 `json`/`yaml` tag，支撑第 1、2 点）。
2. 匹配语义（写进 `ruleMatches` 文档注释，作为约束）：
   - `Scopes`：ALL-of——hop.Scopes 必须为规则列表的超集，每项支持尾部 `"*"` 前缀通配（与 tokenpolicy selector 一致）；
   - `Resources`：ANY-of——hop 目标触及任一受管资源即匹配（deny 规则的防御性默认，封禁某个 audience 不应要求精确全等）；
   - `RequestedTokenType`：精确匹配，空 = 任意。
3. `Evaluate` 的 first-match-wins 与 `defaultAllow` 回退语义不变；现有三字段规则在新语义下行为完全不变（空新字段 = 通配，byte-compatible）。保持函数级预算：通配匹配逻辑提取为小辅助函数（如 `scopeMatches`/`resourceMatches`），`ruleMatches` 不超 50 行、复杂度不超 15。
4. 真值表补全 `tokenexchange_test.go`（含既有 `tokenexchange_types_test.go` 的 Hop 构造）。

**Acceptance check**:
- 新增表驱动用例：scope 前缀通配命中/不命中、部分 scope 子集不命中、resource ANY-of 命中、requested_token_type 精确匹配、deny 规则短路后续 allow 规则、空新字段规则与旧行为逐字节一致。
- `go test ./domains/tokenexchange/... -race` 通过；`go test -run 'TestMaintainability_|TestArchitecture_' .` 通过（无新文件、无预算越界）。
- 三改进联调 E2E：sqlite 持久化 + admin PUT 写入「client A + scope `admin:*` deny」规则 → 重启 → 带 `admin:read` scope 的交换被拒（`invalid_grant`，wire 不泄露规则细节），deny 理由仅出现在 audit 事件——同时满足第 3 点联动（方向文档第 3 项 deny 可观测性依赖本项的规则标识，列为后续方向，不在本次范围）。

---

**Scope guardrails**（AGENTS.md §5/§6）：三改进均为 `domains/tokenexchange` + `config` + `interfaces/sso`（现有文件）+ `cmd/sso-server`（现有文件）+ `docs/` 契约同更；不新增 `interfaces/sso` 文件（60 文件上限），`interfaces/sso` 内新代码进 `accessors_threat.go`/`server_routes_admin.go`。wire 面 oracle 安全不变：`/token` 失败仍坍缩为同一 `invalid_grant`，策略细节只进审计与 admin API。
