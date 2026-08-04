# Tokenpolicy 方向一规格：治理生命周期闭环（可写管理 API、持久化后端与规则校验）

Direction: 方向一 from `docs/auto/domains-tokenpolicy-analysis.md`. Scope is
strictly `domains/tokenpolicy` + its wiring seams; the three improvements below
form one lifecycle: rules enter validated (1), mutate through a writable admin
API (2), and live in a durable single source of truth (3).

Constraints honored (AGENTS.md §3/§5): evaluation stays fail-open on store
outage; oracle-safe wire responses unchanged (`invalid_scope`/`invalid_grant`
still generic); admin endpoints use `admin:read`/`admin:write`; new errors →
`docs/error-codes.md`, endpoints → `docs/openapi.yaml`, config knobs →
`docs/config-reference.md`. Budget check: `domains/tokenpolicy` currently has 6
non-test Go files (limit 10); additions stay within budget, `sqlite/` is a new
subdirectory at depth 3 (allowed), SQLite stays a root-module package
(precedent: `domains/threataction/sqlite`).

## 改进一：规则校验闭环——严格 YAML 解析 + `Policy.Validate` 语义校验 + 发行方默认 TTL 可见性

### 问题

规则加载没有任何校验，三处漂移/静默吞错并存：

1. `ParseYAML`（`domains/tokenpolicy/yaml.go`）用非严格 `yaml.Unmarshal`，
   未知字段被静默忽略——一个拼写错误的维度（如 `max_ttl_`）会让一条治理规则
   静默失效。同层 `conditionalaccess.LoadPolicies`
   （`domains/conditionalaccess/yaml.go`）用
   `yaml.UnmarshalWithOptions(..., yaml.DisallowUnknownField())` 且逐条调用
   `Policy.Validate()`，两域严格性漂移。
2. `Policy` 没有任何 `Validate()`（grep 确认全包无 Validate 逻辑）。负值
   `max_refresh_depth`/`max_active_sessions`、`require_renew_after: 2`（分数
   越界）都能入库；负深度在 `denyReason`（`domains/tokenpolicy/evaluate.go`）
   中 `in.RefreshDepth >= p.MaxRefreshDepth` 恒为 false，规则静默惰化。
3. `MaxTTL` 与发行方默认 TTL 的关系引擎不可见：
   `tokenpolicy.go` 的 `Policy.MaxTTL` 注释自认 "operators MUST set MaxTTL at
   or below the issuer's default lifetime (the engine cannot see that
   default)"。`clampTTL`（`evaluate.go`）对 `RequestedTTL == 0`（= 发行方默认
   哨兵）直接取 `MaxTTL` 为具体值——当 `MaxTTL > core.DefaultTokenTTL`
   （`shared/core/consts_oauth.go:134`，默认 1h）时，策略非但不收紧，反而把
   默认客户端的令牌寿命从 1h 静默拉长到 `MaxTTL`，违反"只收紧不放宽"的治理
   语义。

### 证据

- `domains/tokenpolicy/yaml.go` `ParseYAML`（裸 `yaml.Unmarshal`，1 处调用点）
- `domains/conditionalaccess/yaml.go` `LoadPolicies`（`DisallowUnknownField` +
  `Validate`，严格性对照）
- `domains/tokenpolicy/tokenpolicy.go` `Policy.MaxTTL` 注释（"engine cannot see
  that default"）
- `domains/tokenpolicy/evaluate.go` `clampTTL`、`denyReason`（负值/越界值静默惰化）
- `shared/core/consts_oauth.go:134` `DefaultTokenTTL = time.Hour`（发行方默认）

### 提议行为

- `ParseYAML` 改用 `yaml.UnmarshalWithOptions(data, &f, yaml.DisallowUnknownField())`
  并对每条规则调用新的纯函数 `Policy.Validate()`——与 conditionalaccess 对齐，
  未知字段/非法值在加载时响亮失败，而不是静默禁用规则。
- 新增 `Policy.Validate(defaultTTL time.Duration) error`（纯函数，无 I/O，沿用
  Evaluate 的可测试性）：
  - 硬错误（拒绝加载/写入）：`MaxRefreshDepth < 0`、`MaxActiveSessions < 0`、
    `MaxTTL < 0`、`RequireRenewAfter < 0 || > 1`。
  - 告警（不拒绝，但必须响亮）：`0 < MaxTTL && defaultTTL > 0 &&
    MaxTTL > defaultTTL`——该规则对默认客户端永不生效且会拉长寿命。
- 校验接入点（"启动/写入时双重校验"）：config 加载接线（`interfaces/sso`
  `WithTokenPolicy` / `TokenPolicyConfig`）与 admin PUT（改进二）都调用
  `Validate`；告警在启动时写 `logger.Warn`，写入时随 `error_description` 返回。
- 修复语义缺口：`ClampingIssuer`（`domains/tokenpolicy/clamp_issuer.go`）接线时
  携带发行方默认 TTL，使引擎"看到默认值"——`RequestedTTL == 0` 时
  `EffectiveTTL = min(MaxTTL, defaultTTL)`，`MaxTTL` 永远无法把默认客户端的
  寿命拉到发行方默认之上（保持 downward-only）。

### 验收检查

- `yaml_test.go`/`evaluate_test.go` 表驱动用例：未知 YAML 字段 → 解析错误；
  `max_refresh_depth: -3`、`require_renew_after: 2` → `Validate` 错误；
  `max_ttl: 2h` + `defaultTTL: 1h` → 返回告警（非静默）；现有合法 fixture
  解析结果字节不变。
- 接线层：配置了 `MaxTTL > 发行方默认` 的服务器启动时打印 warning 日志；
  默认客户端（`RequestedTTL==0`）签发 TTL ≤ 发行方默认。
- 现有 `clamp_issuer_test.go`、`rootcov_token_policy_enforce_test.go` 全绿
  （无回归：合法 `MaxTTL ≤ default` 的行为不变）。

## 改进二：可写管理 API——`Store` SPI 写方法 + PUT/DELETE 端点

### 问题

tokenpolicy 是"启动时灌入、只读展示"的静态治理面。`Store` 接口
（`domains/tokenpolicy/tokenpolicy.go`）只有 `Policies()`；全库唯一的写入口
`memory.Store.Replace`（`domains/tokenpolicy/memory/store.go`）经 grep 确认在
非测试代码中零调用方（无热重载、无 admin 写端点）。admin 侧仅
`HandleAdminPolicies`（`domains/tokenpolicy/admin.go`，GET-only），
`docs/openapi.yaml:6836` 的 `/api/v1/admin/token-policies` 只有 `get` 操作。
运维调策略必须改配置、重启/重推全部副本，无热调整、无按规则查看/删除、无
回滚路径。同层治理域 threataction 已有完整生命周期先例：
`ThreatPolicyStore`（`domains/threataction/policy.go:238`）=
List/Get/Put/Delete，`HandleAdminPutPolicy`/`HandleAdminDeletePolicy`
（`domains/threataction/admin.go`）带 decode-vs-semantic 错误拆分
（`ErrInvalidRequest` vs `ErrInvalidPolicy`，`shared/core/errors.go:313`），
`interfaces/sso/sso.go:489-498` 以 `admin:write` 门控。

### 证据

- `domains/tokenpolicy/tokenpolicy.go` `Store` 接口（仅 `Policies`）
- `domains/tokenpolicy/memory/store.go` `Replace`（零调用方）
- `domains/tokenpolicy/admin.go` `HandleAdminPolicies`（GET-only）
- `docs/openapi.yaml:6836`（仅 `get` 操作）
- `domains/threataction/policy.go:238` `ThreatPolicyStore`（List/Get/Put/Delete
  接口形状先例）、`domains/threataction/admin.go` `HandleAdminPutPolicy`/
  `HandleAdminDeletePolicy`（校验 + 错误拆分先例）、
  `domains/threataction/policy.go:234` `ErrPolicyNotFound`（404 先例）

### 提议行为

- 扩展 `Store` 接口（镜像 `ThreatPolicyStore`）：
  `Get(ctx, name) (Policy, error)`、`Put(ctx, Policy) error`、
  `Delete(ctx, name) error`；新增 `ErrPolicyNotFound` 哨兵。`Policies()` 的
  只读契约与 COW 语义不变（热路径读取不被写操作打扰）。
- `memory.Store` 改为按 Name 键控（map + COW 快照），`Replace` 保留为
  config 启动播种的批量路径；admin 写操作走新的 Put/Delete。
- 新增 admin 处理器（镜像 threataction 的 decode-vs-semantic 拆分）：
  - `PUT /api/v1/admin/token-policies/:name`（`admin:write`）：JSON 解码失败 →
    `400 invalid_request`；`Validate`（改进一）失败 → `400 invalid_policy` +
    `error_description`（含 MaxTTL-vs-default 告警文案）；成功 → 200 + 回显规则。
    `Name` 以路由参数为准（同 `HandleAdminPutPolicy` 的 `policy.Name = name`）。
  - `DELETE /api/v1/admin/token-policies/:name`（`admin:write`）：未知 name →
    `404 not_found`（`ErrPolicyNotFound`）；成功 → 200。
  - `GET /api/v1/admin/token-policies/:name`（`admin:read`）：单规则查看。
- 接线：`interfaces/sso/sso.go` 在 `WithTokenPolicy` 挂载分支下注册新路由
  （保持"未接线则 404 不挂载"的既有测试语义）；admin 前缀中间件提供
  `admin:write` 门控与 `Bearer realm="admin"` 401。
- 同变更更新契约：`docs/openapi.yaml` 新增 get-by-name/put/delete 三个操作；
  `docs/error-codes.md` 记录 `invalid_policy` 在本端点的新用途；
  `docs/config-reference.md` 说明 config 播种集与 admin 写集的优先级
  （admin 写覆盖播种集）。

### 验收检查

- `memory/store_test.go`：Put/Get/Delete 往返、按名覆盖、Delete 未知名 →
  `ErrPolicyNotFound`、Put 并发期间 `Policies()` 读到旧快照不撕裂
  （`-race` + `-count=10+`）。
- 服务器级（扩展 `interfaces/sso/rootcov_admin_token_policies_test.go`）：
  PUT 后 GET 列表含新规则；DELETE 后消失；非法 body → 400 `invalid_request`；
  负深度 → 400 `invalid_policy`；无 `WithTokenPolicy` 时 PUT/DELETE 路由 404；
  非 admin 令牌 → 401 realm=admin。
- `docs/openapi.yaml` 校验通过（`make ci` 含 openapi 检查）。

## 改进三：持久化后端——SQLite `Store` 作为多副本单一事实源

### 问题

唯一的 `Store` 实现是内存 COW 快照（`domains/tokenpolicy/memory/store.go`）：
每个副本各自持有启动时播种的独立快照。改进二落地后，admin 写入的规则在
重启后丢失、在多副本间发散——"无单点真相"。同层兄弟域已解决此问题：
`domains/threataction/sqlite/policy_store.go`（"The memory store loses every
admin-authored policy on restart; this backend persists them so a
threat-response policy list survives a redeploy and is shared across replicas
pointed at the same database file"，单表 `name TEXT PRIMARY KEY` + JSON 列，
`platform/migrate` 版本化迁移）与 `domains/tokenexchange/sqlite/chain_store.go`
同为先例。`TokenPolicyConfig`（`config/config_snapshot.go:298`）只有
`File`/`Policies` 二选一，无持久化选项。

### 证据

- `domains/tokenpolicy/memory/store.go`（仅内存实现）
- `domains/threataction/sqlite/policy_store.go`（sqlite 持久化 + 迁移先例）
- `domains/tokenexchange/sqlite/chain_store.go`（同层第二先例）
- `config/config_snapshot.go:298` `TokenPolicyConfig`（File/Policies 二选一，
  无 DB 来源）
- `interfaces/sso/server_invalidation.go`（跨副本失效总线先例：发布事件 →
  对端重读/清缓存）

### 提议行为

- 新增根模块包 `domains/tokenpolicy/sqlite`，实现扩展后的 `Store`（含改进二
  的 Get/Put/Delete）：单表 `token_policies (name TEXT PRIMARY KEY,
  policy_json TEXT NOT NULL)`，整条 `Policy` JSON 落列（镜像 threataction——
  无 SQL WHERE 查询需求，扁平化只增迁移面）；迁移用 `platform/migrate`
  版本化（baseline v1），`modernc.org/sqlite` 纯 Go 驱动（已是根模块依赖）。
- 配置接线：`TokenPolicyConfig` 新增 `sqlite` DSN 选项，与 `File`/`Policies`
  互斥（沿用"歧义来源是配置错误"的既有规则）；启动时若表为空则以
  config/File 播种一次，此后 admin 写集为唯一事实源。
- 热路径契约不变：`Policies()` 失败仍 FAIL OPEN（照常签发）；sqlite store
  维护一份内存快照并在失效事件/写操作后刷新，`Policies()` 不每请求落盘。
- 跨副本一致性：admin PUT/DELETE 成功后经失效总线发布 `token-policy` 类事件
  （对齐 server_invalidation.go 的发布模式），对端副本刷新快照；总线故障
  FAIL OPEN（副本在下一次 `Policies()` 时重读）。AGENTS.md 的跨副本失效清单
  随之扩展并同步到该处注释/文档。
- 同变更更新 `docs/config-reference.md`（新配置节）。

### 验收检查

- `domains/tokenpolicy/sqlite` 测试：CRUD 往返；关闭后重开 DB 规则存活
  （重启持久化）；迁移幂等（重复初始化无错）；并发 Put/Policies
  `-race` 干净。
- 集成（`test/`，`package ssotest`）：两个服务器实例共享同一 DB 文件——
  经实例 A 的 admin API PUT 后，实例 B 的 GET 可见（失效刷新后）；重启
  实例 B 规则仍在。
- `make ci` 全绿（sqlite 留在根模块，不触发嵌套模块规则；`go build ./... &&
  go vet ./...` 与架构层测试先行通过）。
