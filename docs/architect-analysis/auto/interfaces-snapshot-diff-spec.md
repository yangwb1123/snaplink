# 需求规格：interfaces/snapshot 方向 3 — 快照差异与漂移检测

来源：[interfaces-snapshot-analysis.md](docs/auto/interfaces-snapshot-analysis.md) 方向 3
（snapshot-vs-live / snapshot-vs-snapshot 对比）。方向 1（恢复安全化）与方向 2（凭据感知
恢复）不在本规格范围。

范围约束：

- wire 兼容：`proto/admin/v1` 是 STABLE 包（ADR-0008），只允许 additive 变更（新 RPC、
  新 message、新字段）；`ResourceCategory` 保持 string，不引入 schema bump。
- 导入方向：`interfaces/snapshot` → `platform/configaudit` 合法（先例
  `interfaces/sso/server_backup.go:64-65` 已确立 interfaces → platform 依赖）。
- 无新 `Err*` 哨兵，`docs/error-codes.md` 不变；端点/请求字段变更同步
  `docs/openapi.yaml`（AGENTS.md §5 第 6 条）。
- 文件预算：`snapshot/` 在 `engineering.yaml:43` 的 `ignore_pattern` 中，新增
  `diff.go`/`diff_test.go` 不触发文件数门；每文件仍 ≤500 行。
- 验证：每次 `.go` 编辑后 `go build ./... && go vet ./...` 与
  `go test -run 'TestMaintainability_|TestArchitecture_' .`；收尾 `go test ./... -race`
  与 `make ci`。

## 决策 1：条目级差异引擎 — dry-run 从计数升级为条目级 snapshot-vs-live 预览

**名称**：条目级 Snapshot Diff 引擎（纯函数）与 `Unchanged` 语义

**问题**：模块文档把"time-travel debugging（变更前打快照）"列为核心用例，但 dry-run
只产出每类别计数，回答不了"具体哪些 client/user/role 会变、每个条目变了什么"。更糟的是
现有 dry-run 的 `Updated` 语义是"目标中存在即 Updated"——即使内容完全相同，也无法区分
no-op 与真实变更，operator 无法据此审阅恢复影响面。

**证据**：

- `interfaces/snapshot/restorer.go` — `Report.Items map[ResourceCategory]CategoryCounts`
  与 `CategoryCounts{Inserted,Updated,Deleted,Skipped}` 只有计数，无条目级、无字段级。
- `interfaces/snapshot/restorer_clients.go` `upsertClient` dry-run 分支：
  `if _, err := r.Clients.Get(ctx, cl.ID); err == nil { c.Updated++ } else { c.Inserted++ }`
  —— 存在即计 `Updated`，不比较内容；`mergeClient` dry-run 同理只测存在性。
- `interfaces/snapshot/restorer_users.go` `mergeUser`/`userPresent` — 同样的存在性探测。
- `interfaces/snapshot/snapshot.go:8-9` 包注释 "Time-travel debugging (snapshot before a
  risky change)" — 声称的用例没有对应能力。
- `interfaces/snapshot/snapshotter.go` `exportResources` — 每个 category 的 Lister 已齐备
  （`Clients.List`/`Users.List`/`NetPolicy.List`/…），live 侧的输入来源现成。
- 身份键先例：`restorer_clients.go` `pruneClients` 按 `Client.ID`、`restorer_users.go`
  `pruneUsers` 按 `User.ID`、`restorer_roles.go` `indexRolesByClient` 按 `ClientID` +
  `permissions.Role.Code`、`domains/permissions/provider.go:64` `Assignment{UserID, Roles}`
  按 `(ClientID, UserID)`——diff 对齐必须与恢复语义一致，否则预览与实做会撒谎。

**拟议行为**：

1. 新增 `interfaces/snapshot/diff.go`：纯函数
   `func Diff(before, after *Snapshot, opts DiffOptions) (*DiffResult, error)`，不触任何
   后端。身份对齐键与 restorer 逐类别一致（clients→ID、users→ID、tenants→ID、
   tenant_domains/connections/netpolicy→各自标识、roles→(ClientID, Role.Code)、
   assignments→(ClientID, UserID)、menus→(ClientID, MenuTree)、pairwise→映射键）。
2. `DiffResult` 每类别输出条目列表：`{Category, ID, Status:
   inserted|updated|unchanged|deleted, Changes []FieldChange}`。`updated` 的判定用规范化
   JSON 比较（`json.Marshal` 对 map 键排序、slice 保序，字节比较稳定）；`Changes` 复用
   `platform/configaudit.Diff` 的 RFC 6902 patch（条目 marshal 为 `map[string]any` 后
   输入），字段路径形如 `/clients/{id}/redirect_uris`。
3. `CategoryCounts` 增加 `Unchanged int`（proto `CategoryCounts.unchanged` 同步新增，
   additive）。语义修正：dry-run 的 `Updated` 仅在内容实际不同时计数，内容相同计
   `Unchanged`。既有 `TestRestore_Overwrite_DryRun`
   （`restore_modes_test.go:330`，目标 client Name="Stale" 与快照不同）断言不受影响。
4. 敏感字段：diff 输入统一先过 `SnapshotRedactSecrets`（`Get` 端点同款，
   `admin_snapshots.go` `Get`），`Secret`/`RegistrationAccessToken`/用户口令属性永不进入
   diff 输出——diff 是只读检查面，不是凭据恢复通道。
5. 确定性保证：同一对输入两次 Diff 输出字节一致（排序稳定），供后续决策 3 的 digest
   复用。

**验收检查**：

- 新增 `interfaces/snapshot/diff_test.go`：相同快照 → 全类别零条目；目标仅增一个 client →
  `inserted` 条目含 ID；改 `redirect_uris` → `updated` 条目含 patch 路径；删 user →
  `deleted`；roles 按 (ClientID, Role.Code) 对齐；含 Secret 的 client 的 diff 输出不含
  Secret 值。
- dry-run 集成：既有 `TestRestore_Replace_DryRun_NoMutation`、
  `TestRestore_Overwrite_DryRun` 保持通过；新增断言"内容相同的目标 client 计
  `Unchanged` 而非 `Updated`"。
- `go build ./... && go vet ./...` 与 maintainability/architecture 测试通过。

## 决策 2：Compare RPC — snapshot-vs-snapshot 与跨节点漂移比对

**名称**：`SnapshotAdminService.Compare` 端点（快照间对比，消费 `SourceNodeID`）

**问题**：`SourceNodeID`/`SourceNamespace` 已为多节点溯源预留，但没有任何消费它们的对比
端点；五个 RPC 中无 compare 方法。跨环境（prod→staging 迁移、DR 副本 vs 主节点、
replace 恢复前后）的差异比对只能靠人肉，迁移遗漏从"可自动告警"退化为"事故后才发现"。
配置层已有完整的集群 diff 面（`handleConfigClusterDiff`），快照层缺失同等可观测性。

**证据**：

- `proto/admin/v1/snapshots.proto` — `SnapshotAdminService` 仅
  Export/List/Get/Restore/Delete 五个 RPC，无 compare 方法。
- `interfaces/snapshot/snapshot.go:52` `SourceNodeID string json:"source_node_id,omitempty"`
  与 `SourceNamespace` — 全仓唯一消费点是 `admin_snapshots.go:63` Export 写入与
  `admin_snapshots.go:523` meta 投影，无对比/漂移消费端。
- `interfaces/sso/server_backup.go:54-55` `mountConfigAuditAPI` 挂载
  `handleConfigDiff`/`handleConfigClusterDiff`；`platform/configaudit/handlers.go:94`
  `HandleClusterDiff` — "调用方自带 peer 快照、本端只算 diff"的先例模式，且其 POST body
  `ClusterDiffRequest{Snapshot map[string]any}` 证明"由调用方供给对端状态"不会引入新的
  出网能力。
- `docs/dr-framework.md` §7.1 `verify_integrity` — DR 演练只重算 envelope 内嵌 SHA-256
  （完整性），从不比对内容差异（漂移）；恢复 runbook 的验证手段是计数与 digest。
- `platform/configaudit/digest.go` `Digest` — 稳定 sha256（`json.Marshal` 排序保证）可
  直接复用为廉价漂移信号。

**拟议行为**：

1. proto 增加 `rpc Compare(CompareSnapshotsRequest) returns (CompareSnapshotsResponse)`，
   REST 路由 `POST /api/v1/admin/snapshots:compare`（集合级自定义动作，与
   `{id}:restore` 风格一致）。additive，无 schema bump。
2. 请求二选一：(a) `before_id` + `after_id`（两个已存快照，经 `Pipeline.Load` 解密）；
   (b) `id` + `live=true`（对当前节点跑 `Snapshotter.Export` 实时导出后对比，即
   snapshot-vs-live 的 wire 形态）。可选 `exclude` 类别过滤。
3. 响应：决策 1 的 `DiffResult` proto 投影（条目级 inserted/updated/deleted 列表 + 变更
   字段）+ 双方 `SnapshotMeta`（`source_node_id`/`source_namespace`/`taken_at_unix`）。
   双方 `SourceNodeID` 不同即跨节点漂移的机器可读证据；DR 场景可对比主节点快照与
   `dr.target_dir` 副本。输出先过 `SnapshotRedactSecrets`（与 `Get` 一致）。
4. 只读端点（`admin:read`），与 `Get` 一致不写审计事件；`before_id`/`after_id` 未知 →
   复用 `mapSnapshotError` 的 `NotFound` 映射。不新增出网能力——对端状态一律由调用方
   供给（`HandleClusterDiff` 同款模式）。
5. 附带 `snapshot.SnapshotDigest(s *Snapshot) (string, error)`：规范化 JSON sha256（模式
   同 `configaudit.Digest`），供外部自动化把"两节点快照是否一致"降为常量级比对。
   非目标：cluster bus 周期广播（`configaudit.DriftDetector` 的领地），不在本决策内。

**验收检查**：

- bufconn 集成测试（沿用 `interfaces/grpcserver/admin_snapshot_test.go:43`
  `startSnapshotGRPC` harness）：导出 A → 改一个 client、删一个 user → 导出 B →
  Compare(A,B) 返回对应 inserted/updated/deleted 条目与双方 `source_node_id`；
  Compare(A,A) 返回空 diff；`live=true` 反映当前 store 状态；未知 id → `NotFound`。
- `docs/openapi.yaml` 增加 `snapshots:compare` 端点与两个新 message 的 schema。
- `make ci` 通过（含 proto 生成校验）。

## 决策 3：恢复预览门与条目级审计证据 — replace 恢复前必算 preview 并落盘

**名称**：恢复前 preview 集成（operation ResultJSON + audit meta 条目级证据）

**问题**：`restoreTracked` 在 replace 非 dry-run 路径上，D1 安全快照 capture 之前只跑
`ValidateRestore`（合法性校验），没有任何"将要做什么"的审阅输出；审计事件只有 4 个标量
meta key，operation `ResultJSON` 存的是计数 Report——"3 inserted, 2 updated"无法作为
合规/事故复盘的可提交证据，恢复失败后也无法回溯"本要做什么"。

**证据**：

- `interfaces/grpcserver/grpcadmin/admin_snapshots.go` `restoreTracked` — 步骤顺序
  `load_snapshot → capture_safety_snapshot → apply_resources`，capture 前无 preview。
- 同文件 `restoreAuditMeta` — 仅 `safety_snapshot_id`/`auto_safety`/`committed`/
  `rolled_back`（+失败时 `rollback_error`）标量 key，无条目级信息。
- 同文件 `result, _ := json.Marshal(rep)` — `RestoreSnapshotResponse` 与
  `GetOperation`（`admin_paginate.go:251`）暴露的 `ResultJSON` 都是计数 Report。
- `interfaces/snapshot/restorer.go` `Report` — 无 diff/preview 字段。
- `platform/audit/auditreport/drift_test.go:46` — `EventSnapshotRestored` 已分类，复用
  无需新事件类型（AGENTS.md §4：新事件类型必须在 auditreport 分类，避免扩张）。
- AGENTS.md §4 — audit meta 须保持有界基数，条目全量不能进 meta，digest + 计数可进。

**拟议行为**：

1. `RestoreOptions` 增加 `Preview bool`；`Report` 增加 `Diff *DiffResult`。`Restore` 在
   任何写入（含 Phase A）之前用决策 1 的引擎计算条目级 diff 并填充 `Report.Diff`；
   dry-run 自动附带，`Preview=true` 的非 dry-run 也附带（默认 false，存量调用零行为
   变化）。
2. `restoreTracked` 在 `capture_safety_snapshot` 步骤之前（`ValidateRestore` 之后）计算
   preview，写入 operation `ResultJSON` 的 `preview` 段；失败路径
   （`failRestoreOperation`）同样保留该段——恢复失败后 `GetOperation` 仍可审计"本要
   做什么"，与既有"partial report 落 ResultJSON"的纪律一致（`admin_snapshots.go:314`）。
   零新端点。
3. `restoreAuditMeta` 增加两个固定 key：`diff_digest`（preview 规范化 JSON 的 sha256，
   复用决策 2 的 `SnapshotDigest`）与 `diff_summary`（`{inserted:N,updated:N,deleted:N,
   unchanged:N}` JSON 串）。固定 key 集、有界基数，符合 AGENTS.md §4；条目全量只进
   operation `ResultJSON`，不进 audit meta。
4. wire：`RestoreReport` 增加 `preview` 字段（additive）；`RestoreSnapshotResponse` 不回
   传 preview 正文（operator 经 `GetOperation` 取），保持响应体轻量。复用
   `EventSnapshotRestored`，不新增事件类型。
5. `docs/openapi.yaml` 的 `RestoreSnapshotRequest`/`RestoreReport` schema 同步
   `preview` 字段说明。

**验收检查**：

- 集成测试：replace 非 dry-run 恢复失败后 `GetOperation` 的 `ResultJSON` 含 `preview`
  段，且与同状态下独立 dry-run 的 diff 逐条目一致；`Preview=true` 的成功路径 `Report`
  携带 `Diff`。
- audit 断言：`EventSnapshotRestored` 事件 meta 含 `diff_digest` 与 `diff_summary`；
  同一状态两次 preview 的 digest 字节相同（可重放证据）。
- 既有 `TestRestore_Replace_DryRun_NoMutation`、`TestRestore_Overwrite_DryRun` 保持通过
  （Preview 默认关闭，行为不变）。
- `make ci` 通过。
