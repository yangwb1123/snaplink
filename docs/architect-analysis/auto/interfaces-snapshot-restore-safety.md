# Requirements Spec: interfaces/snapshot 恢复安全化（原子性/回滚 + 恢复前自动安全快照）

> 来源：`docs/auto/interfaces-snapshot-analysis.md` 方向 1。本文是需求规格（intent），
> 实现与验收以可执行代码和提交的门禁为准。范围限定在恢复（Restore）路径的安全化，
> 不含方向 2（凭据/MFA 可移植性）与方向 3（快照差异比对）。
>
> 原则：复用现有 `Snapshotter.Export` + `Pipeline.Save/Load`（DR 复制器
> `platform/lifecycle/dr` 已证明此组合可复用，见 `dr-framework.md` §4）；新增字段全部
> additive（proto `optional`/新字段、JSON `omitempty`），schema 保持 `"2"`；失败语义
> 遵循 AGENTS.md §3 的 fail-closed 纪律。

## 范围与现状

- `Restorer.Restore`（`interfaces/snapshot/restorer.go`）逐类别执行 `restorePlan`，
  首个硬错误即返回 `(rep, err)`，**此前已应用的类别保持生效**；`Report` 只有计数与
  `Errors []string`，无 committed/applied 状态。
- `ModeReplace` 是"先删除、后插入"：`restoreClients`→`pruneClients`、
  `restoreUsers`→`pruneUsers`、`restoreTenants`→`pruneTenants`、
  `restoreConnections`→`pruneConnections`、`restorePairwise`→`prunePairwise`、
  `restoreAssignments`→`pruneAssignments` 均在类别内先删后插；`restorePlan` 的
  类别顺序中 assignments 是倒数第二类，netpolicy 是最后一类——在这两类失败时，
  clients/users 等早已被 wipe。
- `interfaces/grpcserver/grpcadmin/admin_snapshots.go` 的 `restoreTracked` 用
  `operations.Store` 做步骤簿记（`Start`/`BeginStep`/`FinishStep`/`Finish`），
  `failRestoreOperation` 只把操作标记为失败——**没有 undo 路径**；
  `Operation.Compensations []Step` 字段（`platform/lifecycle/operations/operations.go`）
  存在但从未被本 surface 使用。
- `RestoreInvalidator.InvalidateRestoredControlPlane()` 仅在全部类别成功后才调用
  （`restorer.go` `Restore` 尾部）——部分应用后原存储已变但缓存不失效，且无任何
  恢复状态可观测信号。

预算检查：`restorer.go` 474 行、`snapshotter.go` 471 行，均接近 500 行上限；
下述实现的新代码必须落到新文件（`restorer_stage.go`、`restorer_safety.go` 等），
不得把 `restorer.go` 推过 500 行。`interfaces/sso` 60 文件上限不涉及本模块。

---

## 决策 1：恢复前自动安全快照（Pre-Restore Safety Snapshot）

### 名称

**恢复前自动安全快照** — `ModeReplace` 非 dry-run 恢复前，先用现有
`Snapshotter`+`Pipeline` 导出目标节点当前状态并落库，作为内建回退工件。

### 问题

破坏性恢复没有任何"恢复前状态"留存：`restoreTracked` 的 `operations.Store` 步骤是
重启持久的审计簿记，不是 undo 数据；一旦 wipe 后 insert 中途失败，目标节点处于
半应用状态且**没有任何可回退的快照**。`SnapshotAdminService` 同时持有了
`pipeline`、`storage`、`snapshotter`、`restorer` 四个依赖（`NewSnapshotAdminService`，
`cmd/sso-server/main_servers.go:232`、`build_http.go:463` 装配），但 `Restore` 路径
从不使用 `snapshotter`——捕获成本几乎为零，却完全缺失。

### 证据

- `interfaces/grpcserver/grpcadmin/admin_snapshots.go`：`restoreTracked` 仅做
  `operations.Start/BeginStep/FinishStep/Finish` 簿记；`failRestoreOperation` 只
  `operations.Finish(..., mapped)`，无补救步骤。
- `interfaces/snapshot/snapshotter.go`：`Snapshotter.Export(ctx, ExportOptions)` 已存在
  （`cmd` 默认装配 `DefaultExportRedactor`，但 per-call `Redactor` 覆盖优先，
  `effectiveRedactor` 实现该语义；`RedactorFunc` 类型已存在，可传显式 no-op）。
- `interfaces/snapshot/pipeline.go`：`Pipeline.Save/Load` + `Storage` 已由 `Export` RPC
  与 `platform/lifecycle/dr` 复制器复用。
- `interfaces/snapshot/retention.go`：`PruneOldest` 按 `snap_` 前缀 + 时间序清理最旧
  快照——无保护时安全快照可能在被回滚前就被 retention 扫掉。
- `interfaces/snapshot/snapshot.go`：`Snapshot` 无 kind/用途标记，无法区分
  "普通导出"与"安全快照"。

### 建议行为

1. `Snapshot` 增加 additive 字段 `Kind string`（`json:"kind,omitempty"`），常量
   `KindSafetySnapshot = "safety"`。`SchemaVersion` 保持 `"2"`（旧读者忽略未知字段；
   无 schema bump）。
2. `RestoreOptions` 增加 `AutoSafetySnapshot bool`，SDK 默认值：`Mode == ModeReplace &&
   !DryRun` 时为 true，否则 false；`prepareRestore` 校验：replace + 非 dry-run +
   `AutoSafetySnapshot == false` 视为显式 opt-out（仅允许在显式确认下，见下）。
3. gRPC/REST 面（`RestoreSnapshotRequest` 增加 `google.protobuf.BoolValue
   auto_safety_snapshot`，三态：nil=服务器默认，false=显式 opt-out）：
   - `restoreTracked` 在 `apply_resources` 步骤之前新增 `capture_safety_snapshot`
     步骤：`snapshotter.Export(ctx, ExportOptions{SourceNodeID: <本节点>, Redactor:
     RedactorFunc(func(*Snapshot){})})`（显式 no-op 覆盖 `DefaultExportRedactor`——
     脱敏快照不可用于恢复，安全快照与目标快照同属一个信任域/存储），随后
     `pipeline.Save(ctx, snap, storage, snap.SnapshotID)`，并给快照打
     `Kind = KindSafetySnapshot`。
   - 响应 `RestoreSnapshotResponse` 增加 `safety_snapshot_id`；`Operation.ResultJSON`
     与 `EventSnapshotRestored` 审计事件经 `audit.SetMeta`（不新增事件类型，保持
     `auditreport` 有界基数）携带 `safety_snapshot_id` 与 `auto_safety=false`（opt-out 时）。
   - snapshotter 未装配且未显式 opt-out → `FailedPrecondition`，**在写入任何存储之前**
     拒绝恢复（fail-closed）。
   - `RestoreOptions.AutoSafetySnapshot == false` 时，`Restore` 恢复自身不触发捕获；
     `restoreTracked` 层面再由显式 opt-out 决定。
4. 递归防护：`pipeline.Load` 出的快照 `Kind == KindSafetySnapshot` 时，恢复它不再
   触发新的安全快照（回滚自身不得再产生安全快照）。
5. Retention 保护：`PruneOldest` 跳过 `Kind == KindSafetySnapshot` 的条目（回滚窗口
   内不被自动清理）；清理走显式 `Delete` RPC（文档写明：回滚窗口结束后由 operator
   删除，或后续迭代加 TTL）。
6. 范围边界：dry-run 恢复永不捕获；merge/overwrite 默认不捕获（无删除语义），
   `AutoSafetySnapshot` 可在 SDK 层显式开启。

### 验收检查

- Given 目标节点有 N 个 client、M 个 user（含既有 role/assignment/netpolicy），
  When 经 gRPC 执行 `mode=replace, dry_run=false` 恢复，Then `storage.List` 恰好新增
  1 个 `snap_*` envelope，`Pipeline.Load` 解码后各 category 与恢复前各 store
  `List()` 结果逐项相等（顺序无关），响应 `safety_snapshot_id` 等于该 ID，
  `EventSnapshotRestored` 审计元数据携带该 ID。
- Given 上述安全快照，When 以它自身为源执行 replace 恢复（confirm=其 ID），
  Then 目标节点回到恢复前状态，且**没有**产生第二个安全快照（递归防护）。
- Given `PruneOldest(keep=0)`，When 存储中含 safety-kind 快照，Then 安全快照不被删除，
  显式 `Delete` RPC 可删除。
- Given snapshotter 未装配且未显式 opt-out，When 发起 replace 恢复，Then 返回
  `FailedPrecondition` 且所有 store 零写入。
- Given `auto_safety_snapshot=false` 显式 opt-out，When 发起 replace 恢复，Then 恢复
  正常执行但审计元数据记录 `auto_safety=false`。

---

## 决策 2：破坏性操作延迟提交（Stage-Then-Prune 原子性）

### 名称

**两阶段恢复：非破坏性暂存（stage）先行，破坏性删除（prune）最后提交** —
把 `ModeReplace` 的"先删后插"改为"先插后删"，使中途失败的状态要么是
"旧状态超集"（安全、可重试），要么是"目标状态超集"（可续跑收敛），从根上消除
"半 wipe"状态。

### 问题

`restorePlan` 逐类别执行且每个类别内 `prune*` 先于插入。跨存储（`ClientStore`、
`UserProvider`、`permissions.Provider`、`tenant.Store`、`connections.Store`、
`netpolicy.Store`、`PairwiseSubjectStore`）不存在分布式事务，原子性只能靠
**操作排序 + 幂等重试**实现；当前排序把唯一不可逆的操作（Delete/UnassignRoles）放在
最前，一次后端故障（如 `restoreAssignments` 的 `AssignRoles`/`ListAssignments` 错误，
或 `restoreNetPolicy` 错误）就把已 wipe 的早期类别留在原地。

### 证据

- `interfaces/snapshot/restorer.go`：`restorePlan` 返回 10 个 `catRunner`（tenants →
  tenant_domains → connections → clients → users → pairwise → roles → menus →
  assignments → netpolicy），每个 runner 内 `pruneX` 在插入循环之前；`Restore` 对
  首个错误直接 `return rep, fmt.Errorf(...)`，此前类别保持应用。
- `interfaces/snapshot/restorer_clients.go`：`restoreClients` 先调 `pruneClients`
  （`r.Clients.Delete` 循环）再 `upsertClient`；`restorer_users.go` `pruneUsers` 同理。
- `interfaces/snapshot/restorer_assignments.go`：`pruneAssignments` →
  `pruneClientAssignments`（`Permissions.UnassignRoles`）先于 upsert。
- 幂等性已具备：`mergeClient`/`upsertClient`（`Add` + `ErrClientExists` → `Update`）、
  `mergeUser`/`upsertUser`（`CreateOrUpdate`）、`AssignRoles`/`PutTenant`/
  `Upsert` 均可重放；`prune*` 全部基于快照 keep-set（纯函数，不依赖插入结果），
  天然幂等。

### 建议行为

1. `Restorer.Restore` 对 `ModeReplace` 拆两阶段（实现放新文件 `restorer_stage.go`，
   避免 `restorer.go` 超 500 行预算）：
   - **Phase A（stage）**：按 `restorePlan` 顺序只执行各类别的 insert/update/upsert
     （跳过所有 `prune*`）。失败 → 目标节点是旧状态超集（旧记录一个未删），
     重试安全。
   - **Phase B（commit）**：Phase A 全部成功后，才执行所有类别的 `prune*`。失败 →
     目标节点是目标状态超集（部分删除），对同一快照重试整个恢复即可收敛
     （Phase A 重放为幂等 upsert，Phase B 补删剩余）。
2. 能力预检前移：`prunePairwise`/`pruneConnections` 等依赖 `Lister`/`Deleter` 能力
   接口（`ErrUnsupportedRestore`）的检查移入 `prepareRestore`（replace 模式下对全部
   将删类别预检），保证"后端不支持删除"仍在**零写入**时失败，而不是阶段拆分后
   变成"先插后报错"。
3. `Report` 增加 `Committed bool`（Phase B 完成才置 true）；阶段拆分不改变成功路径
   的 `CategoryCounts` 语义（回归不变）。
4. dry-run 不变（纯计数、零写入）。

### 验收检查

- Given 注入 `permissions` 后端在第 K 次 `AssignRoles` 时返回错误，When 执行
  replace 恢复，Then 返回 error、`Report.Committed == false`，且所有类别
  `Deleted == 0`、各 store `List()` 与恢复前完全一致（旧状态超集，零删除）。
- Given 注入 `ClientStore.Delete` 在第 2 个 client 时返回错误（Phase B 中途失败），
  When 执行 replace 恢复，Then 所有插入已生效、第 1 个删除已生效、其余保留；
  When 以同一快照重试同一恢复，Then 成功且最终状态与一次性成功执行的终态逐项相等。
- Given 某类别后端缺少删除能力（如无 `PairwiseSubjectDeleter`），When 发起 replace
  恢复，Then `ErrUnsupportedRestore` 在**任何写入之前**返回（零写入）。
- Given 干净目标节点 + replace 恢复，When 无故障执行，Then `CategoryCounts` 与拆分前
  行为完全一致（回归）。

---

## 决策 3：失败自动回滚与恢复状态可观测性（RollbackOnError + Committed/RolledBack）

### 名称

**失败自动回滚与部分应用状态暴露** — 恢复失败时可选地自动用决策 1 的安全快照
回滚，并在 `Report`/RPC/operation/审计四层显式暴露
"已提交 / 已回滚 / 部分应用"三态。

### 问题

`Restore` 失败后调用方无法判断目标节点处于"未变 / 半应用 / 已应用"哪种状态：
`Report` 无 committed 标志，gRPC 错误路径连 report 都不返回（`restoreTracked` 直接
`failRestoreOperation`）；`RestoreInvalidator` 只在全成功时触发，半应用状态既改了
原始存储又不失效缓存；`operations.Store` 的操作记录没有补偿步骤，回滚只能靠人工
逐类别排查——这正是分析文档所述"小时级人工排错"的来源。

### 证据

- `interfaces/snapshot/restorer.go`：`Restore` 循环中 `rep.Errors = append(...)` 后
  `return rep, fmt.Errorf(...)`；`Invalidator.InvalidateRestoredControlPlane()` 在
  循环成功后才调用（`if !opts.DryRun && r.Invalidator != nil`）；`Report` 结构体无
  committed/rolled-back 字段。
- `interfaces/grpcserver/grpcadmin/admin_snapshots.go`：`restoreTracked` 错误路径
  `failRestoreOperation` 只做 `operations.Finish(..., mapped)`，无补偿步骤、无
  report 随错误返回。
- `platform/lifecycle/operations/operations.go`：`Operation.Compensations []Step`
  字段已存在（`StateFailed`/`StateSucceeded` 语义齐备），本 surface 从未使用——
  回滚簿记的现成槽位。

### 建议行为

1. `RestoreOptions` 增加 `RollbackOnError bool`；`prepareRestore` 校验：
   `RollbackOnError && !AutoSafetySnapshot` → 校验错误（无安全网不得自动回滚），
   零写入。
2. `Report` 增加 `Committed bool`、`RolledBack bool`、`SafetySnapshotID string`；
   `reportToProto` 同步投影（`RestoreReport` 加 additive 字段）。
3. `restoreTracked` 编排（错误路径）：
   - `restorer.Restore` 返回 error 且 `RollbackOnError` 时：`BeginStep
     "rollback_safety_snapshot"` → `pipeline.Load(safetyID)` →
     `restorer.Restore(ctx, safetySnap, RestoreOptions{Mode: ModeReplace,
     Confirm: safetySnap.SnapshotID, AutoSafetySnapshot: false,
     RollbackOnError: false})`（递归防护由决策 1 的 Kind 守卫 + 显式关闭双重保证）。
   - 回滚成功后：向 `Operation.Compensations` 追加 `Step{Name:
     "rollback_safety_snapshot", State: StepSucceeded}`（`operations` 包需暴露
     append 辅助或直接操作 `Operation` 值），调用
     `Invalidator.InvalidateRestoredControlPlane()`（状态又变了，必须再失效），
     `operations.Finish` 以失败态收尾但 `ResultJSON` 携带
     `{rolled_back: true, safety_snapshot_id}`，返回的 error 经 `mapSnapshotError`
     后带前缀 `restore <id> rolled back to safety snapshot <sid>`——RPC 仍失败
     （fail-closed：调用方必须知道恢复未生效），但状态已安全。
   - 回滚自身失败（如安全快照被删/校验失败）：补偿步骤记
     `StepFailed`，返回错误明确说明"回滚失败、目标状态未知"（不得声称已恢复），
     审计元数据记 `rolled_back=false, rollback_error=...`。
4. 审计与运维：`EventSnapshotRestored` 经 `audit.SetMeta` 携带 `rolled_back`、
   `safety_snapshot_id`、`committed`；不回滚路径（`RollbackOnError=false`）行为与
   现状完全一致（部分应用 + error，向后兼容）。
5. 范围边界：本决策的编排在 gRPC/REST 层（`restoreTracked`）；SDK 直接调用
   `Restorer.Restore` 的路径（`platform/lifecycle/dr` 的 `StateRestorer` 适配、
   `bootstrap-restore-from`）仅获得 `Report.Committed/RolledBack` 字段，不强制编排。

### 验收检查

- Given 注入 `restoreAssignments` 失败 + `RollbackOnError=true`，When 执行 replace
  恢复，Then RPC 返回非 nil error 且消息含 `rolled back to safety snapshot`；各 store
  `List()` 与恢复前逐项相等；`operations.Store.Get(opID)` 的 `Compensations` 含
  `rollback_safety_snapshot`（state=succeeded）；`RestoreReport.RolledBack == true`、
  `Committed == false`；审计元数据 `rolled_back=true`；invalidator 探针被调用两次
  （apply 失败前不调、回滚成功后调一次）。
- Given `RollbackOnError=true, AutoSafetySnapshot=false`（SDK 层），When 发起恢复，
  Then `prepareRestore` 返回校验错误且零写入。
- Given 安全快照被删除后（`pipeline.Load` 失败），When 恢复中途失败且
  `RollbackOnError=true`，Then 操作记为失败、补偿步骤 state=failed、错误消息声明
  "rollback failed"，不得声称已恢复。
- Given `RollbackOnError=false`（默认），When 恢复中途失败，Then 行为与现状一致：
  部分应用保留、error 返回、`Report.Committed == false`（向后兼容）。

---

## 文档与契约联动（同一次变更内完成）

- `proto/admin/v1/snapshots.proto`：`RestoreSnapshotRequest.auto_safety_snapshot`
  （BoolValue）、`RestoreSnapshotResponse.safety_snapshot_id`、`RestoreReport`
  的 `committed/rolled_back/safety_snapshot_id`——全部 additive，无 schema bump。
- `docs/openapi.yaml`：Restore 端点请求/响应新字段；`docs/error-codes.md`：新增
  `ErrRollbackWithoutSafety`（校验类）与恢复回滚状态的错误描述。
- `docs/dr-framework.md`：§4/§6 runbook 补充"恢复前自动安全快照 + 失败自动回滚"
  行为与安全快照清理指引。
- 审计：不新增事件类型（`audit.SetMeta` 元数据承载），`auditreport` 无需改分类；
  若后续需要独立事件，须先在 `auditreport` 分类并保持有界基数。

## 验证计划

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/snapshot/... ./interfaces/grpcserver/grpcadmin/... -race
go test ./test/ -run TestE2E -v
make ci
```

针对性测试：故障注入（阶段 A/B 各自中途失败、回滚失败、能力缺失预检）、
安全快照往返一致性、retention 保护、递归防护、向后兼容（`RollbackOnError=false`）。
