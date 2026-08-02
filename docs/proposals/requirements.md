已产出需求规格，写入 `docs/auto/interfaces-snapshot-diff-spec.md`（与来源分析文档同目录，沿用 `docs/auto/` 既有 spec 命名惯例）。规格聚焦方向 3，含 3 个证据支撑的决策：

## 决策 1：条目级差异引擎（snapshot-vs-live）
- **问题**：`Report.Items`/`CategoryCounts` 只有计数；`upsertClient` dry-run 分支（`restorer_clients.go`）"目标存在即 `Updated++`"，无法区分 no-op 与真实变更；包注释宣称的 time-travel 用例无能力支撑。
- **拟议**：新增纯函数 `snapshot.Diff(before, after *Snapshot)`（`diff.go`），身份对齐键与 restorer 各类别一致（`Client.ID`/`User.ID`/`(ClientID, Role.Code)`…）；`CategoryCounts` 增加 `Unchanged`，`Updated` 仅在内容不同时计数；字段级变更复用 `configaudit.Diff` 的 RFC 6902 patch（导入方向合法，先例 `server_backup.go`）；diff 输入先过 `SnapshotRedactSecrets`。
- **验收**：`diff_test.go` 覆盖零变更/增/改/删/红action；既有 dry-run 测试保持通过。

## 决策 2：Compare RPC（snapshot-vs-snapshot / 跨节点漂移）
- **问题**：proto 五个 RPC 无 compare；`SourceNodeID`/`SourceNamespace`（`snapshot.go:52`）全仓无消费端；DR 演练只验 SHA-256 完整性（`dr-framework.md` §7.1）不验内容差异；配置层 `handleConfigClusterDiff` 已有先例。
- **拟议**：`rpc Compare`（`POST /api/v1/admin/snapshots:compare`），`before_id`+`after_id` 或 `id`+`live=true`；响应为 DiffResult 投影 + 双方 `SnapshotMeta`（source_node_id 不同即漂移证据）；对端状态由调用方供给（`HandleClusterDiff` 模式，零新出网能力）；附带 `SnapshotDigest` 供廉价漂移检测；cluster bus 广播列为非目标。
- **验收**：bufconn 测试（沿用 `admin_snapshot_test.go` harness）+ openapi 更新。

## 决策 3：恢复预览门与条目级审计证据
- **问题**：`restoreTracked` 在 D1 capture 前只跑 `ValidateRestore`，无"将要做什么"的审阅输出；`restoreAuditMeta` 仅 4 个标量 key；`ResultJSON` 是计数 Report，无法作为合规证据。
- **拟议**：`RestoreOptions.Preview` + `Report.Diff`（默认关闭，存量零变化）；`restoreTracked` 在 capture 前算 preview 并写入 operation `ResultJSON.preview` 段（失败路径也保留）；audit meta 增加 `diff_digest` + `diff_summary` 两个固定 key（有界基数合规）；复用 `EventSnapshotRestored`，不新增事件类型。
- **验收**：失败恢复的 ResultJSON 含 preview 且与独立 dry-run 一致；digest 可重放稳定。

关键约束已写入规格头部：proto 仅 additive（ADR-0008）、无新 `Err*`、`snapshot/` 在 `engineering.yaml:43` ignore_pattern 中不触发文件数门、每次 `.go` 编辑后跑构建与架构门。本次为纯文档变更，未触碰 Go 代码。
