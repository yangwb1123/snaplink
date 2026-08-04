我已经全局扫描了 `interfaces/snapshot/`（约 5400 行，含 pipeline、snapshotter、restorer、codec、redactor、retention、loader、storage/encryption 后端）、其 gRPC/REST 暴露层（`proto/admin/v1/snapshots.proto`、`interfaces/grpcserver/grpcadmin/admin_snapshots.go`）、`cmd/sso-server` 的装配与调度、DR 框架（`platform/lifecycle/dr`、`docs/dr-framework.md`）以及相关 store 接口。基于现状，以下是 3 个最高价值的改进方向。

## 方向 1：恢复安全化 — 原子性/回滚与恢复前自动安全快照

**问题**：`Restorer` 是逐类别、非事务地应用快照的，且 `ModeReplace` 是"先删除、后插入"（`restorer.go` 的 `restorePlan`、`restorer_clients.go` 的 `pruneClients`、`restorer_users.go` 的 `pruneUsers`）。一旦在 wipe 之后、insert 完成之前失败（如 `restoreAssignments` 中途遇到后端错误），目标节点就处于半应用状态，没有任何内置回滚手段。`operations.Store` 日志（`admin_snapshots.go` 的 `restoreTracked`）只是重启持久的审计簿记，不提供 undo；恢复前也不会自动生成一个"恢复前快照"供回退。

**证据**：`interfaces/snapshot/restorer.go`（`Restore` 返回部分 `Report` + error 后继续、无事务边界）；`pruneClients`/`pruneTenants`/`pruneConnections` 全部是 delete-first；`interfaces/grpcserver/grpcadmin/admin_snapshots.go:163` 的注释自述 "Restore is intended for fresh/maintenance nodes" 且不使缓存失效；`restorer.go` 中 `RestoreInvalidator` 只在全部类别成功后才触发——侧面说明作者知道"半成功"是真实状态。

**为什么需要**：快照模块的头号卖点就是 DR（`docs/dr-framework.md` Level 3/4 恢复流程）。`replace` 模式在接近生产的环境（或恢复后校验发现问题）中一旦中断，会造成比原故障更糟的控制面损坏，且当前无回退路径。恢复前自动导出安全快照（复用现有 `Snapshotter`+`Pipeline`，代价极低）+ 可选的"暂存后提交"或逐类别补偿回滚，是把 RTO 从"小时级人工排错"降到"分钟级重试"的关键；这也与仓库既有的 fail-closed 纪律（AGENTS.md §3 中 refresh 轮换、恢复总线等均要求原子/可恢复）一致。

## 方向 2：凭据感知的恢复 — 客户端密钥再生与 MFA 注册数据可移植性

**问题**：快照永远不携带客户端凭据（`shared/core/types.go:24` 的 `Client.Secret json:"-"`，序列化即剥离），而 `preserveClientSecrets`（`restorer_clients.go:129`）只从**目标节点现存记录**回填。恢复到全新节点时没有现存记录 → 每个机密型 client 的 Secret 为空，`client_secret` 授权直接不可用，且 `Report` 不标记、无自动 `RotateSecret` 工作流。同理，WebAuthn 凭据（`domains/authenticators/webauthn*` 各后端）与 TOTP 种子（`domains/authenticators/totp*.go`）完全不在快照范畴（`docs/dr-framework.md` §1 明确列出 MFA enrollments 为遗漏项）——恢复后所有启用 MFA 的用户被锁死，只能人工重新注册。

**证据**：`shared/core/types.go` `Client.Secret` 的 `json:"-"` 与 `restorer_clients.go` 的 `preserveClientSecrets`（fresh-node 场景下 `ErrNoSuchClient` → 返回空 Secret 的 client）；`shared/core/spi.go:78` `ClientStore.RotateSecret` 已存在但恢复路径从不调用；`redactor.go` 中 `secretUserAttrKeys` 只覆盖用户口令（password_hash 可随快照迁移），与客户端/MFA 形成鲜明对比；`docs/dr-framework.md` §1 与 §6 恢复 runbook 未提及凭据补救步骤。

**为什么需要**：DR 恢复的目标是"用最少人工步骤恢复服务"。当前从 DR 副本拉起新集群后，confidential client 全部需要手动轮换密钥、MFA 用户全部需要重新注册——这在 RTO 里是小时级的人为操作且极易遗漏（遗漏=生产事故）。WebAuthn 凭据记录（credential ID、公钥、counter）本身不是秘密，可安全随快照迁移；TOTP 种子与客户端密钥则可走"加密 sealer 门控的可选导出 + 恢复后强制轮换/标记"路径。这是把快照从"半套 DR 方案"补成"完整控制面恢复"的最高杠杆点。

## 方向 3：快照差异与漂移检测 — snapshot-vs-live / snapshot-vs-snapshot 对比

**问题**：模块文档（`snapshot.go` 包注释）把"time-travel debugging（变更前打快照）"列为核心用例，但实际没有任何对比能力：`RestoreOptions.DryRun` 只产出**计数**（`Report.Items` 的 `CategoryCounts{inserted,updated,deleted,skipped}`），回答不了"具体哪些 client/user/role 会变"；也没有 snapshot-vs-snapshot 对比来回答"这个节点和那个节点的状态差了什么"。对照之下，配置层已经有完整的 diff 面（`interfaces/sso/server_backup.go` 的 `mountConfigAuditAPI` 挂载 `handleConfigDiff`/`handleConfigClusterDiff`，`platform/configaudit` 实现），快照层却缺失同等的可观测性。

**证据**：`interfaces/snapshot/restorer.go` `Report/CategoryCounts` 只有计数、无条目级差异；`proto/admin/v1/snapshots.proto` 的 `SnapshotAdminService` 五个 RPC（Export/List/Get/Restore/Delete）没有任何 compare 方法；`Snapshot.SourceNodeID`（`snapshot.go`）与 `SourceNamespace` 已为多节点溯源预留了字段，却没有消费它们的对比端点；`server_backup.go` 的 config diff 路由与 `configaudit.HandleDiff` 是现成的模式参照。

**为什么需要**：三个真实场景都直接受益：(a) 恢复前预览——operator 用 dry-run + diff 而不是猜计数来审阅"这个快照会改什么"；(b) 多节点漂移检测——`SourceNodeID` 已存在，跨环境（prod→staging 迁移、DR 副本与主节点）差异比对是把"迁移遗漏"从事故变成告警的手段；(c) 审计与合规——恢复/变更报告从"3 inserted, 2 updated"升级为可提交的条目级证据。成本可控：资源已按 category 组织，条目级 diff 是对现有 `List`/`Report` 数据的纯函数投影，且 wire 层加一个 RPC 即可（`ResourceCategory` 已设计为 string 以支持无 schema bump 演进）。

---

未选入前三但值得记录的低优先项：`Snapshotter.Export` 全量驻留内存、`Get` 返回整包 `resources_json`（大用户量下的内存/传输上限，控制面状态按 `dr-framework.md` 设计是"小而低频"，故降级）；`redactor.go` 连接配置密钥名启发式黑名单与用户属性黑名单的漏网风险（有文档自述 LIMITATION，属已知取舍）。
