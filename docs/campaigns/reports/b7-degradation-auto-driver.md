全部完成。提交 `19a6981b`（已推送），工作树仅剩任务前已存在的无关改动（未触碰）。

## 交付总结

**第一步 — 设计文档** `docs/design/degradation-auto-driver.md`，四个决策全部代码实证：

1. **探针源**：复用现有 `sso.StorageHealthSource` seam（`internal/handler/serverdeps.go:180`、`WithStorageHealth`、`serverbuildsign.AppendStorageHealthSource` 只收集有 `Ping` 的 store）——即 admin `/storage-health` 报告背后的同一批 Ping 闭包。degradation 包不向上依赖（只引 stdlib + `shared/spi`），由 composition root（serverbuildplatform）适配；**audit-* 排除**（audit 错误按 AGENTS.md 契约 fail-open，绝不能触发 read_only）。
2. **驱动循环**：新键 `degradation.auto_read_only.interval`（默认 30s）+ `.grace`（默认 60s）；连续不健康 ≥ grace 才翻转（滞回）；健康恢复 → 回 `initial_mode`；仅当当前模式 = baseline 才动作（operator 覆盖优先，回到 baseline 且 store 仍失则重申不变式）；标准 cancel+done 优雅停机。
3. **失败模式**：三态裁决（Healthy/Unhealthy/Unknown），探针错误/超时（每探针超时 `interval/2` 钳制 `[100ms,3s]`）→ Unknown → fail-open 不转换；转换走既有 `OnChange`（`onDegradationChange`：日志 + `sso_degradation_mode` gauge + `EventDegradationModeChanged`），与 admin dr/mode 同一路径。
4. **硬边界**：Policy/Mode 未动；未启用/未设标志/无 watchable store = 字节不变；零豁免；无向上依赖；`interfaces/sso` 未触碰。

**第二步 — 实现**：`driver.go`（+10 个假探针单测：丢失→read_only、恢复→复原、抖动、Unknown、hung 超时、operator 覆盖、手动 read_only 不自动复原、默认值、停机）；config 新节；`BuildDegradationAutoDriver`（+audit 排除适配测试）；`wireDegradation` 内联启动 driver（**新建 cmd 文件被冻结的 24 文件 fan-out 上限否决**，已在设计中记录）；cancel/done 贯穿 appBuilder→app→`stopScheduler`；`degradation_wiring_test.go` 接线级测试（含 `build_app_security.go` ≤500 行断言）。

**验证输出**（全部实际运行）：

| 命令 | 结果 |
|---|---|
| `go build ./... && go vet ./...` | PASS |
| `go test ./platform/lifecycle/degradation/... -count=1`（+`-race`） | PASS（10 个 driver 测试 + 既有 6 个） |
| `go test ./cmd/sso-server/... -count=1 -run 'Degrad'`（+全量 +`-race`） | PASS（5 个接线测试 + adapter 测试） |
| `go test -count=1 -run 'TestMaintainability_\|TestArchitecture_\|TestDirectory' .` | PASS（4 个改动文件全部 ≤500 行，fan-out 合规） |
| `python3 cli.py config-validate-all` | **该命令在本仓库不存在**（已记录于设计文档）；以 `cli.py check`（PASS）+ `cli.py complexity`（PASS）+ `go test ./config/...`（PASS）替代 |

文档同步：`config-reference.md`（新键 + 段首说明）、`deferred-backlog.md`（Deferred decision → **Implemented (opt-in)**）、`CHANGELOG.md`（Added）。
