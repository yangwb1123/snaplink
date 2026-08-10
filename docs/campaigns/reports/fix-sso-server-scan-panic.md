完成。已提交 `017433c0`（`fix(sqlite): fail open when client expiry scan sweeps a closed store`）。

## 根因

flaky panic 的机制：`startGovernanceWorkers`（build_app_security.go:421）启动 scanner 后，`Run` 的**首次 sweep 立即执行**在后台 goroutine 中。`TestBuildApp_ReadyCheck_SQLiteFlipsTo503`（以及类似测试）为了模拟 store 故障会在测试中调用 `sqlite.ClientStore.Close()`，它把 `db` 置为 nil（`Close()` 明确 `s.db = nil`）。sweep 与该 Close 竞争时，`List` 直接解引用 nil `*sql.DB` → 后台 goroutine panic → 整个测试进程崩溃。单跑包时 goroutine 调度通常赶在 Close 前完成 sweep，全量跑时调度延迟使其落在 Close 后——完全符合"时序相关、单跑未必复现"。

## 修复选择（契约论证）

- **不改 wiring**：`buildApp` 交给 scanner 的 store 总是已打开且可用的（`BuildClientStore` 要么成功要么报错），`!= nil` 判断在接线点正确。测试里 Close 是运行期故障模拟，不是接线错误。
- **store 侧 nil-DB guard**（选此项）：`List` 与 `Ping`/`Close` 已有约定一致——nil DB = `"sqlite: client store closed"` 错误。closed store 即 store 故障形态，scanner 现有的 fail-open 错误路径（`"client secret expiry scan failed"` + 中止）自动接管，panic 消失。scanner 侧无需改动，因为 `core.ClientStore` 是接口、无可用性探针，只能在 store 实现处把故障转成 error。
- 顺带把 `clientMigrations` 移到 `clients_migrations.go`（内容逐字节不变）——guard 使 clients.go 达到 504 行，触发 500 行预算，按要求拆分而非豁免。

## 回归测试（三层）

1. **sqlite**：`TestSQLiteClients_ListClosedStoreReturnsError` — Close 后 List 返回 error、不 panic。
2. **rotation**：`TestClientSecretScan_StoreOutageFailsOpen` 增强 — 断言 fail-open 日志 `"client secret expiry scan failed"` 恰好一条、零事件。
3. **cmd/sso-server**：`TestClientSecretScan_ClosedStoreFailsOpen` — 确定性复现 flake：sqlite identity 构建 → Close store → 起 scanner → 干净退出 + fail-open 日志。已实测**去掉 guard 时该测试确定性崩溃**（栈与报告一致），加上后通过。

## 验证结果

| 验证 | 结果 |
|---|---|
| `go build ./... && go vet ./...` | ✅ |
| `TestMaintainability_ / TestArchitecture_` | ✅ |
| `go test ./cmd/sso-server/ -count=5` | ✅ |
| `go test ./platform/lifecycle/rotation/... -count=1` | ✅ |
| `go test ./infrastructure/defaultimpl/sqlite/` | ✅ |
| `go test ./... -race` | ✅（除下述预存失败） |
| `go test ./test/ -run TestE2E -v` | ✅ |
| modules check / check-routes / proto-openapi-parity / adapters / check-root | ✅ |

**预存问题（与本次无关，单独报告）**：① `./test/` 的 `TestSdkForm_PARClaimsThreaded` 失败，自述 "sibling F1 decoder not landed"——B4-4 进行中 campaign 的未落地功能断言；② `make ci` 的 fmt 门禁被两个预先存在的未格式化文件阻塞：`cmd/sso-ctl/main.go`、`test/credential_content_type_test.go`（均非本次改动）。
