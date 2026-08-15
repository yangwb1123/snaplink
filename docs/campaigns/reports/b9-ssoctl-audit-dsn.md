Task complete. Summary of the finish-up work on the sso-ctl audit DSN read path:

## 核验结论（实现已保留完整，未重写）

通读了全部保留实现，确认上一轮 1800s 超时前实现已完整落地且逻辑自洽：

- **`cmd/auditstore`**（共享只读读取器）：DSN 方言分类器（`postgres://`/`postgresql://` 前缀 vs sqlite 路径/`file:` URI）、`OpenReadOnly` 双 opener 分派、`ReadChain` 最新优先分页+反转成链序；`--limit` 截断保留**genesis 锚定的最旧前缀**并诚实上报（与 URL 分页器的语义差异有注释说明）。因 `cmd/sso-ctl` 已到 16 子目录上限，落位 `cmd/` 层（需求文档 §4 允许的 "equivalent shared reader home"），架构门 `layerName` 无需新增条目。
- **`infrastructure/postgres/audit_readonly.go`**：非迁移 opener——`postgres.Open`（仅拨号/池/ping，无 DDL）+ `CurrentVersion`（SELECT-only）fail-closed 校验 `schema_migrations_audit` 与二进制预期版本一致；注释完整声明 never-migrate 契约与只读角色建议。
- **接线**：`audit-verify --dsn`（互斥 `--from-file`/`--from-url`/`--bearer`）、`audit-export --dsn` postgres 与 `--from-url`（QueryPager 适配器，单页/次、bearer、过滤参数透传、无重定向、非 2xx 报 offset）；`--verify`/`BuildExportBundle`/链校验核心零改动。`audit-verify/main.go` 437 行、`auditexport/main.go` 490 行均守 500 上限。

## 发现并修复的缺口

1. **`gofmt` 违规**：`audit_readonly.go` import 块后缺空行，`make ci` 的 fmt 步骤拦截 → 加空行修复（唯一根因，上一轮未跑 `make ci`）。
2. 无其他缺口；postgres e2e 实跑发现的是**已存在**的并行竞态（见下）。

## 验证输出（全部实跑）

| 命令 | 结果 |
|---|---|
| `go build ./... && go vet ./...` | PASS |
| `go test ./cmd/sso-ctl/... -count=1` | 17 包 ok（含 DSN 各用例） |
| `go test ./infrastructure/postgres/... -count=1`（无 DSN） | ok；DSN 门控测试如实 SKIP（audit_readonly 4 项） |
| `SSO_TEST_POSTGRES_DSN=... go test ./infrastructure/postgres/ -run 'TestOpenAuditReadOnly|TestAudit_' -v` | **audit_readonly 4/4 PASS**；`TestAudit_QueryFilterOrderAndFacets`/`TestAudit_PruneAndLastHash` **预存在失败**（详见下） |
| `SSO_TEST_POSTGRES_DSN=... go test ./test/ -run 'AuditExport\|AuditDSN\|AuditVerify' -count=1 -v` | **A1-A3 PASS / B1-B2 PASS** |
| `go test -count=1 -run 'TestMaintainability_\|TestArchitecture_\|TestDirectory' .` | ok |
| `SSO_TEST_POSTGRES_DSN=... go test ./test/ -count=1`（全包） | ok 23.5s |
| `go test -race ./cmd/auditstore/ ./cmd/sso-ctl/auditverify/ ./cmd/sso-ctl/auditexport/` | ok |
| `make ci` | **全绿**（fmt/vet/race/nested modules/route 契约/profile 证据/adapters） |

**A1-A3 逐断言**（`TestAuditExport_PostgresLeg`）：`--dsn postgres` 导出 exit 0 ✓；`bundle.HeadHash == sink.LastHash` ✓；`--verify` exit 0 ✓；字节篡改一个事件 hash → `--verify` exit 1 + stderr `bundle FAILED verification` ✓。
**B1-B2**（`TestAuditExport_FromURL`）：advertised `/api/v1/audit/events` 永不 404 ✓；no-bearer 401 / weak-bearer 401 / valid 200 ✓；CLI `--from-url` 无 `--bearer` → exit 2 ✓；HTTP 导出 bundle `--verify` exit 0 且行数等于 sink ✓。

**postgres 环境说明**：容器实际是 scram-sha-256 网络认证（任务所述"免密"仅对 docker-exec/本地 trust 成立），使用其 `POSTGRES_PASSWORD` 建 DSN `postgres://postgres:difyai123456@172.18.0.9:5432/sso_test?sslmode=disable`（已自建 `sso_test` 库）。

**预存在失败（与本次改动无关，未修）**：`TestAudit_QueryFilterOrderAndFacets`/`TestAudit_PruneAndLastHash` 三个 `t.Parallel()` 测试共享 `audit_events` 表互相 TRUNCATE 竞态——仅 DSN 环境实跑时暴露；各自单独运行全过，且与我的新测试（顺序执行）无关。未触碰该文件。

## 文档/契约同步（同提交）

- CHANGELOG `[Unreleased] → Added` 新增条目（顶部，符合仓库惯例）。
- `cmd/sso-ctl/main.go` 顶层 usage 的 `audit-verify` 描述补充 store 来源。
- 需求文档无独立 status 字段，无需改动。

## 提交

`d7a9e301 feat(sso-ctl): add durable-store audit DSN read paths and --from-url export`（13 文件，+2051/−38；conventional + AI co-author trailer；post-commit 钩子已同步 origin/main）。**REQ-4 audit-agg 明确排除**（`auth.token.issue` L1 聚合为 [PROPOSED] 独立表面，dispatch 表无 `audit-agg` 条目），已在提交正文注明。硬边界全守：audit 导出严格只读永不迁移、零豁免、新文件 ≤500 行、函数 ≤50 行/cyclo ≤15、`cmd/sso-ctl` 非测试 .go ≤10。工作树中 batch-runner 产物（`state.jsonl`、campaign 文件、`.pi-batch.lock`、b9 报告）按"保留无关改动"原则未纳入提交。
