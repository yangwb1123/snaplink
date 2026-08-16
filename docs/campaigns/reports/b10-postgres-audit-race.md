All done. Final report:

---

## B10 收尾：postgres 审计测试并行 TRUNCATE 竞态修复

### 1. 复现（修复前，原命令如实输出）

```
SSO_TEST_POSTGRES_DSN='postgres://postgres:difyai123456@172.18.0.9:5432/sso_test?sslmode=disable' \
  go test ./infrastructure/postgres/ -run 'TestAudit_' -count=10 -race -v
```

失败样本（-count=10 中 3 次迭代失败，均为共享 `audit_events` 表互清）：

```
=== NAME  TestAudit_PruneAndLastHash
    audit_test.go:121: LastHash = ("", <nil>), want ("recent", nil)      ← 数据被并行测试 TRUNCATE 清空
--- FAIL: TestAudit_PruneAndLastHash
=== NAME  TestAudit_QueryFilterOrderAndFacets
    audit_test.go:89: Query(type=login) = 3 events, newest=failure; want 2 newest-first   ← 串入他测数据
--- FAIL: TestAudit_QueryFilterOrderAndFacets
FAIL    github.com/yangwb1123/snaplink/infrastructure/postgres  1.737s
```

### 2. 修复与选择理由

`infrastructure/postgres/audit_test.go`（仅此文件，含 helper 注释）：

- 移除三个共享表测试的 `t.Parallel()`（`TestAudit_RecordGetQuery`、`TestAudit_QueryFilterOrderAndFacets`、`TestAudit_PruneAndLastHash`），在 `freshAuditSink` 上注释说明禁止并行原因。
- **选型理由**：Go runner 对非并行测试天然严格串行；`audit_readonly_test.go` 本就共享 `audit_events` 且无 `t.Parallel()`——三个测试改顺序后，包内所有 `audit_events` 访问完全串行化，竞态从根上消失。备选方案否决：独立表/schema 需动迁移/DDL（超出硬边界、且测试与生产 schema 耦合）；包级互斥是重复造轮子（runner 已提供）。无 sleep/重试掩盖，无跳过，skip 语义不变，生产代码零改动。

### 3. 验证输出（均实际运行）

| 命令 | 结果 |
|---|---|
| 上述复现命令（修复后） | **30/30 PASS**（10 迭代 × 3 测试，`-race`），`ok ... 3.477s` |
| 无 DSN 同命令 | 3 项 `--- SKIP`，`PASS`（skip 语义保持） |
| `go build ./... && go vet ./...` | `BUILD+VET OK` |
| `go test -count=1 -run 'TestMaintainability_\|TestArchitecture_\|TestDirectory' .` | `ok github.com/yangwb1123/snaplink 0.218s` |
| `go test ./infrastructure/postgres/ -count=1`（任务 DSN） | 运行完成，20 项失败 **全部为预存在失败，与本次改动无关**（见下） |

### 4. 预存在失败（已单独核验，非本次改动引入，超出硬边界未修）

- `TestMigrate_RunIdempotentAndVersioned`：**陈旧断言**——`consent.go` 迁移集已有 v2（`1b448ad7` 加入），测试仍断言 v1（`13fe3a94` 写入），任意库上隔离运行即失败。
- 其余包级失败为**同类并行 TRUNCATE 竞态**（users/tenants/clients/sessions/invitations/totp/password_credentials/pairwise/permissions 等文件，`t.Parallel()` + 共享表 helper），隔离运行通过、全包运行失败；另有 `TestRefreshGraceStore_RememberLookupAndFailClosed`（PruneExpired 时间边界）与 `TestAuthCodeStore_OpaqueLookupKeysAndRotation` 隔离即败。
- 证据：stash 回 HEAD 后同一全包命令失败 **35 项（全新库）/34 项（任务 DSN 库）**；含修复后 **18/20 项**，且失败清单中无任何 `TestAudit_*`。B9 报告只跑了 `-run 'TestOpenAuditReadOnly|TestAudit_'`，未跑全包，故这些潜伏失败未被发现。

### 5. 提交

`eb544c37 fix(postgres): serialize shared-table audit tests to remove TRUNCATE race`（imperative 主体 + 理由正文 + `Co-authored-by: pi <pi@earendil-works.local>`；仅 `audit_test.go`，4+/3-），已推送到 `origin/main`。工作区其余无关改动（batch 管线文件）原样保留未提交。
