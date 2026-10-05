# postgres 集成测试隔离 + rotation-window sweep 修复

范围：`infrastructure/postgres`（13 个测试文件 + 1 个生产文件 `refresh_token.go`）。
承接 B10 报告（`b10-postgres-audit-race.md`）中列为"预存在失败、本次未修"的清单。

## 1. 复现（修复前，原命令如实输出）

```
SSO_TEST_POSTGRES_DSN='postgres://snaplink:ci@127.0.0.1:55439/snaplink?sslmode=disable' \
SSO_TEST_POSTGRES_DIALECT=postgres go test ./infrastructure/postgres/ -count=1
```

```
--- FAIL: TestUser_List_OrderById          users_test.go:168: got 10 users, want 3
--- FAIL: TestUser_ListPaginated            users_test.go:253: total=12, want [b c], 5
--- FAIL: TestClient_ListByTenantIsolationAndRotate  clients_test.go:187: Add c1: sso: client already exists
--- FAIL: TestDomain_PutHostnameConflictRejected    tenant_test.go:376: PutDomain: tenant: not found
--- FAIL: TestPermissionProvider_RemoveRoleStripsAllUsers  permissions_conformance_test.go:79: AddRole admin: permissions: role already exists
--- FAIL: TestTenant_PutPreservesCreatedAt
panic: runtime error: invalid memory address or nil pointer dereference [recovered, repanicked]
[signal SIGSEGV: segmentation violation code=0x1 addr=0x78 pc=0xddbbf8]
	infrastructure/postgres/tenant_test.go:225
FAIL	github.com/yangwb1123/snaplink/infrastructure/postgres	13.667s
```

24 项 `--- FAIL` + **SIGSEGV 中止整个测试二进制**（失败清单被截断，14 个测试从未被报告）。

## 2. 根因与修复

### 2.1 测试隔离（12 组共享表，82 处 `t.Parallel()`）

每个 `fresh*` helper 对本组共享表执行 `TRUNCATE`，而组内每个测试都 `t.Parallel()`。
并发 `TRUNCATE` 取 `ACCESS EXCLUSIVE` 锁，会删掉运行中测试刚写入的行；同一测试的下一次
`TRUNCATE` 又删掉对端的 fixture。

- 移除 82 处 `t.Parallel()`（12 文件），并在每个截断型 helper 上加注释说明禁止并行的原因
  （沿用 B10 `freshAuditSink` 的模板）。
- `session_test.go` **额外**新增 `freshSessionManager` 截断 `sessions`：该文件断言绝对行数
  （`want 2`）却从不截断，行数跨测试、跨运行单调累积（实测 26→29→30→32）。仅串行化不足。
- `postgres_test.go` 的 `TestMigrate_RunIdempotentAndVersioned` 会 `DROP TABLE consent_grants`，
  与 `freshConsentStore` 的 `TRUNCATE` 同表，两者必须串行。
- SIGSEGV 的根因随之消失：`tenant_test.go:225` / `:102` 丢弃 `GetTenant` 的错误后解引用 nil，
  当对端在 `PutTenant` 与 `GetTenant` 之间 `TRUNCATE tenants` 时即崩溃。**不改动这两处代码**——
  崩溃停止的原因是数据不再被清空。
- 选型理由：Go runner 对非并行测试天然严格串行；每个表在全二进制内只剩一个写者。
  否决备选：独立 schema/独立库（需动 DDL、与生产 schema 耦合）、包级互斥（重复造轮子）、
  sleep/重试（掩盖缺陷，且不修 nil 解引用这一崩溃类）。

### 2.2 陈旧断言（5 处，全部落到已核实的生产契约上，无一处放宽）

| 位置 | 原断言 | 修正 | 依据 |
|---|---|---|---|
| `oauth_store_test.go` AuthCode | 写入用 `current`，读取用 `(new, previous)` | 读取用 `(new, current)` | `opaqueLookupCandidates` 返回 `[h1(新), h1(旧), raw]`；轮换必须在 TTL 内保留**写入过该行**的 key（服务端接线正是传 `(current, previous)`） |
| 同上 `InspectDeleteAndCount` | `CountForSubject(u1,"")==1`、`DeleteAllForSubject(u1,"")==1` | 均改为 `0` | `rt-a` 已被消费、`rt-b` 已被删除，`u1` 已无活跃 token；两处必须同步改 |
| 同上 `ListExpiring…` | `SetLookupHMACKeys` 在 `Issue` **之后**调用；`SELECT … LIKE 'h1:%'` 取任意一行 | key 前置；SELECT 加 `expires_at >= $1 ORDER BY expires_at ASC LIMIT 1` 钉到 24h 行 | 写入时必须已有 key，否则行以 raw 存储、永远不会出现 `h1:` 值；钉死后比对才落在 ListExpiring 实际返回的那一行 |
| 同上 `ReaperPrunes…` | 过期 token 首次 Consume ⇒ reuse | 首次 ⇒ `ErrRefreshTokenNotFound`，**并新增**二次 Consume ⇒ `ErrRefreshTokenReused` | `consume()` 与 SQLite 逐行一致（`sqlite/refresh_tokens.go:181-183`）；既有的通过用例 `TestRefreshTokenStore_UnknownAndExpiredCollapse` 已固化该契约。保留 ledger 行的测试意图 |
| 同上 `RefreshGraceStore…` | `PruneExpired==1`，随后断言 `Lookup` 必 miss | 额外 `Remember` 一条真过期行；断言 `PruneExpired==1`、**新增**在窗口内的行仍然命中、被剪的行 miss | `PruneExpired` 用挂钟时间（`refresh_grace.go:154-156`），原行 `expires_at = now+10m` 根本未过期 |
| `postgres_test.go` | consent 版本 1；`CheckSchema(…,1)` | `migrate.MaxVersion(consentMigrations)` | `consent.go:41` 声明 v2；改为从迁移集派生，不会再次腐化 |

### 2.3 唯一生产缺陷：rotation-window sweep 从未执行

`infrastructure/postgres/refresh_token.go:85` 第三条 sweep 语句：

```sql
DELETE FROM refresh_rotation_windows
 WHERE family_id NOT IN (SELECT family_id FROM refresh_token_families)
   AND $1 > 0          -- $1 = now.UnixNano() ≈ 1.79e18
```

**根因是 SQL 参数类型推断，不是逻辑错误。** `$1` 紧邻裸整数字面量 `0`，Postgres 将无类型参数
推断为 `int4`（OID 23），pgx 因此拒绝编码 Unix 纳秒 int64：

```
failed to encode args[0]: unable to encode 1790848437345243893 into binary format
for int4 (OID 23): 1790848437345243893 is greater than maximum value for int4
```

而 `StartReaper` 用 `_, _ =` 丢弃了该错误，**第三条 sweep 从上线起一次都没跑成功**，
`refresh_rotation_windows` 在部署生命周期内无界增长。

修复：`AND $1 > 0` → `AND $1::bigint > 0`（行数中性，文件仍为 500 行），并在同一行注释中
记录该 cast 为何是必需的。测试侧的 `sweepStatements` 是语句的手抄副本，同步加 cast。

**安全契约影响：无。** 该 sweep 仅做有界行回收（`$1::bigint > 0` 恒真，且只删除已无 ledger 行的
family）；轮换上限本身由 `RecordRotation` 独立滚动窗口（`refresh_token_rotation.go:35-40`），
family 复用检测、grace 窗口、单次消费 `DELETE … RETURNING` 全部不经过此语句。
(sweep 1)(2) 一直正常执行。

**回归覆盖（新增用例，非空断言）**：`TestRefreshTokenStore_ReaperPrunesOrphanRotationWindow`
驱动**出厂的** `StartReaper` 而非语句副本，使"运行时静默失败"无法再躲在镜像漂移背后。
已验证非空：把 `refresh_token.go:85` 的 cast 还原（测试副本仍带 cast）后，该用例失败并报
`reaper never pruned: tokens=0 ledger=0 windows=2`；恢复后通过。

> 说明：原 requirements 将本次定为"仅测试改动"。Change 4 触及生产文件是**必要的**——
> 测试里的语句副本执行的是同一条坏语句，替代方案只有 `t.Skip` 或放宽 sweep 断言，
> 即掩盖缺陷。本次同时关闭 `docs/DECISIONS.md` 中 `database_architect` 评审的
> **F-2（rotation-window reaper 缺第三条 sweep 导致无界增长）**。
> `DECISIONS.md` 是 harness 的只追加评审日志，故不追溯改写历史条目，在此报告中记录关闭。

## 3. 验证输出（均实际运行）

| 命令 | 结果 |
|---|---|
| `go test ./infrastructure/postgres/ -count=1` | **115 PASS / 0 FAIL / 0 SKIP**，无 panic，`ok … 8.5–11.2s` |
| 同上，连跑 3 次 | 3/3 `ok`（修复前 3 次失败清单各不相同） |
| `go test ./infrastructure/postgres/ -count=2 -race` | `ok … 81.693s`，`DATA RACE` 0 处 |
| 六组单独跑（`TestTenant_\|TestDomain_` 等 6 条） | 全部 `ok`，无 `panic:` |
| 六组选择集 `-parallel 1` vs 默认并行 | 均 **59 PASS / 0 SKIP**，选择集逐项相同 |
| `env -u SSO_TEST_POSTGRES_DSN` 同命令 | `ok`（skip 语义不变，`postgres_test.go:15-22` 未动） |
| `go build ./... && go vet ./...` | exit 0 |
| `go test -count=1 -run 'TestMaintainability_\|TestArchitecture_' .` | `ok github.com/yangwb1123/snaplink` |
| `go test ./test/ -run TestE2E` | `ok … 102.258s`（`make ci` 内） |
| `wc -l refresh_token.go` | 500（未超 500 行预算） |

**隔离守卫仍真实执行并通过**（未被 skip/改名）：`TestDomain_ListByTenant`、
`TestDomain_PutSameTenantUpdateAllowed`、`TestDomain_PutHostnameConflictRejected`、
`TestDomain_PutConcurrentCrossTenantClaimIsSerialized`、`TestInvitation_ListByTenantAndIsolation`、
`TestUser_ListPaginated`、`TestUser_List_OrderById`、`TestPermissionProvider_Conformance`、
`TestPermissionProvider_RemoveRoleStripsAllUsers`、`TestClient_ListByTenantIsolationAndRotate`、
`TestSessionManager_ListByUser/_ListByTenant/_DeleteByTenant`、
`TestPasswordCredentials_UpsertReplacesInFull`。

## 4. 预存在失败（已单独核验，非本次改动引入，超出范围未修）

`make ci` 的 `race` 阶段仍 FAIL，来自**本次范围外**的两个包。二者在 stash 回 HEAD 后的
原始工作树上失败项**完全相同**，已逐项核验：

| 包 | 失败数（HEAD 原始树 / 本次改动后） | 缺陷类别 |
|---|---:|---|
| `domains/authenticators/webauthnpostgres` | 7 / 7 | **同类**并行共享表竞态（`webauthn_users` 无截断 + `t.Parallel()`），但属另一个包，本次计划未覆盖 |
| `infrastructure/postgres/tenantcommerce` | 1 / 1 | **不同类**：`schema "tenant_commerce_upgrade_1" already exists`，测试未清理上一轮遗留 schema |

`infrastructure/postgres` 本身在 `-race` 下 `ok 80.506s`。

其他已记录、未修的观察项：Postgres 的 `consent` / `device_secrets` 命名空间无 `CheckSchema` 启动闸门；
`permissions_conformance_test.go` 中 `truncatePermissions` 为无调用者、无函数体的死桩。

### 4.1 跨包 `audit_events` 竞态（`make ci` 仍红的实际原因，超出批准范围）

`cmd/auditstore/store_test.go:275`、`cmd/sso-ctl/auditverify/dsn_test.go:333`、
`test/auditexport_evidence_test.go:111` 各自对**同一张** `audit_events` 执行 `TRUNCATE`。
`go test -p N ./...` 会让这些包与 `infrastructure/postgres` 并发跑，而本包的
`TestAudit_PruneAndLastHash` / `TestAudit_QueryFilterOrderAndFacets` 对该表敏感
（B10 的 `eb544c37` 只做了**包内**串行化，未及跨包）。实测（每次 3 包并发、6 次采样）：

| | 本包失败项 |
|---|---|
| 修复后（6 次采样） | 5/6 次为 `TestAudit_PruneAndLastHash` 或 `TestAudit_QueryFilterOrderAndFacets`，1/6 次全绿 |
| 本包单独跑 | 3/3 次 `ok`（`-count=1`） |

本次改动**未触碰** `audit_test.go`（见 `git diff`），该竞态纯属跨包、高一层，
且批准的计划明确将其列为"report, not fix"。修复它需要改 `cmd/` 与 `test/` 下的测试文件，
超出本次授权范围，故仅如实上报。
