# 需求规格：interfaces/snapshot/storagefile — sanitize 单射化，杜绝快照名称坍缩导致的静默串读

来源：[interfaces-snapshot-storagefile-2eb8501b.json](auto/analyses/interfaces-snapshot-storagefile-2eb8501b.json)
方向 2（storagefile 名称净化非单射 → 快照静默互相覆盖/串读）。方向 1（B4-2 scope
registry 入快照信封）与方向 3（rename 后目录 fsync）不在本规格范围。

范围约束：

- 仅改 `interfaces/snapshot/storagefile`（`file.go` + `file_test.go`）。不新增包、不新增
  `Err*` 哨兵、不动 `pipeline.go`（契约允许本方案的编码路径，见下）、不动 `loader`、
  不动 `snapshot.go` / `restorer*.go` / `issue_payload.go` / `spi.go`。
- 无新配置项、无 HTTP/proto 面、`docs/openapi.yaml` / `docs/config-reference.md` /
  `docs/error-codes.md` 均不变。
- 文件预算：`file.go` 现 157 行，新增编码/解码助手后仍远低于 500 行上限；`file_test.go`
  现有 7 个测试函数，追加用例不触目录/文件数门；函数复杂度、if 嵌套不越界。
- 验收沿用方向原文两条：① `Put("a/b", v1)` 与 `Put("a_b", v2)` 并存可检索；② 恢复级
  测试断言不同快照的 roles/tenant 绑定绝不串读（保护 T-8(a)）。

## 1. 证据核对表（逐条对仓库验证）

| 方向引用 | 验证结果 | 说明 |
|---|---|---|
| `storagefile/file.go:130-152` `sanitize` | ✅ 符号与行为属实（函数实为 130-153 行） | 逐 rune 将非 `[A-Za-z0-9_.-]` 字符替换为 `_`；`"a/b"` 与 `"a_b"` 均坍缩为 `a_b`。非单射成立 |
| `storagefile/file.go:50-86` Put/Get 用净化名、静默覆盖 | ✅ Put 实为 50-86 行（Get 88-105、Delete 107-120 同经 `sanitize`） | Put 经 `os.Rename` 覆盖目标；同名二次 Put 静默替换旧数据。`TestPutAtomic`（file_test.go:90-104）还把"覆盖=预期行为"固化成用例 |
| `storagefile/file_test.go:83-103` `TestSanitisesNames` 缺碰撞用例 | ⚠️ 符号属实，行号修正：该函数实为 **68-88 行**（83-103 落在 `TestPutAtomic` 区域） | 仅断言"危险字符被替换 + 原名 Get 仍可读"，从不验证不同输入保持可区分 |
| `snapshot/pipeline.go:15-18` Storage 契约 | ✅ 精确（`Storage` 接口声明 15-28；"Overwrites are allowed (older copy is replaced)" 在 16-18） | 契约允许覆盖（同名的有意替换），但 `a/b` vs `a_b` 是名称坍缩歧义，非有意替换；契约同时允许实现 "MAY reject names with path separators"——但拒绝方案无法满足本方向验收（见决策备选） |
| `infrastructure/defaultimpl/issue_payload.go:26` `buildAccessPayload` | ✅ 函数定义在 27 行（注释头 21-26） | `TenantID: subject.TenantID` 无条件字面量写入访问令牌；roles 由 `Subject.Roles` 经 `applyOptionalClaims` 投影（`ed25519_types.go:53`） |
| `shared/core/spi.go:171` `Subject.TenantID` | ✅ 精确行号 | 登录时由 `client.TenantID` 盖章（`interfaces/sso/server_login_client.go:329`；`shared/core/types.go:47` `Client.TenantID`） |

信任链补充证据（快照 → 恢复 → 令牌 claims）：

- `cmd/sso-server/serverbuildstore/build_stores_helpers.go:135-144` — 服务器默认快照存储
  即 `storagefile.New(dir)`。
- `interfaces/snapshot/restorer.go`（`Restorer{Clients, Permissions, ...}`）+
  `restorer_permissions.go:37-74` — 恢复把 `Resources.Clients`（含 `TenantID`）与
  `Resources.Roles` 重新播种进目标 stores。
- `docs/campaigns/implementation-gate.md:11` — T-8(a)：`POST /token` → 200 + claims
  `{iss/aud/scope/client_id/tenant_id/roles}`。恢复出的 client 绑定直接决定这些 claim 值。
- `cmd/sso-ctl/snapshotcmd/main.go:101-110`、`interfaces/snapshot/retention.go:42-68` —
  `list`/`inspect`/`verify`/retention 均以 `List` 输出或 operator 提供的原始名调用
  `Get`/`Delete`，名称寻址链全部落在 storagefile 内。

## 2. 决策：sanitize 改为逐字节百分号编码（单射），List 返回解码后的原名

**问题**：`sanitize` 把每个非白名单字符映射为 `_`，不做碰撞检测。`Put("a/b", v1)` 与
`Put("a_b", v2)` 都写 `a_b.snap`，后写者静默覆盖先写者，`Get("a/b")` 返回 v2。快照携带
clients/roles/assignments，恢复后经登录路径变成 `tenant_id`/`roles` claims（§1 信任链）；
被静默替换的快照会把错误绑定/角色喂进恢复节点的信任路径。Storage 契约允许覆盖，但此处
是名称歧义而非有意替换——歧义必须由存储层消除。

**备选（否决）**：按契约 "MAY reject names with path separators" 直接拒绝含非法字符的
名称。否决理由：方向验收要求 `Put("a/b", v1)` 与 `Put("a_b", v2)` 两者都可检索并存，
拒绝方案使 `Put("a/b")` 直接报错，不满足验收。故采用编码方案。

**拟议行为**（全部在 `file.go` 内，调用结构不变）：

1. **`sanitize` 单射化**（逐字节，UTF-8）：
   - `[A-Za-z0-9_.-]` 原样保留；
   - `%` → `%25`（**必须先转义**：`%` 是转义前缀，不先转义则解码有歧义）；
   - 其余每个字节 → `%XX`（大写十六进制，多字节 rune 逐字节编码，如 `é` → `%C3%A9`）。
   - 保留现有守卫：空名、结果为 `.`/`..` 报错。
   - 该编码是前缀码：输出中的 `%` 只作为转义起始出现，解码（`%` + 2 个 hex 取原字节）
     无歧义 ⇒ 编码单射。旧实现中坍缩的任意输入对（`"a/b"`/`"a_b"`、`"a:b"`/`"a b"`、
     `"ø"`/`"ñ"` 等）输出互不相同。
2. **`List` 返回解码后的原名**：对每个 `.snap` 文件去后缀后，把良构 `%XX` 序列解码回
   原字节；裸 `%`（后无两个 hex）保持字面（防御非本实现写入的文件）。由此保证
   `Get(List 返回名)` 恒命中同一文件（List→Get 往返无双重编码）；operator 在
   `snapshotcmd list` 中看到的是原始名，`inspect/verify --id <原始名>` 照常工作。
3. **`Put`/`Get`/`Delete` 调用点不变**——三者已统一经 `sanitize` 寻址，只有
   `sanitize` 实现与 `List` 解码变化。删除隔离自动成立：`Delete("a/b")` 只删
   `a%2Fb.snap`，不影响 `a_b.snap`。
4. **固定点**：仅含白名单字符的名称（生产默认 `snap_<...>` 名称）映射到自身，磁盘文件
   名不变 ⇒ 存量干净名称完全兼容。
5. **文档注释同步**：`file.go` 包注释与 `sanitize` 注释改写为单射编码语义（现注释
   "everything else is replaced with `_`" 删除）。

**兼容性与回滚说明**：

- 含非法字符的**遗留文件**：旧代码把 `"a/b"` 写到 `a_b.snap`；新代码 `Get("a/b")` 寻址
  `a%2Fb.snap` → `ErrSnapshotNotFound`。遗留坍缩文件无法与真 `a_b` 快照区分，不做迁移
  （operator 需重新导出）；旧文件仍可按净化名（`"a_b"`）读取。
- **loader 交互（范围外，仅记录）**：`loader.fromFile` 在无 `?name=` 查询参数时从
  URI 路径基名派生名称，新格式文件名（含 `%`）会派生为已编码名导致 `Get` 不命中；
  使用 `file:///dir/?name=<原始名>` 形式即可。`loader` 解码属后续项，本规格不改。
- 回滚：仅改一个包内部函数与一个测试文件，无状态迁移；直接 revert 即回滚。

## 3. 验收标准

### 通用（EVALUATION.md U1–U9 + AGENTS.md 强制门）

- [ ] `go build ./... && go vet ./...` 通过
- [ ] `go test -run 'TestMaintainability_|TestArchitecture_' .` 通过
- [ ] `go test ./... -race` 与 `make ci` 通过
- [ ] 无新 `Err*`、无新配置、无 OpenAPI/错误码/配置文档改动

### 特征验收（方向验收原样保留，可测试化）

**A1（storage 级主验收 — `storagefile/file_test.go`）**

Given 空目录 `file.Storage`；
When `Put("a/b", []byte("v1"))` 再 `Put("a_b", []byte("v2"))`；
Then：

1. `Get("a/b")` == `"v1"` 且 `Get("a_b")` == `"v2"`（两者并存、各取所写）；
2. `List` 排序后恰好返回 `["a/b", "a_b"]`（两个名字都在）；
3. 随后 `Delete("a/b")` 后 `Get("a_b")` 仍 == `"v2"`（删除不串扰）；
4. 目录内无 `.tmp-` 残留文件（沿用 `TestPutAtomic` 的检查方式）。

**A2（单射性表驱动 — `storagefile/file_test.go`）**

Given 旧实现坍缩的输入对：`("a/b","a_b")`、`("a:b","a_b")`、`("a b","a_b")`、
`("a%b","a_b")`、`("a//b","a__b")`、`("ø","ñ")`；
When 对每对分别 `Put` 两值；
Then 两个 `Get` 各自命中自己写入的值（`sanitize` 输出两两不同、磁盘文件不同）。

**A3（List 往返 — `storagefile/file_test.go`）**

Given 名称 `"site-A/backup"`、`"备份/2024"`、`"a%b"` 各 `Put` 一条；
Then `List` 返回这三个原始名，且对每个返回名 `Get` 命中该名写入的数据（无双重编码）。

**A4（恢复级验收 — `storagefile/file_test.go`，方向验收第二条）**

Given：

- 手构两个快照（`snapshot_v2_test.go:53-57` 手构先例；`Snapshot.Validate` 仅要求
  `SchemaVersion: snapshot.SchemaVersion` 与非空 `SourceNamespace`）：
  - S1：`Clients=[{ID:"c1", TenantID:"tenant-A", Active:true}]`，
    `Roles=[{ClientID:"c1", Roles:[{Code:"admin"}]}]`；
  - S2：`Clients=[{ID:"c2", TenantID:"tenant-B", Active:true}]`，
    `Roles=[{ClientID:"c2", Roles:[{Code:"viewer"}]}]`；
- `Pipeline{Sealer: encryptionnone.New()}` 把 S1 `Save` 为 `"site-A/backup"`、S2 为
  `"site-A_backup"`（旧 sanitize 下两者坍缩为同一文件 `site-A_backup.snap`）；
- 分别 `Load` 原名后，各 `Restore`（`RestoreOptions{Mode: ModeMerge}`，目标为全新
  `defaultimpl.NewMemoryClientStore()` + `permissions.NewMemoryProvider()`，其余后端
  nil 按契约跳过）进两个独立目标。

Then：

1. 目标 1 仅含 client `c1`（`TenantID=="tenant-A"`），`c1` 的 roles 恰为 `{admin}`，
   不含 `viewer`；
2. 目标 2 仅含 client `c2`（`TenantID=="tenant-B"`），`c2` 的 roles 恰为 `{viewer}`，
   不含 `admin`；
3. 目标 1 不出现 `c2`/`viewer`，目标 2 不出现 `c1`/`admin`。

即：恢复出的 client 绑定（`tenant_id`/`roles` claim 的来源）绝不跨快照串读 —— 修复后
`Load("site-A/backup")` 与 `Load("site-A_backup")` 是两个独立数据流，这正是 T-8(a)
（`implementation-gate.md:11`：`/token` claims `{...tenant_id/roles}`）在恢复侧的
前置保证。

### 回归

- [ ] 既有测试全绿：`TestPutGet`、`TestList`、`TestDeleteIdempotent`、`TestPutAtomic`、
  `TestNew_RequiresBaseDir`、`TestBaseDirReturnsAbs` 均用干净名（固定点），不受影响；
  `TestSanitisesNames` 的"原名 Get 仍可读"断言在编码方案下继续成立（
  `Get("ok/with..bad chars*")` → `ok%2Fwith..bad%20chars%2A.snap` 命中）。
- [ ] `interfaces/snapshot` 全量测试（含 `pipeline_aesgcm_file_test.go` 往返、
  `snapshotcmd` 测试）不回归。

## 4. 文件

### Modify

```text
interfaces/snapshot/storagefile/file.go — sanitize 单射编码（% 转义 + 逐字节 %XX）、
    List 解码原名、包注释与 sanitize 注释同步
interfaces/snapshot/storagefile/file_test.go — 新增 A1–A4 用例
```

### Do not modify

```text
interfaces/snapshot/pipeline.go — Storage 契约；编码方案在契约内，覆盖语义不变
interfaces/snapshot/loader/loader.go — 路径派生名解码属后续项（§2 兼容性说明）
interfaces/snapshot/snapshot.go / restorer*.go — 信封与恢复语义不变
infrastructure/defaultimpl/issue_payload.go、shared/core/spi.go — 信任链下游，不动
```

## 5. 验证计划

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/snapshot/... -run 'TestSanitise|TestPutGet|TestList|TestRestore|TestPut|TestDelete' -v
go test ./... -race
make ci
```
