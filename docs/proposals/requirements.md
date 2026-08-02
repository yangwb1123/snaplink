# Requirements Specification — 管理面 List RPC 全量物化 (interfaces/grpcserver)

**范围**：`grpcadmin` 9 个 List 系 RPC（Clients/Users/ListSessions/Releases/ListTenants/ListDomains/ListRoles/ListAssignments/Snapshots/ListOperations）+ `ListExpiring`。**约束**：grpcadmin 非测试文件已达 10 文件扇出上限（新代码只能进现有文件，首选 `admin_paginate.go`）；SPI 扩展遵循 `core.TenantScopedClientStore` 先例（类型断言优先、`List()` 回退）；proto wire 契约已把 `page_token` 定为 "Opaque cursor"、`total_size` 定为 "Approximate"（`proto/admin/v1/clients.proto:84,100`），本方案零破坏性变更。

## 1. 可选分页 Store SPI：keyset 下推 + List() 回退

**问题**：每个 List RPC 每页都先 `store.List(ctx)` 全量物化，再内存过滤/排序/切片，分页只裁剪响应。N 行存储翻 P 页总成本 O(N·P)；`ListExpiring` 无分页参数，每次调用都是 O(N) 全表扫描。代码自身标注这是已知债务，且指出正确修法但标记 deferred。

**证据**：
- `interfaces/grpcserver/grpcadmin/admin_paginate.go:10-22` 注释：*"This shim paginates AFTER a full store.List(ctx) — it bounds the gRPC RESPONSE, not the store-side materialization, so a >10K-row store still pays a full in-memory scan per page. The correct fix for that is an OPTIONAL store extension type-asserted at this layer (mirroring the existing core.TenantScopedClientStore precedent …) — e.g. a future core.PaginatedClientStore / core.PaginatedUserProvider. Deferred; out of scope here."*
- 9 处同构实现：`ClientAdminService.List`（admin_clients.go:76-103）、`UserAdminService.List`（admin_users.go:33-66）、`TokenAdminService.ListSessions`（admin_tokens.go:74-118）、`ReleaseAdminService.List`（admin_releases.go:71-98）、`TenantAdminService.ListTenants`（admin_tenants.go:76-99）、`ListDomains`（admin_domains.go:25-51）、`PermissionAdminService.ListRoles`/`ListAssignments`（admin_permissions.go:51/139）、`SnapshotAdminService.List`（admin_snapshots.go:91）、`OperationAdminService.ListOperations`（admin_paginate.go:271-289）。
- 先例：`shared/core/spi.go:84-95` `TenantScopedClientStore`（"callers type-assert before using, so adding this interface doesn't break existing ClientStore implementations"）；装饰器透传 `interfaces/sso/servercache/server_client_cache.go:203-231`；durable 后端已实现可选扩展 `infrastructure/postgres/clients.go:383-387` `ListDueForRotation`。
- 网关继承同一瓶颈：`cmd/sso-server/build_http.go:422+` `RegisterXxxServiceHandlerServer` 将同一批服务暴露为 `/api/v1/admin/*`（openapi.yaml:6211）。

**拟议行为**：
1. 在 `shared/core/spi.go`（与 `TenantScopedClientStore` 并列）新增可选 SPI，如 `PaginatedClientStore`：`ListPage(ctx, PageQuery{Limit, OrderBy, Desc, Filter, After}) → (items, next, totalHint, err)`；按实体（User/Session/Release/Tenant/…）各自最小化定义。
2. `grpcadmin` 各 List 处理函数改为：类型断言扩展接口 → 命中走 `ListPage`（过滤/排序/计数下沉后端，keyset 谓词见改进 2）；未命中走现有 `List()` + filter/sort/slice 路径，行为逐字节不变。
3. 内存实现（`infrastructure/defaultimpl/memorystoreidentity/memory_clients.go`、`platform/releases/storememory`、`operations.MemoryStore`）实现该 SPI（等价于现状排序+切片，但统一新路径以便并发稳定性测试）。
4. `ClientStoreCache` 按 server_client_cache.go:203-231 先例透传新能力（uncached，admin 列表非热路径）。

**验收检查**：
- 计数 fake store 单测：N=10,000、page_size=100、翻 3 页，扩展路径下 `List(ctx)` 调用 0 次，`ListPage` 每次仅取 ≤100 行。
- 回退测试：不实现扩展的 store 上，现有 `admin_*_test.go` 全部断言（顺序、TotalSize、next_page_token、filter/order_by 错误码）全绿。
- `ClientStoreCache` 包装后扩展能力仍可达（转发测试）。
- `test/` e2e 中 REST 翻页断言不变。
- 门禁：`go build ./... && go vet ./...`、`go test -run 'TestMaintainability_|TestArchitecture_' .`、`make ci`。

## 2. keyset 游标替代 base64 偏移：并发稳定、防篡改、绑定 filter/order

**问题**：page token 是 `base64(strconv.Itoa(offset))` 纯十进制偏移；并发写（增删行）下翻页漂移——同一行跳过或重复；token 与发起页的 filter/order_by 无绑定，换参复用旧 token 静默返回错位页；明文可读、可伪造（虽被解码校验拒绝，但无完整性保护）。

**证据**：
- `admin_paginate.go:154-186` `decodeOffset`/`encodeOffset`、`pageBounds`（188-198，offset 越界钳制而非报错——"paging past the end is not a client error"）。
- proto 契约已允许 opaque 游标：`proto/admin/v1/clients.proto:84` "Opaque cursor from the previous response. Empty on the first page."——wire 不要求偏移语义，改造零破坏。
- 现有测试把 next_page_token 非空/为空当作行为契约（admin_snapshots_test.go:205-206、admin_tenants_test.go:332-333、admin_releases_test.go:213-214）。
- 偏移分页的确定性依赖服务端强制排序：admin_clients.go:151-152 "MANDATORY stable sort that makes offset paging deterministic over the memory store's random map iteration"——durable 后端无此保证。
- 全库无 keyset 先例但方向已被承认：`platform/audit/auditexport/auditexport.go:27-29` "pagination is OFFSET-based … keyset/cursor pagination is a future upgrade"。

**拟议行为**：
1. 新 token 格式（版本化 + 完整性保护）：`v1:<MAC(filter_fingerprint|order_by|last_sort_key|last_id|seq)>:<payload>`，payload 编码最后一行排序键 + tiebreaker id + filter 表达式指纹 + order_by；MAC 密钥接入现有密钥体系（实现时定，禁止明文偏移格式外泄）。
2. 下一页谓词为 keyset 比较 `(k > lastK) OR (k == lastK AND id > lastID)`（降序取反），在扩展 store 内求值；tiebreaker 用 id 保证全序。
3. 失败模式保持 oracle-safe：filter/order_by 与 token 指纹不符、MAC 校验失败、解码失败 → 一律 `codes.InvalidArgument "invalid page_token"`，错误消息逐字节相同（与现负偏移处理一致）。
4. 兼容：无扩展 store 的回退路径继续用偏移游标（行为不变）；扩展路径不签发偏移 token，旧偏移 token 一律按 invalid page_token 拒绝（token 是短生命周期 opaque 值，无需跨版本容忍）。

**验收检查**：
- 并发稳定性测试：第 1 页与第 2 页之间插入/删除行，与无写入基线对比——无重复、无遗漏。
- 篡改/错配测试：翻转 token 任一字节、换 filter、换 order_by 复用旧 token → 均返回 `invalid page_token` 且消息逐字节一致。
- 回退路径：内存 store 上现有分页测试（含 next_page_token 边界断言）全绿。
- e2e：REST 网关 page_token 往返行为不变。
- 门禁同改进 1。

## 3. TotalSize 与全量物化解耦；ListExpiring 窗口化

**问题**：9 个 List RPC 的 `TotalSize` 全部来自过滤后全集的 `len(all)`——"精确计数"强迫每页全量扫描，而 proto 文档只承诺 approximate；`ListExpiring` 无任何分页参数，默认 30 天窗口却每次全表扫描，属运维定时任务形态，持久化后端接入后即每轮全表扫描。

**证据**：
- `TotalSize: int32(len(all))` 共 9 处：admin_clients.go:98、admin_users.go:57、admin_tokens.go:102、admin_releases.go:94、admin_tenants.go:98、admin_domains.go:49、admin_permissions.go:70/158、admin_snapshots.go:107。
- proto 契约允许近似：`proto/admin/v1/clients.proto:100` "Approximate total count matching the filter (for UI display)"。
- 廉价计数先例已存在：`shared/core/spi.go:97-125` `ClientStoreStats.Stats() (count, hash)`，装饰器透传 server_client_cache.go:216-224。
- `ListExpiring` 全扫描：admin_paginate.go:43-73（`all, err := s.store.List(ctx)` → 内存过滤 `SecretExpiresAt <= cutoff` → 排序），proto 无 page 字段（clients.proto:104）。
- 窗口查询先例：`infrastructure/postgres/clients.go:383-387` `ListDueForRotation(ctx, olderThan)` 实现 `clientrotation.ClientRotationLister`——durable 后端已有按时间窗口索引查询的实现模式。

**拟议行为**：
1. 扩展路径下 `TotalSize` 来源优先级：(a) 分页 SPI 的 `totalHint`（后端 COUNT/索引计数）；(b) filter 为空且实体为 client 时用 `ClientStoreStats.Stats().count`；(c) 均不可用时维持现有精确 `len(all)` 回退。扩展路径永不因计数调用 `List(ctx)`。
2. `ListExpiring` 增加可选扩展（推广 `clientrotation.ClientRotationLister` 模式）：`ListExpiring(ctx, cutoff)` 由后端索引查询；无扩展时回退现有全扫描。proto 增量加可选 `page_token`/`page_size` 字段（向后兼容）以约束超大窗口响应。
3. 契约文档同步：`docs/openapi.yaml` total_size 描述已是 approximate（无需改动，仅确认）；`docs/feature-matrix.md` 记录分页下推能力；无新 `Err*`、无新配置键，故 error-codes/config-reference 无需改动。

**验收检查**：
- 计数 fake store 测试：扩展路径下请求 TotalSize 不触发 `List(ctx)`（调用计数 0），返回值等于后端 count。
- ListExpiring 测试：扩展 store 上仅调用窗口查询且携带正确 cutoff（fake store 记录参数）；无扩展 store 上行为与现状一致（admin_clients_test.go:197 等全绿）。
- 内存 store（无 Stats/无窗口扩展）上全部现有断言不变——精确 TotalSize 语义保留。
- 网关 e2e 翻页 + TotalSize 数值断言不变。
- 门禁同改进 1。

---

**依赖顺序**：1 → 2 → 3（改进 2 的 keyset 谓词是改进 1 扩展 SPI 的 `After` 载体；改进 3 复用改进 1 的 `totalHint` 通道）。三者合计不新增 grpcadmin 文件、不改 proto wire 字段名、不改错误码。
