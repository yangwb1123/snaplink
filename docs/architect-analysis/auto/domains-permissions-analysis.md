已完成全局扫描。先给出模块现状结论，再列出 3 个高价值方向。

## 模块现状（上下文基线）

`domains/permissions` 的基础层已经非常扎实：`Provider`（roles/permissions/menus + 管理变更）有 4 个后端（`memory`/`sqlite`/`redis`/`postgres`），全部通过 `permissionstest.ConformanceSuite`；消费面完整——REST `/me/*`（`handlers.go`）、admin gRPC（`grpcadmin/admin_permissions.go`）、authz gRPC（`interfaces/grpcserver/authz.go`）、SCIM Groups（`protocols/scim/group.go`）、snapshot、conditional access `user.member_of`、PolicyBundle 导出（`server_resource.go` + `policy_bundle.go`）。但两个"扩展"（资源目录、SoD）和授权决策面存在结构性断层，详见下文。

## 方向 1：把资源目录（ResourceProvider）从"已构建未接线"变成资源级授权执行点

**问题**：`ResourceProvider` 是完整实现 + 高密度测试的扩展，但全仓库除 `domains/permissions/` 自身外**零消费者**——没有中间件调用 `ResolveResource`，没有 admin API 注册资源，没有持久化后端实现它，也没有文档条目。它是"模型没有执行点"的典型：代码在跑，策略不生效。

**证据**：
- `domains/permissions/resources.go`：`ResourceProvider`（Register/Get/List/Delete/ResolveResource）、6 种 `ResourceType`（http_api/grpc_api/graphql_api/page/ui_element/js_fn）、`RequireMode` any/all、`Resource.RequiresAuth`——完整契约。
- 实现仅 `memory_resources.go`；`domains/permissions/sqlite/sqlite.go:18-21` 注释明说资源目录"NOT covered"；redis/postgres 同样没有。
- 消费面缺口：`interfaces/grpcserver/authz.go:34` 的 `Check` 只做 `permissions.Matches(perms, in.Permission)` 扁平码匹配；`Permission.Resource` 字段无任何后端填充（`memory.go` 的 `Permissions()` 只产出 `Permission{Code: code}`），而 `proto/authz/v1/authz.proto` 的 wire 上已预留 `resource` 字段——协议层预期了资源级授权，实现层没有。
- `protocols/oauth/oauthvalidate/rar.go`：RFC 9396 `authorization_details` 只做形状校验（`checkRARShape`）后原样塞进 token，从不解释、不校验——资源目录是它现成的校验对端。
- 已投入却闲置的测试：`memory_resources_test.go`、`memory_resources_extra_test.go`、`memory_extra_test.go`；且 `permissionstest/conformance.go` 没有资源目录的 conformance suite，后端无法被验证。

**为什么需要**：这是产品从"UI 菜单/扁平 RBAC"升级到"API 资源级授权"（method+path、service+method 粒度）的分水岭；`ResolveResource` 的 O(1) 热路径、any/all 组合模式、`RequiresAuth` 都已设计好，只差接线——接入 authz `Check`（资源感知）、RAR 校验（合规抓手，token 里已经在传 `authorization_details`）、admin gRPC/REST 管理面 + 至少一个持久化后端落地，就能让已投入的工程变成可售卖的细粒度授权能力，而非死代码。

## 方向 2：把 SoD（SSoD/DSoD）从"内存演示"变成可运营的合规控制

**问题**：分离职责（Separation of Duty）是 SOC2/审计的高频检查项，但当前 SoD 三缺：**不可配置**（无 admin API 声明冲突集）、**不持久**（仅 MemoryProvider 实现）、**不执行**（没有任何决策点消费 ACTIVE 角色集）。模型、错误类型、测试都在，但客户无法在真实部署中使用它。

**证据**：
- `domains/permissions/sod.go`：`SoDProvider`（`SetConflictSets`/`ConflictSets`）、`SessionRoleActivator`（`ActivateRoles`/`ActiveRoles`/`DeactivateSession`）、`ErrRoleConflict`/`ConflictError`——契约完整。
- 实现仅 MemoryProvider（`memory.go`/`sod.go`）；sqlite/redis/postgres 均未实现，`permissionstest/sod_conformance.go` 靠 type-assert 对非实现后端直接 skip——conformance 自己承认后端能力矩阵不一致。
- 管理面缺失：`proto/admin/v1/permissions.proto` 的 `PermissionAdminService` 只有 roles/assignments/menus 六组 RPC，没有声明冲突集或激活会话角色的 RPC。
- 执行面缺失：全仓库 grep `ActiveRoles`/`SessionRoleActivator` 在包外零命中——`ActivateRoles` 写入的 ACTIVE 集没有任何请求路径读取（`authz.go` 的 `Check` 用的是 `Permissions()` 全量 ASSIGNED 集）。DSoD 即便在 memory 后端也是"激活了但无人检查"。
- 契约文档缺位：`docs/feature-matrix.md` 无 SoD 行，`docs/error-codes.md` 无 `ErrRoleConflict`/`ErrRoleNotAssigned` 条目（违反 AGENTS.md §5 的契约同步要求）。

**为什么需要**：合规控制"存在但不可运营"比不存在更危险——客户配置了冲突集却发现不生效（或无法配置）。补齐三件事即可闭环：admin gRPC/REST 的冲突集声明 + 会话激活端点（DSoD 的 sessionID 与 OIDC `sid` 天然契合，零信任最小权限激活是明确的产品卖点）、sqlite/postgres 持久化（SSoD 表是纯数据，成本低）、让 `Check`/授权路径按需消费 `ActiveRoles`。这是合规销售（SOC2/金融行业）的直接支撑项。

## 方向 3：授权决策平面可观测性 + 策略导出数据补全（决策黑盒与侧车漂移）

**问题**：整个授权决策面是黑盒且策略数据只导出"一半"。(a) `Authorizer.Check` 每次裁决无审计、无指标、无 deny 日志——对比同模块的 `/me/*` 查询有 `RecordQuery` 发出 `audit.EventPermissionQuery`，授权裁决反而比"查询权限列表"更不可观测；(b) 导出给外部执行器的 `PolicyBundle` 只含角色定义，不含资源目录条目、`RequireMode`/`RequiresAuth` 语义、SoD 冲突集——侧车（`docs/examples/opa-authz-policy.rego`）与服务器自身 `Check` 的裁决语义可以漂移。

**证据**：
- `interfaces/grpcserver/authz.go` 的 `Check` 函数体：仅 `permissions.Matches(perms, in.Permission)` 返回 bool，无 audit 事件、无 metrics 向量（全仓库无 `sso_authz_*` 计数）。
- 对照：`domains/permissions/handlers.go` 的 `RecordQuery`（`audit.EventPermissionQuery`，定义于 `platform/audit/aliases_spi.go:162`）只服务于 `/me/*` REST 路径。
- `domains/permissions/policy_bundle.go`：`PolicyBundle` 只含 `RoleBundle`（code→permissions）+ 静态 `WildcardSemantics`；`interfaces/sso/server_health.go:40` 自己的注释就承认它是 "the role-definition **half** of the permissions model"。
- 存量机制可用：`grpcadmin.NewPermissionAdminService` 已有 `invalidateAuthzPolicy` 回调（bundle 缓存失效），说明策略数据闭环的骨架已存在，只是导出内容不全。

**为什么需要**：授权是安全关键决策，"谁在何时被拒/被允许"是审计和排障的第一问题，当前无法回答；而仓库把"契约即回归边界"当纪律（AGENTS.md §1/§3），外部执行器拿到的策略数据与服务器裁决语义不一致会在侧车部署里造成隐性授权漂移。补 `Check` 的 audit 事件 + 决策计数（沿用 metering/audit 既有模式），并把资源目录与 SoD 集合纳入 `PolicyBundle`（版本化、ETag 已就绪），成本低、收益是"决策可解释 + 多执行器语义一致"。

---

优先级建议：方向 1 收益最大（把已投入工程变现为产品能力，且 RAR/资源级授权是差异化卖点）；方向 2 次之（合规刚需、缺口最明显）；方向 3 是前两者的支撑面，可与 1、2 的实施合并推进（每接一个执行点就补对应的审计与导出数据）。
