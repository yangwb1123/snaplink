扫描完成。以下是基于全局代码库（状态机实现、admin 接口、认证热路径、合规模块、配置与部署接线）的分析结果。

---

## 1. 生命周期状态只是"管理元数据"，从未真正执行——SUSPENDED 用户依然可以登录并换取新令牌

**问题**：`domains/userlifecycle` 的七个状态（INVITED→ACTIVE→{SUSPENDED,INACTIVE}→ARCHIVED→PURGED）当前完全不影响认证决策。登录门禁只认 `core.User.IsActive()`（`shared/core/types_auth.go:417-425`），而它只反映 SCIM 的 `scim:active` 属性；`server_login_auth.go:149` 与 `server_oauth.go:223`（refresh 路径）均只检查 `IsActive()`。管理员通过 `POST /api/v1/admin/users/:id/lifecycle` 将账号置为 SUSPENDED/INACTIVE/ARCHIVED 后，该用户仍可用正确口令完成新登录并拿到全新令牌——包文档甚至明确声明"not an auth decision on the request path"（`userlifecycle.go` 包注释）。现有的 `LifecycleEventBus.OnUserSuspended` 只能撤销已存在会话/令牌，无法阻止下一次登录。这在产品语义上是"安全剧场"：运营者按下"挂起"按钮时相信访问已被切断，实际并没有。

**证据**：`domains/userlifecycle/userlifecycle.go`（`DefaultState` 语义、"governance metadata" 注释）；`shared/core/types_auth.go`（`IsActive` 仅看 `scim:active`）；`interfaces/sso/server_login_auth.go:149`、`interfaces/sso/server_oauth.go:223`（认证门禁不查 lifecycle store）；`interfaces/admin/lifecycle.go`（`HandleAdminTransitionUserLifecycle` 只写 store + 审计，不联动任何执行）。

**为什么需要**：这是该模块"高价值"与"高危险"的分水岭。SUSPENDED/ARCHIVED 若要在产品上成立（合规挂起、离职处置、调查冻结），必须成为读取侧门禁：login/refresh/authorize 等热路径在签发凭据前检查生命周期状态，非 ACTIVE 状态 fail closed。实现上应保持"无记录=ACTIVE"的向后兼容锚点（作为可选接线而非默认行为），避免破坏现有 wire 契约——这正是 AGENTS.md 强调的回归边界。这是任何客户部署此功能前必然会问的第一个问题。

---

## 2. PURGED 声称"数据已擦除"却无任何擦除动作；INVITED 状态没有任何生产入口（邀请流程缺失）

**问题**：状态机把 PURGED 定义为终态并注释"the account's data has been erased"（`userlifecycle.go`），但整个代码库没有任何路径把 `protocols/compliance.Eraser`（`erasure.go`，跨 store 的删除权擦除器，已带 dry-run/审计）接到 PURGED 转换上——`OnUserPurged` 只是空糖方法，没有任何注册方或参考实现。管理员手动走到 PURGED 时，账户的会话/令牌/个人数据原样保留。同时，INVITED 状态没有任何写入方：全库检索不到任何 `Store.Append(StateNone/StateInvited)` 的生产调用，而 admin 转换接口总是从 `rec.State` 出发校验（无记录读作 ACTIVE，`ACTIVE→INVITED` 非法），因此 INVITED 在当前接线中不可达——七个状态里一个是空转的，一个是说谎的。

**证据**：`protocols/compliance/erasure.go`（`Eraser` 及其 `EraseOptions.DryRun`、`Report`）与 `domains/userlifecycle` 零交叉引用；`domains/userlifecycle/bus.go` 的 `OnUserPurged` 无任何调用方；`protocols/lifecyclereactions/revoke_on_archive.go` 只覆盖 ARCHIVED（撤销凭据，不擦数据）；`interfaces/admin/lifecycle.go:79-80` 是唯一 `Append` 生产调用点且 `From` 恒为 `rec.State`。

**为什么需要**：对 GDPR/合规客户，生命周期终态与数据擦除的脱节是审计失败项——状态机声称"已擦除"而数据仍在，比不提供擦除更糟。高价值方向是让 PURGED 成为被编排的终态：以 Eraser 为参考 reaction 接线 `OnUserPurged`（复用其 dry-run/幂等/审计语义），或让转换依赖擦除完成（fail closed），并补齐 INVITED 的邀请/预置流程（SCIM 或独立邀请流写入种子转换），使七状态模型完整可用。

---

## 3. 生产化短板：仅内存 store、跨副本状态发散、sweep 全量扫描、活动信号无生产写入方

**问题**：`Store` 只有 `memory.Store` 一个实现（`domains/userlifecycle/memory/memory.go`），无 SQL/Redis 对等实现，多副本部署下各副本生命周期状态各自发散，且 AGENTS.md 要求的跨副本失效机制（令牌吊销、密钥轮换、租户挂起）不含用户生命周期。sweep 每次遍历 `core.UserProvider.List` 全量花名册（`sweep.go` 的 `SweepOnce` 无分页、无游标），而 `Store.ListByState`（本应支持按状态增量扫描）从未被 sweep 使用；多副本同时跑 sweep 时靠 `ErrStateConflict` 静默吞掉竞争。更关键的是活动信号：`memory.ActivityTracker.Touch/TouchAt` 在整个生产代码中没有任何调用方（登录热路径从不写"最后活跃时间"），默认接线 `SessionLastActive` 又只能看到存活会话（文档自认的盲区）——即默认配置下 dormancy 要么"无证据不动"，要么随会话过期失明。

**证据**：`cmd/sso-server/serverbuildplatform/build_userlifecycle.go`（`BuildUserLifecycle` 仅 `userlifecyclememory.New()`）；`interfaces/sso/options_admin.go:320-345`（`RunUserAutoDeprovision` + `SweepDeps`）；`domains/userlifecycle/sweep.go:48-70`（`Users.List` 全量枚举）；`domains/userlifecycle/dormancy.go`（`SessionLastActive` 的 retention-window caveat）；`rg "\.Touch\("` 全库仅 `interfaces/admin/middleware.go:405`（admin token，非用户活跃度）；`docs/config-reference.md:697-708`（确认"no other activity backend exists in this wiring today"）。

**为什么需要**：这是"演示可用"与"生产可用"的分界线。任何多副本部署（本仓库面向的正是 OpenResty/Envoy 代理的多实例架构）都会遇到状态发散；全量扫描在万级用户后每轮 sweep 都成为负担。高价值方向：实现 SQL 持久化 `Store` 对等体 + 登录热路径写入持久化活跃时间戳 + 单副本 sweep 租约/分布式锁 + 基于 `ListByState`/游标的增量扫描（配合 `MaxPerSweep` 已有的风暴防护），使自动去预置在真实规模下可运行、可收敛、可审计。

---

**优先级建议**：方向 1（认证执行）是安全/合规硬伤，最优先；方向 2（PURGED↔Eraser 打通、INVITED 落地）次之，因为它直接决定状态机语义是否可信；方向 3 是规模化前提，可在同一批接线中与方向 1 的持久化活动时间戳共用基础设施。三者互不冲突，且都遵循"可选接线、零值即关闭、无记录=ACTIVE"的既有向后兼容锚点。
