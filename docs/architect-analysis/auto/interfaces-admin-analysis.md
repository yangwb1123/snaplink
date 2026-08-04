已完成全局扫描（`interfaces/admin/`、`internal/adminuser/`、`interfaces/grpcserver/grpcadmin`、`proto/admin/v1/*`、`platform/lifecycle/{admingovernance,operations,sessionhub}`、`platform/audit`、`platform/bootstrap/builtin`、`docs/openapi.yaml` 132 个 admin 路径、`server_routes_admin.go`/`server_admin_handlers.go`、`shared/core/tenant_user.go` 等）。以下是基于现有实现（仅指已落地的功能）的高价值扩展方向。

## 1. 管理授权模型升级：从二元 scope 到可组合的委派 RBAC（角色 × 资源 × 租户）

**问题**：整个管理面的鉴权被压缩成 `admin:read` / `admin:write` 两个布尔判定。中间件只回答"这个主体有没有这个 scope"，回答不了"这个主体能不能动这批资源、这个租户、这个阶段"。权限管理基础设施（角色 CRUD、指派、菜单）已经存在，但执行点消费不了它。

**证据**：
- `interfaces/admin/middleware.go`：`Scope/ScopeRead/ScopeWrite` 三个常量就是全部授权语言；`providerAuthorizer.HasAdminScope` 返回 `(bool, error)`；`scopeForHTTP`/`scopeForGRPC` 只可能产出 `admin:read` 或 `admin:write` 两种需求值。`permissions.Matches`（`domains/permissions/matcher.go`）支持 `admin:*` 通配，但没有任何调用方要求 `admin:clients:write` 这类资源级代码。
- `interfaces/admin/deps.go` 头部注释明言："Every admin operation is gated UPSTREAM by AdminMiddleware… handlers run only after that gate, so they assume admin authorization"——即 40+ 个 `HandleAdminX` 内部零授权分层，任何持有 write scope 的主体可执行从 `HandleAdminRotateSigningKey` 到 `HandleAdminExportTenant` 的一切。
- `platform/bootstrap/builtin/builtin.go`：`stepSeedAdminRole` 只种一个 `sso-admin` 角色，"Full admin:* scope across the control plane"；而 `proto/admin/v1/permissions.proto` 的 `PermissionAdminService`（ListRoles/AssignRoles/SetMenus）证明角色模型已建好却未被管理面消费。
- 租户维度只是"best-effort hint"：`governance.go` 的 `tenantHintFromClaims`（读 `claims.Extra[tenant_id]`）只用于写配额键；`tenants.go` 的 `tenantRequestMismatch` 基于 host 路由且 fail-open。没有"租户管理员只能管本租户"的授权原语。
- break-glass 的地板也是二元的：`break_glass.go` 的 `TargetHoldsAdminScope` 注释承认它只能判断"目标是否持有任意 admin scope"，无法表达"L1 支持人员可冒充普通用户、不可冒充安全管理员"这类分级。
- `admingovernance` 双人审批流（`HandleAdminApproveChange`）没有角色矩阵——`ApprovalActionTypes` 只约束 action_type，任何第二个 `admin:write` 持有者都能放行。

**为什么需要**：这是企业级落地的硬门槛。运维组织的现实是 L1 helpdesk（只能重置密码/吊销设备）、安全管理员（只能管 key/CAEP）、租户管理员（只能管本租户）需要不同边界；当前模型迫使部署方"要么全权、要么无权"，直接导致 break-glass 无法分级、审批无法按角色路由、租户隔离只能依赖路由层而非授权层。基础设施（角色/指派/通配匹配器）已就位，缺的是把 `HasAdminScope` 扩展为资源-租户维度的判定并让 handler 层声明所需能力——这是一条低新增概念、高产品价值的主线。

## 2. 管理面双轨一致性：HTTP 与 gRPC 的单一事实源与能力对齐

**问题**：管理面存在三套并行实现（原生 HTTP handler、gRPC 服务、grpc-gateway 代理），授权判定、路由、scope 映射各自手维护且规则不同；同时两条轨道的管理能力严重不对称，导致外部自动化（gRPC 消费者）无法触达一半以上的管理操作。

**证据**：
- 能力不对称：`proto/admin/v1/` 只有 9 个服务（clients/keys/operations/permissions/releases/snapshots/tenants/tokens/users），而 HTTP 面（`docs/openapi.yaml` 132 个 admin 路径）额外覆盖 connections/provider CRUD+probe（`connections.go`）、设备/登录历史（`lifecycle.go` 的 `HandleAdminListAllDevices`、`HandleAdminListUserLoginHistory` 等）、break-glass 全流程（`break_glass.go`）、变更审批（`governance.go`）、token portfolio（`token_portfolio.go`）、租户导出/邀请/域名（`tenants.go`）、审计查询（`platform/audit/handlers.go`）——这些都没有 gRPC 对应 RPC。
- 双网关互相镜像靠注释承诺：`middleware.go` 的 `isGatedGRPCMethod` 注释写明 "MIRRORS the HTTP IsProtectedPath set"；但读方法判定规则不同——HTTP 用方法名（GET/HEAD/OPTIONS），gRPC 用 RPC 名前缀启发式（`isReadMethod` 的 List/Get/Search/Find），`methodScopes` 覆盖表在两个传输各维护一份。
- 路由与契约四处手改：新增一个管理端点要动 `server_routes_admin.go`（手工挂载）、`SetMethodScope`、`docs/openapi.yaml`，若要 gRPC 还要 proto + 重新生成 + `cmd/sso-server/build_http.go` 的 grpc-gateway 映射——没有从 proto 或路由表生成另一侧的任何机制。
- 不对称的后果已可观察到：管理面治理设施（写配额、IP 白名单、破坏性确认）只挂在 HTTP 侧（`governance.go` 的 `checkIPPolicy`/`checkWriteQuota`/`checkDestructiveConfirm` 在 `HTTPMiddleware` 内），gRPC 拦截器只有 scope 检查，同一操作走两条轨道治理强度不同。

**为什么需要**：scope 标注错误是安全事件而非体验问题，双轨手维护意味着每次新增端点都有漂移风险；同时自动化（CI、sso-operator、MCP、Terraform 类工具）只能驱动 gRPC 子集，helpdesk 工作流（设备吊销、break-glass 审批、连接探测）被锁死在 HTTP 上。以单一事实源（proto 或路由表）生成 scope 映射、补齐 gRPC 缺失服务、把治理检查下沉到两轨共享的构造对象，能同时消除安全漂移和自动化断层。

## 3. 管理面拒绝路径审计盲区：被拦截的访问不进审计

**问题**：管理面承诺完整审计（W3C trace ID、事件分类、SSE 实时流），但所有"请求被拦下"的路径——IP 白名单拒绝、管理面限流、破坏性确认缺失、鉴权失败、scope 不足、配额超限——在 HTTP 侧全部静默返回，不产生任何审计事件；而 gRPC 侧连拒绝都记录（`EventAdminGRPCCalled` + "denied" reason）。安全团队看到的审计流系统性丢失了"谁在试图碰管理面"这个最重要的信号。

**证据**：
- `interfaces/admin/governance.go`：`checkIPPolicy`（403，无 audit 调用）、`checkRateLimit`（429）、`checkDestructiveConfirm`（409）、`checkWriteQuota`（429，只设 Retry-After）——四个治理闸门全部 return false 即结束。
- `interfaces/admin/middleware.go`：`authenticateHTTP` 的 401（missing/invalid token）与 403（forbidden）均无审计调用；`HTTPMiddleware` 全路径零 `Recorder` 引用。对比 `SetAuditRecorder` 的文档注释明确写的是 "logs every gRPC admin RPC"，且 `UnaryServerInterceptor` 在拒绝时也 `recorder.Record` 了 `EventAdminGRPCCalled + OutcomeFailure`——两轨的审计覆盖不对称是代码事实而非猜测。
- 衍生盲区：`WithSSEBroker` 的实时管理事件流（`server_health.go`）tap 的是审计管道，因此继承了同样的盲区；`checkIPPolicy` 的注释自称 "no oracle: the response is identical…"，只保证了响应一致性，没有保证"拒绝本身可观测"。

**为什么需要**：对 SSO 产品而言，管理面是最高权限面，SOC/合规审计最关心的恰恰是"谁尝试过、被什么策略拦下、从哪里来"。当前实现让暴力尝试管理端点、绕 IP 白名单、探测破坏性端点等行为在审计中完全隐身，也与 AGENTS.md 的审计纪律（`audit.SetMeta`、事件分类、trace ID）形成明显落差。修复成本低（四个闸门 + 两个鉴权失败点各补一个 denial 事件，事件类型进 `auditreport` 分类），但补齐的是审计完整性的最后一块拼图。
