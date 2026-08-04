全局扫描完成。已核对 `interfaces/grpcserver/`（6 个文件 + `grpcadmin/` 10 个文件、9 个 Admin 服务、4 个核心服务）、`interfaces/admin/middleware.go`（HTTP/gRPC 双传输管理中间件）、`cmd/sso-server/main_servers.go`（gRPC 装配）、`interfaces/grpcserver/grpcadmin/admin_paginate.go`（分页）、`platform/registry`、`docs/openapi.yaml` 与 `test/` e2e 覆盖。以下是最有价值的 3 个方向：

## 1. gRPC 管理面传输级治理缺失：IP 策略/速率限制/破坏性确认/空闲超时/写配额在原生 gRPC 上被整体绕过

**问题**：`AdminMiddleware` 的注释宣称 "Both transport variants share one AdminMiddleware construction object so the scope rules can't drift between them"，但实际上两个传输只共享了 bearer+scope 校验，其余全部治理检查只在 HTTP 路径执行。gRPC 是自动化/批量管理的主通道（长生命周期 token、脚本、网关节点的上游），却绕过了运维者为 HTTP 管理面配置的全部传输级防护，形成安全姿态不一致。

**证据**：
- `interfaces/admin/middleware.go`：`HTTPMiddleware` 依次执行 `checkIPPolicy` → `checkRateLimit` → `checkDestructiveConfirm` → `authenticateHTTP` → `enforceIdleTimeout` → `checkWriteQuota`；而 gRPC 路径 `authorizeGRPC`（`UnaryServerInterceptor`/`StreamServerInterceptor` 共用）只做 bearer 校验 + `HasAdminScope`，`enforceIdleTimeout` 的 `adminTokenStore.Touch` 也从未在 gRPC 上触发。
- `cmd/sso-server/main_servers.go`：`grpcInterceptorOptions` 只链 `Recovery*Interceptor` + `adminMW` 两个拦截器；`grpcServerOptions` 中 TLS 仅在 `tlsCert != "" && tlsKey != ""` 时启用，而 `-grpc-listen :8081` 默认开启（main.go:59）。
- grpc-gateway 代理的 REST 面（`build_http.go:232` `adminMW.HTTPMiddleware(gw)`）走的是完整治理链——同一批 `RegisterXxxServiceHandlerServer` 服务，两个入口防护等级不同。

**为什么需要**：AGENTS.md 的安全基线要求管理面 401 标识 `Bearer realm="admin"`、admin:read/write 授权，这部分已达标；但速率限制（共享令牌桶）、IP 白名单/地理锁、破坏性操作 `X-Confirm` 确认、admin token 空闲超时是防爆破/防滥用/防误删的实际控制面。攻击者或失陷的自动化客户端只需直连 gRPC 端口即可绕过全部传输层防护，且该端口默认开启、TLS 可选。这是比"缺功能"更严重的 posture drift，应在拦截器链中补齐与 HTTP 等价的治理检查（IP 策略、限流、确认头、idle-timeout、配额），并强制/默认 TLS。

## 2. 管理面 List RPC 全量物化：分页只裁剪响应、不裁剪扫描，每页 O(N) 且游标不稳定

**问题**：`grpcadmin` 的所有 List RPC 都是"先 `store.List(ctx)` 全量取出、内存过滤排序、再按 offset 切片"，分页只约束 gRPC 响应大小，不约束 store 侧物化成本。代码注释自己承认这是已知债务并标记 deferred。

**证据**：
- `interfaces/grpcserver/grpcadmin/admin_paginate.go` 顶部注释：*"This shim paginates AFTER a full store.List(ctx) — it bounds the gRPC RESPONSE, not the store-side materialization, so a >10K-row store still pays a full in-memory scan per page … e.g. a future core.PaginatedClientStore / core.PaginatedUserProvider. Deferred; out of scope here."*
- `admin_clients.go` `List`（`all, err := s.store.List(ctx)` → `filterClients` → `sortClients` → `decodeOffset` → `pageBounds`）、`admin_releases.go` `List`、`ListExpiring`（admin_paginate.go:51）、`OperationAdminService.ListOperations`（admin_paginate.go:276）全部同构；`TotalSize` 依赖全量 `len(all)`。
- page token 是 base64 十进制 offset（`decodeOffset`/`encodeOffset`），并发写入下分页漂移，无 keyset/cursor 语义。
- 该层同时是 grpc-gateway 的 REST 管理面（`build_http.go` 的 `RegisterXxxServiceHandlerServer`，docs/openapi.yaml:6211 "Admin gRPC services exposed via grpc-gateway"），因此 `/api/v1/admin/*` 继承同一瓶颈。

**为什么需要**：这是代码库内唯一被显式标注"正确修法已知但推迟"的扩展性债务。按 DIRECTORY_MAP，Redis/Postgres 已是 root-module 持久后端，一旦管理面接入持久化存储，每页全表扫描的 O(N) 成本会直接成为管理面扩展性瓶颈（大租户 + 分页浏览 + `ListExpiring` 定时任务叠加）。方向明确：参照现有 `core.TenantScopedClientStore` 的"类型断言优先、退化为 List()"先例，新增可选的分页 store 接口 + keyset 分页，把过滤/排序/计数下沉到后端。

## 3. gRPC 平面运维可观测性缺失：无健康检查、无 reflection、无 metrics/tracing 拦截器，TLS 可选

**问题**：HTTP 面有完整的 `/readyz` 就绪检查、storage-health 报告和 otelhttp 埋点，而 gRPC 平面既无 `grpc_health_v1` 健康服务、无 `reflection.Register`、也无任何 per-RPC 指标/追踪拦截器——整个 gRPC 面的可观测性只有 admin-gated RPC 的可选 `EventAdminGRPCCalled` 审计事件。对依赖该模块的外部 SDK 消费者而言，这是不可运维的。

**证据**：
- `cmd/sso-server/main_servers.go`：`newGRPCServer` 只注册 authz/discovery/admin 服务；全库 grep 无 `grpc_health_v1`/`healthpb`/`reflection.Register`；`grpcInterceptorOptions` 只有 Recovery + adminMW。
- 对比：`build_app_core.go` `registerIdentityHealth` 挂载 `/readyz` 与 storage-health 源；go.mod 中已有 `otelhttp` 埋点与 `otlptracegrpc` 导出器，但无 `otelgrpc` 拦截器；`platform/tracing`、`platform/metrics` 均无 gRPC 接入。
- `aliases.go` 注释明确 gRPC 服务是公共契约：*"SDK consumers that construct and register the admin services themselves"*；`platform/registry` 提供 etcd 后端 + Watch，说明存在多实例/集群部署形态（LB 探活依赖健康检查），而 `grpcServerOptions` 的 TLS 仍是可选的。

**为什么需要**：该模块是"可嵌入 SDK + 独立 sso-server"双形态交付（AGENTS.md §1），外部消费者（如 `cmd/sso-operator` 类控制面、ext-authz 数据面依赖 `AuthzService.Check` 的可用性）无法用标准工具做探活、服务发现（grpcurl/reflection）和延迟/错误率观测；集群形态下 LB 无法对 gRPC 端口做健康判定。补齐 grpc_health 服务 + reflection + 统一拦截器输出指标（对接现有 platform/metrics 与 tracing）并默认启用 TLS，是把 gRPC 面从"功能可用"提升到"可运营交付"的最小高杠杆改动。

---

**附：扫描中排除的低优先级候选**——`admin` 服务在 `build_http.go`（gateway 注册）与 `main_servers.go`（原生注册）双处重复装配、存在漂移风险（属维护性，非高价值扩展）；`grpcadmin` 目录已达 10 文件扇出上限（新服务需拆子包）；Discovery 无心跳 RPC（registry 接口注释声明后端自动续约，属设计决策）。
