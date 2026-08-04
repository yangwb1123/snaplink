全局扫描完成。当前 `domains/tenant` 已覆盖：Tenant/Domain CRUD（memory/sqlite/postgres 三后端）、Host→Domain→Tenant 路由中间件、`ClientOK` 租户隔离门（introspect/revoke/PAR/CIBA）、停用强制（token 门 + refresh/session 主动撤销）、数据驻留（HomeRegion/AllowedRegions + TTL 缓存 + 失效总线）、双品牌机制（`Domain.Branding` 公开 `/branding` 与版本化 `BrandingStore`）、B2B 跨租户协作（memory-only）、gRPC `TenantAdminService` + HTTP admin 面、快照 v2、用量计量与每租户指标。基于此提出 3 个高价值方向：

## 方向 1：租户解析热路径"两跳查询 + 零缓存"——收敛重复解析逻辑并接入失效总线

**问题**：每个请求都要执行 `GetDomain` + `GetTenant` 两次存储往返；限流拒绝路径用 `ResolveTenantID` 把整条解析逻辑重复实现了一遍（与中间件两份拷贝，存在漂移风险）；停用检查、驻留检查各有 TTL 缓存和失效总线事件，唯独最底层的 Domain→Tenant 路由解析完全无缓存——`Store` 注释明言"backends MAY cache aggressively"，但 sqlite/postgres 后端每次都是活查询。

**证据**：`domains/tenant/middleware.go`（`Middleware` 双查询、`ResolveTenantID` 重复逻辑）；`domains/tenant/tenant.go` Store 接口注释；`infrastructure/postgres/tenant_domains.go` `GetDomain`（无缓存直查）；`interfaces/sso/server_tenant_residency.go`（suspension/residency 各自的 TTL 缓存）；`interfaces/sso/server_invalidation.go`（`cluster.KindTenantSuspension` / `KindTenantResidency`，无路由类事件）。

**为什么需要**：多租户 SaaS 下每次登录/token/userinfo 请求都付 2 次 DB 往返，且域名变更（改绑、删除）无法跨副本即时生效；平台已有成熟的 TTL 缓存 + 失效总线基建，只差把路由解析纳入同一模式（新增 `KindTenantDomain` 类事件），或把租户关键字段反规范化进 Domain 快照使解析收敛为一跳。这是当前租户模块最确定的规模化收益点，同时消除两份解析逻辑的长期漂移风险。

## 方向 2：`Domain.DefaultClientID` 是"有字段无行为"的悬空契约——接入登录解析或删除

**问题**：`DefaultClientID` 在所有后端持久化（postgres/sqlite/memory）、经 gRPC proto 和配置暴露，但全库无任何消费方——没有任何登录 handler 读取它。`tenant.go` 注释承诺"consulted by handlers that need to pick a client without one in the URL"，行为却未实现。

**证据**：`domains/tenant/tenant.go` Domain 字段及注释；`infrastructure/postgres/tenant_put.go`/`tenant_scan.go`、`domains/tenant/sqlite/`、`interfaces/grpcserver/grpcadmin/admin_domains.go`（仅序列化）；`interfaces/sso/` 全部 login 解析路径（`server_login_client.go`、`server_login_resolve.go`）零读取；`test/testkit/testkit.go` 也只在测试夹具里设置。

**为什么需要**：这是多租户登录体验的天然下一步——`auth.acme.com` 无 `client_id` 时按域名默认到租户的登录客户端，也是 `Domain` 存在的产品理由之一。当前状态是典型的半成品字段：运维配置了它却不生效，属于"字段陷阱"。要么把租户校验过的默认客户端解析接入登录流程（配合 `ClientOK` 同款租户门），要么移除字段，二选一消除契约与行为的背离。

## 方向 3：B2B 跨租户协作"内存-only + 零管理面"——补齐持久化后端与运营/审计表面

**问题**：`GuestRecord` 与 `TenantCollaboration`（信任边 + 访客指针）是产品级 B2B 能力，但唯一实现是进程内 `memory` 后端；无任何 HTTP/gRPC 管理 CRUD 或列表面，无快照/备份覆盖，无配置化供给。重启即丢失全部信任图和访客注册，运维无法审计"谁信任谁"、无法主动吊销单个访客。

**证据**：`domains/tenant/tenant_collab.go`（SPI 定义，注释自陈"any Store backend a deployment needs (sqlite, etcd, ...) implements the same two interfaces"）；`domains/tenant/memory/collab_store.go`（唯一实现）；`interfaces/sso/options_grants.go`（仅 `WithExternalUserStore`/`WithTenantCollaborationStore` 接线）；`internal/handler/tokengrant/token_exchange.go`（唯一消费方）；对照：同包租户资源均有完整管理面——`interfaces/grpcserver/grpcadmin/admin_tenants.go`（`TenantAdminService` CRUD + set-status + 吊销钩子）、`interfaces/admin/tenants.go`（成员/邀请/导出）。

**为什么需要**：跨租户访客是 SSO 产品差异化卖点，但当前只能在单进程内存中演示。生产部署（sqlite/postgres 后端）下信任图无法持久化，与同模块其他资源"SPI + 参考实现 + 管理面 + 审计"的完整度严重不齐；且信任边是安全敏感数据，缺少"列出/吊销"运营面意味着发现风险后只能重启清空或改代码，与模块自身 fail-closed 的信任模型（AGENTS.md §3）形成运维缺口。补齐 sqlite/postgres 后端 + 仿照 `TenantAdminService` 的 admin CRUD（含审计事件）是让该特性可交付的必经之路。
