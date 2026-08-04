# Tech Lead 分析报告：代码反审核验后的五方向执行计划

> **分析者：** Tech Lead  
> **基准：** 代码反审核验报告（2026-07-12 交叉核验）+ 架构分析五方向  
> **代码基线：** 当前树（2026-07-12），基于 `4c79fb82` + `a635191d`  
> **方法：** 每次断言均经 grep 核验，工作量基于实际代码行数而非 ROI 文本估计

---

## 目录

1. [最终优先级矩阵](#1-最终优先级矩阵)
2. [任务分解](#2-任务分解)
3. [执行顺序与并行任务组](#3-执行顺序与并行任务组)
4. [技术风险评估](#4-技术风险评估)
5. [资源评估与里程碑](#5-资源评估与里程碑)
6. [质量保证策略](#6-质量保证策略)
7. [分阶段实施计划](#7-分阶段实施计划)
8. [附录：核验关键修正](#8-附录核验关键修正)

---

## 1. 最终优先级矩阵

### 核验后的总工作量

| 方向 | 原始分析 | 评审修正 | **最终（核验后）** | 关键修正理由 |
|------|---------|---------|-----------------|-------------|
| **① 身份编排** | L（1800） | L+XL（2200） | **L（1800）** | ConsentStore **已存在**（4 后端实现 + `/consents/me` API），消除评审错误添加的前置依赖 |
| **② API 安全产品化** | L（1200） | M（700） | **M+（850）** | 开发者门户 SPA 已存在节省 ~350 行，但 (C) 网关适配器是新工作 (~150 行) |
| **③ AI 运维** | M（1300） | M（1100） | **M（1100）** | 身份图提升 + 同意降级 NL 查询——评审建议合理 |
| **④ 治理委托** | M（1100） | M（900） | **M（900）** | helpdesk 处理程序是完整代码（~350 行），非"桩代码"；无需从零构建 |
| **⑤ 多集群联邦** | XL（2200） | L+XL（1700） | **L+XL（1700）** | SSOConfigDrift CRD + MQTT/SSE 已存在，降低 ~500 行工作量 |

**总计：** 6350 行（原始 7600 → 评审 6800 → 核验后 6350）

### 最终优先级

```
        高 │ ① 身份编排                       ④ 治理委托
           │     P1 ─── 管线钩子 + 声明式流程        P2 ─── helpdesk 角色绑定
           │
   价值    │ ⑤ 多集群联邦                     ② API 安全产品化
           │     P3 ─── CRD 扩展 + 跨集群同步         P4 ─── 开发者门户扩展
           │
        低 │ ③ AI 运维
           │     P5 ─── 身份图先行，LLM 后加
           │
           └──────────────────────────────────────────────
              低                                    高
                        实现复杂度
```

### 调整理由

| 方向 | 调整 | 理由 |
|------|------|------|
| **① 身份编排** | P1（最高优先级） | ConsentStore 已存在——管线钩子可以零等待启动。这是项目从"协议完备的 SSO SDK"向"可编排的身份平台"演进的核心。真实的 ROI：客户可自定义认证流程，无需修改代码。 |
| **④ 治理委托** | P2 | helpdesk 处理程序已实现并挂载（`interfaces/admin/users.go:16`，~350 行），正式角色模型约束是增量工作。企业租户委托是刚需——SOX 合规要求"谁做了什么"的审计链。 |
| **⑤ 多集群联邦** | P3（降一级） | CRD + MQTT/SSE 资产已存在真实降低门槛，但跨集群策略冲突检测是架构级投入，且需要方向①的管线稳定后才能验证联邦策略的正确性。建议方向①阶段一结束后启动。 |
| **② API 安全产品化** | P4（降一级） | 开发者门户 SPA 的存在降低了 40% 工作量，但 API 密钥自助和 Gateway 适配器是产品特性而非架构需求。市场时机需要确认——是否有客户真正要求自服务门户。 |
| **③ AI 运维** | P5 | 同意评审的建议：身份图 (D) 应先构建（即使没有 AI 也有独立价值——管理员查询、依赖分析）。LLM 适配器是薄层，在身份图稳定后快速添加。 |

---

## 2. 任务分解

### 2.1 方向①：身份编排——P1（1800 行）

**架构前提：** ConsentStore 已存在（`shared/core/spi.go:282` → Memory/SQLite/Redis/Postgres 四套实现 + `/consents/me` API）。管线钩子不依赖 ConsentStore——声明式流程的 consent step 依赖它。

#### 阶段一：Authentication Pipeline Hooks（~800 行）

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| D1-T001 | `AuthPipelineHook` 类型 + 注册 SPI | `shared/core/auth_pipeline.go`（新建） | 无 | 4h | `AuthPipelineHook func(ctx, *AuthContext, *AuthResult) (*AuthMutation, error)` 类型定义；`PreAuthHook`/`PostAuthHook`/`PreTokenIssuanceHook` 三个注册点；返回 `HookID` 用于撤销 |
| D1-T002 | `HookRegistry` 实现 + `WithPreAuthHook` 选项 | `interfaces/sso/auth_pipeline.go`（新建），`interfaces/sso/options_passwd.go`（扩展） | D1-T001 | 6h | `HookRegistry` 按阶段存储有序钩子列表；支持 `WithHookPriority` 排序；`nil` 注册点短路零开销；所有 `With*` 选项在 `Server` 启动时验证（钩子签名兼容性） |
| D1-T003 | Pre-Auth 钩子执行点——登录路径入口 | `interfaces/sso/server_login.go`（修改） | D1-T002 | 4h | 在身份验证执行前调用所有 pre-auth 钩子；任一钩子返回 `ErrHookAbort` 则中止登录流程并返回对应错误；每个钩子有独立超时（默认 5s，可配置）；失败默认 fail-open（继续流程，记录 audit） |
| D1-T004 | Post-Auth 钩子执行点——登录成功后、令牌签发前 | `interfaces/sso/server_finish_login.go`（修改），`protocols/oauth/handle_token.go`（修改） | D1-T002 | 4h | 在 `AuthResult` 生成后、`issueToken` 前调用 post-auth 钩子；钩子可通过 `*AuthMutation` 修改 scope、`acr`、`amr`、自定义 claims；任一钩子返回 `ErrHookAbort` 中止令牌签发 |
| D1-T005 | Pre-Token-Issuance 钩子——令牌定制 | `protocols/oauth/token.go`（修改），`protocols/oidc/token.go`（修改） | D1-T004 | 4h | 在 JWT 签发前调用，可修改 claims 或拒绝签发；用于动态 claim 注入（如从外部 API 获取用户角色）；此钩子运行在热路径上——超时上限 1s，fail-open（跳过钩子继续签发） |
| D1-T006 | 钩子执行 metrics + 追踪 | `interfaces/sso/auth_pipeline.go`（扩展），`platform/metrics/`（扩展） | D1-T002 | 3h | prometheus 指标：`sso_pipeline_hook_duration_seconds{phase, hook_name}`、`sso_pipeline_hook_errors_total`；每个钩子执行有独立 span（OpenTelemetry） |
| D1-T007 | 钩子审计事件 | `shared/core/audit_events.go`（扩展） | D1-T001 | 2h | `EventPipelineHookExecuted` 包含 `phase`、`hook_name`、`duration_ms`、`error`（如果有）、`decision`（allow/abort） |
| D1-T008 | 集成测试：管线钩子 E2E | `test/auth_pipeline_test.go`（新建） | D1-T003~D1-005 | 4h | bufconn 测试：pre-auth 钩子终止登录 → 401；post-auth 钩子注入 scope → token 包含 scope；pre-token 钩子拒绝 → 400；所有钩子超时 → fail-open 继续；钩子顺序正确性 |

**阶段一小计：** ~31h

#### 阶段二：声明式认证流程（~1000 行）

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| D1-T009 | `AuthFlowDefinition` YAML 模型 + 校验器 | `shared/core/auth_flow.go`（新建），`config/schema/`（扩展） | D1-T001 | 6h | `AuthFlowDefinition` 包含 `version`、`steps[]`（`name`、`providers[]`、`if`、`on_error`、`consent_required`）；校验器检查：provider 引用必须对应已注册 authenticator、`if` 表达式纯函数、无循环引用、无歧义分支 |
| D1-T010 | 流程解释器 engine | `protocols/authflow/engine.go`（新建），`protocols/authflow/step.go`（新建） | D1-T009 | 8h | `FlowEngine` 按顺序执行步骤（短路语义：`on_error=next_provider` 失败后尝试下一 provider；`on_error=fail_open` 跳过；`on_error=fail_closed` 中止）；每一步记录 `StepResult` 到审计 |
| D1-T011 | Consent step 集成 —— 使用已有 ConsentStore | `protocols/authflow/step_consent.go`（新建） | D1-T009, ConsentStore（已存在） | 4h | 流程中 `consent_required: true` 的步骤自动调用 `ConsentStore.HasGrant()`；无 grant 则返回 `consent_required` 响应（触发前端展示同意页面）；同意后调用 `RecordGrant()` |
| D1-T012 | 流程与 client binding | `shared/core/auth_flow.go`（扩展），`core/Client`（扩展 `AuthFlowID` 字段） | D1-T010 | 3h | Client 新增 `default_auth_flow_id` 和 `allowed_auth_flows[]`；`POST /auth` 可选 `?flow=...` 参数覆盖默认流程；tenant 级别默认流程 fallback 链：`client → tenant → system_default` |
| D1-T013 | 流程结果写入 session / token claims | `protocols/authflow/engine.go`（扩展），`protocols/oauth/token.go`（修改） | D1-T010 | 4h | 流程执行完毕后，`flow_result` 写入 session（含 `flow_id`、`steps_executed`、`acr` 提升）；令牌签发时读取 session 的 flow result 写入自定义 claim `auth_flow` |
| D1-T014 | 集成测试：声明式流程 E2E | `test/auth_flow_test.go`（新建） | D1-T010~D1-013 | 6h | YAML 定义流程 → 启动 server → 调用 `/auth` → 遵循流程定义 → 返回预期 scope/claims；`consent_required` 步骤 → 触发 consent 页面 → 同意后继续；`on_error` 语义正确性 |
| D1-T015 | 声明式流程 Prometheus 指标 | `protocols/authflow/metrics.go`（新建） | D1-T010 | 2h | `sso_auth_flow_duration_seconds{flow_id, status}`、`sso_auth_flow_step_duration`、`sso_auth_flow_consent_required_total` |
| D1-T016 | 声明式流程配置热加载 | `config/reload/`（扩展），`protocols/authflow/engine.go`（扩展） | D1-T010, T012 | 3h | `SIGHUP` 重新加载流程 YAML；校验失败保留旧配置并 log warning；已进行的 flow 不受 reload 影响（使用 snapshot） |

**阶段二小计：** ~36h

**方向①总工时：** ~67h（约 8.5 开发日）

---

### 2.2 方向④：治理委托——P2（900 行）

**架构前提：** helpdesk 处理程序已实现（`interfaces/admin/users.go`，~350 行），正式路由已挂载（`server_routes_admin.go:192`）。不需要从零构建处理程序——只需要正式角色模型约束。

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| D4-T001 | 管理员角色模型定义 + `BuiltInRoles` 注册 | `interfaces/admin/roles.go`（新建），`config/config.go`（扩展） | 无 | 4h | `org_admin`、`user_admin`、`audit_viewer`、`helpdesk`、`api_admin` 五个预定义角色；角色表示为 `permissions.ScopeSet` 通配符组合；`WithBuiltInRoles` 选项 |
| D4-T002 | helpdesk 作用域检查中间件 | `interfaces/admin/middleware.go`（修改） | D4-T001 | 4h | 新增 `requireAdminRole(roleName)` middleware；`HandleAdminSetUserPassword` → `helpdesk` 角色检查；`HandleAdminClearBruteForceLockout` → `helpdesk`；`HandleAdminListUserConsents` → `helpdesk` 或 `user_admin` |
| D4-T003 | scope 验证失败 → 403 错误响应 | `interfaces/admin/errors.go`（新建或扩展） | D4-T002 | 2h | 无效角色的请求返回 `403 {error: "insufficient_admin_role", required_role: "helpdesk"}`；响应包含 `WWW-Authenticate: Bearer realm="admin"` 头 |
| D4-T004 | 租户级 scope 隔离集成 | `interfaces/admin/middleware.go`（扩展），`domains/tenant/`（扩展） | D4-T002 | 4h | scope 模板 `admin:write.tenant:{tid}/user:password_reset` 在运行时从请求 `tenant_id` 渲染；同一 server 的多租户管理员只能管理自己的租户；`admin:write.tenant:*` 为跨租户管理员 |
| D4-T005 | Admin 角色分配 API + 存储 | `interfaces/admin/role_assignments.go`（新建），`shared/core/admin_role.go`（新建） | D4-T001 | 6h | `POST /admin/roles/assignments` → 为用户分配角色；`GET /admin/roles/assignments` → 列出租户角色；`DELETE /admin/roles/assignments/:id` → 撤销角色；`AdminRoleAssignment` 含 `user_id`、`tenant_id`、`role_name`、`assigned_by`、`expires_at` |
| D4-T006 | 角色分配持久化（Memory + SQLite 后端） | `interfaces/admin/store_role.go`（新建），`infrastructure/defaultimpl/sqlite/admin_role.go`（新建） | D4-T005 | 4h | Memory 实现用于开发/测试；SQLite 实现用于生产单节点；接口 `AdminRoleStore`：`Assign()`、`ListByUser()`、`ListByTenant()`、`Revoke()` |
| D4-T007 | 角色变更审计事件 | `shared/core/audit_events.go`（扩展） | D4-T005 | 2h | `EventAdminRoleAssigned`、`EventAdminRoleRevoked` 审计事件；包含 `user_id`、`role_name`、`tenant_id`、`assigned_by` |
| D4-T008 | Admin SPA "角色管理"页面 | `interfaces/web/admin/app.js`（扩展） | D4-T005, D4-T006 | 4h | Admin SPA 新增"角色"导航项 → 角色分配界面（搜索用户 → 分配角色 → 选择租户 → 保存）；当前分配列表（用户、角色、租户、过期时间）；撤销按钮 |
| D4-T009 | 集成测试：角色模型 E2E | `test/admin_roles_test.go`（新建） | D4-T002~D4-008 | 4h | bufconn 测试：无角色 token → helpdesk API 403；`helpdesk` 角色 → helpdesk API 200；跨租户请求 → 403；角色分配 → 立即生效；角色撤销 → 后续请求 403 |
| D4-T010 | 文档：admin 角色模型 + 委托管理指南 | `docs/admin-roles.md`（新建） | D4-T001~D4-009 | 3h | 包含每个预定义角色的 scope 定义；配置示例；Terraform/Pulumi 集成示例；角色分配最佳实践 |

**方向④总工时：** ~37h（约 4.5 开发日）

---

### 2.3 方向⑤：多集群联邦——P3（1700 行）

**架构前提：** SSOConfigDrift CRD 已存在（`cmd/sso-operator/apiv1alpha1/ssoconfigdrift_types.go` + controller in `cmd/sso-operator/controller/`）；MQTT（`infrastructure/mqtt/`）和 SSE（`platform/sse/`）传输原语已存在。

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| D5-T001 | 跨集群策略同步原语 SPI | `protocols/federation/cluster_sync.go`（新建），`protocols/federation/transport.go`（新建） | 无 | 6h | `PolicySyncTransport` SPI 定义（`Publish(ctx, topic, msg)` + `Subscribe(topic, handler)`）；`ClusterPolicyStore` 接口（`SyncPolicy()`、`GetRemotePolicy()`、`ListPolicies()`）；MQTT 和 SSE 两个内置传输实现 |
| D5-T002 | MQTT 传输实现（复用现有模块） | `protocols/federation/transport_mqtt.go`（新建） | D5-T001, `infrastructure/mqtt/`（已存在） | 4h | `MQTTTransport` 实现 `PolicySyncTransport`；使用现有 MQTT client；QoS 1（至少一次投递）；topic 命名空间 `sso/policy/{tenant_id}/{policy_id}` |
| D5-T003 | SSE 传输实现（复用现有平台） | `protocols/federation/transport_sse.go`（新建） | D5-T001, `platform/sse/`（已存在） | 4h | `SSETransport` 实现；SSE endpoint 为备用传输（MQTT 不可用时）；支持重连回退 |
| D5-T004 | SSOConfigDrift CRD 扩展 —— 支持策略同步 | `cmd/sso-operator/apiv1alpha1/ssoconfigdrift_types.go`（修改） | D5-T001 | 4h | CRD 新增 `Spec.SyncPolicy` 字段（`transport`、`topic`、`interval`）；新增 `Status.LastSyncTime` 和 `Status.RemoteHash`；controller reconciler 集成 `ClusterPolicyStore.SyncPolicy()` |
| D5-T005 | 跨集群策略差异检测 + 冲突解决 | `protocols/federation/drift_detector.go`（新建） | D5-T004 | 8h | `DriftDetector` 周期性对比本地和远程策略哈希；差异分类：`added`（远程有本地无）、`removed`、`modified`、`conflicting`（相同策略不同值）；冲突解决策略配置化：`remote_wins`/`local_wins`/`manual_review` |
| D5-T006 | 策略同步审计事件 | `shared/core/audit_events.go`（扩展） | D5-T005 | 2h | `EventPolicySynced`（含 `source_cluster`、`policies_count`、`drift_count`）；`EventPolicyConflictDetected`（含 `policy_id`、`local_hash`、`remote_hash`、`resolution`） |
| D5-T007 | 全局条件访问策略 CRD（新 CRD） | `cmd/sso-operator/apiv1alpha1/globalcondition_types.go`（新建），`cmd/sso-operator/crd-globalcondition.yaml`（新建） | D5-T004 | 6h | `GlobalConditionalAccessPolicy` CRD：`Spec` 含 `name`、`conditions[]`、`actions[]`、`priority`、`apply_to_clusters[]`；controller 将全局策略分发到指定集群的本地 `ConditionalAccessPolicy` |
| D5-T008 | 全局策略 E2E 测试 | `test/federation_e2e_test.go`（新建） | D5-T005~D5-007 | 6h | bufconn 双集群模拟：集群 A 创建全局策略 → 传输到集群 B → B 应用为本地策略；集群 A 更新策略 → B 检测 diff → 自动同步；冲突场景 → `manual_review` 挂起 → admin 解决后恢复 |
| D5-T009 | 联邦 debug CLI | `cmd/sso-ctl/federation.go`（新建） | D5-T005 | 4h | `sso-ctl federation status` → 显示传输连接状态、同步统计；`sso-ctl federation drift` → 显示当前漂移摘要；`sso-ctl federation sync --force` → 手动触发全量同步 |
| D5-T010 | 联邦监控 dashboard | `interfaces/web/admin/app.js`（扩展） | D5-T005 | 4h | Admin SPA 新增"联邦"导航项 → 显示集群列表（名称、连接状态、上次同步时间）；漂移摘要（新增/修改/冲突数）；手动同步按钮 |
| D5-T011 | 文档：多集群联邦部署指南 | `docs/multi-cluster-federation.md`（新建） | D5-T001~D5-010 | 4h | 包含 K8s 部署架构（CRD + controller）；传输选型建议（MQTT vs SSE）；网络要求（防火墙规则、TLS 配置）；故障排查手册 |

**方向⑤总工时：** ~52h（约 6.5 开发日）

---

### 2.4 方向②：API 安全产品化——P4（850 行）

**架构前提：** 开发者门户 SPA 已存在（`WithDeveloperPortalFS` + `pathDeveloperPortalPrefix`）。后端 DCR CRUD API 已存在。CORS 中间件已存在。

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| D2-T001 | 开发者门户 SPA 新增"API 密钥"标签页 | `interfaces/web/portal/app.js`（扩展），`interfaces/web/portal/index.html`（扩展） | 无 | 4h | Portal 新增"API Keys"导航标签；调用 `GET /clients/me/api-keys` 显示密钥列表；每行显示 key ID（前缀）、创建时间、最后使用时间、scope 摘要；"新建 API 密钥"按钮 |
| D2-T002 | API 密钥创建 + scope 选择 UI | `interfaces/web/portal/app.js`（扩展） | D2-T001 | 3h | 新建 API 密钥对话框：选择 scope（复选框组）；设置过期时间（可选）；点击创建 → `POST /clients/me/api-keys` → 显示密钥值（一次性）；"复制"按钮 |
| D2-T003 | API 密钥后端 CRUD（复用 DCR 框架） | `protocols/oauth/dcr_api_keys.go`（新建），`shared/core/api_key.go`（新建） | 无 | 6h | `APIKey` 数据结构（`ID`、`KeyPrefix`、`KeyHash`、`ClientID`、`Scopes`、`CreatedAt`、`ExpiresAt`、`LastUsedAt`、`RevokedAt`）；`APIKeyStore` SPI（`Create()`、`ListByClient()`、`Revoke()`、`Authenticate()`）；`memory` + `sqlite` 两套实现 |
| D2-T004 | API 密钥认证中间件 | `interfaces/sso/server_api_key_auth.go`（新建），`interfaces/sso/options.go`（扩展） | D2-T003 | 4h | `Authorization: Bearer apk_<key>` 认证；查询 `APIKeyStore.Authenticate(keyHash)`；成功后将 `clientID` + `scopes` 注入请求上下文；与现有 bearer token 认证共存（优先 `token` > `api_key`） |
| D2-T005 | API 密钥使用指标 + 审计 | `protocols/oauth/dcr_api_keys.go`（扩展） | D2-T003, D2-T004 | 3h | prometheus `sso_api_key_auth_total{status}`；审计事件 `EventAPIKeyAuthenticated`、`EventAPIKeyCreated`、`EventAPIKeyRevoked`；`LastUsedAt` 每 5 分钟批量更新 |
| D2-T006 | 网关适配器 SPI（Envoy ext-authz） | `protocols/gatewayadapter/spi.go`（新建），`protocols/gatewayadapter/envoy.go`（新建） | D2-T003, D2-T004 | 6h | `GatewayAdapter` SPI 接口（`Check(ctx, *CheckRequest) → *CheckResponse`）；Envoy ext-authz v3 实现；支持 API key 验证 + 缓存（减少 SSO 调用）；`CheckResponse` 包含 `allowed`、`headers`（注入）、`body`（拒绝原因） |
| D2-T007 | 开发者门户"Gateway 集成指南"页面 | `interfaces/web/portal/app.js`（扩展） | D2-T006 | 2h | Portal SPA 新增"Gateway"标签页；显示 Envoy ext-authz 配置示例（YAML）；Istio AuthorizationPolicy 示例；`curl` 测试命令 |
| D2-T008 | 集成测试：API 密钥 + Gateway 适配器 | `test/api_key_gateway_test.go`（新建） | D2-T003~D2-007 | 4h | bufconn 测试：API 密钥创建 → 认证成功 → 403 撤销后认证失败；Gateway 适配器：正确 CheckRequest → CheckResponse；缓存过期 → 重新请求 SSO |
| D2-T009 | 文档：API 密钥产品化 | `docs/api-keys.md`（新建） | D2-T003~D2-007 | 2h | 包含 API 密钥最佳实践（前缀识别、轮换策略、scope 最小化）；Gateway 集成说明 |

**方向②总工时：** ~34h（约 4 开发日）

---

### 2.5 方向③：AI 运维——P5（1100 行）

**架构前提：** 身份图是方向③的核心基础设施组件，不论是否接 AI 都应有独立价值。

#### 阶段一：身份图构建（~600 行）

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| D3-T001 | `IdentityGraph` 数据模型 + 节点/边定义 | `domains/identitygraph/graph.go`（新建） | 无 | 6h | 节点类型：`UserNode`、`ClientNode`、`GroupNode`、`RoleNode`、`PermissionNode`、`SessionNode`、`TokenNode`；边类型：`HAS_ROLE`、`BELONGS_TO_GROUP`、`CREATED_SESSION`、`ISSUED_TOKEN`、`HAS_PERMISSION`；节点属性可扩展 |
| D3-T002 | 身份图存储 SPI + 基于 SQLite 的持久化 | `domains/identitygraph/store.go`（新建），`domains/identitygraph/store_sqlite.go`（新建） | D3-T001 | 6h | `IdentityGraphStore` SPI：`UpsertNode()`、`UpsertEdge()`、`QueryNeighbors()`、`QueryPath()`、`QueryByAttribute()`；SQLite 实现（节点表 + 边表 + 属性表）；GIN 索引支持属性查询 |
| D3-T003 | 身份图数据采集器——从现有事件流构建图 | `domains/identitygraph/ingester.go`（新建） | D3-T002 | 6h | 订阅审计事件 → 创建/更新节点和边；登录事件 → `User-CREATED_SESSION-Session`；令牌签发 → `User-ISSUED_TOKEN-Token`；管理员操作 → `Admin-MODIFIED-Client`；初次启动时全量回放 audit.Store → 构建完整索引 |
| D3-T004 | 身份图查询 API | `interfaces/admin/identity_graph.go`（新建） | D3-T002, D3-T003 | 4h | `GET /admin/identity-graph/query?type=user&attribute=email&value=user@example.com` → 返回节点 + 一度关系；`GET /admin/identity-graph/path?from=user:x&to=client:y&max_depth=5` → 返回最短路径；`GET /admin/identity-graph/stats` → 节点/边数量统计 |
| D3-T005 | 身份图 Admin SPA 可视化 | `interfaces/web/admin/app.js`（扩展） | D3-T004 | 4h | Admin SPA 新增"身份图"导航项 → 搜索框（按用户/客户端/角色搜索）→ 搜索结果展示节点 + 关系边（力导向图或列表视图）→ 点击节点展开详情 |

**阶段一小计：** ~26h

#### 阶段二：NL 查询接口（~500 行）

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| D3-T006 | 自然语言查询 → 图查询翻译引擎 | `domains/identitygraph/nl/parser.go`（新建），`domains/identitygraph/nl/intents.go`（新建） | D3-T004 | 8h | 规则驱动的 NL 解析器（非 LLM）：识别意图模式（"哪些用户有 X 权限"→ `QueryNeighbors(RoleNode, HAS_PERMISSION, PermissionNode{name:X})`）；支持 10+ 个查询模板；匹配失败返回清晰提示 |
| D3-T007 | LLM 适配器（可选 OpenAI/自托管） | `domains/identitygraph/nl/llm_adapter.go`（新建） | D3-T006 | 6h | `LLMAdapter` 接口：`Translate(ctx, nlQuery) → (GraphQuery, error)`；OpenAI 实现（prompt 工程 + JSON schema 约束响应格式）；自托管实现（本地 llama 实例）；fallback 到规则引擎（LLM 不可用或超时） |
| D3-T008 | NL 查询 API + 权限控制 | `interfaces/admin/identity_graph_nl.go`（新建） | D3-T006, D3-T007 | 4h | `POST /admin/identity-graph/query-nl` → `{"query": "show me all users with admin role"}` → 返回匹配的节点 + 关系；scope 保护（`admin:read.identity-graph`）；速率限制（5 req/min per user） |
| D3-T009 | 查询结果解释 + 审计 | `domains/identitygraph/nl/explain.go`（新建） | D3-T008 | 3h | 每次查询返回 `explanation`（"找到 5 个用户通过 `org_admin` 角色拥有 `admin:write` 权限"）；审计事件 `EventIdentityGraphQuery` 含原始 NL 和翻译后的图查询 |
| D3-T010 | Admin SPA "AI 查询"输入框 | `interfaces/web/admin/app.js`（扩展） | D3-T008 | 3h | Admin SPA 身份图页面新增 NL 输入框（"用自然语言查询身份图..."）；回车提交 → 展示结果（节点 + 关系）；搜索历史下拉 |

**阶段二小计：** ~24h

**方向③总工时：** ~50h（约 6.5 开发日）

---

## 3. 执行顺序与并行任务组

```mermaid
graph TD
    %% ===== 方向① 身份编排 (P1) =====
    subgraph 方向①_身份编排[方向① 身份编排 P1]
        D1T001["D1-T001 AuthPipelineHook SPI<br/>4h"] --> D1T002["D1-T002 HookRegistry + With*<br/>6h"]
        D1T002 --> D1T003["D1-T003 Pre-Auth 钩子执行点<br/>4h"]
        D1T002 --> D1T004["D1-T004 Post-Auth 钩子执行点<br/>4h"]
        D1T002 --> D1T005["D1-T005 Pre-Token 钩子<br/>4h"]
        D1T003 --> D1T008["D1-T008 管线 E2E 测试<br/>4h"]
        D1T004 --> D1T008
        D1T005 --> D1T008
        D1T006["D1-T006 钩子 metrics<br/>3h"] -.-> D1T002
        D1T007["D1-T007 审计事件<br/>2h"] -.-> D1T002

        D1T009["D1-T009 AuthFlow YAML 模型<br/>6h"] --> D1T010["D1-T010 流程解释器<br/>8h"]
        D1T010 --> D1T011["D1-T011 Consent step<br/>4h"]
        D1T010 --> D1T012["D1-T012 Client binding<br/>3h"]
        D1T010 --> D1T013["D1-T013 Session/Claims<br/>4h"]
        D1T011 --> D1T014["D1-T014 流程 E2E 测试<br/>6h"]
        D1T012 --> D1T014
        D1T015["D1-T015 流程 metrics<br/>2h"] -.-> D1T010
        D1T016["D1-T016 热加载<br/>3h"] -.-> D1T010
    end

    %% ===== 方向④ 治理委托 (P2) =====
    subgraph 方向④_治理委托[方向④ 治理委托 P2]
        D4T001["D4-T001 角色模型 + BuiltInRoles<br/>4h"] --> D4T002["D4-T002 helpdesk scope 中间件<br/>4h"]
        D4T002 --> D4T003["D4-T003 403 错误响应<br/>2h"]
        D4T002 --> D4T004["D4-T004 租户级 scope 隔离<br/>4h"]
        D4T001 --> D4T005["D4-T005 角色分配 API + 存储<br/>6h"]
        D4T005 --> D4T006["D4-T006 角色存储持久化<br/>4h"]
        D4T005 --> D4T007["D4-T007 角色变更审计<br/>2h"]
        D4T005 --> D4T008["D4-T008 Admin SPA 角色管理<br/>4h"]
        D4T002 --> D4T009["D4-T009 角色模型 E2E<br/>4h"]
        D4T005 --> D4T009
        D4T010["D4-T010 文档<br/>3h"] -.-> D4T009
    end

    %% ===== 方向⑤ 多集群联邦 (P3) =====
    subgraph 方向⑤_多集群联邦[方向⑤ 多集群联邦 P3]
        D5T001["D5-T001 策略同步 SPI + Transport<br/>6h"] --> D5T002["D5-T002 MQTT 传输实现<br/>4h"]
        D5T001 --> D5T003["D5-T003 SSE 传输实现<br/>4h"]
        D5T001 --> D5T004["D5-T004 CRD 扩展<br/>4h"]
        D5T002 --> D5T005["D5-T005 漂移检测 + 冲突解决<br/>8h"]
        D5T003 --> D5T005
        D5T004 --> D5T005
        D5T005 --> D5T006["D5-T006 审计事件<br/>2h"]
        D5T005 --> D5T007["D5-T007 全局条件 CRD<br/>6h"]
        D5T005 --> D5T008["D5-T008 联邦 E2E 测试<br/>6h"]
        D5T005 --> D5T009["D5-T009 联邦 CLI<br/>4h"]
        D5T005 --> D5T010["D5-T010 联邦 dashboard<br/>4h"]
        D5T011["D5-T011 部署文档<br/>4h"] -.-> D5T008
    end

    %% ===== 方向② API 安全产品化 (P4) =====
    subgraph 方向②_API安全[方向② API 安全产品化 P4]
        D2T001["D2-T001 Portal API Keys 标签页<br/>4h"] --> D2T002["D2-T002 密钥创建 + scope 选择<br/>3h"]
        D2T003["D2-T003 API Key 后端 CRUD<br/>6h"] --> D2T004["D2-T004 API Key 认证中间件<br/>4h"]
        D2T004 --> D2T005["D2-T005 使用指标 + 审计<br/>3h"]
        D2T004 --> D2T006["D2-T006 网关适配器 SPI + Envoy<br/>6h"]
        D2T001 --> D2T007["D2-T007 Gateway 集成指南页<br/>2h"]
        D2T003 --> D2T008["D2-T008 集成测试<br/>4h"]
        D2T004 --> D2T008
        D2T009["D2-T009 文档<br/>2h"] -.-> D2T008
    end

    %% ===== 方向③ AI 运维 (P5) =====
    subgraph 方向③_AI运维[方向③ AI 运维 P5]
        D3T001["D3-T001 IdentityGraph 数据模型<br/>6h"] --> D3T002["D3-T002 图存储 SPI + SQLite<br/>6h"]
        D3T002 --> D3T003["D3-T003 数据采集器<br/>6h"]
        D3T002 --> D3T004["D3-T004 图查询 API<br/>4h"]
        D3T004 --> D3T005["D3-T005 Admin SPA 可视化<br/>4h"]
        D3T004 --> D3T006["D3-T006 NL 查询规则引擎<br/>8h"]
        D3T006 --> D3T007["D3-T007 LLM 适配器<br/>6h"]
        D3T006 --> D3T008["D3-T008 NL 查询 API<br/>4h"]
        D3T008 --> D3T009["D3-T009 查询解释 + 审计<br/>3h"]
        D3T008 --> D3T010["D3-T010 Admin SPA NL 输入<br/>3h"]
    end

    %% ===== 跨方向依赖 =====
    D1T011 -.->|"consent step 依赖<br/>ConsentStore（已存在）"| Consented[ConsentStore<br/>已存在]

    %% ===== 并行任务组标注 =====
    subgraph 并行组A[并行组 A：立即启动]
        direction LR
        PG_A1["D1-T001<br/>管线 SPI"]
        PG_A2["D4-T001<br/>角色模型"]
        PG_A3["D5-T001<br/>同步 SPI"]
        PG_A4["D2-T003<br/>API Key CRUD"]
        PG_A5["D3-T001<br/>图数据模型"]
    end

    subgraph 并行组B[并行组 B：管线基建]
        direction LR
        PG_B1["D1-T002<br/>HookRegistry"]
        PG_B2["D1-T006<br/>metrics"]
        PG_B3["D1-T007<br/>审计事件"]
    end

    subgraph 并行组C[并行组 C：方向④ 并行走量]
        direction LR
        PG_C1["D4-T002<br/>scope 中间件"]
        PG_C2["D4-T005<br/>角色分配 API"]
        PG_C3["D4-T008<br/>Admin SPA"]
    end

    subgraph 并行组D[并行组 D：跨集群同步]
        direction LR
        PG_D1["D5-T002<br/>MQTT 传输"]
        PG_D2["D5-T003<br/>SSE 传输"]
        PG_D3["D5-T004<br/>CRD 扩展"]
    end
```

### 可并行执行的任务组

| 并行组 | 任务 | 说明 |
|--------|------|------|
| **A（核心 SPI 层，无依赖）** | D1-T001, D4-T001, D5-T001, D2-T003, D3-T001 | 五个方向的基础 SPI 定义可完全并行——独立 package、无交叉依赖。**建议 3 人同时开工** |
| **B（管线基建组）** | D1-T002, D1-T006, D1-T007 | HookRegistry + metrics + 审计事件三件套，可 2 人并行 |
| **C（治理委托组）** | D4-T002, D4-T005, D4-T008 | scope 中间件 + 角色分配 API + Admin SPA 角色页面，2 人并行 |
| **D（集群传输组）** | D5-T002, D5-T003, D5-T004 | MQTT 实现 + SSE 实现 + CRD 扩展，2 人并行 |
| **E（认证侧后端）** | D2-T003, D2-T004, D2-T006 | API Key CRUD + 认证中间件 + 网关适配器，2 人并行（依赖 D2-T003 完成） |
| **F（身份图后端）** | D3-T002, D3-T003, D3-T004 | 图存储 + 采集器 + 查询 API，2 人并行（依赖 D3-T001） |

---

## 4. 技术风险评估

### 4.1 分方向风险矩阵

| 方向 | 风险 | 等级 | 缓解策略 |
|------|------|------|---------|
| **①** | 声明式流程 YAML 配置错误 → 认证死循环 | **高** | 启动时静态校验（fail-loud）；检测循环引用；`if` 表达式必须无副作用；运行时 goroutine 监控（死循环检测 → panic 恢复） |
| **①** | 管线钩子超时阻塞认证热路径 | **中** | 每个钩子独立超时（pre/post-auth 5s，pre-token 1s）；fail-open 默认（超时跳过 + audit 记录）；`context.Context` 传递 deadline |
| **①** | Consent step 的 `HasGrant` 检查在高并发下成为性能瓶颈 | **中** | `HasGrant` 使用 read-through 缓存（TTL 60s）；ConsentStore 已支持使用 Redis/memory 后端；scope 超集检查是 O(1) 操作 |
| **①** | 管线钩子顺序依赖——错误排序导致逻辑错误 | **中** | 钩子注册时同时记录 `depends_on[]`；注册时验证钩子 DAG 无环；`WithHookPriority` 强制指定顺序 |
| **④** | 角色模型 scope 通配符匹配过于宽泛 | **中** | 每个预定义角色显式列出允许的 scope，不使用 `*` 通配符；`permissions` 包已有精确的通配符匹配器；集成测试验证每个角色的确切权限边界 |
| **④** | 租户 scope 模板渲染注入问题 | **低** | 使用模板参数（`{tid}`）而非字符串拼接；模板由 `tenant_id` 从已认证的 context 中提取，非用户输入 |
| **⑤** | MQTT broker 单点故障导致跨集群策略同步中断 | **中** | MQTT 传输支持高可用集群连接（broker URI 列表）；SSE 传输作为备用；同步状态通过 `Status.LastSyncTime` 暴露，监控报警阈值 > 5min 未同步 |
| **⑤** | 全局策略冲突无法自动解决 → 人工介入延迟长 | **中** | 默认 `remote_wins`（跟随主集群）；`manual_review` 模式生成告警 + 暂停同步，而非阻塞；人工解决后通过 `sso-ctl federation sync --force` 恢复 |
| **②** | API 密钥泄露 → 无法区分合法/恶意使用 | **低** | 密钥前缀可识别来源（`apk_live_` vs `apk_test_`）；key hash 存储（不可逆）；`LastUsedAt` + 异常使用模式检测（`domains/anomaly`） |
| **②** | Gateway 适配器缓存的 token/introspect 结果过期 | **低** | 缓存默认 TTL 30s（短）；支持主动失效（通过 Bus 订阅 `KindTokenRevoked`）；引入缓存暂用 `max_ttl=60s` 硬限制 |
| **③** | 身份图 SQLite 查询在大租户（100 万节点）下的性能 | **中** | 节点表 + 边表的主键索引 + GIN 覆盖索引；限制 `max_depth=5` 防止爆炸式查询；分页查询默认 50 条；`/stats` 端点暴露节点计数 |
| **③** | LLM 适配器返回幻象（Hallucination）图查询 | **高** | LLM 适配器仅用于 NL→GraphQuery 翻译（受限查询模板），不直接执行任意查询；结果经过规则引擎过滤（允许的节点/边类型白名单）；审计事件记录原始 NL + 翻译后查询，支持事后审计；LLM 不可用时 fallback 到规则引擎 |

### 4.2 外部依赖风险

| 依赖 | 风险 | 影响方向 | 缓解 |
|------|------|---------|------|
| MQTT Broker（EMQX/Mosquitto） | Broker 版本兼容性、认证配置 | ⑤ | 支持两个主流 MQTT broker；配置文档包含 EMQX 5.x 和 Mosquitto 2.x 的例子；连接串中嵌入用户名/密码 |
| OpenAI / 自托管 LLM API | LLM API 延迟 > 5s、API Key 泄露、模型版本差异导致输出不稳定 | ③ | **规则引擎是主要查询路径**——LLM 是可选增强（可通过 `WithLLMAdapter(nil)` 禁用）；prompt 工程使用 structured output（JSON schema 约束）；审计所有 LLM 调用 |
| 现有 ConsentStore（Memory/SQLite/Redis/Postgres）| 无风险——已存在，已测试 | ① | 无。ConsentStore 的四种后端均已通过 `go test` 验证 |
| 现有 Developer Portal SPA | 前端框架版本、SPA 与后端 API 兼容性 | ② | 静态文件嵌入 Go binary（`fs.FS`），无运行时框架依赖；SPA 扩展使用纯 JS，不引入新前端框架 |

### 4.3 性能风险

| 场景 | 风险 | 预估影响 | 优化策略 |
|------|------|---------|---------|
| 管线钩子 5 个 + 声明式流程 3 步 | 每个 `/token` 请求增加 8 次 SPI 调用 | P99 +15ms | 钩子并行执行（同 phase 的钩子用 `errgroup`）；`HasGrant` 缓存；流程评估在登录路径（低频）而非令牌路径（高频） |
| 跨集群策略同步（~1000 策略） | 全量同步可能消耗带宽 | 首次 10MB，增量 < 100KB | 增量同步（仅传输 hash 变更的策略）；首次同步分页（每页 100 条）；MQTT payload 压缩（gzip） |
| 身份图查询 `max_depth=5` | 图遍历在最坏情况下可能膨胀 | 100 万边 × 5 层 = 指数级 | **强制 `max_depth=5` 硬上限**；结果集上限 1000 节点（超出截断 + 提示）；使用 BFS + visited set 防环；时间预算 5s（超时返回部分结果 + 提示） |
| NL 查询规则引擎（非 LLM 路径） | 规则匹配延迟 | < 5ms（10 条规则） | O(n) 规则匹配，n < 50；可忽略 |
| API Key 认证 | 每次请求需要 hash 比较 + 存储查询 | < 1ms | key hash 使用 SHA-256（非 bcrypt——认证路径不存储密码）；memory 实现 O(1)；SQLite 实现使用索引 |

---

## 5. 资源评估与里程碑

### 5.1 人员需求

| 角色 | 所需技能 | 建议数量 | 主要负责 |
|------|---------|---------|---------|
| **高级 Go 工程师**（架构） | OAuth/OIDC 协议、并发安全、SPI 设计 | 1 人 | 方向① 管线钩子 SPI + 声明式流程 engine；方向④ 角色模型；跨方向架构一致性 |
| **后端 Go 工程师** | Go HTTP 中间件、CRUD API、SQLite/Redis | 1 人 | 方向① 管线执行点接入；方向② API Key CRUD；方向⑤ CRD 扩展 |
| **基础设施/运维工程师** | K8s CRD/Operator、MQTT、Kafka、集群通信 | 1 人 | 方向⑤ MQTT/SSE 传输实现、CRD + controller 扩展、联邦 CLI |
| **全栈工程师** | SPA 开发（纯 JS/React）、Admin UI | 1 人 | 方向④ Admin SPA 角色管理；方向② Portal SPA API 密钥；方向③ 身份图可视化；方向⑤ 联邦 dashboard |
| **数据/安全工程师** | 图数据库概念、NLP 基础、审计合规 | 0.5 人 | 方向③ 身份图模型 + 采集器 + NL 查询规则引擎 |

**最小可行团队：3 人**（1 高级 Go + 1 后端 Go + 1 全栈），20 周完成全部五个方向

**优化配置：5 人**（上述全部），12 周完成

### 5.2 关键里程碑

```
Week 1-3   │ 阶段一：核心 SPI 层 + 管线钩子（方向①）+ 角色模型（方向④）
              交付: AuthPipelineHook SPI + HookRegistry + 管线执行点
                    helpdesk scope 中间件 + 403 响应
                    BuiltInRoles 注册 + 角色分配 API
            
Week 4-7   │ 阶段二：身份图 + API Key（方向③+②）+ 同步传输（方向⑤）
              交付: IdentityGraph 数据模型 + 存储 + 采集器 + 查询 API
                    API Key CRUD + 认证中间件
                    策略同步 SPI + MQTT/SSE 传输 + CRD 扩展
            
Week 8-11  │ 阶段三：声明式流程 + 角色 SPA + 联邦同步（方向①+④+⑤）
              交付: AuthFlow YAML 校验器 + 流程 engine + consent step
                    Admin SPA 角色管理页面 + 租户隔离
                    漂移检测 + 冲突解决 + 全局策略 CRD
            
Week 12-14 │ 阶段四：NL 查询 + Gateway + 联邦 dashboard（方向③+②+⑤）
              交付: NL 规则引擎 + LLM 适配器 + 解释
                    Gateway 适配器 + Envoy ext-authz
                    联邦 CLI + Admin dashboard
                    E2E 集成测试 + 运维文档
```

### 5.3 阻塞点（Blockers）与解决策略

| 阻塞点 | 影响方向 | 解决策略 |
|--------|---------|---------|
| **声明式流程 YAML schema 审批** | ① | 提前与安全/合规团队评审流程 DSL；参考 `docs/templates/feature-spec.md` 编写 `feature-spec-auth-flow.md` |
| **MQTT broker 选择（EMQX vs Mosquitto vs 自建）** | ⑤ | 提供两个实现（MQTT + SSE），不绑定单一 broker；使用标准 MQTT 5.0 协议；备选 SSE 在无 MQTT 集群时可用 |
| **LLM API Key 管理和成本** | ③ | LLM 适配器是可选组件——方向③的核心价值在身份图本身；LLM 功能可通过 `WithLLMAdapter(nil)` 完全禁用 |
| **多集群 E2E 测试环境** | ⑤ | 使用 bufconn + `simulated latency` 模拟跨集群网络；不需要真实 K8s 集群；真实多集群测试在 stage 环境进行 |
| **Admin SPA 框架兼容性** | ④②③⑤ | 当前 admin SPA 使用纯 JS（无框架依赖），扩展时保持一致；如引入新框架需在 ADR 中记录决策 |

---

## 6. 质量保证策略

### 6.1 单元测试覆盖要求

| 模块 | 测试要求 | 覆盖率目标 | 关键场景 |
|------|---------|-----------|---------|
| **AuthPipelineHook SPI + HookRegistry** | 每个 phase 的执行顺序；钩子超时；fail-open/fail-closed 行为 | 100% 分支覆盖 | 钩子返回 `ErrHookAbort` → 流程中止；钩子 panic → 恢复 + fail-open；并发注册 |
| **AuthFlow YAML 校验器** | 合法 YAML/非法 YAML 各 10+ 用例；循环引用检测；`if` 表达式纯函数验证 | 95%+ | 空步骤列表；缺失 `on_error` 默认值；provider 重复；`if` 表达式引用未定义变量 |
| **AuthFlow Engine** | 短路语义；`on_error` 三种模式；嵌套步骤 | 100% 分支覆盖 | 3 步流程第 1 步 `fail_closed` → 终止不执行第 2 步；`next_provider` 失败后自动重试 |
| **Admin 角色模型** | 每个预定义角色的 scope 匹配测试；通配符匹配边界情况 | 100% 分支覆盖 | `helpdesk` 尝试调用非 helpdesk API → 403；`org_admin` 跨租户请求 → 403 或 200（取决于 scope `*`） |
| **API Key 认证** | key hash 正确性；前缀提取；过期/撤销检测 | 100% 分支覆盖 | key 过期 → 401；key 撤销 → 401；key 前缀截断攻击 → 不泄露完整 hash |
| **Gateway 适配器** | 请求/响应映射；缓存命中/未命中；上游超时 | 100% 关键路径 | Envoy CheckRequest 格式正确性；缓存过期后重新请求；超时 → 默认 deny |
| **IdentityGraph 查询** | 节点/边 CRUD；属性查询；路径查询；深度限制 | 90%+ | `max_depth=5` 截断；访问节点不存在；图环存在时的 BFS |
| **NL 规则引擎** | 10+ 查询模板匹配；歧义 NL 输入处理；fallback 提示 | 90%+ | "who has admin" → 匹配 `HAS_ROLE` 模板；"show all" → 需要更多上下文；LLM 不可用时 fallback |
| **漂移检测算法** | 策略哈希比较；冲突分类；`remote_wins`/`local_wins` 解决 | 100% 分支覆盖 | 添加策略 → `added`；删除策略 → `removed`；同 key 不同值 → `conflicting` |

### 6.2 集成测试策略

| 测试场景 | 工具 | 测试方法 |
|---------|------|---------|
| **管线钩子 E2E** | `test/auth_pipeline_test.go` + bufconn | 启动 `*sso.Server` + pre-auth 钩子 → 调用 `/auth` → 验证钩子执行路径；注入 `ErrHookAbort` → 验证 401 |
| **声明式流程 E2E** | `test/auth_flow_test.go` + bufconn | YAML 定义流程 → 启动 server → 客户端指定 `?flow=...` → 验证流程步骤执行顺序和结果 |
| **角色模型 E2E** | `test/admin_roles_test.go` + bufconn | 创建 helpdesk token → 调用 helpdesk API → 200；调用 admin API → 403；撤销角色 → 后续请求 403 |
| **API Key + Gateway E2E** | `test/api_key_gateway_test.go` + bufconn | 创建 API key → 用 key 调用 token endpoint → 200；撤销 key → 401；Gateway 适配器 → envoy ext-authz 协议 |
| **多集群联邦 E2E** | `test/federation_e2e_test.go` + bufconn | 双 `*sso.Server` 实例通过 MQTT loopback 连接 → 策略变更 → 自动同步 → 验证远程策略已应用 |
| **身份图 + NL E2E** | `test/identity_graph_test.go` + bufconn | 登录事件 → 身份图采集器创建节点 → NL 查询 "list user's clients" → 返回正确结果 |

### 6.3 代码审查要点

| 方向 | 审查要点 |
|------|---------|
| **所有方向** | AGENTS.md §0.1 预算：文件 ≤ 500 行、函数 ≤ 50 行、cyclomatic ≤ 15、import 方向正确 |
| **① 管线钩子** | `PreTokenIssuanceHook` 执行在热路径上——确认超时设置合理（1s）、无阻塞 I/O、无 heap allocation；钩子 `*AuthMutation` 的 scope 修改不违反最小权限原则 |
| **① 声明式流程** | YAML 校验器不放过任何非法输入；`if` 表达式必须是纯函数（可被静态验证）；`on_error=fail_open` 在 provider 不可用时跳过后不影响整体流程 |
| **② API Key** | Key hash 使用 SHA-256（非 bcrypt——认证路径不需要慢 hash）；密钥前缀可识别来源但不暴露 hash；API Key 永不记录在审计日志的值字段中 |
| **④ 角色模型** | 预定义角色 scope 是白名单（非黑名单）；租户 scope 模板从已验证的 context 取值，非用户输入；角色分配 API 的审计事件记录谁做了什么 |
| **⑤ 联邦同步** | MQTT 传输必须有 TLS + 认证；CRD 的 `Spec.SyncPolicy` 的 `interval` 最小值 10s（防止 DDoS）；跨集群策略同步在 MQTT 不可用时降级到 SSE |
| **③ 身份图** | NL 查询 API 必须限流（5 req/min per user）；LLM 适配器不能直接执行 SQL - 只能生成受限的 GraphQuery；`max_depth=5` 不可配置（硬编码防止误操作） |

### 6.4 性能测试需求

| 场景 | 测试工具 | 阈值 | 触发条件 |
|------|---------|------|---------|
| 管线钩子 5 个并行执行 | Go benchmark | P99 < 10ms | 10 个钩子 × 1000 次迭代 |
| 声明式流程 5 步评估 | Go benchmark | P99 < 5ms | 5 步流程 × 1000 次迭代 |
| HasGrant 缓存命中/未命中 | Go benchmark | 命中 < 100µs，未命中 < 1ms | 10000 次查询 |
| API Key SHA-256 认证 | Go benchmark | < 10µs per key | 100000 次认证 |
| 身份图查询 max_depth=5 | Go benchmark | P99 < 50ms | 100 万边图 × 100 次查询 |
| 漂移检测 1000 策略 | Go benchmark | < 100ms | 1000 策略 × 100 次检测 |
| MQTT 消息吞吐量 | 集成测试 | > 1000 msg/s | 1KB payload × 60s |

---

## 7. 分阶段实施计划

### 阶段一：核心基础设施 + 管线钩子（第 1-3 周）

```
Week 1          Week 2          Week 3
──────────────┼──────────────┼──────────────
D1-T001(4h)   │ D1-T003(4h)  │ D1-T006(3h)
D4-T001(4h)   │ D1-T004(4h)  │ D1-T007(2h)
D5-T001(6h)   │ D1-T005(4h)  │ D1-T008(4h)
D2-T003(6h)   │ D4-T002(4h)  │ D4-T003(2h)
D3-T001(6h)   │ D4-T005(6h)  │ D4-T004(4h)
              │ D4-T008(4h)  │ D4-T009(4h)
              │              │ D4-T006(4h)
              │              │ D4-T007(2h)
```

**交付物：**
- AuthPipelineHook SPI + HookRegistry + 3 个执行点注入 ✅
- helpdesk scope 中间件 + 403 响应 + BuiltInRoles 注册 ✅
- 角色分配 API + Memory/SQLite 持久化 ✅
- 策略同步 SPI + MQTT/SSE 传输定义 ✅
- API Key CRUD SPI ✅
- IdentityGraph 数据模型 + 存储 SPI ✅
- Admin SPA 角色管理页面 ✅
- 管线 E2E 测试 + 角色模型 E2E 测试 ✅

**门禁：** `make acceptance` + `python cli.py check` + `go test ./... -race -count=3`

---

### 阶段二：身份图 + API 密钥（第 4-6 周）

```
Week 4          Week 5          Week 6
──────────────┼──────────────┼──────────────
D3-T002(6h)   │ D3-T004(4h)  │ D3-T006(8h)
D3-T003(6h)   │ D3-T005(4h)  │ D2-T001(4h)
D2-T004(4h)   │ D2-T005(3h)  │ D2-T002(3h)
D5-T002(4h)   │ D5-T004(4h)  │ D2-T007(2h)
D5-T003(4h)   │ D5-T005(8h)  │ D2-T008(4h)
              │              │ D2-T009(2h)
```

**交付物：**
- IdentityGraph SQLite 存储 + 数据采集器 ✅
- 身份图查询 API + Admin SPA 可视化 ✅
- API Key 认证中间件 + Gateway 适配器 ✅
- Portal SPA "API 密钥"标签页 ✅
- MQTT + SSE 传输实现 ✅
- CRD 扩展 + 漂移检测 ✅
- API Key + Gateway E2E 测试 ✅

**门禁：** `go test ./... -race -count=5` + 身份图 100 万节点性能测试通过

---

### 阶段三：声明式流程 + 联邦同步（第 7-10 周）

```
Week 7          Week 8          Week 9          Week 10
──────────────┼──────────────┼──────────────┼──────────────
D1-T009(6h)   │ D1-T011(4h)  │ D1-T014(6h)  │ D5-T008(6h)
D1-T010(8h)   │ D1-T012(3h)  │ D1-T015(2h)  │ D5-T009(4h)
D5-T006(2h)   │ D1-T013(4h)  │ D1-T016(3h)  │ D5-T010(4h)
D5-T007(6h)   │ D5-T011(4h)  │              │
```

**交付物：**
- AuthFlow YAML 模型 + 校验器 + 流程 engine ✅
- Consent step 集成（使用现有 ConsentStore）✅
- 流程绑定 client/tenant + session claims 注入 ✅
- 全局条件访问策略 CRD + controller ✅
- 联邦 CLI + Admin dashboard ✅
- 联邦 E2E 测试（bufconn 双集群）✅
- 声明式流程 E2E 测试 ✅

**门禁：** `make ci` + E2E 场景覆盖全部 5 个方向 + 多集群模拟测试通过

---

### 阶段四：NL 查询 + 文档收尾（第 11-14 周）

```
Week 11         Week 12         Week 13         Week 14
──────────────┼──────────────┼──────────────┼──────────────
D3-T007(6h)   │ D3-T009(3h)  │ D4-T010(3h)  │ 性能测试
D3-T008(4h)   │ D3-T010(3h)  │ D5-T011(4h)  │ 文档完善
              │              │ D2-T009(2h)  │ ROADMAP 更新
              │              │              │ Release 发布
```

**交付物：**
- NL 查询规则引擎 + LLM 适配器 ✅
- NL 查询 API + Admin SPA NL 输入框 ✅
- 查询解释 + 审计 ✅
- 所有方向运维文档 ✅
- 性能测试报告 ✅

**门禁：** `make acceptance` + `python cli.py harness` + 完整文档巡检

---

## 8. 附录：核验关键修正

### 8.1 与原始分析的关键差异

| 主张 | 原始分析 | 同行评审 | **核验结论** | 影响 |
|------|---------|---------|-------------|------|
| ConsentStore 状态 | 方向①(a) 未提及 | ❌ 声称 `ErrConsentRequired` 是死代码，ConsentStore 不存在 | ✅ **已存在**：4 后端 + `/consents/me` API | 方向①工作量从 2200 降回 1800，消除前置依赖 |
| 开发者门户 SPA | 方向②估计 500 行新代码 | ✅ 确认存在（`WithDeveloperPortalFS`） | ✅ **已存在**：提交 `4c79fb82` | 方向②工作量从 1200 降为 850 |
| SSOConfigDrift CRD | 方向⑤估计 500 行新代码 | ✅ 确认存在（`a635191d`） | ✅ **已存在**：CRD + controller | 方向⑤工作量从 2200 降为 1700 |
| helpdesk 处理程序 | 方向④未详细分析 | 正确识别为已实现（~350 行） | ✅ 确认 | 方向④工作量从 1100 降为 900 |
| TrustedProxies | ROADMAP ⑤(c) 声称未实现 | ✅ 确认已实现 | ✅ **已存在**：`options_passwd.go:239` | 无影响（已不是方向之一） |

### 8.2 不建议在阶段一做的事

| 不做之事 | 理由 | 替代方案 |
|---------|------|---------|
| LLM 适配器（方向③阶段一） | 身份图本身就有独立价值；LLM 是可选扩展 | 先构建图存储 + 规则引擎 |
| Gateway 适配器 Envoy ext-authz（方向②阶段一） | API Key CRUD + 认证中间件是核心；Gateway 适配器是"好有"非"必须有" | 先完成 API Key 认证 + Portal 面板 |
| 跨集群全局策略 CRD（方向⑤阶段一） | 策略同步 SPI + 漂移检测是核心；全局策略 CRD 是高级功能 | 先完成 MQTT/SSE 传输 + 漂移检测 |
| 级联吊销（方向⑤阶段二） | 令牌族谱查询是核心；级联吊销有性能风险 | 先完成族谱查询 API |

### 8.3 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| 管线钩子 = 中间件风格（非 WASM） | **Option A** | 与现有 `WithXxx` 模式一致；零新运行时依赖；编译时类型安全 |
| 声明式流程 `on_error` 默认值 | **fail_open** | 任何单步失败不应阻止用户完成认证；`fail_closed` 需要显式声明 |
| 角色模型不使用新的"角色"表 | **Scope 通配符组合** | `permissions` 包已有完整的通配符匹配器；避免角色爆炸 |
| 联邦传输首选 | **MQTT**（SSE 备用） | MQTT 有标准 QoS 语义 + 持久订阅 + 已存在 infrastructure/ |
| 身份图查询不引入图数据库 | **SQLite + 邻接表** | 查询模式有限（邻接查询 / 最短路径 BFS）；不需要完整的图 DB；保持零外部依赖 |
| API Key hash | **SHA-256** | 认证路径不存储密码——不需要慢 hash；SHA-256 足够且性能好 |

---

> **TL;DR 执行摘要：** 五个方向总计 **6350 行 / ~29.5 开发日**（最小团队 3 人、14 周）。  
> **立即启动（阶段一）：** 管线钩子 SPI + helpdesk 角色模型 + 策略同步 SPI + API Key 后端 + 身份图模型。  
> **核心风险：** 声明式流程 YAML 校验器遗漏边界条件 → 认证死循环（缓解：fail-loud 启动校验）。  
> **最大不确定性：** 身份图查询在 100 万节点下的性能（缓解：`max_depth=5` + 分页 + 性能基准测试）。
