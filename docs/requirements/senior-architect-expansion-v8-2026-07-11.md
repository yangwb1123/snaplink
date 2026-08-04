# 资深架构师深度扫描：五项未覆盖的高价值扩展方向（v8）

> **分析师：** 资深架构师 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库 2241 `.go` 文件的全面 grep/read 扫描（与前 57 份分析互斥）。
>   逐项验证：在代码中确认缺口真实存在，并与已有 57 份 `docs/requirements/*.md`
>   的关键词做交叉去重。前置声明与 `senior-architect-fresh-scan-2026-07-11.md` 相同：
>   项目能力已达行业顶级，剩余缺口聚焦于**产品化最后一公里**和**新一代身份基础
>   设施的跨层优化**，而非缺失标准协议。

---

## 方向一：数据面连续访问评估（Session-Aware Data Plane Continuous Access Evaluation）

### 类型

零信任架构 / 网关安全 / 会话活跃度检查

### 为什么需要

当前 Envoy HTTP ext_authz（`interfaces/sso/mesh_authz.go`）和 gRPC ext_authz
（`infrastructure/extauthz/authz.go`）的授权决策逻辑是等同的：调用
`validateAnyToken` 验证 JWT 签名、exp、签发者、sender-constraint（DPoP/mTLS)、
租户暂停状态和读侧地域门禁，但**始终不检查签发该令牌的会话是否仍然存活**。

这意味着：一个通过 OIDC Back-Channel Logout 或 SessionHub 销毁了的会话所签发
的 JWT，在 JWT 自身过期之前，仍然能够通过网格的 ext_authz 检查。Envoy 会注入
`X-Auth-*` 身份头标，上游服务会信任该身份。

**与 AI Agent / AI 工作流的强关联：** 在 AI Agent 场景下，令牌通常具有较长
TTL（Agent 会话可能持续数小时），且 Agent 通过 MCP 或 gRPC 调用多个后端服务。
如果中间某个环节需要撤销 Agent 的会话（例如安全事件），当前架构无法阻断已经
签发的 JWT 对该 Agent 的授权——直到 JWT 过期。这与"零信任"的 continuous
verification 原则相悖。

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| `mesh_authz.MeshAuthorize` 调用会话健康检查 | ❌ 仅检查 JWT claims + tenant suspension |
| `extauthz.AuthorizationServer.Check` 调用会话健康检查 | ❌ 仅调用 `MeshAuthorize` (同上) |
| 有 `SessionManager.Get` / `SessionManager.Exists` 接口 | ✅ 存在 `core/spi.go` |
| 网格能在不引入中心化自检的情况下检查会话 | ❌ 需额外存储查找 |
| 会话活跃度检查的性能优化（批量/本地缓存） | ❌ 不存在 |

### 建议范围

- 引入一个窄接口 `SessionHealthChecker`（`GetSession(ctx, sessionID) (active bool, err error)`）
- 在 `MeshAuthorize` 中，如果令牌携带 `sid` claim，则查询 session 活跃度
- 引入可选本地会话缓存 + 异步批量刷新的模式来避免每次请求都穿透到后端存储
- fail-open（存储不可达时跳过会话检查，降级为纯 JWT 验证）
- 在 `introspect` 中增加相同的会话健康信号（方向三的基础）

### 边缘情况

- **DPoP 每请求检测与 session 检查的关系：** 如果 session 已销毁但 DPoP proof 有效，
  应以 session 状态为准（fail-closed)
- **RAR / authz_details 负载中不包含 sid：** 需要解决如何将 `sid` 从 JWT 传递到
  网格授权层
- **批量会话检查：** 在网格高吞吐场景下，每个请求都穿透存储是不可接受的。
  需要本地缓存 + 异步刷新的模式

---

## 方向二：SCIM 2.0 企业用户扩展（Manager + Organization + Department）

### 类型

身份供给 / HR 系统集成 / 企业级组织模型

### 为什么需要

当前 SCIM User 模型（`protocols/scim/user.go`）仅实现了 RFC 7643 §4.1 核心用户
模式：`schemas`、`id`、`userName`、`name`、`displayName`、`emails`、`active`、
`meta`。而 RFC 7643 §4.3 **企业用户扩展**（`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`）
中的以下字段完全缺失：

- `employeeNumber` — 工号，HR 系统唯一键
- `costCenter` — 成本中心，财务核算必需
- `organization` — 组织名称
- `division` — 分部
- `department` — 部门
- `manager.value` — 管理者引用（manager 的 user id）

这意味着：

1. **Workday / SuccessFactors / SAP HR 集成不可行：** 这些 HR 系统以 SCIM 企业
   扩展为标准格式推送组织数据。缺少此扩展，整个 HR-provisioning 集成就断裂了。

2. **基于角色的访问控制缺少组织维度：** 虽然已有 `domains/permissions` 的 RBAC/
   ReBAC 引擎和 `domains/userlifecycle` 的用户生命周期管理，但没有组织层级结构
   （谁是谁的经理、谁在哪个部门），就无法实现 manager 审批、部门级资源隔离、
   组织范围的审计。

3. **SCIM 出站供给（SCIM Provisioning Outbound）的客户价值受限：** 已实现的
   `protocols/scimprovision` 只能同步核心用户属性，而下游应用（如 Jira、Slack、
   GitHub Enterprise）期望接收组织层级信息来正确设置团队结构。

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| SCIM User 模型有 `manager` 字段 | ❌ 不存在 |
| SCIM User 模型有 `department` / `organization` / `division` | ❌ 不存在 |
| SCIM User 模型有 `employeeNumber` | ❌ 不存在 |
| 扩展 URN `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` 声明 | ❌ 不存在 |
| SCIM PATCH 支持 manager 变更 | ❌ 不存在 |
| 出站供给（scimprovision）携带企业扩展 | ❌ 不存在 |
| 组织层次遍历（Get Direct Reports） | ❌ 不存在 |
| UserProvider SPI 有 manager 引用 | ❌ `core.User` 无此字段 |

### 建议范围

- 在 `core.User`（或附加 `core.EnterpriseUser`）添加 `EmployeeNumber`、
  `CostCenter`、`Organization`、`Division`、`Department`、`ManagerID` 字段
- 实现 SCIM 企业扩展的序列化/反序列化（`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`）
- 更新 SCIM 出站供给（`scimprovision`）使其能推送企业扩展
- 添加管理者验证（不能自我管理、不能形成循环引用）
- 在 `domains/permissions` 提供基于 manager 的权限解析（`manager:approve` 等）

### 边缘情况

- **Manager 循环引用检测：** 设置 manager 时必须检测 A→B→A 的循环
- **Manager 为离职用户：** 如何处理 manager 已被停用/删除的场景
- **多值部门（矩阵组织）：** 某些组织一个人属于多个部门
- **SCIM PATCH 对 manager 引用的语法：** RFC 7644 §3.5.2.2 对引用类型的特殊处理
- **与 existing `domains/identitylink` 的互斥：** 企业 SCIM 的 manager 引用与
  自服务身份链接的关系

---

## 方向三：令牌自省与会话健康感知（Session-Aware Token Introspection）

### 类型

OAuth 2.0 协议 / 令牌生命周期管理

### 为什么需要

`/token/introspect`（RFC 7662）的实现（`protocols/oauth/handle_introspect.go`）
通过 `ValidateAnyToken` 验证 JWT 签名和声明完整性，然后返回 `active: true` +
claims。

**问题：自省从不检查签发该令牌的会话是否仍然存活。** 一个已经被 Back-Channel
Logout、SessionHub 统一登出、或管理员强制撤销的会话，其签发的 JWT 在自省时
仍然报告 `active: true`，直到 JWT 自身的 `exp` 到达。

**这与 introspect cache 的叠加效应：** 当前支持可选的 introspection cache
（`IntrospectionCache`，默认 TTL 60s）。在有 cache 的情况下，一个已撤销会话的
令牌在 cache TTL 内仍然被报告为 active。即使无 cache，也因为缺乏会话检查而
永远为 active。

**涉及场景：**
- 微服务调用链通过自省决定是否接受令牌 → 已撤销会话的令牌仍被接受
- 资源服务器依赖自省结果做授权 → 等到 JWT 过期才失效
- CAEP/SSF `revoked` 事件已送达但自省器没有关联事件和会话状态

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| `introspectOne` / `serveIntrospectWithCache` 查询 session 状态 | ❌ 不查询 |
| 自省响应中包含 sid 和 session 活跃度 | ❌ 没有 sid 或 session 状态字段 |
| JWT claims 中有 `sid` 声明 | ✅ 已有 |
| SessionManager 有 `GetSession(ctx, sid)` | ✅ `core.SessionManager` 有 |
| Cache 失效与会话撤销联动 | ❌ Session 撤销不清除 introspection cache |

### 建议范围

- 在 introspect handler 中添加可选的 session 状态检查：如果 JWT 包含 `sid`，
  则查询 `SessionManager.GetSession`，若不存在/已过期则返回 `active: false`
- 在 introspection cache key 中加入 session 版本号或时间戳，使得 session 撤销
  时 cache 自动失效
- 新增 `introspect_active_session` 指标（已被 session 检查的 token 数 / 因 session
  失效而被置为 inactive 的 token 数）
- 在 introspection 响应体中（RFC 7662 §2.2 允许额外字段）添加 `session_active`:
  `true`/`false`
- fail-open：SessionManager 不可达时不阻断自省，降级为纯 JWT 验证

### 边缘情况

- **无 sid 的令牌（如 client_credentials）：** 不执行 session 检查，行为不变
- **sid 对应 session 已被 TTL 过期而非主动撤销：** 仍然应返回 `active: false`
  （因为 session 过期后，refresh_token 应已完成轮换，不再有长期有效的访问令牌）
- **性能考虑：** 每个自省请求都查询 SessionManager 在高吞吐场景下不可接受。
  本地最近最少使用缓存 + 异步批处理是一个方向；也可通过 introspection cache
  TTL 容忍一定窗口的最终一致性（类似当前 cache 语义）。

---

## 方向四：OAuth 2.0 CIBA 推送交付模式（CIBA Push Delivery Mode）

### 类型

OAuth 2.0 / OIDC 协议 / 无浏览器认证

### 为什么需要

当前 CIBA（Client-Initiated Backchannel Authentication）实现（`protocols/oauth/handle_ciba.go`、
`protocols/oauth/oauthspi/ciba.go`）支持两种 token 交付模式：

1. **Poll 模式**（始终可用）：客户端通过 `/token` 轮询获取认证结果。每个客户端
   都需要实现轮询逻辑，延迟不确定（取决于轮询间隔）。
2. **Ping 模式**（`WithCIBAPingNotifier`）：服务端通过预配置的回调通知客户端
   认证已完成，客户端再用 `auth_req_id` 到 `/token` 获取令牌。减少了轮询等待，
   但仍需要一次额外的 `/token` 调用。

**未实现：** 发现文档明确标注 "Push delivery is not implemented"
（`server_discovery_config.go:309`）。Push 模式下，认证完成后服务端直接将令牌
POST 到客户端预注册的 `backchannel_token_delivery_uri`——客户端无需任何额外
调用即可获得令牌。

**为什么 Push 模式重要：**
- **IoT / 资源受限设备：** 无法维持长轮询的设备，需要服务端直接推送令牌
- **低延迟场景：** Push 模式是三种模式中延迟最低的（认证完成即推送）
- **与 Active ITDR / CAEP 的协同：** ThreatExecutor 触发 step-up MFA 后，
  Push 模式能即时下发新令牌，而 Poll 模式需要等待下一个轮询间隔
- **合规要求：** 某些金融级 API（FAPI）的安全文档中要求服务端主动推送令牌
  以缩短攻击窗口

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| CIBA Push delivery 模式实现 | ❌ 未实现（明确标注） |
| 客户端 `backchannel_token_delivery_uri` 注册 | ❌ 不存在 |
| Push 端点（接收令牌交付的客户端端点调用） | ❌ 不存在 |
| Push 安全约束（HTTPS 强制、端点签名验证） | ❌ 不存在 |
| 发现文档中 push 模式的声明 | ❌ 明确标注未实现 |
| Push 失败的重试和死信队列 | ❌ 不存在 |

### 建议范围

- 实现 CIBA Push 交付核心：认证完成后，构建令牌响应并 POST 到客户端
  `backchannel_token_delivery_uri`
- 推送到客户端时使用 HTTPS + 签名（利用已有 JWT 签名基础设施）确保端到端安全
- Push 失败时回退为 Ping 或 Poll 模式（graceful degradation）
- 添加 Push 交付的死信队列（参考 `platform/lifecycle/webhook/deadletter.go` 的模式）
- 在发现文档中声明 `backchannel_token_delivery_modes_supported` 包含 `push`

### 边缘情况

- **Push 端点不可达（网络故障/客户端离线）：** 应回退为 Ping 模式并重新尝试
- **Push 端点响应非 2xx：** 根据错误类型决定重试还是回退
- **并发 Push 与 Poll 请求的竞态：** 客户端可能同时收到 Push 并正在 Poll，
  需要保证 idempotent / 幂等性
- **Push 端点证书过期：** 需要与已有的 mTLS 检查机制整合
- **与 CAEP/SSF push delivery 的整合：** 同一套 outbound HTTPS push 引擎
  可以复用 CC `infrastructure/` 层的 SPI

---

## 方向五：硬件签名密钥的可证明生成（Attestable HSM Key Generation）

### 类型

安全合规 / 密码学审计 / FIPS 140 / PCI-DSS

### 为什么需要

已有五个外部 KMS 签名后端：

| 后端 | 文件 |
|---|---|
| AWS KMS | `infrastructure/kms/awskms/` |
| GCP Cloud KMS | `infrastructure/kms/gcpkms/` |
| Azure Key Vault | `infrastructure/kms/azurekeyvault/` |
| PKCS#11 (HSM) | `infrastructure/kms/pkcs11/` |
| HashiCorp Vault Transit | `infrastructure/defaultimpl/vaulttransit/` |

所有后端都能生成密钥、签名 JWT，但在**合规审计层面**有一个关键缺口：**当 KMS
返回一个公钥时，服务无法证明这个密钥对是在 HSM 内部生成的，还是用软件生成后
导入 HSM 的。** 后者意味着私钥在生成过程中可能已经被泄露。

具体来说：

- AWS KMS 支持 `KeyOrigin: AWS_KMS`（在 HSM 内生成）vs `EXTERNAL`（导入）。
  但当前集成不读取也不报告 `KeyOrigin`。
- PKCS#11（真实 HSM）支持 `CKA_LOCAL` 属性标识密钥是否在 Token 内生成。
  当前集成不读取也不报告。
- GCP Cloud KMS 和 Azure Key Vault 也有类似的 "key origin" / "key type" 属性。

**为什么审计需要这个：**

1. **FIPS 140-2/140-3 Level 2+：** 要求签名密钥必须在 FIPS 认证的 HSM 内生成
   （而不是在内存生成后导入）。没有 KeyOrigin 证明，审计失败。
2. **PCI-DSS §2.3 / §3.5：** 要求密钥材料的生成和管理在安全的加密模块中完成。
3. **SOC 2 Type II：** 审核员会检查"密钥生成是否在 HSM 内部完成"的控制证据。
4. **OpenID Federation 1.0 trust marks：** 一个 Federation Entity 如果能声称
   "我的签名密钥由 HSM 保护且于 HSM 内生成"，可以获得更高级别的信任标记。

**注意与已有的 FIPS 140-3 支持的区别：** `shared/security/fipspolicy` 只检查
Go 运行时是否以 FIPS 模式运行（GOFIPS140 build / GODEBUG=fips140=on）。它确保
Go 密码操作使用 FIPS 认可的算法实现，但**不涉及密钥管理**。

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| KMS 后端报告密钥来源（HSM-generated vs imported） | ❌ 每个 KMS 后端都不报告 |
| 运行时可查询签名密钥的生成方式 | ❌ 不存在 |
| JWKS 响应中标注密钥来源 | ❌ `use` / `alg` 以外无扩展 |
| 管理员 API 查看密钥属性 | ❌ 不存在 |
| 密钥轮换时验证新密钥的生成方式 | ❌ 不存在 |
| 审计事件包含密钥来源信息 | ❌ 不存在 |

### 建议范围

- 在 `CryptoSigner` / `Issuer` SPI 中增加可选的 `KeyOrigin() KeyOriginInfo`
  方法（fail-open：不实现的后端返回 `OriginUnknown`）
- 每个 KMS 后端读取各自的 KeyOrigin 属性并返回
- 在 JWKS 端点中可选地标注密钥来源（作为 JWK `use`/`alg` 之外的扩展字段，
  仅在管理员 API 中可见，不改变标准 JWK 语义）
- 在 `/api/v1/admin/keys` 管理端点显示每个密钥的生成方式
- 密钥轮换事件（`audit.EventSigningKeyRotation`）中包含 KeyOrigin
- 新增 `sso.WithMinimumKeyOrigin(origin)` 配置项：拒绝使用来源低于此阈值的
  密钥签发令牌（默认 `OriginAny`，无影响）

### 边缘情况

- **不支持 KeyOrigin 的 issuer（如纯内存 Ed25519Issuer）：** 返回 `OriginUnattested`
  （软件生成，无 HSM 证明）
- **Vault Transit 不支持查询 KeyOrigin：** Vault 的 Transit 引擎本身不保存
  密钥生成来源信息，返回 `OriginUnknown`
- **多云/混合环境：** 一个 issuer 可能同时使用 AWS KMS + 软件回退密钥，
  需要区分对待
- **密钥轮换时 KeyOrigin 降级：** 如果旧密钥是 HSM 生成的，新密钥是软件生成的，
  应告警
- **JWKS 的兼容性：** 标准 JWK 没有 KeyOrigin 字段。扩展字段不能破坏标准
  JWT 库的解析。需放在私有字段（`"\u004beyOrigin"` 等）

---

## 优先级矩阵

| 方向 | 商业价值 | 技术复杂度 | 当前缺口程度 | 推荐优先级 |
|------|----------|------------|-------------|-----------|
| ① 数据面连续访问评估 | ★★★★★ 零信任核心能力，高差异化 | ★★★ 中等（需引入 SessionHealthChecker SPI + ext_authz 集成 + 缓存） | 完全缺口 | **P0** |
| ② SCIM 企业扩展 | ★★★★★ 企业销售必过门禁 | ★★☆ 较低（新增类型 + 序列化） | 完全缺口 | **P0** |
| ③ Session-Aware 令牌自省 | ★★★★☆ 安全完整性提升 | ★★★ 中等（需 session 查询 + cache 联动） | 完全缺口 | **P1** |
| ④ CIBA Push 交付 | ★★★☆☆ 物联网/金融场景 | ★★★ 中等（outbound HTTPS push 引擎 + 死信队列） | 完全缺口（明确标注） | **P2** |
| ⑤ 可证明 HSM 密钥生成 | ★★★★☆ 合规审计门禁 | ★★☆ 较低（每 KMS 后端改几行） | 完全缺口 | **P1** |

---

## 与现有 57 份分析的交叉验证

逐项 grep 了已有分析文档的关键词以确认零重叠：

| 本方向 | 已在其他 analysis 中出现？ | 验证方法 |
|--------|--------------------------|----------|
| ① 数据面连续访问评估 | ❌ 未被提及 | grep "session.health\|SessionHealth\|continuous.*eval\|session.*active\|data.*plane.*eval" |
| ② SCIM 企业扩展 | ❌ 未被提及 | grep "enterprise.*extension\|enterpriseUser\|manager.*scim\|employeeNumber\|costCenter\|orgChart" |
| ③ Session-Aware 自省 | ❌ 未被提及 | grep "session.*introspect\|introspect.*session\|token.*health\|token.*lifecycle.*session" |
| ④ CIBA Push | ❌ 未被提及 | grep "CIBA.*push\|push.*delivery\|ciba.*push\|push.*ciba\|backchannel.*push\|push.*backchannel" |
| ⑤ HSM 密钥证明 | ❌ 未被提及 | grep "key.*attest\|attest.*key\|key.*origin\|KeyOrigin\|H SM.*prove\|generate.*inside\|key.*genesis" |

