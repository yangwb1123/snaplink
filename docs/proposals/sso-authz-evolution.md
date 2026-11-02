# SSO 底座与可选授权：演进规划

> 状态：Proposed，待独立设计评审；不是功能实现、生产验收或发布承诺。
> 源码基线：`6c9637918df5ddd92d74ecddaf4978c16cbb86dd`。
> 本轮只产出规划，不修改业务代码，不启动开发循环、后台服务或部署。

## 1. 目标与用户结果

定位：**以 SSO 认证为底座，提供可独立使用的业务授权；统一 SDK 接入，不强制统一所有应用的权限模型。**

| 接入方式 | 身份责任 | 权限责任 | 开发者结果 |
|---|---|---|---|
| 只认证 | Snaplink 认证；应用验证结果并建立本地会话 | 应用自己的角色／ACL | 不依赖业务权限模块也能完整接入 SSO |
| 只授权 | 注册且获准的 App 后端负责自己的用户认证 | Snaplink 业务授权模块 | 后端提供应用凭据与已登录用户，查询本应用范围内的权限 |
| 认证＋授权 | Snaplink 身份凭证 | Snaplink 业务授权模块，应用执行决策 | SDK 的一次资源检查内完成身份验证与权限判断 |

这里的“一次”指登录完成后的资源检查，不是把 OIDC 登录协议所有步骤压成一次请求。认证结果是可验证的身份／会话，不只是一个登录布尔值。

成功标准：三个参考应用分别采用上述模式；停用业务授权模块不破坏只认证应用；任何应用不能凭自己的凭据冒充其他应用或租户的主体。

## 2. 现有基础与真实缺口

### 2.1 可直接复用

| 基础 | 源码依据 | 边界 |
|---|---|---|
| OAuth/OIDC、Code＋PKCE、刷新、会话、撤销、浏览器 OP 身份复用 | [功能矩阵](../feature-matrix.md)、[配置合同](../config-reference.md) | 浏览器身份复用为 opt-in；登录 UI 外置；协议实现不是官方认证 |
| Client 注册与持久化、启停、租户绑定、secret 生命周期 | [Client 模型](../../shared/core/types.go)、[Postgres ClientStore](../../infrastructure/postgres/clients.go) | Memory／SQLite／Postgres 均存在，不是所有部署默认采用数据库 |
| 认证／授权客户端分离、local／remote 适配 | [客户端接口](../../interfaces/ssoclient/client.go) | 已有逻辑分离，不需要先拆微服务 |
| 按 client 的 RBAC、角色分配、菜单、SoD | [Provider](../../domains/permissions/provider.go)、[SoD](../../domains/permissions/sod.go) | 基础角色分配没有通用有效期、来源和审批记录 |
| gRPC Check／ListPermissions／ListRoles／GetMenus | [Authorizer](../../interfaces/grpcserver/authz.go)、[稳定 proto](../../proto/authz/v1/authz.proto) | 有 session/resource 扩展，不等于已有外部调用方信任闭环 |
| 多语言登录、会话与授权投影读取 | [SDK 合同](../sdk-paradigm.md)、[包边界](../../sdks/README.md) | Go／TS／Python／Rust／PHP 有共同基础；Kotlin／Swift 仍有独立接入与平台验收边界 |
| 管理 API、审计、健康检查、指标、持久后端 | [功能矩阵](../feature-matrix.md) | 管理前端外置；可用实现不等于默认配置、发布或生产 HA |

### 2.2 首期必须处理的缺口

1. **授权入口信任边界。** [管理拦截器](../../interfaces/admin/middleware.go)明确放过 Authorizer；[remote 适配](../../interfaces/ssoclient/remote/authz.go)直接传入 subject/client。当前没有数据库 client-secret 调用认证及相应作用域闭环，不能把 TLS 服务端证书当作调用方身份。
2. **路由声明与实现需要核对。** ReBAC 标准路由／挂载注释称 client-credentials-gated，但本轮读到的[处理函数](../../platform/lifecycle/rebac/api.go)和[挂载](../../platform/lifecycle/rebac/mount.go)未体现该校验。M0 应以实际请求回归确定完整边界，不能仅依赖注释或 OpenAPI 声明。
3. **三种能力的注册合同。** Client 已存在，但讨论中的认证／授权能力选择及外部用户委托并没有完整的数据、管理、SDK、运行时合同。
4. **SDK 调用次数与语义。** [Go Authorize](../../sdks/go/authorization.go)聚合四个 HTTP 读取，是授权投影，不是一次远程资源决策。保留此用途，不把它偷偷改造成新语义。
5. **初始化与运行时管理。** [Client seed](../../cmd/sso-server/serverbuildsign/seed.go)通常新增不存在的记录，并有特定 public-client 兼容修正；[权限 seed](../../cmd/sso-server/serverbuildplatform/build_permissions_risk.go)会更新角色、菜单和分配。数据库管理后“重启不覆盖修改”不能视为已经全部成立。

上述为只读源码观察，不是执行过攻击回归或独立安全审计的结论。

## 3. 产品边界与非目标

- 认证协议、PKCE、issuer/audience/client/tenant 绑定、MFA、会话和撤销继续属于核心。
- 业务角色、权限、临时授权、变化记录、Explain 属于可选授权模块。
- Go SDK 可嵌入，stock server 按能力装配；前端继续独立部署。
- 首期保持一个服务和清晰的进程内边界；网络传输不决定领域边界。
- 新外部业务授权入口默认不开放；启用需要管理员授予应用能力。
- 不把 FeatureGates、冷构建 profile 或商业 entitlement 当成 per-client 授权能力。

首期不做：新 IAM 平台、全新认证引擎、统一策略语言、多级审批引擎、角色模板版本树、用户专属角色、跨应用自动账号合并、通用迁移平台、任意 Go 热插件、强制独立授权数据库／服务。

## 4. 架构决策

### D1. 模块化单体优先，复用已有授权用例

```text
App SDK / 资源服务（执行 allow / deny）
    │
    ├─ 只认证：OIDC / 本地会话或 token 校验 → 本地业务权限
    │
    └─ 选择中央授权：受保护访问检查入口
           → 应用／token 验证
           → 规范化主体与 client/tenant 上下文
           → 现有 RBAC / session-active-role 决策
           → 可选治理扩展
```

同进程直接调用；远程使用受保护传输。不要在同一服务内部为了“认证＋授权”额外绕一次 gRPC。逻辑可选不等于物理故障隔离：共享进程或身份存储故障仍可能同时影响多项能力。

### D2. 延用同一份 Client 注册

- 管理界面可表现为“只认证／只授权／两者”，底层仅新增所需的最小能力数据；枚举或能力位的具体表示在 M0 定稿，不同时维护两套等价字段。
- `Active` 继续作为已有总开关；用户登录能力与业务授权能力分别执行，不能用 scope 替代能力注册。
- 新的外部授权／App 主体委托默认关闭；已有 OAuth 登录行为保持兼容。旧业务授权消费者先盘点、迁移，不能默认为任何既有 client 开启用户委托。
- 能力修改仅走有权限的管理面；DCR 和客户端自助管理不得自行启用外部用户委托。
- 新字段必须有 presence／未指定语义；旧 SDK 更新名称等字段不能清空新增策略。
- Client、凭据、能力变更复用并验证跨副本失效链路；明确生效上限，不能只做本进程缓存清除。

能力约束需要覆盖登录、代码兑换、刷新与在线检查等相关入口；只在登录按钮处判断是不完整的。已有 JWT 的离线有效期另行记录，不承诺改数据库就让离线 token 立即失效。

### D3. 两条身份来源，不要求双重凭据堆叠

**Snaplink 身份路径：** 使用有效 access token，服务端验证签名、issuer、预期资源 audience、client/tenant 和时间；按现有合同执行 sender/session 绑定。主体从验证结果取得，不能由请求中的 user_id 替换；pairwise sub 通过现有可信解析映射。ID Token 不能当 API access token，`aud[0]` 不能当作 `client_id`。

**只授权的 App 身份路径：** 后端通过 TLS 携带注册应用凭据，从自己已验证的会话取得稳定用户标识。服务端认证应用后，仅接受其声明本应用命名空间的用户。信任的是 App 的用户认证责任，不是声称 secret 能证明用户已经登录。

- MVP 优先支持登记为 secret 认证的 confidential client，复用现有哈希校验、过期和轮换重叠语义；secret 通过凭据提供器取得，仅驻留后端，不出现在 URL、普通配置快照或日志中。
- 已注册 private_key_jwt／mTLS 等认证方式的应用不得静默降级为 secret；对应接入适配未就绪时拒绝启用，而不是另写简化验签器。
- public client 可以走适用的 SSO／PKCE，但不能凭公开 client_id 获得 App 用户委托权限。
- App 外部用户按 `(tenant, client, external_user_id)` 归属，映射为无歧义的授权主体；不强迫创建认证账号，不按 email 自动关联，也不能混用已有 Snaplink 用户 ID。具体编码／映射纳入 M0 规格。
- 第一版中，“两者”模式默认用 Snaplink 用户凭证；“只授权”模式才显式接受 App 用户委托。不得在 token 无效时自动切换为 App 声明。
- 调用应用凭据不授予角色管理、其他命名空间用户查询或跨应用访问能力；管理面仍按 admin 权限执行。
- App 被攻破或凭据泄漏时，其命名空间内的用户声明可能被伪造；作用域约束、凭据轮换和审计用于限制影响。让同一个 App 再签一份 JWT 不能独立消除此风险。

不默认增加自签 Subject Assertion、独立 Trust Registry 或 token exchange；未来只有跨信任域需求明确时再引入。

### D4. 一个远程资源检查，不等于每次重新登录

资源检查应包含身份验证和权限决策，不再先远程调用 userinfo、再读取角色、再调用 Check。已有身份／权限／菜单聚合保持独立用途。

“一次”的验收口径：应用发起一个业务检查请求；不包含初始 discovery/JWKS 准备或应用显式选择的刷新流程。SDK 不得在检查失败后悄悄重新登录、换身份来源或降级放行。

传输建议：应用级统一入口优先采用 HTTPS，便于多语言 SDK 复用已有 transport；现有 gRPC 消费者通过适配接入同一用例。不在 SDK 中暴露“必须先调用内部 gRPC”的细节。具体路由、消息名和错误码随首期规格评审，不在本规划中宣布为稳定 API。

### D5. 新入口不能留下旧接口旁路

现有 `authz.v1` 是稳定协议，空 client 的全局语义也属于现有合同。不能直接修改字段意义、删除方法或用新接口掩盖旧接口仍匿名可达的问题。

M0 的上线阻断决策：盘点现有消费者后，确定旧 RPC 的鉴权适配／迁移与受控 listener 隔离方案。推荐将应用流量迁入受保护入口；保留的可信内部调用必须有可验证的隔离边界。TLS、内网名称和“加一段文档”都不能单独代替隔离证明。

- 对外应用入口不提供隐式全局查询，不能接受请求自由选择 client/tenant。
- 已有 local Provider 的全局语义不因此改变。
- 对旧 RPC 新增认证要求也是可观察行为变更，需要迁移说明、消费者回归及独立评审；不能只凭 buf wire 检查宣称兼容。
- 无法同时满足安全与兼容时，阻断对外上线，按 [ADR-0008](../adr/ADR-0008-proto-versioning.md)另定迁移，不保留匿名 fallback。

### D6. 明确故障与缓存合同

- 新入口的调用方认证、client 读取或业务权限查询无法完成时，不返回 allow；区分正常 deny 与服务不可用。
- 只认证不依赖权限查询成功。现有 refresh／ID-token helper、权限附带投影、审计外送、租户停用查询等既定 fail-open/fail-closed 合同不被顺便改写。
- MVP 不增加新的 allow 决策缓存；已有缓存仍需逐项核对。后续缓存必须有权限变更失效和最大陈旧时间。
- 在线授权可校验当前状态；离线 JWT、本地 Session、第三方缓存不能自动获得即时撤销保证。
- SDK 提供决策不等于替应用执法；受保护操作必须由后端／资源服务执行，菜单隐藏不是安全边界。

## 5. 分阶段交付

阶段表示依赖与验收顺序，不是自动开工授权或固定工期承诺。

### M0：边界、兼容与首期规格

交付：

1. 客户端／调用方／用户主体／资源的信任与作用域矩阵。
2. Authorizer、ReBAC、权限投影和管理入口清单；针对缺失认证、跨 client/tenant 的实际回归。
3. Client 最小能力表示、旧记录默认值、主体命名空间、旧 RPC 迁移及具体 API 规格。
4. 数据库管理与 seed 规则；生产管理后重启不静默覆盖，旧 seed 行为如需改变必须有显式迁移／配置合同。
5. 独立设计评审和各实现切片的文件清单／预算确认。

出口：安全入口无未决旁路；协议兼容和默认值方案获评审。此阶段不重写 RBAC，不扩展治理对象。

### M1：三种接入的最小可用闭环

按顺序拆成可独立验证的变更：

| 切片 | 增量 | 完成标准 |
|---|---|---|
| M1-A | Client 能力存储、管理投影、迁移、缓存失效与 seed 合同 | Memory／SQLite／Postgres 一致；旧 SDK 更新不破坏新字段；重启不覆盖已管理策略 |
| M1-B | 应用凭据认证、主体规范化、受保护授权入口和旧入口迁移 | 错凭据、停用、越权、跨租户、全局查询和身份来源混淆均不能成功 |
| M1-C | 组合 token 验证＋现有权限决策；Go 消费适配和用法 | 三种参考应用可运行；一次业务检查；只认证不依赖权限后端 |
| M1-D | TS／Python，随后 Rust／PHP 的高层接入和共享 fixtures | 按语言分别验收；没有实现的能力明确标记，不能宣称全语言无缝完成 |

SDK Go 客户端保持 `sdks/go` 独立模块／版本边界；`interfaces/ssoclient` 是根模块消费接口，两者不得混称为同一个包。Kotlin／Swift 另行完成原生平台和安全验收，不继承服务端或其他语言的 PASS。

出口：三个真实接入样例及管理流程闭环，完成根门禁和独立复审；不包含临时授权和完整前端开发。

### M2：最小权限治理

顺序为“可靠变更记录 → 临时授权 → 当前权限解释”，分别立规格和交付，不合成一个大改动。

**M2-A：角色变化可追溯。**

- 角色修改保存 before/after、操作人、原因与时间；分配／撤销记录目标主体和来源。
- 持久变更账本与业务修改同事务提交；并发修改必须检测旧版本，不能生成与实际状态不符的 before。
- 外送审计继续遵守既有失败策略；新增事务性业务账本不等于把 audit sink 改为 fail-closed。
- 先做增量记录，不宣称能还原引入账本以前的所有历史。

**M2-B：临时授权独立记录。**

概念字段：grant ID、tenant/client、主体引用、role、`valid_from`、`valid_until`、状态、来源、原因、操作者、撤销信息及角色修订引用。具体 API／表名不是本规划的既成合同。

- 永久分配保持；有效临时授权为加法，不做每用户 deny 覆盖。
- 权限判定执行 `valid_from <= now < valid_until`；sweeper 只负责提醒、索引回收和审计。
- 推荐首版语义：grant 绑定角色的单调修订号；权限定义发生变化后不匹配的临时 grant 失效，需重新授予。角色回滚也产生新修订，不能让旧 grant 复活。不是完整不可变角色版本树，此决策需在 M2-B 评审确认。
- SCIM／IdP 不得因为同步永久分配而删除独立临时 grant；各来源只管理自己的记录。
- 临时角色纳入同一有效权限、SoD 和 session-active-role 判定，不能在另一个旁路做简单并集绕过约束。
- MVP 的期限保证限于接入实时决策的资源；不把临时权限灌入长期 token 后声称到期即时失效。Roles、Permissions、Menus、Check 的投影语义必须一致。
- Memory 参考实现与所宣称的 SQLite／Postgres 实现需要同一 conformance；不支持的 backend 明确不可启用，不得静默回退。

**M2-C：简单 Explain。**

回答当前决策的角色／权限／授权来源、有效期限与拒绝分类；他人的详情只向有权限的管理调用方展示。与实际 Check 共用解析结果，不另写一套规则引擎。它不是任意历史时间的完整决策重放，也不输出凭据和敏感内部故障细节。

### M3：有真实需求再做

- 角色定义复制：预览、diff、冲突、目标 client 映射；默认不复制用户分配，不复制认证秘密。
- 访问复核、到期通知：先接现有工单／通知系统，不自建完整审批引擎。
- 独立授权进程：只有独立伸缩、团队／故障边界明确时启动；沿用同一领域合同，不另造一套 client 权威数据。

现有 [PolicyBundle](../../domains/permissions/policy_bundle.go)不含主体分配；TenantExport 也不是通用反向导入闭环。二者不能直接包装成完整迁移产品。

## 6. 所有权与工程约束

| 职责 | 优先扩展的 owner |
|---|---|
| Client 能力数据与凭据合同 | `shared/core`、现有 ClientStore、`config`、管理 Client API |
| 有效业务权限、变更／grant 语义 | `domains/permissions` 及必要的向下职责提取 |
| 存储与事务 | Memory、`domains/permissions/sqlite`、`infrastructure/postgres` |
| 安全入口、上下文规范化与适配 | `interfaces` 现有 owner；stock 在 `cmd/sso-server` 组合 |
| 应用 SDK | `interfaces/ssoclient` 和各 `sdks/<language>`，不混淆独立发布边界 |
| 跨服务集成用例 | `test/`，`package ssotest` |

本次观测到的预算：`interfaces/sso` 生产文件 60；`domains/permissions` 生产文件 10；`shared/core/types.go` 496 行；`interfaces/sso/handlers.go` 490 行；`server_routes.go` 498 行；`cmd/sso-server/build_app_core.go` 500 行。

这些不是可继续增长的余量。实施前重查预算，先做有界职责提取，不新增豁免、不增长已有超限目录、不在 sso 增加第 61 个生产文件。保持单向分层；不在领域层引用 server，不引入 OAuth↔OIDC 导入。

不修改：认证 cost、安全断言、refresh family／single-use／grace、MFA、oracle-safe wire、依赖／Go directive／模块发布所有权、冷构建 profile，除非另立明确规格。

## 7. 验收矩阵

除 [EVALUATION](../agent-os/EVALUATION.md) 的 U 类、适用的 S／A／O 类要求外：

| ID | Given / When / Then |
|---|---|
| C1 | 身份存储正常时，只认证应用关闭业务权限能力或运行期仅业务权限查询故障，SSO 登录仍按既有合同工作 |
| C2 | 未知、禁用、错误／过期凭据或未授能力的应用请求新入口，不能得到授权成功；凭据失败不泄露隐藏原因 |
| C3 | App-A 携带自己的有效凭据请求 App-B、另一 tenant、全局范围或 Snaplink 主体，均不能越界 |
| C4 | 请求 user_id、client_id、tenant_id 与已验证身份不符，不能覆盖可信上下文；App 来源和 Snaplink 来源不串用 |
| C5 | public client、注册认证方式不匹配、轮换 overlap 前后／secret 到期，行为符合登记合同，无降级认证 |
| C6 | 错 issuer／audience、ID Token 冒充 access token、过期／撤销 session、pairwise 主体映射均有正负例 |
| C7 | 一次业务检查不会顺带调用 userinfo／roles／menus；超时、后端错误和正常 deny 可区分，均不自动放行 |
| C8 | 旧 SDK 更新、旧数据库迁移、seed／重启、新能力关闭以及旧 RPC 消费者有兼容回归；旧入口不存在旁路 |
| C9 | 两副本间 client／角色／分配／grant 变更按声明失效期限生效；并发修改／撤销在 race 重复中正确 |
| C10 | 临时授权开始前、开始时、结束前、结束时、撤销后及角色修订变化均正确；不依赖 sweeper 才失效 |
| C11 | 角色回滚不会复活旧临时 grant；SoD 与活动角色约束覆盖临时授权；各查询投影与 Check 一致 |
| C12 | 业务变更或事务账本任一写入失败都不产生半提交；并发 before/after 与实际状态一致；Explain 与真实判定一致 |

C1–C8 为 M1 必需；C9 的 client／现有策略部分在 M1 执行，grant 部分在 M2 执行；C10–C12 为 M2 必需。不存在的后端、平台或功能不能用 skip 充当验收。

每个 Go 编辑后立即执行：

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

实施交接至少包括针对性测试、适用的 conformance 与真实后端测试、并发场景 `-race -count=10` 或更高、全库 race、独立 E2E、完整 `make ci`、diff 检查及独立复审。proto 变化额外做 against 精确旧基线的 breaking 检查；HTTP／错误／配置变化同步对应合同与 SDK 注册／生成检查。

真实 Postgres／stock 验收使用明确 owned fixture；没有 DSN／二进制导致的 skip 不算通过，不为清理而补造验收证据。

## 8. 发布、回滚与开工门槛

- 迁移先扩展兼容 schema，再升级全部相关副本；确认能力识别和客户端适配后才逐应用启用。
- 旧程序可能忽略新的禁用能力、主体或 grant 语义，不能混跑并宣称已强制执行。回滚先关闭新入口／新能力并隔离风险路径，不直接让不识别策略的旧二进制接管。
- 新数据先保留，默认不做破坏性 schema 回滚；不为回滚重新开放匿名旧接口。
- 模式变化、凭据、角色、分配和 grant 修改的缓存失效／旧 token 最长残留时间必须可观测、可测试。
- 文档随实现更新：OpenAPI、proto、错误码、配置、功能矩阵、deferred backlog、SDK paradigm／surface、迁移说明；不能先把 Proposed 改成 Implemented。
- 本地源码门禁通过不等于发布。镜像、扫描、同字节运行、外部前端及真实供应商集成另行验收；不自动 push／发布／部署。

M1 开工前必须定稿：Client 默认与 presence 语义、外部主体映射、旧 RPC／ReBAC 入口迁移隔离、HTTP／gRPC 鉴权与错误合同、seed 迁移、SDK 先行语言、精确文件范围和预算。若任一项未定，不以“先开发再补安全”绕过。

本次只完成 Proposed 规划及文档级检查。未执行新功能测试、Go／CI 交接或独立设计评审；它们是后续实际交付的门槛。
