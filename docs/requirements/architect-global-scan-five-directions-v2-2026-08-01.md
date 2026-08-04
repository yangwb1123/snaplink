# 全局扫描（第二轮）：五个高价值扩展方向

- 日期：2026-08-01
- 范围：对当前工作树做一次全局扫描（`shared/` → `domains/` → `protocols/` → `platform/` → `infrastructure/` → `interfaces/` → `cmd/` + 契约文档），以**可执行代码与已提交契约为唯一事实来源**。
- 方法与去重：与 `docs/requirements/` 下 160+ 份历史分析、`deferred-backlog.md`、`ROADMAP.md`、`feature-matrix.md` 交叉核验。本报告的五个方向中，**审计链头锚定与生产级 GeoIP 后端**在历史分析中从未作为方向提出；其余三个是"历史分析曾以愿景形式提及、但当前代码证据表明核心缺口仍然存在"的**可验证剩余缺口**（历史文档与代码不一致处以代码为准，见各方向"与已有分析的差异"小节）。
- 定位：本文是需求/分析意图，不是已实现功能的承诺。功能现状以 [feature-matrix.md](../feature-matrix.md) 与 [deferred-backlog.md](../deferred-backlog.md) 为准。

---

## 方向一：审计哈希链的链头锚定与周期性签名 Checkpoint（合规/取证）

### 为什么需要

`platform/audit` 的 hash chain 防篡改是项目对外宣称的合规能力（SOC2/审计导出/CEF/OCSF/webhook 消费）。但链式哈希有一个**结构性的最后一个事件盲区**，且没有任何外部锚定：审计验证（`sso-ctl audit-verify`、`VerifyChain`）只能证明"被验证的数据内部自洽"，无法证明"数据没有被整体替换"。攻击者若能同时控制存储与验证通道，可以篡改任意事件后重新计算链并"验证通过"；最后一个事件甚至不需要重算链。对受监管场景（取证、SOC2、ISO 27001 审计证据）这是不可接受的盲区——而代码注释明确承认了这一点并把它推迟到 v1 之外。

### 代码证据

- `platform/audit/chainer.go:26-30` —— 显式声明限制："tampering with the LAST event isn't detectable from the chain alone (no future hash to break). Detection requires either a periodic external attestation (publish the head hash to a separate channel) or a cryptographic signature on the head hash — both out of scope for v1."
- `platform/audit/sqlite/maintenance.go` —— 已有 `VerifyChain`（链完整性校验原语）与保留期清理，但**没有**定时生成链头 checkpoint 的任务、没有 checkpoint 存储、没有链头签名密钥。
- `cmd/sso-ctl/auditverify/main.go` —— 已有 CLI 验证导出的链，但只能做内部一致性验证，无外部锚定比对。
- `platform/audit/async_sink.go:409-410` —— 链头（ChainTip）跨进程/跨 sink 恢复已实现，说明"链头"这个概念机器已经存在，缺的只是"锚定"这最后一环。

### 边界情况

- **末事件篡改**：任何时刻的最后一个事件都可被静默修改——只有"定期把链头哈希发布到带外通道"才能让事后检测成为可能；
- **链头恢复与分叉**：进程重启、跨副本切换后从何处恢复链头；若两副本各自分叉，锚定必须能暴露分叉；
- **锚定密钥轮换**：签名 checkpoint 的密钥需独立于业务签名密钥轮换，且轮换本身要留痕；
- **锚定频率与成本**：每秒锚定不可行，需权衡"检测延迟"与写放大（对高吞吐审计是纯额外写）；
- **带外通道的可用性**：外部公证（如对象存储、区块链无关的 append-only 服务、审计文件系统）不可用时的降级语义——fail-open（记录告警）还是 fail-closed。

### 建议落地形状（设计方向）

- 新增"链头公证服务"：周期性（可配置，如每 5 分钟或每 N 事件）对当前链头哈希做签名 checkpoint，写入独立存储并支持导出到带外通道（对象存储/日志收集器）；
- checkpoint 自带序号与时间戳，验证工具（`audit-verify` 扩展）支持"以最近 checkpoint 为锚重放验证"，从而检测末事件篡改与分叉；
- 签名密钥复用 `platform/signingkeys` 的协调轮换机制；checkpoint 写入失败打审计 + 指标，不阻断主审计管道（保持 fail-open 纪律）。

**优先级：P1。规模：S-M。** 改动面小（一个公证循环 + 一个存储 + CLI 扩展），但对合规取证价值是决定性的：这是当前唯一的"审计防篡改声明无法自证"的漏洞。

---

## 方向二：登录时连接健康感知与 IdP 故障降级/熔断（可靠性/UX）

### 为什么需要

`domains/connections` 已经保存了每个上游 IdP 连接的健康状态（probe 结果），但**登录路径完全不消费它**：企业 IdP 宕机时，登录页照样展示"Sign in with <IdP>"按钮，用户点击后得到的是超时/泛化错误；没有降级提示、没有备用路径、没有熔断。对 B2B 场景这意味着：上游 IdP 故障 = 整租户静默无法登录 + helpdesk 风暴，且运维只能靠手动跑 probe 才发现。健康数据已经躺在存储里，缺的只是把它接进认证热路径——这是典型的"基础设施已就绪、消费端未接线"的高 ROI 缺口。

### 代码证据

- `domains/connections/health.go:1-6` —— 明确自述：健康状态是 "as observed by the **admin-triggered** probe"；
- `interfaces/admin/connections.go:225,274` —— `Health()` / `observeConnectionProbe` 是**仅有的两个消费者**，全部在管理面；
- `interfaces/sso/server_login.go`（provider 列表/home-realm 发现）—— 登录路径遍历连接时**不读取** `Health()`；一个 `HealthUnreachable` 的 provider 与健康 provider 展示完全一致；
- `domains/connections/probe.go` —— probe 基础能力（超时/响应体上限、SSRF 防护复用）已完备，说明扩展成本集中在"何时探、怎么用"而不是"怎么探"。

### 边界情况

- **探针新鲜度**：admin 手动 probe 的频率不足以支撑登录期决策——需要登录路径的"按需带缓存探针"（TTL 内复用，过期才真正探测，避免把探测压力放大到每个登录请求）；
- **探针与登录并发**：探针本身不能成为登录的同步依赖（登录应使用缓存状态 + 失败时回退到当前行为）；
- **抖动/翻覆（flapping）**：一次失败立即降级会误伤健康 IdP——需要连续失败计数与熔断窗口（半开探测）；
- **多副本一致性**：健康状态是易变状态，跨副本共享（Redis/共享存储）或各自缓存并接受短暂不一致；
- **枚举安全**：降级信息不能成为"该租户有哪些 IdP"的 oracle——展示层语义需与现有 `unsupported_provider` 的字节一致纪律对齐；
- **降级路径本身**：主 IdP 不可用时的回退选项（备用 IdP / 本地密码 + 步升认证）必须由租户策略显式配置，不能隐式放开安全边界。

### 建议落地形状（设计方向）

- 登录路径接入带 TTL 的缓存健康读取；连续失败触发熔断（半开窗口），熔断后 provider 在登录页置灰/隐藏或返回明确的 `provider_unavailable` 错误（与 `unsupported_provider` 的反枚举纪律一致）；
- 可选租户策略："主 IdP 熔断时回退到备用 IdP/本地认证"，默认关闭；
- probe 调度升级：admin 手动触发之外增加后台周期性扫描（复用 notification 的 session-scan 模式），健康变化打审计 + 指标 + 可选通知事件。

**优先级：P1-P2。规模：M。** 与历史分析中"IdP 健康感知路由"的愿景文档（`architect-expansion-novel-5-horizons-scan.md`）不同，本方向不做 IdP 路由引擎/属性映射/JIT 的大盘子，只做**基于现有 probe 数据的登录热路径消费**——改动收敛、价值直接（可用性 + 可观测性 + UX）。

---

## 方向三：生产级 GeoIP 后端缺失（`geo/maxmind` 被引用但不存在）+ 静态库无更新通道（功能/运维）

### 为什么需要

Geo 数据被多个**有业务后果**的功能消费：按区域路由 SMS、从已知办公 IP 跳过 MFA、区域数据驻留判定、`new_country` 异常检测、登录页语言选择。但生产级 IP 覆盖的推荐后端在包文档中被点名（`geo/maxmind`），**代码库里并不存在**——唯一实现是 `geo/static` 手工维护的 CIDR 表。这意味着开箱部署要么没有完整 IP 覆盖（新分配网段、非办公网段全部 miss），要么依赖手工维护，且**没有任何更新/刷新通道**：数据过期后，跳过 MFA 的判定与"新国家登录"告警会随互联网地址分配持续漂移，安全语义逐渐失真。文档承诺与代码现实不一致，属于必须显式关闭的契约漂移。

### 代码证据

- `platform/geo/geo.go:10-14` —— 包文档："Production deployments wanting full IP coverage should use **geo/maxmind** on top of a curated geo/static"；
- `platform/geo/` 全部文件 —— 只有 `static` 一个后端（`platform/geo/static/static.go`），**不存在 maxmind 包**；`static.go:1-8` 自述 "Operators curate the entries"；
- `platform/geo/static/static.go:39-44` —— `Add` 是进程内手工登记，无文件加载、无下载、无校验、无原子替换；
- `domains/anomaly/detect/new_country.go` 与 `platform/geo/middleware.go` —— 消费方依赖 Lookup 结果做安全/体验决策（fail-open 但会误判）。

### 边界情况

- **数据更新失败回退**：MaxMind 下载失败必须保留旧库继续服务（fail-open），并暴露"数据陈旧"指标与审计；
- **原子替换与并发查找**：更新时正在进行的 Lookup 不能读到半替换状态（原子指针/版本化快照）；
- **校验与许可证**：GeoLite2/GeoIP 下载需 checksum 校验；许可证（EULA）约束决定能否随发行版分发；
- **私有网段与覆盖顺序**：static 覆盖层与 maxmind 主库的优先级（longest-prefix 语义）需在合成 Provider 中明确；
- **时区/国家边界漂移**：IP 段重新分配导致的国家归属变化，会影响 `new_country` 检测基线——检测器应容忍低频变化（已有基线机制可复用）。

### 建议落地形状（设计方向）

- 新增 `platform/geo/maxmind` 后端（读 .mmdb，支持内存快照原子替换），合成 Provider = static 覆盖层 + maxmind 主库；
- 后台刷新任务：定期下载 → checksum 校验 → 原子替换 → 打审计与指标（数据版本、覆盖率、陈旧度）；失败保持旧库并告警；
- 运维命令（`sso-ctl`）支持手动触发更新与健康检查；配置侧给出下载 URL/凭证/频率的默认关闭开关（默认仍可用 static，保证小部署零依赖）。

**优先级：P2。规模：S-M。** 纯新增后端 + 一个刷新任务，不触碰现有消费方接口；但补上的是"文档承诺的生产能力"缺失，直接改善区域驻留/MFA 跳过/异常检测三类安全语义的正确性。

---

## 方向四：客户端密钥到期预警扫描与轮换编排的剩余缺口（运维/事故预防）

### 为什么需要

客户端密钥到期**在 `/token` 已被强制执行**（到期后 `invalid_client`），但到期本身对运维是"突然死亡"：DCR 注册的成百上千个客户端各自持有 `client_secret_expires_at`，没有扫描任务、没有预警事件、没有自动轮换编排。对依赖机器身份的生产系统，一个被遗忘的到期日 = 一次凌晨的生产中断；对合规（SOC2/ISO 27001 要求定期凭据轮换），只靠人工 `RotateSecret` 不可审计也不可规模化。历史分析（2026-07-11 v6）曾提出完整方案，其中**字段、宽限期、expiring 列表已落地**；本方向只针对**仍缺失的剩余部分**，以代码为准，不重复已完成项。

### 代码证据（已完成 vs 剩余缺口）

已完成（本报告验证通过，不重复提议）：

- `infrastructure/redis/clients.go:132` 与 `infrastructure/defaultimpl/sqlite/clients.go:186` —— `ValidateSecret` 强制执行到期（过期即 `invalid_client`）；
- `infrastructure/redis/clients.go` / `sqlite/clients.go` —— `SecretOverlapUntil` 宽限期（新旧双密钥并存）已实现；
- `interfaces/grpcserver/grpcadmin/admin_paginate.go:58` —— gRPC 管理面已有"expiring secrets"列表能力。

剩余缺口（本方向范围）：

- `docs/notifications.md` 事件映射表 —— **没有** `client_secret_expiring` 类事件；`platform/lifecycle/notification/` 全目录 grep `secret` **零命中**——与已有的 `password_expiring`/`session_expiring` 扫描（notifications 的 session-scan 模式）形成鲜明对比；
- `interfaces/grpcserver/grpcadmin/admin_clients.go:298` —— `RotateSecret` 是纯手动 API，无到期前自动轮换或批量轮换编排；
- `tls_client_auth`/`self_signed_tls` 客户端（RFC 8705）的证书 `NotAfter` 没有任何跟踪或预警（`WithMTLSRevocationChecker` 只做吊销检查，不做到期管理）。

### 边界情况

- **到期精度与时钟**：到期判断按秒精度，预警窗口按天——扫描任务需处理时区/时钟偏差（沿用"生产时钟会漂移，不会倒退"的既有纪律）；
- **宽限期内的双密钥**：自动轮换必须先发新密钥、确认宽限期、再淘汰旧密钥，不能一步覆盖（现有 `SecretOverlapUntil` 机制可直接复用）；
- **批量轮换的爆炸半径**：DCR 客户端轮换失败不能影响未涉及客户端；每客户端轮换独立审计；
- **公钥客户端豁免**：`token_endpoint_auth_method=none` 无密钥可轮换，扫描必须豁免且不产生噪音告警；
- **预警投递对象**：到期预警的消费者是**运维/开发者**而非终端用户——需与现有 per-subject 通知路由区分（或走 webhook/管理面告警而非用户 inbox）。

### 建议落地形状（设计方向）

- 后台扫描任务（复用 notification 的 session-scan 调度模式）：对 `secret_expires_at` 在 N 天（如 30/14/7）内的客户端产出审计事件 + 管理面指标 + 可选 webhook/通知；
- `tls_client_auth` 证书到期跟踪（从注册证书解析 `NotAfter`），与密钥扫描共用同一预警通道；
- 可选"轮换编排 API"：`POST /admin/clients/rotate-expiring?within=30d` 批量轮换（每客户端独立事务 + 审计），与现有宽限期机制衔接。

**优先级：P2。规模：S。** 纯运维面新增，无协议/存储改动；价值是消除一类"静默到期中断"事故并满足凭据轮换合规证据。

---

## 方向五：租户级委派管理（Tenant-Scoped Delegated Admin）（产品/B2B）

### 为什么需要

`TenantRoleAdmin`（租户管理员角色）已经存在于租户成员模型中，但**管理面授权完全不认它**：`HasAdminScope` 的签名里没有租户维度，持有 `admin:write` 的管理员可以操作**任意**租户。对于把 Snaplink 作为多租户 B2B 平台底座的产品，这意味着平台方无法把"本租户管理"委派给客户自己的管理员——每个管理员要么是全局超级管理员，要么什么都不能管。这是多租户产品最常被企业客户追问的能力之一（"我们能否让客户的 IT 自己管理他们租户的用户/客户端/策略？"），而基础设施（租户成员、角色、permission wildcard 匹配器）都已存在，缺的只是把租户维度接进授权决策。

### 代码证据

- `interfaces/admin/middleware.go:46` —— `HasAdminScope(ctx, userID, clientID, requiredScope)`：**无 tenantID 参数**；`middleware.go:236,378` 两处调用均不携带租户上下文；
- `interfaces/sso/aliases.go:474-478` —— `TenantRole` 注释自述为 "B2B org membership standing"，`TenantRoleAdmin` 已定义；
- `interfaces/admin/tenants.go:88` —— 租户成员可被添加并授予 `TenantRoleAdmin`，但该角色在 `interfaces/admin/middleware.go` 的授权路径中**零引用**；
- `interfaces/sso/server_tenant.go` —— 租户中间件（`X-Tenant` 上下文）只服务于用户面 API，不进入管理面授权。

### 边界情况

- **越权面**：租户级管理员只能操作自己租户的资源（用户、客户端、策略、令牌吊销）——资源归属（tenantID）必须在每个管理端点强制校验，不能只靠前端隐藏；
- **全局与租户角色的叠加**：全局管理员能力不受影响；同一用户同时持有全局与租户角色时取并集，且全局操作必须打全局审计；
- **授权失败语义**：租户越权返回 `403 tenant_mismatch`（复用现有错误码），且不能暴露"该资源是否存在"（与 oracle-safe 纪律一致）；
- **租户删除/成员移除**：移除成员必须同时吊销其管理令牌/会话（复用现有 `revokeTenantSessions`/失效广播机制）；
- **scope 字符串兼容**：新租户维度建议以 `admin:write` + tenant 断言（如 `admin:write:tenant:<id>` 或授权回调内的租户过滤）实现，不得破坏现有 wildcard 匹配语义。

### 建议落地形状（设计方向）

- 扩展 `Authorizer`/`HasAdminScope` 增加租户参数（或新增 `HasTenantAdminScope(ctx, userID, tenantID, scope)`），在 HTTP 中间件与 gRPC 拦截器两处统一接线（保持"两个传输共用同一构造对象"的既有纪律）；
- 租户管理端点按资源归属强制租户断言；`TenantRoleAdmin` 映射为"本租户 admin:read/admin:write"；
- 管理面审计记录携带租户维度；委派管理员的操作与全局管理员一样进入 `admingovernance` 审批与 break-glass 体系。

**优先级：P1-P2（产品向）。规模：M。** 与历史分析中"组织层级（父子组织）+ 团队管理"的大愿景（`architect-gap-analysis-2026-07-11.md`）不同，本方向不引入组织层级模型，只做**在现有扁平租户模型上补齐授权维度**——是愿景的第一个、也是最有价值的一步。

---

## 优先级汇总

| 方向 | 类型 | 优先级 | 规模 | 关键证据（文件） |
|---|---|---|---|---|
| 1. 审计链头锚定 + 签名 Checkpoint | 合规/取证 | P1 | S-M | `platform/audit/chainer.go:26-30`（显式 v1 外限制） |
| 2. 登录时连接健康感知 + 熔断/降级 | 可靠性/UX | P1-P2 | M | `domains/connections/health.go:1-6`；消费方仅 `interfaces/admin/connections.go` |
| 3. 生产级 GeoIP 后端（maxmind 缺失） | 功能/安全语义 | P2 | S-M | `platform/geo/geo.go:10-14` 引用 `geo/maxmind`，代码不存在 |
| 4. 客户端密钥到期预警 + 轮换编排 | 运维/合规 | P2 | S | `docs/notifications.md` 事件表无 secret 到期；`platform/lifecycle/notification` 零命中 |
| 5. 租户级委派管理 | 产品/B2B | P1-P2 | M | `interfaces/admin/middleware.go:46`（授权无租户维度）；`aliases.go:474-478` |

## 与既有文档的差异说明

- **方向一、三**：`docs/requirements/` 160+ 份历史分析中从未作为方向提出（仅"PITR checkpoint""WAL checkpoint"等不同概念出现过），代码注释即缺口声明。
- **方向二、四、五**：历史分析曾以愿景/大方案形式提及（IdP 路由引擎、组织层级、密钥到期全套方案）。本报告以当前代码为准重新验证：方向二只取"消费现有 probe 数据"这一已接线可行子集；方向四明确区分"已落地（字段/宽限期/列表）"与"仍缺失（扫描/预警/编排）"；方向五收敛为"现有租户模型上的授权维度补齐"，不做组织层级。
- 所有方向均不与 `ROADMAP.md` 已承诺项冲突；未入选候选（SMS 多提供商故障转移、TOTP 时钟漂移、SCIM value-path、Redis 租户索引、分布式限流等）因已被近期分析覆盖或代码证据不足而排除。
