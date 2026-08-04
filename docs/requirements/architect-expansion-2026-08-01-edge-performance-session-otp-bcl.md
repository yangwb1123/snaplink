# 架构扩展分析：验证码通道、出站投递、会话策略与跨副本一致性

> 分析日期：2026-08-01
> 方法：对当前工作树做一次全局扫描（`interfaces/`、`protocols/`、`domains/`、`infrastructure/`、`platform/`、`shared/`、`cmd/`、`docs/`），以可执行代码和已提交契约为唯一事实来源；用 `docs/feature-matrix.md`、`docs/deferred-backlog.md` 与 `docs/requirements/` 下已有分析交叉核对，排除已被实现或已被识别的方向。本文只做分析与需求论证，不含实现代码。
> 定位：本文是需求/分析意图，不是已实现功能的承诺。功能现状以 [feature-matrix.md](../feature-matrix.md) 与 [deferred-backlog.md](../deferred-backlog.md) 为准。

## 0. 现状基线

代码库在协议面（OAuth 2.0/OIDC/FAPI/CIBA/PAR/JAR/JARM/DPoP/mTLS/token-exchange/CAEP-SSF/SAML/SCIM/WebAuthn）与平台面（多租户、条件访问、ITDR、计量、通知、SSE、gRPC 管理面、DR、基准门禁、k6 负载测试）均已高度成熟。`docs/requirements/` 已有 160+ 份历史分析，2026-08-01 的两份分析已覆盖：租户配额持久化、Redis 客户端租户索引、SCIM 索引化与 value-path、分布式平滑限流、登录链路延迟预算、密码哈希策略治理。

因此本文刻意选取**上述分析未覆盖、且在当前代码中有直接证据**的方向，且尽量保持"同一主题下功能扩展 + 边界情况 + 性能"三者的平衡。选择标准：安全/合规影响 × 爆炸半径、运营成本随规模增长曲线、与既有承诺（feature-matrix / deferred-backlog / ROADMAP）不冲突、代码证据可定位到文件:行。

---

## 方向一：Backchannel Logout 出站投递可靠性——单发无重试 + 请求作用域上下文

> 2026-08-01 实现进展：单发与请求取消问题已收口。当前实现对瞬时网络错误、408、429、5xx
> 在同一个 5 秒总预算内最多尝试 3 次（抖动指数退避、每次 fresh `jti`），投递上下文保留
> trace/tenant value 但脱离浏览器取消；失败目标不会再从 SubjectClientIndex 遗忘。现已增加可选
> 内存/Redis 失败队列：Redis 跨重启持久化并用租约协调多副本，后台与管理 API 均可重放，
> 每次重签 fresh `jti`、不落盘已签名 token；成功确认后清理索引，优雅停机等待 worker 收敛。
> 永久 RP 4xx 只进入人工治理视图，不参与后台反复投递。本方向列出的投递可靠性闭环已交付。

### 为什么需要

OIDC Backchannel Logout（BCL）是**唯一一条"注销承诺"完全依赖外部 RP 可达性**的通道：本地会话、refresh token 已撤销，但 RP 侧的会话是否被清除，取决于一次无重试的 HTTP POST。当前实现是"单发 + 日志/审计"，失败即丢。对比仓库内其余三个出站投递机制（CAEP SET 投递、SCIM outbound provisioning、webhook），**BCL 是唯一没有重试/死信语义的**——机制不一致本身就是缺陷信号。

安全影响：设备丢失/账号被盗场景下，管理员吊销会话（`/admin` 会话吊销、租户挂起、`subject_client_index` 多 RP 扇出），本地一切正常，但每个 RP 的会话残留至 token 过期。企业合规审计（"该用户已从所有应用登出"）无法兑现。此外投递上下文派生自 `ctx.Request().Context()`——**请求结束/客户端断连即取消投递**，在高并发登出或网关超时下，健康 RP 也可能收不到通知。

### 代码证据

- `interfaces/sso/server_backchannel_logout.go:155-201` — `sendBackchannelLogout`：签发 logout_token 后**单次** `logoutNotifier.Notify`；失败仅 `recordLogoutNotifyFailure`（审计）后返回，无重试、无队列、无死信。
- `interfaces/sso/server_backchannel_logout.go:158` — `tokenCtx, cancel := context.WithTimeout(ctx.Request().Context(), DefaultBackchannelLogoutTimeout)`：**请求作用域上下文**，父请求取消则投递中止。
- `interfaces/sso/server_backchannel_logout.go:115-145` — `HTTPLogoutNotifier.Notify`：单 POST、5s 超时、非 2xx 即错误。
- `interfaces/sso/server_backchannel_logout.go:300-318` — 扇出在 `go func()` 中执行，与请求生命周期解耦不足。
- 对照先例：`protocols/caep/broadcaster_retry.go`（`WithDeliveryRetry` 指数退避 + 抖动，默认单发但可选重试）；`protocols/scimprovision/sink.go:28-38`（重试耗尽进死信队列 + `scim_provision_failed` 审计 + `DeadLettered` 指标）；webhook 同样有 DLQ。BCL 没有等价物。

### 边界情况

- **RP 宕机/维护窗口**：单发失败后无补投，RP 恢复后会话仍残留；
- **部分扇出**：`subject_client_index` 多 RP 场景，第 3 个 RP 失败不影响前两个成功——无"部分成功"的对账视图，管理员无法得知谁没收到；
- **请求取消**：登出响应已返回（用户看到"已登出"）但通知 goroutine 的 ctx 已取消，投递静默失败；
- **drain/优雅停机**：`platform/lifecycle` 的 drain 只覆盖模块生命周期，不等待在途 BCL goroutine，停机窗口内的登出通知丢失；
- **重放与幂等**：重试必须保证 logout_token 语义安全（`events` + `sid` 去重由 RP 侧负责，发送方需避免重复审计计数）。

### 建议落地形状（设计方向）

- 为 BCL 引入与 CAEP 同形的可选重试（退避 + 抖动 + 总尝试上限），失败进入有界死信队列（内存 + 可选 Redis），支持后台补投；
- 投递上下文改为独立的后台 ctx（带绝对期限），与请求 ctx 解耦；drain 阶段等待在途投递收敛；
- 管理面暴露"RP 投递状态"（成功/失败/待补投/死信）与审计事件、`sso_bcl_delivery_failed_total` 类指标 + 告警规则；
- 优先级：P1。规模：中等（一个 notifier 包装层 + 队列 + admin 视图），不触碰 `interfaces/sso` 文件上限。

---

## 方向二：一次性验证码通道的双向滥用治理与发送可靠性（SMS/Email/Magic Link）

> 2026-08-01 实现进展：内存与 Redis CodeStore 已统一为每个签发值最多 5 次失败验证，成功
> 单次消费；同步发送失败会按生成值做条件撤销并释放 60 秒冷却，避免误删并发换发值。现已
> 增加默认每个租户内同一身份 20 次、租户总计 1,000 次/24h 的可配置固定窗口发送配额；
> Redis 通过单租户哈希与 Lua 在多副本间原子记账，超额对外仍是通用成功响应。现已增加
> 可选的有界内存异步投递队列：请求只等待入队，后台按超时与指数退避有限重试；队列满
> 同步回滚，重试耗尽则条件失效当前验证码并释放配额，优雅停机等待已接收任务收敛。明文
> 验证码刻意不落持久化队列，进程崩溃时依靠短 TTL 失效并由用户重新发起。

### 为什么需要

Email/Phone OTP 与 Magic Link 是低摩擦认证与恢复通道，但当前实现存在三个方向的不对称：

1. **验证侧无独立尝试上限**：`MemoryCodeStore.Verify` 对错误尝试**没有计数**，6 位数字码（10^6 空间）的暴力破解只依赖可选的 `WithAccountLockout` 门禁（未接线即裸奔）；且每次失败即删除 code 条目——攻击者可以反复触发 `SendCode` 拿到新码继续猜，猜错不产生任何发送侧成本。
2. **发送侧无配额**：重发仅受 60s cooldown 约束，**没有每日/每身份/每租户发送上限**。SMS 按条计费（`infrastructure/sms` 直连 Twilio API），攻击者对受害者号码反复触发 `SendCode` 即可：烧钱（成本滥用）、轰炸受害者手机/邮箱、并借"多次重置触发锁定向导"锁定受害者账户（账户锁定 DoS）。
3. **发送失败烧掉冷却窗口（边界）**：`SendCode` 先 `store.Save` 再 `sender.Send`——供应商超时/失败时 code 已入存储且 `savedAt` 已记录，用户**没收到**验证码却要再等 60s 冷却，且该 code 在存储中处于"已激活但用户未知"状态。

另有性能点：`/auth/send-code` 在**请求路径内同步**调用外部供应商（Twilio 默认 10s 超时），登录 UI 的"发送验证码"按钮等待与供应商可用性耦合。

### 代码证据

- `domains/authenticators/codestore.go:64-88` — `Verify` 无尝试计数、失败即删；cooldown 仅作用于 `Save`（重发）。
- `domains/authenticators/codestore.go:20-23` — `DefaultCodeResendCooldown = 60s`，无每日配额概念。
- `domains/authenticators/email.go:60-75` — `SendCode`：Save 成功后才 Send，Send 失败返回错误但条目保留。
- `interfaces/sso/server_logout.go:117-146` — `handleSendCode`：仅依赖通用限流中间件 + `recordCodeSent` 审计，无身份级配额校验。
- `infrastructure/sms/sender.go` — 每条短信一次外部 HTTP 调用（计费面）。
- 对照：`interfaces/sso/server_login_auth.go:75-125` 的账户锁定向导只覆盖 `Authenticate`（验证）路径，`SendCode` 路径不经过锁定向导。

### 边界情况

- 攻击者以受害者邮箱/手机号触发 `SendCode` 与密码重置 → 收件箱轰炸 + 账户锁定 DoS（锁定向导与发送路径解耦）；
- 供应商故障：Send 失败后冷却卡死（上文）；供应商 5xx 与超时如何区分"重试发送"与"告知用户稍后再试"；
- 验证尝试上限的判定主体：按 code 计数 vs 按身份计数（攻击者可每个新码只猜一次规避按码计数）；
- 配额与锁定的交互：配额耗尽后的响应必须与"发送成功"在外观上不可区分（oracle-safe，参照 AGENTS.md §3 纪律）；
- 多副本下 cooldown/配额的原子性（见方向四）。

### 建议落地形状（设计方向）

- `CodeStore` 增加可选 `AttemptLimiter`/配额扩展（或独立 SPI）：每身份每日发送配额、每 code 尝试上限（原子 INCR，Redis 模式已有先例 `account_lockout`）；
- 修复发送失败语义：Send 失败时补偿删除条目（或把 cooldown 记账与 code 条目分离），让用户能立即重试；
- `SendCode` 支持异步投递队列（邮件/SMS 出站不阻塞请求路径），保留失败审计与指标（`sso_otp_send_total{provider,outcome}`）；
- 优先级：P1（安全 + 直接成本面）。规模：小-中，主要落在 `domains/authenticators` 与 `interfaces/sso` 各一处接线。

---

## 方向三：会话级条件访问——策略只在登录时评估，且缺少会话年龄/重认证条件

> 2026-08-01 实现进展：CAP 已在 refresh-token 续签前按当前用户组、设备、信任、地理与策略
> 重新评估；deny、step-up 与 scope 收缩均即时生效，连续验证写入的 `StepUpRequired` 也会阻止
> refresh 继续续命。策略现支持 `session.age_seconds` 与 `authentication.age_seconds`，可表达
> 定期重认证；缺失/未来时间信号不匹配。现已补齐 `session.max_concurrent`（登录按 prospective
> count、存量扫描只撤销超额会话）、启动即执行/周期执行的有界存量会话收敛、四类会话后端的
> 授权上下文持久化，以及 `POST /api/v1/admin/access-policies/converge` 管理面即时应用。deny
> 撤销会话，step-up 写入 `StepUpRequired`，scope 收缩形成 refresh 不可再扩张的持久上限；策略
> 数据源故障不做任何会话变更并在下一周期重试。

### 为什么需要

条件访问引擎（CAP）已覆盖用户组、设备托管/类型/信任分、新设备、新地点、风险分、地理、时间窗口——但有两个产品级缺口：

1. **无会话维度条件**：没有"会话年龄 > N 天强制重认证""每 M 天要求 step-up""并发会话数 > K 拒绝新会话"这类条件。`Conditions` 结构体（`domains/conditionalaccess/conditionalaccess.go:121-161`）无任何会话年龄/计数字段。会话 TTL 是 wiring 时固定的（且 `WithSessionTTL` 被既有分析标记为无效选项），无法按租户/客户端/风险档位差异化。
2. **评估只发生在登录时**（`interfaces/sso/server_login_gates.go:133`），**已登录会话不随策略变更收敛**：管理员收紧策略（如"所有会话 24h 后必须重认证"）后，存量会话继续有效至 TTL；设备丢失场景下，被吊销的会话可以靠 refresh token 续命（refresh 只检查会话过期/吊销，不重跑 CAP）。这与"条件访问是零信任强制点"的定位不符——当前它只是登录时的一次性闸门。

### 代码证据

- `domains/conditionalaccess/conditionalaccess.go:121-161` — `Conditions` 字段清单（group/device/risk/geo/time），无 session_age / reauth_cadence / concurrent_sessions。
- `interfaces/sso/server_login_gates.go:133` — `capEngine.Evaluate` 仅在登录门禁调用；`interfaces/sso/accessors_handlers.go:68` 为管理面评估入口。
- `infrastructure/defaultimpl/memorystoreidentity/memory_session.go:170-189` — `Refresh` 只检查 `Revoked/IsExpired`，不重新评估策略。
- 对照：`domains/tokenpolicy/evaluate.go` 的 `RequireRenewAfter` 只影响 introspection 的 `renew_after` 提示（建议性），不是强制重认证。

### 边界情况

- 策略变更后的存量会话收敛窗口（立即失效 vs 宽限）与通知（`session_expiring` 通知已存在，可复用）；
- 重认证后的授权码/令牌链：step-up 的 `AuthTime/AMR` 传播（RFC 9470 helper 已存在，需要接线到会话策略）；
- 并发会话数条件的计数一致性（跨副本原子计数，见方向四）；
- 会话年龄的时钟基准（数据库时间 vs 本地时钟，参照 AGENTS.md 时钟纪律）；
- 高优先级会话（break-glass）豁免路径，避免管理员被自己的策略锁死。

### 建议落地形状（设计方向）

- `Conditions` 增加 `SessionAge`、`ReauthCadence`、`MaxConcurrentSessions` 字段（YAML/管理 API 双入口，沿用现有 `yaml.go` 解析与 `Validate` 模式）；
- 评估时机扩展：登录时 + 会话 Refresh 时（低成本点）+ 策略变更广播后的一次性收敛扫描（复用 `server_invalidation.go` 的跨副本广播先例）；
- 管理面策略变更 API 增加"立即应用于存量会话"选项；
- 优先级：P1（产品差异化 + 安全收敛）。规模：中，集中在 `domains/conditionalaccess` 与 `interfaces/sso/server_login*`。

---

## 方向四：进程本地状态的跨副本一致性盲区（幂等键 / 通知冷却 / SSE）

### 为什么需要

代码库对"分布式状态"已有成熟纪律：token 撤销、签名密钥轮换、客户端变更、租户挂起都有跨副本失效广播（`interfaces/sso/server_invalidation.go` + `platform/cluster`），Redis 后端用 Lua 原子脚本做读改写。但仍有三类**进程本地状态**没有同等治理，在多副本生产拓扑（`cluster.ha` 是已支持能力）下产生行为漂移：

1. **幂等键缓存**：`/token` 的 `Idempotency-Key` 去重依赖 `MemoryIdempotentCache`（进程内）。客户端重试打到另一个副本 → 不去重 → 重复签发/重复消耗。幂等语义在故障转移场景下静默失效。
2. **通知冷却**：通知路由器的 per-{subject,type} cooldown 记在进程内 map（`router.go:353` `r.recent[key]`）。两个副本同时看到同一审计事件 → **用户收到两封邮件**；冷却在副本间不共享。
3. **SSE 事件流**：`platform/sse` broker 的事件 ID 是 "monotonic, process-local"，replay ring 也只在单进程内。管理控制台连到副本 A，只能看到 A 处理的事件；故障转移后 `Last-Event-ID` 续传对不上 B 的序列。

### 代码证据

- `infrastructure/defaultimpl/memory_idempotent.go:20-60` — 进程内 map + 本地 prune loop，注释自述 "in-process, non-persistent"。
- `platform/lifecycle/notification/router.go:344-353` — cooldown 写入 `r.recent`（内存 map）。
- `platform/sse/broker.go:14-33` — 文档自述 "monotonic, process-local"、replay ring 有界、满则驱逐（at-least-once 仅限同 broker）。
- 对照先例：`infrastructure/redis/account_lockout.go`（Lua 原子计数）、`infrastructure/redis/jti_replay.go`（SET NX EX）、`interfaces/sso/server_invalidation.go`（跨副本广播）。

### 边界情况

- `/token` 重试跨副本：主副本已消费授权码、副本 B 收到重试 → 二次签发（对授权码流程是 invalid_grant 无害，对幂等承诺是有害的语义漂移）；
- 双副本同时触发同一通知事件 → 重复邮件（用户可见的信任损伤）；
- SSE 故障转移：broker 重启/切副本后 `Last-Event-ID` 从新序列开始，管理面漏事件；
- 冷却/幂等的时钟基准与 TTL 语义在共享存储下的原子性。

### 建议落地形状（设计方向）

- 幂等键与通知冷却提供 Redis 后端（复用现有 Lua 模式；幂等键即 `SET key value NX EX ttl` + 响应体缓存，与 `memory_idempotent.go` 同接口）；
- SSE：要么副本亲和路由（管理面粘性会话），要么经共享总线（Redis pub/sub 或 Kafka，仓库已有 Kafka 模块）扇出事件 + 每副本独立游标；
- 在 `feature-matrix`/部署文档中明确"进程本地状态的单副本语义"边界，避免运维误以为多副本下行为一致；
- 优先级：P2（一致性语义，事故面在故障转移与重复投递时显现）。规模：小-中。

---

## 方向五：数据面大查询的流式化与内存边界（租户导出 / 审计 facets / 主题导出）

### 为什么需要

管理面与合规面存在三条**全量驻留内存 / 全窗口扫描**的路径，随租户规模线性恶化，目前没有任何内存上界或流式出口：

1. **租户导出**：`TenantExporter.BuildTenantExport` 把客户端、成员、邀请、连接、权限等**全量列表组装进一个内存对象**再整体返回/落盘。十万级用户租户 = 十万条记录 ×（结构体 + JSON 缓冲区）双份驻留，GC 压力与 OOM 风险并存，且无分页/流式出口。
2. **审计 facets**：`platform/audit/facets.go:50-51` 自述 "Limit/Offset are ignored — facets describe the whole filtered window"——facets 对**整个过滤窗口**做全量聚合扫描。审计表达到百万级事件后，管理面打开 facets 视图即触发一次大扫描。
3. **主题数据导出**：`protocols/selfservice/data_export.go` 与 `protocols/compliance` 的 subject export 同样以完整对象形态组装（partial_failure 测试证明其健壮性，但未解决内存形态）。

### 代码证据

- `protocols/compliance/tenant_export.go:134-140` — `BuildTenantExport(ctx, tenantID) (*TenantExport, error)` 返回完整对象；`exportClients/exportMembers/...` 各自 `List` 全量 + `sort.Slice`。
- `platform/audit/facets.go:50-51` — facets 忽略 limit/offset，全窗口聚合。
- 对照：`interfaces/admin/token_portfolio.go:150-156` 已有 `defaultTokenExpiringLimit=100 / maxTokenExpiringLimit=1000` 的钳制先例——说明仓库的纪律是"大查询必须钳制"，而导出/facets 尚未纳入。

### 边界情况

- 大租户导出超时/取消：`BuildTenantExport` 中途取消时已读数据全丢，无断点续传（对 GB 级导出是可用性问题）；
- 部分后端失败：`exportPermissions` 依赖 `exportClients` 的产出，失败段的记录与重试（已有 `record` 部分失败报告机制，可扩展为可续跑清单）；
- facets 在过滤窗口极大时的 CPU/内存峰值与响应超时（管理面 UI 直接卡死）；
- 导出内容的一致性快照：全量导出期间数据变更导致的不一致（是否需要事务快照或版本号）。

### 建议落地形状（设计方向）

- 租户/主题导出改为**流式**：NDJSON 分节流式写出 + 后台任务 + 结果下载 URL（复用现有审计查询 API 的分页语义），内存上界 = 单节大小；
- facets 增加窗口上限钳制（沿用 `maxTokenExpiringLimit` 模式）或降级为"前 N 条 + 采样聚合"并显式标注；
- 为三条路径各加一个规模级指标（导出行数、facets 窗口大小）与告警，让退化可观测；
- 优先级：P2（性能/运营成本，随租户规模增长）。规模：中，主要落在 `protocols/compliance` 与 `platform/audit`。

---

## 附录：已扫描但未入选的候选（含排除理由）

| 候选 | 排除理由 |
|---|---|
| 租户配额持久化、Redis 客户端租户索引、SCIM 索引化、分布式平滑限流、登录延迟预算、密码哈希策略 | 已被 2026-08-01 两份分析覆盖，本文不重复 |
| CAEP SET 投递重试、SCIM outbound 重试+死信、webhook DLQ | 已实现；本文方向一借用其作为 BCL 的对照先例 |
| Redis 会话 ListAll / 通知 session 扫描 | 已实现（`infrastructure/redis/session.go:227` 索引化 ListAll） |
| 客户端 JWKS 缓存 / 发现文档缓存 / introspection 缓存 | 已实现且带 ETag/singleflight/指纹 |
| 内存会话/幂等存储无界增长 | 已有 reaper/prune 防御 |
| CIBA user_code 模式 | 已在 deferred-backlog 登记 |
| 管理面分页钳制 | 已实现（token portfolio limit 钳制） |
| 邮件/短信异步投递队列（独立方向） | 并入方向二（发送可靠性） |

## 落地建议（与既有工程门禁对齐）

1. 每个方向先落**测试**再落实现：方向一补"RP 失败→重试→死信"的契约测试（参照 `protocols/caep/broadcaster_retry_test.go` 模式）；方向二补"尝试上限/配额/发送失败补偿"的表驱动用例；方向三补"Refresh 时重评估 + 存量会话收敛"的集成测试；方向四补 `backendsemantics` 级后端对等测试（参照 `test/backendsemantics/`）；方向五补大窗口钳制与流式断点测试。
2. 契约同步：任何新端点/配置键按 AGENTS.md §5 同步 `docs/openapi.yaml` / `docs/config-reference.md` / `docs/error-codes.md` / feature-matrix；新审计事件同步 `auditreport` 分类。
3. 预算检查：方向一、三、四的实现不得触碰 `interfaces/sso` 60 文件上限与目录扇出上限；新 SPI 归类进既有层（`shared/core` 或 `shared/spi`），无需新增 `layerExemptions`。
4. 优先级汇总：P1 = 方向一、二、三；P2 = 方向四、五。规模估计：方向二最小，方向三、五中等，方向一、四中等。
