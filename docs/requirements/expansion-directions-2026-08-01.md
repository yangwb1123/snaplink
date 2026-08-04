# 扩展方向分析：会话数据面、事务邮件、口令策略与恢复链

> 分析日期：2026-08-01
> 方法：对当前工作树做一次全局扫描（`interfaces/`、`protocols/`、`domains/`、`infrastructure/`、`platform/`、`shared/`、`cmd/`、`config/`、`docs/`），以可执行代码与已提交契约为唯一事实来源；每个方向附精确的文件:行证据。本文只做分析与需求方向论证，不含实现代码。
> 定位：本文是需求/分析意图，不是已实现功能的承诺。功能现状以 [feature-matrix.md](../feature-matrix.md) 与 [deferred-backlog.md](../deferred-backlog.md) 为准。`docs/requirements/` 下已有 150+ 份历史分析，本文刻意选取其中未充分覆盖、且扫描中确认存在代码证据的方向。

## 0. 现状基线（扫描结论摘要）

协议面（OAuth 2.0/OIDC/FAPI/CIBA/PAR/JAR/JARM/DPoP/mTLS/token-exchange/RFC 9068/CAEP-SSF/SAML/SCIM/WebAuthn）与平台面（多租户、条件访问、ITDR、计量、通知、SSE、gRPC 管理面、DR、配置审计、混沌/HA 测试、k6 负载测试）均已高度成熟；三套存储后端（memory/SQLite/Redis/Postgres）的对等性工程也做得非常细致（`TenantScopedClientStore`、`ClientStoreStats`、`IntrospectionCacheInvalidator` 等可选扩展接口模式随处可见）。

在如此高的成熟度下，本次扫描确认的剩余缺口集中在四个面上：**数据面规模化**（会话列表的 O(N) 物化）、**投递可靠性**（事务邮件的单次尝试）、**安全策略的一致性**（口令策略 SPI 无 stock 实现、健康检查只挂在登录后）、**账户恢复链**（无密码主认证账户）。另有一个运维观测一致性缺口（热重载语义不对称）。

选择标准（四维加权）：

1. **爆炸半径**：是否造成静默漂移、账户锁死或计费/计数失真；
2. **随规模恶化**：是否随会话/租户/副本数量线性或超线性恶化；
3. **产品差异化**：是否直接改善终端用户或企业客户价值；
4. **与既有承诺不冲突**：不与 feature-matrix / deferred-backlog / ROADMAP 已声明能力重复。

---

## 方向一：会话数据面的 O(N) 物化与生命周期管理（性能 + 正确性）

### 为什么需要

管理面"列出全部会话"是 TokenAdminService 的既有 RPC，但当前实现把**全量物化**放在服务端：先 `ListAll()` 把所有会话载入内存，排序后做 offset 分页。代码注释自己承认："This proto has no order_by/filter fields... See admin_paginate.go for why this bounds the RESPONSE but not the server-side materialization."（`interfaces/grpcserver/grpcadmin/admin_tokens.go:71-105`）。

四个会话后端全部是无界扫描：

- Postgres：`SELECT id, user_id, ... FROM sessions`，无 `LIMIT`、无 `WHERE revoked=0 AND expires_at > now`（`infrastructure/postgres/session.go:201-210`）；
- SQLite：同样形状（`infrastructure/defaultimpl/sqlite/sessions.go:258`）；
- Redis：`SMembers(sessionAllKey)` 全量取 ID 再逐个 MGET（`infrastructure/redis/session.go:227-237`）；
- Memory：`ListAll` 返回**全部**会话，且不像 `ListByUser` 那样过滤 `!s.Revoked && !s.IsExpired()`（`infrastructure/defaultimpl/memorystoreidentity/memory_session.go:191-210`）——语义不一致，`TotalSize` 会把已吊销/已过期会话计入。

在 10M 会话规模下，管理员的每一页请求都是一次全表扫描 + O(N log N) 排序 + O(N) 内存分配；按用户查（`ListByUser`）同样无界。这既是性能问题（数据库负载、GC 压力、gRPC 延迟），也是正确性问题（`TotalSize` 失真、多副本下与并发吊销竞态）。

### 代码证据

- `interfaces/grpcserver/grpcadmin/admin_tokens.go:71-105` — `ListSessions` 全量 `ListAll`/`ListByUser` + `sort.Slice` + offset 分页；
- `infrastructure/postgres/session.go:201-210`、`infrastructure/defaultimpl/sqlite/sessions.go:258` — 无 LIMIT 无过滤的 `SELECT * FROM sessions`；
- `infrastructure/redis/session.go:227-237` — `SMembers` 全量索引；
- `infrastructure/defaultimpl/memorystoreidentity/memory_session.go:191-210` — `ListAll` 不过滤 revoked/expired（与 `ListByUser` 语义不一致）；
- `shared/core/spi.go:142-144` — `ListAll` 的注释本身承认"millions of sessions MAY return ErrUnsupportedOperation"。

### 边界情况

- **游标稳定性**：offset 分页在并发吊销下会跳页/重页；keyset 游标（`WHERE expires_at < ? ORDER BY id`）需要后端 SPI 支持，且游标 token 跨重启必须可解码或显式失效；
- **过期会话竞态**：分页扫描过程中会话过期/吊销，页间一致性无法保证——需明确"快照语义"或接受最终一致并写入 API 文档；
- **`TotalSize` 失真**：Postgres/SQLite 的 `ListAll` 包含已过期行，管理员看到的会话数偏大；应改为 `COUNT(*)`（或近似计数），而不是 `len(all)`；
- **大租户热点**：单租户数万会话时，按租户过滤（`ListByTenant`）若无线索引则退化为全表扫描；
- **内存后端**：`ListAll` 返回内部对象引用（非拷贝），调用方若修改字段会污染存储——当前 gRPC 层只读所以安全，但契约未声明。

### 建议落地形状（设计方向）

- 在 `core.SessionManager` 增加可选扩展接口（沿用 `TenantScopedClientStore`/`ClientStoreStats` 的 type-assert 模式）：`ListAllPage(ctx, after, limit, filter)` 与 `Count(ctx, filter)`，keyset 分页下沉到存储层（Postgres/SQLite 走 `expires_at,id` 复合索引；Redis 走 `SSCAN` + 游标）；
- gRPC `ListSessions` 改为存储层分页，`TotalSize` 用计数接口；不支持分页的后端返回显式错误而不是静默全量；
- 统一 `ListAll`/`ListByUser` 的"是否包含已吊销/已过期"语义（对齐 `ListByUser` 的过滤行为），并补充按租户过滤的索引（`infrastructure/postgres` 已有 `DeleteByTenant`，说明 tenant 列存在，缺的是 `(tenant_id, expires_at)` 索引）；
- 附带做会话表生命周期清理（见方向一的延伸）：Postgres/SQLite 增加后台批量清理任务（`DELETE ... WHERE expires_at < now OR revoked = 1` 分批删除），对齐 Redis TTL 的自我修剪语义。

**优先级：P1（高）** — 管理面随会话规模线性恶化，且 `TotalSize` 计数失真属于正确性缺陷。规模：M（SPI 扩展 + 三后端实现 + gRPC 改造 + 测试）。

---

## 方向二：事务性邮件投递：单次尝试、无重试、无投递反馈（运维可靠性 + 安全闭环）

### 为什么需要

邮件是**认证闭环的一部分**：邮箱 OTP、magic link、密码重置、邮箱验证、改邮、组织邀请全部依赖 `emailsmtp.Sender`。但当前实现是**单次尝试的 fire-and-forget**：

- `Sender.deliver` 直接 `go s.dispatch(to, msg)`（`infrastructure/defaultimpl/emailsmtp/sender.go:175-182`）——每次发送一个无界 goroutine，SMTP 故障时（`net/smtp.SendMail` 可阻塞至 10s 超时）高并发重置/注册流量会无界堆积 goroutine；
- `dispatch` 失败只写一条 log（`transport.go:40-47`），**无重试、无退避、无死信队列、无投递状态**；4xx（临时，可重试）与 5xx（永久）不做区分；
- 对比：通知链路（`platform/lifecycle/notification/router.go:284-291`）对 email 通道有 3 次尝试（25ms/50ms 退避），webhook 引擎有完整的重试 + deadletter（`platform/lifecycle/webhook/`），**但认证关键路径走的是裸 Sender，没有这些保障**；
- 无任何 HTTP 邮件服务商适配器（SES/SendGrid/Postmark），仅 SMTP；无 DKIM 签名（2024 年起 Gmail/Yahoo 对批量发件人强制 DKIM+SPF 对齐，直接影响自建 SMTP 的进箱率）；无 bounce/feedback-loop 反馈——**OTP 悄悄丢失 = 用户被锁在门外 = 工单洪峰，且安全上无法区分"未送达"与"被拦截"**。

### 代码证据

- `infrastructure/defaultimpl/emailsmtp/sender.go:175-182` — `deliver` 每封邮件一个无界 goroutine；
- `infrastructure/defaultimpl/emailsmtp/transport.go:40-64` — 单次 `smtp.SendMail`，仅超时控制，无重试/退避；
- `cmd/sso-server/serverbuildauthn/build_authenticators_helpers.go:206-210` — 邮箱 OTP 直接使用 `buildEmailOTPSender`（裸 Sender）；`cmd/sso-server/serverbuildplatform/email_sender.go:51-78` — 通知通道才包 `NotificationSender`；
- `platform/lifecycle/notification/router.go:284-291` — 只有通知路由有 3 次重试，认证路径无；
- `docs/config-reference.md:213` — SMTP 承担 password-reset/email-verification/email-change/invitation/otp 五类事务邮件。

### 边界情况

- **4xx vs 5xx**：`450/451/452` 可重试、`550/551/552` 永久失败——当前全部一视同仁；
- **SMTP 宕机期间的突发流量**：goroutine 无界增长 + 请求侧内存堆积（消息体在内存中排队）；
- **OTP 重发风暴与送达竞态**：`DefaultCodeResendCooldown`（60s）只限制发送频率，不保证送达；用户点了"重发"但第一封在途，需幂等/覆盖语义；
- **服务商限流**：SES/Postmark 按 24h 配额限流，失败应可辨识（rate-limit 4xx）并计入指标；
- **SPF/DKIM 对齐**：`From` 域名与信封域名不一致会被拒收；当前 `messageIDHost(from)` 已注意 Message-ID，但缺 DKIM 签名；
- **隐私**：现有实现已做 header 注入消毒（`sanitizeHeaderValue`）与错误日志去 token——新增重试/死信机制时必须保持这两条纪律（死信队列里不得出现 OTP/重置 token 明文）。

### 建议落地形状（设计方向）

- 认证邮件走与 webhook 引擎同构的投递管线：有界队列（可复用 `notification.WithQueueSize`/`WithWorkers` 模式）+ 指数退避重试 + 4xx/5xx 分类 + 死信存储（死信只存收件人/消息类型/错误码，不存 token 明文）；
- 增加 HTTP 邮件服务商 SPI（`email.Provider`）与 SMTP 并列，`From` 域名与 DKIM 配置纳入 schema 校验；
- 投递遥测：`sso_email_delivery_total{outcome}` 与 `sso_email_queue_{depth,capacity}`，对齐现有 `sso_notifications_delivery_failed_total` 的有界基数纪律；
- 在 OTP/magic-link 响应中把"已入队"与"已送达"解耦，UI 层可提示"若未收到请检查垃圾箱"，减少盲目重发。

**优先级：P1（高）** — 认证邮件的静默丢失直接造成账户锁死与安全盲区；webhook 引擎已有可复用的先例，实现路径成熟。规模：M（投递引擎抽取 + 死信 + 遥测 + 适配器）。

---

## 方向三：口令策略与泄露检测的强制点缺失——SPI 存在但 stock 无实现、无配置（安全一致性）

### 为什么需要

口令策略相关的 SPI 是齐全的，但**默认部署下没有一个策略在生效**，且四个设置口令的路径规则互不一致：

- `spi.PasswordPolicyValidator` 已定义（`interfaces/sso/server_signup.go:219-231`），注释明言 "When nil (the default), no policy is enforced"；`cmd/sso-server` 的构建代码与 `config/schema` 中**均未接线任何实现、没有任何配置键**——stock 二进制 = 无复杂度策略；
- 管理员建号路径用的是另一套**硬编码**规则（8 字符 + 字母 + 数字，`internal/adminuser/validation.go:17-19`），与自助路径完全脱节；
- 口令健康检查（字典/HIBP）只挂在**登录成功之后**、非阻断（`shared/spi/password_health.go:9-12`、`config/config_authn.go:109-135`），`config/config_authn.go` 与 `shared/spi/password_health.go` 的注释还写着 "This server has no register / change-password endpoint"——与现状（自助注册、`POST /me/password`、`POST /auth/reset-password`、管理员改密全部存在）**已经漂移**；
- 结果：用户在自助注册/改密/重置时设置的新口令**完全不经过**强度与泄露检查（`protocols/selfservice/signup.go:318` 与 `protocols/selfservice/selfserviceaccount/security.go:83` 只在非 nil 时调用 validator），HIBP 泄露库的 k-anonymity 能力被浪费在"事后打信号"上。

### 代码证据

- `interfaces/sso/server_signup.go:213-231` — `WithPasswordPolicy`，默认 nil；`cmd/sso-server/serverbuildauthn/` 与 `config/schema/` 无对应接线/键；
- `config/config_authn.go:109-135` — `PasswordHealthConfig` 只作用于 login-time 且 "NEVER blocks login"；
- `internal/adminuser/validation.go:17-19` — 管理路径独立的硬编码规则；
- `protocols/selfservice/signup.go:318`、`protocols/selfservice/selfserviceaccount/security.go:83` — validator 调用点（默认 nil 空转）；
- `cmd/sso-server/serverbuildauthn/build_authenticators_helpers.go:139-146` — 健康检查只附加到 password authenticator（登录）。

### 边界情况

- **策略变更与存量用户**：新策略上线后，存量弱口令用户何时被要求改密？（max-age 强制过期已有：`PasswordMaxAgeProvider`）；需"宽限期 + 登录时逐步强制"的设计；
- **设置时 vs 登录时**：设置时检查泄露口令必须 fail-open（HIBP 故障不能阻止用户改密——否则变成可用性攻击面），但要落 `password_compromised` 审计，与登录时的非阻断信号合并为同一事件词汇表；
- **多路径一致性**：自助注册 / 自助改密 / 重置 / 管理员建号 / 管理员重置五条路径必须共用同一策略对象，避免"管理员建号弱口令、自助改密强口令"的规则分裂；
- **Oracle 安全**：策略校验失败必须保持现有"统一错误文案"（`server_signup.go:227-230` 已注明），不得通过报错差异枚举策略内部；
- **导入用户**：`PasswordHashImporter` 支持预哈希导入（argon2id/PBKDF2/bcrypt），`LazyRehashVerifier` 会静默升级为 bcrypt——策略引擎应能识别"从未经过策略校验的导入口令"并纳入宽限期。

### 建议落地形状（设计方向）

- 在 `cmd/sso-server` 提供 stock 的 `PasswordPolicyValidator` 实现（复杂度规则可配置）+ 配置键，接入现有五条设置路径；
- 将 HIBP/字典检查从"登录后信号"扩展为"设置时可选择阻断"（fail-open 语义），复用 `PasswordHealthConfig` 的字典/HIBP 两种 checker 与 k-anonymity 前缀协议；
- 用策略配置生成一条审计事件（`password_policy_violation`），与 `password_weak`/`password_compromised` 归入同一有界词汇表（`auditreport` 分类）；
- 修订 `config/config_authn.go` 与 `shared/spi/password_health.go` 中关于 "no register / change-password endpoint" 的过期注释，防止后续维护者据错误前提做决策。

**优先级：P1（高）** — 安全策略存在但默认不生效、路径间规则分裂，属于"看似有、实则无"的静默漂移。规模：S-M（stock 实现 + 配置 + 接线 + 审计事件）。

---

## 方向四：无密码主认证账户的恢复链缺口（产品价值 + 边界情况）

### 为什么需要

WebAuthn passwordless 主登录已经落地（`webauthn.primary_auth_enabled`、`Client.AllowPasswordlessOnly`，见 `docs/config-reference.md:465`），但**恢复链没有闭合**：

- `webauthn.passkey_policy.passkey_recovery_allowed` 只是 "Advisory metadata echoed alongside the nudge... Enforces no recovery flow itself"（`docs/config-reference.md:468`）；
- `domains/authenticators/passkeypolicy/policy.go:33-42` 自述："this package intentionally implements NO recovery flow"；并明确承认现有恢复路径（recovery code 作为 MFA 因子）**无法回到主登录**——"closing that gap would mean accepting a recovery code as a PRIMARY authenticator, new attack surface"；
- 对 `AllowPasswordlessOnly` 的账户：丢失 passkey = **永久锁死**（无密码可重置、recovery code 是第二因子而非第一因子）。这是企业客户部署 passwordless 时的头号顾虑，直接决定该功能能否批量签约。

### 代码证据

- `docs/config-reference.md:465-468` — passwordless-only 语义与 `passkey_recovery_allowed` 的 advisory 定位；
- `domains/authenticators/passkeypolicy/policy.go:33-42, 108` — "implements NO recovery flow"、"the passwordless-only gap that reuse does NOT close"；
- `interfaces/sso/server_mfa.go` + `shared/core/recovery_code.go` — 现有 recovery-code 仅作为 MFA 完成因子；
- `interfaces/sso/server_login_auth.go` 附近 — `provider=webauthn` 主认证路径。

### 边界情况

- **设备丢失 + 密码为空**：唯一凭据丢失即账户丢失——恢复仪式必须存在且有上限（如"已验证邮箱 + 冷却期 + 管理员可介入"）；
- **恢复码作为主因子**：若放开"恢复码当主因子"，需严格限次、限时、限 IP/设备指纹，并全程 `mfa_failure`-风格审计；否则等于在无密码账户上开了个 8 字符口令后门；
- **passkey 跨生态同步**：iCloud/Google/第三方同步器不受服务器控制，"用户以为 passkey 在"的误判场景需要会话侧的设备指纹与信任分辅助兜底（`domains/authenticators/device` 已有基础）；
- **管理员强制 passwordless-only**：策略强制下用户失去恢复手段，管理面需 break-glass 重置流程（对照现有 break-glass 会话标注 `SessionKindAdminImpersonation` 的先例，`shared/core/spi.go`）；
- **与信任分/条件访问的交互**：恢复仪式应被条件访问策略视为高风险事件（新设备 + 恢复路径 = 触发 step-up 或冷却）。

### 建议落地形状（设计方向）

- 设计"无密码账户恢复仪式"：已验证邮箱/手机验证 + 冷却窗口 + 限次 + 新设备提示，成功后可注册新 passkey；全程审计事件归入既有审计词汇表；
- 恢复码升级：允许"恢复码 + 已验证联系方式"组合作为 passwordless-only 账户的一次性主认证（限 1 次/窗口），而不是放开为常态主因子；
- 策略护栏：`AllowPasswordlessOnly` 生效前要求账户已持有 ≥2 个凭据（passkey ×2 或 passkey + recovery），防止单点凭据账户被策略锁定；
- 管理面 break-glass 与审计：对照现有 break-glass 会话模式，提供管理员重置无密码账户的显式流程与审计。

**优先级：P1-P2（高价值、中紧迫）** — 直接决定 passwordless 产品的可用性与企业采纳率；恢复仪式属于安全敏感设计，建议先出设计评审再实现。规模：M（恢复仪式 + 策略护栏 + 管理流程 + 测试）。

---

## 方向五：安全关键配置的热重载语义不对称（运维一致性 + 观测漂移）

### 为什么需要

SIGHUP 热重载是已承诺能力，但覆盖范围是**非对称的**：同一安全域内的旋钮，有的可热载、有的必须重启，且运行态指标不随重载更新。对自动化运维（配置即代码、滚动发布）而言，"重载了但没生效"与"生效了但指标没变"都是静默漂移的温床：

- `security.rate_limit.*` 可热重载（整表重建 + 热替换，`docs/config-reference.md:408`），但 `security.client_registration_rate_limit` **明确不在 SIGHUP 重建范围内**（`docs/config-reference.md:56`："a change here needs a restart"）；
- feature gate 可热重载（`interfaces/sso/feature_gate_hotreload_test.go`），但 `sso_feature_gate_enabled` gauge **只在启动时播种一次**（`docs/observability.md`："A supported SIGHUP reload changes live route state but does not currently update this gauge"）；
- `platform/configaudit` 的 drift 检测以启动时 applied snapshot 为基线（`interfaces/sso/server_backup.go:23-29`），重载路径与重启路径的配置历史记录粒度不一，运维难以回答"当前生效的完整配置是什么"。

### 代码证据

- `docs/config-reference.md:56` — DCR 限流不参与热重载，需重启；
- `docs/observability.md` — `sso_feature_gate_enabled` 仅 boot 播种，重载不更新；
- `docs/config-reference.md:408` — `security.rate_limit.*` 的重建与热替换机制（对比项，证明"可热载"是既有标准）；
- `interfaces/sso/feature_gate_hotreload_test.go` — gate 热重载测试存在；
- `platform/configaudit/`（drift.go/handlers.go）— drift 检测与配置历史。

### 边界情况

- **部分应用**：一次配置变更中混合冷/热旋钮，重载后一半生效一半未生效，且无提示——需要"重载结果报告"（哪些生效、哪些需重启）；
- **指标与事实不符**：gate 已热切换但 gauge 停留在 boot 值，告警规则（`platform/metrics/alert_rules_test.go`）基于错误信号决策；
- **安全姿态评估**：安全审计/合规巡检读取的是 applied snapshot 而非运行时生效配置，冷热混杂下得出错误结论；
- **回滚**：热重载失败或部分生效时的回滚路径不清晰（与 configaudit 的 diff/history 如何衔接）。

### 建议落地形状（设计方向）

- 建立"可重载性清单"契约：每个安全相关配置键标注 `reloadable | restart-required`，SIGHUP 处理器返回结构化结果（成功/跳过/需重启项），并落一条 `config_reload` 审计事件；
- 热重载时同步更新 `sso_feature_gate_enabled` 等 boot 播种 gauge（或明确改名为 `sso_feature_gate_initial_*` 防止误用）；
- configaudit 的 diff 基线从"启动快照"扩展为"最近一次完整生效快照"，使 drift 检测覆盖重载路径；
- 将 `security.client_registration_rate_limit` 纳入重载管线（与 `security.rate_limit.*` 同构），消除"同域不同语义"。

**优先级：P2（中）** — 不直接造成数据/安全问题，但放大自动化运维中的静默漂移风险。规模：S-M（重载结果契约 + gauge 更新 + 文档化清单）。

---

## 附：交叉验证与不重复声明

- 会话分页/生命周期：`docs/requirements/architect-expansion-2026-08-01.md` 方向二关注"扫描原语规模化"，本文方向一聚焦 gRPC `ListSessions` 的 O(N) 物化、`TotalSize` 失真与过期行清理，证据与落点不同；
- Redis 客户端注册表缺口（租户索引 + 廉价指纹）：已由 `architect-global-scan-5-directions-2026-08-01.md` 覆盖，本文不重复；
- 租户配额持久化/跨副本一致性：已由 `architect-expansion-2026-08-01.md` 方向一覆盖，本文不重复；
- 本文方向二（邮件投递）与刚落地的 notification 生命周期不冲突：通知路由已有 3 次重试，缺口在**认证关键路径**（OTP/magic link/重置）的裸 Sender 上；
- 本文方向三、四、五在扫描到的历史文档中未见等价覆盖。
