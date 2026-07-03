# 架构级扩展方向分析报告（卷九：密码学身份转型·身份生命周期·事件生态·设备信任·关系授权）

> 基于 2026-07-01 对全代码库（1639 个 `.go` 文件）的全局扫描。
> 分析视角：资深架构师 / 产品经理。
> 定位：此前 8 轮分析（30+ 方向）覆盖了协议扩展、实时基建、Edge Cases、代码健康、架构债务、API 产品化、运营治理、供应链韧性。**本轮聚焦此前从未被触及的 5 个横切面：密码学身份转型、身份生命周期管理、事件驱动生态、设备信任模型、关系授权模型。**
> 原则：不写代码。每条方向锚定具体代码位置与 grep 核验。

---

## 总体判断

项目已从"功能完整"跨越到"生产就绪"。此前 30+ 方向覆盖了协议完备性、性能优化、运营治理、安全防御。但以下 5 个方向代表**从身份协议库到下一代身份平台的战略跨越**——它们解决的不是"还有什么协议没实现"，而是"身份平台在 2026 年应该长什么样"。

> 每一方向均经对抗式 grep 核验（默认"它可能已实现，逐行读码证伪"），并与此前 8 轮全部 30+ 方向交叉对比，确认**不重叠**。

---

## 方向一：Passkeys 作为主认证（Passwordless-First Login）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~600 行核心 + 300 行测试 + 无前端） |
| 价值 | **极高**（密码淘汰是行业确定性方向） |
| 类型 | 产品功能 + 认证模式转型 |
| 现有基础 | WebAuthn 基础设施极为完善 |
| 覆盖检查 | 此前 8 轮分析均未覆盖此方向 |

### 现状代码核验

**已实现：**
- `domains/authenticators/webauthn/webauthn.go` — 完整的 WebAuthn ceremony 支持（BeginLogin/FinishLogin、BeginRegistration/FinishRegistration、BeginConditionalLogin/FinishLoginConditional）
- `domains/authenticators/webauthn/conditional_login.go` — 条件中介登录（Passkey Autofill）
- `domains/authenticators/webauthn/attestation_policy.go` — 证明策略（Basic/None/Indirect/Direct）
- `domains/authenticators/webauthn/mds.go` — FIDO MDS（Metadata Service）集成
- `domains/authenticators/webauthn/registrar.go` — 注册器
- `domains/authenticators/webauthnsqlite/` — SQLite 持久化用户/会话存储
- `domains/authenticators/webauthnredis/` — Redis 会话存储（跨副本）
- `domains/authenticators/webauthnpostgres/` — Postgres 用户存储
- `domains/authenticators/webauthn/mfa_enrollment_adapter.go` — 将 WebAuthn 凭据暴露为 MFA 因素

**缺口验证：**

```bash
# 1. WebAuthn 包首行明确声明不实现 Authenticator 接口
$ head -5 domains/authenticators/webauthn/webauthn.go
# > "The package intentionally does NOT implement [sso.Authenticator] — the
# >  standard Authenticator interface is single-step..."
# 确认：四步 ceremony 无法适配单步 Authenticator 接口

# 2. 没有 passwordless 登录流集成到标准 /auth/login 管道
$ grep -rn "passwordless\|Passwordless\|password.*less" domains/authenticators/webauthn/ --include="*.go" | grep -v "_test.go"
# 输出为空 → 确认无 passwordless-first 概念

# 3. WebAuthn 仅在认证后作为 MFA 注册/验证暴露，不是主认证
$ grep -rn "WithWebAuthn\|webauthn.*Registrar\|WebAuthnRegistrar" interfaces/sso/options_passwd.go
# > WithWebAuthnRegistrar wires AUTHENTICATED self-service passkey registration
# > (POST /me/mfa/webauthn/{begin,finish})
# 确认：WebAuthn 只走 /me/mfa/*（认证后的 MFA 管理），不走 /auth/login

# 4. Authenticator 列表中没有 webauthn
$ grep "Method\|Name()" domains/authenticators/consts.go
# MethodPassword, MethodPhone, MethodEmail, MethodTempToken,
# MethodKeyPair, MethodAPIKey, MethodCertificate, MethodTOTP,
# MethodOIDCFed —— 无 MethodWebAuthn / MethodPasskey
```

### 为什么需要

1. **行业确定性方向**：Apple、Google、Microsoft 已全面推广 Passkeys 作为密码替代品。2025-2026 年，主流浏览器和操作系统已原生支持 Passkey Autofill（条件中介）。不做 Passkeys 做主认证 = 被市场视为"过时的密码认证平台"。
2. **WebAuthn 基础设施已完备**：项目拥有比大多数竞品更完整的 WebAuthn 底座（MDS、Attestation Policy、多后端持久化、条件中介、可发现凭据）。**唯一缺失的是"把上述能力包装成一个 Authenticator"**。
3. **竞品对标**：Auth0 已有 Passwordless（魔法链接 + 无密码 WebAuthn）；Okta 有 Okta FastPass；Corbado 和 Hanko 等初创公司以 Passkeys 为主打卖点。snaplink 的 WebAuthn 层比大多数竞品更深——补上最后 600 行即可从"具备 WebAuthn"跨越到"Passkeys 作为主认证"。
4. **产品叙事**：从"支持密码 + MFA 的 SSO"升级为"默认 Passkeys 优先，密码退居备选的下一代身份平台"。

### 范围

```go
// 不完整的设计草图，方便评估工作量
// 1. PasskeyAuthenticator（~200 行）—— 实现 sso.Authenticator 接口
//    将四步 ceremony 封装为两步抽象：
//    - Name() → "passkey"
//    - Authenticate(ctx, req) → 判断 req 中是否有 webauthn assertion →
//      调用 Helper.FinishLogin → AuthResult
//    - LoginURL(state) → 返回 /webauthn/login/begin?state=...（托管页）
//    - Callback(ctx, state) → 用于条件中介异步回调

// 2. 标准 /auth/login 集成点（~100 行）
//    在 /auth/login 的 provider 路由中新增 "passkey"：
//    - provider=passkey, 无 credential → 返回 BeginLogin challenge
//    - provider=passkey, 有 credential → FinishLogin → 发 token
//    - discovery 文档新增 passkey 声明

// 3. Passwordless 客户端策略（~60 行）
//    Client.PasswordlessOnly bool —— 此客户端禁止密码登录，
//    仅接受 passkey / magic link / OTP 等无密码方式

// 4. Self-service Passkey 管理集成（~100 行）
//    现有的 WithWebAuthnRegistrar 从 "已登录用户的 MFA 注册" 升级为
//    "用户可以在自助门户管理自己的 passkeys"（登录/列表/重命名/撤销）

// 5. 可发现凭据 + 条件中介统一（~80 行）
//    为 BeginLoginConditional 提供标准的 HTTP handler，作为
//    /.well-known/webauthn 或 /webauthn/assertion/begin 端点
```

### 关键设计约束

- **Oracle-leak 兼容**：未知 passkey 用户坍缩为与密码相同的 `invalid_grant`
- **跨副本**：Passkey 挑战会话必须跨副本共享（现有 `webauthnredis` 已解决）
- **Passkey 注册**：用户必须先通过某种方式验证身份（密码/MFA/魔法链接）后才能注册 Passkey——先验证人，后注册凭据
- **克隆检测**：利用现有的 `CloneWarning` + 签名计数器做凭据克隆检测，CAEP 广播撤销
- **无密码引导**：首次注册时引导用户创建 Passkey，然后才进入应用

### ROI

- **价值**：极高——这是从"密码认证平台"到"下一代无密码身份平台"的产品升级
- **工作量**：M（~600 行核心逻辑），WebAuthn 底座已完备，只需包装 + 接线
- **竞品差距**：Auth0/Okta 有 Passwordless 但作为独立附加功能；本项目可做到默认 Passkeys-first

---

## 方向二：身份全生命周期管理（Identity Lifecycle Management）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **L**（~1500 行 + 存储层 + 测试 + 策略引擎） |
| 价值 | **高**（企业采购必问项） |
| 类型 | 产品功能 + 合规治理 |
| 现有基础 | User CRUD + SCIM 端点 + 审计事件已就位 |
| 覆盖检查 | ROADMAP 方向②聚焦 B2B 连接/HRD/导入，未覆盖生命周期 |

### 现状代码核验

**已实现：**
- `shared/core/types.go:16` — `User` 结构体：`ID`、`ExternalID`、`Provider`、`Email`、`Name`、`Attributes`、`CreatedAt`、`UpdatedAt`
- `shared/core/types.go:31-47` — `IsActive()`：仅通过 SCIM 的 `Attributes["scim:active"] == "false"` 判断，无结构化状态
- `domains/tenant/tenant.go:42-46` — Tenant 有 `Status`（active/suspended），User 无
- `protocols/scim/` — SCIM 2.0 端点（含 Patch、Bulk、Filter）
- `interfaces/sso/options_passwd.go:344` — `WithJITMembership`：登录时自动预配组织成员
- `interfaces/sso/server_logout.go:337-358` — JIT 预配实现：登录时自动创建组织成员记录
- `platform/audit/auditspi/event_types.go:109` — `EventOrgMemberAutoProvisioned` 审计事件

**缺口验证：**

```bash
# 1. User 结构体无状态字段
$ grep -A 10 "type User struct" shared/core/types.go
# 只有 ID, ExternalID, Provider, Email, Name, Attributes, CreatedAt, UpdatedAt
# 没有 Status, SuspendedAt, DisabledReason, LastLoginAt, Dept, Title, Manager 等企业必填字段

# 2. 无批量 deprovisioning 机制
$ grep -rn "Deprovision\|deprovision\|BulkSuspend\|bulk.*suspend\|RevokeAllTokens\|revokeAll\|expireAll\|ExpireAll" --include="*.go" . | grep -v "_test.go" | grep -v "\.pb\."
# 仅 admin API 有逐条操作，无批量 / 自动 / 定时吊销

# 3. 无用户状态机
$ grep -rn "UserStatus\|userStatus\|StatusActive\|StatusSuspended\|StatusDisabled\|StatusArchived\|user_state\|UserState" --include="*.go" shared/core/ domains/ protocols/ 2>/dev/null | grep -v "_test.go" | grep -v "\.pb\."
# 输出为空 → 确认无结构化生命周期状态

# 4. 无定时清理/归档机制
$ grep -rn "UserArchive\|user.*archive\|InactiveUser\|inactive.*user\|UserCleanup\|user.*cleanup\|UserPurge\|user.*purge\|UserRetention\|user.*retention" --include="*.go" . 2>/dev/null | grep -v "_test.go"
# 输出为空 → 确认无生命周期定时任务
```

### 为什么需要

1. **企业采购的合规刚需**：每个企业身份采购问卷都包含："是否支持用户生命周期管理（入职→转岗→离职）？"、"是否有自动取消预配机制？"、"是否支持基于时间的账户过期？"
2. **JIT 仅覆盖入职**：现有的 JIT 预配（`WithJITMembership`）解决了"用户首次登录时自动创建组织成员"，但离职/转岗没有任何自动化——用户离开上游 IdP 后仍然可以登录（因为 SSO 侧的用户记录从未被标记为已离职）
3. **安全风险**：没有生命周期管理意味着：
   - 离职员工的 token 继续有效直到自然过期（最长可能 30 天）
   - 无法判断哪些用户是"幽灵账户"（已离职但系统里还活着）
   - SCIM 的 active=false 只被 `IsActive()` 读取，但没有级联动作（吊销 token、过期 session、广播 CAEP）
4. **审计合规**：GDPR/CCPA/SOC 2 要求有用户数据保留/删除策略，无生命周期状态机器就无法持续、自动地执行

### 范围

```
1. 用户状态模型（~200 行）
   type LifecycleStatus string
   const (
       StatusActive       LifecycleStatus = "active"       // 正常可用
       StatusSuspended    LifecycleStatus = "suspended"    // 管理暂停，不可登录
       StatusDisabled     LifecycleStatus = "disabled"     // 已离职/已停用
       StatusArchived     LifecycleStatus = "archived"     // 数据已归档，仅审计可查
   )
   User 增加 Status + StatusChangedAt + StatusReason 字段
   向后兼容：空 Status = 视为 active

2. 状态转换器（~300 行）
   每个状态转换触发级联动作：
   active → suspended: 撤销所有活跃 session + 标记 token 为已吊销
   suspended → disabled: 清除所有 refresh token family + 广播 CAEP TokenRevoked
   disabled → archived: 清除 PII（匿名化 email/name），保留审计引用
   archived → deleted: 物理删除（GDPR 擦除）

3. 自动 deprovisioning 引擎（~400 行）
   - 定时 job（可配置 cron）：扫描"上游 IdP 已删除但本地仍 active"的用户
   - 定时 job：扫描"超过 N 天未登录"的用户 → 自动 suspended
   - 定时 job：扫描"remaining TTL 结束"的 suspended 用户 → 自动 archived
   - 作业执行记录 + 审计事件

4. 上游 IdP 同步钩子（~300 行）
   - SCIM 的 active=false Patch → cascade to lifecycle
   - JIT 的"用户不在上游 group 中" → 触发 suspended
   - 企业连接（Enterprise Connections）的用户目录同步

5. 管理 API 扩展（~300 行）
   - GET /admin/users/:id/lifecycle — 查看完整生命周期时间线
   - POST /admin/users/:id/suspend — 管理暂停 + 原因
   - POST /admin/users/:id/restore — 恢复（撤销暂停）
   - POST /admin/users/:id/archive — 强制归档
   - GET /admin/users/lifecycle-audit — 生命周期变更审计日志
```

### 关键设计约束

- **级联必须是原子性或者最终一致的**：suspended 时吊销所有 token 如果部分失败，不应该留下不一致的状态。使用现有 cluster.Bus 广播吊销事件
- **免于时间窗口竞争**：生命周期状态变更与活跃登录请求不能竞态（用户在登录过程中被 suspend → 登录完后才收到 403，但 token 已签发 → 需验证 token 时的懒检查）
- **Audit 合规**：每个生命周期事件记录：actor、action、old_status、new_status、reason
- **Fail-open 默认**：归档进程失败不阻塞登录——降级为保留原状态 + 审计告警
- **SCIM 兼容**：现有 `UserAttrActive`（`"scim:active"`）映射到 `LifecycleStatus`

### ROI

- **价值**：高——企业采购决策中，生命周期管理是"有没有"级的区别，不是"做得好不好"
- **工作量**：L——但大部分是现有基础设施的组合（SCIM + audit + cluster.Bus + revoke）
- **ROADMAP 关系**：方向②（B2B 企业化）专注上游连接和导入，本方向专注下游生命周期治理——互补而非重叠

---

## 方向三：事件驱动生态——通用 Webhook / Egress 事件系统

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **L**（~1200 行 + 存储层 + 订阅管理 + 基础设施） |
| 价值 | **高**（平台级扩展点，企业集成刚需） |
| 类型 | 平台扩展 + 生态基建 |
| 现有基础 | 审计 Webhook Sink + CAEP 收发器已就位 |
| 覆盖检查 | 此前 8 轮分析均未覆盖此方向 |

### 现状代码核验

**已实现：**
- `platform/audit/auditsink/webhook_sink.go` — 审计事件 Webhook Sink（POST JSON 到配置 URL）
- `protocols/caep/transmitter.go` — CAEP/SSF 事件推送（仅限安全事件，推送给受影响 RP）
- `platform/cluster/bus.go` — 内部 Pub/Sub 总线（KindTokenRevoked、KindSigningKeyRotation、KindClientChange、KindAuthzPolicyChange）
- `platform/audit/async_sink.go` — 异步事件处理器
- `platform/audit/recorder_events.go` — 39 种审计事件类型

**缺口验证：**

```bash
# 1. 无通用 Webhook 系统——现有的 WebhookSink 是审计专用的，不是通用事件 egress
$ grep -rn "EventSubscription\|event.*subscription\|WebhookConfig\|webhook.*config\|WebhookEndpoint\|webhook.*endpoint\|Subscription|\
.Events\|events.*subscribe\|EventRule\|event.*rule" --include="*.go" . 2>/dev/null | grep -v "_test.go" | grep -v "\.pb\." | grep -v "event_typ" | grep -v "EventType\|event_type" | head -5
# 输出为 0 → 确认无通用事件订阅模型

# 2. 无法让下游系统订阅身份事件
$ grep -rn "user\.created\|user\.deleted\|session\.created\|token\.revoked\|client\.updated" --include="*.go" . 2>/dev/null | grep -v "_test.go" | head -5
# 输出为 0 → 这些事件存在于审计代码中，但没有作为外部可订阅的事件暴露

# 3. 无事件过滤/路由机制
$ grep -rn "EventFilter\|event.*filter\|EventRouter\|event.*route\|EventTransform\|event.*transf" --include="*.go" . 2>/dev/null | grep -v "_test.go"
# 输出为空 → 确认无事件路由

# 4. 无事件重试/死信队列
$ grep -rn "DeadLetter\|dead.*letter\|RetryQueue\|retry.*queue\|Backoff\|backoff\|EventRetention\|event.*retention" --include="*.go" platform/audit/auditsink/ 2>/dev/null | grep -v "_test.go"
# webhook_sink.go 有重试逻辑但无持久化队列和死信
```

### 为什么需要

1. **企业集成生态的关键入口**：每个企业都有 SIEM（Splunk/Datadog/Sentinel）、事件总线（Kafka/EventBridge）、自动化平台（Zapier/n8n/Tray）。没有通用事件系统，这些集成都需要定制开发。
2. **现有的 CAEP + audit webhook 太狭**：CAEP 只推安全事件（令牌吊销、登录），audit webhook 只面向审计。企业需要 `user.created` 去触发 HR 系统、`token.revoked` 去通知 API 网关、`client.updated` 去触发 CD 流水线。
3. **竞品对标**：
   - Auth0: Actions/PostLogin/PreUserRegistration — 事件驱动
   - Clerk: Webhooks（user.created, user.updated, session.created, ...）
   - WorkOS: Events API + Webhooks
   - Keycloak: Event Listener SPI（可扩展）
4. **复用现有基础设施**：39 种审计事件类型 + cluster.Bus（内部） → 只需要增加：
   - 外部事件订阅模型（租户级、事件类型级）
   - 事件序列化 + 签名（JWS 签名事件 payload，防伪造）
   - 投递管理（重试、退避、死信）
   - 管理 API（CRUD 事件订阅）

### 范围

```
1. 事件模型与 SPI（~200 行）
   type Event struct {
       ID        string            // 唯一事件 ID（用于幂等投递）
       Type      EventType         // "user.created", "token.revoked", ...
       Source    string            // "sso", "tenant:acme"
       Subject   string            // "user:u-abc123"
       Data      json.RawMessage   // 事件负载（bounded cardinality）
       Timestamp time.Time
   }
   type EventStore interface {
       Create(ctx, event) error
       ListBySubscription(ctx, subID, since) ([]Event, error)
   }

2. 事件订阅模型（~200 行）
   type Subscription struct {
       ID           string
       TenantID     string
       Name         string
       EventTypes   []EventType   // 空 = 所有事件
       Endpoint     string        // HTTPS URL 或内部 channel
       SigningKey   string        // HMAC/JWS key 用于签名事件 payload
       RetryPolicy  RetryConfig   // 退避策略
       DeadLetterURI string       // 可选死信队列
       Active       bool
       CreatedAt, UpdatedAt time.Time
   }
   type SubscriptionStore interface {
       Create/Get/List/Update/Delete
   }

3. 事件投递引擎（~400 行）
   - 事件路由器：内部 AuditRecorder → EventRouter → 匹配 Subscriptions
   - HTTP 投递器：POST JSON 到 HTTPS 端点（带 JWS 签名 + 重试 + 退避）
   - 持久化重试队列（SQLite/Postgres）：失败事件可回溯重试
   - 死信队列：超过重试次数的事件进入死信，可手动重放
   - 速率限制：per-subscription token bucket

4. 事件类型注册（~100 行）
   - 在现有 39 种审计事件基础上定义外部可订阅事件
   - 每个事件类型声明其 Schema（payload 结构）
   - 与现有审计事件的映射关系

5. 管理 API + 配置（~300 行）
   - POST /api/v1/events/subscriptions — 创建订阅
   - GET /api/v1/events/subscriptions — 列举订阅
   - POST /api/v1/events/subscriptions/:id/test — 发送测试事件
   - GET /api/v1/events/subscriptions/:id/deliveries — 投递历史
   - POST /api/v1/events/subscriptions/:id/dead-letter/replay — 死信重放
   - 配置：sso.WithEventRouter(store, sender)
```

### 关键设计约束

- **事件至少投递一次**：不保证精确一次（at-least-once），但幂等性由消费者通过 `event.id` 自行处理
- **签名必须**：每个事件 payload 用配置的密钥做 HMAC 或 JWS 签名，接收方验证签名确认来源
- **回压保护**：投递器必须保护内部事件循环（来自慢消费者的回压不应阻止 AuditRecorder 记录新事件）
- **租户隔离**：订阅只能在租户上下文中查看和管理——租户 A 不能订阅租户 B 的事件
- **数据边界**：事件 payload 不能包含凭据、secret、token 原文。引用（`user:u-abc123`）而非包含
- **可观测性**：每个投递尝试产生 `sso_event_delivery_attempts_total{status=ok|retry|dead}|subscription}` 指标

### ROI

- **价值**：高——把 SSO 从一个"门"变成"一个可编程的身份事件源"
- **工作量**：L——事件模型 + 订阅存储 + 投递引擎 + 管理 API。复用现有 audit 事件基础设施
- **竞品差距**：Auth0/Clerk/WorkOS 都把 Webhooks 作为基础功能。缺此能力则企业集成场景受限
- **与 CAEP 的关系**：CAEP 是安全标准（一种特定的事件类型），本方向是通用事件平台——CAEP 可作为系统内建的一个订阅

---

## 方向四：设备信誉与 Session 绑定（Device Trust & Session Binding）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~800 行 + 存储层 + 策略） |
| 价值 | **中-高**（安全差异化 + 风控基础） |
| 类型 | 安全功能 + 风控 |
| 现有基础 | DPoP + mTLS + session meta 已就位 |
| 覆盖检查 | 此前 8 轮分析均未覆盖（连续风险引擎关注服务端行为，本次关注客户端设备） |

### 现状代码核验

**已实现：**
- `shared/core/types_token.go:163-174` — 令牌的 `ConfirmationJKT`（DPoP `cnf.jkt`）和 `ConfirmationX5TS256`（mTLS `cnf.x5t#S256`）
- `shared/core/spi.go:147-163` — `SessionMeta` 结构体：IP、UserAgent、TenantID
- `protocols/oauth/oauthwire/bearer.go` — Bearer token 验证 + DPoP 绑定检查
- `interfaces/sso/options_security.go` — DPoP 配置（`WithDPoPNonceProvider`）
- `shared/core/types_token.go:12-15` — `DeviceSecret` 结构体（设备绑定的临时凭证）
- `infrastructure/redis/session.go` — Redis 会话存储（含 user_agent 和 ip）

**缺口验证：**

```bash
# 1. 无设备注册概念
$ grep -rn "DeviceRegistration\|device.*register\|DeviceFingerprint\|device.*fingerprint\|DeviceID\|device_id\|DeviceStore\|device.*store" --include="*.go" shared/core/ domains/ protocols/ 2>/dev/null | grep -v "_test.go" | grep -v "\.pb\." | head -5
# 输出为空（除了 device_code 流中的设备概念）→ 确认无设备注册模型

# 2. 无设备信誉/评分
$ grep -rn "DeviceTrust\|device.*trust\|DeviceScore\|device.*score\|DeviceReputation\|device.*reputation\|DeviceRisk\|device.*risk" --include="*.go" . 2>/dev/null | grep -v "_test.go"
# 输出为空 → 确认无设备信誉模型

# 3. 无"信任此设备"工作流
$ grep -rn "RememberMe\|remember.*me\|TrustDevice\|trust.*device\|TrustBrowser\|trust.*browser\|known.*device\|KnownDevice" --include="*.go" . 2>/dev/null | grep -v "_test.go"
# 输出为空 → 确认无"信任此设备"功能

# 4. Session 不绑定到具体设备
$ grep -rn "DeviceID\|device_id\|DeviceType\|device_type\|DeviceOS\|device_os\|DeviceModel\|device_model" --include="*.go" shared/core/spi.go 2>/dev/null
# outputs: 0 → SessionMeta 不含设备标识
```

### 为什么需要

1. **安全基石**：DPoP 将 access token 绑定到公钥，但 session 本身不绑定到设备——如果 session cookie 被盗，攻击者可以用它发起新授权，DPoP 只在 /token 路径上有保护，对 /auth/login 的 session 无作用
2. **风控数据源**：设备指纹（屏幕分辨率、已安装字体、WebGL 渲染器、时区、语言）是风险引擎的黄金信号。没有设备信息，风险评估只有 IP + 用户代理——粒度太粗
3. **用户体验权衡**："信任此设备 30 天"（受信设备免 MFA）是登录体验的常见优化，没有设备注册就无法实现
4. **合规记录**：PCI DSS / SOC 2 要求"记录每次访问的设备标识"。当前 session 只记 `user_agent`+`ip`，无法确认"两次登录来自同一个设备还是不同设备"
5. **竞品对标**：Okta 有 Device Trust（Jamf/Intune 集成）和 Known Devices；Auth0 有 Device Fingerprinting（通过 Signals）；Azure AD 有 Device Registration + Conditional Access

### 范围

```
1. 设备注册 SPI（~200 行）
   type Device struct {
       ID          string
       UserID      string
       Name        string            // 人类可读名（"Alice's iPhone 15"）
       Platform    string            // "iOS", "Android", "macOS", "Windows", "Web"
       Fingerprint DeviceFingerprint // 设备指纹（bounded cardinality）
       FirstSeenAt time.Time
       LastSeenAt  time.Time
       TrustLevel  TrustLevel        // untrusted | trusted | admin_approved
       CreatedAt, UpdatedAt time.Time
   }
   type DeviceStore interface {
       Create/Get/ListByUser/Update/Delete
   }

2. 设备指纹收集器（~200 行）
   - 可选：浏览器端通过 JS 收集设备指纹（canvas fingerprint, WebGL, audio, fonts）
   - 必选：从 TLS 握手 + HTTP 头 + DPoP 公钥推断的 Passive 指纹
   - 指纹归一化 + hash + 去重（避免精确原始数据泄露）
   - Privacy 设计：指纹 hash 不可逆，不存储原始指纹数据

3. "信任此设备"工作流（~200 行）
   - /auth/login 响应中可包含 trust_device 提示
   - 用户确认后在设备注册表中创建 `trusted` 条目 + 设置持久 cookie
   - 受信设备的后续登录可跳过 MFA（配置策略）
   - 设备撤销：用户可在"已登录设备"列表中撤销某设备
   - 可疑行为：设备在新地理位置首次出现 → 降级信任 → 要求 step-up MFA

4. Session 到设备绑定（~100 行）
   - SessionMeta 增加 DeviceID 字段
   - /auth/login 时自动绑定（如果有受信设备 cookie）
   - session refresh 时验证设备匹配
   - 跨设备 session 迁移？不允许——设备绑定的 session 只能在该设备上 refresh

5. 设备管理 API（~100 行）
   - GET /me/devices — 当前用户的所有已注册设备
   - POST /me/devices/:id/trust — 手动信任
   - POST /me/devices/:id/revoke — 撤销设备
   - GET /admin/users/:id/devices — 管理端查看用户设备
   - POST /admin/users/:id/devices/:id/revoke — 管理端远程注销设备
```

### 关键设计约束

- **隐私优先**：设备指纹不可反解为具体设备型号/user agent/IP，只用 hash 匹配；用户可在自助门户中清除设备记录（GDPR 擦除）
- **非唯一标识**：不支持跨用户/跨网站追踪；设备注册绑定到 (user_id, tenant_id)
- **Fallback 设计**：不支持 JS 指纹收集的客户端（curl、CLI）降级为 Passive 指纹（TLS + HTTP 头 + DPoP key）——缺失某些信号但不停顿
- **信任衰减**：设备信任应在长时间未使用后自然衰减（降回 untrusted），需要用户重新验证
- **不出现在令牌中**：设备指纹/ID 不应出现在 JWT claims 中——不增加 token 大小，不泄露设备信息给 RP

### ROI

- **价值**：中-高——高安全性组织（金融、医疗、政府）将设备绑定作为关键采购要求
- **工作量**：M——设备注册 + 指纹 + 信任工作流 + 管理 API
- **与方向⑤（连续风险引擎）的协同**：设备信誉是风险引擎的输入信号之一——"来自受信设备的登录"降低风险分数
- **与已有 DPoP/mTLS 的关系**：补充而非替代——DPoP 保护单次 token 请求，设备信任保护整个 session 生命周期

---

## 方向五：关系授权模型——从 RBAC 到 ReBAC（Relationship-Based Access Control）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **XL**（~2500 行 + 存储层 + SPI + gRPC + SDK） |
| 价值 | **高**（架构级差异化，细粒度授权是行业方向） |
| 类型 | 架构级扩展 + 授权模型转型 |
| 现有基础 | RBAC + Policy Bundle + Wildcard Matcher 已就位 |
| 覆盖检查 | 此前 8 轮分析均未覆盖（权限方向仅聚焦策略导出和审计，未触及授权模型本身） |

### 现状代码核验

**已实现：**
- `domains/permissions/` — 完整的 RBAC 模块：角色、菜单、权限、资源、通配符匹配、策略束导出
- `domains/permissions/matcher.go` — 权限通配符匹配器（`user:*` 包含 `user:read`）
- `domains/permissions/policy_bundle.go` — 策略束导出（供 sidecar 拉取）
- `domains/permissions/sqlite/` — 持久化存储（角色、分配、菜单）
- `domains/permissions/permissionstest/conformance.go` — 合规测试套件
- `shared/core/spi.go` — `PermissionsProvider` 接口（`Check`、`ListPermissions`、`ListRoles`、`GetMenus`）

**缺口验证：**

```bash
# 1. 无 ReBAC 概念——授权基于"subject 有 role"而非"subject 与 resource 的关系"
$ grep -rn "Relationship\|relationship\|Tuple\|tuple\|Object\|object.*permission\|Relation\|relation.*perm\|Zanzibar\|zanzibar\|ReBAC\|rebac\|SpiceDB\|spicedb\|AuthZed\|authzed" --include="*.go" domains/permissions/ 2>/dev/null | grep -v "_test.go"
# 输出为 0 → 确认无关系授权概念

# 2. 无资源层次结构
$ grep -rn "ResourceTree\|resource.*tree\|ResourceHierarchy\|resource.*hierarchy\|ParentResource\|parent.*resource\|ChildResource\|child.*resource\|ResourceGraph\|resource.*graph" --include="*.go" domains/permissions/ 2>/dev/null | grep -v "_test.go"
# 输出为 0 → 确认资源扁平，无层次

# 3. 权限检查是布尔值（有/无），非"计算路径"
$ grep -rn "Check(context.Context\|Check(ctx" --include="*.go" domains/permissions/provider.go
# > Check(ctx context.Context, subjectID, permission string) (bool, error)
# 确认：权限检查返回 bool，而非"允许路径"或"推导链"

# 4. 无外部授权引擎集成
$ grep -rn "OPA\|Rego\|regoreg\|open.policy\|policy.*engine\|ExternalAuthorizer\|external.*auth" --include="*.go" domains/permissions/ 2>/dev/null | grep -v "_test.go"
# 仅 policy_bundle.go 的注释提到 "sidecar (OPA/Cedar/custom) pulls to enforce"
# 但无实际 OPA 集成代码 → 确认无外部策略引擎集成
```

### 为什么需要

1. **从 RBAC 到 ReBAC 的行业演进**：Google（Zanzibar → Spanner-based 关系授权）、Auth0（FGA → Fine-Grained Authorization）、Okta（收购 Spherical → 关系授权）、AWS（Cedar → 策略引擎）。细粒度、关系驱动的授权是身份行业的确定方向。
2. **企业客户场景驱动**：
   - 文档协作：用户 A 可以读文档 D，因为 A 是 B 团队的成员，B 团队对项目 P 有贡献者角色，文档 D 属于项目 P
   - 组织层次：CEO 可以看所有团队的仪表盘，经理只看自己团队的
   - 资源树继承：仓库 /org/repo 的写权限自动继承到其下的所有目录和文件
3. **现有 RBAC 的局限性**：当前的 `Check(subject, permission)` 模式无法表达"用户 X 有权限 Y 因为用户 X 在组 G 中，组 G 有角色 R，角色 R 对资源 T 有权限 Y"。所有推理必须在调用方完成。
4. **差异化价值**：作为身份平台，不仅提供"谁可以登录"，还提供"谁能做什么"——这是从 IAM（身份和访问管理）通向 CIEM（云基础设施授权管理）的关键一步。

### 范围

> ReBAC 是一个大型架构扩展。以下范围是本方向的起点（MVP），而非完整实现。

```
1. 关系模型定义（~200 行）
   // Userset/Zanzibar 风格关系模型
   type RelationTuple struct {
       Object   ObjectRef    // 资源对象: {type: "document", id: "doc-123"}
       Relation string       // "owner", "editor", "viewer", "parent"
       Subject  SubjectRef   // 主体: {type: "user", id: "u-abc"} 或 {type: "team", id: "t-xyz", relation: "member"}
   }

   // 类型安全的关系定义（Schema）
   type RelationSchema struct {
       Type      string     // "document"
       Relations []Relation // "owner", "editor", "viewer", "parent"
   }

2. 关系存储 SPI（~200 行）
   type RelationTupleStore interface {
       Create(ctx, tuple) error
       Delete(ctx, tuple) error
       Read(ctx, object, relation) ([]SubjectRef, error)
       Check(ctx, object, relation, subject) (bool, error)
       Expand(ctx, object, relation) (*SubjectSet, error)
       // 批量操作用于导入
   }

3. ReBAC 检查引擎（~400 行）
   - 递归检查：subject 对 object 有 relation R 吗？
   - 关系派生：parent → viewer 自动继承
   - 集合运算：union（任意）、intersection（全部）、exclusion（非的）
   - 计算缓存：基于 TTL 的检查结果缓存
   - 检查深度控制：最大递归深度（默认 10），防御图爆炸

4. 与现有 RBAC 集成（~300 行）
   - 现有的 PermissionsProvider.Check 增加 ReBAC 回退
   - Role 可以定义为一组关系权限的快捷方式
   - Admin API 支持关系元组的 CRUD
   - 审计：每次 ReBAC 检查的记录（含检查链）

5. Policy Bundle 扩展（~200 行）
   - 现有的 PolicyBundle 增加 ReBAC 关系导出
   - sidecar（OPA/SpiceDB）可以拉取关系数据做本地授权
```

### 关键设计约束

- **ReBAC 不取代 RBAC**：两者共存——RBAC 适合"谁可以访问这个菜单/API"，ReBAC 适合"谁可以对这篇文档做什么"
- **计算代价控制**：递归检查的深度和广度必须限制；使用关系缓存 + TTL；最坏情况的检查时间应有上限
- **事件一致性**：关系元组变更通过 cluster.Bus 广播，缓存失效
- **导入兼容性**：从现有 RBAC 权限可以生成初始关系元组（"用户 u-abc 对 resource:* 有 admin 权限" → 关系元组）
- **API 兼容**：现有 `Check(subject, permission) bool` 保持不变——内部增加 ReBAC 回退

### ROI

- **价值**：高——细粒度授权是身份平台从"能认证"到"能授权"的战略升级
- **工作量**：XL——但 MVP（关系存储 + 检查引擎 + RBAC 桥接）可约束在 ~1200 行
- **竞品差距**：Auth0 FGA、Okta（Spherical）、Google Zanzibar 都是独立产品/收费功能——内建 ReBAC 是显著的差异化卖点
- **Pipeline 位置**：当 Hosted Login（ROADMAP 方向①）和 B2B 企业化（方向②）落地后，授权模型是客户自然的下一个问题

---

## 优先级摘要

| # | 方向 | 工作量 | 价值 | 类型 | 适合时机 | 核心收益 |
|---|------|--------|------|------|----------|----------|
| 1 | **Passkeys 作为主认证** | **M** | **极高** | 产品 | 立刻 | 从密码平台转型为下一代无密码平台 |
| 2 | **身份全生命周期管理** | **L** | **高** | 产品+合规 | ROADMAP ②之后 | 企业合规刚需，防止幽灵账户 |
| 3 | **事件驱动 Webhook 系统** | **L** | **高** | 平台基建 | 方向②后 | 让 SSO 成为可编程身份事件源 |
| 4 | **设备信誉与 Session 绑定** | **M** | **中-高** | 安全 | 方向①后 | 安全差异化，风控信号源 |
| 5 | **关系授权（ReBAC）** | **XL** | **高** | 架构 | FAPI 深度采用时 | 从 IAM 到 CIEM 的战略升级 |

### 阶段建议

**Phase 1（本月）**：方向①——Passkeys 作为主认证。WebAuthn 基础设施已完备，缺的只是包装成一个 Authenticator + 集成到标准登录流。工作量适度（~600 行），产品叙事价值极高："无密码 SSO平台"。

**Phase 2（下月）**：方向②——身份生命周期。作为 B2B 企业化（ROADMAP 方向②）的自然延续。上游 IdP 连接做完了 → 用户从哪里来解决了；接下来是用户怎么走。

**Phase 2 并行**：方向③——事件 Webhook 系统。方向①和②都会产生新的事件类型（passkey_registered、user_suspended），通用的事件系统让这些事件可以被下游消费。

**Phase 3（季度）**：方向④——设备信誉。设备注册 + 指纹收集 + 信任工作流。与方向①新认证方式（Passkeys）天然互补——Passkeys 识别"谁"，设备信任识别"从哪来"。

**Phase 4（待定）**：方向⑤——ReBAC。架构级扩展，当前 RBAC 满足大多数场景，ReBAC 是"当客户需要细粒度授权时再开启"的开关。

### 与既有路线图的关系

| 本卷方向 | 与 ROADMAP v5.0 的关系 | 与此前分析的关系 |
|----------|----------------------|-----------------|
| ① Passkeys 主认证 | 互补——方向①（Hosted Login）聚焦 UI，本方向聚焦新认证方式 | 未覆盖 |
| ② 身份生命周期 | 互补——方向②（B2B 企业化）聚焦上游连接，本方向聚焦下游治理 | 未覆盖 |
| ③ 事件 Webhook | 互补——方向④（Extensibility）聚焦 SDK/CLI/MCP，本方向聚焦事件驱动 | 未覆盖 |
| ④ 设备信誉 | 互补——方向⑤（Security Baseline）聚焦 CI/SAST/合规，本方向聚焦运行时设备风险 | 未覆盖 |
| ⑤ ReBAC | 互补——方向②（B2B 企业化）聚焦租户和连接，本方向聚焦授权模型升级 | 未覆盖 |

---

## 附录：核验方法

每个方向的确立经历：
1. **假设生成**：基于架构/产品经验，列出可能缺失的能力
2. **关键词 grep**：每个方向使用 10-20 个关键词在全树 `.go` 文件中搜索
3. **排除干扰**：排除 `*_test.go`、`*.pb.go`、`vendor/`、`.git/`
4. **代码交叉验证**：对命中的代码逐行读码，确认是"做了"还是"只是注释提到"
5. **文档交叉验证**：对比 ROADMAP v5.0 + 此前 8 轮共 30+ 方向的分析文档，确认无重叠
6. **未命中的方向如实标注**：如果 grep 有命中（哪怕只是注释），如实标注"部分已实现"

### 典型核验过程（以方向①为例）

```bash
# Step 1: 确认 WebAuthn 不实现 Authenticator 接口
$ head -5 domains/authenticators/webauthn/webauthn.go
# > "The package intentionally does NOT implement [sso.Authenticator]"
# → 确认真缺口

# Step 2: 确认认证器列表无 WebAuthn
$ grep "Method\|Name()" domains/authenticators/consts.go
# → password, phone, email, temp_token, keypair, apikey,
#   certificate, totp, oidc_federation — 无 webauthn

# Step 3: 确认文档无覆盖
$ grep -l "passkey\|passwordless\|webauthn.*primary\|WebAuthn.*Auth" docs/*.md
# → 仅 webauthn 技术文档，无"作为主认证"的产品方向讨论

# Step 4: 确认此前 8 轮分析均未覆盖此方向
$ for f in docs/expansion-*.md docs/expansion-analysis-*.md docs/edgecases-*.md \
           docs/completeness-*.md docs/ops-api-*.md docs/runtime-*.md; do
  echo "=== $f ==="
  grep -c "passkey\|Passwordless\|passwordless" "$f" 2>/dev/null
done
# → 全部为 0 → 确认此前分析未覆盖
```

（方向②~⑤的核验过程类似，可参考各节 "缺口验证" 中的 grep 命令）
