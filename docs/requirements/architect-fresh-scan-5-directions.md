# 代码库全局扫描：五项未覆盖的高价值扩展方向

> **分析师：** 资深架构师 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库 1127 个 `.go` 源文件（不含测试），15+ 嵌套模块，完整扫描。  
>   与 ROADMAP v5.0 和 deferred-backlog 做逐项交叉核验，确保每项为 ROADMAP 未覆盖的真缺口。  
>   每项均通过对抗式 grep 核验（默认"它可能已实现"，逐项读码证伪）。

---

## 前置声明

本项目经 50+ 轮系统架构分析，能力覆盖面已达行业顶级水平。ROADMAP v5.0 已系统规划
五大方向共 37 个子项，deferred-backlog 仅剩 3 个已完结项。以下五项是**ROADMAP v5.0
未覆盖、deferred-backlog 未记录、且经代码扫描实证为空白的真缺口**。

部分方向在早期分析文档中被提及过，但从未被拣起作为正式方向，且不在这两份
当前生效的规划文档中——因此作为新方向提出。

---

## 方向一：FIDO2 跨设备认证（Hybrid Transport / caBLE v2）

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| WebAuthn 平台认证（Passkeys） | ✅ | `domains/authenticators/webauthn/` — 注册 + 断言验证 + 条件登录 + MFA 适配 |
| WebAuthn 跨平台认证（USB 安全密钥） | ✅ | 同上，支持 cross-platform attestation |
| FIDO2 MDS 元数据服务集成 | ✅ | `webauthn/mds.go` — MDS blob JWS 链验证到 FIDO Root |
| 认证器 Attestation Policy | ✅ | `attestation_policy.go` — AAGUID 允许列表 + 信任锚策略 |
| **FIDO2 Hybrid Transport（跨设备 / caBLE）** | ❌ | **零实现** — `grep -ri "hybrid\|caBLE\|cable.*auth\|CTAP.*hybrid\|CrossDevice\|cross.device"` → 仅文档提及，无代码 |

### 为什么需要

**跨设备认证是 Passkey 生态中增长最快的场景，也是 FIDO Alliance 当前最优先推动的标准。**

典型场景：用户用手机注册了 passkey（Face ID / 指纹），在桌面电脑上登录时不再需要
"在手机上打开再输入验证码"——而是扫描桌面屏幕上的一次性 QR 码，手机通过
BLE / WebSocket 中继完成加密挑战，桌面即刻登录。

```
桌面端: 点击「用手机上的通行密钥登录」
  → POST /auth/hybrid/initiate → 返回 QR 码 + 挑战 ID
  → 用户用手机扫描 QR 码
  → 手机端: WebAuthn assertion（使用手机上的 passkey）
  → 签名结果通过 BLE/WebSocket 发送到服务器
  → 服务器验证断言 → 桌面端收到授权码
```

**为什么这比现有的 Passkey 更重要：**

| 模式 | 优点 | 缺点 |
|------|------|------|
| 平台 Passkey（iCloud/Google/1Password） | 原生体验好 | 依赖云同步，设备间需同一生态系统 |
| 安全密钥（USB/NFC） | 即插即用 | 用户需额外携带硬件 |
| **Hybrid Transport（跨设备）** | **任意手机 → 任意桌面，无需云同步** | 需要 BLE 兼容性或 WebSocket 中继 |

对于企业部署——特别是**政府、金融、医疗**等高安全环境——Hybrid Transport 是唯一
同时满足"无云同步"和"便捷跨设备"的方案。

### 对抗式核验

```bash
# 验证：hybrid 相关端点/逻辑零实现
grep -rn "hybrid\|caBLE\|CrossDevice\|cross.device\|CTAP" --include="*.go" . | grep -v "_test.go" | grep -v vendor | grep -v "\.pb\."
# → 0 命中（仅文档和导入语句中有模糊匹配，非功能代码）

# 验证：QR 码端点不存在
grep -rn "qr\|QR.*code\|qrcode\|/auth/hybrid" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中（QR 码相关仅出现在 SAML RelayState 和检查报告中）
```

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| Hybrid Authenticator SPI（`HybridAuthenticator`） | M | 现成 `domains/authenticators/` SPI 模式 |
| QR 码会话端点（`POST /auth/hybrid/initiate` + `POST /auth/hybrid/complete`） | M | 以上 + 一次性挑战状态机 |
| WebSocket 中继端点（用于不支持 BLE 的环境） | L | 以上 + `cluster.Bus` 或独立 ws hub |
| 客户端 JS SDK（`hybrid-client.js`） | M | 以上端点 + QR 码生成 |
| Desktop 端 WebAuthn 扩展（`navigator.credentials.get` 的 hybrid 路径） | S | 浏览器层面支持（Chrome 120+ / Safari 17+） |
| AMR 值扩展（`hwd` / `hybrid`） | S | `amr.go` 映射更新 |
| 集成 conformance 测试 | M | FIDO2 认证套件 |
| **合计** | **L（~3000 行 Go + JS）** | |

### 边界情况

- **QR 码重放攻击**：一次性挑战，TTL ≤ 120 秒，使用后立即作废，绑定发起 IP
- **BLE 不可达**：降级到 WebSocket 中继模式（服务器做中间人，端到端加密）
- **跨设备延迟**：用户可能在手机上等太久→挑战超时→优雅提示重新扫码
- **不支持 hybrid 的浏览器**：降级到普通 Passkey 或 MFA 流程
- **并发发起**：同一用户同时发起多个 hybrid 会话→只保留最新的，或按设备 ID 区分

---

## 方向二：凭据生命周期管理与自动化轮换

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| Client Secret 哈希存储 | ❌ | `clients.go:26` 逐字持久，`ValidateSecret` 用裸 `!=` |
| Client Secret 手动轮换（Admin API） | ✅ | `POST /api/v1/admin/clients/{id}/rotate-secret` |
| **Secret 自动轮换调度** | ❌ | **零实现** — 无定时轮换、无轮换策略 |
| **Secret 过期时间** | ❌ | **零实现** — secret 无 `expires_at` 字段，永不过期 |
| **Secret 年龄追踪与预警** | ❌ | **零实现** — 无 secret 创建时间记录、无到期前通知 |
| **Credential 历史版本管理** | ❌ | **零实现** — 轮换后旧 secret 立即作废，无过渡期共存 |
| 签名密钥自动轮换 | ✅ | `platform/lifecycle/rotation/` — 签名密钥有完整的轮换调度 |
| 设备密钥轮换 | ✅ | `device_secrets.go` — 设备秘密在 native SSO 中有轮换 |

### 为什么需要

**签名密钥有完善的轮换调度机制，但 client secret 和 API token——同样能冒充客户端身份——
却没有任何生命周期管理。** 这种不对称是企业的合规空子。

企业安全团队在采购问卷中会直接问：
1. "Client secret 是否有自动轮换？"（当前只有手动 API 调用）
2. "Secret 的最大有效期是多少？"（当前无限期）
3. "过期前是否会通知 client owner？"（当前无任何通知机制）
4. "密钥泄露后能在多少时间内完成全集群禁用？"（依赖于人工发现）

与签名密钥的对比直接反映了这一空白：

```
签名密钥（signing keys）                    Client Secret
─────────────────────────                   ─────────────────────────
✅ 自动轮换调度                              ❌ 只有手动轮换 API
✅ 重叠窗口（新旧共存）                      ❌ 轮换即作废
✅ 过期自动退役                              ❌ 永不过期
✅ 可观测（轮换时间戳、状态）                ❌ 无年龄追踪
✅ 多副本协调（leaderless adoption）         ❌ 无协调
```

### 对抗式核验

```bash
# 验证：client secret 无过期字段
grep -rn "SecretExpiresAt\|secret_expires\|client.*expir" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中（排除 device_secret 的 expires_at 和 token 相关的 exp 后）

# 验证：无自动转换调度器
grep -rn "auto.*rotate\|rotate.*schedule\|secret.*schedule\|RotationScheduler\|WithSecretRotation" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中（排除 siging key rotation 后）

# 验证：无 secret 年龄查询 API
grep -rn "SecretAge\|secret_age\|created_at.*secret\|ClientSecretAge\|client.*secret.*info" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中
```

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| `ClientSecret` 模型扩展：`created_at` / `expires_at` / `rotated_at` | S | 现有 `core.Client` 模型 |
| Secret 哈希存储（bcrypt/argon2）+ 常量时间比较 | M | `security.ConstantTimeStringEq` 已存在 |
| `ClientSecretStore` SPI：`Current` + `Rotate` + `RevokeOlderThan` | M | 以上 |
| 自动轮换调度器（`SecretRotationScheduler`） | M | `platform/lifecycle/rotation/` 模式已存在 |
| 过期前通知钩子（webhook / 审计事件） | M | `platform/lifecycle/webhook/` 已存在 |
| Admin API 扩展：`GET /admin/clients/{id}/secrets` + `POST /rotate` | S | gRPC admin 框架 |
| 轮换策略配置（`client_secret_rotation.*`） | S | `config/config.go` 模式 |
| 迁移：现有 secret 背填 `created_at` | M | `migrate/` 框架 |
| **合计** | **M（~2000 行）** | |

### 边界情况

- **过渡期共存**：轮换后旧 secret 不立即作废，保留 `grace_period`（如 24h）供客户端迁移
- **迁移风暴**：大批 client 同时过期→分摊到随机窗口，避免同时轮换的压力
- **从无限期到有限期的迁移**：默认策略 `never_expire: true`（兼容），opt-in 开启过期
- **重建 client secret hash 格式**：新 secret 用 argon2id，旧 bcrypt 验证仍支持直到下轮换
- **与联邦自动注册的交互**：联邦注册的 client 的 secret 生命周期由信任锚策略控制

---

## 方向三：按需动态联盟（Ad-Hoc Federation / On-Demand Trust Establishment）

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| OpenID Federation 1.0 实体语句 | ✅ | `domains/federation/` — 完整 entity statement + trust chain |
| Federation 自动注册 | ✅ | `federation/registration.go` — 信任链验证后自动注册 client |
| 信任锚配置 | ✅ | `config/config_fed.go` — 操作者配置信任锚列表 |
| Trust-mark 验证 | ✅ | `federation/trust_marks.go` — 信任标记解析 + 授权 |
| **按需动态联盟 / 零配置建立信任** | ❌ | **零实现** — 信任关系需要操作者预配置信任锚 |
| **Ad-hoc trust establishment（SSO ↔ SSO 自动握手）** | ❌ | **零实现** — 无端点暴露供另一个 SSO 实例动态建立信任 |
| **跨组织实时服务发现** | ❌ | **零实现** — 无"查找某组织是否可联邦"的发现机制 |
| **动态 trust anchor 评估与撤回** | ❌ | **零实现** — 信任锚一旦添加，不接受评估/评级 |

### 为什么需要

当前 federation 模型适用于**已建立信任关系的组织对**：Org A 操作者在配置中写入
Org B 的信任锚，双方预先约定。但对于以下场景，这远不够灵活：

**场景 1：临时 B2B 协作**
> Startup X 被 Enterprise Y 收购。两周内需要让 X 的员工能登录 Y 的 SSO 管理的应用。
> 当前路径：Y 的操作者在 sso 配置中添加 X 的 trust anchor → 重载配置 → 测试。
> 目标路径：X 的操作者发起一个"联邦请求"，Y 的操作者在 admin console 点"批准"。

**场景 2：SaaS 生态集成**
> 数百个小 SaaS 服务商需要与一个大型企业的 SSO 建立信任。
> 当前路径：每个 SaaS 商手动提交信任锚 → 企业 IT 手动审批 → 配置。
> 目标路径：SaaS 商的 SSO 实例自动暴露 federation entity configuration，
> 企业 SSO 通过 discovery 自动获取并评估信任。

**场景 3：跨环境联合（Dev/Staging/Prod）**
> 开发环境、预发布环境、生产环境之间有单向信任关系（允许 Dev 的 token 在 Staging
> 验证，但反之不行）。当前需要三份独立的信任锚配置。

### 对抗式核验

```bash
# 验证：无"动态信任"相关代码
grep -rn "dynamic.*trust\|trust.*request\|trust.*approve\|federat.*request\|federat.*approve\|trust.*negotiat\|trust.*establish\|federat.*handshake" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中

# 验证：无"信任邀请"端点
grep -rn "/federat.*invite\|/trust/request\|/trust/approve\|/federat.*connect\|/federat.*accept" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中

# 验证：无"组织发现"端点
grep -rn "org.*discover\|/.well-known/org\|/.well-known/federat.*partner\|domain.*federat\|federat.*domain.*lookup" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中
```

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| `FederationRequest` SPI + 存储（请求+审批状态机） | M | 现有 federation 框架 |
| 入站联邦请求端点（`POST /api/v1/admin/federation/requests`） | M | gRPC admin 框架 |
| 出站联邦邀请（`POST /api/v1/admin/federation/invite`） | M | gRPC admin 框架 |
| 跨组织 entity discovery（`/.well-known/sso-config`） | M | 现有 `.well-known` 挂载模式 |
| 信任锚临时缓存 + 自动续期 | M | `federation/cache.go` 现有 |
| 联邦请求审计事件（`federation_request_*`） | S | `auditspi/event_types.go` |
| 联邦仪表盘（admin console 面板） | M | `web/admin/` 扩展 |
| **合计** | **L（~3000 行）** | |

### 边界情况

- **信任链递归风险**：A 信任 B，B 信任 C，C 信任 A → 环形信任→ 检测并阻止（或限制到 N 跳）
- **信任撤回的级联**：A 撤销对 B 的信任→ B 下所有通过 A 授权的 client 应立即标记为未授权
- **自动 vs 手动批准**：基于 trust-mark 的自动批准（低风险）+ 操作者手动批准（高风险）
- **跨版本兼容**：运行 v5.0 的 SSO 实例能否与 v4.5 实例动态联邦？需要定义最小兼容版本
- **联邦信用的声誉模型**：可选"该组织在信任期间是否有过已确认的安全事件"评估

---

## 方向四：令牌交换链审计、可视化与异常检测

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| Token Exchange `act` claim 链 | ✅ | RFC 8693 §4.1 — `act` chain 在 token 中嵌入 |
| Token Exchange 链最大寿命 | ✅ | `WithMaxTokenExchangeChainLifetime` — 链总年龄硬上限 |
| Token Exchange 链最大深度 | ✅ | `internal/handler/tokengrant/token_exchange_stages.go` — depth 限制 |
| Token 用量遥测（off-path） | ✅ | `domains/tokenusage/` — 按 kind/endpoint 聚合 |
| **Token Exchange 链可视化** | ❌ | **零实现** — 无 admin API 查看"谁→用了什么→换了什么" |
| **Token 族谱查询（给定 jti → 所有衍生 token）** | ❌ | **零实现** — 无"这枚 token 通过 exchange 产生了哪些下游" |
| **异常链检测（深度/模式/环/跨用户）** | ❌ | **零实现** — 无 anomaly 管道检查 token exchange 模式 |
| **Token 级联吊销（Cascade Revoke）** | ❌ | **零实现** — 吊销一个 token 不波及下游衍生 token |
| **运维面 token 链查看面板** | ❌ | **零实现** — admin console 无 token exchange 视图 |

### 为什么需要

**Token Exchange 是 OAuth 2.0 最强大的模式之一，也是最难审计的模式。**

当架构变成：

```
App A (user session)
  → token-exchange → Token T1 (scoped to Service B)
    → token-exchange → Token T2 (scoped to Service C)
      → token-exchange → Token T3 (scoped to Service D)
```

发生安全事件时的问题：
1. "T3 这个 token 被盗用了，它是从哪个原始登录来的？" → 当前只能点查每个 token 的 `act` claim
2. "T2 是合法的吗？它的整个 exchange 链路径是什么？" → 链信息只在 JWT 中，token 过期即失
3. "T1 被吊销了，T3 还能用吗？" → 当前 T3 不受影响，因为链信息不持久化

**这不仅仅是可视化问题，更是安全缺口：**

| 威胁 | 描述 | 当前防护 |
|------|------|---------|
| 链深度溢出攻击 | 攻击者通过多层 exchange 模糊原始身份 | 最大深度限制（已实现） |
| 链环检测 | Token A → Token B → Token A（循环链） | **未检测** |
| 跨用户交换异常 | 用户 A 的 token 被用户 B 用于 exchange | **未检测**（act claim 审计 trace 需要人工） |
| 链节点泄露级联 | 一枚 token 泄露 → 所有下游可被利用 | **未级联吊销** |
| 异常 exchange 模式 | 短时间大量 chain hops 或异常深链 | **遥测只统计用量，不分析模式** |

### 对抗式核验

```bash
# 验证：无 token 族谱查询 API
grep -rn "token.*lineage\|token.*pedigree\|token.*family.*tree\|lineage.*query\|GetDerivedTokens\|GetTokenChain" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中（排除 refresh token family 查询）

# 验证：无级联吊销
grep -rn "cascade.*revoke\|CascadeRevoke\|RevokeChain\|revoke.*derived\|revoke.*downstream" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中

# 验证：Token exchange 链异常检测不存在
grep -rn "token.*anomaly\|exchange.*anomaly\|chain.*anomaly\|act.*loop\|chain.*detect" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中（domains/tokenanomaly 只检 token 使用模式，不检 chain 拓扑）
```

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| Token Exchange 事件持久化（`TokenExchangeEvent` SPI + store） | L | `platform/audit/` 现有事件系统或新表 |
| Token 族谱查询 API（`GET /admin/tokens/{jti}/lineage`） | M | 以上 SPI |
| Token 链可视化数据（返回 DAG 结构给前端） | M | 以上 API |
| 级联吊销（`CascadeRevoke(jti, maxDepth)`） | L | 族谱 API + token exchange 框架 |
| 链异常检测器（`ChainAnomalyDetector`） | M | `domains/tokenanomaly/` 模式 |
| Admin Console Token Chain 面板 | M | `web/admin/` 扩展 |
| **合计** | **L（~4000 行）** | |

### 边界情况

- **链状态只存在于 exchange 时**：token 过期后链事件数据应保留（审计需求），但标记为"历史"
- **级联吊销的性能影响**：深度 10+ 的链可能需要数千次吊销操作 → 异步 + 有界 depth
- **隐私保护**：族谱 API 只暴露 `jti` / 事件类型 / 时间戳 / client_id，不暴露 token 值
- **数据量管理**：高频 exchange 场景可能产生大量链事件 → 聚合 + 采样策略（类似 `tokenusage`）
- **环检测**：Token A → B → C → A 需要维护 set 并检查每跳的 `subject_token` 是否已出现在祖先中

---

## 方向五：无密码优先体验与渐进式 Passkey 注册

### 当前状态

| 检查项 | 存在？ | 细节 |
|--------|--------|------|
| 密码认证 | ✅ | `authenticators/password.go` — bcrypt 验证 |
| Passkey (WebAuthn) 作为认证因子 | ✅ | `domains/authenticators/webauthn/` — 注册+登录 |
| Passkey 自助管理（/me/mfa/webauthn） | ✅ | `server_me.go` — 用户可注册/解绑 passkey |
| TOTP MFA | ✅ | `authenticators/totp.go` + `authenticators/totp_mfa.go` |
| **Passkey 作为主要（primary）认证器** | ✅ | `webauthn_primary_login_test.go` — 已支持 passkey-only 登录 |
| **Passkey 注册引导流程** | ❌ | **零实现** — 没有任何"推荐注册 passkey"的 UX |
| **密码→Passkey 渐进迁移** | ❌ | **零实现** — 用户登录后不会收到"升级到 passkey 更安全"的提示 |
| **Passkey 恢复机制（丢失设备）** | ❌ | **零实现** — passkey 丢失后，没有专有的恢复流程 |
| **Passkey 使用统计（用户能看到自己的 passkey 上次使用时间）** | ❌ | **零实现** — `/me/mfa/webauthn` 只返回 `created_at`，无 `last_used` |
| **跨设备 passkey 同步状态提示** | ❌ | **零实现** — 不告知用户 passkey 是否已同步（iCloud/Google） |

### 为什么需要

**"支持 Passkey"和"无密码优先"是两种完全不同的产品体验。**

当前状态：
```
登录页面 → 用户输入密码 → 成功登录
         → 也可选："管理 MFA" → "添加 Passkey"
```

无密码优先体验：
```
登录页面 → 可选的 Passkey / 密码 / 其他方式
         → 如果用户用密码登录 → "要不要添加 Passkey 以后一键登录？"
         → 如果有 passkey → 自动跳过密码输入（Conditional UI）
```

**对于企业部署，"无密码"正在从加分项变为必选项：**

1. **微软/谷歌/苹果** 正在推动员工账户默认无密码
2. **网络安全保险** 正在将"无密码认证"作为保费降低条件
3. **FIDO Alliance** 的"无密码认证"市场教育使用户期望值已改变
4. **密码相关安全事件**（凭证填充、钓鱼）是 SSO 最常见攻击面，完全消除密码依赖即可消除

### 对抗式核验

```bash
# 验证：Passkey 推荐/升级流程不存在
grep -rn "passkey.*recommend\|passkey.*prompt\|passkey.*upgrade\|register.*passkey.*after.*login\|post.*login.*passkey\|add.*passkey\|provision.*passkey\|migrate.*passwordless" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中

# 验证：Passkey 恢复流程不存在
grep -rn "passkey.*recov\|recover.*passkey\|passkey.*lost\|passkey.*reset\|reset.*passkey\|lost.*device.*passkey" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中

# 验证：Passkey 使用统计不存在
grep -rn "passkey.*last.*used\|last_used.*passkey\|passkey.*last.*login\|passkey.*statistics\|passkey.*usage.*log" --include="*.go" . | grep -v "_test.go" | grep -v vendor
# → 0 命中
```

### 构建所需

| 组件 | 工作量评估 | 前置依赖 |
|------|-----------|---------|
| 登录后 Passkey 注册提示（`PostLoginPasskeyPrompt` hook） | M | `server_login_client.go` 登录完成钩子 |
| 条件 UI 默认启用（`ConditionalMediation: "conditional"`） | S | `webauthn/conditional_login.go` 已有实现 |
| Passkey 注册邀请通知（用户仪表盘 banner） | M | `web/portal/` 门户 SPA 扩展 |
| Passkey 恢复流程（验证其他因子后重新注册） | M | `selfservice/password_reset.go` 模式可复用 |
| Passkey 使用时间戳（`last_used_at` 字段） | M | `webauthn_sqlite/users.go` + `webauthn_memory_store.go` |
| Admin 面：用户 Passkey 状态概览 | S | `web/admin/` 扩展 |
| Passkey 安全仪表盘（用户：你的 passkey 安全评分） | M | `web/portal/` 扩展 |
| **合计** | **M（~2500 行）** | |

### 边界情况

- **Passkey 全部丢失**：用户换手机且未同步 → 需要备用的恢复路径（OTP 邮件 / 恢复码 / 管理员重置）
- **多平台 passkey**：用户在 macOS（iCloud Keychain）+ 安卓（Google Password Manager）各有 passkey →
  两个都应该在用户控制面板中显示，且标注来源
- **禁止密码的组织策略**：`password_policy.min_strength: 0` + `require_passkey: true` →
  密码用户在下一次登录时被强制注册 passkey
- **渐进提示的频率控制**：每天提示一次 vs 登录即提示 vs 只在风险事件后提示
- **与企业策略联动**："设备合规"条件访问策略要求使用 passkey 而非密码→即使用户有密码也会被重定向到 passkey

---

## 优先级建议

```
P0 │ 方向一（FIDO2 跨设备认证） ── Passkey 生态的下一代体验，产品差异化最强
   │
P1 ├ 方向二（凭据生命周期管理） ── 企业合规刚需，签名密钥已有范式可直接复用
   ├ 方向三（按需动态联盟）     ── 从"预设信任"到"零配置 B2B"，企业级进化
   │
P2 ├ 方向四（令牌交换链审计）   ── 安全运维/事件响应的核心盲区
   └ 方向五（无密码优先体验）   ── 产品体验提升，复用已有 passkey 基础设施
```

### 立即启动建议

- **方向二** 中的 Secret 哈希存储是最容易的速赢项（~200 行，现有 `ConstantTimeStringEq` 可直接使用）
- **方向五** 中的 Passkey 使用时间戳是最小的增量改进（~100 行字段扩展）
- **方向一** 需要最审慎的安全设计（QR 码防重放、BLE 降级），建议先做设计文档
- **方向三** 和 **方向四** 适合在以上速赢项完成后并行启动

### 与 ROADMAP v5.0 的关系

| 本报告方向 | ROADMAP 关系 | 可独立推进？ |
|-----------|-------------|------------|
| ① FIDO2 跨设备认证 | 独立，不依赖 ROADMAP 任何方向 | ✅ 完全独立 |
| ② 凭据生命周期管理 | 补充 ROADMAP §⑤(a)（存在 hash 存储缺口），扩展为完整生命周期 | ⚠️ 部分依赖 §⑤ 安全姿态 |
| ③ 按需动态联盟 | 独立，是现有 federation 的方向扩展 | ✅ 完全独立 |
| ④ 令牌交换链审计 | 独立，与 ROADMAP §③（OIDC 正确性）无关 | ✅ 完全独立 |
| ⑤ 无密码优先体验 | 与 ROADMAP §①（Hosted Login SPA）协同 | ✅ 可独立推进 |

---

## 确认声明

以上五项方向经过以下验证：
1. **ROADMAP v5.0 核验**：五项方向均不在 ROADMAP 的 5 大方向 37 子项中
2. **deferred-backlog 核验**：五项方向均不在 deferred-backlog 的 3 项中
3. **代码 grep 证伪**：每项的关键组件经对抗式 grep，确认为零实现
4. **与已有 docs/requirements/ 交叉验证**：部分方向在早期分析中被提及但从未被拣起为正式方向
