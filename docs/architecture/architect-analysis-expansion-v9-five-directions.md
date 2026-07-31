# 架构分析：v9 五个扩展方向评估与实现建议

> **分析师：** 架构师代理  
> **依据：** `docs/requirements/expansion-directions-v9-analysis.md`（v9 评估报告）  
> **同行评审：** `docs/requirements/expansion-directions-v9-analysis.out.md`（独立验证审核）  
> **补充上下文：** `docs/architecture/architect-analysis-expansion-five-directions.md`（前期五方向）  
> **日期：** 2026-07-12

---

## 前置：同行评审关键发现的影响分析

在开始架构分析前，先评估同行评审对 v9 报告的修正及其对架构决策的影响。

| 发现 | 严重程度 | 对架构分析的影响 |
|---|---|---|
| **① IAL 部分与 v7 方向 2 重叠** | 中 | 方向①的 IAL 组件不再被视为"纯新缺口"。账户恢复框架仍是新缺口，但渐进式 IAL（NIST SP 800-63A IAL2 身份证明管道）已存在概念设计。方向①需要**拆分**：账户恢复（新）和 IAL（扩展已有设计）。建议将 IAL 部分重定向到 v7 方向 2 的实施路径 |
| **③ 工作量低估 (M → M-L)** | 低 | FCM HTTP v1 API 的 OAuth 令牌管理 + APNS HTTP/2 连接池 + PushMFAProvider 重构使得 Phase 1 从 M 上升至 M-L。这影响阶段划分的资源估算，但不改变方向的有效性 |
| **⑤ IssueToken 位置校正** | 低 | `IssueToken` 在 `defaulttoken/jwt_issuer.go:57` 而非各算法 issuer。核心结论（无 scope 感知分支）仍成立。这简化了集成点——只需要改一个文件而非三个 |
| **② 设计最优确认** | — | 利用已有 `TempTokenStore` + `EmailSender`，约 300 行 Go。这强化了方向②的 P1 优先级 |
| **所有缺口真实存在** | — | 五个方向的确覆盖了未实现的代码路径，只是 IAL 部分的概念设计在先。总体方向有效性不受影响 |

**核心建议重组**：将方向①拆分为 **(a) 自助账户恢复框架**（新，约 600 行）和 **(b) 渐进式 IAL 集成**（与 v7 方向 2 合并，约 1200 行）。本分析将把方向①视为"自助账户恢复"（不含 IAL），IAL 部分作为跨方向的协作点处理。

---

## 1. 架构评估

### 1.1 从 v9 方向看当前架构的优势

v9 报告选择的五个方向从侧面反映了项目的架构成熟度。每个方向之所以有价值，恰恰因为底层基础设施已经到位：

| v9 方向 | 依赖的已有基础设施 | 架构成熟度信号 |
|---|---|---|
| ① 自助账户恢复 | `EmailSender`、`temp_token.go`、`break_glass.go` | 认证恢复所需的最小原语已存在——只缺编排层 |
| ② Magic Link | `EmailSender`、`TempTokenStore`、`authenticators.CodeStore` | 临时令牌基础设施完备——只缺认证流集成 |
| ③ 推送通知 | `PushMFAProvider`、`push_webhook.go` | 推送 MFA 挑战/响应环已闭环——只缺传输层 |
| ④ 安全运维面板 | `tokenusage/portfolio`、`anomaly/`、`threataction/`、`sse.Broker` | 数据面和事件面已完整——只缺聚合展示层 |
| ⑤ 令牌敏感度分类 | JWT Issuer（统一签发）、DPoP/mTLS、Refresh 轮换 | 令牌管道和绑定机制已完整——只缺策略挂载点 |

**核心观察**：五个方向都是在"已有完整基础设施"之上构建**编排/策略/展示层**。这不是巧合——项目经过多轮迭代后，基础设施层已趋于稳定，扩展的自然方向是向上层（产品体验、治理、运维）移动。这与 AGENTS.md 的成熟度判断一致。

### 1.2 当前架构的局限性（v9 方向暴露的问题）

五个方向共同暴露了三个架构层面的缺口：

#### 缺口 A：缺乏"恢复"和"注册"之间的生命周期连贯性

项目有完整的**登录前**（注册门禁、DCR）和**已登录**（会话管理、令牌管理）路径，但**用户丢失全部凭据**（全丢失恢复）是一个灰色地带——无法映射到现有的认证流程组件。

```
注册 → 登录 → 认证 → 授权 → 令牌生命周期
                                  ↑
                           全丢失恢复 ← 无映射路径
```

这不是缺少一个端点的问题——而是需要引入**恢复 Token（recovery token）** 作为与 access/refresh/id 并列的令牌类型。恢复 Token 有特殊的生命周期（短 TTL、与用户身份证明级别绑定、需要 audit trail 追踪全部恢复步骤）。

#### 缺口 B：认证方式之间缺乏组合编排

现有认证方式（密码、WebAuthn、TOTP、SMS、邮箱验证码）各自独立实现，互不知晓。Magic Link（方向②）是一个新的认证方式，但更根本的问题是：**认证方式应该如何组合成一个信任评分？**

当前架构：
```
认证方式 A → 通过/失败 → 登录
认证方式 B → 通过/失败 → 登录
```

目标架构（隐含在方向①的 IAL 和方向⑤的敏感度中）：
```
认证方式 A → 证据质量 = 0.7 
认证方式 B → 证据质量 = 0.5  → 组合评估 → IAL 级别 → 令牌敏感度
认证方式 C → 证据质量 = 0.9
```

**这需要一个 Evidence SPI**——每个认证方式在验证通过后返回的不只是"用户已验证"，而是"用户已验证 + 证据等级 + 验证上下文"。当前所有认证器的返回签名都需要调整。

#### 缺口 C：安全治理数据有输出无输入闭环

方向④（安全运维面板）和方向⑤（令牌敏感度）都依赖安全数据（异常告警、令牌使用统计、会话元数据）。这些数据当前是 **emit-and-forget**——记录到审计日志和 metrics，但没有被任何策略引擎消费来改变运行时行为。

这是前期架构分析中"授权决策管道"缺口的子问题——安全数据需要回流的管道：

```
异常检测 → 安全面板可视化 → 管理员手动操作  (当前)
异常检测 → 策略评估 → 自动响应 (目标)
```

### 1.3 关键设计决策评估

| 决策 | 对应 v9 方向 | 评估 |
|---|---|---|
| `EmailSender` 作为独立 SPI 而非内嵌在认证器中 | ①② | ✅ 正确。方向①和②都复用同一 `EmailSender`，说明抽象到正确粒度 |
| `TempTokenStore` 与 `AuthCodeStore` 分离 | ② | ✅ 正确。Magic Link 需要在临时令牌上绑定完整的 OAuth 参数（client_id、redirect_uri、code_challenge），这超出了 AuthCode 的设计目标 |
| DPoP/mTLS 绑定在签发路径末尾而不是入口 | ⑤ | ⚠️ 合理但增加了集成难度。要在签发路径中插入 scope 感知的策略（方向⑤），需要在 `IssueToken` 之前、scope 确认之后设置策略注入点。当前 DPoP 在签发末尾做，策略如果在它之前评估，无法利用 DPoP 状态 |
| 推送 MFA 挑战通过轮询而非 SSE | ③ | ✅ 对于移动场景正确。SSE 需要长连接，移动端不适合；轮询模式对推送场景是最兼容的 |
| Admin Console 以 SPA 形式嵌入 | ④ | ✅ 正确。方向④的核心价值是聚合现有 API 的数据，SPA 架构天然适合这种展示层聚合。但需要在 admin API 侧添加聚合端点（如 `POST /admin/security/overview` 一次返回所有面板数据），避免 SPA 发 5-6 个请求 |

### 1.4 架构债务汇总（v9 视角新增）

| 债务 | 对应于 | 严重度 | 根因 | 修复成本 |
|---|---|---|---|---|
| 全丢失恢复无路径 | 方向①前置条件 | 中 | 生命周期覆盖缺口 | ~600 行（账户恢复框架） |
| 认证器返回无证据等级 | 方向①⑤ | 低-中 | SPI 设计未考虑组合场景 | 修改 Authenticator SPI（影响 8+ 实现） |
| 安全数据无回流闭环 | 方向④⑤ | 中 | emit-and-forget 模式 | ~800 行（策略引擎 + 事件总线） |
| PushMFAProvider 与 PushSender 耦合 | 方向③ | 中 | webhook 模式硬编码 | 重构 PushMFAProvider（~400 行） |
| 令牌签发无 scope 感知策略挂载点 | 方向⑤ | 中 | 签发路径无扩展点 | 在 `IssueToken` 前增加 `TokenPolicyEvaluator` SPI |

---

## 2. 扩展方向

本节对 v9 报告的五个方向进行架构层面深入评估。与 v9 报告的产品-经理视角不同，本分析侧重**架构决策、技术挑战、集成设计**。

### 方向 A：自助账户恢复框架 — P1

> 对应 v9 方向①（不含 IAL 部分，IAL 已确认与 v7 方向 2 重叠）

#### 为什么需要（架构价值）

账户恢复不是一个"新协议"而是一个**安全状态机**——用户从"已锁定/已丢失"状态转换回"已验证"状态。这个状态机需要：

1. **恢复令牌**（与 access/refresh/id 并列的第四令牌类型）——短 TTL、单用途、与用户身份证明级别绑定
2. **恢复会话**——与普通登录会话隔离的临时上下文，用于多步恢复流程
3. **组合验证编排**——将多个低信任度的验证方法组合为高信任度的恢复决策

当前架构有零散的低级原语（`forgot-password`、`recovery_mfa_provider`、`break_glass`），但没有编排层将它们组合成完整的恢复流程。

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| **恢复令牌与 OAuth 流程的集成** | ★★★ | 恢复成功后需要颁发临时 access_token（让用户设置新密码），但正常 OAuth 流程期望的是 auth_code。恢复流程的 OAuth 集成需要一种"降级"授权模式——使用 `grant_type=recovery` 而非标准 grant |
| **防枚举** | ★★★ | 所有恢复入口必须返回统一响应。但多步恢复（`initiate → verify → complete`）的每一步都提供状态信息——规范设计需要在抗枚举与用户体验之间找到精确平衡 |
| **会话隔离** | ★★ | 恢复中的用户不应同时拥有活跃的登录 session——攻击者可能在用户恢复过程中利用已登录的 session 操作。需要确保恢复开始 → 完成期间，所有已有 session 被冻结或终止 |
| **`TempTokenStore` 能力扩展** | ★★ | 方向②和方向①都依赖 `TempTokenStore`。但恢复场景需要更丰富的元数据存储（当前方法、验证 proof、过期时间）。需要评估 `TempTokenStore` 的 SPI 是否需要扩展，还是创建 `RecoveryStore` |

#### 预期架构变更

```
新增包:
  domains/accountrecovery/
  ├── recovery.go            # RecoveryFlow 类型 + 状态机
  ├── recovery_store.go      # RecoveryStore SPI（或扩展 TempTokenStore）
  ├── recovery_provider.go   # RecoveryProvider SPI（验证方法提供者）
  ├── email_recovery.go      # 邮箱验证恢复（inline impl）
  └── admin_review.go        # 管理员审批恢复（与 break_glass 集成）

新增端点:
  interfaces/admin/
  └── recovery_api.go        # GET /admin/recovery-requests — 待审批的恢复请求

修改:
  protocols/oauth/
  └── handle_auth.go  ← 添加 grant_type=recovery 支持（或专门的 recovery handler）

  interfaces/sso/
  ├── handlers.go      ← 添加 /auth/recover/* 路由
  └── options.go       ← 添加 WithAccountRecovery(...) 配置
```

**放置决策**：`domains/accountrecovery/` — 位于 domain 层，因为它是业务能力的编排（组合多个认证/验证方法）。不放在 `protocols/oauth/` 因为它不是 OAuth 协议的一部分，而是与 OAuth 集成的上层能力。

#### IAL 集成策略（与 v7 方向 2 的关系）

根据同行评审的发现，IAL 部分不拆入方向①而是重定向到 v7 方向 2 的实施路径：

```
v7 方向 2（NIST SP 800-63A IAL2） ← IAL SPI + 证明级别
    ↑ 集成
方向① Phase 2（账户恢复 + IAL 级别影响令牌） 
```

具体协作点：
- `IdentityProofingProvider` SPI 在 v7 方向 2 的实施中定义
- 方向①的恢复流程在 `recovery_complete` 时根据 IAL 级别颁发不同信任度的令牌
- IAL 级别的 `acr` claim 在签发时注入（也服务方向⑤的令牌敏感度输入）

#### 对现有系统的影响

- **低侵入**：新增包和端点，不影响现有 OAuth 流程
- **TempTokenStore 可能需扩展**：如果当前 SPI 不支持恢复流程所需的元数据，需要添加 `RecoverySessionStore`（或扩展 `TempTokenStore`）
- **与 break_glass 集成**：管理员审批恢复流应复用现有的管理 API 认证和审计路径，而不是新建

---

### 方向 B：Magic Link 免密主认证 — P1

> 对应 v9 方向②，已验证最优设计

#### 为什么需要（架构价值）

Magic Link 是 OAuth 授权码流程的一次性临时令牌认证器——它本质上是 **PKCE 的 UX 等价物**：PKCE 用 `code_verifier` 将授权码绑定到初始请求，Magic Link 用 `magic_token` 将授权码绑定到邮箱验证。两者都是"在重定向路径中保持绑定"的解决方案。

从架构角度，Magic Link 的引入验证了一个重要的设计决策：**`TempTokenStore` 抽象的正确性**。如果 `TempTokenStore` 的设计足够通用，Magic Link 的实现应该接近零架构改动——只是新增一个端点 + 一个邮件模板。

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| **OAuth 参数提前绑定** | ★★ | Magic Link 在用户认证前就需要知道 `client_id`、`redirect_uri`、`scope`、`code_challenge`。需要在 `POST /auth/magic-link` 时验证这些参数的合法性（client 存在、redirect_uri 在白名单中），但此时用户未认证——需要在"无用户"上下文中做 OAuth 参数校验 |
| **与现有 login SPA 的交互模式** | ★★ | SPA 的当前登录 flow 是"输入凭据 → 登录 → 重定向"。Magic Link 需要"输入邮箱 → 发送链接 → 用户离开 → 点击链接 → 完成"。SPA 需要处理中间态（邮件已发送、等待点击） |
| **会话发现（silent auth）** | ★★★ | 如果用户已有 session，应直接完成授权而不发邮件。但如何高效检测？当前 silent auth 通过 `prompt=none` + iframe 实现。Magic Link 需要同等的静默检测逻辑，但通过邮箱而非 session cookie |
| **防枚举** | ★★ | 与方向①相同，所有入口返回统一响应。但 Magic Link 在第二步（GET 回执）时会暴露 token 有效/无效——设计必须确保无效 token 不泄露"邮箱是否存在" |

#### 预期架构变更

```
新增端点:
  protocols/oauth/
  └── handle_magic_link.go   # POST /auth/magic-link + GET /auth/magic-link/verify

修改:
  interfaces/sso/
  ├── handlers.go            ← 添加路由
  └── options.go             ← 添加 WithMagicLink(...) 配置

新增邮件模板:
  assets/templates/
  └── magic_link.tmpl        # Magic Link 邮件内容

修改 SPA:
  interfaces/sso/public/oauth2/login/
  └── app.js                 ← "免密登录" tab + 发送/等待/重试 UI
```

**放置决策**：`protocols/oauth/` 下的 `handle_magic_link.go` — 因为 Magic Link 是 OAuth 授权码流程的特殊入口。它不改变 OAuth 协议，而是新增一种"获取 auth_code 的认证方式"。

#### 集成设计关键点

```
POST /auth/magic-link
├── 验证 client_id, redirect_uri, scope 等 OAuth 参数（无用户上下文）
├── 根据邮箱查找用户（如果存在）
├── 生成 magic_token → 存入 TempTokenStore
│   └── 绑定: {client_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, state, email}
├── 发送邮件（含 magic_link URL）
└── 返回 {"status":"sent"}（统一响应）

GET /auth/magic-link/verify?token=xxx
├── 从 TempTokenStore 读取绑定数据
├── 验证 token 有效性（存在、未过期、未使用、IP 匹配？）
├── 创建用户 session（如果用户存在）
│   └── 如果用户不存在 → 可选自动注册（需 WithMagicLinkAutoSignup 配置）
├── 生成 auth_code（绑定原有参数）
└── 302 重定向到 client's redirect_uri?code=xxx&state=xxx
```

#### 对现有系统的影响

- **极低侵入**：新增一个端点文件、一个邮件模板、SPA 的 JS 修改
- **TempTokenStore 复用**：Magic Link 不需要修改 TempTokenStore SPI——如果当前 SPI 支持任意 key-value 绑定，则零改动
- **与现有登录流程共存**：Magic Link 是"并行认证方式"，不影响密码/WebAuthn 流程

---

### 方向 C：推送通知基础设施与移动认证 — P1

> 对应 v9 方向③，工作量已校正为 M-L（Phase 1）

#### 为什么需要（架构价值）

推送通知是 OAuth 生态中唯一一个**需要服务端主动发起 HTTP 请求给第三方平台**（FCM/APNS）的能力模块。这与项目其他所有模块（都是被动等待请求）不同。这意味着：

1. **需要一个新的出站 HTTP 客户端模式**——与现有处理入站请求的模式正交
2. **需要令牌管理**——FCM HTTP v1 API 需要 OAuth 2.0 访问令牌（使用 Google 服务账户的 JWT 断言来获取）
3. **需要连接池管理**——APNS HTTP/2 需要维持到 Apple 服务器的持久连接

这不仅仅是"添加一个 FCM 库"——而是引入一个**新的运行时基础设施类别**：入站无关的出站推送通道。

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| **FCM OAuth 令牌管理** | ★★★ | FCM HTTP v1 API 需要一个 OAuth 2.0 access_token（通过 Google 服务账户 JWT 断言换取，scope=`https://www.googleapis.com/auth/firebase.messaging`）。这需要在 infrastructure/fcm/ 中实现一个轻量级的 OAuth 客户端来管理令牌生命周期（获取、缓存、刷新）。同行评审确认此工作量被低估 |
| **APNS HTTP/2 连接池** | ★★★ | Apple APNS 要求使用 HTTP/2 持久连接（不支持 HTTP/1.1 的点对点请求）。Go 的 `net/http` 支持 HTTP/2，但连接池需要仔细管理（连接泄漏、超时、证书轮换）。此外需要区分 APNS 生产环境（`api.push.apple.com:443`）和开发环境（`api.sandbox.push.apple.com:443`） |
| **PushMFAProvider 重构** | ★★ | 当前 `push_mfa_provider.go` 假设推送是"发送 webhook + 轮询结果"。重构为"发送推送 notification + 监听批准回调"需要明确的架构边界：webhook 模式和 FCM/APNS 模式应共享挑战/轮询逻辑，只替换发送通道 |
| **设备注册的生命周期管理** | ★★ | 设备推送令牌会因多种原因失效（应用卸载、权限撤销、令牌轮换）。需要后台扫描器定期清理失效令牌，否则推送渠道变得不可靠 |
| **平台特定逻辑** | ★ | FCM 和 APNS 的推送负载格式不同（FCM 使用 `message.notification` + `message.data`，APNS 使用 `aps` 字典）。需要统一抽象（`PushNotification`）在 SPI 层，序列化到各平台格式在 impl 层 |

#### 预期架构变更

```
新增 SPI:
  shared/spi/
  └── push.go                # PushSender SPI + PushNotification 类型

新增基础设施实现（独立子模块，与 `infrastructure/fcm/` 和 `infrastructure/apns/` 平行的 `go.mod`）:
  infrastructure/fcm/
  ├── sender.go              # PushSender 实现（FCM HTTP v1 API）
  ├── token.go               # Google OAuth 令牌管理（JWT 断言 → access_token）
  └── fcm_test.go            # 集成测试（需 FCM 凭据）

  infrastructure/apns/
  ├── sender.go              # PushSender 实现（APNS HTTP/2）
  ├── connection.go          # HTTP/2 连接池管理
  └── apns_test.go           # 集成测试（需 APNS 证书）

新增:
  protocols/oauth/
  └── push_device.go         # 设备注册端点（POST /me/devices）

修改:
  domains/authenticators/
  ├── push_mfa_provider.go   ← 重构：抽出 PushSender 依赖，PushMFAProvider 只做挑战/轮询
  └── push_webhook.go        ← 作为 PushSender 的 webhook 实现保留

  interfaces/sso/
  ├── handlers.go            ← 添加 /me/devices 路由
  └── options.go             ← 添加 WithFCM()、WithAPNS() 配置
```

**放置决策**：`infrastructure/fcm/` 和 `infrastructure/apns/` 放在 infrastructure 层——它们是具体的 SPI 实现。`PushMFAProvider` 的挑战/轮询逻辑留在 `domains/authenticators/`。`PushSender` SPI 放在 `shared/spi/` — 被 domain 和 protocol 层引用。

#### FCM OAuth 令牌管理的自建 vs 引入

| 方案 | 优点 | 缺点 | 推荐 |
|---|---|---|---|
| 引入 `firebase.google.com/go/v4/messaging` | 官方 SDK，处理令牌刷新 | CGO 非必需但 SDK 有额外的依赖（`google.golang.org/api/option`、`golang.org/x/oauth2`） | ⚠️ 可考虑，但需评估依赖大小 |
| 自建（~200 行） | 零外部依赖；完全控制令牌缓存逻辑 | 需要自己实现 JWT 断言 → access_token 流程 | ✅ 推荐 — 流程标准（RFC 7523 §2.1 service account JWT for Google API），使用已有 `golang.org/x/oauth2` |

#### 对现有系统的影响

- **中侵入**：PushMFAProvider 需要重构——需要确保向后兼容 webhook 模式
- **新增向外依赖**：FCM 和 APNS 通信需要出站 HTTPS——需要在部署时配置网络策略
- **设备注册数据持久化**：新增 `DeviceStore` SPI——需要所有存储后端实现（Memory / SQLite / Postgres / Redis）

---

### 方向 D：令牌与会话生命周期治理面板 — P2

> 对应 v9 方向④

#### 为什么需要（架构价值）

安全运维面板与 v9 其他方向的不同之处在于：它**不引入新功能**，而是**聚合现有数据**做可视化。从架构角度，这是对现有可观测性基础设施的"最后一公里"交付——代码已有数据（anomaly、threataction、tokenusage），只是没有被最终用户（运维人员）消费。

**架构信号**：当项目需要"安全运维面板"时，意味着：
1. 数据面已成熟（anomaly 检测器、threataction 执行器、portfolio 统计器）
2. 控制面已成熟（会话管理、令牌撤销 API）
3. 缺口在展示面（管理员没有一站式视图）

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| **数据聚合延迟** | ★★ | 面板需要实时数据（活跃会话数、最新告警）和近实时数据（趋势图、统计信息）。实时数据走直接查询，近实时数据走预聚合。需要设计两种查询路径 |
| **跨区域数据的一致性** | ★★★ | 如果部署多区域且无全局 session store，每个区域有自己的活跃会话数据。面板需要显示"本区域"和"全局"两个视图——全局视图需要跨区域聚合 |
| **SSE 集成** | ★ | 已有 `sse.Broker`，但当前 SSE 通道是为用户通知设计的（用户登录提醒、session 过期）。安全面板的 SSE 需要为管理员分配独立的通道，并确保 `admin:security` scope 正确过滤事件 |
| **批量操作的安全性** | ★★★ | 批量终止会话是高危操作。设计需要：二次确认 -> 审计日志 -> 操作执行 -> 结果反馈 -> 回滚能力。批量操作应使用异步任务（返回 task_id），而非同步执行 |

#### 预期架构变更

```
新增 API:
  interfaces/admin/
  ├── security_dashboard.go   # GET /admin/security/overview — 面板数据聚合端点
  ├── security_sessions.go    # POST /admin/security/sessions/terminate — 批量终止
  ├── security_stats.go       # GET /admin/security/stats — 统计
  └── security_timeline.go    # GET /admin/security/timeline — 事件时间线

新增 SPA 页面:
  admin/
  └── security-dashboard/     # 新 SPA 页面（与现有 admin SPA 集成）

修改:
  interfaces/sso/
  └── handlers.go             ← 添加 admin/security/* 路由

  domains/anomaly/
  └── alert.go                ← 添加 SSE 事件发布（已有 sse.Broker）
```

**放置决策**：新增 API 放在 `interfaces/admin/`（管理面 API）。不需要新增 domain 包——聚合逻辑是编排（调用多个已存在的 SPI），在 handler 层实现即可。

#### 后端聚合 API 设计原则

```
GET /admin/security/overview
返回: {active_sessions, active_tokens, anomaly_alerts, recent_events}

实现: 并行调用 session store (count) + token store (count) + anomaly store (list alerts) + audit store (recent events)
超时: 总 < 500ms。每个子调用的独立超时 + fail-open（单个子调用失败不影响其他数据）
```

**关键设计决策**：聚合 API 应该在 handler 层并发调用多个存储 SPI，而不是新增一个"聚合存储 SPI"。原因是：
- 数据源来自不同领域（session、token、anomaly、audit），它们不应该被耦合在一个 SPI 中
- 并发模式可以在 handler 层直接使用 `errgroup` 实现，不需要中间层

#### 对现有系统的影响

- **低侵入**：只新增 API 和 SPA 页面，不修改现有逻辑
- **性能**：需要为统计查询建立索引——活跃会话数的 count 查询在大规模部署中需要预计算（Redis 的 `SCARD` 或 Postgres 的物化视图）
- **权限**：新增 `admin:security` scope——需要更新权限模型

---

### 方向 E：令牌敏感度分类与自适应保护 — P2

> 对应 v9 方向⑤，IssueToken 位置已校正（`defaulttoken/jwt_issuer.go:57`，非各算法 issuer）

#### 为什么需要（架构价值）

令牌敏感度分类是五个方向中**架构最深、影响面最广**的一个。它构建在依赖方向④（安全面板提供异常信号）和方向① IAL（身份证明级别提供用户信任度）之上。

从架构角度，这是从**统一的令牌策略**（所有令牌同一安全属性）进化到**差异化令牌策略**（令牌安全属性绑定到 scope 敏感度）。这个进化涉及：

1. **签发路径扩展**——在 `IssueToken` 中注入 scope 评估逻辑
2. **刷新家族隔离**——将单一 refresh family 拆分为多个敏感度级别的子家族
3. **策略同步**——敏感度策略变更需要在所有副本之间同步

#### 核心挑战

| 挑战 | 难度 | 说明 |
|---|---|---|
| **签发路径的非侵入性扩展** | ★★★ | 当前 `IssueToken(ctx, claims, ttl)` 是嵌入式方法（在 JWT issuer 结构体上）。要插入 scope 评估逻辑，要么：A) 在调用点包装（handler 层评估 scope 后调用 `IssueToken` 时传入策略约束），或者 B) 在 `IssueToken` 内部添加钩子。方案 A 更干净——handler 层知道 scope，issuer 不需要知道 scope 语义 |
| **Refresh Family 隔离的设计** | ★★★★ | 当前 refresh family 是用户级别的一个 UUID——所有 scope 共享同一个 family。要实现按敏感度隔离，需要将 family 从"用户级"改为"（用户 + 敏感度）级"。影响：① RefreshTokenStore 的 `FamilyID` 查询需要额外字段；② 家庭重用检测（`DeleteFamily`）需要范围为特定敏感度级的家庭；③ 迁移——现有 refresh 无敏感度级别，如何处理？默认降级为 Standard |
| **DPoP 强制与客户端兼容性** | ★★★ | 要求 `admin:*` scope 的客户端必须使用 DPoP——这是 OAuth 协议的正确做法，但当前客户端可能不支持。需要在 `/token` 响应中使用 `invalid_scope` 错误（而非 `invalid_client` 或 `invalid_request`），并附带 `scope` 参数说明需要哪些 scope 需要 DPoP |
| **策略同步的原子性** | ★★ | `TokenSensitivityPolicyChange` 事件需要在新令牌签发前到达所有副本。使用 `cluster.Bus` 广播——但 Bus 不是强一致性的。如果在策略更新期间签发令牌，不同副本可能应用不同策略——需要版本号机制 |

#### 预期架构变更

```
新增:
  shared/core/
  └── token_classification.go  # TokenSensitivityLevel + TokenSensitivityPolicy + DefaultScopeSensitivity()

  shared/spi/
  └── token_policy.go          # TokenPolicyEvaluator SPI（可选扩展点）

修改:
  interfaces/sso/
  ├── server_token.go          ← 签发路径：在 IssueToken 调用前评估 scope 敏感度
  └── options.go               ← WithTokenSensitivityPolicy(...) 配置

  protocols/oauth/
  ├── handle_token.go          ← 刷新令牌时传递 scope 敏感度信息到签发路径
  └── refresh_token.go         ← RefreshFamily 隔离逻辑

  defaultimpl/
  └── sqlite/oauth_refresh_tokens.go ← 扩展 FamilyID 为（user_id, sensitivity_level）复合键
  └── memory/refresh_token_store.go  ← 同上

  platform/cluster/
  └── bus_types.go             ← 新增 KindTokenSensitivityPolicyChange
```

**放置决策**：
- `TokenSensitivityLevel` 和默认映射放在 `shared/core/`——被所有层引用
- `TokenSensitivityPolicy` 配置在 `interfaces/sso/options.go` ——它是服务器级别的配置
- Refresh family 隔离逻辑在 `protocols/oauth/refresh_token.go` ——与 refresh 轮换逻辑在一起

#### Token Policy Evaluator 的集成点设计

**推荐方案**（在 handler 层评估，而非嵌入式）：

```go
// 当前签发路径（在 handle_token.go 中）:
func (s *Server) issueAccessToken(ctx, client, user, scopes, ttl) {
    token, err := s.tokenIssuer.IssueToken(ctx, &Claims{Scopes: scopes}, ttl)
}

// 扩展后:
func (s *Server) issueAccessToken(ctx, client, user, scopes, ttl) {
    // 1. 计算 scope 敏感度
    sensitivity := evaluateScopeSensitivity(scopes)
    
    // 2. 获取策略
    policy := s.getTokenPolicy(sensitivity)
    
    // 3. 应用策略约束
    effectiveTTL := min(ttl, policy.MaxTTL)
    
    // 4. 如果是 refresh，检查 step-up 要求
    if isRefresh && policy.RefreshStepUp {
        requireLatestAuth(ctx, user)
    }
    
    // 5. 传递敏感度级别到 issuer（供 claims 注入和 family 隔离）
    ctx = context.WithValue(ctx, ctxKeySensitivity, sensitivity)
    
    token, err := s.tokenIssuer.IssueToken(ctx, &Claims{Scopes: scopes}, effectiveTTL)
}
```

此方案的优点：
- Issuer 不需要知道 scope 语义——它只接收最终的 TTL 和 claim 参数
- 策略逻辑在 handler 层，与协议逻辑在一起（易于调试和审计）
- 新 grant 类型自动继承策略（只要它们通过 `issueAccessToken` 签发）

#### 对现有系统的影响

- **中侵入**：修改签发路径（一个中心位置 `server_token.go` 或 `handle_token.go`）、修改 refresh family 逻辑（影响全部 4 个存储后端）、新增 cluster bus 事件类型
- **不影响**：现有令牌验证路径（token 验证不需要改变）、协议行为（OAuth/OIDC 协议行为不变）
- **迁移挑战**：现有 refresh tokens 没有敏感度标签——它们默认视为 Standard 级别。现有用户不需要任何操作。但升级后，刚获得 admin scope 的令牌可能自动应用更严格策略——这是预期行为

---

## 3. 接口设计建议

### 3.1 核心 SPI 设计原则（v9 方向适用）

| 原则 | 适用方向 | 说明 |
|---|---|---|
| **编排层不修改 SPI** | ①②④ | Magic Link 和账户恢复使用 `TempTokenStore` 和 `EmailSender`——不应为了新场景扩展已有 SPI，而是使用组合 |
| **新的传输通道用新 SPI** | ③ | `PushSender` SPI 是全新接口，独立于现有的 `PushMFAProvider`——后者是"挑战/响应"逻辑，前者是"通知发送"逻辑 |
| **策略挂载点用 middleware 模式** | ⑤ | Token Policy Evaluator 应该是签发路径中的一个可选步骤，而非修改 IssueToken 签名 |
| **聚合数据在 handler 层并发** | ④ | 安全面板的跨 SPI 数据聚合在 handler 层用 `errgroup` 实现，不引入新的聚合 SPI |
| **错误码守 orcale-leak** | ①②③ | 所有方向的新端点必须遵守现有的 orcale-leak 保护规范——统一响应、防枚举、一致的状态码 |

### 3.2 是否需要新的抽象层

| 方向 | 新抽象 | 类型 | 位置 | 理由 |
|---|---|---|---|---|
| ① | `RecoveryProvider` SPI | 编排 SPI | `domains/accountrecovery/` | 不同的恢复方法（邮箱、短信、管理员审批）需要统一的调用接口 |
| ① | `RecoverySessionStore` SPI | 存储 SPI | `shared/spi/`（或扩展 TempTokenStore） | 恢复流程需要持久化中间状态 |
| ② | 不需要 | — | — | 复用 `TempTokenStore` + `EmailSender` |
| ③ | `PushSender` SPI | 基础设施 SPI | `shared/spi/push.go` | 统一的推送发送抽象，FCM/APNS/webhook 都是其实现 |
| ③ | `DeviceStore` SPI | 存储 SPI | `shared/spi/` | 设备注册需要持久化 |
| ④ | 不需要 | — | — | 聚合逻辑在 handler 层 |
| ⑤ | `TokenPolicyEvaluator` | 策略 SPI | `shared/spi/`（可选） | 如果策略逻辑需要可插拔（自定义 scope 映射），则需要 SPI；如果使用固定配置 + 选项模式，则不需要 |

**核心建议**：只有在需要"多种实现可插拔"时才引入 SPI。方向①的恢复肯定需要多种方法（邮箱、管理员审批等），但方向⑤的 scope 映射可能不需要 SPI——`DefaultScopeSensitivity()` 提供默认值，`WithScopeSensitivity()` 提供覆盖，两个函数即可满足 95% 的场景。

### 3.3 向后兼容性策略

| 方向 | 兼容性策略 |
|---|---|
| ① 账户恢复 | 完全新增功能。默认关闭，`WithAccountRecovery()` 启用。不修改现有密码重置路径 |
| ② Magic Link | 完全新增功能。默认关闭，`WithMagicLink()` 启用。与现有密码/WebAuthn 登录并行 |
| ③ 推送通知 | PushMFAProvider 重构为可插拔 PushSender：webhook 实现保持原行为（默认），FCM/APNS 是新增选项。重构不改变 `PushMFAProvider` 的公共 API 签名 |
| ④ 安全面板 | 完全新增 API 端点。不修改现有 admin API。SPA 页面是新增页面，不影响现有 admin 页面 |
| ⑤ 令牌敏感度 | 新增策略默认关闭（`WithTokenSensitivity()` 启用）。关闭时行为完全不变。开启后：Scope 映射有默认行为（无需配置），Refresh family 隔离只影响新签发的令牌 |

---

## 4. 技术选型

### 4.1 新依赖引入评估

| 方向 | 潜在新依赖 | 必要性 | 推荐 |
|---|---|---|---|
| ① 账户恢复 | **无** | — | 自建。邮箱验证用已有 EmailSender，管理员审批是业务流程 |
| ② Magic Link | **无** | — | 自建。纯编排逻辑 |
| ③ 推送通知 | `firebase.google.com/go/v4/messaging` | 可选 | **不建议**。FCM HTTP v1 API 只需 service account JWT + 标准 HTTP POST——自建约 200 行，比引入整个 Firebase SDK 更轻量 |
| ③ 推送通知 | `golang.org/x/oauth2` | 必需 | 已存在。FCM OAuth 令牌获取需要使用 `jwt.go`（Google 服务账户 JWT 断言） |
| ③ 推送通知 | 第三方 APNS 库（如 `github.com/sideshow/apns2`） | 可选 | **不建议**。APNS HTTP/2 通信使用 Go 标准库 `net/http`（支持 HTTP/2）即可——自建约 150 行。第三方库增加 CVE 暴露面 |
| ④ 安全面板 | **无** | — | 自建。纯 API 聚合 + SPA UI |
| ⑤ 令牌敏感度 | **无** | — | 自建。纯策略逻辑 |

**结论**：五个方向**零必需外部运行时依赖**。这是项目"纯 Go、零外部运行时依赖"原则的自然结果。

### 4.2 自建 vs 引入的详细决策

| 组件 | 决策 | 估算 | 理由 |
|---|---|---|---|
| FCM 客户端 | ✅ 自建 | ~200 行 | HTTP v1 API 只需要 POST `https://fcm.googleapis.com/v1/projects/{project}/messages:send` + Bearer 令牌。认证流程（service account JWT → access_token）是标准 RFC 7523——已有 `crypto/rsa` 和 `golang.org/x/oauth2/jwt` |
| APNS 客户端 | ✅ 自建 | ~150 行 | HTTP/2 POST + TLS 客户端证书。Go 标准库原生支持 HTTP/2——只需要正确配置 `http.Transport` |
| 设备注册 | ✅ 自建 | ~300 行 | CRUD SPI + 标准 API 端点 |
| 安全面板 SPA | ✅ 自建 | ~800 行 JS | 纯数据可视化，不需要 UI 框架。已有 admin SPA 的图表库（Chart.js 或类似）可复用 |
| Token Policy | ✅ 自建 | ~200 行 | 纯逻辑（scope → level → policy），无外部依赖 |

### 4.3 分层放置新代码的决策框架

```
新代码应放在哪个层？
├── 如果是"与协议语义相关" → protocols/
│   ├── Magic Link (OAuth 授权码流程变体) → protocols/oauth/
│   └── 令牌敏感度在签发路径的集成 → protocols/oauth/
├── 如果是"业务能力编排" → domains/
│   ├── 账户恢复 → domains/accountrecovery/
│   └── 设备注册 → domains/devices/ (或 domains/userdevices/)
├── 如果是"具体 SPI 实现" → infrastructure/
│   ├── FCM 实现 → infrastructure/fcm/
│   ├── APNS 实现 → infrastructure/apns/
│   └── SQLite/Postgres 设备存储 → infrastructure/sqlite/ + postgres/
├── 如果是"SPI 接口定义" → shared/spi/ 或 shared/core/
│   ├── PushSender → shared/spi/push.go
│   └── TokenSensitivityLevel → shared/core/token_classification.go
└── 如果是"管理面 API + UI" → interfaces/admin/
    ├── 安全面板 API → interfaces/admin/
    └── 安全面板 SPA → public/admin/
```

---

## 5. 实施路线图

### 5.1 优先级重排（基于架构分析）

同行评审校正后的优先级评估：

| 排名 | v9 方向 | 架构价值 | 工作量 | 侵入性 | 依赖 | 建议优先级 |
|---|---|---|---|---|---|---|
| **1** | ② Magic Link | ★★★★ | ~400 行 | 极低 | EmailSender + TempTokenStore（已存在） | **P1** |
| **2** | ① 账户恢复（不含 IAL） | ★★★★ | ~600 行 | 低 | EmailSender + TempTokenStore（已存在） | **P1** |
| **3** | ③ 推送通知 Phase 1 | ★★★★ | ~800 行 | 中 | PushMFAProvider 重构 | **P1** |
| **4** | ④ 安全面板 | ★★★★ | ~1200 行 | 低 | anomaly / threataction / tokenusage（已存在） | **P2** |
| **5** | ⑤ 令牌敏感度 Phase 1 | ★★★★★ | ~600 行 | 中 | 无（独立交付 Phase 1: scope 映射 + TTL 缩短） | **P2** |
| **6** | ③ 推送通知 Phase 2-3 | ★★★ | ~1000 行 | 中 | Phase 1 完成 | **P2-P3** |
| **7** | ⑤ 令牌敏感度 Phase 2-3 | ★★★★ | ~1200 行 | 高 | Phase 1 + Refresh Family 重构 | **P3** |

**关键变更为**：
- 方向⑤从 P1 降级为 P2（Phase 1 可独立交付，但完整价值需要 Refresh Family 隔离 + DPoP 强制——两者都是高侵入性变更）
- 方向③ Phase 1 保持在 P1 但拆分为独立交付物（PushSender SPI + FCM 实现）
- 方向② 和方向① 保持在 P1——它们是独立、低侵入、高消费者价值的方向

### 5.2 阶段划分

#### 阶段 1：消费者认证体验（2-3 周）

聚焦 Magic Link + 账户恢复框架。两者共用 EmailSender + TempTokenStore 基础设施。

```
Sprint 1A: Magic Link（方向②）
├── 交付: POST /auth/magic-link + GET /auth/magic-link/verify + 邮件模板 + SPA UI
├── 工作量: ~300 行 Go + ~100 行 JS + 1 个模板
├── 验收: E2E 测试：输入邮箱 → 收到邮件 → 点击链接 → 登录成功
└── 安全验收: 统一响应防枚举、单次使用、TTL 15 分钟、重新发送使旧 token 失效

Sprint 1B: 自助账户恢复框架（方向① Phase 1）
├── 交付: POST /auth/recover/{initiate,verify,complete} + RecoveryStore (memory)
├── 工作量: ~600 行 Go
├── 验收: E2E 测试：全丢失 → 邮箱验证 → 恢复成功 → 设置新凭据
└── 安全验收: 多方法组合验证、防枚举、恢复通知原所有者

Sprint 1C: PushSender SPI + FCM 实现（方向③ Phase 1）
├── 交付: PushSender SPI + FCM 实现 + PushMFAProvider 重构（webhook 保留）
├── 工作量: ~500 行 Go（含 FCM OAuth 令牌管理 ~200 行）
├── 验收: PushMFAProvider 可通过 FCM 通道发送推送通知
└── 依赖: Google 服务账户凭据（测试环境）
```

#### 阶段 2：安全治理与运维（4-6 周）

聚焦安全面板 + 令牌敏感度 Phase 1。

```
Sprint 2A: 安全运维面板（方向④）
├── 交付: POST /admin/security/overview + sessions/terminate + timeline + SPA
├── 工作量: ~800 行 Go + ~800 行 JS
├── 验收: 面板显示实时数据、可批量终止会话、趋势图正确
└── 安全: admin:security scope 保护

Sprint 2B: 令牌敏感度分类 Phase 1（方向⑤ Phase 1）
├── 交付: ScopeSensitivity 映射 + 签发路径 TTL 缩短 + 增强审计
├── 工作量: ~600 行 Go
├── 验收: admin:write 令牌 TTL < openid 令牌 TTL、审计记录包含敏感度级别
└── 兼容: 默认关闭，开启后不影响现有 client

Sprint 2C: 设备注册 API（方向③ Phase 2）
├── 交付: DeviceStore SPI + /me/devices CRUD + memory 实现
├── 工作量: ~500 行 Go
├── 验收: 用户注册/列出/删除设备
└── 依赖: Sprint 1C 的 PushSender SPI
```

#### 阶段 3：深度安全（4-6 周）

聚焦令牌敏感度 Phase 2 + 推送登录审批。

```
Sprint 3A: Refresh Family 隔离（方向⑤ Phase 2）
├── 交付: 按敏感度级别的 Refresh Family 隔离 + 全部 4 个后端实现
├── 工作量: ~800 行 Go
├── 验收: Standard 级别 refresh 轮换不影响 Critical 级别
└── 迁移: 现有 refresh token 默认 Standard 级别

Sprint 3B: DPoP 强制 + Refresh Step-up（方向⑤ Phase 2-3）
├── 交付: admin:* scope 要求 DPoP + 高敏感 token refresh 要求 step-up
├── 工作量: ~600 行 Go
├── 验收: 请求 admin:write 无 DPoP → invalid_scope、高敏感 refresh 要求重新认证

Sprint 3C: 推送登录审批（方向③ Phase 3）
├── 交付: 新设备登录推送通知 + 推送内"是否你"操作
├── 工作量: ~400 行 Go + ~300 行 JS
├── 验收: 新设备登录时用户收到推送通知，可批准/拒绝
```

### 5.3 风险矩阵

| 风险 | 概率 | 影响 | 缓解策略 |
|---|---|---|---|
| Magic Link 被钓鱼利用 | 中 | 高 | 邮件中显示登录上下文（IP、设备、时间）；短 TTL（15min）；每次新链接使旧链接失效；一次性使用 |
| 账户恢复的枚举攻击 | 低 | 高 | 所有入口返回统一响应；速率限制（每用户每小时 3 次）；多方法组合（至少 2 种不同方法） |
| FCM OAuth 令牌刷新时机导致推送失败 | 中 | 中 | 令牌提前刷新（TTL 过半时异步刷新）；失败时重试 1 次（新令牌）；不缓存到磁盘（重启后重新获取） |
| 安全面板在百万会话级别时性能不达标 | 中 | 中 | 统计查询使用预计算（Redis SCARD / Postgres 物化视图）；面板数据缓存 30 秒；超时 500ms 降级 |
| Refresh Family 隔离导致已存在的 refresh token 不兼容 | 高 | 低 | 不迁移现有 refresh token——它们默认属于 Standard 级别。隔离只影响开启后新签发的令牌 |
| DPoP 强制导致不支持的客户端无法使用 admin scope | 中 | 中 | `invalid_scope` 响应明确提示需要 DPoP；文档化迁移指南；提供客户端库（ssoclient/rs 已支持 DPoP） |
| 推送通知的隐私合规（GDPR 数据传输） | 低 | 高 | FCM/APNS 推送负载不包含个人数据（只有 challenge_id + title/body）；设备令牌不关联用户身份（使用随机 device_id） |

### 5.4 跨方向依赖关系图

```
阶段 1 (2-3周)                 阶段 2 (4-6周)                阶段 3 (4-6周)
┌────────────────────┐       ┌────────────────────┐        ┌────────────────────┐
│ ② Magic Link        │       │ ④ 安全面板          │        │ ⑤ Phase 2-3        │
│ (独立, 400行)        │       │ (聚合现有 API)       │        │ (Refresh隔离+DPoP)  │
└────────────────────┘       └────────────────────┘        └────────────────────┘
                                                                         ↑
┌────────────────────┐       ┌────────────────────┐        ┌────────────────────┐
│ ① 账户恢复 Phase 1  │       │ ⑤ Phase 1           │───────│─ ⑤ Phase 2 依赖    │
│ (独立, 600行)        │       │ (scope映射+TTL缩短)  │        └────────────────────┘
└────────────────────┘       └────────────────────┘
                                                                         
┌────────────────────┐       ┌────────────────────┐        ┌────────────────────┐
│ ③ PushSender+FCM   │       │ ③ Phase 2           │        │ ③ Phase 3          │
│ (独立, 500行)        │       │ (设备注册API)        │        │ (推送登录审批)       │
└────────────────────┘       └────────────────────┘        └────────────────────┘
```

### 5.5 与前期架构分析的合并建议

v9 的五方向 + 前期架构分析的五方向（授权管道、Session Hub 登出、Token Proxy、状态 Fuzzing、硬件 Attestation）存在互补关系：

| 协同组合 | 方向 | 协同价值 |
|---|---|---|
| **账户恢复 + 授权管道** | ① + 前期 A | 恢复流程中如果用户 IAL 级别不足，触发 step-up 认证后再进入授权管道——概念上同源 |
| **Magic Link + Token Proxy** | ② + 前期 C | Token Proxy 可以为非 Go 服务验证 Magic Link 签发的 access_token——验证逻辑一致 |
| **推送通知 + Session Hub 登出** | ③ + 前期 B | 推送通道可逆向用于登出通知——"你已在其他设备登出"推送 |
| **令牌敏感度 + 授权管道** | ⑤ + 前期 A | 令牌敏感度是授权管道的输入信号——Critical 级别的令牌需要更高的信任要求 |
| **安全面板 + 状态 Fuzzing** | ④ + 前期 D | Fuzzing 发现的异常可推送到安全面板的事件时间线——"OAuth 状态机异常检测" |

**合并路线图建议**：

```
Phase A (P1): 消费者认证体验 + Session Hub 登出
  → Magic Link + 账户恢复 + Session Hub 登出（3 个独立 sprint）

Phase B (P1-P2): 推送通知 + 状态 Fuzzing
  → PushSender/FCM + 状态机 Fuzzing（基础设施和验证同时进行）

Phase C (P2): 安全运维 + 令牌敏感度 Phase 1 + Token Proxy
  → 安全面板、Scope 映射/TTL 缩短、Edge Token Proxy MVP

Phase D (P3): 深度安全 + 授权管道
  → Refresh Family 隔离、DPoP 强制、授权决策管道、硬件 Attestation
```

---

## 附录 A：与 v9 报告的分歧说明

| v9 报告结论 | 本分析立场 | 理由 |
|---|---|---|
| 方向①包含 IAL 作为 Phase 2 | **拆分**：账户恢复（方向①-a）与 IAL（合并到 v7 方向 2） | 同行评审确认 IAL 与 v7 方向 2 重叠。避免重复建设 |
| 方向③ Phase 1 工作量 M | **上调为 M-L** | 同行评审确认 FCM OAuth 令牌管理 + APNS HTTP/2 连接池 + PushMFAProvider 重构被低估 |
| 方向⑤ IssueToken 在各算法 issuer 中 | **校正**：在 `defaulttoken/jwt_issuer.go:57` | 同行评审发现错误。不影响核心结论但简化集成设计 |
| 方向⑤优先级 P2 | **赞同但分层细化** | Phase 1（scope 映射 + TTL 缩短）P2，Phase 2-3（Refresh 隔离 + DPoP 强制）P3 |
| 方向②设计最优 | **赞同** | 确认已有基础设施（EmailSender + TempTokenStore）足够支撑 |
| 五个方向"零重叠" | **指出重叠**：方向① IAL 与 v7 方向 2 重叠 | 同行评审发现的不准确声明。本分析已做拆分处理 |

## 附录 B：预估工作量汇总

| 方向 | 组件 | Go 行数 | JS/模板行数 | 后端改动 | 总人天 |
|---|---|---|---|---|---|
| ② Magic Link | 认证端点 + 模板 + SPA | 300 | 150 | 新增 2 个端点 | 5-7 |
| ① 账户恢复（Phase 1） | 3 个恢复端点 + RecoveryStore | 600 | 0 (复用现有登录页) | 新增 3 个端点 + 1 个 SPI | 8-10 |
| ③ 推送 Phase 1 | PushSender SPI + FCM + APNS + PushMFA 重构 | 800 | 0 | 新增 1 个 SPI + 2 个 impl + 重构 1 个 provider | 12-15 |
| ④ 安全面板 | 4 个聚合 API + SPA 页面 | 800 | 800 | 新增 4 个端点 | 10-12 |
| ⑤ Phase 1 | Scope 映射 + TTL 缩短 + 增强审计 | 600 | 0 | 修改签发路径 | 6-8 |
| ③ Phase 2 | DeviceStore SPI + 设备 CRUD | 500 | 200 | 新增 1 个 SPI + 5 个端点 | 6-8 |
| ⑤ Phase 2 | Refresh Family 隔离 | 800 | 0 | 修改 4 个后端 | 10-12 |
| ⑤ Phase 3 | DPoP 强制 + Step-up | 600 | 0 | 修改签发路径 + DPoP | 6-8 |
| **总计** | | **5000** | **1150** | | **63-80** |

---

*本分析基于 `expansion-directions-v9-analysis.md`（v9 评估报告）和 `expansion-directions-v9-analysis.out.md`（同行评审），结合项目架构建模。所有建议均遵循 AGENTS.md 的工程原则、DIRECTORY_MAP.md 的分层模型和 maintainability gates。*
