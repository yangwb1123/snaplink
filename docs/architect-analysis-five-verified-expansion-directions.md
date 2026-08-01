# 架构分析报告：五项已验证的扩展方向（交叉验证后）

> **分析师：** 资深架构师 Agent  
> **日期：** 2026-07-12  
> **基于：** 交叉验证报告（五项产品级扩展方向验证）+ 全代码库 grep 实证  
> **前置分析参考：** `docs/architect-analysis-v6-five-directions.md`（后端基础设施方向）、`docs/feature-spec-architecture-analysis-five-verified-directions.md`（前端/产品方向）  
> **状态：** 五项方向中三项为**真缺口**，两项需标注来源关系  
> **输出格式：** 本文件为独立架构级分析，后续可拆分为 `docs/feature-spec-*.md`

---

## 1. 架构评估

### 1.1 当前架构的总体状态

本项目历经 60+ 轮系统分析，架构成熟度已达行业顶级水平。从架构角度看，当前系统处于一个有趣的拐点：

| 阶段 | 状态 | 说明 |
|------|------|------|
| **协议完备性** | ✅ 完成 | OAuth 2.0 + OIDC + SAML 2.0 + SCIM + FAPI + CAEP/RISC + CIBA + 所有标准 grant |
| **存储多样性** | ✅ 完成 | Memory / SQLite / Redis / etcd / PostgreSQL（各 store 均可选切换） |
| **安全姿态** | ✅ 完成 | EdDSA/ES256/RS256/PS256 + KMS 集成 + bcrypt + 常量时间比较 + DPoP/mTLS |
| **多副本协调** | ✅ 完成 | 集群总线 + 跨副本撤销 + 签名键聚合 + 协调轮换 |
| **管理面** | ✅ 完成 | Admin gRPC/REST + SPA + 开发者门户 + 自助门户 + 托管登录页 |
| **运维工具体系** | 🟡 进行中 | 配置验证 CLI、能力注册表、GitOps diff 算子已完成，但配置 APPLY/CI 门禁未完成 |
| **前端全球化** | ❌ 未开始 | 4 个 SPA 全部硬编码英语，零 i18n 实现 |
| **移动端支持** | ❌ 未开始 | 零原生 SDK（iOS/Android），也无 Passkey 原生桥接 |

### 1.2 当前架构的优势（与本次验证相关）

| 优势 | 表现 | 与五大扩展方向的关系 |
|------|------|---------------------|
| **SPI 驱动架构** | 每个横切关注点 = interface + 多个实现，可插拔 | Passkey 可插为新 authenticator；VC 可插为新 token 格式；移动 SDK 吃现成 API |
| **协议层与展示层分离** | `/auth/login` 纯 JSON 契约，SPA 是可选的前端 | 移动 SDK 只需消费 JSON API，不需内嵌 WebView |
| **模块化子模块模式** | `saml/`、`kms/*`、`redis/` 等独立 go.mod | 移动 SDK 可为独立仓库；GitOps 算子可为独立模块 |
| **集群总线基础设施** | `cluster.Bus` + etcd/Redis/MQTT 后端 | 跨集群联邦总线可直接复用 |
| **渐进式配置模式** | 所有 `With*` 默认 nil = 当前行为 | GitOps 控制器的 config APPLY 模式可作为 opt-in 扩展 |

### 1.3 当前架构的瓶颈与局限性

与本次验证的五个方向直接相关的架构瓶颈：

#### 瓶颈一：认证因子扩展点未到达传输层

当前 `core.Authenticator` SPI 设计为"验证身份"的纯逻辑接口：

```go
type Authenticator interface {
    Init(ctx, req) (*core.InitResult, error)
    Authenticate(ctx, req) (*core.AuthResult, error)
}
```

这个 SPI 对 WebAuthn（Passkey）的"本地设备认证"处理是正确的——WebAuthn 的 `BeginRegistration`/`FinishRegistration` 被封装在 `WebAuthnRegistrar` SPI 中。但 FIDO2 **混合传输（hybrid transport）** 需要：

1. 发现对端设备（通过 QR 码/蓝牙/云中继）
2. 建立安全通道（cross-device 加密隧道）
3. 传输认证断言

当前 `Authenticator` SPI 没有"传输层协商"的概念——它假设 auth 过程在**同一设备**上完成。要将 hybrid transport 接入，需要在 authenticator 和请求处理之间新增一个**传输发现层**。

#### 瓶颈二：令牌格式系统不可扩展

当前 token 被硬编码为两种格式：

```
issuer.go:  MintAccessToken(ctx, sub, clientID, scopes, ...) → *core.AccessToken
            MintIDToken(ctx, ...) → *core.IDToken
```

Verifiable Credentials（OID4VCI/OID4VP）引入了一种**全新的 token 格式**——它不是 JWT 的变体，而是带有选择性披露（SD-JWT/BBS+）和可验证演示（VP）的凭证格式。当前 issuer/validator 的接口完全围绕 JWT 设计，SD-JWT 的支持需要在格式层面插入。

#### 瓶颈三：部署配置模型仅面向"运行态"，无"期望状态"概念

当前配置模型的架构：

```
config.yaml → cmd/sso-server 读取 → runtime config（运行态）
                                               ↓
                    config/cluster-diff（比较两个运行态——没有期望状态）
```

GitOps 身份基础设施需要反转这个模型：

```
Git repo（期望状态）→ GitOps reconciler → sso-server config APPLY API → 运行态
```

这要求新增：
- **声明式配置模型**（与当前 config.yaml 兼容但可独立于运行时）
- **三向 diff**（期望 vs 运行 vs 基线）
- **APPLY 端点**（带 dry-run + 审批流程）

当前 `platform/configaudit` 只有 diff（比较两个运行集群），没有 apply 能力。

#### 瓶颈四：`core.Subject` 无跨集群身份绑定

`core.Subject` 在当前模型中代表了"此 SSO 管理的用户"：

```go
type Subject struct {
    ID         string
    TenantID   string
    Identities []Identity  // 仅本地身份源
}
```

跨集群联邦需要在 `Subject` 中新增：
- **SPIFFE ID**（`spiffe://trustdomain.local/ns/default/sa/myapp`）
- **外部队落信任状态**（federated_identity 集合）
- **跨集群 token 桥接记录**（哪个集群的什么令牌映射到此 subject）

#### 瓶颈五：无"移动端优先"的 API 契约

当前所有 API 设计为 HTTP JSON（面向浏览器/后端）。移动端 SDK 需要的不仅仅是 JSON 封装：

| 移动端需求 | 当前状态 |
|-----------|---------|
| 原生 PKCE + 浏览器跳转（ASWebAuthenticationSession/Chrome Custom Tab） | ❌ 无封装 |
| 安全存储（iOS Keychain / Android EncryptedSharedPreferences） | ❌ 无封装 |
| 推送通知（远程撤销通知） | ❌ 无封装 |
| 离线令牌验证（不依赖网络验 local JWT） | ❌ 无封装 |
| 设备生物识别绑定（Face ID / 指纹） | ❌ 无封装 |

---

## 2. 扩展方向分析

### 2.1 方向一：Passkey 跨设备认证（FIDO2 Hybrid Transport）——P0

#### 为什么需要（业务价值）

| 价值 | 说明 |
|------|------|
| **用户体验革命** | 用户用手机扫码即可在桌面端完成无密码登录——这是 FIDO2 的杀手级场景 |
| **行业标准方向** | Apple、Google、Microsoft 全面推行 Passkey，2025-2026 年是 Passkey 的临界点 |
| **安全提升** | 相比输入密码 + OTP，hybrid transport 是加密安全的跨设备认证，抵抗钓鱼 |
| **竞品对齐** | Okta、Auth0、Keycloak 均已支持 Passkey——这是身份平台的标配能力 |
| **利用已有投资** | SSO 已有 WebAuthn 注册/认证能力（`domains/authenticators/webauthn`、`WebAuthnRegistrar` SPI），hybrid transport 是扩展而非重写 |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **传输层发现** | H | Hybrid transport 需要 QR 码 / 蓝牙 / 互联网中继协商。QR 模式最简单（手机扫桌面码，通过 FIDO 联盟的云中继服务传递断言），但引入了对外部中继的依赖 |
| **第三阶段加密隧道** | H | FIDO2 hybrid transport 实际是两个设备间的 ECDH 密钥协商 + 加密通道——这就是一个迷你的 Noise Protocol 实现 |
| **SSO 在哪儿** | M | Hybrid transport 的 RP（Relying Party）是 SSO 本身。浏览器 SSO 页面显示 QR 码 → 手机扫描 → 手机与 RP 通信 → RP 返回成功给浏览器。但 SSO 的当前认证流是同步 HTTP 的——hybrid transport 需要**异步轮询**（浏览器不断问 RP："手机验证完成了吗？"） |
| **WebAuthn 与 Hybrid 的整合** | M | 现有 WebAuthn 实现假设"同一设备"（浏览器 navigator.credentials.create/get）。Hybrid 需要分为"QR 显示"（桌面）和"断言签署"（手机）两阶段 |
| **中继依赖** | M | FIDO2 hybrid 依赖一个名为 "FIDO 联盟的云中继服务"（可自托管或使用公共实例）——这是 SSO 新引入的外部依赖 |

#### 架构设计

**核心架构变更：新增"传输发现层"**

当前认证流程：
```
User → 浏览器 → /auth/login → Authenticator.Authenticate() → token
```

Hybrid transport 流程：
```
User → 浏览器 → /auth/login?passkey=hybrid
                   ↓
              SSO 生成 session + QR 码（含临时通道 ID）
                   ↓
              浏览器显示 QR 码 + 轮询 /auth/login/poll/{session}
                   ↓
          ┌──────手机扫描 QR 码──────┐
          │                          │
      手机与 FIDO 中继通信        手机与 SSO Hybrid 端点通信
      （签署断言）                  （提交签名结果）
          │                          │
          └──────────┬───────────────┘
                     ↓
              浏览器轮询到结果 → Authenticate() 完成 → token
```

**新增组件：**

```
domains/authenticators/
├── webauthn/          ← 已有（同一设备 WebAuthn）
│   ├── webauthn.go
│   ├── registration.go
│   ├── authentication.go
│   └── ...
└── passkeyhybrid/     ← 新增（跨设备 Passkey Hybrid）
    ├── hybrid.go         ← Authenticator 实现
    ├── transport.go      ← ECDH 密钥协商 + 加密通道
    ├── relay.go          ← FIDO 中继服务客户端（可选多中继后端）
    ├── qr.go             ← QR 码生成 + session 绑定
    └── poll.go           ← 轮询端点处理
```

**关键设计决策：Hybrid 中继依赖**

| 选项 | 优点 | 缺点 |
|------|------|------|
| **A: FIDO 联盟公共中继** | 零运维；用户手机信任公共中继 | 外部依赖；如果中继不可用则功能降级（fail-open 到同一设备 WebAuthn） |
| **B: 自托管中继** | 完全控制；无外部依赖；数据不出网络边界 | 运维成本；需要 WebSocket 或 SSE 基础设施 |
| **C: 无中继——仅 QR + 本地网络** | 无外部依赖；极低延迟 | 仅限同一局域网；用户场景受限 |

**推荐混合策略：默认 A，可选 B。** 理由：
- FIDO 联盟的公共中继是 FIDO2 hybrid 标准设计的一部分——Apple 和 Google 都使用相同的公共中继
- 如果 SSO 部署在隔离网络（air-gapped），自托管中继是合规必需
- 同一局域网检测可作为 fallback（无中继时自动尝试）

**轮询 vs WebSocket 决策：**

| 方案 | 优点 | 缺点 |
|------|------|------|
| **轮询（推荐）** | 无持久连接；与现有基础设施一致；超时简单 | 延迟略高（~500ms 轮询间隔） |
| **WebSocket/SSE** | 实时通知；减少请求数 | 需要持久连接管理；负载均衡需支持 WebSocket；增加架构复杂度 |

**推荐轮询**。原因：Passkey 认证的体验目标是"扫码后 2-3 秒完成"，500ms 轮询间隔足够。WebSocket 为身份认证场景增加了不必要的连接管理。用户是**人**——人的感知时间是秒级，不是毫秒级。

#### 与现有 WebAuthn 的整合

```
Authenticator SPI
├── Authenticate(ctx, req) → AuthResult
├── Init(ctx, req) → InitResult  （用于 MFA 挑战）
└── 新增（Hybrid 需要）：
    ├── CanHybrid() bool               ← WebAuthn 返回 true，Password 返回 false
    ├── BeginHybrid(ctx, req) → HybridSession  ← 生成 QR 码 + 通道 ID
    └── CompleteHybrid(ctx, sessionID, assertion) → AuthResult  ← 手机提交结果
```

**不修改 `core.Authenticator` 核心接口**——而是新增一个可选的 `HybridCapable` 接口（类似 Go 的接口惯用法）：

```go
// HybridCapable 是可选的 Authenticator 扩展接口。
// 实现此接口的 Authenticator 支持 FIDO2 跨设备混合传输。
type HybridCapable interface {
    // CanHybrid 如果当前环境支持混合传输返回 true。
    CanHybrid(ctx context.Context, req *core.AuthRequest) bool

    // BeginHybrid 启动混合传输会话。
    // 返回一个编码为 QR 码的传输令牌和会话 ID。
    BeginHybrid(ctx context.Context, req *core.AuthRequest) (*HybridSession, error)

    // CompleteHybrid 完成混合传输认证。
    // 手机侧通过 FIDO2 中继或直接端点提交断言。
    CompleteHybrid(ctx context.Context, sessionID string, assertion []byte) (*core.AuthResult, error)
}

type HybridSession struct {
    SessionID   string `json:"session_id"`
    QRData      string `json:"qr_data"`     // URL（含通道 ID）
    ExpiresAt   time.Time `json:"expires_at"`
    RelayURL    string `json:"relay_url,omitempty"`   // 中继服务地址
}
```

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 新增包 | `domains/authenticators/passkeyhybrid/`（~400 行） |
| 新增端点 | `GET /auth/hybrid/begin`（返回 QR 码数据）、`GET /auth/hybrid/poll/{session}`（轮询）、`POST /auth/hybrid/complete`（手机提交） |
| Authenticator SPI | **不修改**——新增可选 `HybridCapable` 接口 |
| 后端变更 | 新端点 + 轮询 session 存储（复用现有 session 基础设施或新增轻量 map） |
| 前端变更 | Login SPA 新增 QR 码渲染组件（`qrcode.js`，~100 行，可使用 `qrcode-generator` 轻量库或自建） |
| 外部依赖 | FIDO 联盟公共中继（可选自托管） |
| 向后兼容 | 完全兼容——`?passkey=hybrid` 是新的登录选项，不影响现有密码/WebAuthn/MFA 流 |

---

### 2.2 方向二：Verifiable Credentials（OID4VCI/OID4VP）——P1

#### 为什么需要（业务价值）

| 价值 | 说明 |
|------|------|
| **行业趋势** | EU Digital Identity Wallet（eIDAS 2.0）要求 2026 年前支持 OID4VCI/OID4VP。这是欧洲市场的合规要求 |
| **选择性披露** | SD-JWT/BBS+ 允许用户只披露必要属性（"证明我 > 18 岁"而不暴露生日）——隐私增强 |
| **可验证演示** | OID4VP 允许持有者向 RP 展示 VC，而 RP 不需回源 IdP——离线场景的关键 |
| **竞争差异** | 多数竞品（Auth0/Okta）尚未深度支持 OpenID4VC——这是率先进入市场的窗口 |
| **与现有 SSO 的故事** | SSO 将不仅颁发 "JWT"（access/id_token），还能颁发 "Verifiable Credential"——成为"身份凭证工厂" |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **凭据格式生态** | H | SD-JWT、BBS+、JSON-LD + Zero-Knowledge Proofs……每个格式有自己的加密原语和选择性披露机制。选择哪个？全部支持？ |
| **Token 格式扩展性** | H | 当前 issuer/validator 围绕 JWT（compact serialization）设计。VC 的格式（SD-JWT 仍是 JWT 变体，但携带 disclosure array；BBS+ 是完全不同的签名方案）需要 issuer SPI 扩展 |
| **OID4VCI 协议** | M | 带授权/预授权 code flow 的凭证发行协议——类似 OAuth 2.0 但增加 `credential_offer` 端点、`credential_issuer` metadata 等 |
| **OID4VP 协议** | H | 凭证演示协议——RP 发 `presentation_definition`，Wallet 返回 `presentation_submission` + `verifiable_presentation`。包含查询语言（`presentation_definition` 的 JSON-LD 查詢语法，或 SD-JWT 的 `vp_token`） |
| **钱包生态** | M | VC 需要一个"钱包"（数字身份钱包）。SSO 是否要自己构建钱包？还是仅作为 issuer/verifier？ |
| **凭证生命周期** | M | 吊销、过期、更新的管理——VC 可以长寿命（离线可用），吊销成为一个挑战（当前 JWT 的 `exp` 短寿命 + 在线验证模式 > VC 离线模式） |

#### 架构设计

**核心架构决策：SSO 的 VC 角色**

```
                  发行凭证               保存凭证
    SSO（Issuer） ─━━━━━━━━━━━━━━→ 用户钱包（Wallet）
        │                                    │
        │         请求演示凭证                │
        │ ←━━━━━━━━━━━━━━━━━━━━━             │
        │                                    │
        ↓　验证凭证                           ↓
    资源服务器（Verifier） ←━━━━━━━━━━ 用户钱包
```

**决策：SSO 作为 Issuer + Verifier，不做 Wallet。**
- Issuer：SSO 颁发 Verifiable Credential（用户属性的已签名声明）
- Verifier：SSO 的 `/userinfo` 或新端点可验证 VC
- Wallet：留给第三方（Apple Wallet、Google Wallet、EU Digital Identity Wallet）或未来独立项目

**Token 格式选择：SD-JWT（第一阶段）→ BBS+（第二阶段）**

| 格式 | 第一阶段（P1） | 第二阶段（P2） |
|------|--------------|--------------|
| SD-JWT（RFC 9449-ish） | ✅ 选择——JWT 变体，最平滑引入 | 保留 |
| BBS+（multi-message signatures） | ❌ 复杂度高 | ✅ 选择性披露 + 多消息聚合 |
| JSON-LD + ZKP | ❌ 超出范围 | ❌ 超出范围 |
| mDL（ISO 18013-5） | ❌ 超出范围 | ❌ 超出范围 |

理由：SD-JWT 是 JWT 的超集——当前 issuer 的签名逻辑（EdDSA/ES256/RS256）可直接复用。SD-JWT 携带的 `_sd`（选择性披露声明）和 `_sd_alg` 是新增包装层，不改变底层签名。

**新增组件：**

```
protocols/
├── oauth/                        ← 已有
├── oidc/                         ← 已有
├── saml/                         ← 已有
└── oid4vc/                       ← 新增
    ├── issuer.go                 ← OID4VCI Issuer 实现
    ├── verifier.go               ← OID4VP Verifier 实现
    ├── credential_offer.go       ← credential_offer 端点 + 元数据
    ├── presentation_definition.go ← presentation_definition 解析
    ├── sd_jwt.go                 ← SD-JWT 格式（选择性披露编码/解码）
    ├── disclosure.go             ← Disclosure 管理
    └── wallet_client.go          ← 颁发/验证协议客户端

shared/
├── security/
│   ├── ...（现有）...
│   └── sd_jwt.go                 ← SD-JWT 核心密码学（哈希、salt、_sd 数组排序）
```

**issuer SPI 扩展（最小修改）：**

```go
// 在现有 Issuer 接口旁新增 VC 颁发能力
type CredentialIssuer interface {
    // IssueSDJWT 颁发 SD-JWT 格式的 Verifiable Credential。
    IssueSDJWT(ctx context.Context, req *SDJWTRequest) (*SDJWT, error)

    // VerifySDJWT 验证 SD-JWT 并返回披露的声明。
    VerifySDJWT(ctx context.Context, sdJWT string, disclosureKeys []string) (*SDJWTVerifyResult, error)
}

type SDJWTRequest struct {
    Subject     core.Subject
    Claims      map[string]interface{} // 所有可声明的属性（由 presentation_definition 筛选）
    HolderKey   *crypto.PublicKey      // holder 公钥（绑定 VC 给特定 holder）
    ExpiresAt   time.Time
    Issuer      string                 // credential_issuer URL
}
```

**OID4VCI 协议流：**

```
SSO metadata: /.well-known/openid-credential-issuer
                  ↓
Wallet 获取 issuer metadata（credential_configurations_supported、authorization_server）
                  ↓
1. 授权：OAuth 2.0（现有 SSO 流程）→ 授权 code
2. Token：code → access_token + c_nonce
3. 发行：POST /credential（带 access_token + proof（JWT with c_nonce））
   响应：Verifiable Credential（SD-JWT）
```

**OID4VP 协议流（第一阶段：相同设备）：**

```
RP POST /verify/presentation（带 presentation_definition）
    ↓
SSO 验证持有者身份 → 生成授权请求（包含 presentation_definition）
    ↓
Wallet 解析 presentation_definition → 选择凭据 → 构造 VP Token
    ↓
POST /verify（带 vp_token + presentation_submission）
    ↓
SSO 验证 VP → 返回验证结果
```

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 新增包 | `protocols/oid4vc/`（~1000 行）+ `shared/security/sd_jwt.go`（~200 行） |
| 新增端点 | `/.well-known/openid-credential-issuer`（元数据）、`POST /credential`（发行）、`POST /verify`（验证） |
| Token 格式 | 新增 SD-JWT 格式，不影响现有 JWT（access_token/id_token）路径 |
| Issuer SPI | 新增可选 `CredentialIssuer` 接口，不影响现有 `TokenIssuer` |
| 后端变更 | 新协议层，零改动现有 OAuth/OIDC 核心 |
| 向后兼容 | 完全兼容——`credential` 端点是 OAuth 2.0 的扩展，不影响现有 grant 流程 |
| 新增依赖 | SD-JWT 不需要新依赖（SHA-256 已在标准库）；BBS+ 需要 BLS 签名库（第二阶段） |
| 外部依赖 | 无（除 future BBS+） |

---

### 2.3 方向三：原生移动端 SDK（iOS / Android）——P1

#### 为什么需要（业务价值）

| 价值 | 说明 |
|------|------|
| **移动端用户 > 桌面端** | 大多数用户通过手机访问服务。没有原生 SDK = 移动端只能使用 WebView 登录，体验和安全性都不如原生 |
| **PKCE + 浏览器跳转** | OAuth 2.0 for Mobile Apps 的最佳实践是外部浏览器（ASWebAuthenticationSession / Chrome Custom Tab），而不是嵌入式 WebView——但当前 SSO 没有提供封装好的 Swift/ Kotlin 库 |
| **安全基线** | 原生 SDK 确保 client_secret 不泄露（使用 `client_id` + PKCE 而非 secret）、令牌安全存储（iOS Keychain / Android EncryptedSharedPreferences） |
| **竞品对齐** | Auth0 提供 30+ SDK、Okta 提供 10+ SDK、Keycloak 有 Keycloak Kotlin 和 Swift 库——没有原生 SDK 是 RFP 明晃晃的减分项 |
| **Passkey 的移动场景** | FIDO2 hybrid transport（方向一）和移动 SDK 天然互补——移动 SDK 是 hybrid transport 的手机端（Wallet/验证器角色）的自然载体 |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **SDK 维护成本** | H | 两个语言（Swift/Kotlin）+ 两个生态（iOS/Android）的长期维护。需要 CI 矩阵、示例应用、文档 |
| **API 稳定性** | M | SDK 应该包装哪些 API？如果只包装 OAuth/OIDC 核心（`/authorize`、`/token`、`/userinfo`），API 稳定。但如果 SDK 也包装 admin/self-service API（那些仍在快速演进），SDK 会持续跟随后端变化 |
| **安全存储** | M | iOS Keychain 和 Android EncryptedSharedPreferences 的使用模式不同——SDK 需要提供统一接口 |
| **令牌刷新** | M | 移动场景下 token refresh 需要处理"应用被杀死后恢复"、"多屏"、"后台刷新"等边界 |
| **SSO 登录的浏览器跳转** | M | ASWebAuthenticationSession / Chrome Custom Tab 的回调路由（custom scheme → 应用）需要正确配置 |
| **推送通知** | L | 远程撤销通知（如果 CAEP 支持）原生 SDK 可接收推送 → 清除本地令牌 |

#### 架构设计

**核心架构决策：独立仓库 + API 第一设计**

```
github.com/snaplink/sso        ← 核心 Go 仓库
github.com/snaplink/sso-swift   ← iOS SDK（独立仓库）
github.com/snaplink/sso-kotlin  ← Android SDK（独立仓库）
```

理由：
1. Go 仓库的 `go.mod` 不应引入 Swift/Kotlin 生态
2. SDK 的发布节奏（跟随 iOS/Android 版本）与后端不同
3. 两个 SDK 不需要同步发布
4. SDK 开发者不需要了解 Go

**SDK 范围（第一阶段：核心 OAuth/OIDC）：**

```swift
// Swift SDK（第一阶段 API）
public class SnaplinkSSO {
    // 授权：外部浏览器 + PKCE
    public func authorize(
        clientID: String,
        redirectURI: URL,
        scopes: [String],
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding
    ) async throws -> TokenResponse
    
    // 令牌管理：安全存储 + 自动刷新
    public func tokenManagement() -> TokenManager
    
    // 用户信息
    public func userInfo(accessToken: String) async throws -> UserInfo
    
    // 登出
    public func endSession(idToken: String, redirectURI: URL) async throws
    
    // 可选：远程撤销通知（通过 CAEP 推送）
    public func enablePushRevocation(deviceToken: Data)
}
```

```kotlin
// Kotlin SDK（第一阶段 API）
class SsoClient(private val config: SsoConfig) {
    // 授权：Chrome Custom Tab + PKCE
    suspend fun authorize(
        clientId: String,
        redirectUri: String,
        scopes: List<String>
    ): TokenResponse
    
    // 令牌管理
    fun tokenManager(): TokenManager
    
    // 用户信息
    suspend fun userInfo(accessToken: String): UserInfo
    
    // 登出
    suspend fun endSession(idToken: String, redirectUri: String)
}
```

**安全存储抽象：**

```swift
// iOS 安全存储 —— 内部使用 Keychain
internal class KeychainTokenStore: TokenStore {
    func storeToken(_ token: TokenResponse) throws
    func retrieveToken() throws -> TokenResponse?
    func clearToken() throws
}
```

```kotlin
// Android 安全存储 —— 内部使用 EncryptedSharedPreferences
internal class EncryptedTokenStore(context: Context): TokenStore {
    fun storeToken(token: TokenResponse)
    fun retrieveToken(): TokenResponse?
    fun clearToken()
}
```

**不做之事（第一阶段）：**

| 不做 | 原因 |
|------|------|
| 不构建 Wallet（不存储 Verifiable Credentials） | 方向二是 VC 的 Issuer/Verifier，Wallet 是独立问题 |
| 不构建混合 transport 的移动端 half | 方向一的移动端 half 是独立模块，SDK 可复用 |
| 不构建管理 API 的移动版本 | Admin Console 是 web 优先，移动端不优先 |
| 不构建推送通知服务器 | 推送通知基础设施的投入大，这是 CAEP 方向的扩展（ROADMAP v5 §④） |

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 新增仓库 | 2 个独立仓库（sso-swift + sso-kotlin），不修改核心仓库 |
| CI 新增 | Swift/Kotlin 的 CI 矩阵（build + test + lint），独立于现有 Go CI |
| 后端变更 | **零变更**——SDK 纯消费现成 HTTP API。如果 SDK 发现 API 需要调整（如某些端点的响应格式不便于移动端解析），需要小幅后端调整 |
| 文档变更 | 新增 SDK 的安装指南 + 快速入门 + 示例应用 |
| 安全影响 | SDK 的安全模型是"零信任后端"——不引入新攻击面 |
| 向后兼容 | SDK 始终调用生产 API，无兼容性问题 |

---

### 2.4 方向四：声明式 GitOps 身份基础设施——P1（需注明来源关系）

> **重要来源关系说明：**  
> `docs/deferred-backlog.md` 已将"声明式多集群配置治理"列为 PARTIAL 实现，明确包含：
> - ✅ `POST /api/v1/admin/config/cluster-diff`（运行集群间 diff）
> - ✅ `SSOConfigDrift` CRD + K8s operator（周期性 drift 检测）
> - ❌ **OUT OF SCOPE**：config APPLY、GitOps reconciler、canary rollout、auto-remediation  
> 
> 本方向将这些 deferred-backlog 中标记为 OUT OF SCOPE 的项提升为一等方向，并增加 PR webhook、审批流、敏感字段加密等新维度。**这不是"未识别"的缺口，而是已有基础的扩展。**

#### 为什么需要（业务价值）

| 价值 | 说明 |
|------|------|
| **配置即代码** | 身份配置（客户端、用户、权限、租户）应像基础设施一样通过 Git 管理——可审计、可追溯、可回滚 |
| **审批流程** | 企业需要"配置变更 → PR → 审查 → 审批 → 自动 apply"的工作流。当前 `sso-ctl config apply` CLI 是手动操作，无审批门禁 |
| **多环境同构** | Dev/Staging/Prod 应通过同一 Git 配置的不同 overlay 管理——当前只能手动逐集群配置 |
| **审计合规** | "谁在什么时候改了什么"在 Git 历史中比在数据库中更透明——Git 操作是经过签名的 |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **反向模型转换** | H | 当前 admin API 是 CRUD（创建/更新/删除单个资源）。GitOps 需要一个'声明式全量'模型——用户提交完整配置 YAML，系统自动计算 diff 并 apply。需要新增 `POST /admin/config/apply` 端点，接受完整配置快照，执行三向 diff（期望 vs 运行 vs 基线） |
| **冲突检测** | M | 如果 Git 中的配置和运行中的配置同时被修改（例如 admin 通过 Console 手动改了一个客户端），apply 时需要检测冲突 |
| **幂等性与顺序** | M | 配置条目之间存在依赖关系（用户依赖组、客户端依赖租户）。Apply 需要拓扑排序 |
| **敏感字段加密** | M | `client_secret`、`registration_access_token` 等字段不应明文存储在 Git 中。需要 SOPS/age/外部 KMS 加密——但 apply 时需要解密 |
| **回滚** | M | Git revert + apply 应该回滚配置——但回滚可能会撤销用户自己的密码更改（非托管状态） |

#### 架构设计

**Config APPLY API（核心新增）：**

```go
// 新增端点：POST /admin/config/apply
type ApplyRequest struct {
    // Desired 是期望的完整配置快照。
    // 格式与 config/running 的响应相同。
    Desired ConfigSnapshot `json:"desired"`

    // DryRun 为 true 时只计算 diff 不做任何更改。
    DryRun bool `json:"dry_run"`

    // ApplyStrategy 指定冲突时如何解决。
    // "fail"（默认）→ 检测到冲突则拒绝 apply
    // "force" → 用期望状态覆盖运行状态
    // "merge" → 三向合并（期望 vs 运行 vs 基线）
    ApplyStrategy string `json:"apply_strategy,omitempty"`

    // Source 标识配置来源（用于审计和回滚）。
    Source string `json:"source"`  // "git:commit:abc123" | "cli:sso-ctl" | "api:admin"
}

type ApplyResponse struct {
    JobID       string         `json:"job_id"`
    Status      string         `json:"status"`  // "accepted" | "dry_run" | "conflict"
    Diff        json.RawMessage `json:"diff,omitempty"`    // RFC 6902 Patch
    Conflicts   []Conflict     `json:"conflicts,omitempty"`
    ChangedBy   string         `json:"changed_by"`
    AppliedAt   time.Time      `json:"applied_at,omitempty"`
}
```

**GitOps Reconciler（新子模块）：**

```
cmd/
├── sso-server/               ← 已有
├── sso-ctl/                  ← 已有
└── sso-gitops-reconciler/    ← 新增子模块（独立 go.mod）
    ├── main.go               ← 控制器入口
    ├── reconciler.go         ← Git → SSO 同步循环
    ├── config_source.go      ← Git 读取（go-git / 本地克隆）
    ├── diff.go               ← 期望 vs 运行 比较
    ├── apply.go              ← POST /admin/config/apply 调用
    ├── encrypt.go            ← SOPS/age 解密
    └── webhook.go            ← Git webhook 处理（自动触发）
```

**PR 审批流程：**

```
开发者修改 Git 中的 config/*.yaml
    ↓
PR 创建 → webhook → sso-gitops-reconciler 执行 dry-run
    ↓
dry-run 结果作为 PR comment 发布（"3 个资源变更，2 个新增，1 个删除"）
    ↓
审查者批准 PR
    ↓
PR merge → webhook → sso-gitops-reconciler 执行 full apply
    ↓
apply 结果 → 更新 PR 状态 / 发送通知
```

**三向 diff 策略：**

```
期望状态（Git） ──────┐
                      ├── Diff（三向合并）
运行状态（SSO） ──────┤
                      │
基线状态（上次 apply ─┘
成功的快照）

merge 策略：
- 如果运行状态 == 基线状态：直接 apply 期望状态（无冲突）
- 如果运行状态 != 基线状态 && 期望状态 == 基线状态：保留运行状态（Git 未改，运行改了）
- 如果三者都不同：conflict（需人工介入）
```

**敏感字段加密：**

`config/*.yaml` 中的 `client_secret` 字段使用 SOPS/age 加密。Reconciler 在 apply 前自动解密：

```yaml
# config/clients/myapp.yaml（加密后）
apiVersion: sso.snaplink.io/v1
kind: Client
metadata:
  name: myapp
spec:
  redirect_uris:
    - "https://app.example.com/callback"
  # 加密字段（使用 age 公钥加密）
  client_secret: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
```

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 新增端点 | `POST /admin/config/apply` |
| 新增子模块 | `cmd/sso-gitops-reconciler/`（新独立 go.mod，约 500 行） |
| configaudit 增强 | 当前 diff-only 端点需增强为 apply-capable |
| 审计增强 | 新增 `EventConfigApplied`、`EventConfigApplyFailed` 等审计事件 |
| CLI 增强 | `sso-ctl config apply` 接受 Git commit 引用 |
| 新依赖 | `go-git`（或其他轻量 Git 库）用于 reconciler |
| 向后兼容 | 完全兼容——apply 端点是全新功能，现有 diff 端点不变 |

---

### 2.5 方向五：跨集群联邦身份数据面——P2（需注明边界关系）

> **重要边界说明：**  
> ROADMAP v5.0 集群视角 C① 已完成**单集群**网格身份数据面：
> - ✅ HTTP+gRPC `ext_authz`（`mesh_authz.go` + `extauthz/`）
> - ✅ SPIFFE JWT-SVID token-exchange
> - ✅ 去中心化 authz policy-bundle 导出
>
> 本方向在此基础上扩展到**跨集群**维度：多 trust domain 联合、跨集群 token 桥接、边缘身份缓存、workload 身份注册表。**这是单集群能力的自然延伸，不是从零开始。**

#### 为什么需要（业务价值）

| 价值 | 说明 |
|------|------|
| **多集群网格身份统一** | 企业运行多个 Kubernetes 集群（prod/staging/dev/us/eu）。跨集群的服务间调用需要统一的身份——不能因为在不同集群就使用不同的 token/证书 |
| **SPIFFE trust domain 联邦** | Istio/Linkerd 每个集群有自己的 `trustDomain`。跨集群调用时，服务 A（`spiffe://cluster-a/ns/app`）需要信任服务 B（`spiffe://cluster-b/ns/app`） |
| **跨集群 token 桥接** | 集群 A 的用户访问集群 B 的服务。当前架构需要用户重新认证一次——跨集群桥接可以透明传递身份 |
| **边缘身份缓存** | 靠近用户的边缘节点（CDN/Edge）缓存身份决策，降低全局延迟 |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **多 trust domain 联合** | H | SPIFFE 的信任联合需要双边交换 bundle（CA 公钥集）。每个联盟需要单独的联合配置——这不是技术难度，而是配置复杂度和安全审计 |
| **跨集群 token 桥接端点** | H | 集群 A 的 `/token/bridge` 端点接受集群 B 的 token（act_as 角色）并返回集群 A 的等价 token。这实际上是本 SSO 的 token-exchange（RFC 8693）的跨集群版本——需要跨集群的 `act` 链验证 |
| **Workload 身份注册表** | H | 工作负载身份（SPIFFE ID、SVID、K8s SA）需要统一注册和查询。这类似于 SPIFFE/SPIRE 的 Registration API——但需要与 SSO 的 client/permission 模型集成 |
| **边缘缓存的一致性** | M | 边缘节点的身份缓存（authz 决策、JWKS 公钥）在撤销/轮换时如何失效？不是强一致（边缘是 AP），但需要最终一致 + TTL |
| **跨集群 mTLS CA** | M | 如果 SSO 作为跨集群 mTLS 的 CA（Certificate Authority），需要管理跨集群的证书签发和吊销——这是 PKI 基础设施的范畴 |

#### 架构设计

**核心架构决策：SPIFFE 联邦作为基础，SSO 作为控制平面扩展**

```
集群 A（trustDomain: cluster-a.sso）         集群 B（trustDomain: cluster-b.sso）
     │                                               │
     │  SPIRE Agent                                   │  SPIRE Agent
     │  ↓                                             │  ↓
     │  SSO（控制平面）                                 │  SSO（控制平面）
     │  ├── Token Bridge Endpoint ←━━━━━━━━━━━━━━━━━━│
     │  ├── Workload Registry ←━━━━━━━━━━━━━━━━━━━━━│
     │  └── mTLS CA ←━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│
     │                                               │
     └─────────────── ext_authz ─────────────────────┘
                      ↓
             服务网格 sidecar（envoy）
```

**新增组件：**

```
platform/
├── cluster/               ← 已有（集群总线）
├── ...
└── federation/            ← 增强
    ├── spire_bridge.go    ← SPIFFE/SPIRE 工作负载身份桥
    ├── trust_domain.go    ← Trust domain 联合配置
    ├── token_bridge.go    ← 跨集群 token 桥接端点
    ├── workload_registry.go ← 工作负载身份注册表
    └── edge_cache.go      ← 边缘身份缓存

interfaces/
├── sso/                   ← 已有
│   ├── server_extensions.go
│   └── ...
└── mesh/                  ← 增强
    ├── ext_authz.go       ← 已有（单集群）
    └── cross_cluster_authz.go ← 跨集群授权
```

**Token Bridge 端点设计：**

```go
// POST /token/bridge
// 跨集群 token 桥接——将集群 B 的 token 转换为集群 A 的等价 token。
type BridgeTokenRequest struct {
    // SourceToken 是源集群（B）签发的 access_token
    SourceToken string `json:"source_token"`

    // SourceTrustDomain 是源集群的 trust domain
    SourceTrustDomain string `json:"source_trust_domain"`

    // DestinationScope 是目标集群（A）中所需的 scope
    DestinationScope string `json:"scope,omitempty"`

    // ActorToken 是请求者的凭据（如果跨集群调用是服务间而非用户间）
    ActorToken string `json:"actor_token,omitempty"`
}

type BridgeTokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`   // "Bearer"
    ExpiresIn    int    `json:"expires_in"`
    IssuedTokenType string `json:"issued_token_type"`
}
```

**流程：**

```
集群 B 的微服务调用集群 A 的微服务：
1. 服务 B 有集群 B 签发的 access_token（带 spiffe://cluster-b/...）
2. 服务 B 调用集群 A 的 SSO /token/bridge：
   - 验证集群 B token 的签名（通过信任联合的公钥）
   - 将 spiffe://cluster-b/... 映射到集群 A 的 subject
   - 签发集群 A 的 access_token（带 spiffe://.../act_as=cluster-b/...）
3. 服务 B 使用新 token 调用集群 A 的服务
4. 集群 A 的 ext_authz 验证 token → 通过
```

**Workload 身份注册表：**

```go
// WorkloadRegistry 管理工作负载身份的注册和查询。
// SPI：可选择 SPIRE 后端（生产）或 memory 后端（测试/演示）。
type WorkloadRegistry interface {
    // Register 注册一个工作负载身份。
    Register(ctx context.Context, wl *WorkloadIdentity) error

    // Resolve 根据 SPIFFE ID 查询工作负载身份。
    Resolve(ctx context.Context, spiffeID string) (*WorkloadIdentity, error)

    // ListByTrustDomain 列出指定 trust domain 下的所有工作负载。
    ListByTrustDomain(ctx context.Context, trustDomain string, limit, offset int) ([]*WorkloadIdentity, error)

    // Revoke 吊销一个工作负载身份。
    Revoke(ctx context.Context, spiffeID string) error
}

type WorkloadIdentity struct {
    SPIFFEID    string            `json:"spiffe_id"`
    TrustDomain string            `json:"trust_domain"`
    Namespace   string            `json:"namespace"`
    SA          string            `json:"service_account"`
    Attributes  map[string]string `json:"attributes,omitempty"`
    Certificate *x509.Certificate `json:"-"`
    ExpiresAt   time.Time         `json:"expires_at"`
    Revoked     bool              `json:"revoked,omitempty"`
}
```

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 新增包 | `platform/federation/`（~600 行）增强 |
| 新增端点 | `POST /token/bridge`、`POST /admin/workloads/*` |
| 增强现有 | `ext_authz` 端点的跨集群支持、`token-exchange` 的跨集群 `act` 链验证 |
| SPI 变更 | `core.Subject` 可能需要 `SPIFFEID` 字段（可选） |
| 向后兼容 | 完全异步——`/token/bridge` 是新端点，`token-exchange` 的跨集群模式是新功能 |
| 新增依赖 | SPIRE 集成库（如果直接对接 SPIRE），或纯 SPI 接口（无依赖） |

---

## 3. 接口设计原则

### 3.1 通用原则

| 原则 | 说明 | 本分析中的应用 |
|------|------|--------------|
| **SPI 不膨胀** | 新功能用可选接口/包裹器模式，不修改现有 SPI | `HybridCapable` 可选接口；`CredentialIssuer` 独立接口；`WorkloadRegistry` 新 SPI |
| **默认 nil = 当前行为** | 新 `With*` 选项默认零值 | Passkey 默认不启用；VC 默认不启用；GitOps reconciler 默认不运行 |
| **fail-open > fail-closed** | 新组件的错误不应降级现有系统 | Transport 中继不可用 → 回退相同设备 WebAuthn（非 500）；GitOps reconcoler 失败 → 保留运行配置 |
| **子模块隔离** | 新功能放独立子模块，不污染核心 go.mod | 移动 SDK（独立仓库）、GitOps reconciler（独立 go.mod）、OID4VC（新 `protocols/oid4vc/`） |

### 3.2 各方向接口映射

| 方向 | 新接口/类型 | 所属包 | 类型 |
|------|-----------|--------|------|
| ① Passkey | `HybridCapable` 可选接口 | `core/spi.go` | 可选接口（不修改 `Authenticator`） |
| ① Passkey | `HybridSession` | `core/types.go` | 值类型 |
| ① Passkey | `BeginHybrid`/`CompleteHybrid` | `domains/authenticators/passkeyhybrid/` | 方法 |
| ② VC | `CredentialIssuer` | `core/spi.go` | 新可选接口 |
| ② VC | `SDJWTRequest`/`SDJWTHolder` | `shared/security/sd_jwt.go` | 值类型 |
| ② VC | `CredentialOffer`/`PresentationDefinition` | `protocols/oid4vc/` | 协议类型 |
| ③ SDK | `SnaplinkSSO`（Swift）/`SsoClient`（Kotlin） | 独立仓库 | SDK 公开 API |
| ④ GitOps | `ApplyRequest`/`ApplyResponse` | `platform/configaudit/` | 端点请求/响应 |
| ④ GitOps | `SSOConfigReconciler` | `cmd/sso-gitops-reconciler/` | K8s operator 模式 |
| ⑤ 联邦 | `WorkloadRegistry` | `platform/federation/` | 新 SPI |
| ⑤ 联邦 | `BridgeTokenRequest`/`BridgeTokenResponse` | `interfaces/sso/` | 端点 DTO |
| ⑤ 联邦 | `WorkloadIdentity` | `platform/federation/` | 值类型 |

### 3.3 保持向后兼容性的策略

| 向后兼容维度 | 策略 |
|-------------|------|
| **协议兼容** | 所有新端点（hybrid、credential、bridge）是全新路径，不影响现有端点 |
| **SPI 兼容** | 新增可选接口（`HybridCapable`、`CredentialIssuer`），现有 `Authenticator`/`TokenIssuer` 不变 |
| **配置兼容** | 零值 = 不启用新功能；`passkeyhybrid` 等配置块默认 nil |
| **部署兼容** | 子模块（GitOps operator、移动 SDK）可选部署，不改变核心 SSO 流程 |
| **数据兼容** | 新字段（`Subject.SPIFFEID`）可选，不为空的补默认值 |

---

## 4. 技术选型

### 4.1 五方向的技术栈决策总览

| 方向 | 新依赖 | 技术栈选择 | 决策理由 |
|------|--------|-----------|---------|
| ① Passkey | FIDO 公共中继（可选自托管） | 无代码库依赖 | FIDO2 hybrid transport 依赖中继服务，非代码库。密码学（ECDH、AES-GCM）全在 Go 标准库 |
| ② VC | 无（第一阶段） | 标准库 SHA-256 | SD-JWT 仅需 SHA-256。BBS+（第二阶段）需要 BLS 签名库——等生态成熟再引入 |
| ③ SDK | 无（使用平台标准库） | Foundation（iOS）/ AndroidX（Android） | 移动 SDK 不使用第三方 HTTP/OAuth 库——减少依赖和审计成本 |
| ④ GitOps | `go-git`（纯 Go Git 实现） | `go-git` v5 | 轻量级、纯 Go、无 CGO。比 `libgit2` 更适合嵌入 operator |
| ⑤ 联邦 | 无（第一阶段） | 标准库 + gRPC | 跨集群 gRPC 使用现有 `grpcserver` 基础设施；SPIRE 集成可选（第二阶段） |

**结论：所有五个方向（第一阶段）均不需要引入重大的新第三方依赖。**

### 4.2 自建 vs 采购/集成

| 决策项 | 决策 | 理由 |
|--------|------|------|
| FIDO2 中继 | **使用 FIDO 联盟公共中继**（默认）+ 可选自托管 | 公共中继是标准设计的一部分；自托管适用于隔离网络 |
| 数字身份钱包 | **不做 Wallet**。SSO 作为 Issuer + Verifier | Wallet 是独立产品方向。EU 数字身份钱包、Apple/Google Wallet 已在做 |
| 移动端安全存储 | **使用平台 API**（Keychain / EncryptedSharedPreferences） | 平台 API 已被安全审计，不需要第三方加密库 |
| Git 操作 | **自建 reconciler**（使用 go-git） | 不需要 ArgoCD/Flux 集成——SSO 的配置模型是 SSO 特定的 |
| SPIRE 集成 | **可选**——WorkloadRegistry SPI 可对接 SPIRE（生产）或 memory（测试） | SPIRE 是成熟的工作负载身份解决方案，但集成应该是选项而非强依赖 |

### 4.3 不做之事（第一阶段）

| 不做 | 原因 |
|------|------|
| 不做 Passkey 聚合登录（多设备 Passkey 同步） | Apple/Google/Microsoft 平台负责设备间 Passkey 同步——SSO 不需自己建同步层 |
| 不做 BBS+ 签名（V2） | 需 BLS 签名库，生态未成熟。SD-JWT 第一阶段足够 |
| 不做移动端 Admin API SDK | Admin API 仍在演进——SDK 仅包装稳定的 OAuth/OIDC 核心 |
| 不做 GitOps 的 canary rollout | 增加复杂度的 V2 功能——第一阶段只做 full rollout |
| 不做跨集群 mTLS CA（V2） | PKI 基础设施是独立领域——第一阶段只做 token 桥接 |

---

## 5. 实施路线图

### 5.1 优先级总览

```
        高 │ 方向① Passkey Hybrid            方向③ 移动端 SDK
           │     P0 ─── 2026 年 Passkey 浪潮        P1 ─── 移动端用户覆盖
           │
   业务价值 │ 方向② Verifiable Credentials
           │     P1 ─── EU eIDAS 2.0 窗口
           │
        低 │ 方向④ GitOps                     方向⑤ 跨集群联邦
           │     P1 ─── 企业配置管理              P2 ─── 多集群网格身份
           │
           └──────────────────────────────────────────────
              低                             高
                        实现复杂度
```

### 5.2 阶段划分

#### 阶段一：Passkey Hybrid（P0）——6-8 周

| 子项 | 工作量 | 产出 |
|------|--------|------|
| `HybridCapable` 可选接口定义 | S | Authenticator 扩展点 |
| `domains/authenticators/passkeyhybrid/` 实现 | L | ECDH 密钥协商 + 加密通道 + 中继客户端 |
| QR 码生成 + Session 绑定 | M | Login SPA 显示 QR 码 |
| `/auth/hybrid/*` 端点 | M | begin + poll + complete |
| FIDO 公共中继集成 | M | 跨设备断言传递 |
| 回退：相同设备 WebAuthn | M | hybrid 不可用时自动回退 |

**验证标准：** 桌面浏览器登录页面展示 QR 码 → 手机扫码 → 手机上完成生物识别 → 桌面自动登录成功。

**关键路径：** FIDO2 hybrid transport 的中继通信协议——这是技术风险最高的子项。

#### 阶段二：移动端 SDK（P1，与阶段一并行）——4-6 周

| 子项 | 工作量 | 产出 |
|------|--------|------|
| iOS SDK 核心授权流 | M | ASWebAuthenticationSession + PKCE 封装 |
| Android SDK 核心授权流 | M | Chrome Custom Tab + PKCE 封装 |
| 令牌安全存储（双平台） | M | Keychain / EncryptedSharedPreferences |
| 令牌自动刷新 | M | 后台 token refresh 管理 |
| 示例应用（双平台） | M | 集成演示 |

**验证标准：** 示例应用使用 SDK 完成登录 → 令牌安全存储 → 应用重启后令牌恢复 → 自动刷新 → 登出。

**关键路径：** 两个平台的同步开发——如果资源有限，优先 iOS（Swift），Android（Kotlin）紧随。

#### 阶段三：Verifiable Credentials（P1）——6-8 周

| 子项 | 工作量 | 产出 |
|------|--------|------|
| SD-JWT 格式支持 | M | 选择性披露编码/解码 |
| `CredentialIssuer` 可选接口 | S | Issuer SPI 扩展 |
| OID4VCI Issuer 端点 | L | `credential_offer` + `/credential` |
| OID4VP Verifier 端点 | L | `/verify` + `presentation_definition` |
| `/.well-known/openid-credential-issuer` | S | 元数据文档 |

**验证标准：** 外部 Wallet（如 EU Digital Identity Wallet 测试版）可连接 SSO 的 credential_issuer → 完成授权 → 获取 SD-JWT → 在 Verifier 端点验证。

**关键路径：** SD-JWT 格式的规范跟踪——RFC 尚未最终定稿，需要跟踪 drafts。

#### 阶段四：GitOps 身份基础设施（P1）——4-6 周

| 子项 | 工作量 | 产出 |
|------|--------|------|
| `POST /admin/config/apply` 端点 | L | 三向 diff + apply |
| `config apply` 冲突检测 | M | 基线 vs 运行 vs 期望 |
| `cmd/sso-gitops-reconciler/` | L | Git → SSO 同步循环 |
| SOPS/age 加密集成 | M | 敏感字段自动解密 |
| PR webhook 集成 | M | PR 评论 + auto-apply |

**验证标准：** Git 仓库配置变更 → PR → reviewer 批准 → merge → 自动 apply 到 SSO → `config/running` 反映更改。

**关键路径：** 三向 diff 算法——需要正确处理多用户并发修改的场景。

#### 阶段五：跨集群联邦（P2）——6-8 周

| 子项 | 工作量 | 产出 |
|------|--------|------|
| `WorkloadRegistry` SPI + memory impl | M | 工作负载身份注册 |
| `/token/bridge` 端点 | L | 跨集群 token 转换 |
| Trust domain 联合配置 | M | 跨集群公钥交换 |
| 边缘身份缓存 | M | 边缘节点 authz 缓存 + 失效 |
| ext_authz 跨集群扩展 | M | sidecar 支持跨集群验证 |

**验证标准：** 集群 B 的微服务调用集群 A 的微服务 → token bridge → 集群 A 的 ext_authz 验证通过。

**关键路径：** 跨集群信任关系的建立——需要编写清晰的配置文档和最佳实践。

### 5.3 依赖关系图

```
阶段一：Passkey Hybrid（P0，6-8 周）
    │
    ├── 依赖：现有 WebAuthn 基础设施（已有）
    ├── 依赖：Login SPA（已有）
    └── 无外部依赖
    │
阶段二：移动端 SDK（P1，4-6 周）← 可与阶段一并行
    │
    ├── 依赖：现有 SSO HTTP API（已有，稳定）
    ├── 依赖：无后端变更
    └── 无外部依赖
    │
阶段三：Verifiable Credentials（P1，6-8 周）← 可在阶段一之后开始
    │
    ├── 依赖：现有 TokenIssuer（已有，SD-JWT 扩展）
    ├── 依赖：OAuth 2.0 授权流（已有）
    └── 跟踪：SD-JWT draft 规范
    │
阶段四：GitOps（P1，4-6 周）← 可与阶段二并行
    │
    ├── 依赖：现有 config/running 端点（已有）
    ├── 依赖：现有 config/cluster-diff 端点（已有）
    └── 新依赖：go-git
    │
阶段五：跨集群联邦（P2，6-8 周）← 在阶段一/三之后
    │
    ├── 依赖：现有 ext_authz（已有）
    ├── 依赖：现有 token-exchange（已有）
    ├── 依赖：现有 cluster.Bus（已有）
    └── 新依赖：SPIRE（可选）
```

**推荐启动顺序（按资源约束）：**

```
资源充足（2-3 个开发团队并行）：
  阶段一（Passkey） + 阶段二（移动 SDK） + 阶段四（GitOps）并行
  → 阶段三（VC）→ 阶段五（联邦）

资源有限（1 个团队）：
  阶段一（Passkey）→ 阶段二（移动 SDK）→ 阶段三（VC）→ 阶段四（GitOps）→ 阶段五（联邦）
```

### 5.4 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| **FIDO2 hybrid transport 协议尚未广泛部署**——Apple/Google 支持程度、FIDO 中继可用性不确定 | H | H | 先做最小可行版本（QR + 轮询 + 公共中继）；中继不可用时 fail-open 到同一设备 WebAuthn |
| **SD-JWT/OpenID4VC 规范仍在演进**——RFC 尚未定稿 | M | M | 跟踪 https://openid.net/wg/digital-credentials-charter/ 的最新 drafts；设计时考虑向后兼容（版本字段 + 格式协商） |
| **移动 SDK 维护成本超预期**——两个平台 + 过时版本 + API 兼容性 | M | M | 优先覆盖最新 iOS/Android 版本；使用平台标准库减少随时间腐烂的第三方依赖；测试只在最新两个大版本运行 |
| **GitOps apply 的三向 diff 过于复杂**——冲突检测 + 拓扑排序 + 回滚的复杂度 | M | M | 第一阶段只做 `ApplyStrategy: force`（全量覆盖），`merge` 模式推迟到 V2 |
| **跨集群联邦的采用门槛**——用户需要运行多个 SSO 集群 + SPIRE + 配置联邦关系 | H | M | 高质量文档 + 快速启动脚本（`sso-ctl federation init --trust-domain`）；第一阶段只做核心 token bridge，降低入门门槛 |
| **五个方向争夺有限资源**——每个方向都是中等以上投入 | H | H | 严格按优先级投入：P0 方向（Passkey）先做 80% 价值；P1 方向（移动 SDK/VC/GitOps）做最小可行版本；P2（联邦）做 SPI 设计 + 内存实现 |

### 5.5 跨方向协同效应

| 协同 | 说明 |
|------|------|
| **Passkey × 移动 SDK** | 移动 SDK 是 Passkey hybrid transport 的手机端（认证器）的理想载体——SDK 中可以提供 `PasskeyHybridClient` 专门处理手机侧的 QR 码扫描 + 断言签署 |
| **VC × 移动 SDK** | 移动 SDK 是 Verifiable Credential Wallet 的自然位置——虽然第一阶段不做 Wallet，但 SDK 架构应预留 `VCHolder` 接口 |
| **GitOps × 跨集群联邦** | GitOps reconciler 的配置可以包括联邦关系（trust domain、bridge endpoint）——一次 apply 配置工作负载身份 + 联邦关系 |
| **Passkey × VC** | Passkey 的私钥可以绑定到 Verifiable Credential 的 holder——Passkey 作为 VC holder 的认证方式 |
| **移动 SDK × 集群联邦** | 移动端可能需要访问多个集群的服务——跨集群桥接 token 对移动端透明（SDK 只认 access_token） |

---

## 6. 与其他已知工作的整合

### 6.1 与 ROADMAP v5.0 的关系

| ROADMAP v5 方向 | 与本分析的关系 |
|----------------|--------------|
| ① Hosted Login + Consent + Console | **独立**——Passkey/VC/SDK 是协议侧的扩展，Console 是 UI/UX 侧 |
| ② B2B 企业化 | **互补**——企业连接 + HRD 定义用户在哪里，Passkey/VC 定义用户怎么认证 |
| ③ OIDC 一致性收口 | **独立**——本分析的五个方向不依赖 OIDC 正确性修复；但 Passkey 作为认证因素，AT_hash/AMR 修复后的 id_token 更准确 |
| ④ 多副本数据面韧性 | **互补**——跨集群联邦（方向五）是多副本数据面韧性在跨集群维度的扩展 |
| ⑤ 安全姿态与供应链 | **独立**——安全修复不依赖新功能方向 |

### 6.2 与前置分析（architect-analysis-v6-five-directions.md）的关系

| 前置分析方向 | 当前分析方向 | 关系 |
|-------------|-------------|------|
| 多区域主动-主动复制 | 跨集群联邦 | **互补**——多区域复制是数据层（session/token 跨区一致）；跨集群联邦是身份层（workload 身份跨cluster） |
| 外部依赖韧性 | Passkey（中继依赖） | **适用**——FIDO 公共中继不可用时的 fallback 策略是韧性工程的应用 |
| 限流完备化 | 所有方向 | **独立**——所有新端点都需接限流，但限流接线是模板化工作 |
| 配置验证门禁 | GitOps | **强互补**——配置验证门禁是 GitOps 的前置条件：CI 中先 `sso-ctl config validate --ci` 再 apply |
| 令牌链式溯源 | Verifiable Credentials | **互补**——VC 的生命周期追踪（发放→持有→验证→吊销）是令牌溯源在 VC 维度的应用 |

**总体关系：** 两个分析的 10 个方向分属不同层级（后端基础设施 vs 面向市场的新协议/产品），互不阻塞，但存在互补协同。

---

## 7. 总结

### 7.1 总体评估

| 维度 | 评估 |
|------|------|
| **架构健康度** | 极高——五个方向均可在当前架构内实现，不需要架构重组 |
| **最大战略价值** | 方向① Passkey Hybrid——2026-2027 年是 Passkey 的临界点 |
| **最高 ROI（投入/价值）** | 方向③ 移动 SDK——后端零变更，纯封装投资 |
| **合规驱动** | 方向② Verifiable Credentials——EU eIDAS 2.0 合规 |
| **运营价值** | 方向④ GitOps——配置管理是企业级身份平台的标配能力 |
| **架构前瞻性** | 方向⑤ 跨集群联邦——单集群 → 多集群的网格身份扩展 |

### 7.2 核心决策回顾

| 决策 | 选择 | 替代方案被否决的原因 |
|------|------|-------------------|
| Passkey 中继 | 公共 FIDO 中继（默认）+ 可选自托管 | 自建中继=重复造轮+ 运维成本；无中继=局域网受限 |
| VC 格式 | SD-JWT（第一阶段）→ BBS+（第二阶段） | JSON-LD+ZKP 复杂度高，生态未成熟 |
| 移动 SDK 仓库 | 独立仓库 | 核心 Go 仓库不应引入 Swift/Kotlin 生态 |
| GitOps 审核流 | 三向 diff（基线 vs 运行 vs 期望）+ force 策略 | merge 策略复杂度高，推迟到 V2 |
| 跨集群 token 桥接 | 新端点 `/token/bridge` + 现有 token-exchange 扩展 | 扩展现有 `/exchange` 端点会破坏单一集群语义 |
| WebSocket vs 轮询（Passkey） | 轮询 | 人的感知是秒级，500ms 轮询已足够；WebSocket 增加架构复杂度 |

### 7.3 不做之事

| 不做 | 原因 |
|------|------|
| 不做 Wallet（数字身份钱包） | 第三方（Apple/Google/EU）已提供，SSO 应做 Issuer + Verifier |
| 不做跨设备 Passkey 同步 | 平台原生同步，SSO 不需自建 |
| 不做 canary/rollback 的 GitOps rollout | V2 功能，第一阶段只做 full rollout |
| 不做跨集群 mTLS CA | PKI 是独立领域，第一阶段只做 token 桥接 |
| 不引入新 schema 语言 | 现有反射式 JSON Schema 生成已足够 |

### 7.4 核心建议

1. **立即启动方向①（Passkey Hybrid）**——这是 2026 年身份领域唯一的"必做"功能，且 SSO 的 WebAuthn 基础设施已在树内、FIDO2 Hybrid 是一次自然的扩展
2. **方向③（移动 SDK）同步启动**——与方向①共享"移动端"场景，可以共享产品设计和测试
3. **方向②（Verifiable Credentials）跟踪规范进展**——在 SD-JWT/RFC 定稿前完成设计，但不 rush 实现；eIDAS 2.0 的 deadline 会驱动需求
4. **方向④（GitOps）是 deferred-backlog 中 OUT OF SCOPE 项的自然升格**——已有 diff 基础，apply 是三向 diff + 审计的自然延伸
5. **方向⑤（跨集群联邦）有序推进底层基础设施**——先完成 ROADMAP v5.0 方向④（多副本数据面韧性），再扩展到跨集群维度
