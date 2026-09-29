# SDK 范式规正设计（Proposal）

> **状态：W1 已落地，W2–W6 待实施。**
> 本文件是设计提案与理由记录；**规范性契约是 [`docs/sdk-paradigm.md`](../sdk-paradigm.md)**，
> 机器真源是 `ops/build/sdk-paradigm.json`，门禁是 `python cli.py sdk-paradigm check`。
> 两者冲突时以 `docs/sdk-paradigm.md` 为准。
>
> 目标是把当前**隐式、只靠人工同步**的 SDK 现状，
> 收敛为**有规范、有机器门禁、跨语言同构**的范式，并解决两个具体问题：
> ① 接口如何优雅暴露；② 商业功能如何用 secret 门控。

---

## 0. 现状事实（已逐文件核实，非推测）

### 0.1 两层结构，只有一层有治理

```
Tier 1  生成层  ops/build/sdk-surface.json  ← 唯一机器治理
        321 ops / 13 groups，cmd/gensdk 从 docs/openapi.yaml 生成
        语言：TypeScript、Python（cmd/gensdk/main.go 只认 ts/py/all）
        门禁：cli.py sdk-surface {check,diff,versions} + sdk-drift check

Tier 2  手写 hosted-login 层  ← 零治理
        Go / Rust / PHP / TS / Python 各一份手写
        门禁：只有各语言自己的 package CI
        无 parity 清单，无跨语言一致性校验
```

`docs/deferred-backlog.md:35` 已承认此裂缝：*"Rust/PHP remain independent SDK
packages with their own release boundaries"*。`docs/campaigns/reports/
sdk-version-followup.md` 进一步要求门禁"准确区分 TS/Python generated clients
与 **Rust/PHP 独立 package gates**"——**范式目前是"承认漂移"而非"消除漂移"**。

### 0.2 能力矩阵实测

| 能力 | Go | TS | Python | PHP | Rust |
|---|:--:|:--:|:--:|:--:|:--:|
| login 起+回调 | ✅ | ✅ | ✅ | ✅ | ✅ |
| StateStore / Memory | ✅ | ✅ | ✅ | ✅ | ✅ |
| setup / 激活 | ✅ | ✅ | ✅ | ✅ | ✅ |
| get_account_context | ✅ | ✅ | ✅ | ✅ | ✅ |
| access_token | ✅ | ✅ | ✅ | ✅ | ✅ |
| is_logged_in | ❌ | ✅ | ✅ | ✅ | ✅ |
| logout | ❌ | ✅ | ✅ | ✅ | ❌ |
| **refresh** | ❌ | ✅ 私有自动 | ❌ | ❌ | ❌ |
| preferences 交接 | ❌ | ✅ | ✅ | ❌ | ❌ |
| 生成客户端(321) | ✅ | ✅ | ✅ | ❌ | ❌ |
| RS 本地验签 | ✅ | ❌ | ❌ | ❌ | ❌ |
| 传输层可注入 | ✅ | ✅ | ❌ | ✅ | ⚠️ blocking |
| 原生异步 | ✅ ctx | ✅ | ❌ | ❌ | ⚠️ **blocking** |

### 0.3 商业能力的现状：**裸 JSON，且表达不了三态**

- Rust：`entitlement: Option<serde_json::Value>`（`sdks/rust/src/lib.rs:283`）
- Python：`Dict[str, Any]`；PHP：`array`；TS：`CommerceEntitlement` TypedDict（有形状无语义）
- **10 个 `FeatureKey`（`core_sso`/`multi_tenant`/`audit_governance`/`notifications`/`im`/`account`/`vault`/`scim`/`federation`/`high_availability`）和 6 个 `LimitKey` 一个都没进任何 SDK。**
- `EntitlementSnapshot.effective(at)`（`domains/tenant/commerce/models.go:256-273`）
  是**服务端**逻辑：要求 `Active && !before(EffectiveAt) && !after(ExpiresAt)`。
  SDK 拿到的消费者若只判 `entitlement != null`，**会把已过期/已停用的授权当成有效**。
  这不是风格问题，是正确性陷阱。
- `Option<entitlement>` 无法区分三态：**未激活 / 曾激活但失效 / 有效**。

---

## 1. 六个结构性问题

| # | 问题 | 后果 | 严重度 |
|---|---|---|---|
| **P1** | hosted-login 层零治理，5 语言能力集纯人工同步 | 已实际漂移（见 0.2） | 高 |
| **P2** | 商业能力是裸 JSON，非一等公民 | 消费者无法安全 gate | **高** |
| **P3** | 表达不了授权三态 | 过期授权被误判为有效 | **高** |
| **P4** | 认证 secret 与商业 secret 混为一谈 | 只有一次性 bootstrap 凭据，无离线授权载体 | **高** |
| **P5** | 错误分类不统一（仅 TS/Py 携带 OAuth `error` code） | 无法可移植地 branch on `activation_invalid` | 中 |
| **P6** | 传输层 3/5 不可注入；Rust 锁死 blocking | Rust 在 tokio/axum 里不可用 | 高 |

另有两个接口优雅性问题：

| # | 问题 |
|---|---|
| **P7** | `LoginOptions` 12 个扁平 builder（含 `allow_insecure_http_for_development` 这类危险开关），90% 调用方只填 3 个字段 |
| **P8** | `setup()` + `login()` 两段式带隐藏 pending 状态；`LoginResult` 强 enum 强迫每个调用点 match |

---

## 2. 目标范式：四层

```
┌─ L3 Entitlement ──────────────────────────────────────────┐
│  一等公民：有类型、有时效语义、可离线验签、跨语言同构 fixture │
├─ L2 Session ──────────────────────────────────────────────┤
│  显式生命周期：start / refresh / logout，无隐藏状态          │
├─ L1 ApiClient ────────────────────────────────────────────┤
│  321 ops 生成层（已有，扩展到 5 语言）                       │
├─ L0 Transport ────────────────────────────────────────────┤
│  可注入、async 优先、5 语言同构的 send(req)->resp           │
└───────────────────────────────────────────────────────────┘
```

每层有独立门禁。**上层可跳过下层**（纯离线场景只用 L3+L0）。

---

## 3. L3 Entitlement —— 商业能力升为一等公民

### 3.1 三态模型（解决 P3）

```rust
pub enum LicenseState {
    /// 从未激活：没有 product→tenant 绑定
    NotActivated,
    /// 曾激活但当前无效（过期 / 停用 / 计划降级）
    Inactive { reason: InactiveReason, until: Option<i64> },
    /// 当前有效
    Active(Entitlement),
}

pub enum InactiveReason { Expired, Suspended, Revoked, PlanChanged }
```

`InactiveReason` 只用于**展示**，不得据此做安全判定（对齐 AGENTS.md §3 的
oracle-safe 纪律：不同内部原因在 SDK 侧也不应驱动不同的重试行为）。

### 3.2 类型化 Feature / Limit（解决 P2）

```rust
pub struct Entitlement {
    pub plan: PlanRef,
    pub revision: u64,              // 乐观并发 + 缓存失效键
    pub features: FeatureSet,       // 枚举化，10 个已知 key
    pub limits: LimitSet,           // 枚举化，6 个已知 key + soft/hard/unlimited
    pub effective_at: i64,
    pub expires_at: Option<i64>,
    pub generated_at: i64,
}

impl Entitlement {
    /// 与服务端 EntitlementSnapshot.effective() 语义严格一致
    pub fn effective_at(&self, now: i64) -> bool;
    pub fn has(&self, f: Feature) -> bool;
    pub fn limit(&self, l: Limit) -> Option<LimitGrant>;
}
```

**关键约束**：`effective_at()` 的判定逻辑必须在 **5 语言同构**，
由一份共享 conformance fixture 驱动（见 §6.2），否则语义必然漂移。

### 3.3 铁律：SDK 不是权威

```
                    ┌──────────────────────────────────────┐
   请求 ──────────► │ 服务端按 entitlement 独立判定（权威）    │
                    │ Licensed grant → 预编译模块 / 配置       │
                    └──────────────────────────────────────┘
                              ▲ 只"读"，不"绕"
                    ┌──────────────────────────────────────┐
                    │ SDK 侧 = 体验层                        │
                    │  UI 门控 / 早失败 / feature 提示        │
                    └──────────────────────────────────────┘
```

1. SDK 侧 gate **只用于体验**（提前隐藏按钮、给出可读文案），**服务端永远独立判定**。
2. SDK **不得**缓存过期 entitlement 用于 gate：`revision` + `effective_at` 必须在
   每次 `has()`/`limit()` 调用时求值，不做"取一次缓存一辈子"。
3. license 失败**既不 fail-open 也不 panic**，落到显式 `LicenseState` / `LicenseError`。

---

## 4. L3 商业授权的四种 secret（解决 P4 —— 用户核心关切）

当前只有 `license_key` / `invitation_code`，且都是 **bootstrap-only 一次性**
（`activation.Code.MaxClaims` 默认 1）。但 `docs/commercial-model.md` 明确存在
**四种互不等价的凭据**。范式必须把它们分层，否则调用方会拿错东西：

| 名称 | 形态 | 门控什么 | 生命周期 | 存放 | 现有实现 |
|---|---|---|---|---|---|
| `license_key` | 短字符串 | 首次绑定 product→tenant | **一次性** | 用户输入，**不落盘** | ✅ 已有 |
| `invitation_code` | 短字符串 | 同上，邀请通道 | **一次性** | 同上 | ✅ 已有 |
| `client_secret` | OAuth secret | 该 client 取 token | 长期 | KMS / env | ⚠️ 混在构造参数里 |
| **`entitlement_file`** | **Ed25519 签名文件** | **离线/气隙部署的商业功能** | 合约期 | 只读挂载 | ❌ **不存在** |

### 4.1 `entitlement_file` 是缺口，也是最优雅的一环

`docs/commercial-model.md` 原文：

> Offline/private deployments use a **signed commercial entitlement file** or
> operator-provisioned catalog; **authentication must not call a vendor
> licensing service on a login path.**

**推论**：气隙部署要 gate 商业功能，SDK 必须能**本地验签**，否则只能调
`/api/v1/me/account-context` —— 那等于把登录路径绑到厂商服务上，直接违反上面这条。

```rust
// 完全离线，零网络
let file = EntitlementFile::verify(&bytes, LicenseTrust::vendor_pinned())?;
match file.state(now) {
    LicenseState::Active(e) if e.has(Feature::Scim) => { /* 启用 */ }
    LicenseState::Active(_) => { /* 只读降级，提示升级 */ }
    other => { /* 明确文案 + 遥测，不 fail-open */ }
}
```

设计要点：
- **Ed25519 验签**，与 snaplink 签 token 同一套算法心智（不引入第二套密码学）
- vendor **公钥编译进 SDK 常量**（公钥不是秘密）；允许调用方 pin 自有公钥覆盖
- 验签失败 → `LicenseError::Signature`，**绝不降级为 free**
- 私钥**永不**进 SDK、永不进仓库、永不进 CI

### 4.2 secret 不进 options struct（解决 P7 的延伸）

现在 `client_secret` 直接躺在 `SSOClient.__init__(client_secret=...)` 里。范式改为**凭证提供者**：

```rust
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    async fn credential(&self) -> Result<Credential>;
}

impl CredentialProvider for StaticSecret { .. }        // 测试/开发
impl CredentialProvider for EnvVar { .. }               // SNAPLINK_CLIENT_SECRET
impl CredentialProvider for AwsSecretsManager { .. }    // 生产
impl CredentialProvider for KmsRef { .. }               // 轮转
```

收益：secret 不进 `Debug` 输出、不进配置文件快照、可热轮转、可审计。
配合 `deny_unknown_fields` 与 `#[derive(Deserialize)]` 边界，禁止 secret 意外落盘。

---

## 5. L0/L1/L2 —— 接口如何更优雅

### 5.1 L0 Transport：统一可注入 + async 优先（解决 P6）

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError>;
}
```

- Rust 提供 `ReqwestTransport`（async，默认）+ `BlockingTransport`（`feature = "blocking"`，给 CLI/脚本）
- **5 语言同构**：`send(request) -> response` 同一形状
  - Python `Transport` Protocol（**当前直接用 `urllib.request`，无 seam —— 必须补**）
  - TS `FetchLike` ✅ 已有
  - Go `http.RoundTripper` ✅ 已有
  - PHP `callable` ✅ 已有
  - Rust: 由具体类型别名改为 **trait**（breaking，但 0.x 允许）

### 5.2 L2 Session：显式生命周期（解决 P3/P8 与 refresh 缺失）

现状：refresh 只有 TS 有且是**私有自动**（`browser-login.ts:384 tryRefresh`），
其余 4 语言都没有 → access token 一过期就掉线。

范式：**显式，不用隐藏状态**。

```rust
let outcome = Session::start(&client, &login_request).await?;
match outcome {
    LoginOutcome::Redirect { url, .. } => redirect(url),      // 浏览器场景
    LoginOutcome::Authenticated(s) => {
        let _ = s.access_token();
        let _ = s.entitlement();      // L3，一等公民
        let _ = s.refresh().await?;   // 显式轮换
        s.logout().await?;
    }
}
```

配套：
- 用 `LoginOutcome` + 便利方法（`.authenticated()?`）替代强 enum，削掉 P8 的 match 噪音
- `AutoRefreshingSession` 作为**可选装饰器**单独提供，不作为默认行为
  （自动触发会让"什么时候发了网络请求"不可测，测试与排障都痛苦）
- **5 语言必须都有 `refresh()`** —— 这是登录态可持续性的底线

### 5.3 P7：分层 options，危险开关独立命名空间

现状 12 个扁平 builder。范式按语义分三层，危险项隔离：

```rust
LoginRequest {
    issuer:   Issuer,                    // 必填：base_url + product_id
    client:   PublicClient { id },       // 必填
    redirect: RedirectUri,               // 必填
    session:  SessionHints { .. },       // return_to / locale / login_hint
    oidc:     OidcHints { .. },          // scopes / acr / prompt / max_age / resources
    // 危险项：独立 namespace，肉眼可辨
    dev:      DevEscapeHatches { allow_loopback_http: bool },
}
```

规则：
- 必填项在顶层，编译器强制
- 危险开关一律进 `dev`/`unsafe` 命名空间，且默认关闭
- `Debug` 派生**必须**对 secret 类字段打码

### 5.4 L1 ApiClient：生成层扩到 5 语言

`cmd/gensdk` 当前只有 `ts`/`py`。范式要求 Rust/PHP/Go 消费同一份
`ops/build/sdk-surface.json`（321 ops），generator 自身**不带 allowlist**
（沿用现有正确设计）。Rust/PHP 各新增一个 `gen_*.go`。

---

## 6. 治理

### 6.1 范式文档 + 机器可读矩阵

| 产物 | 作用 |
|---|---|
| `docs/sdk-paradigm.md` | 人读的规范：四层、命名、版本策略、parity 要求 |
| `ops/build/sdk-paradigm.json` | 机器读的 L2/L3 能力矩阵（5 语言 × N 能力） |
| `python cli.py sdk-parity check` | 校验矩阵与代码实际存在性一致，纳入 `make ci` |

沿用现有成熟设计：`sdk-surface.json` 的 **"generator 不带 allowlist、
registry 是唯一真源"** 原则，扩展到 hosted-login 层。

### 6.2 跨语言 conformance fixture（关键防漂移手段）

`ops/build/sdk-conformance/*.json` —— **一份 fixture，5 语言跑同一组断言**：

| Fixture | 断言内容 |
|---|---|
| `errors.json` | 每个受控 error code 的映射与消息形状（`activation_invalid` / `invalid_grant` / `insufficient_scope` / `commerce_entitlement_not_found` …） |
| `entitlement.json` | **时效边界**：`ExpiresAt` 前 1 秒 / 恰好 / 后 1 秒；`Active=false`；`EffectiveAt` 未到；空 entitlement |
| `transport.json` | 请求/响应规范化形状（header 大小写、form 编码、no-store） |
| `license_file.json` | 签名有效 / 签名损坏 / 公钥不匹配 / 过期 四态 |

**这是"时效语义不会在某个语言里悄悄漂移"的唯一保障。**
错误码词表直接取自 `docs/error-codes.md`（受控、单源）。

### 6.3 版本策略

| 变更类型 | 语义化 | 示例 |
|---|---|---|
| 生成层新增 operation / optional 字段 | additive，patch | 新增 `getXxx` |
| operationId 重命名 / 删除 / 跨 group 移动 | **breaking**，minor（0.x） | 沿用现有 policy |
| 范式层 breaking（Transport 改 trait、Error 变体） | **breaking**，minor（0.x） | Rust 0.3→0.4 |
| 新增能力（`refresh()`/`LicenseState`） | additive，minor | |

生成层**永不破坏**既有调用点；范式层在 0.x 内允许破坏，靠 fixture + CHANGELOG 兜底。

---

## 7. 落地顺序

| 波 | 内容 | 理由 |
|---|---|---|
| **W1** | 规范文档 + `sdk-paradigm.json` + `sdk-parity check` + 4 份 fixture 骨架 | 治理先行，先让漂移可见可拦 |
| **W2** | **L3 Entitlement**：5 语言类型化 `LicenseState`/`Entitlement` + `entitlement_file` 本地验签 | 用户核心关切；也是纯离线部署的前提 |
| **W3** | **L2 Session**：5 语言补 `refresh()`/`logout()`，Rust 去掉 `Result` 强 enum，分层 options | 解掉实际漂移与 P7/P8 |
| **W4** | **L0 Transport**：Rust 改 async trait + 5 语言 seam 统一（Python 补 seam） | 解 Rust 在 tokio 不可用 |
| **W5** | **L1 生成层**扩到 Rust/PHP | 工作量最大，独立一轮 |
| **W6** | 发布：crates.io / npm / PyPI / Packagist（tag `sdk-rs-v0.4.0` 等） | W2–W4 稳定后 |

---

## 8. 待决

1. **vendor 公钥分发**：编译进 SDK 常量（简单，但换 key 要发版）还是随 entitlement
   文件分发 pin（灵活，但多一个信任根）？建议**内置 + 允许覆盖**。
2. **`entitlement_file` 的签发方**：Snaplink 官方 CA，还是允许 OEM/私有 CA 自签？
   影响 `LicenseTrust` 是否可配置。
3. **W5 是否本轮做**：生成器扩语言是最大的一块，是否单独立项。
4. **Rust breaking 的时机**：`Transport` 改 trait 是 breaking，趁 0.3.0 用户还少时
   做，还是等有稳定用户后走 1.0？
