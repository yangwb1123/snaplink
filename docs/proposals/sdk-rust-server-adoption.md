# Rust SDK 服务端接入设计：Aero IM 采纳（Proposal）

> 状态：提案。本文只解决 `docs/proposals/sdk-paradigm.md` 未覆盖的**服务端**维度，
> 以及 Rust 侧 W3/W4/W6 的可执行规格。范式总纲、跨语言治理、能力矩阵以
> `sdk-paradigm.md` + `ops/build/sdk-paradigm.json` 为准，本文不重复定义。

## 0. 结论先行

采纳 Aero IM **不需要**重写 SDK 的状态层。Aero IM 已有的 flow cookie 存储
（加密、作用域化、可清除）天然满足 `StateStore` 契约。真正阻塞的只有三项：

| 缺口 | 现有状态 | 阻塞 Aero IM 的原因 |
|---|---|---|
| **W4 Transport** | `reqwest::blocking::Client` 硬编码为类型别名 | 在 Tokio worker 上阻塞网络 I/O，Aero IM 是 `tokio = { features = ["full"] }` 的 axum 服务 |
| **W3 Session** | 无 `refresh()` / `logout()` | access token 过期即掉线；无服务端注销 |
| **W6 Publish** | `sdks/rust` 全部为未提交改动，未上 crates.io | 引用它等于把未发布代码绑进线上镜像 |

状态层（`StateStore`）**不是缺口** —— 见 §3。

## 1. 现状事实（已核实）

- `sdks/rust/src/lib.rs` 单文件 1353 行，同时承载 login / token / StateStore / error / client。
- 传输层：`use reqwest::blocking::Client as HttpClient;` —— 是具体类型别名，
  `with_http_client` 接受该具体类型，调用方**无法**传入异步客户端。
- `StateStore` 是同步 trait（`fn take` / `fn save`，非 `async fn`），
  值是 `Vec<u8>`；`MemoryStateStore` 是进程内 `HashMap`，注释自述
  "for development and single-process examples"。
- token 交换只发 `grant_type` / `client_id` / `code` / `code_verifier` / `redirect_uri`，
  **不发 `client_secret`** —— 公共客户端专用，README 明言 "No BFF or client secret is required"。
- `cargo test` 当前 41 个测试全绿（3 + 11 + 13 + 14）。
- `python3 ops/scripts/sdk_paradigm.py check` 当前**已失败**，两条既有 symbol 漂移：
  `session.clear.go`、`session.clear.rust`。与本次工作无关，但会让"门禁转绿"这件事
  不能被单独归因给 W3/W4。采纳前需先确认这两条的处理方式。

## 2. W4 Transport：async 优先，阻塞降级为 feature

按 `sdk-paradigm.md` §5.1 的规定落地，Rust 侧具体化为：

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<TransportResponse, TransportError>;
    async fn post_json_auth(&self, url: &str, body: &serde_json::Value, bearer: &str)
        -> Result<TransportResponse, TransportError>;
}

pub struct TransportResponse { pub status: u16, pub body: String }
```

要求：

1. `SnaplinkClient` 只持有 `Arc<dyn Transport>`，**不再引用任何 reqwest 具体类型**。
2. 默认 feature 提供 `ReqwestTransport`（`reqwest` **async**，无 `blocking` feature）。
3. `feature = "blocking"` 单独提供 `BlockingTransport` 适配器（`spawn_blocking` 包装），
   供 CLI/脚本使用。`blocking` 与 async 二者**不同时启用**，用编译期 cfg 拒绝。
4. `Cargo.toml` 移除 `features = ["blocking"]`，改为默认 async；`blocking` 移入可选 feature。
5. 超时与重试是**调用方责任**（在 Transport 实现里配置），SDK 不内置重试 ——
   登录链路重试会造成重复 code 交换。

破坏性变更：`with_http_client` 移除。0.x 允许，按 `sdk-paradigm.md` §6.3 走 CHANGELOG。

## 3. 状态层：不需要改 SDK

`StateStore` 的契约（`take` / `save` 字节）已经足够。Aero IM 现有的 flow cookie
实现就是参考实现：

| SDK 需求 | Aero IM 现有资产 |
|---|---|
| `save(key, bytes)` | `flow_cookie` + `scoped_flow_cookie_value`（加密、作用域化） |
| `take(key)` | `flow_from_cookies` |
| 事务后清除 | `append_clear_flow_cookies` |

因此 Aero IM 侧只需实现一个 `CookieStateStore`，把 `key` 映射到既有 cookie 名，
`value` 用既有加密封装 —— **SDK 侧零改动**。

设计约束（写进 SDK 文档）：

- `StateStore` 保持同步 trait。服务端实现若需 I/O（如 Redis），
  由实现方在 `spawn_blocking` 内完成；SDK 不为存储引入 async 以免传染整个 API。
- 文档明确 `MemoryStateStore` 仅适用于单进程，**多副本部署必须提供外部实现**。

## 4. W3 Session：补 `refresh()` / `logout()`

按 `sdk-paradigm.md` §5.2（显式生命周期，不用隐藏状态）：

```rust
impl SnaplinkClient {
    pub async fn refresh(&mut self) -> Result<TokenResponse, SnaplinkError>;  // refresh_token grant
    pub async fn logout(&mut self) -> Result<(), SnaplinkError>;           // POST /logout
    pub fn clear(&mut self);                                                // 仅清本地，不撤销
}
```

- `clear()` 语义收窄为"本地重置"，文档注明不触发服务端撤销。
- 不提供 `AutoRefreshingSession` 默认行为；如需自动续期由调用方显式装饰。

## 5. 模块边界

`lib.rs` 拆分，对齐 Go SDK 的文件布局：

```
sdks/rust/src/
  lib.rs              仅 re-export + crate 级文档
  transport.rs        Transport trait、ReqwestTransport、BlockingTransport(feature)
  login.rs            LoginOptions、LoginResult、login()、exchange()
  session.rs          refresh() / logout() / clear() / access_token()
  state.rs            StateStore trait、MemoryStateStore
  error.rs            SnaplinkError
  entitlement.rs      （现状已合格，feature = "entitlement" 隔离）
  license_file.rs     （同上）
  preferences.rs      （同上）
```

`entitlement` / `license_file` / `preferences` 属于 L3 商业能力，与登录无依赖关系，
用 feature 隔离，让只做登录的服务（如 Aero IM）不必编译它们及其依赖
（`ed25519-dalek`、`sha2` 仅校验时需要，可归入 entitlement feature）。

## 6. 安全边界（本次决策）

**`aero-im` 客户端从机密改为公共**，作为采纳前提。

| | 机密（现状） | 公共（采纳后） |
|---|---|---|
| 客户端认证 | secret | 无 |
| 绑定 | secret + PKCE S256 | PKCE S256 + 精确 redirect URI |
| 泄露后果 | secret 泄露即可冒用 | 需同时获得 code 与 verifier |

实施要点：

- 仅 `aero-im` 改为 `token_endpoint_auth_method: none`、
  **清空 secret**、`require_pkce: true`、`allowed_pkce_methods: ["S256"]` 保持。
- `redirect_uris` 保持 `https://im.ywbsd.site/callback` 不变。
- SDK 保持"无 secret"设计（README 已如此），不新增机密客户端能力 ——
  这是**有意的边界**，不是缺口。若将来需要，应在 `ClientAuth` 命名空间单独建模，
  而不是给 `LoginOptions` 加一个可选 secret 字段。

## 7. 验收门禁

| 门禁 | 判据 |
|---|---|
| `cargo test` | 现有 41 个不回归；新增 `refresh`/`logout`/async transport 测试 |
| `python3 ops/scripts/sdk_paradigm.py check` | 4 条 `missing` 翻为 `present`（transport seam、refresh、logout、blocking feature），且**先解决既有 2 条漂移** |
| 跨 SDK fixture | `login` / `refresh` / `logout` 三条 fixture 五语言同构（§6.2） |
| 发布 | `cargo publish` 成功，`sdks/rust` 从未提交状态转为 tag `sdk-rs-v0.4.0` |

## 8. 采纳顺序（Aero IM）

1. W4 Transport + W3 Session 落地，`lib.rs` 拆分，本地测试通过。
2. 发布 crates.io，Aero IM 用版本依赖（非 path/git）引入。
3. Snaplink 侧 `aero-im` 改公共客户端（先 `--validate-only` 过再替换 Secret）。
4. `sso.rs` 用 SDK 重写 OIDC 段：删除 `authorization_url`、
   `exchange_authorization_code`、`verify_authorization_issuer`、`verify_nonce`、
   `oidc_jwks_provider`；保留既有 `CookieStateStore` 资产。
5. 重建 `aero-im` 镜像、导入 containerd、滚动更新，用无头浏览器验证
   登录起点 → Snaplink → 回调 → 会话落地全链路。

## 9. 风险

| 风险 | 缓解 |
|---|---|
| 公开客户端弱于机密客户端 | PKCE S256 + 精确 redirect URI 强制；secret 本就存于同一集群，不构成隔离 |
| SDK 未发布即被引用 | §7 要求先发布再引用，禁止 path 依赖进生产镜像 |
| paradigm 门禁已被既有漂置弄红 | 先清 `session.clear.*` 两条，否则无法归因 |
| 阻塞 SDK 残留 | 移除 `reqwest` 的 `blocking` feature；cfg 拒绝同时启用 |
| 多副本下 `MemoryStateStore` 失效 | 文档标注仅单进程；Aero IM 提供 cookie 实现 |
