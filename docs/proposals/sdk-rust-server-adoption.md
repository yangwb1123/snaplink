# Rust SDK 服务端接入设计：Aero IM 采纳（Proposal）

> 状态：SDK W3/W4 已在本地实现并通过 Rust 定向门禁；W6 crates.io 发布与 Aero IM
> 采纳仍待完成。本文只解决 `docs/proposals/sdk-paradigm.md` 未覆盖的**服务端**维度，
> 范式总纲、跨语言治理、能力矩阵以 `sdk-paradigm.md` + `ops/build/sdk-paradigm.json` 为准。

## 0. 结论先行

采纳 Aero IM **不需要**重写 SDK 的状态层接口，但服务端尚需实现 cookie-backed `StateStore`。当前 Aero IM 已有 state-scoped、HttpOnly/Secure cookie 模式（cookie 值并未加密），可作为适配起点，不能直接宣称满足原子消费契约。

| 项目 | 现状 | 后续 |
|---|---|---|
| **W4 Transport** | async 注入、默认 `ReqwestTransport`、可选 `BlockingTransport` 已在本地实现 | 发布后由 Aero IM 按 crates.io 版本引用 |
| **W3 Session** | async `refresh()` / `logout()` 已实现；明确区分 `clear()` | 本地测试覆盖旋转、注销与 credential no-store headers |
| **W6 Publish** | `snaplink-sso@0.4.0` 尚未发布；本机未配置 crates.io 凭据 | 需完成授权发布后才能按计划采纳 |
| **OIDC 验证边界** | SDK 返回原始 ID token 和本次 flow 的 nonce，不验证 JWT 签名 | Aero IM 必须保留 issuer/audience/JWKS/nonce 验证 |

状态层接口已具备；Aero IM 适配器仍待实现与验证。

## 1. 现状事实（已核实）

- `lib.rs` 现在只声明模块并 re-export；login、session、transport、state、error 分属独立模块。
- `SnaplinkClient` 持有 `Arc<dyn Transport>`；默认走 async reqwest，`blocking` feature 通过 `spawn_blocking` 执行。
- `StateStore` 是同步 trait（`fn take` / `fn save`），值为 `Vec<u8>`；内置 `MemoryStateStore` 仅适合单进程。登录事务键现在按 client 与随机 state 区分并行 flow。
- token 交换不发 `client_secret`。SDK 在事务中生成 OIDC nonce，callback 结果通过 `LoginResult::nonce()` 返回；ID-token 签名仍由 relying party 验证。
- Rust SDK 默认 58 项测试、启用 `blocking` 59 项测试全绿；`cargo package` 与 `cargo publish --dry-run --allow-dirty` 验证通过。dry-run 警告 lockfile 含已撤销的 `chacha20 0.10.1`。
- `sdk_paradigm.py check` 已通过。全仓 `make ci` 被两个既有 `.pi-batch/worktrees` Go 格式问题阻断；全量 Rust Clippy 另被未修改的 entitlement conformance 测试 lint 阻断。

## 2. W4 Transport：async 优先，阻塞降级为 feature

按 `sdk-paradigm.md` §5.1 的规定落地，Rust 侧具体化为：

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(
        &self,
        request: TransportRequest,
    ) -> Result<TransportResponse, TransportError>;
}

pub struct TransportResponse { pub status: u16, pub body: String }
```

要求：

1. `SnaplinkClient` 只持有 `Arc<dyn Transport>`，**不再引用任何 reqwest 具体类型**。
2. 默认 feature 提供 `ReqwestTransport`（`reqwest` **async**，无 `blocking` feature）。
3. 可选 `feature = "blocking"` 提供 `BlockingTransport`；它仍实现 async seam，并把 reqwest blocking I/O 放入 Tokio `spawn_blocking` 池。调用方通过注入选择 backend。
4. 默认构建只启用 async reqwest；`blocking` 是 opt-in feature，使用时仍需 Tokio runtime。
5. 超时与重试是**调用方责任**（在 Transport 实现里配置），SDK 不内置重试 ——
   登录链路重试会造成重复 code 交换。

破坏性变更：`with_http_client` 移除。0.x 允许，按 `sdk-paradigm.md` §6.3 走 CHANGELOG。

## 3. 状态层：不需要改 SDK

`StateStore` 的契约（同步 `take` / `save` 字节）已存在。Aero IM 现有的 scoped
HttpOnly/Secure flow cookie 可作为适配基础，但值是明文 cookie 内容（非加密）：

| SDK 需求 | Aero IM 现有资产 |
|---|---|
| `save(key, bytes)` | 生成按 SDK state key 命名的 HttpOnly/Secure cookie，限制编码后大小 |
| `take(key)` | 由 callback state 定位 cookie 并恢复 SDK 事务字节 |
| 事务后清除 | 复用 `append_clear_flow_cookies` 的 scoped 清理策略 |

Aero IM 侧仍需实现和测试 `CookieStateStore`；不能把客户端 cookie 误称为服务器端原子存储。授权码单次消费由 Snaplink token endpoint 强制，cookie 需保留短 TTL、SameSite=Lax 与 callback 清理。

设计约束（写进 SDK 文档）：

- `StateStore` 保持同步 trait。服务端实现若需 I/O（如 Redis），
  由实现方在 `spawn_blocking` 内完成；SDK 不为存储引入 async 以免传染整个 API。
- 文档明确 `MemoryStateStore` 仅适用于单进程，**多副本部署必须提供外部实现**。

## 4. W3 Session：补 `refresh()` / `logout()`

按 `sdk-paradigm.md` §5.2（显式生命周期，不用隐藏状态），Rust SDK 已实现：

```rust
impl SnaplinkClient {
    pub async fn refresh(&mut self) -> Result<TokenResponse, SnaplinkError>;  // refresh_token grant
    pub async fn logout(&mut self) -> Result<(), SnaplinkError>;           // POST /logout
    pub fn clear(&mut self);                                                // 仅清本地，不撤销
}
```

- `clear()` 仅清 SDK 实例的内存状态；SDK 不持久化 token，调用方还须清除自己的 token 副本。
- 不提供 `AutoRefreshingSession` 默认行为；自动续期由调用方显式编排。

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
  entitlement.rs      typed entitlement model
  license_file.rs     offline signature verification
  preferences.rs      preference handoff
```

商业模块已按文件拆分；feature-gating 及可选化 `chrono` / `ed25519-dalek` 依赖尚未实现，作为独立的后续瘦身工作，不阻挡当前登录 SDK 采纳。

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
| `cargo test` | 默认与 `blocking` feature 测试均通过；覆盖 refresh/logout、nonce、state-keyed transaction 和 async transport |
| `python3 ops/scripts/sdk_paradigm.py check` | Rust capability symbols 指向拆分后的真实模块；检查通过 |
| 跨 SDK fixture | `login` / `refresh` / `logout` 三条 fixture 五语言同构（§6.2） |
| 发布 | `cargo publish` 成功，`sdks/rust` 从未提交状态转为 tag `sdk-rs-v0.4.0` |

## 8. 采纳顺序（Aero IM）

1. W4 Transport + W3 Session、模块拆分和本地测试已完成。
2. 授权发布至 crates.io；Aero IM 只能使用版本依赖（非 path/git）。
3. Snaplink 侧 `aero-im` 改公共客户端（先 `--validate-only` 过再替换 Secret）。
4. `sso.rs` 用 SDK 接管 authorization redirect、state/PKCE transaction 与 code exchange；
   SDK callback 结果提供生成的 nonce。**保留** `validate_id_token`、`oidc_jwks_provider` 和
   nonce 比对：SDK 不验证 ID-token 签名，Aero IM 必须继续按 issuer/audience/JWKS 校验后
   才能 JIT provision。适配器复用现有 scoped HttpOnly/Secure cookie 边界。
5. 重建 `aero-im` 镜像、导入 containerd、滚动更新，用无头浏览器验证
   登录起点 → Snaplink → 回调 → 会话落地全链路。

## 9. 风险

| 风险 | 缓解 |
|---|---|
| 公开客户端弱于机密客户端 | PKCE S256 + 精确 redirect URI 强制；secret 本就存于同一集群，不构成隔离 |
| SDK 未发布即被引用 | §7 要求先发布再引用，禁止 path 依赖进生产镜像 |
| crates.io 尚未发布 | 发布前不得将本地/path 依赖并入 Aero IM 部署构建 |
| OIDC token 误信 | Aero IM 保留 `validate_id_token`、JWKS issuer/audience 与 SDK nonce 比对 |
| 多副本下 `MemoryStateStore` 失效 | 文档标注仅单进程；Aero IM 提供 cookie 实现 |
