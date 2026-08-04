已完成全局扫描（`interfaces/ssoclient/` 全部 29 个源文件、`interfaces/sso` 服务端 API、`shared/security`、`gen/proto`、`docs/feature-matrix.md`、`docs/examples/embedded-app`、`test/` 集成面）。以下是基于证据的分析结论。

## 1. 补全 App 侧令牌获取层（OAuth Client）：PKCE/PAR/Device/Refresh/client_credentials + DPoP 证明生成

**问题**：`ssoclient` 目前只是"验证 + 授权 + 审计"门面，App 无法用它向 SSO 服务器**获取**令牌。`doc.go` 宣称"库 vs 网络部署可替换"的承诺只覆盖验证侧；服务端实现的全部获取路径在客户端零封装，App 要么手写 `/token` 协议，要么引入第三方 OAuth 客户端库。更尖锐的是 DPoP：全仓库只有验证端和服务端 nonce 颁发，没有客户端证明生成器——DPoP 发送者约束令牌在 SDK 生态中实际上不可用。

**证据**：
- `interfaces/ssoclient/client.go`：`AuthClient` 只有 `ValidateToken`/`Logout`，注释明言 "Login flow is intentionally NOT in this interface"；`remote/auth.go` 无任何 token 获取方法。
- 服务端能力齐备但无客户端对应物：`interfaces/sso/accessors.go` 的 `PARStore`/`DeviceCodeStore`/`CIBAStore`/`TokenExchangePolicy`、`server_routes.go:182` 的 `PathRevoke`、feature-matrix 第 137 行的 workload identity（GCP/AWS/Azure）。
- DPoP 三处代码均为"非客户端"：`interfaces/ssoclient/rs/dpop.go`（RS 验证）、`interfaces/sso/server_dpop.go`（AS 颁发 nonce）、`shared/security/jti_replay.go`（重放存储）。没有任何生成 `dpop+jwt` 证明的签名逻辑，也没有 mTLS/`private_key_jwt` 客户端认证助手。

**为什么需要**：产品定位是"embeddable SSO SDK"，但嵌入方无法使用自家服务器已实现的旗舰能力（DPoP、PAR、设备流、RFC 8693 exchange、client_credentials 服务间调用）。没有证明生成器，RS 端 `rs/dpop.go` 的完整验证体系形同虚设——这是"发送者约束"安全模型从 AS 到 RS 链路中缺失的最后一环，也是多 App 共享中心 SSO 时服务间调用的刚需。

## 2. 统一并加固验证契约：ssoclient 门面缺失 iss/aud 强制，弱于其封装的 rs 层

**问题**：同一仓库内，面向 RS 的 SDK（`rs`）强制 `iss` 精确匹配 + `ExpectedAud`，而面向 App 的门面 `ssoclient` 只校验签名和时间。`remote.AuthClient.ValidateToken` 解析出 `Iss` 却从不比较，`aud` 仅透出到 `Subject` 不校验；`local` 实现同样不校验。多 App 共享中心 SSO 正是 `remote` 的典型场景，此时 App 可以接受"为另一个 client 签发"的令牌（横向越权面）。此外 `remote.Logout` 在 `logoutURL` 未配置时**静默返回 nil**，与服务端 `/token/revoke` "200 无论 token 是否存在"的标准语义相悖。

**证据**：
- `interfaces/ssoclient/remote/auth.go`：`ValidateToken` → `validateTokenTime` 仅做 exp/nbf；`jwtPayload.Iss` 字段解析后从未被读取（`subjectFromPayload` 不用它）；`AuthOption` 只有 `WithAuthHTTPClient`/`WithLogoutURL`，无 expected-issuer/audience 选项。`Logout` 首行 `if c.logoutURL == "" || req == nil { return nil }`。
- `interfaces/ssoclient/local/auth.go`：`ValidateToken` 无 aud 校验；`docs/examples/embedded-app/main.go` 甚至用 `clientID=""` 规避 aud 问题（注释自认）。
- 对照：`interfaces/ssoclient/rs/validate.go` `validateClaims` 强制 `Issuer` 精确匹配 + `ExpectedAud`，`rs/middleware.go` 完整实现 401/403 挑战语义；服务端 `server_routes.go:182` 有标准 RFC 7009 `POST /token/revoke`（`interfaces/sso/options_misc.go:165` 的 deny-set 语义）。

**为什么需要**：这是安全契约不对称——门面比其封装的内核更弱。`aud` 校验缺失在多租户/多 App 部署下是实打实的越权面；静默 no-op 的 `Logout` 让调用方误以为撤销已生效（`client.go` 注释自己承认"downstream cache might take their TTL to clear"，但连撤销请求本身都可能没发出）。修复成本极低（选项注入 + 校验），收益是消除整个门面层最大的安全隐患。

## 3. 补齐 App 侧事件平面：CAEP/backchannel-logout 接收端 + 批量审计流

**问题**：`rs` 本地验证模式文档明确承认撤销盲区（"revocation before natural expiry is NOT visible in this mode"），而服务端已具备完整推送基建（CAEP Transmitter/StreamStore/Receiver、OIDC backchannel logout 服务端、logout token 签发、重试队列），`ssoclient` 却没有任何 App 侧接收端：无 SET 验证器（`secevent+jwt` typ 校验、jti 重放检查）、无 `backchannel_logout_uri` 的 logout-token 校验助手。App 感知"用户全局登出/会话吊销"只能等 TTL 过期。审计面同样滞后：proto 已定义流式 API，`remote/audit.go` 只有 unary `Record`，`doc.go` 写着 "remote impls keep a background goroutine if streaming is wired"——从未接线。

**证据**：
- 服务端能力：`interfaces/sso/options_security.go` 的 `WithCAEPTransmitter`/`WithCAEPStreamStore`/`WithCAEPReceiver`；`interfaces/sso/server_backchannel_logout.go`（RP 通知、logout token、`backchannelHTTPError` 重试语义）；`test/ssf_stream_e2e_test.go`、`test/caep_integration_test.go`、`test/backchannel_logout_test.go` 证明端到端已通。
- App 侧空白：`interfaces/ssoclient/` 下无任何 caep/SSF/backchannel 文件；`shared/security/jti_replay.go` 的 `JTIReplayStore` 只有服务端使用。
- 审计流未接线：`gen/proto/audit/v1/audit_grpc.pb.go` 已生成 `AuditWriter_StreamEvents`；`interfaces/ssoclient/remote/audit.go` 仅 unary `Record`（注释要求高吞吐调用方自行批处理）；`interfaces/ssoclient/doc.go` 的批处理承诺未兑现。

**为什么需要**：安全事件闭环依赖 App 感知。本地验证（性能最优模式）的撤销盲区只能靠 CAEP 推送弥补，否则用户被全局登出后，App 缓存仍接受其令牌——这是 `client.go` 注释自己承认的过期窗口问题，而服务端推送基建已经完备，缺的只是接收端封装。审计流式 API"定义了未接线"是文档承诺与实现的漂移，高吞吐 App 每事件一次 RPC 的成本（无缓冲、无重试、无背压）会直接劝退 `remote` 审计的采用。

---

**优先级建议**：#2 是纯加固、成本最低、风险最高（安全不对称），应最先做；#1 是最大的产品增量（解锁 DPoP/PAR/服务间调用），决定 SDK 能否兑现"嵌入式 OAuth 客户端"定位；#3 是生态完备性，与 #1 的服务间调用场景天然互补。三者互不依赖，可并行排期。
