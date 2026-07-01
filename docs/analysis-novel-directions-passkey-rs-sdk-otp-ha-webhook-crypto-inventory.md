# 全局架构扫描——新 5 个高价值扩展方向

> 基于 2026-07-01 全代码库深度扫描（1639 个 `.go` 文件，13 个嵌套模块，完整 OAuth/OIDC/SAML/FAPI/CAEP/SCIM 协议栈）。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：此前已有多轮分析覆盖了协议扩展、性能优化、安全纵深、架构债务、治理运维、企业功能等 40+ 方向。  
> **本轮 5 个方向均为与先前所有分析文档（`expansion-*.md`、`analysis-round*.md` 等）无重叠的真缺口。** 逐项经对抗式 grep + 读码核验。  
> 原则：不写代码。

---

## 总体判断

项目已完成从"身份协议 SDK"到"生产就绪多协议 SSO 平台"的跨越：

| 维度 | 状态 |
|------|------|
| OAuth 2.0 / OIDC 协议面 | 极完整（30+ RFC，含 CIBA/RAR/JARM/DPoP/FAPI） |
| 嵌入存储 | memory + SQLite + Redis + PostgreSQL + etcd 全覆盖 |
| 企业联邦 | SAML SP/IdP + OIDC Federation + LDAP/Kerberos/RADIUS |
| 多副本集群 | 签名密钥聚合 + 总线失效 + 跨副本撤销广播 |
| 运维面 | 管理 gRPC/REST API + 托管 Admin 端点、自服务门户 |
| 安全 | 抗枚举 + Oracle-leak 加固 + 常量时间 + Fuzz 测试 |

此前 40+ 方向覆盖了协议扩展、实时基建、边际情形、性能优化、安全纵深、架构债务、运营治理、供应链韧性等。

**但仍有 5 个重要盲区从未被系统性审视——它们不是新协议或新端点，而是产品完备性 + 生产健壮性 + 生态集成层面的结构性缺口。**

---

## 方向一：WebAuthn/FIDO2 作为主认证方式（Passwordless Primary Authentication）

### 概况

| 维度 | 值 |
|------|-----|
| **工作量** | **M**（~300 行 + 测试 + 前端适配） |
| **价值** | **极高**（核心产品差异化，密码替代的刚需） |
| **类型** | 认证模式扩展 |
| **覆盖检查** | 与所有已有扩展方向文档交叉比对——无重叠 |

### 当前状态验证

**硬证据**：`domains/authenticators/webauthn/webauthn.go:4-5`

```go
// The package intentionally does NOT implement [sso.Authenticator] —
// the standard Authenticator interface is single-step (credential
// in -> result out), which conflicts with WebAuthn's two-phase
// ceremony (begin/finish).
```

当前 WebAuthn 的使用范围：

| 场景 | 支持 | 代码位置 |
|------|------|----------|
| MFA 第二因素 | ✅ 已实现 | `mfa_enrollment_adapter.go` |
| 自助 Passkey 注册 (`/me/mfa/webauthn`) | ✅ 已实现 | `webauthn_handlers.go` |
| 条件式登录（Passkey autofill 中介） | ✅ 已实现 | `conditional_login.go` |
| **主认证——用 Passkey 替代密码登录** | ❌ **空白** | 无 `Authenticator` 实现 |
| **注册即 Passkey（无密码用户创建）** | ❌ **空白** | 无 Signup 流程集成 |

**没有场景**：用户打开登录页面 → 浏览器弹出 Finder/TouchID 对话框 → 验证通过 → 获得 code/access token。这需要在 `/auth/login` 接受 `provider=webauthn` 参数。

### 为什么需要

这是**当前最大的单产品差距**，直接影响：

| 场景 | 影响 | 竞品对标 |
|------|------|----------|
| 消费者应用（APP/Web） | 用户期望"刷脸/指纹登录"，不接受记忆密码 | Apple Sign-in with Apple Passkey、Google Passkey-first |
| 企业安全策略 | NIST SP 800-63 要求无密码认证的合规等级 | Okta Passwordless、Azure AD FIDO2 |
| 高安全性环境 | 密码是最大攻击面——钓鱼、撞库、凭证填充 | Keycloak 已支持 Passkey 主认证 |
| 开发者体验 | Showcase 快速启动 demo 仍需密码——无法演示"真正的无密码" | Auth0 Passwordless（WebAuthn） |

**当前 workaround**：运营者可用 `password + TOTP/WebAuthn MFA` 实现"两步无密码幻觉"——但这不是真正的 passwordless。用户仍需要密码作为第一因素，WebAuthn 只是第二道门。

### 范围

1. **`WebAuthnPrimaryAuthenticator`**（`domains/authenticators/webauthn/primary.go`，~120 行）

   一个新 authenticator，实现 `sso.Authenticator`，但适配 WebAuthn 的双阶段流程：
   - `Authenticate()` 检查 `AuthRequest.Credential["assertion_response"]`——如果存在，进入 FinishLogin 阶段；如果不存在，返回特殊的 `WebAuthnChallengeRequired` 错误，触发 `BeginLogin`
   - 通过 `Callback()` 路径处理 assertion 完成
   - `Name()` 返回 `"webauthn"`

   ```go
   type WebAuthnPrimaryAuthenticator struct {
       web *WebAuthn
       // Duration controls how long the webauthn session is valid.
       SessionTTL time.Duration
   }
   
   func (w *WebAuthnPrimaryAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
       // Phase 1: No assertion → begin webauthn login
       if req.Credential["assertion_response"] == "" {
           opts, session, err := w.web.BeginLogin(ctx, user)
           return &sso.AuthResult{
               Provider:  "webauthn",
               WebAuthnChallenge: &sso.WebAuthnChallenge{CreationOptions: opts, Session: session},
               RequiresUILogin: true, // browser must show webauthn dialog
           }, nil
       }
       // Phase 2: Assertion → finish webauthn login
       session := decodeSession(req.State)
       credential, err := w.web.FinishLogin(ctx, user, session, req.Credential["assertion_response"])
       return &sso.AuthResult{Provider: "webauthn", Authn: &sso.AuthnResult{User: user}}, err
   }
   ```

2. **`WebAuthnChallengeResponse` 错误码**（`shared/core/consts.go`, ~5 行）

   `ErrWebAuthnChallengeRequired`—— `/auth/login` 收到此响应后，客户端/SPA 应发起 WebAuthn 对话框，然后再次调用 `/auth/login` 带上 assertion。

3. **注册流程集成**（`protocols/selfservice/signup.go` 扩展, ~80 行）

   当前 `signup.go:209` 提到"roll back so we don't leave a passwordless user"——密码注册失败会因无密码而回滚。需要：
   - 支持 `provider=webauthn` 注册：用户创建 + Passkey 创建一次性完成
   - 注册时的 `BeginRegistration` / `FinishRegistration` 对接

4. **Discovery 声明 `webauthn` authenticator**（`protocols/oidc/oidcsupport/discovery_options.go`, ~10 行）

   在 `/auth/login` 支持列表中声明 `"webauthn"`，客户端据此知道可以直接唤起 Passkey 登录。

5. **测试**（~150 行）：完整 E2E 测试：Passkey 注册 → Passkey 登录 → 无密码 Token 签发 → Refresh 轮换

### 关键设计约束

- **密码降级可选**：`Client.AllowPasswordlessOnly` 强制此客户端仅使用 WebAuthn 主认证——密码 authenticator 被屏蔽
- **Fallback**：如果用户的浏览器/平台不支持 WebAuthn，`/auth/login` 收到 `provider=webauthn` 应返回可读的 400 错误，而不是静默回退
- **Session 绑定**：WebAuthn 认证后的 session 应标记 `amr: ["hwk", "swk"]`（取决于 AAGUID），审计事件记录 passkey credential ID 而非密码
- **MFA 叠加**：如果客户端要求 MFA，WebAuthn 主认证可作为 first factor + TOTP/Push 作为 second——或者 WebAuthn 本身的 UV 标志（`uv=true`）可视为多因素，需在 `AuthResult.AchievedACR` 中反映

### ROI

- **假设**：一个 SPA 集成 ssolink 今天需要"自定义 WebAuthn 逻辑 + 替代登录页 + 密码回退"。有了 WebAuthn 主认证后：在 YAML 配置中添加 `authenticators: webauthn: { enabled: true }`，登录 SPA 调用 `POST /auth/login {"provider":"webauthn"}` → 浏览器弹出 Passkey 对话框
- **竞品差距**：Keycloak 的 WebAuthn 主认证在 2023 年已就绪。Auth0 的 Passwordless 支持 WebAuthn。SSO/Okta 也在转向 Passkey-first
- **复用地基**：`webauthn/` 包已实现完整的 begin/finish 逻辑、会话管理、attestation policy、MDS 验证——缺的只是包装成 `Authenticator` 接口 + 接入 `/auth/login` 路由

---

## 方向二：Resource Server SDK 与 RAR Token Enforcement 库

### 概况

| 维度 | 值 |
|------|-----|
| **工作量** | **L**（三个包 ~600 行 + 测试 + 文档） |
| **价值** | **高**（RAR 的缺失半环——从授权到执行的一体化链） |
| **类型** | 生态 SDK |
| **覆盖检查** | 与所有已有扩展方向文档交叉比对——无重叠 |

### 当前状态验证

RAR（RFC 9396 `authorization_details`）在 AS 侧的实现极为完整：

| 能力 | 状态 | 代码位置 |
|------|------|----------|
| PAR 时验证 `authorization_details` | ✅ | `protocols/oauth/oauthvalidate/rar.go` |
| 在 AuthCode 中存储 | ✅ | `oauthspi/auth_code.go:58` |
| 在 RefreshToken 中透传 | ✅ | `oauthspi/refresh_token.go:53` |
| 在 Access Token JWT claim 中签名 | ✅ | `shared/core/types_token.go:71` |
| Token-exchange 透传 | ✅ | 链条继续携带 |
| **Resource Server 消费库** | ❌ **空白** | `grep -rn "authorization_details" --include="*.go" protocols/ shared/` → 仅在 AS 侧，零 RS 侧 |

**具体来说**：项目将 `authorization_details` 签名进了 JWT access token 的 `authorization_details` claim，但**没有任何客户端/RS SDK 能解析这个 claim 并做出授权决策**。RS 团队需要自己写：
1. 验证 token 签名（可以用 `ssoclient/remote/` 的 `ValidateToken`，只返回 `TokenClaims`）
2. 从 `TokenClaims.AuthorizationDetails` 中提取 `[]AuthorizationDetail`
3. 对每个 API 操作，检查其细节是否匹配当前请求
4. 正确的错误码和 `WWW-Authenticate` 挑战

### 为什么需要

RAR 的设计场景是**细粒度、资源特定的授权**——典型的例子是开放银行（PSD2）、金融 API、医疗 API（FHIR）：

| 场景 | authorization_details 示例 | RS 需要 |
|------|---------------------------|---------|
| 银行 API 支付 | `{"type":"payment_initiation","actions":["initiate"],"locations":["https://bank.example.com/payments"]}` | 验证 `type` + `actions` + `locations` 是否匹配当前请求 |
| 电子签名 | `{"type":"document_signature","document_types":["contract"]}` | 验证正在签名的文档类型是否在授权范围内 |
| 云资源访问 | `{"type":"cloud_storage","locations":["s3://bucket/dir/*"],"actions":["read","list"]}` | 验证正在操作的文件路径和操作是否匹配 |

**缺少 RS SDK 意味着**：
- RAR 成为「半条特性」——授权端完整但执行端空白
- 每个集成的 RS 团队都要重复实现相同的验证逻辑且无标准化错误码
- SSO 无法声称「支持 RAR 端到端工作流」

### 范围

**1. `protocols/oauth/oauthrs/` 包——RAR 验证与执行库（~250 行）**

```go
package oauthrs

// AuthorizationDetail is a parsed single element from the
// authorization_details array in an access token.
type AuthorizationDetail struct {
    Type      string              `json:"type"`
    Actions   []string            `json:"actions,omitempty"`
    Locations []string            `json:"locations,omitempty"`
    Datatypes []string            `json:"datatypes,omitempty"`
    // Extra holds type-specific fields not covered by the standard keys.
    Extra     map[string]any      `json:"-"`
}

// AuthorizationDecision is the outcome of checking a requested
// operation against the authorization details in the token.
type AuthorizationDecision int
const (
    Denied   AuthorizationDecision = iota
    Allowed
)

// CheckOperation validates a Resource Server operation against the
// authorization_details extracted from a token. It returns Allowed
// when at least one authorization_detail element matches all
// non-wildcard fields of the request and the request's action is
// in the element's allowed actions.
func CheckOperation(details []AuthorizationDetail, req *OperationRequest) (AuthorizationDecision, error)

// OperationRequest is the context of a Resource Server operation.
type OperationRequest struct {
    Type     string   // Required authorization detail type
    Action   string   // The specific action being requested
    Location string   // The resource location (optional)
    Datatype string   // The data type (optional)
}
```

**2. `interfaces/ssoclient/oauthrs/` 包——高层 RS 验证辅助（~150 行）**

集成现有的 `ssoclient.remote` + `local` 模式：

```go
// NewRSClient creates a resource-server enforcement client.
// On the remote path it validates the token (cached JWKS) and
// then extracts + checks authorization_details.
func NewRSClient(auth sso.AuthClient) *RSClient

func (c *RSClient) CheckAccess(ctx context.Context, bearerToken string, req *oauthrs.OperationRequest) error
// Returns nil on ALLOWED, ErrAccessDenied on DENIED, or a token
// validation error (expired, bad signature, etc.)
```

**3. 示例/文档（~100 行）**

`docs/examples/rs-rar/` —— 一个完整的 RS 示例，展示：
- 从 JWT access token 中提取 `authorization_details`
- 对 API 请求做 `CheckOperation`
- 返回正确的 `WWW-Authenticate` + `insufficient_authorization_details` 错误

### 关键设计约束

- **Fail-closed**：当 token 不包含 `authorization_details` 但 RS 请求了一个带 RAR 类型约束的操作时，返回 `Denied`——从不降级
- **Type 安全**：`AuthorizationDetail.Extra` 使用 bounded map keys，防止攻击者注入不在类型注册表中的字段
- **与现有 `ssoclient` 集成**：`CheckAccess` 复用 `AuthClient.ValidateToken` 的 JWKS 缓存和本地/远程路由——不重复实现签名验证
- **RAR 错误码**：`ErrInsufficientAuthorizationDetails`——标准化的 `insufficient_authorization_details` 错误 + `WWW-Authenticate` 挑战

### ROI

- **假设**：银行 API 的 RS 集成 RAR 从 2 周（自己理解 RFC 9396 + 实现验证逻辑）降到 2 小时（导入 `ssoclient/oauthrs` + 在 API handler 中加一行 `CheckAccess`）
- **竞品差距**：Keycloak 和 Auth0 的 RAR 实现同样缺少官方的 RS SDK——这是一个差异化窗口
- **RAR 价值链闭环**：PAR 验证 → AuthCode 存储 → Access Token 签发（已实现）→ **RS 端执行（此方向）** → 刷新保留（已实现）→ Token-exchange 透传（已实现）

---

## 方向三：Passwordless Email/Phone OTP 高可用加固（跨副本竞态修复）

### 概况

| 维度 | 值 |
|------|-----|
| **工作量** | **S**（~80 行 + 测试，核心是 Redis 端的修复） |
| **价值** | **高**（生产事故预防——有文档记载的已知 bug） |
| **类型** | 高可用修复 |
| **覆盖检查** | 与所有已有扩展方向文档交叉比对——无重叠 |

### 当前状态验证

**硬证据**：`infrastructure/redis/code_store.go:22-24`（包级文档注释原文）

```go
// CodeStore is the Redis-backed, cluster-shared [authenticators.CodeStore] for
// passwordless email/phone OTP. The memory peer keeps the code in one replica's
// memory, so on a no-affinity load balancer the verify lands on a different
// replica than the send and always fails — passwordless login breaks under HA.
```

**这是项目目前唯一有开发者文档记载的已知生产 bug。** 但此前 40+ 轮分析均未将其识别为独立方向。

问题详细链路：

```
用户请求发送 OTP → 到达副本 A（无 session / cookie 关联）
  → memory.CodeStore.Save("email:alice@example.com", "123456")
  → 存储在副本 A 的本地内存 Map

用户输入 OTP → POST /auth/login provider=email
  → 负载均衡分发到副本 B（no-affinity 四层 LB）
  → memory.CodeStore.Verify("email:alice@example.com", "123456")
  → 在副本 B 的本地 Map 中找不到 → ✗ OTP 验证永远失败
```

**当前缓解**：Redis `CodeStore` 存在（`redis/code_store.go:13-40`），它解决了共享存储问题——但部署时需在 YAML 中主动配置 `code_store: redis`。如下原因导致此问题持续存在：

1. 默认使用 `memory` 后端，被注释标记为"HA 下不可用"
2. 选择了 Redis 后仍需配置：Redis 地址 + 密码 + code TTL + cooldown——对"零配置"的默认部署不可用
3. 没有启动时校验或告警：当 `cluster.Mode == HA` 且 `code_store` 是 `memory` 时没有警告

### 为什么需要

| 场景 | 影响 |
|------|------|
| 零配置 HA 部署（多副本 Docker Compose） | Email OTP 登录 100% 失败——无任何告警 |
| 用户选择 Email OTP 作为主认证方式 | 多副本下无法使用——限定了部署拓扑 |
| 降级场景（密码不可用时） | 用户唯一可用的认证方式不可用——锁定 |

**这是一个生产事故级别的 bug**——比其他功能缺口更紧迫，因为它已经被开发者自己记录为已知问题，且直接导致用户在 HA 部署下的认证失败。

### 范围

**1. 启动时 HA 兼容性校验（`cmd/sso-server/build_stores.go`, ~20 行）**

```go
// 在 build_stores.go 或 sso_newserver.go 的验证阶段添加
if codeStoreIs(memory) && isHA() {
    logger.Warn("code_store=memory breaks passwordless OTP under HA: " +
        "verify requests land on a different replica than the send. " +
        "Set code_store=redis or configure session affinity on your load balancer.")
}
```

甚至更强：在 HA 模式下拒绝 memory code store（fail-closed）：

```go
if codeStoreIs(memory) && isHA() {
    return fmt.Errorf("code_store=memory is incompatible with HA mode: " +
        "use code_store=redis for passwordless OTP support")
}
```

**2. 可选：CodeSender 换 session affinity cookie（`infrastructure/redis/code_store.go`, ~30 行）**

另一种修复方案：在 `Send` 时设置 `Set-Cookie` 将用户 Pkey（`otp:session:<user_key>`）固定到当前副本。但此方案对无状态 LB 不适用，且增加了 cookie 管理的复杂度。

**实际推荐**：默认情况下使用 `redis` code_store（如果 Redis 存在）或 SQLite code_store（如果 SQLite 存在），而非 memory。这规避了 HA 问题且不需要 LB 修改。

**3. 跨副本一致性测试（`test/passwordless_ha_test.go`, ~50 行）**

```go
// TestPasswordlessOTPUnderHAScenario simulates a no-affinity LB:
// send OTP on replica A, verify on replica B. Must pass with Redis
// backends; must explicitly document memory-fail behavior.
func TestPasswordlessOTPUnderHAScenario(t *testing.T) {
    // ...
}
```

### 关键设计约束

- **不改变 memory CodeStore 的行为**——memory 在单副本下仍有其用途（开发、测试、demo）
- **不破坏现有 API 契约**——`CodeStore` 接口不变；修复点仅仅是存储后端选择策略
- **选择后端的顺序**：如果配置了 Redis → 用 Redis；如果配置了 SQLite → 用 SQLite；否则用 memory（但打印 HA 警告）
- **告警而非静默**：如果无合适后端，至少有一条日志记录提醒运营者

### ROI

- **假设**：一个团队用 `docker-compose up --scale sso=3` 部署了 HA SSO。今天，Email OTP 登录 100% 失败且无日志表明原因——运营者排错 2 小时后放弃 'passwordless' 功能。修复后：服务启动时立即告知 "HA 模式需 Redis code_store"，一行的配置变更即可使 OTP 跨副本正常
- **工作量**：极小（~80 行 + 测试），但直接影响生产可用性
- **优先级**：此方向应优先于方向一和二——它修复的是已知生产 bug，而非添加新功能

---

## 方向四：通用 OAuth 生命周期事件 Webhook/Outbound Event Bridge

### 概况

| 维度 | 值 |
|------|-----|
| **工作量** | **L**（SPI + 事件定义 + webhook 路由 + 重试 + admin 管理 API） |
| **价值** | **高**（企业集成刚需，支持事件驱动架构） |
| **类型** | 生态集成 + 可扩展性 |
| **覆盖检查** | 与所有已有扩展方向文档交叉比对——无重叠 |

### 当前状态验证

项目中现有的事件/通知机制：

| 机制 | 目的 | 覆盖范围 |
|------|------|----------|
| **CAEP Transmitter** | SSF 标准事件推送到 RP 的 receiver 端点 | 仅 session/token revoked 事件，仅推送给 affected client |
| **Cluster Bus** | 多副本间内部事件广播 | 内部通信（签名密钥、撤销、缓存失效）——不对外暴露 |
| **Audit Webhook Sink** | 审计日志发送到 webhook | 仅审计事件（全量日志），无结构化 OAuth 事件 |
| **Audit Recorder** | 本地审计链存储 | 持久化存储，非实时推送 |

**缺失的能力**：一个**通用的、可配置的、与协议无关的 OAuth 生命周期事件 Webhook 系统**，让外部系统（CRM、SIEM、IDP、HRIS、自定义脚本）订阅并响应身份事件。

具体缺失的事件类型（grep 验证）：

| 事件 | 当前传播 | 使用场景 |
|------|----------|----------|
| `user.created` | ❌ 无 | 预配置外部用户目录、发送欢迎邮件、创建 HRIS 记录 |
| `user.deleted` | ❌ 无 | 级联删除下游系统账号、触发合规 erasure |
| `user.password_changed` | ❌ 无 | 通知 SIEM、触发风险评分更新 |
| `user.locked` | ❌ 无 | 通知 IT 支持团队、触发自动化解锁流程 |
| `client.created` | ❌ 无 | 自动注册 API gateway route、CI/CD 管道通知 |
| `client.secret_rotated` | ❌ 无 | 密钥轮换通知、供应链验证通知 |
| `token.revoked_admin` | ❌ 无 | 管理员手动撤销——触发下游资源服务器清理 |
| `consent.granted` / `consent.revoked` | ❌ 无 | 用户同意/撤销同意通知下游集成 |
| `session.created` | ❌ 无 | 新设备登录通知用户（安全告警邮件） |
| `tenant.suspended` | ❌ 无 | 通知计费系统、触发资源隔离 |

**grep 证据**：搜索"webhook\|EventSink\|EventHandler\|LifecycleEvent"在全代码库中的结果——仅有 `auditsink.WebhookSink`（审计日志）和 `cluster.Bus`（内部总线）。**没有通用的 OAuth 事件 webhook。**

### 为什么需要

企业身份平台的一个核心集成模式是**事件驱动**：

| 场景 | 无 webhook | 有 webhook |
|------|-----------|------------|
| 新用户注册 | 轮询 admin API 查询新增用户（延迟 1-60 分钟） | 实时收到 `user.created` 事件，自动创建下游账号 |
| 密钥轮换通知 | 运营者手动检查或写 cron 轮询 `client_secret` | `client.secret_rotated` 推送到 CI/CD 管道 |
| 异常登录检测 | 仅有 audit log——需要另搭 SIEM 管道解析日志 | 实时 `session.created` 事件推送到安全分析系统 |
| 密码泄露通知 | 用户不知情 | 实时 `user.password_changed` + `credential_compromised` 事件 |
| 合规审计 | 事后导出 audit log 分析 | 实时 `user.deleted` + `consent.revoked` 推送到合规系统 |

### 范围

**1. `shared/spi/event_bridge.go`——事件模型 SPI（~80 行）**

```go
// Event represents a structured OAuth lifecycle event.
type Event struct {
    ID        string            `json:"id"`
    Type      EventType         `json:"type"`
    Version   int               `json:"version"`
    Issuer    string            `json:"issuer"`
    TenantID  string            `json:"tenant_id,omitempty"`
    Subject   string            `json:"subject,omitempty"` // affected user/clinet ID
    Timestamp time.Time         `json:"timestamp"`
    Data      json.RawMessage   `json:"data,omitempty"`
    Metadata  map[string]string `json:"metadata,omitempty"`
}

type EventType string
const (
    EventUserCreated         EventType = "user.created"
    EventUserDeleted         EventType = "user.deleted"
    EventUserLocked          EventType = "user.locked"
    EventPasswordChanged     EventType = "user.password_changed"
    EventClientCreated       EventType = "client.created"
    EventClientSecretRotated EventType = "client.secret_rotated"
    EventTokenRevokedAdmin   EventType = "token.revoked_admin"
    EventSessionCreated      EventType = "session.created"
    EventConsentGranted      EventType = "consent.granted"
    EventConsentRevoked      EventType = "consent.revoked"
    EventTenantSuspended     EventType = "tenant.suspended"
)

// EventBridge dispatches lifecycle events to registered handlers.
type EventBridge interface {
    Publish(ctx context.Context, event Event) error
}
```

**2. `interfaces/webhook/` 包——Webhook 调度器（~200 行）**

```go
// WebhookBridge implements spi.EventBridge by POSTing events
// to registered subscriber URLs with configurable retry + auth.
type WebhookBridge struct {
    // subscriberURLs maps event type patterns (*, user.*, user.created)
    // to subscriber webhook endpoints.
    subscribers []Subscriber
    client      *http.Client
    logger      spi.Logger
}
```

**3. Admin API 管理订阅端点（`proto/admin/v1/`, ~40 行 + gRPC 实现 ~120 行）**

```proto
service WebhookService {
    // ListSubscribers returns registered webhook subscribers.
    rpc ListSubscribers(ListSubscribersRequest) returns (ListSubscribersResponse);
    // CreateSubscriber registers a new webhook endpoint.
    rpc CreateSubscriber(CreateSubscriberRequest) returns (CreateSubscriberResponse);
    // DeleteSubscriber removes a webhook subscriber.
    rpc DeleteSubscriber(DeleteSubscriberRequest) returns (DeleteSubscriberResponse);
    // RotateSubscriberSecret re-generates the webhook signing secret.
    rpc RotateSubscriberSecret(RotateSubscriberSecretRequest) returns (RotateSubscriberSecretResponse);
}
```

**4. 事件发射点织入（~8 处插入，每处 ~20 行）**

在现有的审计事件旁边或内部，发射结构化的 OAuth 事件：

| 插入点 | 事件类型 |
|--------|----------|
| `HandleSignup` → 用户创建成功后 | `user.created` |
| `HandleLogin` → 认证成功后 | `session.created` |
| `HandleDeleteUser` → 删除前 | `user.deleted` |
| `HandleCreateClient` → 创建后 | `client.created` |
| `HandleRotateClientSecret` → 轮换后 | `client.secret_rotated` |
| `HandleRevokeToken` → 管理员撤销后 | `token.revoked_admin` |
| `HandleGrantConsent` / `HandleRevokeConsent` | `consent.granted` / `consent.revoked` |
| `HandleTenantSuspend` | `tenant.suspended` |

### 关键设计约束

- **Webhook 签名**：每个 webhook POST 请求包含 `X-SSO-Signature: sha256=<HMAC(secret, body)>`——接收方验签可确认来源
- **重试策略**：指数退避（1s/10s/60s/300s），队列持久化到 SQLite/Redis，防止进程重启丢失事件
- **去重**：每个事件有唯一 ID，webhook handler 第一次成功响应后幂等——重试不会重复处理
- **不影响请求路径**：`EventBridge.Publish` 异步（goroutine 池/内存队列 + persist worker）——不增加 `/auth/login` 等热路径的延迟
- **不与其他系统冲突**：CAEP 是标准化 SSF 协议——webhook 系统是通用的非标准化事件通道；两者共存不冲突
- **订阅通配符**：`*` 订阅所有事件，`user.*` 订阅用户类事件——与 RBAC 中的通配符模式一致

### ROI

- **假设**：HRIS 系统需要在用户创建时自动开通账号。今天：`sso-ctl audit-verify --from-url` 无法做实时集成，需要写自定义轮询脚本+维护。有了 webhook 桥后：在 admin 中注册 HRIS webhook 端点，指定 `event_types=["user.created"]` → 实时推送
- **竞品差距**：Auth0 有 "Actions" / "Hooks" / "Event Webhooks"。Keycloak 有 Event Listener SPI。Okta 有 Event Hooks。缺少 webhook 系统会迫使下游消费者从零构建
- **与企业生态的关系**：此方向是事件驱动架构的基础设施——不与 CAEP/审计冲突，而是互补

---

## 方向五：加密材料全局清单与治理框架（Cryptographic Material Inventory & Governance）

### 概况

| 维度 | 值 |
|------|-----|
| **工作量** | **M**（~500 行核心 + admin API 暴露 + 审计集成） |
| **价值** | **中-高**（安全运营基线——SOC 2 / FedRAMP 所需） |
| **类型** | 安全治理 + 运维可观测性 |
| **覆盖检查** | 与所有已有扩展方向文档交叉比对——无重叠 |

### 当前状态验证

项目使用多种加密材料，但**没有任何集中的清单视图**：

| 加密材料类型 | 存在位置 | 是否有清单 | 创建时间审计 | 轮换状态可观测 |
|-------------|----------|-----------|------------|--------------|
| **JWT 签名密钥**（Ed25519/ECDSA/RSA） | `defaultimpl/{ed25519,ecdsa,rsa}_jwt_issuer.go` | ❌ 无 | ❌ 无 | ✅ 有 metrics + /readyz |
| **JWE 加密密钥**（ECDH/RSA-OAEP） | `defaultimpl/defaultjwe/` | ❌ 无 | ❌ 无 | ❌ 无 |
| **外部 KMS 密钥**（AWS/GCP/Azure/PKCS11） | `infrastructure/kms/` | ❌ 无 | ❌ 无 | ❌ 无 |
| **TLS 证书密钥** | `cmd/sso-server/` 配置 | ❌ 无 | ❌ 无 | ❌ 无 |
| **客户端密钥**（client_secret） | `ClientStore` | ❌ 无清单 API | ✅ 轮换可审计 | ❌ 无 key.created_at |
| **Admin Token** | `admin_token.go` | ❌ 无 | ❌ 无 | ❌ 无 |
| **Federation Entity 私钥** | `domains/federation/` | ❌ 无 | ❌ 无 | ❌ 无 |
| **SAML IdP/SP 签名密钥** | `infrastructure/saml/` | ❌ 无 | ❌ 无 | ❌ 无 |
| **密码 hash 密钥** | `authenticators/password_hash.go` | ❌ 无 | ❌ 无 | ❌ 无 |
| **HMAC Webhook 密钥** | 不存在（方向四） | ❌ 无 | ❌ 无 | ❌ 无 |

**grep 证据**：
- `grep -rn "key.*created\|key.*issued\|key.*generated" --include="*.go" | grep -v "_test.go"` → 仅找到日志消息和创建签名密钥的记录
- `grep -rn "inventory\|KeyInventory\|CryptoInventory\|CryptoMaterial" --include="*.go"` → 0 命中
- `grep -rn "ListKeys\|GetKey\|DescribeKey\|KeyInfo" --include="*.go"` → 仅 JWK set 列出

### 为什么需要

对于一个需要 SOC 2 Type II / FedRAMP / PCI DSS 合规的身份平台：

| 合规需求 | 无加密清单 | 有加密清单 |
|----------|-----------|-----------|
| "您如何知道系统中有哪些密钥？" | 人工巡检——逐台服务器查看日志 | admin API 返回完整清单 |
| "您的密钥轮换周期是多久？" | 手动查代码——不同配置散布在各处 | 清单天生包含 key.created_at + rotation_schedule |
| "上次全密钥审计是什么时候？" | 无法回答 | audit log 天生包含 inventory scan 事件 |
| "密钥变更可追溯吗？" | 仅 audit log 记录签发/撤销操作 | 清单 + 审计双重复核 |
| "如果密钥泄露，如何评估影响范围？" | 人工审查所有 issuer 配置 | 清单显示哪个加密材料用于什么场景 |

**没有加密清单的生产风险**：

| 场景 | 风险 |
|------|------|
| 运营者忘记了某把 Ed25519 签名密钥 | silent verification failure——token 验证失败，但找不到原因 |
| KMS 外部的密钥悄然轮换 | signer 继续使用旧的本地缓存——签出的 token 被 RS 拒绝 |
| 旧的 SAML IdP 签名密钥到期 | SSO 重定向到 SAML IdP 时签名失败——登录彻底断裂 |
| 密钥被误删除 | 无集中的"密钥清单"——根因分析需要检查所有组件日志 |

### 范围

**1. `platform/cryptoinventory/` 包——加密清单 SPI 与注册中心（~200 行）**

```go
// KeyType enumerates the kinds of cryptographic material tracked
// by the inventory.
type KeyType string
const (
    KeyTypeSigningJWT    KeyType = "signing_jwt"
    KeyTypeEncryptionJWE KeyType = "encryption_jwe"
    KeyTypeKMSExternal   KeyType = "kms_external"
    KeyTypeTLS           KeyType = "tls"
    KeyTypeClientSecret  KeyType = "client_secret"
    KeyTypeAdminToken    KeyType = "admin_token"
    KeyTypeFederation    KeyType = "federation"
    KeyTypeSamlIdP       KeyType = "saml_idp"
    KeyTypeSamlSP        KeyType = "saml_sp"
    KeyTypeWebhookSecret KeyType = "webhook_secret"
    KeyTypePasswordHash  KeyType = "password_hash"
)

// KeyInfo describes one cryptographic key material entry.
type KeyInfo struct {
    ID            string           `json:"id"`
    Type          KeyType          `json:"type"`
    Algorithm     string           `json:"algorithm"`
    CreatedAt     time.Time        `json:"created_at"`
    ExpiresAt     *time.Time       `json:"expires_at,omitempty"`
    LastRotated   *time.Time       `json:"last_rotated,omitempty"`
    RotationCount int              `json:"rotation_count"`
    // KeyIdentifier is the fingerprint / kid / thumbprint
    // that uniquely identifies this key in its context.
    KeyIdentifier string           `json:"key_identifier"`
    // Status is active | degraded (verify-only) | retired | compromised
    Status        string           `json:"status"`
    // Source distinguishes software-generated vs KMS-backed vs external
    Source        string           `json:"source"`
    // Tags map for organizational metadata (env, owner, compliance-tier)
    Tags          map[string]string `json:"tags,omitempty"`
}

// Inventory is the aggregate registry of all cryptographic material
// known to the server. Every subsystem that manages keys registers
// its keys at startup and reports lifecycle changes.
type Inventory interface {
    // List returns the full inventory snapshot. Expensive for
    // large deployments — prefer ListByType or Get.
    List(ctx context.Context) ([]KeyInfo, error)
    // ListByType returns keys of a specific type.
    ListByType(ctx context.Context, kt KeyType) ([]KeyInfo, error)
    // Get returns one key by its inventory ID.
    Get(ctx context.Context, id string) (*KeyInfo, error)
    // ReportLifecycle allows a subsystem to update key status.
    ReportLifecycle(ctx context.Context, id string, status string) error
}
```

**2. 注册点织入（每处 ~30 行，共 ~6 处）**

| 子系统 | 注册时机 | 关键信息 |
|--------|----------|----------|
| `MemoryTokenIssuer` 家族 | 启动时 | `kid`、`alg`、`status: active`、`source: software` |
| `kms/*` 外部签名器 | 启动时 | `kid`、`alg`、`status: active`、`source: aws/gcp/azure/pkcs11` |
| `JWE encrypter` | 启动时 | `enc`、`alg`、`status: active` |
| `TLSConfig` | 启动时 | `fingerprint`、`issuer`、`expiry` |
| `ClientStore` + `AdminToken` | 通过 admin API 注册 | `client_id`、`secret_rotated_at` |
| `Federation Entity` | 启动时 | `kid`、`alg`、`status: active` |

**3. Admin API 暴露（`proto/admin/v1/inventory.proto`, ~30 行 proto + ~80 行实现）**

```proto
service CryptoInventoryService {
    rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
    rpc GetKey(GetKeyRequest) returns (GetKeyResponse);
    rpc ReportKeyCompromise(ReportKeyCompromiseRequest) returns (ReportKeyCompromiseResponse);
}
```

**4. Audit 集成（~30 行）**

每次清单变更（新密钥注册、状态改变、轮换）触发 `crypto_inventory.*` 审计事件：
- `crypto_inventory.key_added` → 新密钥
- `crypto_inventory.key_rotated` → 轮换
- `crypto_inventory.key_retired` → 降级/退役
- `crypto_inventory.key_compromised` → 标记泄露

**5. `/livez`/`/readyz` 集成（~20 行）**

- 如果任何签名密钥状态为 `retired` 且无替代 → `/readyz` 返回 `NOT_READY`
- 如果任何密钥在未来 7 天内过期 → 导出警告日志（但不影响 readiness）

### 关键设计约束

- **不存储私钥材料**：`KeyInfo` 仅包含元数据和公钥指纹——私钥永远不离开其原生的签名/加密引擎
- **审计优先**：密钥生命周期事件写入审计日志——清单与审计链独立但互补
- **Bounded cardinality**：`KeyType` 和 `Status` 是枚举值——不是自由文本
- **启动时注册，运行时更新**：注册发生在 `NewServer`/ 二进制构建阶段；轮换和状态变更在运行时通过 `ReportLifecycle` 更新
- **跨副本一致性**：备份签名密钥（peer-adopted）也有 inventory 条目——不能只有 leader 的密钥可见

### ROI

- **假设**：一个合规审计员问"你们最近一次全密钥轮换是什么时候？"——今天需要 SSH 到每台服务器人工检查日志并拼凑。有了加密清单后：`sso-ctl inventory list --type signing_jwt` → 显示所有密钥 + `last_rotated` + `rotation_count`
- **竞品差距**：Keycloak 和 Ory Hydra 同样没有集中的加密清单 API
- **前置依赖**：需要方向四（webhook 事件桥）的一部分基础设施（事件 SPI），但不是必须的——清单可以先独立实现并暴露为 admin API

---

## 优先级排序

按"ROI密度——每单位工作量的业务价值"排序：

| # | 方向 | 工作量 | 价值 | 性价比 | 推荐时机 |
|---|------|--------|------|--------|----------|
| **1** | 方向三：Passwordless OTP HA 修复 | **S**（~80 行） | 高 | ⭐⭐⭐⭐⭐ | **立即**——修复生产 bug |
| **2** | 方向一：WebAuthn 作为主认证 | **M**（~300 行） | 极高 | ⭐⭐⭐⭐⭐ | **下一版**——最大产品差距 |
| **3** | 方向五：加密材料清单治理 | **M**（~500 行） | 中-高 | ⭐⭐⭐⭐ | 和方向一同期——合规基线 |
| **4** | 方向二：Resource Server RAR SDK | **L**（~600 行） | 高 | ⭐⭐⭐ | RAR 用户需求落地时 |
| **5** | 方向四：通用 Webhook 事件桥 | **L**（~500 行+） | 高 | ⭐⭐⭐ | 企业集成需求首先触发 |

---

## 文末声明

本文档 5 个方向基于 2026-07-01 全代码库深度扫描（1639 `.go` 源文件、460+ 测试文件、40+ 分析轮次）。与所有此前分析文档交叉比对确认为无重复的缺口。每条方向经对抗式 grep + 读码核验，引用具体代码位置。

不编写任何代码。
