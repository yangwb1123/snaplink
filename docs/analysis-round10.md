# 分析第 10 轮 — WebAuthn Passkey UX / 无浏览器超时 / gRPC 测试缺口 / 配置静默忽略 / Proto 版本策略

> 扫描日期：2026-06-29
>
> 前九次路线：① 产品/协议 → ② `time.Now()`/集群 → ③ 刷新令牌 → ④ 安全头/KDF → ⑤ 会话/密码 → ⑥ session/SAML → ⑦ 注册/Fuzz → ⑧ 邮箱/TTL/审计 → ⑨ Dependabot/测试并行/Helm/发布
>
> 本次聚焦：之前九轮从未触及的 WebAuthn 浏览器 UX、gRPC E2E 测试、配置解析安全性、Proto API 治理

---

## 方向一：WebAuthn 不支持 Conditional Mediation（Passkey 自动填充）— 浏览器无原生 passkey 建议能力

**代码验证：**

```go
// domains/authenticators/webauthn/webauthn.go:243-244
// 创建注册/登录选项时，传递 AuthenticatorSelection 参数：
if cfg.RequireUserVerification {
    gwCfg.AuthenticatorSelection.UserVerification = protocol.VerificationRequired
}
// 但从不设置 ConditionalMediation 相关选项
```

全库零命中：
| 搜索词 | 命中数 |
|--------|--------|
| `ConditionalMediation` | 0 |
| `conditional`（WebAuthn 上下文中） | 0 |
| `autofill` | 0 |
| `mediation` | 0 |

**什么是 Conditional Mediation？**

WebAuthn Level 2 (2023) 定义的 `mediation` 参数允许浏览器以两种模式启动 WebAuthn 认证：

- **`optional`**（默认）：弹出一个**模态对话框**，要求用户点击按钮确认使用 passkey
- **`conditional`**：浏览器在 `<input>` 元素的**自动填充菜单**中列出可用 passkey，用户可以直接选择——不需要弹对话框

**当前实现的行为：**

用户访问登录页面 ↓
输入用户名 ↓
点击"使用 Passkey 登录"（需要额外操作） ↓
浏览器弹出模态框 ↓
用户选择 / 取消

**标准 Passkey UX（使用 Conditional Mediation）：**

用户访问登录页面 ↓
点击用户名输入框 ↓
浏览器自动填充菜单显示 "使用 Passkey 登录" ↓
用户选择 → 自动认证，无需点击额外按钮

```html
<!-- 前端需要：autocomplete="username webauthn" 属性 + ConditionalMediation 启动 -->
<input type="text" name="username" autocomplete="username webauthn">
```

**影响：**

1. 2024-2025 年的 WebAuthn 用户体验标准（Apple Passkeys、Google Password Manager、Microsoft Authenticator）全部使用 Conditional Mediation
2. 当前用户必须**手动点击 passkey 登录按钮** + 确认模态框，两步操作
3. Conditional Mediation 让 passkey 认证与密码自动填充一样无缝
4. 服务端只需要在 `BeginLogin` 调用时传递 `gw.WithConditionalMediation()` 选项

**建议修复：**
- 在 `webauthn.go` 的 `BeginLogin` 方法中添加 `WithConditionalMediation` 选项
- 新增 `POST /webauthn/login/conditional/begin` 端点（区别于常规登录端点）
- 返回 `PublicKeyCredentialRequestOptions` 时带上 `mediation: 'conditional'`
- 前端 HTML/JS 相应更新（使用 `navigator.credentials.get({mediation: 'conditional', ...})`）

---

## 方向二：WebAuthn 注册/认证未设置浏览器可见超时 — 用户无操作时模态框无限等待

**代码验证：**

```go
// domains/authenticators/webauthn/webauthn.go:230-260
// BeginRegistration / BeginLogin 创建 gw.WebAuthn 配置：
gwCfg := &gw.Config{
    RPDisplayName: cfg.RPDisplayName,
    RPID:          cfg.RPID,
    RPOrigin:      cfg.RPOrigin,
    AuthenticatorSelection: ...
    // ❌ 未设置 Timeout
}
```

`go-webauthn` 库的 `gw.BeginRegistration` 和 `gw.BeginLogin` 接受 `gw.WithTimeout(time.Duration)` 选项，该选项在 `PublicKeyCredentialCreationOptions` 和 `PublicKeyCredentialRequestOptions` 中设置 `timeout` 字段。

**当前浏览器行为：**
1. 用户点击"注册 Passkey"
2. 浏览器弹出模态框："xxx 想要保存凭据"
3. 用户走开，吃午餐，回来——**模态框仍在**
4. 唯一退出方式是手动取消（浏览器行为）或等待页面/会话过期

**标准行为（设置 timeout）：**

```go
// go-webauthn 支持的选项
gw.WithTimeout(60 * time.Second) // 60s 后浏览器自动取消模态框
```

`SessionTTL`（`webauthn.go:77`）控制的是**服务器端 session 过期时间**，不是**浏览器端的超时时间**。这两个超时是独立的：
- 服务器端 `sessionTTL`：session 数据在服务器存储中的 TTL（默认 5 分钟）
- 浏览器端 `timeout`：`PublicKeyCredential.timeout`，告诉浏览器多少毫秒后放弃

**影响：**
- 用户无操作时浏览器模态框无限等待，直到服务器 session 过期（5 分钟）——但浏览器仍在等待
- 未决模态框阻塞用户无法在同一标签页中执行其他操作
- 对于自助注册流程（`/me/mfa/webauthn`），用户可能打开模态框后跳去做其他事

**建议修复：**
- 在 `webauthn.go` 的 `Config` 中添加 `CeremonyTimeout time.Duration` 字段
- 在 `BeginRegistration` 和 `BeginLogin` 调用中传递 `gw.WithTimeout(d)`
- 默认值 60 秒（行业标准，符合 FIDO2 规范建议范围 30-180s）
- `WithCeremonyTimeout(d time.Duration)` 配置选项

---

## 方向三：gRPC 管理服务缺少端到端集成测试 — 150+ HTTP 零 gRPC

**代码验证：**

```bash
$ ls test/*_test.go | wc -l
# 150+ 测试文件

$ grep -rn "proto.*admin\|adminv1\.\|ClientAdmin\|UserAdmin\|TokenAdmin\|PermissionAdmin\|TenantAdmin\|SnapshotAdmin\|ReleaseAdmin" test/*_test.go | grep -v "_test.go:"
# 仅发现 test/e2e_test.go 中使用了 bufconn，但用于内部 Authz/Audit 服务
# 管理面 gRPC 服务（ClientAdmin / UserAdmin / TokenAdmin / PermissionAdmin / TenantAdmin / SnapshotAdmin / ReleaseAdmin）
# 零直接引用

$ grep -rn "grpc\.Dial\|grpc\.DialContext\|bufconn" test/*_test.go
# 仅在 test/e2e_test.go 中用于内部 Authz/Audit，非管理面
```

**当前测试覆盖：**

| 服务层 | 测试方式 | 覆盖范围 |
|--------|----------|----------|
| HTTP REST 端点 | `test/*_test.go` (150+ 文件) | POST /GET /DELETE 全覆盖 |
| **gRPC 管理面** | ❌ **无 E2E 测试** | **零覆盖** |
| gRPC 内部面（Authz/Audit） | bufconn（test/e2e_test.go） | 基本覆盖 |
| gRPC-gateway 路由 | 仅单元测试（不支持 wire） | 零覆盖 |

**gRPC 管理服务列表（无 E2E 测试）：**

| 服务 | proto | handler |
|------|-------|---------|
| `ClientAdminService` | `admin/v1/clients.proto` | `grpcserver/admin_clients.go` |
| `UserAdminService` | `admin/v1/users.proto` | `grpcserver/admin_users.go` |
| `TokenAdminService` | `admin/v1/tokens.proto` | `grpcserver/admin_tokens.go` |
| `PermissionAdminService` | `admin/v1/permissions.proto` | `grpcserver/admin_permissions.go` |
| `TenantAdminService` | `admin/v1/tenants.proto` | `grpcserver/admin_tenants.go` |
| `SnapshotAdminService` | `admin/v1/snapshots.proto` | `grpcserver/admin_snapshots.go` |
| `ReleaseAdminService` | `admin/v1/releases.proto` | `grpcserver/admin_releases.go` |

**为什么需要：**
- 管理 API 是运维人员操作 SSO 服务器的核心入口（CRUD 客户端、用户、权限）
- gRPC-gateway 自动转换 proto 到 REST，但 **gateway 的路由匹配 + 参数映射 + 错误码映射** 只有通过 E2E 测试才能验证
- 当前 proto 定义中使用了 `google.api.http` 注解（如 `get: "/api/v1/admin/clients"`），但这些 REST 路径的正确性只有在完整栈测试中才能验证

**建议修复：**
- `test/admin_grpc_test.go`：使用 `bufconn` 创建 gRPC 连接，直接调用每个 admin 服务的 RPC 方法
- `test/admin_gateway_test.go`：使用 `httptest.Server` + gRPC-gateway mux，验证 REST 路径 → gRPC 的端到端转换
- 覆盖：Create、Get、List、Update、Delete 基本 CRUD，以及 error 映射

---

## 方向四：YAML 配置解析静默忽略未知字段 — 拼写错误不报错

**代码验证：**

```go
// cmd/sso-server/config.yaml — 1658+ 行 YAML 配置
// 由 config.LoadFile / config.LoadYAML 解析为 Go struct
// 使用标准 encoding/json 或 yaml.v3 反序列化
```

**风险场景：**

```yaml
# 运维人员误写：
server:
  session_ttl: 24h
  token_ttl: 1h
  sesssion_ttl: 48h   # 0 个 s 变 3 个 s — 静默忽略
  # session_ttl 仍然是 24h，不是 48h
```

```yaml
# 或者忘记连字符导致结构体字段映射错误
audit:
  webhook:
     url: "https://hooks.example.com"    # 应该是 url:（没有缩进）
  # 解析后 webhook.url = ""，webhook 被禁用——静默失败
```

**现有防御：**
- `sso-ctl config validate --file config.yaml` — **离线可用**，但基于同样的 Go struct 解析，同样不会捕获未知字段
- `encoding/json` 和 `yaml.v3` 默认行为：`DisallowUnknownFields: false`（不会报错）

**为什么需要：**
- SSO 服务器配置涉及安全关键选项（issuer、backends、bootstrap admin）
- 一个拼写错误导致 `session_ttl` 使用默认值 24h 而非预期的 48h——不会触发错误，不会写入日志
- 运维人员只有在观察到非预期行为后才可能意识到配置未生效
- 当前 1658 行的 config.yaml 有数十个嵌套字段，手工排查代价高

**建议修复：**

```yaml
# 在解析层增加 strict 模式：
server:
  config_strict: true   # ← 新字段，启用后拒绝未知 YAML 键
```

实现方式：
- 对 `yaml.v3` decode 设置 `KnownFields(true)`（Go 1.x + yaml.v3 支持）
- 或使用双层解析：先 decode 到 `map[string]any`，再 decode 到 struct，比较键集合
- 对 `encoding/json` 设置 `DisallowUnknownFields: true`
- 启动时打印 WARNING：`"config: ignoring unknown key 'server.sesssion_ttl'"`

---

## 方向五：Proto API 版本策略未文档化 — `v1` 是唯一版本，无兼容性保证

**代码验证：**

```protobuf
// proto/admin/v1/clients.proto
package snaplink.admin.v1;
// 所有管理 API 都是 v1
// 无 v2alpha / v2beta / v1beta
// 无 Deprecation 注解
// 无字段级 @deprecated 标记
```

```bash
$ grep -rn "deprecated\|Deprecated\|deprecation\|Deprecation\|v2\|v1beta\|v1alpha\|v2alpha\|v2beta" proto/ --include='*.proto'
# ❌ 无 deprecation 标记
# ❌ 无未来版本规划
```

**Proto API 清单：**

| proto 包 | REST 路径 | 版本 |
|----------|-----------|------|
| `snaplink.admin.v1` | `/api/v1/admin/...` | v1 |
| `snaplink.authz.v1` | (internal gRPC only) | v1 |
| `snaplink.audit.v1` | (internal gRPC only) | v1 |
| `snaplink.discovery.v1` | (internal gRPC only) | v1 |
| `snaplink.netpolicy.v1` | (internal gRPC only) | v1 |

**缺少的内容：**
1. **无版本迁移策略文档**：当需要修改 proto 字段时（如添加新 required 字段），团队不知道应该怎么操作
2. **无 deprecation 注解**：如果淘汰一个字段，应该使用 `deprecated = true` + `reserved` 标记
3. **无 `v2alpha` 预览路径**：当引入重大变更时，没有实验性版本路径让客户端可以提前适配
4. **proto 与 REST 路径间的版本耦合**：`/api/v1/admin/clients` 中的 `v1` 同时约束 proto package 和 HTTP 路径
5. **无兼容性保证的显式声明**：README 或文档中没有写"哪些变更被视为 breaking"或"v1 的兼容性承诺"

**建议修复（文档层，非代码层）：**
- 在 `docs/adr/` 下创建 proto-versioning.md，记录版本策略：
  - `v1` 在向前兼容范围内可增字段（不能删、不能改类型、不能改编号）
  - 重大变更走 `v2alpha` → `v2beta` → `v2` 路径
  - `v2alpha` 和 `v2beta` 在同一 gRPC 服务中注册不同名称
  - HTTP REST 路径跟随 proto package：`/api/v2/admin/clients`
- 更新现有的 proto 文件：对已知可能弃用的字段添加 `deprecated = true` 注解
- 在 `.proto` 文件头添加兼容性注释
- buf breaking 检查已在 CI 中运行（`proto-breaking` make target），但无文档解释 breakage 如何处理

---

## 优先级排序

| 方向 | 价值 | 工作量 | 建议顺序 |
|------|------|--------|----------|
| **① WebAuthn Conditional Mediation** | 中-高（产品 UX 差距） | M | 第 1（与 Passkey 策略同步） |
| **② WebAuthn 浏览器超时** | 中（产品细节） | S | **第 1 Sprint 并行** |
| **③ gRPC E2E 测试** | 中（质量保障） | M | 第 2 |
| **④ YAML 配置严格解析** | 中（运维可靠性） | S | **第 1 Sprint 并行** |
| **⑤ Proto 版本策略** | 中（长期治理） | S（文档） | 第 2（ADR + 文档） |

**一句话：** ① Conditional Mediation (passkey 自动填充) 是 2024+ WebAuthn 交互标准——无此功能的 SSO 服务器让用户在 2026 年仍需手动点击 passkey 按钮而非享受浏览器原生的自动填充建议 → ② 浏览器模态框在没有 `timeout` 参数时将无限等待用户操作，直到 session 过期（5 分钟）才被服务器拒绝——设置 60 秒超时是基本的 UX 改进 → ③ 150+ HTTP 测试零 gRPC E2E 测试意味着所有的管理 API（Client CRUD、User CRUD、Permissions、Tenant、Snapshot、Releases）只能通过 gRPC-gateway 在 HTTP→gRPC 变换的缝隙中没有被端到端覆盖 → ④ 1658 行 YAML 配置中一个拼写错误（`sesssion_ttl` 三个 s）不会产生任何错误——配置被静默忽略，非预期的默认值生效 → ⑤ `v1` 作为唯一 Proto API 版本没有 deprecation 注解、没有迁移策略、没有 `v2alpha` 预览路径——当引入重大变更时，客户端会意外断裂。
