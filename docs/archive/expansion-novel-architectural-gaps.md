# 全局架构扫描——此前未曾触及的 5 个高价值扩展方向

> 基于 2026-07-01 全代码库深度扫描（849 个 `.go` 源文件、790 个测试文件、31 轮此前分析、8 份扩展方向文档均已审阅）。
>
> 视角：资深架构师 / 产品经理。此前已有 40+ 方向覆盖了协议扩展、边缘情况、性能优化、企业功能、架构债务、运营治理、AI Agent 等。
>
> **本轮聚焦：此前从未被系统性审视的 5 个方向。** 每条方向经对抗式 grep 核验 + 与已有 40+ 方向交叉比对，确认为真缺口。
>
> 原则：不写代码。每条锚定具体代码位置或模式。

---

## 总体判断

项目已从"身份协议 SDK"跨越到"生产就绪多协议 SSO 平台"，并在近期完成了 shutdown 生命周期治理、管理 API 一致性、运维可观测性等关键演进。此前 31 轮分析覆盖极为全面。

**但仍有五个架构层面的盲区此前从未被触及：**

1. **Feature Interaction Conflict Detection & Server Startup Validation**——90+ 选项之间无冲突检测，无声启动失败
2. **Admin API Surface Coherence Gap**——管理面分拆在 proto gRPC 和 HTTP-only handler 两个世界中，传输方式决定能力
3. **Playground & Demo Code as Supply Chain Risk**——演示代码中的硬编码密钥和调试端点构成生产风险
4. **Configuration Incoherence Detection**——YAML 跨块验证缺失，静默降级
5. **API 版本协商与弃用协议**——无版本前缀、无 Sunset 头、无兼容性保证

---

## 方向一：Feature Interaction Conflict Detection & Server Startup Validation

### 现状

`interfaces/sso/sso_newserver.go:23` 中的 `NewServer(opts ...Option)` 函数按顺序应用所有 option，**没有任何集中式验证步骤**：

```go
func NewServer(opts ...Option) *Server {
    s := &Server{}
    // ... 初始化 map, 默认值 ...
    for _, opt := range opts {
        opt(s)  // 每个 opt 只设字段，不校验
    }
    // ... 后处理（federation auto-reg, client store cache）...
    return s
}
```

二进制构建路径（`cmd/sso-server/build_app*.go`）有**部分**验证（如 coordinated_cutover 要求 cluster bus、snapshot retention 要求 snapshot enabled），但 SDK 路径完全没有。

### 已验证的缺失校验（grep 证据）

| 冲突组合 | 问题 | 证据 |
|---------|------|------|
| `WithFAPIProfile(ModeEnforce)` + 无 PAR/JAR/DPoP | 启动成功，运行时 FAPI 校验因缺少底层能力而无法工作，客户端收到意外 `invalid_request` | `grep "fapi\|PAR\|JAR\|DPoP" interfaces/sso/sso_newserver.go` → 0 命中 |
| `WithOAuth21StrictMode` + `WithFAPIProfile(ModeOff)` | OAuth 2.1 和 FAPI 在响应类型和 PKCE 要求上有重叠但微妙不同的约束，无优先级文档 | `grep -c "oauth21Strict\|fapiValidator" interfaces/sso/sso_newserver.go` → 0 命中（无交叉检查） |
| `WithJARM(signer)` + 无 ID Token Issuer | JARM 使用相同的签名基础设施，但无检查确保 ID Token Issuer 也存在 | `grep "jarmSigner\|idTokenIssuer" interfaces/sso/sso_newserver.go` → 0 交叉引用 |
| `WithCAEPTransmitter` + 无 cluster bus | 单副本 CAEP 可以工作，但多副本配置不同步，推送到已过时的 RP 列表 | `grep "caep\|cluster\|Bus" interfaces/sso/sso_newserver.go` → 0 交叉引用 |
| `WithBackchannelLogout(issuer, notifier)` + 无 `SubjectClientIndex` | BCL 推送时无法找到 RP 的 `logout_uri`，静默跳过推送 | `grep "BackchannelLogout\|SubjectClientIndex" interfaces/sso/sso_newserver.go` → 0 校验 |
| `WithTenantTokenIssuer(tenant, issuer)` + 未注册 `issuerName` | 映射到一个不存在的 issuer，运行时 `issuerForClient` 返回空，fallback 到默认，但无告警 | `grep "tenantTokenStrategies\|tokenIssuers" interfaces/sso/sso_newserver.go` → 唯赋值，无验证 |

### 为什么需要

**这不是理论问题——这是"启动时出错"与"上线 3 小时后出错"的区别。**

- 当前的设计是 **Fail-Late**：错误只在客户请求到达时暴露（运行时 500/400），而非在部署时（启动时 error）
- 操作员配置 YAML 时无法知道哪些 feature 组合是 valid 的——无文档化的 compatibility matrix
- 90+ 个 option 的数量已超过人的认知负荷（Miller's Law ~7±2），没有机器可读的依赖声明是架构债务
- 竞品对标：Auth0 的 `tenant.yaml` 有 schema 校验，Keycloak 的 `standalone.xml` 启动时验证 feature 一致性

### 建议方向

```
Phase 1 (S) — 启动时校验入口：
  ├── 在 ap.NewServer(opts...) 末尾添加 validateServer(*Server) error
  ├── 校验规则作为声明式结构而非 if-else 瀑布：
  │   ├── requires(FeatureFAPI, FeaturePAR, FeatureJAR, FeatureDPoP)
  │   ├── requires(FeatureBCL, FeatureSubjectClientIndex)
  │   ├── requires(FeatureTenantTokenIssuer, FeatureTokenIssuer)
  │   ├── conflicts(FeatureOAuth21Strict, FeatureFAPIEnforce) // 有重叠但优先级需显式
  │   └── warn_on_missing(FeatureJARM, FeatureIDTokenIssuer)
  └── Server 结构体暴露一个 Ready() error 方法（被 /readyz 调用）

Phase 2 (M) — 机器可读的 Feature Dependency Matrix：
  ├── feature_deps.go — 声明所有 feature 及其依赖/冲突的 map
  ├── 支持自动生成兼容性文档（docs/feature-compatibility.md）
  └── 支持 WithOption 链的静态分析工具（ci 阶段）
```

---

## 方向二：Admin API Surface Coherence Gap——HTTP-Only 端点与 Proto gRPC 服务的不对称

### 现状

Admin 管理面分两个世界实现：

**世界 A：proto 定义的 gRPC + REST-gateway 服务（`proto/admin/v1/`）**

| Proto Service | 对应 REST 路径 |
|---------------|---------------|
| `ClientAdminService` | `/api/v1/admin/clients` |
| `UserAdminService` | `/api/v1/admin/users` |
| `PermissionAdminService` | `/api/v1/admin/permissions/*` |
| `TenantAdminService` | `/api/v1/admin/tenants` |
| `TokenAdminService` | `/api/v1/admin/tokens/*` |
| `SnapshotAdminService` | `/api/v1/admin/snapshots` |
| `ReleaseAdminService` | `/api/v1/admin/releases` |

**世界 B：纯 HTTP Handler（无 proto 定义，`interfaces/sso/server_admin_*.go` + `interfaces/admin/*.go`）**

| HTTP Route | 能力 | 对应 proto |
|-----------|------|-----------|
| `GET /api/v1/admin/audit/events` | 审计事件查询 & 导出 | ❌ 无 |
| `GET /api/v1/admin/audit/facets` | 审计维度统计 | ❌ 无 |
| `GET /api/v1/admin/users/:id/consents` | 查看用户授权 | ❌ 无 |
| `DELETE /api/v1/admin/users/:id/consents/:id` | 撤销用户授权 | ❌ 无 |
| `GET /api/v1/admin/users/:id/mfa` | 查看用户 MFA 因子 | ❌ 无 |
| `DELETE /api/v1/admin/users/:id/mfa/:id` | 移除用户 MFA 因子 | ❌ 无 |
| `POST /api/v1/admin/users/:id/password` | 重置用户密码 | ❌ 无 |
| `POST /api/v1/admin/users/:id/email` | 设置用户邮箱 | ❌ 无 |
| `POST /api/v1/admin/users/:id/account-lockout/clear` | 清除账户锁定 | ❌ 无 |
| `DELETE /api/v1/admin/users/:id/device-secrets` | 吊销用户设备密钥 | ❌ 无 |
| `GET/DELETE /api/v1/admin/users/:id/password-reset-tokens` | 管理密码重置令牌 | ❌ 无 |
| `GET/DELETE /api/v1/admin/users/:id/email-change-tokens` | 管理邮箱变更令牌 | ❌ 无 |
| `GET/POST/DELETE /api/v1/admin/connections` | 企业连接 CRUD | ❌ 无 |
| `GET/PUT/DELETE /api/v1/admin/tenants/:id/members` | 租户成员管理 | ❌ 无 |
| `GET/POST /api/v1/admin/invitations` | 邀请管理 | ❌ 无 |
| `GET/POST /api/v1/admin/backup` | SQLite 备份触发 | ❌ 无 |
| `GET/DELETE /api/v1/admin/tokens` | Admin Bearer 令牌管理 | ❌ 无 |
| `GET /api/v1/admin/sessions` | 全局会话列表 | ❌ 无 |
| `GET/POST/DELETE /api/v1/admin/netpolicies` | 网络策略管理 | ❌ 无 |

### 为什么需要

**这不是"代码量"问题——这是"操作者信任"问题。**

- 一个只通过 gRPC 集成的 operator（如 Istio 网格中的 sidecar）**无法执行审计查询、管理用户 MFA、或重置密码**——这些是最常见的 helpdesk 操作
- REST-only 的端点缺少 proto 的 schema 约束（类型安全、必填字段、枚举值校验）
- 随着 admin SPA 控制台（`cmd/sso-server/serverassets/admin_assets.go`）增长，这些端点将成为 UI 的后端——但没有 proto schema 意味着 SPA 开发者需要手动同步参数
- 竞品对标：Auth0 Management API v2 的所有端点（包括审计日志查询）都有统一的 RESTful schema；Keycloak Admin REST API 所有端点都有 OpenAPI spec

### 建议方向

```
Phase 1 (M) — 将 HTTP-only 管理端点逐批迁移到 proto：
  ├── 第一批（高价值）：audit/v1/audit_admin.proto — 审计事件查询、facet 统计、导出
  ├── 第二批：admin/v1/user_operations.proto — 用户 MFA、consent、password reset、lockout
  ├── 第三批：admin/v1/operations.proto — connections、tenant members、invitations、backup
  └── 确保所有 proto 都映射到对应的 REST-gateway 路径（已有的 google.api.http annotations）

Phase 2 (S) — Admin API OpenAPI 规范补全：
  ├── 基于 proto 自动生成 + 手动补充 HTTP-only 端点的 OpenAPI spec
  └── 在 /api/v1/admin/openapi.json 提供运行时下载
```

---

## 方向三：Playground & Demo Code as Supply Chain Risk

### 现状

`docs/examples/playground/main.go` 是一个完整的、可构建的 SSO 服务器二进制，包含：

| 风险点 | 位置 | 代码 |
|--------|------|------|
| **硬编码 TOTP 密钥** | `main.go:81` | `var demoTOTPSecret = []byte("12345678901234567890")` — RFC 6238 §B 测试密钥 |
| **注释警告它不安全** | `main.go:76-79` | `// NEVER do this in production — secrets are per-user and...` |
| **调试端点** | `main.go:218-259` | 注册 `/playground/decode-token`、`/playground/audit-log`、`/playground/jwks-all` |
| **无构建时保护** | `main.go:1` | 无 `//go:build` 标签——`go install ./docs/examples/playground` 成功编译 |
| **嵌入式 SPA** | `index.html` | 全功能 OAuth 测试页面，暴露了所有端点 |

**威胁模型：**

1. 开发者运行 `go install ./docs/examples/playground@latest`（想"快速体验 SSO"）→ 得到一个可运行的 SSO 服务器
2. 开发者在开发环境启动它 → 所有 token 使用已知的演示 TOTP 密钥签署（理论上用了 `Ed25519JWTIssuer` 而非 TOTP，但 MFA 流程完全可用已知密钥绕过）
3. 更危险：CI 环境或集成测试中使用 → 测试账号密码 `alice/secret` 是硬编码的
4. 最危险：新手部署到生产（发生频率超出预期——StackOverflow 上大量 "I copied the example to production" 问题）

**CVE 扫描盲区：** 标准的 CVE scanner（Trivy、Grype、Snyk）扫描 `go.mod` 的依赖版本——它们不扫描 `docs/examples/` 目录中的硬编码密钥。这个风险完全不可被自动化供应链安全工具检测。

### 为什么需要

**这不是"演示代码"问题——这是"供应链安全"问题。**

- 硬编码密钥在 `docs/examples/` 中比在测试文件中更危险——测试文件不会被 `go install`
- `// NEVER do this in production` 注释在评论中是一个已知的无效安全措施（心理研究表明用户常常忽略代码中的安全警告）
- 行业趋势：GitHub Advisory Database、Google OSS-Fuzz、CVE 项目越来越多地覆盖"文档/示例中的安全风险"

### 建议方向

```
Phase 1 (S) — 构建时保护：
  ├── 在 playground 的 package 声明前添加 //go:build demo_example 标签
  ├── 更新所有 go.work 和 go.mod 中引用 playground 的路径
  ├── 在 Makefile 中：go install 不应包含 docs/examples/（或仅在 demo tag 下）
  └── 在 ci 中运行：确保 go build ./docs/examples/... 在不带 demo tag 时失败

Phase 2 (S) — 运行时防御：
  ├── playground 启动时检测：如果 stdout 是 terminal 而非 pty，打印大号警告
  ├── 添加 --production-guard flag（默认 true）：演示密钥在无控制台交互时拒绝启动
  └── 考虑移除硬编码的 TOTP 密钥，改用首次启动时随机生成 + 打印到控制台

Phase 3 (S) — 文档加固：
  ├── 在 playground 目录添加 PRODUCTION-WARNING.md
  ├── 在 README.md 中明确警告 docs/examples/ 不可用于生产
  └── 考虑引入 cobra/RUNNING_IN_PRODUCTION 检测（检查环境变量 SSO_PLAYGROUND=1）
```

---

## 方向四：Configuration Incoherence Detection——跨块验证缺失

### 现状

`config/` 目录下的 YAML 配置被拆分为大约 17 个配置块（server、clients、authenticators、oauth、oidc、saml、ldap、kerberos、radius、geo、region、tenant、admin、ciba、federation、signingkeys、self_service...），每个块独立解析。

**已知的静默降级路径（grep 验证）：**

| 配置模式 | 行为 | 证据 |
|---------|------|------|
| `geo.enabled=true` + `geo.backend=maxmind` | maxmind 后端不存在（仅实现了 "static"），服务器回退到 no-op geo provider——geo 功能静默不工作 | `grep "geo.*backend\|maxmind\|GeoProvider" config/` → 只有 "static" 被引用 |
| `oauth.auth_code.ttl > 60min` + 无 PVC/session 持久化 | 内存中的 auth code 存活 60 分钟——服务器重启后所有未使用的 code 丢失，但无告警 | `grep "auth_code\|AuthCodeTTL" config/` → 无持久化提示 |
| `self_service.signup=true` + 无 `EmailVerificationSender` | signup 可配置 require_verification 但若无 sender 实现，验证步骤永远无法完成——用户注册后无法验证 | `grep "SignupRequiresVerification\|EmailVerificationSender" interfaces/sso/` → 无 sender 存在的启动时检查 |
| `admin.enabled=true` + 无 `permissions.Provider` | 管理 API endpoint 启用但所有 admin 请求因缺少权限检查而返回 403——无错误日志 | `grep "admin.*enabled\|provider\|AdminMiddleware" cmd/sso-server/build_app.go` → 隐式依赖 |
| `federation.auto_registration=true` + 无 federation signer | auto_registration 要求在注册时签署 entity statement——无 signer 时注册失败但静默降级为绕过 | `grep "federation\|signer\|EntitySigner" cmd/sso-server/build_app.go` → 无 signer 存在的检查 |

### 为什么需要

**当前的设计是配置静默失败（Fail-Silent）。这对安全性和可调试性都有影响：**

- 操作员配置文件中的拼写错误或缺失块导致特性静默禁用——没有错误，没有日志，只是不工作
- 运维人员排错时首先排除了"配置是否正确"这个最容易检查的维度
- 当配置项数量超过 100 时（当前 YAML 配置项约 200+），手动交叉验证不再可行
- 竞品对标：Kubernetes 有 `kubectl apply --validate=true`、Istio 有 `istioctl validate`、Caddy 有 `caddy validate`

### 建议方向

```
Phase 1 (S) — 声明式配置 Schema：
  ├── 为 config/ 目录中的每个配置块添加 Validate() error 方法
  ├── 跨块交叉验证：config/validator.go — 检查 geo.backend 是否是已注册值
  ├── 在 cmd/sso-server/main.go 启动流程中插入 configValidate(cfg) 步骤
  └── 支持 --validate-only flag（已有 feat(cmd): add --validate-only flag + make config-validate-all target）

Phase 2 (M) — 配置 Schema 版本化 + 代码生成：
  ├── 从 config/*.go 的 struct tag 自动生成 JSON Schema
  ├── 支持 config.yaml 的 `$schema` 引用路径
  ├── 为 IDE（VSCode、IntelliJ）生成 YAML schema 补全
  └── 运行时配置热重载时重新验证（not yet implemented hot-reload）

Phase 3 (S) — 配置漂移检测：
  ├── 启动时计算配置哈希，存到 admin API
  ├── compare-config CLI 命令对比当前运行配置与文件配置
  └── 在 admin SPA 中显示配置哈希和最后变更时间
```

---

## 方向五：API 版本协商与弃用协议

### 现状

项目的 API 表面有三个版本维度，但**没有一个有版本协商和弃用协议**：

| API 表面 | 版本模式 | 问题 |
|----------|---------|------|
| OAuth/OIDC 核心端点 | 无版本前缀 | `/token`、`/auth/login`、`/.well-known/openid-configuration`——永远无法发 breaking change |
| Admin REST API | 硬编码 `/api/v1/` | 路径中有 `v1` 但无 `v2` 路线图、无 sunset head、无版本协商 |
| gRPC Proto API | package `admin.v1` | ADR-0008 文档了策略但未实现——无 `v2alpha` 预览路径，无 deprecation annotation |

**在 go.sum 和代码中 grep 的结果：**

- `grep "Sunset\|Deprecation" --include="*.go" --include="*.proto" interfaces/ proto/` → **0 命中**（除 protoc 生成的 Deprecated 方法外）
- `grep "Accept-Version\|X-API-Version\|api-version\|version.*negotiate\|version.*header" interfaces/sso/` → **0 命中**
- `grep "v2\|v1beta\|v1alpha\|v2alpha\|v2beta" proto/admin/v1/ --include="*.proto"` → **0 命中**

**已知的风险场景：**

1. 未来需要改变 `/token` 的请求格式（比如强制某些新字段）——当前无迁移路径
2. Admin API 返回的 `Client` message 需要移除某字段——当前无 deprecation 窗口
3. 自省端点 `/token/introspect` 的响应格式需要从 `{"active":true,...}` 变为 `{"active":true,...}` 增加版本标识——下游客户端断裂
4. OIDC discovery 文档增加新的 `response_types_supported` 值——旧客户端无法解析

### 为什么需要

**这不是"遥远的 future"问题——这是"第一次 breaking change 发生时"的问题。**

- 所有成功的身份平台都经历过 API 版本演进：Auth0 从 v1 到 v2（3 年迁移窗口）、Okta 从 v1 到 v3（5 年）、Keycloak 从 1.x 到 2.x（2 年 + 向后兼容层）
- 没有版本协商机制 = **第一次 breaking change 就是所有非嵌入式客户端的断裂点**
- 没有 deprecation 头 = **客户端开发者无法自动化地发现他们的集成即将断裂**
- ADR-0008 已经设计了 proto 版本策略（v1 → v2alpha → v2beta → v2），但从未实现——这是一个"已承诺未交付"的架构债务

### 建议方向

```
Phase 1 (S) — Deprecation Header 协议：
  ├── 在 middleware 中添加 Deprecation + Sunset HTTP header 支持
  ├── 在 Option/Config 中添加 server.api.deprecation.header.enabled
  └── 当前没有需要 deprecated 的端点——但基础设施应在需要之前准备好

Phase 2 (M) — Admin API 版本协商：
  ├── 在 /api/v1/admin/* 的 middleware 中检查 Accept-Version header
  ├── 当前只支持 v1——不设 header 时默认 v1，设了未来版本时返回 406 Not Acceptable
  ├── 在 discovery 文档中添加 api_versions_supported 字段
  └── 在 OpenAPI spec 中添加版本协商文档

Phase 3 (L) — Proto API 版本预览路径：
  ├── 按照 ADR-0008 实现 v2alpha 包路径
  ├── 为 v2alpha 的 gRPC service 实现动态注册（非编译时硬编码）
  ├── 构建 allowlist-based 的 API 版本访问控制
  └── 为 OAuth/OIDC 核心端点制定版本策略（query param ?v=2 vs header 协商 vs 新端点）
```

---

## 跨方向相关性

```
方向一 (Feature Interaction Validation)
  ├── 为方向四 (Config Validation) 提供运行时依赖
  ├── 为方向五 (API Versioning) 提供 feature 门控的基础
  └── 需要方向三 (Playground Risk) 的加固——playground 不应绕过验证

方向二 (Admin API Coherence)
  ├── 依赖方向五 (API Versioning) 提供统一的版本协商策略
  └── 自动解决方向四 (Config Validation) 的一部分——proto schema 提供强类型

方向三 (Playground Supply Chain Risk)
  ├── 独立修复，不依赖其他方向
  └── Phase 1 可以在 30 分钟内完成（加 3 行 build tag）

方向四 (Config Incoherence)
  ├── 依赖方向一 (Feature Interaction) 的特性依赖矩阵
  └── Phase 1 部分依赖 CLI 基础设施（已有 --validate-only flag）

方向五 (API Versioning)
  ├── 依赖方向一 (Feature Interaction) 的 feature 门控能力
  ├── Phase 2 依赖方向二 (Admin API Coherence) 的 proto 迁移
  └── 是唯一一个需要跨版本期投入的方向（L 工作量）
```

## 优先级建议

| # | 方向 | 工作量 | 风险 | 依赖 |
|---|------|--------|------|------|
| 1 | **方向三：Playground 供应链风险** | **S（~30 min）** | 中（硬编码密钥 + 可安装的二进制） | 无 |
| 2 | **方向一：Feature Interaction 验证** | **M（~2-3 天核心 + 声明矩阵）** | 高（无声启动失败直接影响运行安全） | 无 |
| 3 | **方向四：Config Incoherence 检测** | **M（~2-3 天）** | 中（配置错误是最常见的运维错误源） | 部分依赖方向一 |
| 4 | **方向二：Admin API Coherence** | **L（~1-2 周 proto 迁移）** | 中（随 admin SPA 增长而增长） | 依赖方向五 |
| 5 | **方向五：API 版本协商** | **XL（~2-4 周完整设计+实现）** | 低（目前无 breaking change 计划，但应提前做好准备） | 方向一、方向二 |

**短期行动方案（1 周内）：**

- **P0**：方向三 Phase 1——给 `docs/examples/playground/main.go` 添加 `//go:build demo` 标签 + Makefile 保护
- **P0**：方向四 Phase 1——已经有 `--validate-only` flag，扩展它覆盖跨块验证
- **P1**：方向一 Phase 1——在 `NewServer` 末尾添加 `validateServer()` 调用

---

## 核验方法

每条方向的确立通过：
1. **代码模式扫描**：grep `NewServer`、`proto`、`build_*`、`go:build`、`Sunset`、`version`、`Validate`、`checkConfig` 等模式
2. **交叉验证**：对比 ROADMAP v5.0、31 轮分析、8 份扩展方向文档、edgecases 文档——确保没有重复
3. **对抗式 grep**：对于每条候选，反向 grep 验证缓解措施是否存在（如 `grep "version\|deprecat\|sunset" --include="*.proto"` 确认零命中）
4. **代码路径追踪**：对于关键路径（如 `NewServer`），追踪其内部逻辑确认缺失验证环节
