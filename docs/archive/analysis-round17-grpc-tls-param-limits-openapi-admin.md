# 第十七轮分析：gRPC 生产配置、参数长度限制、OpenAPI Admin、State Origin 绑定

> 基于全局代码库扫描产生的全新视角，此前十六轮未覆盖。

---

## 方向一：gRPC 服务器仅使用 Admin 拦截器——缺少 Keepalive、TLS、MaxMsgSize、恢复

**问题：** `cmd/sso-server/main_servers.go:125-133` 创建 gRPC 服务器：

```go
func newGRPCServer(a *app) *grpc.Server {
    var opts []grpc.ServerOption
    if a.adminMW != nil {
        opts = append(opts,
            grpc.UnaryInterceptor(a.adminMW.UnaryServerInterceptor()),
            grpc.StreamInterceptor(a.adminMW.StreamServerInterceptor()),
        )
    }
    s := grpc.NewServer(opts...)
    // ... 注册服务 ...
    return s
}
```

**仅有** admin 认证拦截器。缺少生产就绪配置：

| 配置 | 默认值 | 影响 |
|------|--------|------|
| `grpc.MaxRecvMsgSize` | 4 MB | `ListClients` 有 10,000 个条目 → 约 10 MB → 失败 |
| `grpc.MaxSendMsgSize` | 无限制 | 客户端接收大数据时可能 OOM |
| `grpc.KeepaliveParams` | 无 | 负载均衡器（AWS NLB、GCP TCP LB）的空闲超时 → 断开连接 |
| `grpc.KeepaliveEnforcementPolicy` | 无 | 客户端可以以任意速率 ping → CPU 攻击向量 |
| `grpc.ConnectionTimeout` | 无限 | 慢速客户端永远占用连接 |
| **服务端 TLS** | 无 | 端口 8081（gRPC）无 TLS——admin 密码以明文形式传递 |

**为什么这是一个问题：** gRPC 服务器端口（通常为 8081）承载 admin API，包括 `RotateSecret`（返回明文密钥）和 `TokenAdminService.IssueTempToken`（返回 admin 令牌）。如果端口 8081 暴露给网络，攻击者可以：
1. 嗅探 gRPC 流量并提取明文密钥（无 TLS）
2. 发起 DoS 攻击（无 Keepalive 策略）
3. 通过发送大请求导致 OOM（无 MaxRecvMsgSize）

**修复：** 向 `newGRPCServer` 添加生产 gRPC 服务器选项：
```go
grpc.MaxRecvMsgSize(16 * 1024 * 1024),
grpc.KeepaliveParams(keepalive.ServerParameters{Time: 60 * time.Second, Timeout: 20 * time.Second}),
grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: false}),
grpc.ConnectionTimeout(5 * time.Second),
```

另外：如果 `tlsCert` + `tlsKey` 已配置，则通过 `grpc.Creds(credentials.NewServerTLSFromCert(cert))` 为 gRPC 启用 TLS。

**工作量：** S（~10 行选项 + 条件性 TLS）| **影响：** **中高**（admin API 安全性）| **类型：** 安全/运维

---

## 方向二：状态参数不与请求来源绑定——OAuth CSRF 攻击面

**问题：** OAuth `state` 参数用于将授权响应绑定到客户端的原始请求（CSRF 防护，RFC 6749 §10.12）。但 `state` 值**不与请求来源绑定**。客户端生成 `state` 并期望它原样返回——但服务器不将它与任何特定上下文（原始 URL、HTTP Origin 标头、客户端的注册源）关联。

**攻击场景：**
1. 合法客户端 A（`client_id=app1`）在 `https://evil.com/cb` 注册了 `redirect_uri`
2. 用户已在客户端 A 验证身份
3. 攻击者构造一个 `https://sso.example.com/auth?client_id=app1&redirect_uri=https://evil.com/cb&state=xyz` 的授权请求
4. 用户在被误导的情况下登录 SSO
5. 授权码被发送到 `https://evil.com/cb?code=xxx&state=xyz`
6. 攻击者用 code 交换令牌

**缺少什么：**
- 服务器**不检查** `Origin` 标头是否与客户端的已注册源匹配
- `state` 不包含请求来源的加密哈希
- 服务器可以将 `state` 与 `redirect_uri` 的内容绑定
- 如果 `redirect_uri` 已经被验证过，则这个攻击被缓解——但 `redirect_uri` 验证可能允许通配符或子路径而不检查

**修复：**
1. 添加 `state` 中的 `origin_hash`（HMAC(client_secret, origin)）——在响应时验证
2. 为 `/auth` 添加 `Origin` / `Referer` 标头验证——验证请求来源与客户端的注册域匹配
3. 实现 PKCE 作为所有授权码流程的强制要求（PKCE 通过 `code_challenge` 缓解此攻击）

**工作量：** M（Origin 验证 + state 绑定 + 文档）| **影响：** **中高**（OAuth CSRF/混合攻击）| **类型：** 安全

---

## 方向三：OAuth 授权请求参数缺少长度限制——state/scope/redirect_uri 可能导致 DoS

**问题：** 授权请求参数（`state`、`scope`、`redirect_uri`、`response_type`、`nonce`）进入 Go 的 `net/url` 解析器（默认限制 10 MB）和 Echo 请求绑定器。但**没有应用 OAuth 特定的长度上限**：

- `state`：RFC 6749 建议 ≥ 128 位，但未设置最大长度。100 KB 的 `state` 被完整解析、验证并存储在 auth_code 中。
- `scope`：`scope` 值（空格分隔的令牌）可以很大——100 个作用域令牌，每个 100 个字符 = 10 KB 的 `scope` 字符串被解析、验证和存储。
- `redirect_uri`：无 URL 长度限制。
- `nonce`：无字节限制。

**为什么这是一个问题：**
- **意图 DoS：** 攻击者发送带有 500 KB `state` 和 200 KB `scope` 的授权请求 → 完整的请求被解析、验证、持久化到 PAR/AuthCode 存储中，消耗内存和数据库存储
- **存储膨胀：** PAR 存储将完整的 `state` + `scope` + 参数持久化到 SQLite/Redis 中——巨大的请求会填满共享存储
- **反射放大：** 授权请求中的大 `redirect_uri` 被回显到 302 重定向中——攻击者可以用长 URI 放大响应大小

**修复：** 为授权请求参数添加中心化大小验证：
```go
const (
    MaxStateLen       = 2048   // 字节
    MaxRedirectURILen = 2048   // 字节
    MaxScopeLen       = 4096   // 字节
    MaxNonceLen       = 256    // 字节
)
```

在 `bind.go` 绑定器中或 PAR 验证期间应用。

**工作量：** S（~20 行验证 + 常量）| **影响：** 中（防止授权请求 DoS）| **类型：** 安全

---

## 方向四：OpenAPI 规范不包含 Admin REST API——gRPC-gateway 端点未记录

**问题：** `docs/openapi.yaml` 是一个 8350 行的 OpenAPI 3.0 规范，覆盖 OAuth/OIDC 端点。但**无 admin 端点被记录**——尽管 gRPC-gateway 在 `/api/v1/admin/*` 下生成 REST API。

**缺少的端点：**
- `GET /api/v1/admin/clients` + `POST /api/v1/admin/clients`——客户端 CRUD
- `GET /api/v1/admin/users` + `POST /api/v1/admin/users`——用户管理
- `GET /api/v1/admin/sessions`——会话管理
- `POST /api/v1/admin/tokens/revoke`——令牌吊销
- `GET /api/v1/admin/tenants`——租户管理
- `GET /api/v1/admin/audit/events`——审计查询
- 所有权限管理（角色、分配、菜单）

**为什么这是一个问题：** 使用 admin API 的操作员必须：
1. 从 `gen/proto/admin/v1/*.proto` 读取 protobuf 定义以理解请求/响应结构
2. 使用 curl 尝试，gRPC-gateway 将 HTTP JSON 转换为 protobuf（JSON 字段名映射到 `snake_case` 与 `camelCase` 的 protobuf 方案）
3. 猜测枚举值——admin 端点中的 `client.token_endpoint_auth_method` 映射回其 protobuf 整数值或字符串？

**修复：**
1. 添加 `openapi.yaml` 生成步骤（与 `buf` 或 `grpc-gateway` 的 `openapiv2` 生成器集成）
2. 添加 `make openapi-gen` → 自动从 `.proto` 文件生成 admin OpenAPI 规范
3. （可选）合并 OAuth + Admin 规范成为一个单一的 `openapi.yaml`

**工作量：** M（protobuf 注解 + 生成管道 + 集成测试以确保生成成功）| **影响：** **中高**（API 消费者效率）| **类型：** 文档

---

## 方向五：14 个 `build_*.go` 文件中的复杂条件连接——配置路径的测试覆盖率未知

**问题：** 服务器连接层分布在 14 个 `build_*.go` 文件中（`build_app*.go`、`build_http.go`、`build_stores.go`、`build_bootstrap.go` 等），包含复杂的条件逻辑和 `if cfg.Backend == "sqlite" { ... } else if cfg.Backend == "redis" { ... }` 分支。

**具体问题：**
- **配置路径爆炸：** 每个次优决策（memory vs sqlite vs redis vs postgres）与每个功能（oauth vs oidc vs federation vs CAEP vs scim）相组合——产生数百个独特的配置路径
- **测试覆盖率未知：** `build_app_coverage_test.go`、`build_more_coverage_test.go`、`build_stores_coverage_test.go` 存在，但**我不知道是否每个 `if/else` 分支都被覆盖**。如果我更改了 `BuildAuthCodeStore`，测试是否验证了 memory、sqlite 和 redis 路径？
- **耦合配置：** `Build*` 函数在 `build_oauth_stores.go` 和 `build_identity_stores.go` 之间共享——更改 `SQLite.DSN` 会影响 6+ 个存储

**为什么这是一个问题：** 重构（例如将 `SQLite.DSN` 共享为连接池）需要了解 14 个 `build_*.go` 文件中所有 30+ 个 `NewXStore(dsn)` 调用。没有自动化的方式来确定"哪些存储路径使用 backend=X"。

**修复：**
1. 添加 `config.Schema()` —— 返回所有可能的配置路径的树
2. 添加 `cmd/config-coverage` 工具，该工具枚举所有后端选择并报告哪些已测试
3. 添加 `mustPass[t TestingT, name string, cfg func]` 测试辅助函数，用于注册(backend, feature)路径
4. 在 CI 中强制执行 100% 的构建路径覆盖率

**工作量：** L（配置路径枚举 + 测试辅助函数 + 集成测试夹具构建器）| **影响：** 中（重构安全性）| **类型：** 测试/质量

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | gRPC 服务器生产配置（Keepalive/TLS/MaxMsgSize） | **中高**（admin API 安全性，明文密文） | S | 安全/运维 |
| 2 | State 参数 Origin 绑定（OAuth CSRF 攻击面） | **中高**（授权劫持） | M | 安全 |
| 3 | 授权请求参数长度限制（state/scope/redirect_uri DoS） | 中（资源耗尽） | S | 安全 |
| 4 | OpenAPI 不包含 Admin API（gRPC-gateway 端点未记录） | 中（API 消费者效率） | M | 文档 |
| 5 | Build 配置路径覆盖率（14 个 build_*.go 中的分支） | 中（重构安全性） | L | 测试/质量 |

**按 ROI 排列：** 方向 1（gRPC TLS + Keepalive——10 行选项 = 加密 admin 流量 + 释放空闲连接）→ 方向 3（参数长度限制——20 行验证 = 防止授权请求 DoS）→ 方向 2（State Origin 绑定——防止 OAuth CSRF/混合攻击）→ 方向 4（Admin OpenAPI——自动生成 = 始终最新的 admin 文档）→ 方向 5（Config 路径覆盖率——高工作量，但确保重构不会中断未测试的配置路径）。
