# 第十四轮分析：Panic Recovery、Admin 分页、账户关联、gRPC 配置与授权超时

> 基于全局代码库扫描产生的全新视角，此前十三轮未覆盖。

---

## 方向一：缺少 Panic Recovery 中间件——Handler 崩溃导致进程退出

**问题：** 中间件栈（`interfaces/middleware/middleware.go`）包含 Auth、CORS、Logger 和 Tracing，但**没有 panic recovery 中间件**。如果任何 HTTP handler 或中间件发生 panic（空指针解引用、数组越界、类型断言失败），则：

1. Go 运行时终止整个进程
2. **不会返回 HTTP 500 给客户端**——连接被丢弃
3. 所有进行中的请求被立即截断
4. 审计事件丢失（未刷新的事件）
5. 如果服务器通过 Kubernetes/进程管理器自动重启，则出现停机窗口

**对比：** 标准的 Go HTTP 框架（Echo 的内置 `Recover()`、Chi 的 `Recoverer`、gin 的 `Recovery()`）默认包含恢复中间件。Echo 的 `Recover()` 中间件在 `adapters/echo/` 适配器中可用，但**没有启用**。

**修复：** 在中间件链的前端添加 `Recover()` 中间件（在 `WithTracing` 之后但在任何业务逻辑之前）：

```go
func Recover() core.MiddlewareFunc {
    return func(ctx core.HandlerContext) {
        defer func() {
            if r := recover(); r != nil {
                // 记录栈跟踪
                // 返回 500
                ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
            }
        }()
        ctx.Next()
    }
}
```

通过 `WithPanicRecovery()` 服务器选项启用，默认开启。

**工作量：** S（~20 行的中间件 + 1 个服务器选项）| **影响：** **高**（防止 Panic 导致进程崩溃）| **类型：** 运维/弹性

---

## 方向二：缺少跨 IdP 账户关联——同一用户的多个身份无法合并

**问题：** 目前，通过不同 IdP 认证的用户被视为不同的用户。无论用户通过哪种 IdP 登录，都没有账户关联/合并功能来连接身份。

**具体场景：**
1. 用户 `alice@example.com` 先用 Google SSO 登录 → 创建 Google 身份下的用户记录
2. 后来用户尝试用密码登录 `alice@example.com` → **不同的用户记录**（或"用户不存在"）
3. 用户尝试登录 SAML IdP（公司 ADFS）→ **第三个用户记录**
4. 用户的个人资料、会话、同意记录分散在三个不同的用户 ID 中

**为什么这是一个问题：** 这是企业 SSO 中最常见的用户投诉之一。用户希望用一个身份注册，然后添加另一个登录方式。没有账户关联，他们必须为每个 IdP 单独注册。

**缺少什么：**
- 无 `IdentityLinkStore`——持久化 `(userID, provider, subjectID)` 三元组
- 无 `POST /me/identities/link`——将外部 IdP 身份关联到当前用户
- 无 `POST /me/identities/unlink`——移除关联的身份
- 无 `GET /me/identities`——列出已关联的身份
- 无重复检测——用 Google SSO 登录的 `alice@example.com` 已经有了一个本地密码账户→提示关联

**修复：** 添加 `IdentityLinkStore` SPI + 用于管理关联身份的自助端点 + 登录时的重复检测（匹配 `email` 声明 → "你已经有一个使用此邮箱的账户。关联吗？"）。

**工作量：** L（存储 + 3 个端点 + 登录时的重复检测逻辑 + UI 提示）| **影响：** **高**（用户满意度——"为什么我无法用 Google 登录？"）| **类型：** 功能

---

## 方向三：Admin API List 端点缺少分页、排序与过滤——返回所有记录

**问题：** Admin gRPC 服务（`gen/proto/admin/v1/clients.proto`、`users.proto`、`tokens.proto`）定义了列表端点：

```protobuf
message ListClientsRequest  {}
message ListClientsResponse { repeated Client clients = 1; }

message ListSessionsRequest {}
message ListSessionsResponse { repeated SessionToken sessions = 1; }
```

**没有分页参数**——没有 `page_token`、`page_size`、`offset`、`limit`。**没有排序参数**——没有 `order_by`、`sort_by`、`sort_order`。**没有过滤参数**——没有 `filter`、`query`、`tenant_id`、`user_id`。

**影响：**
- 拥有 10,000 个客户端的部署返回包含全部 10,000 条记录的单个 protobuf 消息
- 管理 UI（`admin/index.html`）必须在客户端渲染所有 10,000 行——导致浏览器冻结
- 无法搜索特定客户端或用户——UI 必须对所有记录进行 JS 端 `filter()`
- `ListSessions` 返回所有活动会话——在 100 万活跃会话的部署中会导致 OOM

**修复：** 向所有 Admin List RPC 添加 `page_token`、`page_size`、`order_by` 和 `filter` 字段。后端实现游标分页、可配置的排序字段和简单的过滤表达式。

**工作量：** L（proto 变更 + 所有 7 个 Admin 服务的存储级分页 + gRPC 网关 + UI 更新）| **影响：** **高**（拥有 >10K 个租户的生产部署的可用性）| **类型：** 运维/功能

---

## 方向四：gRPC 服务器缺少 MaxMessageSize、Keepalive 与连接超时配置

**问题：** gRPC 服务器（很可能在 `grpcserver/` 或 `cmd/sso-server/` 中创建）使用默认的 `grpc.Server` 选项。缺少生产就绪配置：

| 配置 | 默认值 | 为什么需要 |
|------|--------|-----------|
| `grpc.MaxRecvMsgSize` | 4 MB | 具有大量 RAR `authorization_details` 的 PAR 请求可能会超过此大小 |
| `grpc.KeepaliveParams` | 无 | 无 keepalive → 负载均衡器可能会丢弃空闲连接 |
| `grpc.KeepaliveEnforcementPolicy` | 无 | 客户端可能以每分钟一个 ping 的频率 ping——没有最小间隔策略 |
| `grpc.ConnectionTimeout` | 无限 | 慢速客户端占用了 gRPC-gateway goroutine |
| `grpc.MaxConcurrentStreams` | 无限制 | 单个客户端可以打开无限数量的流 |
| `grpc.InitialWindowSize` | 64 KB | 大流量的 Admin List RPC 可能因流控制而停顿 |
| `grpc.InitialConnWindowSize` | 无 | 同上，连接级别 |

**为什么这是一个问题：** gRPC-gateway 将所有 Admin REST API 调用转换为 gRPC。没有这些配置：
- 4 MB 的默认限制可能会拒绝具有较大请求体的合法 Admin API 操作（例如具有许多 `authorization_details` 条目的批量客户端创建）
- 无 keepalive → 经过 AWS NLB 空闲 350 秒后会断开连接
- 无连接超时 → 慢速客户端可以无限期保持连接打开

**修复：** 在 `NewServer` 调用中添加 gRPC 服务器选项：

```go
grpc.NewServer(
    grpc.MaxRecvMsgSize(16 * 1024 * 1024),  // 16 MB
    grpc.KeepaliveParams(keepalive.ServerParameters{...}),
    grpc.KeepaliveEnforcementPolicy(...),
    grpc.ConnectionTimeout(5 * time.Second),
    grpc.MaxConcurrentStreams(100),
)
```

**工作量：** S（~10 行配置）| **影响：** 中（生产 gRPC 可靠性）| **类型：** 运维/性能

---

## 方向五：不透明授权请求在执行过程中没有截止时间——慢速 IdP 挂起 Login 页面

**问题：** 授权请求（`/auth/login`）将用户重定向到上游 IdP 进行认证。但**对于整个交互没有硬截止时间**。当用户被重定向到慢速/挂起的 IdP 时，他们可能会无限期地停留在 IdP 的登录页面上。

**具体场景：**
1. 用户点击"使用企业 SAML 登录"
2. 浏览器重定向到公司 ADFS 服务器
3. ADFS 挂起（负载过高、网络分区、维护中）
4. 用户看到空白页面或旋转的加载图标
5. **没有基于时间的失效**——浏览器选项卡永远挂起
6. 原始的 `AuthCode`（如果 PAR 已使用）在 `PARTTL`（通常 60 秒）后过期，但用户不知道

**缺少什么：**
- 无 `AuthorizeRequestTTL`——授权请求的全局超时
- 无 `max_age` 参数强制执行——OIDC 的 `max_age` 参数告诉 AS 用户的认证时间不能超过 N 秒前；如果无法满足，提示重新认证
- 无重定向到超时 URL——如果 IdP 在 N 秒内没有响应，重定向回到 RP 并返回 `login_required`
- 无前端心跳——登录页面可以检查"仍在等待上游？"并在超时时回退到本地认证器

**修复：**
1. 添加 `WithAuthorizeRequestTimeout(duration)`——授权请求的服务器级超时（默认：5 分钟）
2. 实现 `max_age` 参数强制执行（当前已解析但可能未一致执行）
3. 当授权请求超时时，将用户重定向回 RP 的 `redirect_uri` 并返回 `login_required` + `error=interaction_required`

**工作量：** M（服务器级超时 + max_age 强制执行 + 优雅超时重定向）| **影响：** 中（UX + 资源泄漏预防）| **类型：** 功能/UX

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | Panic Recovery 中间件（Handler 崩溃 → 进程退出） | **高**（防止进程崩溃） | S | 弹性 |
| 2 | Admin API 列表分页/排序/过滤（>10K 条记录会 OOM） | **高**（生产管理 >10K 个条目的可用性） | L | 运维 |
| 3 | 跨 IdP 账户关联/合并（多登录方式） | **高**（用户满意度——"为什么我不能用 Google 登录？"） | L | 功能 |
| 4 | gRPC 服务器生产配置（Keepalive/超时/消息大小） | 中（生产连接可靠性） | S | 运维 |
| 5 | 授权请求截止时间（慢速 IdP 挂起页面） | 中（UX + 资源泄漏） | M | 功能 |

**按 ROI 排列：** 方向 1（Panic Recovery——20 行代码 = 防止进程完全崩溃）→ 方向 4（gRPC 配置——10 行配置 = 消除生产连接问题）→ 方向 2（Admin 分页——L 工作量但生产 >10K 个客户端时必须是 P0）→ 方向 5（授权超时——防止用户因挂起的 IdP 而无限期等待）→ 方向 3（账户关联——L 工作量但解锁了一个主要用户体验功能）。
