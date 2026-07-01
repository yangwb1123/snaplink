# 第十二轮分析：Admin 令牌生命周期、Consent 过期机制、SQLite HA 与 CIBA 可靠性

> 基于全局代码库扫描产生的全新视角，此前十一轮未覆盖。

---

## 方向一：Admin Bearer 令牌生命周期管理缺失——泄漏后的盲区

**问题：** Admin API 使用 Bearer 令牌进行认证，作用域为 `admin:read` 和 `admin:write`（`interfaces/sso/options_passwd.go:231`）。令牌通过 `TokenAdminService.IssueTempToken` RPC 发放。但存在**管理令牌生命周期的多个缺口**：

**具体缺口：**
- 无 `POST /api/v1/admin/tokens/rotate`——管理员无法在不使用 gRPC 的情况下轮换自己的令牌
- 无 `GET /api/v1/admin/tokens`——无法列出已发放的 admin bearer 令牌
- 无 `DELETE /api/v1/admin/tokens/:id`——无法吊销特定 admin 令牌（只能吊销用户令牌）
- 无 admin 令牌到期通知——`TempToken` 生命周期结束时没有日志告警或到期前通知
- 无 admin 令牌使用审计——没有"哪个 admin 最近使用了哪个令牌"的可见性

**为什么这是一个问题：** 考虑场景：一名运营员工离职。他们的 admin bearer 令牌正在 CI/CD 管道或监控脚本中使用。没有 admin 令牌列表，就无法知道哪些令牌需要吊销。运营团队的解决方法是：滚动所有共享密钥，重新发放所有 CI/CD 令牌——或者冒险保留离职员工的活跃令牌。

**修复：**
1. 添加 `AdminTokenStore`——持久化已发放的 admin 令牌及其到期时间、范围、标签和管理员 ID
2. 添加 `GET /api/v1/admin/tokens`——列出自身可见的活跃 admin 令牌
3. 添加 `DELETE /api/v1/admin/tokens/:id`——吊销特定的 admin 令牌
4. 添加 `EventAdminTokenExpiring` 告警——比到期提前 7 天发出告警

**工作量：** M（存储 + 3 个端点 + 审计事件 + 管理 UI）| **影响：** **中高**（运维安全——谁持有令牌？）| **类型：** 运维/安全

---

## 方向二：Consent 授予缺少 TTL——永久授权违反最小权限原则

**问题：** `ConsentStore`（`shared/core/spi.go:247`）定义了 `RecordConsent` 和 `GetConsent`。在 `GetConsent` 的返回中**没有 `expires_at` 字段**——ConsentGrant 结构体中没有 `ExpiresAt`：

```go
type ConsentGrant struct {
    UserID   string
    ClientID string
    Scopes   []string
    GrantedAt time.Time
    // No ExpiresAt!
}
```

一旦用户授予权限，它就永远有效，除非：
- 用户手动通过管理门户撤销
- 管理员通过 `RevokeConsent` 撤销
- 客户端被删除

**为什么这是一个问题：** GDPR 和 ePrivacy 指令要求同意具有明确的**有效期**，并要求**定期更新同意**。对于医疗保健（HIPAA）、金融（PSD2）或儿童数据（COPPA）中的部署，永不过期的同意不合规。

此外，对用户来说，这很令人困惑：用户在 2019 年授予某个 RP 邮箱访问权限。现在是 2026 年。他们忘记了。该 RP 仍然可以访问他们的邮箱。

**修复：**
1. 添加 `MaxConsentTTL time.Duration`——服务器级配置（默认：5 年？服务器配置的）
2. 向 `ConsentGrant` 添加 `ExpiresAt time.Time`
3. 在 `GetConsent` 中添加过期检查——如果超过 TTL，表现得像是 `ErrNoConsentGrant`
4. 添加 `WithConsentTTL(duration)` 服务器选项
5. 每当同意过期时，为用户显示新的同意提示

**工作量：** M（SPI 变更 + 存储迁移 + 过期检查 + 配置 + 新提示 UI）| **影响：** 中（法规合规性 + 用户信任）| **类型：** 功能/合规

---

## 方向三：SQLite 部署缺少跨副本高可用能力——单点故障

**问题：** 代码库支持 PostgreSQL、Redis 等作为集群存储后端。但**SQLite 后端（默认设置）是单节点、单文件的**。在 SQLite 模式下，每个副本运行自己的数据库文件——服务器停机意味着数据不可用。

**具体缺口：**
- 没有内置的 SQLite→SQLite 复制
- 没有 Litestream/LiteFS/region 集成
- 没有 WAL 模式 S3 归档用于时间点恢复
- 热备只能通过 `VACUUM INTO` 或文件级复制实现——没有 SQL 端点
- 对于 SQLite 部署，跨区 HA 的唯一选项是迁移到 PostgreSQL

**影响：** 对于评估 SSO 的团队来说，PostgreSQL 是一种运营开销。SQLite 对于小团队来说非常棒，但"如果我的服务器宕机，我会丢失所有会话和令牌数据"的担忧使采用变得复杂。

**修复：** ADR 驱动的选项：
1. 添加 `WithSQLiteReplicaSource(dsn, replicaLag)`——启动一个后台线程，定期从主副本的 WAL 中获取最新数据（使用 `PRAGMA wal_checkpoint` 或内置的 `backup` API）
2. 添加 `POST /api/v1/admin/backup`——触发 SQLite `VACUUM INTO` 并流式传输备份
3. 添加 Litestream 配置示例（`docs/deploy/litestream.md`）——解释如何将 SQLite 流式传输到 S3 以实现 HA

**工作量：** S（文档 + 备份端点）到 XL（内置复制）（建议从文档 + 备份端点开始）| **影响：** 中（采用阻碍）| **类型：** 运维

---

## 方向四：CIBA 挑战投递无重试——单次投递失败 = 整个认证请求被放弃

**问题：** `protocols/oauth/handle_ciba.go:233` 调用 `DeliverCIBAChallenge` 来推送认证请求（推送通知、短信、WebSocket）。但如果投递失败：

```go
if err := d.DeliverCIBAChallenge(ctx.Request().Context(), authReqID, subjectID, req.BindingMessage); err != nil {
    d.SrvLogger().Error("ciba challenge delivery failed", "error", err)
    ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
    // auth_req_id已持久化，但客户端永远不会知道
    return
}
```

认证请求 ID（`auth_req_id`）已被持久化并返回给客户端。客户端开始轮询 `/token`，但**用户从未收到推送通知**。轮询者一直轮询直到 `auth_req_id` 过期——白白浪费资源。

**为什么这是一个问题：**
- 推送通知投递可能由于网络闪断、设备离线或 APNs/FCM 暂时不可用而短暂失败
- 单次失败放弃了整个 CIBA 流程——而重试可能成功
- 没有替代投递渠道（推送 → 回退到短信 → 回退到轮询）

**修复：**
1. 向 `DeliverCIBAChallenge` 添加重试逻辑——3 次指数退避重试
2. 添加 `WithCIBADeliveryFallback(fallback Sink)`——如果推送失败，回退到备用投递机制
3. 添加 `sso_ciba_delivery_retries_total` 和 `sso_ciba_delivery_failures_total` 指标
4. 在重试耗尽后，使用 `ciba_delivery_failed` 事件标记 `auth_req_id`，以便轮询者及时收到 `access_denied` 而不是静默超时

**工作量：** S（重试循环 + 指标）到 M（回退投递）| **影响：** 中（CIBA 可靠性）| **类型：** 弹性

---

## 方向五：OAuth `state` 参数验证跨响应模式的一致性——安全保证因交付通道而异

**问题：** OAuth 2.0 使用 `state` 参数进行 CSRF 防护（RFC 6749 §10.12）。`state` 由客户端生成，由授权端点回显。但安全保证取决于**响应如何传递**：

| 响应模式 | `state` 保证 | 风险 |
|----------|--------------|------|
| `query`（URL 查询字符串） | ✅ 由授权服务器验证——如果 state 不匹配，返回 `access_denied` | 低——出现在服务器日志中 |
| `fragment`（URL 片段） | ✅ 由授权服务器设置——不通过服务器日志 | 低——不在服务器日志中 |
| `form_post`（POST body 到 RP） | ✅ 作为表单字段传递 | 低——通过 POST body |
| `query.jwt` / `fragment.jwt` / `form_post.jwt`（JARM） | 由 JARM 规范定义——`state` 是签名的 JWT 中的声明 | **最高保证** |

**问题：** 需要检查 `state` 在**所有**响应模式中是否被一致地验证，特别是从 `fragment` 到 `form_post` 到 JARM 模式。如果一个模式省略了 `state` 验证，而客户端依赖于它进行 CSRF 防护，就存在漏洞。

具体的验证点：
- 所有 grant 类型在所有 response_mode 下都检查 `state` 吗？
- `state` 在混合响应类型（`code id_token`）中是否被一致地回显？
- `state` 在错误响应中是否被回显（RFC 6749 §4.1.2.1 要求回显 `state` 如果提供了）？

**修复：** 添加中心化的 `ValidateAndEchoState` 函数，在所有代码路径（授权、令牌、错误）中使用。添加在所有 response_mode（query、fragment、form_post、JARM）中运行的集成测试。

**工作量：** S（审计 + 中心化状态处理）| **影响：** 中（CSRF 防护一致性）| **类型：** 安全/正确性

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | Admin Bearer 令牌生命周期管理 | **中高**（离职人员盲区——活跃但不可见的 admin 令牌） | M | 安全/运维 |
| 2 | Consent 授予 TTL（永不过期的同意） | 中（GDPR 合规性 + 用户信任） | M | 合规 |
| 3 | SQLite 跨副本 HA（Litestream/备份端点） | 中（小团队采用阻碍） | S | 运维 |
| 4 | CIBA 挑战投递重试（单次失败=放弃） | 中（CIBA 可靠性） | S | 弹性 |
| 5 | OAuth `state` 参数跨响应模式验证一致性 | 低-中（CSRF 防护） | S | 安全 |

**按 ROI 排列：** 方向 1（Admin 令牌——安全盲区，离职员工持有活跃 admin 令牌是一个现实风险）→ 方向 2（Consent TTL——永久同意是受监管行业的合规差距）→ 方向 5（State 验证——低工作量、高影响的 CSRF 防护审计）→ 方向 4（CIBA 重试——最小的代码改动解决可靠性问题）→ 方向 3（SQLite HA——对从 SQLite 起步并规划增长的团队最重要）。
