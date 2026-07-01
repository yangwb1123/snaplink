这份分析已经非常扎实——我逐项对照了实际代码进行验证。以下是 **同行审查视角** 的补充和质疑：

---

## ✅ 验证通过的核心判断

### 方向一（SCIM Push）—— 证据确凿

`protocols/scim/` 确实是一个完备的 SCIM Service Provider（32 个 `.go` 文件：filter lexer/evaluator、PATCH 应用引擎、Bulk、ETag、Sort、完整 discovery）。**零** Push 方向代码。Cluster bus 的 `EventKind` 没有 `KindUserProvisioned`/`KindGroupProvisioned`——现有 8 个 kind 全部是缓存失效相关，没有 lifecycle 事件。

**一个加分的发现**：`domains/permissions/provider.go` 中的 `GroupMembershipWriter` 接口（`AddRoleToUser`/`RemoveRoleFromUser`）**恰好是 SCIM Push 所需的增量组成员操作**，且标记为 idempotent。这意味着 SCIM Push 的组成员同步可以直接复用此 SPI，无需重新设计幂等语义。

### 方向二（Break-Glass + 审批）—— 验证通过

`interfaces/admin/middleware.go` 的 `Middleware` struct：
```go
type Middleware struct {
    validator    TokenValidator
    authorizer   Authorizer
    methodScopes map[string]string
    rateLimiter  *rate.Limiter
    recorder     *audit.Recorder
}
```
**没有任何**以下字段：
- `emergencyAccess *EmergencyAccessStore`
- `approvalCheck func(ctx, AdminOperation) error`
- `breakGlassConfig`

纯 scope 检查，分析完全正确。`Authorizer` 接口甚至写了注释 "alternative implementations could read from an external policy engine (OPA, Rego)"——说明设计者预见到了扩展点但未实现。

### 方向五（ABAC）—— 验证通过

`Provider` 接口签名：
```go
type Provider interface {
    Permissions(ctx, userID, clientID string) ([]Permission, error)
    Roles(ctx, userID, clientID string) ([]Role, error)
    Menus(ctx, userID, clientID string) (MenuTree, error)
}
```
**没有** `ResourceContext`、`EnvironmentContext`、`PolicyEngine`。纯 RBAC。

---

## 🔍 盲点与补充

### 盲点 1：方向三缺少一个重要的级联故障来源——**TLS 证书轮换**

分析没有覆盖 **出站 mTLS 连接**（`infrastructure/extauthz/`、`infrastructure/ldap/` 可能使用 TLS）。在企业环境中，后端证书的轮换是 P0 级事故的常见根源：

- LDAP 证书过期 → 所有 LDAP 认证失败
- KMS 客户端证书过期 → 签名/解密全部失败
- CAEP Receiver 的 TLS 证书过期 → 推送全部失败

当前没有 **证书过期预警** 或 **证书热加载** 机制。建议在 `BackendConnector` 框架中加入 `CertificateExpiry() time.Time` 方法，暴露给 `/metrics` 和告警系统。

### 盲点 2：方向四（配置漂移）低估了**Admin API 与 Config YAML 的冲突解决**

分析假设了三种治理模式（Strict/Baseline/Append-Only）但回避了一个关键问题：**当 Config YAML 中的 client 定义与 Admin API 中同一 client 的属性冲突时，谁赢？**

实际上，admin API 的 write path 直接写入 store（用户/租户拥有者通过 API 修改），而 Config YAML 的 `Reconcile` 会覆盖回去。除非引入 **last-writer-wins 带时间戳** 或 **annotation-based 锁定**（"此字段托管于 YAML，禁止 API 修改"），否则 reconciliation 循环会造成无限的配置震荡。

建议补充：每个可 reconcilable 资源需要 `annotations` 字段（类似 Kubernetes）：
```go
type ManagedResource struct {
    ID          string
    Spec        interface{}
    Annotations map[string]string
    // "sso.snaplink/managed-by": "yaml" | "api"
    // "sso.snaplink/last-applied-config": <json>
}
```

### 盲点 3：跨方向的**审计跟踪完整性约束**

方向二（Break-Glass）和方向四（配置漂移）各自引入了审计事件，但分析忽略了 **审计事件本身的完整性**：

- Break-Glass 期间的所有操作必须能被**不可否认地关联**到同一个 Break-Glass session
- 配置漂移的自动修复必须记录 "谁"（系统账号）做了变更
- 审批工作流的每个状态转换（创建 → 待审批 → 批准/拒绝 → 执行/跳过）需要完整 trace

这意味着需要引入 **Audit Session ID** 作为横切关注点——不只是给每个事件一个 ID，而是给一组操作一个公共 Session ID。

### 盲点 4：方向一（SCIM Push）的**速率控制与下游限流**

分析提到了重试和幂等性，但企业 SaaS 下游（Salesforce、Google Workspace、Slack）通常有严格的 API 速率限制（例如 Salesforce 的 1 req/sec 并发）。如果 SCIM Push 引擎没有内置**速率感知调度**（通过 `429 Retry-After` header 自适应降速），初始全量同步会触发下游限流导致大面积失败。

建议：SCIM Push 引擎需要**Backpressure-aware scheduler**：
```go
type RateAwareScheduler struct {
    perTarget RateLimiter  // token bucket per downstream app
    queue     PersistentQueue
    backoff   ExponentialBackoff  // respects Retry-After
}
```

---

## 📊 重新评估的优先级矩阵

加入上述盲点后，我建议的调整：

| # | 方向 | 产品价值 | 架构影响 | 工作量 | 依赖 | 建议 |
|---|------|---------|---------|-------|------|------|
| **P0** | 方向二 Break-Glass | 极高 | 低 | M | 无 | **MVP: 1周** ✅ |
| **P0** | 方向一 SCIM Push | 极高 | 中 | L | 方向五的 GroupMembershipWriter(已存在) | **MVP: 2周，仅推 User CRUD** |
| **P1** | 方向三 弹性框架 | 高 | 中 | L | 方向二优先（因为治理基础设施需先就位） | **但应优先实施 TLS 证书预警** |
| **P1** | 方向四 配置漂移 | 高 | 中 | L | 需要先决策治理模式(Strict vs Baseline) | **建议从 Drift Detection ONLY 启动，先不加 Reconcile** |
| **P2** | 方向五 ABAC | 高 | 中 | M-L | A. 无紧急依赖 | **但需要 CheckWithContext API 先行，即使是空实现** |

**一个具体的路线图修正建议**：方向五的 `CheckWithContext` API 扩展应该提前到 P1.5，因为如果方向三的断路器需要基于环境信息做降级决策（"如果 LDAP 熔断且当前是上班时间，返回 503；如果下班时间，降级为密码认证"），断路器需要向授权引擎传递上下文。CheckWithContext 是这个集成的先决条件。

---

## ⚡ 文档本身的问题

1. **标题**：文档标题是中文但文件名是英文。和 `expansion-v2-2026-07-01.md` 等相邻文件命名风格一致，没有问题。
2. **在已有分析中的定位**：表最后一行的比较非常有价值——明确区分了本轮和之前的分析。非常干净。
3. **缺少一个盲点**：还有一个 **方向六** 没有讨论——**租户隔离的数据面**。当前审计日志、SCIM 数据、Event 推送都是全局的。企业多租户 SaaS 需要每个租户的数据面完全隔离（租户 A 的 SCIM Push 不能因为租户 B 的 LDAP 超时而被阻塞）。这实际上是方向三（弹性框架）和方向一（SCIM Push）的交叉点，但值得独立提及。

---

如果你希望我把上述补充整合到文档中（在保持原始分析完整性的前提下，作为"同行审查批注"或"补充分析"追加），我可以直接编辑文件。或者如果你希望保留这份文档不变，只是讨论，那我以上回复就是我的完整反馈。
