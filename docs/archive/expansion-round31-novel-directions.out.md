这是一个极其扎实的结构化扫描——五个方向都经过代码级验证、有明确的技术债务支撑和竞品对标锚点。我从**架构评审者**角度补充几个盲区、风险点和技术取舍建议。

---

## 总体评价

文本的质量很高——每个方向的"现状→缺口→Scope→Edge Cases→价值"结构符合架构提议（RFC）标准。AGENTS.md 中新增的 oracle-leak/anti-enumeration 约束与方向五（韧性验证）之间的隐含联系是全文最有洞见的连接。

以下逐一补充。

---

## 方向一：AI Agent 身份——缺一个关键的 RFC 合规路径

### 盲区

> `delegation_token` grant type 作为全新 grant type 列出。

这是一个**不必要的协议分歧**。RFC 8693 Token Exchange 的 `act` (actor) claim 已经可以表达 A→B 委托链：

```json
{
  "iss": "https://sso.example.com",
  "sub": "agent-B@org-a",
  "act": {
    "sub": "agent-A@org-a",
    "act": {
      "sub": "user-alice@org-a",
      "agent": true
    }
  }
}
```

现有 `/token` 端点已经处理 `urn:ietf:params:oauth:grant-type:token-exchange`(`protocols/oauth/handle_token_exchange.go`)。**Agent 委托应该复用这个路径**，而非发明新 grant type。需要增加的是：

- `Agent` 作为 `token-exchange` 中的 `actor` 类型（当前只在 `act` 放 `user`）
- `delegation` 作为 `requested_token_type` 的一个子类型（扩展 RFC 8693 §3.1 的 `requested_token_type` 枚举）
- 委托深度限制作为 token-exchange 的 `max_chain_depth` 参数

### 风险点

**MCP 协议的版本稳定性**。`cmd/sso-mcp/` 当前是单文件 Stdio/HTTP transport 实现。MCP 规范 2025-2026 年正快速演进。如果把 agent 身份平面深度耦合到 MCP，协议升级可能带来较大的重构代价。建议：**MCP 只做协议翻译层**，agent 身份逻辑全部放在 `domains/agent/`，通过 SPI 输出。

### 建议 Scope 调整

```
Phase 1 调整：
  ├── shared/core/types_agent.go → 复用 RFC 8693 act 结构，新增 Agent 类型
  ├── protocols/oauth/handle_token_exchange.go 增强 — 接受 agent 作为 actor
  └── 取消独立 delegation_token grant type
```

---

## 方向二：网关边缘身份层——有两个更紧迫的子问题

### 盲区 1：撤销传播的安全窗口是最大的架构债务

你提到的"撤销后边缘可能在 TTL 窗口内放行已撤销令牌"——这在当前设计中不是一个边缘案例，而是一个**可被利用的窗口**。OAuth 2.0 标准假设撤销是通过共享存储（RevocationSet）即时生效的。如果边缘缓存完全独立，那么：

```
1. 用户点击"撤销所有会话"
2. 核心 RevocationSet 更新成功 ✓
3. 边缘缓存无感知 → 撤销令牌在 TTL 期间仍可访问
4. 攻击者若已持有令牌 → 窗口期内完全绕过撤销
```

**临时缓解方案**（在 Phase 1 SSE 之前就可做）：边缘的 `auth.lua` 对撤销类端点（`/token/revoke`, `/token/revoke-all`）做**强制回源**——不允许边缘缓存决定这些操作的验证结果。现在就可以改 2 行 Lua：

```lua
-- auth.lua: 
local is_revoke_endpoint = ngx.var.uri:match("^/token/revoke")
if is_revoke_endpoint then
    -- bypass edge cache, always pass through to core
    return
end
```

### 盲区 2：gateway TLS 终端的 key material 管理

OpenResty 当前配置（`nginx.conf`）中的 TLS 证书和私钥是文件挂载的。如果实现边缘令牌内省（Phase 3），边缘需要能够验证 JWT 签名——这意味着**边缘存储了核心的公钥集**。当前 `jwks_cache.lua` 只缓存 JWKS，但不够：边缘还需要一个机制确认它看到的 `kid` 对应的公钥"没有被撤回"（不仅仅是 TTL 过期）。

### 建议：Phase 0 先做一个"缓存一致性审计"

在 Phase 1 的 SSE 事件通道之前，加一个**可观测性工具**：边缘定期（每 5m）报告其缓存状态的 checksum，核心记录是否匹配。这样至少知道"缓存偏移了多少"，而非盲目信任 TTL。

---

## 方向三：用户生命周期——SCIM 桥接是最大的隐藏依赖

### 关键洞察

当前 SCIM 实现（`protocols/scim/`）的 `UserResource` 结构体有一个 `active` 布尔字段：

```go
// protocols/scim/types.go
type UserResource struct {
    // ...
    Active *bool `json:"active,omitempty"`
}
```

SCIM 的 `active` 语义是"用户是否可登录"。如果引入完整的 `User.Status` 状态机，SCIM 入站同步必须将 `active: false` 映射到正确的状态——但不同的 SCIM 场景映射不同：

| SCIM 场景 | `active: false` 映射到 | 原因 |
|-----------|----------------------|------|
| IdP 主（Okta 推送） | `SUSPENDED` | IdP 侧禁用，保留数据 |
| IdP 主（离职流程） | `ARCHIVED` | SCIM 删除前常先发 `active: false` |
| HR SaaS （入职） | `INVITED` | 尚未完成 onboarding |
| 用户自注册（SCIM 回写） | `INACTIVE` | 用户未在预期时间内激活 |

这意味着 `UserLifecycleManager` 必须知道**状态的来源**（SCIM 入站 vs 管理员操作 vs 自助），不能一刀切映射。

### 另一个隐藏依赖：SQLite 行级 TTL

当前 SQLite 存储没有任何行级 TTL 或过期策略。如果实现 `ARCHIVED`→`PURGED` 自动转换，需要在 SQLite 层支持**基于时间条件的批量删除**。当前 `delete_expired.go` 只处理 token 和 code 过期。需要一个泛化的 `ExpirableStore` SPI。

### 建议：把 SCOPE 中的 Phase 1 拆成"最小可行状态机"

不是一次性引入 6 个状态。先加 3 个：

```
INVITED → ACTIVE → SUSPENDED
                ↘ (直接)
```

`INACTIVE`/`ARCHIVED`/`PURGED` 依赖调度器和 TTL 基础设施，放在 Phase 2。这样 Phase 1 可以在不引入后台调度器的情况下交付核心价值（禁用/恢复）。

---

## 方向四：跨租户协作——缺一个关键的"身份锚点"决策

### 最大的技术分歧：Subject 锚定策略

跨租户场景的核心问题是：**Guest 用户的 `sub` 用哪个值？**

| 策略 | 优点 | 风险 |
|------|------|------|
| **Orig-sub**（`sub=user@org-b`） | 保持 IdP 原生的 subject 引用，与上游 SAML/OIDC 一致 | Token 的 `iss` 与 `sub` issuer 不匹配——OIDC Core §2 要求 `iss` 对应签发方 |
| **Shadow-sub**（影子 subject `sub=guest-uuid`） | `iss` 与 `sub` 一致（都是 Org A 签发） | 失去与 Org B 身份源的关联；多个 Org A 应用看到不同的 sub |
| **Paired-sub**（`sub=pairwise-id`） | 对标 RFC 5885 pairwise 标识符，每个应用看到不同值 | 跨租户撤销复杂——Org B 删除用户时，Org A 不知道对应哪个 pair |

这是**架构级决策**，会影响 token 格式、ID Token 的 `sub` 校验、RP 侧的 subject 处理、审计追踪。应该在 Phase 0 做出 ADR。

### 建议 ADR 方向

参考 Azure AD B2B 模型：Guest 用户在资源租户中有一个**影子对象**（Shadow User），但影子对象的 `sub` 通过 `idp` claim 指向原始 IdP：

```json
{
  "sub": "shadow-guid-for-org-a",
  "idp": "https://sso.org-b.com",
  "oid": "original-user-id-at-org-b",
  "iss": "https://sso.org-a.com"
}
```

这样 `iss` 一致（Org A），`idp` 指向来源（Org B）。这是目前对标实现中最成熟的模式。

### 与 Federation 的关系

`protocols/federation/` 实现了 OpenID Federation 1.0，它的实体元数据包含 `organization_name`、`contacts`、`policy_uri`。这些可以作为**跨租户信任的元数据来源**——自动填充 TrustedTenant 的策略默认值，而非要求管理员手动配置。这个协同点文档中未提到。

---

## 方向五：韧性验证框架——当前最有落地价值的建议

### 为什么这个方向应优先开始

1. **零侵入成本**：故障注入可以通过接口包装器实现，不需要修改任何生产代码的 if/else 逻辑
2. **高信号覆盖率**：6 个关键场景（JTI、Revocation、JWKS、Tenant、Key Publish、Signing Key）覆盖了分区矩阵中 **70%+ 的单元格**
3. **立刻可测**：目前已经有 `memory.*` store 实现——用 `memory.Store` 包装一个 `FaultyStore` 可以在纯内存环境注入故障，不需要 etcd/Redis 集群

### 一个更简单的 Phase 1 替代方案

下面这个 SPI 层实际上是一种侵入。更简单的做法是**利用现有的 interface 边界做 wrapping**：

```go
// test/chaos/wrappers.go — 不需要 shared/core/fault.go
package chaos

import "github.com/snaplink/snaplink/shared/core"

// FaultyTokenStore wraps a TokenStore and injects failures.
type FaultyTokenStore struct {
    core.TokenStore
    failCreate bool
    failFind   bool
}

func (s *FaultyTokenStore) Create(ctx context.Context, t *core.Token) error {
    if s.failCreate {
        return errors.New("injected fault: token store write failure")
    }
    return s.TokenStore.Create(ctx, t)
}
```

这样**零侵入生产代码**，测试通过类型组合注入故障。`FailureMode` Enum 方案会污染生产 import。

### 建议覆盖的"压力测试"场景（文档中未列出但很重要）

| 场景 | 验证目标 | 难度 |
|------|---------|------|
| **双副本同时故障恢复** | 两个副本同时重启后，key adoption 是否产生 split-brain | 中 |
| **时钟大幅偏移** | 多副本间时钟差 30s+ 时，token 的 `iat`/`exp` 验证是否一致 | 低 |
| **慢路径不阻塞快路径** | etcd 读超时（5s）不阻塞本地 token 签发 | 中 |
| **bus 消息重放** | 重复的 `KindTokenRevoked` 消息是否幂等 | 低 |

---

## 跨方向综合建议

### 执行顺序重新考虑

文档说"方向一与方向五并行先启动"。我同意方向五（Phase 1 仅需 S effort）先启动。但**方向一有协议设计分歧（RFC 8693 复用 vs 新 grant type），建议先把 ADR 做了再启动**——不要在分歧未解决时写代码。

**建议的执行序列：**

```
Week 1-2:  方向五 Phase 1（FaultyStore wrapper + JTI/Revocation 两个 case）
           方向三 Phase 1 的 ADR（状态枚举 + 转换规则 + SCIM 映射）
Week 3-4:  方向五 Phase 2（6 个 case）
           方向一 ADR（RFC 8693 复用方案 + Agent 类型设计）
Week 5-6:  方向三 Phase 1（3 状态 MVP + 管理员 API）
           方向二 Phase 0（边缘撤销端点 bypass + 缓存 checksum 审计）
Week 7-8:  方向一 Phase 1（Agent 类型 + token-exchange 扩展）
           方向四 ADR（Subject 锚定策略）
```

### 一个被遗漏的连接点

所有五个方向都忽略了**与 observability 基础设施的协同**。当前的 observability 是 `metrics/` + `audit/` + `health/`。

- 方向一的 Agent 行为审计需要一个新的 `subject_type` 维度——这意味着 `audit.Record` 结构体需要扩展
- 方向二的边缘缓存失效需要被 `health.ReadinessProbe` 感知——边缘 warm-up 完成之前，核心的 readiness 应返回 false
- 方向三的状态转换事件应该走现有的 `cluster.Bus` → 下游可以订阅 `UserLifecycleChanged` 事件
- 方向五的故障注入测试结果应该产出 metrics → Prometheus 告警规则可以基于故障测试结果调整

这是一个**交叉依赖**，应该在所有方向的 Phase 0 中统一处理。

---

## 总结

| 方向 | 文档质量 | 盲区数 | 技术风险 | 建议优先级 |
|------|---------|--------|---------|-----------|
| 一（Agent 身份） | 高 | 1（RFC 8693 复用路径） | 中（协议分歧） | **2**（先做 ADR） |
| 二（边缘身份层） | 高 | 2（撤销 bypass + key mgmt） | 高（安全窗口） | **3**（Phase 0 可立即做） |
| 三（用户生命周期） | 高 | 1（SCIM 映射分歧） | 中（SQLite TTL） | **4**（依赖 infra 就绪） |
| 四（跨租户协作） | 高 | 1（Subject 锚定未定） | 高（协议级决策） | **5**（依赖 ADR） |
| 五（韧性验证） | 高 | 2（测试覆盖范围可扩展） | 低（零侵入方案） | **1**（最低成本最高信号） |

**方向五应该是本周可以开始的事情。方向一的 ADR 应该是下周的主题。** 这五个方向组合起来，将把项目从一个"功能完整、但治理视图不完整"的身份平台推向"AI-native、B2B-ready、韧性可测量"的下一代身份基础设施。

---

以上分析基于全代码库的架构理解。如果需要我针对某个方向展开更深入的技术设计讨论，或者提供某个 Phase 的接口定义草案，请指明。
