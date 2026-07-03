Now I have a clear picture. Let me compile a thorough review of this analysis.

---

## 第一轮分析核查报告

对五个方向逐一核对了代码实际状态，结论如下：

---

### 方向一：托管 Web UI ✅ 方向正确，细节有误

**结论：核心判断成立，但行数严重失实。**

| 文件 | 分析声称 | 实际 |
|---|---|---|
| `interfaces/web/login/index.html` | 981 行 | **150 行** |
| `interfaces/web/admin/index.html` | 1073 行 | **148 行** |
| `interfaces/web/portal/index.html` | 745 行 | **131 行** |

三者确实是**单文件静态 HTML + 内联 JS**（含 SVG logo、表单、`fetch` 调用），不是 SPA 框架工程。方向判断成立——这些是"能跑的 demo"，不是可品牌化、可路由、可 i18n 的托管产品。

补充发现：
- Discovery 仅声明 `prompt_values_supported=["none"]`（`server_discovery_config.go:435`），**确认**无法处理交互式 `prompt=login|consent|select_account`。
- 分析中关于 dogfood、secret 不回显、多租户权限隔离、自助门户边界等考量是合理的。

**建议**：方向优先级应为 **P1**——这是从 SDK 到平台的可见门槛，且后端依赖（admin API、SCIM、permissions、tenant）已全部就绪。

---

### 方向二：OIDC Conformance — max_age 收口 ⚠️ 部分已证伪，但仍有真实缺口

**分析声称**："没有任何代码检查上次认证是否在 max_age 窗口内"

**核查结果：两路径中一路已实现，一路确为存根。**

| 代码路径 | 状态 | 证据 |
|---|---|---|
| `silentRenewalFreshnessOK` (prompt=none) | ✅ 已正确实现 | `handle_silent_renewal.go:213-235` 检查 `time.Since(claims.AuthTime) > max_age` |
| `enforceLoginMaxAge` (交互式 /auth/login) | ❌ **空存根** | `server_login.go:362-371`：函数体永远 `return false`，注释声称"fresh credentials always satisfy"，但 SSO 场景下（用户已有活跃 session、走自动登录）`AuthTime` 可能是数小时前的 |

**真实缺口**：交互式登录路径的 `enforceLoginMaxAge` 需要在以下场景检查 `req.MaxAge`：
1. 用户有活跃 session 但 `max_age` 已过期 → 应要求重新认证
2. 用户刚输入凭据 → `AuthTime = now`，自然满足（现有注释的意图正确，但实现遗漏了 SSO/session-driven 场景）

**建议**：缩小范围到"补齐交互式路径的 `enforceLoginMaxAge`"，其余已证伪项（`at_hash`、AMR、`AchievedACR`、`auth_time`）从 backlog 中移除。优先级 **P2**。

---

### 方向三：时钟安全 ⚠️ 部分已解决，Session Refresh 仍有风险

**分析声称**：DPoP skew 硬编码 60s、session refresh 裸 `time.Now()`。

**核查结果**：

| 问题 | 状态 | 证据 |
|---|---|---|
| DPoP clock skew 硬编码 | ✅ **已可配** | `WithDPoPProofMaxAge` + `WithDPoPMaxClockSkew`（`server_dpop.go:403-428`） |
| DPoP maxAge 不可配 | ✅ **已可配** | 同上 |
| Session Refresh 裸 `time.Now()` | ❌ **确认存在** | `sqlite/sessions.go:208` `now := time.Now()`，`expires_at > ?` 比较用 UnixNano |
| RefreshToken.IsExpired 裸 `time.Now()` | 未找到文件 | `oauthspi/` 下有 `IsExpired` 引用但需进一步确认 |

**真实风险**：NTP 回拨或 VM 快照回滚后，`time.Now()` 可能回退，导致 `expires_at > now()` 在已过期 session 上重新为真。SQLite 的 `WHERE expires_at > ?` 用的 `now.UnixNano()` 直接来自 `time.Now()`。

**建议**：
- Go 1.9+ 的 `time.Time` 内建单调时钟（`t.Add(d)` 用单调分量），但 `time.Now().UnixNano()` **丢弃**单调分量，回到壁钟。所以 SQLite 比较确实有风险。
- 修复方案：在 Refresh 入口记录单调起点 `mono := time.Now()`，用 `mono.Add(ttl)` 计算新过期，用 `mono.Sub(start)` 比较——但跨请求的 `expires_at` 列存储必须用壁钟。真正的防线是**检测壁钟回拨**并在回拨时拒绝 Refresh。
- 优先级 **P2**，与方向二的 max_age 缺口并行处理。

---

### 方向四：JTI Replay Store 熔断 ✅ 方向正确且重要

**分析声称**：`MarkSeen` fail-open，store 故障期间可重放。

**核查结果：完全符合分析描述。**

`security/jti_replay.go` 接口注释（第 20-22 行）明确声明：
> *"Errors are fail-open: store failures shouldn't block valid requests, but callers SHOULD log them"*

调用路径确认：
- JAR `request_uri`（`server_login.go` → fetch → MarkSeen）
- DPoP proof（`server_dpop.go:51` → `enforceDPoPReplay` → MarkSeen）
- Token Exchange actor_token（`token_exchange_stages.go` → MarkSeen）

**分析中提出的"token-exchange 的 actor_token 不能出两次"是硬性安全不变量**——这里 fail-open 是设计妥协，不是正确行为。对于这类场景应该有 fail-closed 降级路径。

**建议**：
1. 按调用方区分策略：JAR/DPoP 可 fail-open（已有 replay 的其他防线如 iat 窗口），但 **token-exchange 的 actor_token 单次消费必须 fail-closed**。
2. 增加 `JTIReplayStore.Health()` 探针 + 熔断指标，让运维能观测降级状态。
3. 优先级 **P1**——这是一个可利用的安全窗口。

---

### 方向五：Policy-as-Code 导出 ❌ 核心前提已满足，需重新定位

**分析声称**：输出格式是自定义 JSON，非标准策略引擎格式。

**核查结果：已有完整 OPA Rego 参考实现。**

```
docs/examples/opa-authz-policy.rego   ← 完整的 OPA Rego 策略（77行）
```

该文件包含：
- 从 bundle 的 `roles[].permissions[]` 展开 `granted` 集合
- 自描述 `wildcard_semantics`（all_token / domain_suffix / separator）
- 精确匹配 + 域通配 + 全权三种 satisfy 规则
- 默认 deny
- 完整的使用文档和 `opa eval` 示例

`PolicyBundle` 已具备：
- 版本号（`PolicyBundleVersion`）
- 规范化字节（`CanonicalBytes`）→ ETag 缓存友好
- 自描述通配语义（sidecar 无需硬编码匹配规则）
- 仅含角色定义（O(roles)），不含用户分配（无 PII 泄露）

**方向五应重新定位为**：
1. **Cedar 格式导出**（目前仅有 OPA Rego，Cedar 是 AWS Verified Permissions 的标准）
2. **Bundle 自动拉取/推送**（cluster.Bus 已有 `KindAuthzPolicyChange` 事件，但缺少 sidecar 拉取协议或 Webhook 推送）
3. **OPA Bundle Server 协议**（让 OPA 直接 `services.sso` 拉取，而非手动 curl + jq）

优先级从 P2 降为 **P3**——核心价值已交付，增量是格式和集成便利性。

---

## 总结：优先级矩阵

| 方向 | 原始判断 | 核查后修正 | 优先级 |
|---|---|---|---|
| 一、托管 Web UI | P1 | ✅ 确认，唯一门槛型缺失 | **P1** |
| 二、max_age 缺口 | P2 | ⚠️ 缩窄为交互式路径一处空存根 | **P2** |
| 三、时钟安全 | P2 | ⚠️ DPoP 已可配；仅 Session Refresh 有风险 | **P2**（缩窄） |
| 四、JTI Replay 熔断 | P1 | ✅ 确认，token-exchange 路径需 fail-closed | **P1** |
| 五、Policy-as-Code | P2 | ❌ OPA Rego 已就绪；增量是 Cedar + 自动拉取 | **P3**（降级） |

**建议执行顺序**：方向四（安全硬伤）→ 方向一（平台门槛）→ 方向二+三（并行，规范合规性收口）→ 方向五（增量扩展）。
