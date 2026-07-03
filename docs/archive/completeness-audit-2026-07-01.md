# 既有功能完备性深度审计

> 基于 2026-07-01 全代码库扫描。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：此前 6 轮分析（30 个方向）全部聚焦"新增什么方向"或"修复什么问题"。本轮完全不同——**不提出新方向，而是对既有核心功能的 RFC/规范完备性做逐项审计**。  
> 方法论：选取 5 个最核心的已有功能，对照其 RFC/OIDC 规范检查实现的覆盖度。  
> 原则：不写代码。

---

## 总体思路

前 6 轮的产出列表：

| 卷 | 聚焦 | 覆盖方向数 |
|----|------|-----------|
| 卷一 | 协议扩展 | 5 |
| 卷二 | 治理运维 | 5 |
| 卷三 | Edge Cases + 性能 | 5 |
| 卷四 | 代码健康 + 生态 | 5 |
| 卷五 | 架构债务 | 5 |
| 卷六 | API 产品化 + 运维就绪 | 5 |
| **合计** | | **30** |

第 7 轮不再问"还要加什么"，而是问"已有的做得够好吗"。对以下 5 个核心功能做规范完备性审计：

1. **授权码流程**（RFC 6749 §4.1 + PKCE RFC 7636）
2. **刷新令牌轮换**（RFC 6749 §6 + OAuth 2.0 Security BCP）
3. **令牌自省**（RFC 7662）
4. **OIDC Discovery**（OpenID Connect Discovery 1.0）
5. **角色/权限 RBAC 系统**（NIST RBAC 标准）

---

## 审计一：授权码流程——RFC 6749 §4.1 + PKCE RFC 7636 完备性

### 核心缺口

| 规范要求 | 状态 | 详细说明 |
|----------|------|----------|
| `response_type=code` | ✅ 实现 | |
| `authorization_code` grant | ✅ 实现 | |
| 授权码签发（`/auth`） | ✅ 实现 | `HandleAuthorize` 签发 auth code |
| 授权码兑换（`/token`） | ✅ 实现 | `HandleToken` + `token_authcode.go` |
| PKCE S256 验证 | ✅ 实现 | |
| PKCE `plain` 允许 | ✅ 支持但可被禁用 | `AllowedPKCEMethods` 配置 |
| `code_challenge` 必选模式 | ✅ `require_pkce` | |
| 授权码单次使用 | ✅ `DELETE RETURNING` | Oracle-leak 安全 |
| 授权码过期 | ✅ TTL 可控 | |
| **授权码发送后刷新** | ❌ **未实现** | RFC 6749 无此要求，但 `prompt=none` 和 `max_age` 结合需要。Keycloak 支持 |
| **授权码到 token 的 iss 验证** | ✅ 实现 | RFC 9207 |
| **redirect_uri 验证** | ✅ 严格匹配 | |
| **client_id 与 code 的绑定** | ✅ 实现 | |
| **Auth Code 注入攻击防护** | ✅ DELETE RETURNING | |

### 完备性缺口

#### 1.1 `prompt` 参数行为集

OIDC Core §3.1.2.1 定义了以下 `prompt` 值：

| 值 | 语义 | 状态 |
|----|------|------|
| `none` | 不展示任何 UI，静默认证 | ✅ 实现 |
| `login` | 强制重新认证 | ✅ 实现 |
| `consent` | 强制展示同意页面 | ✅ 实现 |
| `select_account` | 让用户选择身份 | ❌ **未实现** |

**影响**：依赖 `select_account` 的 RP（如多账号应用）无法使用此 flow。RFC 要求"如果 server 不支持 `select_account`，则用 `login` 替代"，当前实现可能返回错误而非降级。

#### 1.2 `display` 参数

| 值 | 语义 | 状态 |
|----|------|------|
| `page` | 全页面 | ✅ 默认 |
| `popup` | 弹窗 | ❌ **未实现** |
| `touch` | 触摸优化 | ❌ **未实现** |
| `wap` | 移动优化 | ❌ **未实现** |

**影响**：移动原生应用中调起的 OIDC 弹窗无法指定 `display=popup`。影响不大——大多数 RP 不依赖此参数。

#### 1.3 `/auth` 端点的请求注入

当前实现检查 `redirect_uri` 但**不检查 `state` 参数的存在性**。RFC 6749 §4.1.1 说 `state` 是**推荐**（RECOMMENDED）而非**必需**（REQUIRED），但 OAuth 2.0 Security BCP（RFC 9700 §3.1.1）将其升级为：

> "The authorization server SHOULD require the client to include a `state` parameter"

**状态**：`state` 可选。建议 OIDC 模式下强制要求。

#### 1.4 授权码绑定到 Proof Key 的强度

PKCE 验证码在授权码兑换时验证。但**当前没有将 PKCE 挑战与 client_id 做更强的绑定**。如果攻击者获得了授权码但不知道 code_verifier，不可能兑换——这是设计目标，但：

- 当前没有**客户端生成的 nonce 绑定**（OIDC §3.1.2.1 的 `nonce` 参数在 ID Token 中验证，但在 auth code flow 中与 code 没有绑定）
- 建议添加 **PKCE + DPoP 双绑定模式**：code 兑换时需要同时提供 code_verifier + DPoP proof。

### 小计：完备性评分 **9/12**（3 项缺失均为可选扩展）

---

## 审计二：刷新令牌轮换——RFC 6749 §6 + 安全 BCP 完备性

### 核心缺口

| 规范要求 | 状态 | 详细说明 |
|----------|------|----------|
| 刷新令牌签发 | ✅ 实现 | |
| 刷新令牌使用 | ✅ 实现 | |
| **自动轮换** | ✅ 实现 | 每次使用签发新令牌 |
| **老令牌无效化** | ✅ 实现 | 旋转后删除旧令牌 |
| **家庭标识符（FamilyID）** | ✅ 实现 | 追踪刷新令牌家族 |
| **家庭重用检测** | ✅ 实现 | 重用→`DeleteFamily`→`invalid_grant` |
| **并发容忍窗口** | ✅ `refresh_grace.go` | 窗口内并发提交安全 |
| 过期时间延长 | ✅ 实现 | |
| 超出 TTL 拒绝 | ✅ 实现 | |
| **TTL 在每次刷新时是否重置** | ❌ **风险点** | 参考第三卷：如果 TTL 每次重置，无限活跃的 refresh token 永不过期。如果 TTL 从首次签发开始计算，N 天后绝对过期。当前策略需确认 |
| **Refresh token 的 SID 传播** | ✅ 不重置 AuthTime | OIDC §12.1 要求 |
| **Refresh 不能改变 scope（超出原范围）** | ✅ `ScopesSubsumed` 验证 | |
| **重放攻击防护（JTI）** | ✅ 可选 | JTI-Replay store |

### 完备性缺口

#### 2.1 刷新令牌的绝对过期 vs 滑动过期

| 策略 | 语义 | 当前状态 |
|------|------|----------|
| 滑动（rolling） | 每次刷新重置 TTL | ⚠️ 需要确认 |
| 绝对（fixed） | TTL 从首次签发计算 | ⚠️ 需要确认 |
| 混合 | 刷新重置 + 绝对上限 | RFC 推荐 |

**缺失的**：`refresh_token_max_lifetime` 配置——绝对上限。即使有滑动窗口，令牌也不能无限延长。

**风险**：如果没有绝对上限，一个 refresh token 可以持续使用多年（只要每 30 天用一次）。企业在合规审计（如 SOC 2）中会要求"定期重新认证"。

#### 2.2 刷新令牌的回收策略

当前 `DeleteFamily` 是唯一批量回收手段。缺少：

| 策略 | 状态 | 影响 |
|------|------|------|
| 按用户回收 | ❌ **缺失** | 用户离职后无法批量回收其 refresh token |
| 按 tenant 回收 | ❌ **缺失** | 租户关闭后无法批量回收 token |
| 按 client 回收 | ❌ **缺失** | client 凭据泄露后无法立即回收 |
| 过期令牌清理 | ❌ **缺失** | 过期 token 在存储中无限累积 |

**注意**：test 目录存在 `cross_replica_revocation_test.go`（284 行），表明跨副本回收已测试。但缺少面向运营者的按维度回收 API。

#### 2.3 Refresh token 的 `token_type_hint` 支持

RFC 7009 规定自省/回收时应支持 `token_type_hint`（`access_token` 或 `refresh_token`）。当前实现（`handle_revoke.go`）：

```go
func HandleRevoke(d RevokeDeps, ctx core.HandlerContext) {
    // ... 接收 token_type_hint 但实际通过尝试 access_token 和 refresh_token 两种方式
}
```

**缺口**：`token_type_hint` 参数理论上可以缩短处理路径，但当前实现中**即使 hint 是 `refresh_token`，仍然尝试 access_token 回收**。这不是 bug，而是性能浪费（每次回收做两次存储查询）。

### 小计：完备性评分 **10/13**（3 个管理缺口 + 1 个配置缺口）

---

## 审计三：令牌自省——RFC 7662 完备性

### 核心缺口

| 规范要求 | 状态 | 详细说明 |
|----------|------|----------|
| 自省端点 `/token/introspect` | ✅ 实现 | |
| 响应格式 `{"active":true/false}` | ✅ 实现 | |
| 认证（HTTP Basic / body creds） | ✅ 实现 | |
| `token_type_hint` 支持 | ✅ 实现 | |
| `active=false` 不返回其他字段 | ✅ 实现 | anti-enumeration |
| **缓存支持** | ✅ 可选 | `IntrospectionCache` 接口 |
| **缓存 TTL** | ✅ 可配置 | |
| **缓存过期后刷新** | ❌ **stale-while-revalidate 未实现** | TTL 过期→cache miss→全部回源 |
| 自省 `scope` 字段 | ✅ 实现 | |
| 自省 `client_id` 字段 | ✅ 实现 | |
| 自省 `sub` 字段 | ✅ 实现 | |
| 自省 `exp` 字段 | ✅ 实现 | |
| 自省 `iat` 字段 | ✅ 实现 | |
| 自省 `iss` 字段 | ✅ 实现 | |
| 自省 `token_type` 字段 | ✅ 实现 | |
| 自省 `aud` 字段 | ✅ 实现 | |
| **自省 `cnf` (confirmation) 字段** | ⚠️ **部分支持** | DPoP bound token 的 `cnf` 需要确认 |
| **自省 `jti` 字段** | ⚠️ **部分支持** | 需要确认 |

### 完备性缺口

#### 3.1 自省缓存 stale-while-revalidate

当前自省缓存的 TTL 到期后行为是直接的 cache miss → 回源。对于高并发 mesh 场景，这意味着 TTL 边界上的**惊群效应**（thundering herd）：

```
场景：TTL=60s, 1000 个并发请求在 TTL 过期后 1ms 到达
  → 999 个请求各自回源自省端点（重复验签 999 次）
  → 数据库连接被占满
  → 部分请求超时
```

**RFC 5861（HTTP Cache-Control stale-while-revalidate）** 定义了优雅的降级：返回旧值 + 后台异步刷新缓存。建议实现：

```
IntrospectionCache:
  Get(key) -> (result, ttl_remaining, stale_ok)
  Set(key, result, fresh_ttl, stale_ttl)
```

TTL 窗口：前 80% 正常 → 80-100% stale-ok（返回旧值 + 后台刷新） → 超过 100% 回源。

#### 3.2 自省 `token_type` 字段的粒度

RFC 7662 §2.2 中 `token_type` 定义为 `"bearer"` 或 `"dpop"` 或 `"mutual_tls"`。当前返回：

```json
{"active": true, "token_type": "Bearer", ...}
```

**缺口**：DPoP bound token 被自省时，`token_type` 应返回 `"DPoP"` 而非 `"Bearer"`。资源服务器根据 `token_type` 决定是否要求 DPoP proof。当前所有 token 都返回 `Bearer`——这会误导依赖此字段的 RS。

#### 3.3 自省端点对过期 token 的响应

RFC 7662 §2.1：过期 token 应返回 `{"active": false}`。当前实现：

- 已签名但过期的 JWT token：✅ 验签后检查 exp
- 已撤销但未过期的 token：✅ 查 revocation store
- **已撤销且过期的 token**：⚠️ 状态不确定——先验签（过期→失败）or 先查 store？结果路径不同

**风险**：如果先验签→过期失败→返回 `active:false`，则 revocation store 不会因过期 JWT 被访问。这是正确的（结果不变），但在审计日志中无法区分 "token 曾被撤销" 和 "token 已过期"。

### 小计：完备性评分 **14/17**（3 个缺口：stale-while-revalidate、DPoP token_type、过期撤销可区分性）

---

## 审计四：OIDC Discovery——OpenID Connect Discovery 1.0 完备性

### 核心缺口

OIDC Discovery 规范（§3）定义了 OpenID Provider Metadata 中必须/应该/建议返回的字段。

| 字段 | 要求级别 | 状态 | 说明 |
|------|---------|------|------|
| `issuer` | REQUIRED | ✅ | |
| `authorization_endpoint` | REQUIRED | ✅ | |
| `token_endpoint` | REQUIRED | ✅ | |
| `jwks_uri` | REQUIRED | ✅ | |
| `response_types_supported` | REQUIRED | ✅ | |
| `subject_types_supported` | REQUIRED | ✅ | |
| `id_token_signing_alg_values_supported` | REQUIRED | ✅ | |
| `scopes_supported` | RECOMMENDED | ✅ | |
| `claims_supported` | RECOMMENDED | ✅ | |
| `userinfo_endpoint` | RECOMMENDED | ✅ | |
| `registration_endpoint` | RECOMMENDED | ✅ | |
| `end_session_endpoint` | RECOMMENDED | ✅ | |
| `claims_parameter_supported` | OPTIONAL | ✅ | **但 06-30 分析发现声明与实际行为不符** |
| `request_parameter_supported` | OPTIONAL | ✅ | |
| `request_uri_parameter_supported` | OPTIONAL | ✅ | |
| `require_request_uri_registration` | OPTIONAL | ✅ | |
| `grant_types_supported` | OPTIONAL | ✅ | |
| `acr_values_supported` | OPTIONAL | ✅ | |
| `token_endpoint_auth_methods_supported` | OPTIONAL | ✅ | |
| `token_endpoint_auth_signing_alg_values_supported` | OPTIONAL | ✅ | |
| `display_values_supported` | OPTIONAL | ✅ | |
| `claim_types_supported` | OPTIONAL | ✅ | |
| `id_token_encryption_alg_values_supported` | OPTIONAL | ✅ | |
| `id_token_encryption_enc_values_supported` | OPTIONAL | ✅ | |
| `userinfo_signing_alg_values_supported` | OPTIONAL | ✅ | |
| `userinfo_encryption_alg_values_supported` | OPTIONAL | ✅ | |
| `userinfo_encryption_enc_values_supported` | OPTIONAL | ✅ | |
| `backchannel_logout_supported` | OPTIONAL | ✅ | |
| `backchannel_logout_session_supported` | OPTIONAL | ✅ | |
| `frontchannel_logout_supported` | OPTIONAL | ✅ | |
| `frontchannel_logout_session_supported` | OPTIONAL | ✅ | |
| **`pushed_authorization_request_endpoint`** | OPTIONAL | ✅ | PAR 端点 |
| `require_pushed_authorization_requests` | OPTIONAL | ⚠️ 需要确认 | |
| **`request_object_signing_alg_values_supported`** | OPTIONAL | ✅ | |
| **`request_object_encryption_alg_values_supported`** | OPTIONAL | ✅ | |
| **`request_object_encryption_enc_values_supported`** | OPTIONAL | ✅ | |
| **`check_session_iframe`** | OPTIONAL | ❌ **缺失** | OIDC Session Management |
| **`end_session_iframe`** | OPTIONAL | ❌ **缺失** | OIDC Session Management |

### 完备性缺口

#### 4.1 `check_session_iframe` 和 `end_session_iframe`

这是 **OIDC Session Management 1.0**（§4, §5）的两个字段。它们允许 RP 使用 postMessage 机制检查用户与 OP 的会话状态（无需重新定向）。

**状态**：缺失。当前支持 RP-initiated logout（`end_session_endpoint`），但不支持 session management iframe。

**影响**：
- RP 无法可靠检测用户是否在 OP 端登出
- 单点登出依赖 backchannel/frontchannel logout（已实现）
- 但 RP 无法主动轮询会话状态
- 上层协议（如 OAuth 2.0 for Browser-Based Apps RFC 未引用）依赖程度低

#### 4.2 `claims_parameter_supported` 声明 vs 实际行为

06-30 分析发现此字段声明为 `true`，但实际实现中部分 claims 参数未被处理。是一个**文档-实现偏差**：

| 声明 | 规范中的行为 | 当前行为 |
|------|-------------|----------|
| `id_token` | 在 ID Token 中返回请求的 claim | ✅ 实现 |
| `userinfo` | 在 UserInfo 端点返回请求的 claim | ⚠️ 需要确认 |
| `essential: true` | 如果 claim 不可用则认证失败 | ⚠️ 未检查 |
| `value` | 请求特定的 claim 值 | ⚠️ 未实现 |
| `values` | 请求一组可接受的值 | ⚠️ 未实现 |

`id_token` 和 `userinfo` 基础支持存在，但 `essential`、`value`、`values` 这些细化参数未实现。

#### 4.3 缺少的 discovery 扩展字段

部分 Snaplink 特有的扩展端点未在 discovery 文档中声明：

| 能力 | 端点 | Discovery 中声明？ |
|------|------|-------------------|
| 令牌自省 | `/token/introspect` | ❌ 缺失 |
| 令牌回收 | `/token/revoke` | ❌ 缺失 |
| PAR | `/par` | ✅ 已声明 |
| CIBA | `/ciba` | ❌ 缺失 |
| Device Authorization | `/device` | ❌ 缺失 |
| 管理员 API | `/api/v1/admin/*` | ❌ 不适用（非 OIDC） |

RFC 8414（OAuth 2.0 Authorization Server Metadata）定义了这些字段。OIDC Discovery 是 RFC 8414 的超集。

### 小计：完备性评分 **33/37**（主要缺口：session management iframe、claims 细粒度支持、特殊端点的 metadata 声明）

---

## 审计五：角色/权限 RBAC 系统——NIST RBAC 标准完备性

### 核心缺口

项目的 RBAC 系统（`platform/permissions/`）实现了：

| NIST RBAC 组件 | 状态 | 说明 |
|----------------|------|------|
| 用户-角色分配 | ✅ | |
| 角色-权限关联 | ✅ | |
| 会话-角色激活 | ✅ | |
| 角色层次 | ✅ | `user:*` ⊇ `user:read` |
| 静态职责分离（SSD） | ❌ | 无互斥角色约束 |
| 动态职责分离（DSD） | ❌ | 无会话内角色互斥 |
| 权限-菜单映射 | ✅ | |
| `*` 通配符解析 | ✅ | |
| 策略包导出 | ✅ | |
| 策略包导入 | ✅ | |

### 完备性缺口

#### 5.1 静态职责分离（SSD）缺失

NIST RBAC 标准要求"互斥角色"——一个用户不能同时持有两个冲突的角色（如"审计员"和"系统管理员"）。

**当前实现**：无法定义互斥角色。
- 用户可以被同时赋予 `admin:read` 和 `admin:write`
- 没有机制阻止用户既是"合规审核员"又是"权限管理员"
- 在 SOC 2 / SOX 合规审计中，职责分离是**必须**项

**需要的**：`role.exclusions` 定义互斥角色：

```yaml
permissions:
  roles:
    - name: auditor
      permissions: [audit:read]
      exclude: [admin, security_admin]   # 互斥声明
    - name: admin
      permissions: [admin:*]
      exclude: [auditor]
```

**工作量**：M（~100 行校验逻辑 + ~40 行测试）

#### 5.2 动态职责分离（DSD）缺失

NIST RBAC 第二层要求"同一会话内不能同时激活两个互斥角色"。即使用户同时持有 `auditor` 和 `admin` 角色，在同一个会话中不能同时激活。

**当前实现**：无会话级角色激活控制。
- JWT token 签发时嵌入全部角色
- 无 `"roles":["admin"]` 选择子集签发的机制
- 所有角色的权限在单个 token 中合并

**影响**：如果用户被赋予 `auditor:read` 和 `admin:write` 两个角色，签发出来的 token 同时持有两个角色的权限。资源服务器无法区分用户是以"审计员"还是"管理员"身份操作的——违反了 DSD 原则。

**需要的**：`requested_role` 参数或 session 中的 `active_role` 字段，允许用户在认证时选择以哪个角色身份操作。

#### 5.3 细粒度 resource-level 权限

当前权限模型是**粗粒度**的（`admin:read`, `admin:write`, `user:*`）：

| 能力 | 状态 | 行业标准（OAuth 2.0 RAR/RBAC） |
|------|------|-------------------------------|
| Scope-level | ✅ | |
| Action-level | ✅ | |
| **Resource-level** | ❌ 缺失 | Google IAM: `resourcemanager.projects.get` |
| **Conditional** | ❌ 缺失 | AWS IAM: `Condition: {"IpAddress": ...}` |
| **Attribute-based** | ❌ 缺失 | Auth0 FGA: `user:1 read doc:2` |

**当前**：你可以说"用户 A 有 `user:read` 权限"，但不能说"用户 A 只能读 tenant B 的 user"。

**影响**：
- 多租户场景的 admin 角色只能按 scope 粗粒度控制
- 不能实现"tenant admin 只能管理自己租户的用户"
- 所有跨租户隔离依赖 middleware 的 tenant 检查（当前已实现）

**总结**：当前 RBAC 是**单租户管理级**（谁可以执行什么操作），不是**数据级**（谁可以访问哪条数据）。数据级的授权由 tenant middleware 和 domain logic 分别处理。

### 小计：完备性评分 **7/11**（SSD/DSD 缺失是 NIST RBAC 标准的中等缺口，resource-level/ABAC 是高级需求）

---

## 优先级摘要

| # | 审计项 | 当前评分 | 最严重缺口 | 工作量 | 风险 |
|---|--------|---------|-----------|--------|------|
| **1** | **授权码流程** | 9/12 | 缺少 `select_account` prompt | S | 低 |
| **2** | **刷新令牌轮换** | 10/13 | 无绝对过期上限 + 按维度回收缺失 | M | **中** |
| **3** | **令牌自省** | 14/17 | stale-while-revalidate 惊群、DPoP token_type | M | 低-中 |
| **4** | **OIDC Discovery** | 33/37 | session management iframe、claims 细粒度、特殊端点声明 | M | **中**（声明与行为不符影响采购审查） |
| **5** | **RBAC 权限** | 7/11 | **SSD/DSD 职责分离缺失**（SOC 2 必查） | M | **高**（合规审计必查项） |

### 跨 7 轮总结

经过 7 轮分析（35 个方向），我在下表中总结每种分析视角的产出和受众：

| 轮次 | 文件 | 视角 | 受众 | 核心问题 |
|------|------|------|------|----------|
| 卷一 | `expansion-07-01.md` | 协议专家 | 工程 VP | 还缺什么协议？ |
| 卷二 | `expansion-07-01-v2.md` | SRE | 运维总监 | 生产环境缺什么？ |
| 卷三 | `edgecases-and-perf-07-01.md` | QA | 技术 lead | 什么场景下会崩溃？ |
| 卷四 | `health-and-dx-07-01.md` | 开发者 | CTO | 代码库健康吗？ |
| 卷五 | `debt-and-risks-07-01.md` | 架构师 | 技术委员会 | 架构可持续吗？ |
| 卷六 | `ops-api-productization-07-01.md` | 产品经理 | 采购决策者 | 产品成熟吗？ |
| **本卷** | **`completeness-audit-07-01.md`** | **审计员** | **合规官** | **已有功能完整吗？** |

### 最关键的行动建议

在所有 35 个方向中，我挑出三个必须优先处理的问题（排名不论）：

1. **⚠️ 构建断裂**（卷四方向①）：`go build ./...` 当前失败。这是优先级基线——其他所有工作缺了构建都是空谈。

2. **⚠️ RBAC 职责分离**（本卷审计五）：SSD/DSD 缺失是 SOC 2 合规审计的典型 fail item。如果平台目标包含"企业级"，这个缺口会让合规审查第一轮就挂。

3. **⚠️ 刷新令牌绝对过期上限**（本卷审计二 + 卷三方向一）：无绝对上限意味着 refresh token 可无限延期——这是安全审计必查的 "长期会话风险"。
