# 功能扩展方向分析 —— 第一轮

> 日期：2026-06-29
> 扫描范围：全局代码库首次扫描
> 视角：全局产品/协议/安全

---

## 方向一：托管 Web UI（Hosted Login + Admin Console + 自助门户）

**当前状态：**
- `interfaces/web/login/index.html`（981 行）、`interfaces/web/admin/index.html`（1073 行）、`interfaces/web/portal/index.html`（745 行）——都是**单 HTML 存根**（index.html placeholder），不是真实 SPA。
- 登录交互全靠 `curl` 级 JSON 契约，SPA 开发者必须自建登录/consent/MFA/改密页。
- Discovery 只敢声明 `prompt_values_supported=["none"]`，因为无托管登录页来处理交互式 prompt。

**为什么需要：**
这是 "auth 库→身份平台" 的最后一道门槛。Auth0/Okta/Keycloak 的采购首屏 demo 是有品牌化登录页 + consent 屏 + 管理控制台。后端能力（admin CRUD、SCIM、审计、permissions、租户）已全部就绪，只缺前端消费它们。

**边界情况：**
- Console 自身要用本 SSO 登录（dogfood），`client_id=sso-admin-console`
- 敏感字段绝不在前端回显（secret 只显"已轮换"）
- 多租户权限隔离（`admin:read.tenant.{tid}` vs `.global`）
- 自助门户必须强制"用户只能操作自己的数据"

---

## 方向二：OIDC Conformance 正确性收口

**当前状态（经 grep 核对——此方向多数已被后续验证代码证伪）：**

初始假设的缺失项：
- ~~`at_hash` 完全缺失~~ → **证伪**：`infrastructure/defaultimpl/at_hash.go` 已实现，三个 issuer 均调用
- ~~AMR 被压成单一 provider id~~ → **证伪**：`internal/handler/amr.go` 已完整实现 `AmrForResult()` + `WithMFAMethod()`
- ~~`AchievedACR` 字段不存在~~ → **证伪**：`shared/core/types_auth.go:124` 已定义
- ~~`auth_time` 被替换~~ → **证伪**：`protocols/oauth/oauthspi/auth_code.go:40` 已捕获

**仍为开放的缺口：** `max_age` 未强制执行

OIDC Core §3.1.2.6 的 `max_age` 参数被解析（`internal/auth/login/types.go:25`）和存储（`interfaces/sso/server_login_resolve.go:169`），但**没有任何代码检查上次认证是否在 `max_age` 窗口内**。客户端可以带 `max_age=5` 但登录流程永不重新要求认证。

---

## 方向三：时钟安全与单调时间（Monotonic Clock + Skew Tolerance）

**当前状态：**
- `SessionManager.Refresh`（`defaultimpl/sqlite/sessions.go`）用 `expires_at > now()` 判断过期——裸 `time.Now()`，无单调时钟保护
- DPoP `iat` 校验硬编码 60s skew（`server_extensions.go`），无可配 `WithDPoPMaxClockSkew`
- refresh token `IsExpired`（`oauth/refresh_token.go`）同样裸 `time.Now()`

**为什么需要：**
NTP 步进（ntpdate 式回拨）或 VM 快照回滚可让**已过期的 session/token 通过 `expires_at > now()` 被无限续期**。

---

## 方向四：JTI Replay Store 熔断与安全硬化

**当前状态：**
- `security/jti_replay.go` `MarkSeen` 错误时 **fail-open**（默认行为）
- 跨副本模式（Redis/etcd 后端）下，store 瞬时故障期间每个 JTI 都被当作"首见"
- 调用路径：JAR `request_uri`、DPoP proof、actor_token（token-exchange）——全是攻击者可控制的输入

**为什么需要：**
store 故障（Redis 超时、etcd 分区）期间，攻击者可以**重放**同一 JAR 请求 URI / DPoP proof / actor token。对于单用语义的安全不变量（token-exchange 的 actor_token 不能出两次），一个几秒的故障窗口就是可利用的攻击窗。

---

## 方向五：Policy-as-Code 格式导出（OPA Rego / Cedar Bundle）

**当前状态：**
- `domains/permissions/policy_bundle.go` 已有策略包导出机制
- `cluster.Bus` 支持 `KindAuthzPolicyChange` 广播
- 但输出格式是**自定义 JSON**，非标准策略引擎格式

**为什么需要：**
sidecar/envoy 需要在**本地**评估授权决策。标准策略格式（OPA Rego）允许：
- 边车容器拉取一次 bundle，本地评估
- 与 Istio/Envoy 的 external authorization 插件集成
- 审计策略决策
- 100+ 微服务规模下，authz 从"每请求 RPC"降为"缓存 + 本地 eval"

---
