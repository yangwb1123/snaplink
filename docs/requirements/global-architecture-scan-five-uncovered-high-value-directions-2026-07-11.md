# 全局架构扫描：五项未覆盖的高价值扩展方向

> **分析师角色：** 资深架构师 & 产品经理  
> **日期：** 2026-07-11  
> **扫描范围：**
> - 2241 个 `.go` 源文件（1127 非测试 + 1114 测试文件）
> - 82+ 协议/特性实现（OAuth 2.0/OIDC/SAML/SCIM/CAEP/FAPI/Federation/…）
> - 14 个嵌套 `go.mod` 模块（kms×5, saml, ldap, kerberos, radius, extauthz, redis, kafka, mqtt）
> - 50+ 份已有需求分析文档（`docs/requirements/*.md`）
> - `docs/deferred-backlog.md`（聚合有效缺口清单）
> - `docs/ROADMAP.md` v5.0 + `docs/feature-matrix.md`
> - `AGENTS.md`、`docs/architecture/`、ADRs、`.arch/rules.yaml`
> - Git 最近 30 笔提交记录
>
> **核验协议：** 每项方向通过全代码库 grep 确认**零实现**，并通过 50+ 份历史分析文档的全文关键词反查确认**从未作为独立方向被深度 scope**（标签提及不算）。

---

## 前置声明：项目成熟度审计

经过 50+ 轮扩展分析，SnapLink SSO 的功能完整度已达行业顶级水平。所有主要身份协议、安全防线、产品前端、运维基础设施、质量基建均已落地。

| 维度 | 关键能力 | 评估 |
|---|---|---|
| **协议** | OAuth 2.0 ×7 grants (含 PAR/JAR/JARM/RAR/DPoP/mTLS/PKCE/CIBA/Step-Up/TxToken)、OIDC Core/Discovery/Logout/BCL/FCL/Silent Renewal/JWE、SAML 2.0 SP+IdP+SLO、SCIM 2.0 双向+Push Provisioning、CAEP/SSF 双向、FAPI 2.0、OpenID Federation 1.0、LDAP/Kerberos/RADIUS/WebAuthn/SPIFFE/Workload Identity | ✅ 全面 |
| **存储** | Memory + SQLite(WAL+migrate) + PostgreSQL + Redis(全热路径) + etcd(cluster/registry/signingkeys) + KMS×5 + SAML×4 + LDAP/Kerberos/RADIUS/ext_authz/Kafka/MQTT/Vault Transit | ✅ 全面 |
| **安全** | Anti-enumeration×9、Oracle-leak×10、DPoP/mTLS/JKT/SPIFFE、Break-Glass、FIPS 140-3、Account Lockout、Conditional Access、Anomaly Detection×4、Credential Health、Rate Limiting、CSP L3 | ✅ 全面 |
| **产品** | Hosted Login SPA、Admin Console SPA(全CRUD)、Developer Portal SPA、User Portal(/me)、Consent Store×3、B2B Enterprise Connections、SDK Generation(TS+Python)、MCP Server | ✅ 全面 |
| **运维** | DR Framework(snapshot+RPO/RTO)、Config Hot-reload×7、80+ Metrics+Grafana+Alert×16、Audit Hash-chain(OCSF/CEF/Syslog/Webhook/Kafka)、OTel tracing、k6+Chaos tests、K8s Operator | ✅ 全面 |
| **质量** | Architecture layer import boundaries(强制)、File≤500/Func≤50/Cyclo≤15(强制)、Depth≤3/Fanout≤15(强制)、500+ maintainability tests、CodeQL/Trivy/Dependabot×14 modules、Fuzz×10+、Race CI | ✅ 全面 |

**核心发现：** 经过 50+ 轮分析，项目已不存在"缺失某标准协议"或"缺少某存储后端"这类传统缺口。剩余的高价值方向聚焦于**多异构后端共存下的系统级一致性**、**多租户 SaaS 产品化的最后一公里**、以及**面向未来密码学迁移和生产级可观测性的架构基础设施层**。

---

## 方向一：异构存储后端的事务一致性协调器（Cross-Backend Transaction Consistency Coordinator）

### 类型

架构基础设施 / 数据一致性

### 当前状态

| 检查项 | 结果 |
|---|---|
| 代码实现 | ❌ 不存在 |
| 历史分析覆盖 | ❌ 从未作为独立方向（grep `heterogeneous.*transact\|cross.*store.*transact\|multi.*store.*transact\|distributed.*transact\|transaction.*coordinat\|saga.*pattern\|compensat.*transact` 在 50+ 份历史分析中 **0 命中**） |

### 问题描述

当前系统支持同时使用多个异构存储后端（SQLite + Redis + etcd + cluster bus），但**跨后端的原子操作没有事务保证**。例如：

```
/login 流程（简化）：
1. SQLite: INSERT auth_code (成功)
2. Redis: SET session_data (成功)
3. cluster.Bus: 广播 KindClientChange (失败 → 无声丢失)
→ 结果是：auth_code 存在、session 存在、但客户端缓存不会在 peer 副本上失效
```

更危险的场景：

```
/token/revoke-all 流程：
1. SQLite: DELETE FROM refresh_tokens WHERE user_id = ? (成功, 删除 3 行)
2. Redis: DEL user:{id}:refresh_tokens (成功)
3. cluster.Bus: 广播 KindTokenRevoked (部分 peer 收到，部分超时)
→ 结果：刷新令牌在部分副本上仍然有效 → 令牌复活攻击路径
```

| 操作 | 涉及的后端数量 | 事务保证 | 风险 |
|---|---|---|---|
| `/auth/login` (PKCE) | SQLite(auth_code) + Redis(session) + cluster.Bus | 无协调 | 孤立的 auth_code + 无 session |
| `/token` (refresh) | SQLite(refresh_token) + Redis(cache) + cluster.Bus(revoke) | 无协调 | 旧的 refresh_token 仍可双花 |
| `mintImpersonationSession` | SQLite(session) + Redis(cache) + cluster.Bus + audit | 无协调 | 断链后无审计记录 |
| DCR `/register` | SQLite(client) + Redis(cache) + cluster.Bus × 2 | 无协调 | 客户端缓存不一致 |

### 为什么需要它

1. **数据面安全**：在跨后端的操作中，部分失败导致的不一致是**静默的**——不抛错误、不记日志、不影响当前请求，但会在后续请求中表现为不可复现的 bug（"这个 token 为什么在 region B 还能用？"）。

2. **审计完整性**：`mintImpersonationSession`（break-glass 模仿会话）需要同时写入 SQLite(session)、Redis(cache)、cluster.Bus(通知 peers)、audit(记录事件)。如果 audit 写入失败而其他成功，则 break-glass 会话存在但无审计记录——违反 SOC 2 CC6.1。

3. **多后端架构固有复杂度**：项目已投入大量工程资源构建 SQLite、PostgreSQL、Redis、etcd、Kafka 等后端。**后端越多，跨后端一致性问题越严重**。不解决此问题，每增加一个后端都在扩大隐式不一致面。

### Scope

| 子项 | 描述 | 工作量 | 依赖 |
|---|---|---|---|
| **(a) 一致性需求目录** | 审计所有跨后端操作，按风险等级分类（Critical: token/revoke-all → Best-effort: audit async）。产出「一致性需求矩阵」文档 | S | 无 |
| **(b) Saga 编排 SPI** | `SagaCoordinator`：定义 saga step（`do` + `compensate`）+ 执行器。补偿操作可以是「撤销 SQLite 中的 auth code」或「发 cluster.Bus 撤销通知」 | M | (a) |
| **(c) 关键路径 saga 实现** | 在 `/token/revoke-all`、`mintImpersonationSession`、DCR 注册路径中实现 saga 模式 | L | (b) |
| **(d) 一致性检查哨兵** | 后台守护 goroutine，定期对跨后端的关键数据做一致性检查（如「Redis 中的 session 是否在 SQLite 中有对应记录」），检测到不一致时触发告警 + 自动修复 | M | (a) |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| **补偿操作也失败** | 记录到 `DeadLetterStore`（持久化死信队列），管理员可见 + 自动重试。补偿操作的失败不会阻止当前请求返回成功（避免级联失败） |
| **Saga 超时** | 每个 saga step 有独立超时。超时标记 step 为 `UNCERTAIN`，触发人工介入告警。不自动重试不确定的 step（可能已执行） |
| **幂等性保证** | 每个 step 的 `do` 和 `compensate` 都需要是幂等的。使用操作 ID（`operation_id` UUID）去重 |
| **性能开销** | Saga 编排层的开销应 < 0.5ms/step（仅上下文传递 + 日志，无额外 IO）。检查哨兵的运行频率不可高于 1次/分钟 |

---

## 方向二：租户级功能标志层（Tenant-Level Feature Flag Layer）

### 类型

产品化 / 多租户 SaaS 基础设施

### 当前状态

| 检查项 | 结果 |
|---|---|
| 代码实现 | ❌ 不存在（全局 `FeatureGates` 存在，无 tenant-level override） |
| 历史分析覆盖 | ❌ 从未作为独立方向被 scope（`expansion-edge-cases` 中作为边缘案例提及一次，但无设计/scope） |

### 问题描述

当前架构中，功能开关（FeatureGates）是在**服务器级别**全局生效的：

```go
// interfaces/sso/options_httpstack.go
type FeatureGates struct {
    AdminAPI     *bool  // 全局开关
    WebSPA       *bool
    OIDC         *bool
    CIBA         *bool
    CAEP         *bool
    Federation   *bool
    SelfService  *bool
}
```

所有热加载能力（SIGHUP 7 gates）都是全局的。但现实中：

| 场景 | 全局 gate 的限制 |
|---|---|
| **SaaS 定价分层**：Basic 套餐不能用 CIBA，Enterprise 套餐可用 | 无法按租户控制——要么全员可用，要么全员不可用 |
| **逐步上线**：新 CAEP 功能先在 5% 的 beta 租户中启用 | 无法按租户百分比灰度 |
| **合规差异**：金融行业租户需要关闭 federation（安全合规要求） | 无法按租户单独关闭 |
| **内测功能**：FAPI 2.0 功能只对签署了 NDA 的特定租户开放 | 无法按租户白名单控制 |
| **区域合规**：欧盟租户需要关闭某些功能（数据驻留原因） | 全局 gate 无法感知区域 |

### 为什么需要它

1. **SaaS 商业化的硬前提**：没有租户级功能控制，就无法实现基于套餐的定价分层。这是项目从"可自托管的开源身份平台"走向"可商业化的 SaaS IDaaS"的最大单一产品缺口。

2. **降低发布风险**：灰度功能上线（先对 5% 租户开放 → 观察指标 → 逐步扩大到 100%）显著降低每次发布的风险。没有租户级 flag，所有功能都是"大爆炸"式上线。

3. **与现有能力正交**：全局 FeatureGates + SIGHUP 热加载已为租户级 override 提供了基础设施底座——需要添加的是**覆盖层**（tenant override → 合并到全局 gate），而非替换。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 租户功能标志数据模型** | Tenant 扩展 `FeatureOverrides map[string]*bool`（功能名 → 覆盖值）。`nil` = 使用全局值。存储 SPI 扩展 + SQLite migration + Redis 缓存 | S |
| **(b) 分层标志解析引擎** | `resolveFeatureGate(ctx, gateName string) bool`：先查租户覆盖 → 无则全局 gate → 无则默认 off。所有 `GateOn()` 调用改为通过此解析器 | M |
| **(c) Admin API 扩展** | `GET/PUT /api/v1/admin/tenants/{id}/features`——查看/修改租户功能覆盖。`PATCH` 支持单 flag 修改 | S |
| **(d) Admin Console UI** | 租户详情页增加「Feature Flags」选项卡：列出所有功能及其覆盖状态，管理员可切换 | M |
| **(e) 审计 & 指标** | 每次覆盖变更产生 `tenant_feature_override_updated` audit 事件。`sso_tenant_feature_active{tenant,feature}` 指标 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| **全局门禁关闭，租户覆盖打开** | 租户覆盖遵循**最小权限原则**：全局 OFF 时租户不能覆盖为 ON（否则破坏安全基线）。反之（全局 ON / 租户 OFF）则允许 |
| **热加载与租户覆盖的交互** | SIGHUP 重载全局 gate → 租户覆盖保留不变（只影响未覆盖的租户）。租户覆盖本身就是热生效的（读时检查，无重启） |
| **租户覆盖的传播延迟** | Redis 缓存的租户覆盖 TTL 默认 60s。admin 修改后立即 `InvalidateTenantFeatureCache(tenantID)` 推送到 cluster.Bus |
| **功能不存在时的覆盖设置** | Admin API 在设置覆盖时验证功能名是否存在于已知列表中。未知名 → 400 `unknown_feature` |

---

## 方向三：令牌签发水印与取证溯源（Token Issuance Watermark & Forensic Traceability）

### 类型

安全 / 可观测性 / 合规

### 当前状态

| 检查项 | 结果 |
|---|---|
| 代码实现 | ❌ 不存在（token hash 仅用于 introspection，非嵌入 issuance audit） |
| 历史分析覆盖 | ❌ 水印嵌入概念未曾被 scope（`architect-remaining-horizon` 方向二覆盖了"令牌与会话取证工作台"，那是基于已有 audit 事件的查询工具，**非水印嵌入**） |

### 问题描述

当前系统中，一个 access_token 从签发到使用的路径是：

```
签发（/token）→ 使用者携带 token → 验证（本地 JWT 验签 / introspection）
```

从安全审计角度，存在以下盲区：

| 盲区 | 当前能力 | 缺口 |
|---|---|---|
| 给定一个 access_token，找到它的签发事件 | ❌ token hash 不在 audit 事件中 | 无法从 token 追溯到签发时刻 |
| 检测 token 泄露（同一 token 从两个 IP 使用） | ❌ 无此能力 | token 被窃后无法发现 |
| 分析 token 使用模式（使用了多少 token、从哪些位置） | ⚠️ 有 `/api/v1/admin/token-usage`（按 subject 聚合） | 无法分析单个 token 粒度的使用模式 |
| 合规审计：证明某个 token 确实在某时刻被签发 | ❌ `token_issued` audit 事件包含 `client_id` 和 `scopes`，但不含 `token_hash` | 无法将审计结果与具体 token 关联 |

### Key Idea：在签发时将 token 的水印/指纹嵌入审计事件

不是在 `introspect` 时计算 hash（当前做法），而是在**签发时**计算并存储 token 的 SHA-256 hash（或截断指纹），随 `token_issued` audit 事件一起记录：

```
签发时：SHA-256(token) → token_hash → audit event.metadata.token_hash
验证时：计算 SHA-256(bearer) → 查询 audit（可选）→ 关联到签发事件
```

这**不是**存储完整 token（安全风险），而是存储 hash（不可逆，安全），开箱即得以下能力。

### 为什么需要它

1. **合规审计响应速度**：当安全审计问"6 月 15 日 14:32 的 token `eyJ...` 是谁签发的？"时，当前需要 grep 整个 audit 库寻找 `client_id`/`user_id`/`time` 的组合证据。有了 `token_hash`，这是一个精确的单条查询（`WHERE metadata->>'token_hash' = 'abc...'`），毫秒级，零假阳性。

2. **泄露检测**：可选的审计分析器可以检测**同一 token_hash 在两个不同 IP 或 user-agent 的验证请求**，触发安全告警。这为 anomaly 检测引擎（已有 `domains/anomaly`）提供新的高价值信号。

3. **零额外存储成本**：SHA-256 hash 是固定 32 字节，以 hex 编码为 64 字符存储在 audit event `metadata` 的 JSON blob 中。这对审计表的存储增长几乎无影响（每条 audit event 已经是 200-800 bytes）。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 签发时 hash 嵌入** | 在 `token_issued` audit 事件的 `metadata` 中加入 `token_hash: SHA-256(token)`。涉及所有 grant 类型的签发路径（auth_code, client_creds, refresh, device_code, token_exchange, ciba） | M |
| **(b) 验证时 hash 传播** | 在 DPoP、introspection、userinfo 等消费路径的 audit 事件中加入 `token_hash`。支持跨事件关联 | M |
| **(c) Token 溯源查询 API** | `GET /api/v1/admin/forensics/token?hash=<SHA256>`——返回该 token 的完整生命周期（签发 → refresh 轮换 → 撤销 → 使用记录） | S |
| **(d) 泄露检测分析器** | 新 anomaly detector：在时间窗口内检测同一 `token_hash` 是否被多 IP/UA 使用。初始 shadow mode（仅告警，不阻断） | M |
| **(e) Admin Console 取证视图** | 在管理控制台增加「Token 溯源」页面：输入 token（自动计算 hash）或 hash，显示完整时间线 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| **hash 碰撞** | SHA-256 碰撞概率在可预见范围内可忽略。无需额外处理 |
| **token 已过期/撤销** | 溯源仍返回完整生命周期（包括过期时间、撤销事件）。如果 token 从未在 audit 中出现（极早期版本签发的），返回 `not_found` |
| **隐私：hash 是否构成个人身份信息（PII）** | hash 不可逆，不包含用户身份。可作为非 PII 处理。但建议在 GDPR Art.17 erase 时同时清除对应用户签发的 token hash 记录 |
| **hash 的计算性能** | SHA-256 在 Go 中的软件实现 < 1µs。在签发路径上影响可忽略。如果需要极致的 TPS（>100K/s），可改为截断 hash（前 16 字节） |

---

## 方向四：算法与凭据迁移框架（Algorithm & Credential Migration Framework）

### 类型

架构基础设施 / 安全 / 后量子预备

### 当前状态

| 检查项 | 结果 |
|---|---|
| 代码实现 | ❌ 不存在（有 key rotation 但无跨算法迁移框架） |
| 历史分析覆盖 | ❌ 从未作为独立方向被 scope（`expansion-systemic-quality-horizon` 方向一覆盖了二进制升级安全性，非算法迁移） |

### 问题描述

项目支持多种签名算法（EdDSA/ES256/ES384/ES512/RS256/PS256/PS384/PS512），且每种算法有对应的 JWT issuer 实现（`defaultimpl/ed25519_jwt_issuer.go`、`ecdsa_jwt_issuer.go`、`rsa_jwt_issuer.go`）。密钥轮换（`RotateKey`/`RetireKey`）支持同算法内的 overlap window。

但**跨算法迁徙**——例如从 Ed25519 切换到 ES256，或从现在算法迁移到后量子算法（ML-DSA/SLH-DSA）——没有形式化的框架：

| 场景 | 当前支持 | 缺口 |
|---|---|---|
| **同算法密钥轮换**（Ed25519 key A → Ed25519 key B） | ✅ `RotateKey` + overlap window + bus broadcast | 完整 |
| **跨算法迁移**（Ed25519 → ES256） | ❌ `RotateKey` 假设同算法类型 | 需要同时切换 JWK kty 参数、验证路径、客户端缓存 |
| **跨后端密钥迁移**（本地 Ed25519 → AWS KMS ECDSA） | ❌ 需要替换整个 issuer + 重建所有 session | 无过渡路径 |
| **后量子预备**（RSA/ECDSA → ML-DSA） | ❌ 无任何实现 | 2030 CNSA 2.0 要求 |
| **算法降级检测**（旧算法 token 在新配置下被拒绝） | ❌ 无提示 | 静默拒绝已有 token |

### 为什么需要它

1. **后量子密码学（PQC）迁移已经启动**：NIST 于 2024 年 8 月最终确定 FIPS 204（ML-DSA）和 FIPS 205（SLH-DSA）。CNSA 2.0 要求 2030 年前完成迁移。**金融机构和政府部门已经开始在采购 RFI 中要求 PQC 迁移路径。** 如果没有框架，届时每个算法迁移都是紧急的特事特办。

2. **零信任渐进迁移是唯一可行路径**：在生产 SSO 中，"在某一天切换所有 token 的签名算法"是不可能的——所有现有 token 需要在过渡期内保持可验证。一个形式化的框架确保：
   - 旧算法 token 在过渡期内继续可验证
   - 新签发的 token 使用新算法
   - 有一个可度量的"迁移完成"标准（旧算法 token 全部过期/撤销）

3. **降低每次迁移的操作风险**：每次手动算法切换都引入人为错误风险（配置错误 → 证书验证失败 → 生产中断）。框架将迁移包装为可重复、可验证、可审计的过程。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 算法迁移状态机** | `AlgMigrationState`：`PhasePlanning → PhaseDualWriteVerify → PhaseRollingIssue → PhaseDrainOld → PhaseComplete`。状态转换由操作员通过 API 控制 | M |
| **(b) 复合签发器** | `CompositeIssuer` 实现 `core.TokenIssuer`：持有一个签发器列表，按优先级选择用于签发，所有注册的签发器的公钥都出现在 JWKS 中（用于验证） | L |
| **(c) JWKS 算法注释** | JWKS 响应中为每个 key 添加 `alg_migration: "primary" | "secondary" | "draining"` 属性。帮助客户端理解迁移状态 | S |
| **(d) 迁移验证 CLI** | `sso-ctl migrate algorithm --from Ed25519 --to ML-DSA-65`——创建迁移计划、在 dry-run 模式验证、收集现有 token 的算法分布统计 | M |
| **(e) 迁移审计事件** | `algorithm_migration_phase_changed`、`token_signed_with_legacy_algorithm`（可配置告警阈值）、`migration_completed` | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| **迁移过程中回滚** | `PhaseDualWriteVerify` 期间：签发器列表保留旧算法第一优先级，新旧算法的 token 都有效。回滚只需移除新算法签发器 |
| **旧算法 token 在 drain 阶段后仍存活** | `PhaseDrainOld` 持续到最后一个旧算法 token 过期。设置 `MaxLegacyTokenTTL` 告警：如果超过该时间仍有旧算法 token 活跃，触发审计告警 |
| **KMS 不支持新算法** | `CompositeIssuer` 只注册支持的签发器。不支持的算法在迁移计划验证阶段就失败 |
| **客户端缓存中的旧 JWKS** | 迁移应在 JWKS 的 `Cache-Control` TTL 内逐步推进。推荐 `max-age=300`（5分钟），确保算法切换后客户端的 key 信息在 5 分钟内生效 |

---

## 方向五：统一依赖健康图谱与降级传播仪表盘（Unified Dependency Health Graph & Degradation Propagation Dashboard）

### 类型

运维可观测性 / 生产基础设施

### 当前状态

| 检查项 | 结果 |
|---|---|
| 代码实现 | ❌ 不存在（各组件独立 health check，无统一图谱） |
| 历史分析覆盖 | ❌ 从未作为独立方向被 scope（`senior-architect-expansion-v7` 在云 IAM 上下文中提及"health 图谱"一次，非独立方向） |

### 问题描述

项目拥有丰富的健康检查基础设施：

```
/readyz → 检查每个后端的 readiness（SQLite、Redis、KMS、signing keys、rate limit、…）
/metrics → 80+ Prometheus 指标
每个 backend 有自己的健康逻辑
```

但在复杂的多后端、多副本部署中，存在可观测性的**系统性盲区**：

| 场景 | 当前体验 | 期望体验 |
|---|---|---|
| KMS 开始限流 | `/readyz` 仍然 200（KMS 可用但慢），p99 从 5ms 升到 500ms | 仪表盘高亮 KMS 健康从绿变黄，「签名器延迟」红线上升 |
| Redis 连接池耗尽 | `/token` 端点开始返回 503，但 `/readyz` 仍为 200 | 仪表盘显示 Redis 依赖路径红色，显示「连接池使用率 100%」，关联所有受影响的端点 |
| SQLite WAL 检查点阻塞 | userinfo 延迟飙升，但 root cause 是 SQLite 写路径 | Dashboard 显示 SQLite → 写路径红色，标记「WAL 检查点等待」，关联链式影响：SQLite → SessionStore → /userinfo |
| 集群 peer 副本降级 | `signing_key_aggregation` 标记 degraded | Dashboard 显示 peer-replica 依赖线从绿变黄，标注降级原因「peer B 30s 无心跳」 |

### 为什么需要它

1. **降低平均故障恢复时间（MTTR）**：当系统出现性能退化时，运营团队面临的核心问题是"哪个组件是根因"而不是"哪个组件在报错"。统一依赖图谱将**依赖关系可视化**，使降级传播路径一目了然。

2. **降级事件的关联分析**：当前每个组件独立发出告警（"signing key aggregation degraded"、"KMS latency high"、"rate limiting engaged"），但运营人员需要手动关联这些告警以理解因果关系。依赖图谱提供结构化的关联分析。

3. **后端的可观测性需要"后端"**：项目已有 80+ 指标和 16 条告警规则，但缺少的是**将这些指标转化为结构化依赖关系的视图**。指标告诉你"什么"（Redis latency 200ms），图谱告诉你"所以呢"（→ AuthCodeStore 读写慢 → /token 延迟增加）。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 依赖声明 SPI** | 每个子系统声明其依赖关系（提供方 + 消费方 + 健康指标源）。声明式 YAML + 代码注册两种方式 | M |
| **(b) 健康探测聚合器** | 后台 goroutine 定期聚合所有依赖的健康状态。支持健康衰减（degraded 持续 > 30s → 红色） | M |
| **(c) 降级传播分析引擎** | 当依赖 B 降级时，自动找出所有依赖 B 的上游组件，计算受影响面。传播路径可追踪到具体的 API 端点和租户 | L |
| **(d) 运营仪表盘 API** | `GET /api/v1/admin/health/graph`——返回 DAG 格式的依赖健康图谱（节点 + 边 + 健康颜色）。`GET /api/v1/admin/health/graph/propagation?node=kms`——展示 KMS 降级的影响范围 | M |
| **(e) Admin Console 健康图谱页** | 在管理控制台增加「依赖健康」页：交互式 DAG 图，红色/黄色/绿色节点，可缩放/点击查看详情 | L |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| **健康探测本身不可用** | 健康聚合器有独立的超时和断路器。聚合器本身不可用时，最后已知的健康状态保留 30s，然后标记为 `unknown`（灰色） |
| **循环依赖** | 依赖图谱在注册时检测循环依赖，拒绝注册。健康传播时使用拓扑排序，确保不陷入无限循环 |
| **大规模部署的图谱大小** | 默认只展示有健康状态变化的活跃节点。提供「展开所有节点」选项。API 支持按层过滤（只展示存储层 / 只展示网络层） |
| **与现有告警的关系** | 健康图谱是告警的**补充**而非替代。告警告诉你「出事了」，图谱告诉你「哪里出了问题以及为什么」。两者使用相同的健康数据源 |

---

## 执行建议与排序

```
First Wave (P0, 2-3 sprints)
├── 方向二：租户级功能标志 —— 最小 API（a+b+c）可在 2 sprints 内交付
│   └── 直接解锁 SaaS 定价分层 + 灰度发布能力
│
├── 方向三：令牌水印 —— 嵌入 audit 事件（a）可在 1 sprint 内交付
│   └── 零额外存储成本，开箱即得溯源能力
│
Second Wave (P1, 3-5 sprints)
├── 方向一：事务一致性协调器 —— 先目录（a）再 saga（b）再关键路径（c）
│   └── 解决多后端架构的根本性一致性问题
│
├── 方向四：算法迁移框架 —— 先复合签发器（b）再状态机（a）
│   └── PQC 预备 + 降低每次算法切换的操作风险
│
Third Wave (P2, 4-6 sprints)
└── 方向五：依赖健康图谱 —— 先 SPI（a）再聚合器（b）再传播引擎（c）
    └── 最大价值在对现有 80+ 指标 + 16 告警的重组织利用
```

**核心原则**：
1. 方向二和方向三直接提升产品可销售性和安全合规价值，建议 Wave 1
2. 方向一和方向四是基础设施级投资，与 Wave 1 方向无阻塞依赖，可并行
3. 方向五最独立，适合在 Wave 3 或与其他方向并行推进

---

*本报告通过全代码库（2241 个 .go 文件）逐项 grep 验证 + 50+ 份历史分析文档的全文关键词反查交叉验证，确保每一项均为代码级真实缺口且从未作为独立方向被深度分析。*
