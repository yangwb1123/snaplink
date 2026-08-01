# 高价值扩展方向 —— 架构缺口与生产纵深

> **视角：** 资深架构 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库全局扫描（2242+ `.go` 文件、200+ 包、14 个 `go.mod`、4 个嵌入 SPA）。  
> 前置阅读：ROADMAP v5.0、deferred-backlog、feature-matrix、AGENTS.md、EAR.md、  
> docs/requirements/ 下全部已有分析文档（v1–v13、novel*、edge-cases、gaps-analysis、  
> production-hardening、systemic-quality、ciam-identity-horizon、next-wave、  
> senior-architect 等）。对每个方向做全代码库 grep 逐项核验 + 历史文档关键词交叉验证。  
> **定位：** 聚焦于已有 23+ 轮分析未覆盖的剩余高价值缺口。

---

## 前置声明

经过 23+ 轮全局扫描与大量落地实现，本项目的能力覆盖面已达到行业极高水平。  
以下领域已确认**全部覆盖**，本报告不再重复：

| 领域 | 状态 |
|---|---|
| **协议面**（OAuth 2.0 × 7 grants + PAR/JAR/JARM/RAR, OIDC Core/Discovery/Logout/BCL/FCL/CIBA/Form Post/JARM, SAML 2.0 SP+IdP, SCIM 2.0 双向, CAEP/SSF 双向, FAPI 2.0, OpenID Federation 1.0, LDAP, Kerberos, RADIUS, Transaction Token, Step-Up Auth, DPoP, mTLS, SPIFFE JWT-SVID） | ✅ 全部落地 |
| **存储面**（Memory, SQLite, Redis, etcd, PostgreSQL + 14 个嵌套子模块：KMS×5, SAML×4, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT, Vault Transit） | ✅ 全部落地 |
| **安全面**（Anti-enumeration, Oracle-leak, DPoP, mTLS, JWT-SVID, Workload Identity, Break-Glass, Per-tenant 签名隔离, 区域数据驻留, FIPS 140-3, 会话信任衰减, Step-Up Auth, Account Lockout） | ✅ 全部落地 |
| **产品面**（Hosted Login SPA, Admin Console SPA, Developer Portal SPA, User Portal `/me`, Consent Store, B2B Connections + HRD, Org-admin self-service, API docs viewer, SDK 生成 TS + Python, MCP Server） | ✅ 全部落地 |
| **运维面**（DR framework Snapshot/RPO/RTO, Config hot-reload, Metrics/Prometheus/Grafana, Audit hash-chain + OCSF/CEF/Syslog, pprof, k6 load test, Chaos tests, Benchmark gate, Bare-metal HA） | ✅ 全部落地 |
| **韧性面**（Coordinated Key Rotation, Leaderless Peer-Key Adoption, Cross-Replica Revocation, Circuit Breaker, Active-Active, SLO Framework） | ✅ 已分析待落地 |
| **前沿面**（PQC, CIAM/Social Login, Session Roaming, PAM, Developer API Key, Token Status List, FIDO2 Cross-Device, AI Agent Identity, ML Risk Pipeline, Claims Pipeline, Privacy Infrastructure） | ✅ 已分析待落地 |

> **结论：** 已有分析套件已深度覆盖了「新增协议特性」、「补后端实现」、「生产硬化」、「产品面」、「系统性质量纵深」和「前沿方向」——项目在这些维度的覆盖面已接近行业上限。
>
> 本报告 5 个方向聚焦于**所有已有分析均未触及的剩余高价值缺口**，全为代码级实证。

---

## 方向一：密钥管理服务（KMS）高可用与跨提供商故障切换框架

> **全代码库 + 全文档交叉核验：零已有分析覆盖。**

### 现状

项目支持 **5 个 KMS 后端**（AWS KMS、GCP KMS、Azure Key Vault、PKCS#11、HashiCorp Vault Transit）加上 3 个软件签发器（Ed25519/ECDSA/RSA），每个**作为独立、互斥的签发端点启用**：

```
infrastructure/kms/awskms/           # AWS KMS
infrastructure/kms/gcpkms/           # GCP Cloud KMS
infrastructure/kms/azurekeyvault/    # Azure Key Vault
infrastructure/kms/pkcs11/           # PKCS#11 (HSM)
defaultimpl/vaulttransit/            # Vault Transit
defaultimpl/{ed25519,ecdsa,rsa}_*    # Software signers
```

然而：

- **无故障切换（Failover）**——如果配置的 KMS 不可用（AWS KMS 限流、GCP KMS 区域中断、网络分区），签发器简单地返回错误，token 签发停止
- **无降级回退（Degraded Fallback）**——没有机制在 KMS 不可用时自动降级到软件签发（具有适当的告警和审计跟踪）
- **无复合/链式签发（Composite/Chained Signing）**——没有「主 KMS → 备用 KMS → 软件签发」的签发链配置
- **无 KMS 健康探针**——没有针对 KMS 签发的专用 `/readyz` 检查（目前 readiness 只检查聚合循环）

**grep 实证：**

| 概念 | 代码命中 | 状态 |
|---|---|---|
| `kms.*failover\|kms.*fallback\|kms.*backup` | **0** | 零实现 |
| `signer.*chain\|signer.*composite\|signer.*fallback` | **0** | 零实现 |
| `multi.*kms\|kms.*multi\|kms.*ha\|kms.*high.*avail` | **0** | 零实现 |
| `WithKMSFallback\|WithCompositeSigner\|WithKMSHealthCheck` | **0** | 零实现 |

### 为什么需要它

1. **KMS 是单点故障**：无论应用层的高可用做得多么完善，KMS 不可用 = 无法签发 token = 所有新认证失败。对于生产中的 SSO 服务，这是最危险的单点故障之一。
2. **多云战略需求**：采取多云战略的组织希望避免单个 KMS 提供商的锁定。AWS KMS → GCP KMS → 本地 HSM 的故障切换链是实际采购需求。
3. **区域性故障**：云 KMS 是区域性的（us-east-1 的 KMS 中断不影响 eu-west-1）。跨区域故障切换应当是自动化的，不依赖人工干预。
4. **审计要求**：故障切换事件必须有清晰的审计记录——什么时间、为什么故障切换、签发的 token 用了哪个 KMS——以满足合规需求。

### 范围

| 层次 | 组件 | 说明 |
|---|---|---|
| **SPI** | `KMSHealthChecker` / `SignerChain` | `SignerChain` 编排有序的签发器列表，按优先级尝试，故障时降级。每次降级/恢复产生 `kms_failover` 审计事件 |
| **实现** | `CompositeSigner` | 实现 `core.TokenIssuer` + `core.JWK`，包装一个有序签发器列表。配置格式：`signers: [{backend: awskms, key: alias/sso}, {backend: gcpkms, key: projects/p/locations/l/keyRings/k/cryptoKeys/sso}, {backend: ed25519, key: fallback}]` |
| **观测性** | 指标 + readiness | `sso_kms_signer_status{backend="awskms",status="active\|degraded\|down"}`。`/readyz` 在所有配置的 KMS 后端不可用时标记为不健康 |
| **审计** | 故障切换事件 | `kms_failover_activated` / `kms_failover_recovered` / `kms_fallback_engaged` 事件，包含后端标识符和原因 |

### 边界情况

| 场景 | 处理策略 |
|---|---|
| **所有后端都不可用** | `/readyz` 失败；保留用最后缓存的公钥验证现有 token 的能力（不签发新 token） |
| **故障切换抖动** | 故障切换状态有 N 秒的冷却期（debounce），避免 KMS 短暂限流时反复切换 |
| **跨 KMS 的 key 不一致** | 每个签发器维护自己的 kid 命名空间；CompositeSigner 在 JWKS 中发布所有活跃签发器的公钥 |
| **软件降级的安全性** | 软件降级必须显式配置（默认 off），降级时签发 `alg` 加 `_fallback` 标签，以便下游验签器区分 |
| **回切（Fallback → Primary）** | Primary KMS 恢复后，CompositeSigner 自动回切；在冷却期内已发出的 token 用降级 key 签发，直到正常轮换 |

### 价值 · 工作量

- **价值：** **high**（消除 KMS SPOF；多云采购的硬性要求；故障切换审计是 SOC2/PCI 常见问题）
- **工作量：** **M**（SPI + CompositeSigner + 健康探针 + 指标，约 2-3 周）
- **依赖：** 现有所有 KMS signer 无需改动；CompositeSigner 作为装饰器工作

---

## 方向二：声明式租户即代码与 GitOps 身份基础设施

> **全文档交叉核验：独立方向零覆盖。** 此前分析仅在 grep 结果中记录了「identity-as-code: 零实现」(expansion-five-uncovered-gaps.md) 和「租户 onboarding 为零」(expansion-edge-cases.md)，但从未作为完整的扩展方向进行论述。

### 现状

租户管理完全通过 Admin API 完成（`/api/v1/admin/tenants/*`）。创建租户涉及：

```bash
# 没有声明式 DSL；全为过程式 API 调用
curl -X POST /api/v1/admin/tenants -d '{"slug":"acme","name":"Acme Corp",...}'
curl -X POST /api/v1/admin/tenants/acme/domains -d '{"hostname":"acme.com"}'
curl -X POST /api/v1/admin/connections -d '{"tenant_id":"acme","provider":"saml",...}'
curl -X POST /api/v1/admin/clients -d '{"tenant_id":"acme","client_id":"acme-app",...}'
```

grep 实证：

| 概念 | 代码命中 | 状态 |
|---|---|---|
| `tenant.*declarative\|tenant.*as.*code\|tenant.*manifest` | **0** | 零实现 |
| `tenant.*gitops\|tenant.*yaml\|tenant.*blueprint` | **0** | 零实现 |
| `tenant.*quickstart\|tenant.*onboard.*flow\|tenant.*bootstrap.*flow` | **0** | 零实现 |
| `tenant.*template.*provision\|org.*catalog\|org.*template` | **0** | 零实现 |

### 为什么需要它

1. **多租户 SaaS 运营**：对于运行多租户 SSO 的 SaaS 提供商，每个新客户入职都涉及创建租户→配置域名→配置 IdP 连接→创建客户端→设置权限→配置品牌。没有声明式的「租户清单」，这个过程无法版本控制、代码审查或自动化。
2. **GitOps 工作流**：身份基础设施（租户、客户端、策略、连接）应当与基础设施即代码（IaC）对齐。租户 `tenants.yaml` 可以提交到 Git，由 CI 验证，由 operator 自动 apply。
3. **环境复制**：开发/预发布/生产环境的身份配置需要保持同步。声明式规范使得环境间的差异可审计、可对比、可迁移。
4. **合规审计**：谁在什么时候修改了哪个租户的什么配置？声明式规范 + Git 历史提供了内置的变更审计跟踪。

### 范围

| 层次 | 组件 | 说明 |
|---|---|---|
| **规范** | `TenantSpec` YAML schema | 声明式租户规范，包含 slug、name、domains、connections、clients、branding、security_policy、allowed_regions、token_policy 等。支持 `$schema` 验证 |
| **引擎** | `TenantReconciler` | 读入 `TenantSpec`，通过现有的 Admin API 协调到目标状态。支持 create/update/delete 并通过 diff 输出计划 |
| **CLI 工具** | `sso-ctl tenant apply -f tenants.yaml` | 基于文件的声明式租户管理。支持 `-dry-run`（输出计划而不执行）、`-diff`（对比当前状态与期望状态） |
| **GitOps 集成** | 环境清单 + 验证 | `sso-ctl tenant validate -f tenants.yaml`（仅验证 schema + 引用完整性，不连接服务器）；`sso-ctl tenant diff --server`（服务器端对比） |

### 边界情况

| 场景 | 处理策略 |
|---|---|
| **状态偏离（Drift）** | reconciler 运行时检测漂移并报告差异；不自动回滚（operator 检查 diff 后确认 apply） |
| **部分失败** | reconciler 是幂等的；失败时回滚到上一个一致状态，并通过 `--dry-run` 重试 |
| **引用完整性** | 客户端引用了不存在的连接 → validate 阶段拒绝。删除租户时 cascading delete 或 block（取决于 `cascade: true\|false`） |
| **并发修改** | reconciler 对比期望状态时检测到服务器端并发修改则中止（返回 diff），operator 重新 run |
| **大租户** | reconciler 对每个资源类型做分页；支持 `--parallel` 选项 |

### 价值 · 工作量

- **价值：** **high**（多租户 SaaS 提供商的核心运营能力；GitOps 合规）
- **工作量：** **L**（TenantSpec schema + reconciler + CLI + validation，约 3-4 周）
- **依赖：** 现有 Admin API 完全覆盖协调目标；reconciler 只消费已存在的 API

---

## 方向三：上游身份提供商故障切换与联合认证高可用

> **全代码库 + 全文档交叉核验：零已有分析覆盖。**

### 现状

项目支持丰富的入站联合认证（SAML IdP、SP、OIDC Federation、LDAP、Kerberos），但每个联合提供商**作为单点配置**：

- SAML IdP 连接绑定到单个 `EntityID` + `MetadataURL`
- OIDC Federation 使用 `Issuer` 的单一 JWKS URL
- LDAP 配置指向单个服务器主机+端口
- Kerberos 使用单个 KDC 配置

当上游 IdP 不可用时（Okta 中断、ADFS 重启、LDAP 连接超时）：

- 当前行为：`POST /auth/login` 返回错误，用户无法登录
- **无故障切换**：没有备用 IdP、缓存断言、或降级认证方式
- **无健康探针**：没有对上游联合端点的 `/readyz` 级健康检查
- **无自动降级**：没有「SAML IdP 不可用 → 临时允许密码认证 + 审计告警」的策略

**grep 实证：**

| 概念 | 代码命中 | 状态 |
|---|---|---|
| `idp.*failover\|idp.*fallback\|idp.*ha\|idp.*high.*avail` | **0** | 零实现 |
| `provider.*failover\|provider.*fallback\|provider.*chain` | **0** | 零实现 |
| `upstream.*health.*check\|federation.*health.*probe` | **0** | 零实现 |
| `WithIdPFailover\|WithFederationFallback\|IdPHealthChecker` | **0** | 零实现 |

### 为什么需要它

1. **企业 SSO 的核心可靠性**：联合认证是 B2B SSO 的核心能力。当客户的 IdP 宕机时，用户无法访问任何与你 SSO 集成的应用程序——这是直接影响业务连续性的问题。
2. **IdP 冗余是采购要求**：大型企业在采购 SSO 平台时，会要求「上游 IdP 高可用」作为标配。支持多个上游 IdP 实例（主/备）或 IdP 链（尝试第一个，失败时尝试第二个）是 RFP 常见条目。
3. **降级认证策略**：当主 IdP 不可用时，运营者可以选择允许降级（例如，临时允许密码认证 + 记账，或允许缓存的上次认证成功断言在 N 分钟内有效）。
4. **迁移过渡**：在 IdP 迁移期间（从 Okta 迁移到 Azure AD），双运行模式要求两个 IdP 同时活跃并由一个策略决定优先顺序。

### 范围

| 层次 | 组件 | 说明 |
|---|---|---|
| **SPI** | `FederatedProviderGroup` | 一组有序的联合提供商，按优先级尝试。包装现有的 `core.Authenticator`，尝试每个提供商直到成功或全部失败 |
| **策略** | 故障切换策略 | `try_all`（顺序尝试）、`failover_on_error`（识别特定错误后切换）、`latency_based`（基于历史响应时间选择） |
| **健康探针** | 上游健康检查 | 定期探测上游 IdP 的元数据端点/JWKS URL/SOAP 端点，将健康状况暴露为指标。失败时触发 readiness 降级 |
| **降级缓存** | 缓存断言 | 在 IdP 不可用时，允许使用上次成功认证的缓存断言在 N 分钟内登录（必须显式配置、默认 off、带审计告警） |

### 边界情况

| 场景 | 处理策略 |
|---|---|
| **部分失败（SAML IdP 活着的 HTTP 响应但 SOAP 响应错误）** | 健康探针使用语义探测（完整的 SAML 元数据获取 + 签名验证），不只是 TCP 连接 |
| **故障切换期间的会话一致性** | 切换 IdP 后现有会话保持有效；只影响切换后的新认证 |
| **路由标识冲突** | 两个 IdP 可能标识同一用户不同的 `NameID` → 需要身份关联层（复用现有 `domains/identitylink`） |
| **降级认证的安全风险** | 降级必须显式配置（default-off），每次降级认证产生 `auth_degraded_failover` 审计事件，推荐同时要求 MFA |
| **多个租户不同 IdP HA 策略** | IdP 组在连接级别配置（per-tenant `EnterpriseConnection`），每个租户可以有独立的故障切换策略 |

### 价值 · 工作量

- **价值：** **high**（企业采购 RFP 常见项；直接影响登录可用性；迁移场景必须）
- **工作量：** **M**（ProviderGroup + 健康探针 + 降级缓存，约 2-3 周）
- **依赖：** 现有 `domains/connections` + `interfaces/admin/connections.go` 提供天然扩展点

---

## 方向四：跨协议会话枢纽产品化与面向用户/管理的会话管理

> **全文档交叉核验：独立方向零覆盖。** 会话枢纽作为技术组件存在于 `platform/lifecycle/sessionhub/`，但从未被产品化——没有面向用户或管理员的全协议会话视图、没有跨协议单点登出产品功能、没有会话健康仪表盘。

### 现状

`platform/lifecycle/sessionhub/` 实现了一个跨协议会话协调器（global_sid），用于在 SAML 和 OAuth/OIDC 会话之间桥接。但是它：

- **纯后端 SPI**：没有暴露给 `/me/sessions`（用户门户）或 Admin Console
- **协议覆盖不完整**：SAML 有 global_sid 桥接，但 WebAuthn、LDAP、Kerberos 会话未接入
- **无管理界面**：管理员无法查看「用户 X 在所有协议中的所有活跃会话」
- **无会话健康数据**：没有每个会话的信任评分、最后使用时间、设备信息、IP 历史

**grep 实证：**

| 概念 | 代码命中 | 状态 |
|---|---|---|
| `session.*roam\|session.*cross.*device\|session.*transfer` | **0** | 零实现（技术上 session hub 存在但未产品化） |
| `session.*sync.*user\|user.*session.*view\|unified.*session.*view` | **0** | 零实现 |
| `cross.*protocol.*logout\|global.*session.*manage` | **0** | 零实现 |
| `session.*health.*score\|session.*trust.*dashboard` | **0** | 零实现 |

### 为什么需要它

1. **用户自我修复**：当用户怀疑账户被盗用时，第一反应是查看「哪里登录了我的账户」并登出可疑设备。这是 Auth0/Okta/Microsoft Entra 的基本功能。
2. **安全分析师工作效率**：调查身份事件时，分析师需要「这个用户在所有协议中登录了哪些会话」的统一视图——而不是分别在 OAuth session manager、SAML session index、LDAP bind 中查询。
3. **跨协议登出的完整性**：通过 SAML 登录的用户可能同时有 OAuth 会话。当用户登出或管理员强制登出时，应当跨所有协议生效。
4. **信任衰减的产品化**：项目已经实现了会话信任衰减技术（`shared/trust`），但没有任何前端展示当前信任评分、设备信息、最近活动给最终用户或管理员。

### 范围

| 层次 | 组件 | 说明 |
|---|---|---|
| **用户 API** | `GET /me/sessions` | 返回当前用户所有协议的所有活跃会话列表（OAuth session、SAML SP session、WebAuthn、LDAP bind），包含设备信息、创建时间、最后使用时间、IP、信任评分 |
| **用户操作** | `DELETE /me/sessions/:id` | 登出指定会话（跨协议：如果它是 SAML SP session，同时登出关联的 OAuth 会话） |
| **管理员 API** | `GET /api/v1/admin/users/:id/sessions` | 管理员视角的跨协议会话列表，含强制登出操作 |
| **会话健康** | 信任评分 + 指标 | 每个会话的 `sso_session_trust_score` 指标 + admin 仪表盘上的「会话健康分布」面板 |
| **全局登出** | 跨协议 SLO | `POST /token/revoke-all`（现有）扩展为同时清除 SAML SP session index 和 WebAuthn 凭证（存在 session hub 时） |

### 边界情况

| 场景 | 处理策略 |
|---|---|
| **大量会话的用户** | 分页 API + 可选的 `active_within` 过滤器；后台异步清除过期会话 |
| **跨协议会话关联失败** | session hub bridge 返回 error 时，对已关联的协议执行登出，未关联的部分记录审计事件 `global_logout_partial` |
| **登录页面看不到 session hub** | 登录路径注入 global_sid 到创建的 session 对象中（当前 OAuth session 需要增字段；SAML 已有） |
| **管理员的跨租户查看** | 管理员 `admin:read.global` 可跨租户查看；`admin:read.tenant.{tid}` 只能看本租户 |
| **会话信任评分波动** | 评分在用户 API 中表示为分类（low/medium/high）而非原始分，以避免攻击者猜测评分算法 |

### 价值 · 工作量

- **价值：** **medium-high**（用户体验改进 + 安全分析师效率 + 自我修复能力）
- **工作量：** **M**（User API + Admin API + SPA 集成 + cross-protocol SLO 扩展，约 3 周）
- **依赖：** Session hub 已存在并连接 OAuth + SAML；需要将 WebAuthn/LDAP/Kerberos session 也接入 hub

---

## 方向五：联合认证提供商健康与治理框架

> **全代码库 + 全文档交叉核验：独立方向零覆盖。** 此前分析覆盖了单个 IdP 的配置、conditional access、连接健康探测（`domains/connections/health`），但从未系统地考虑多提供商联合治理——即运行期所有联合提供商的健康聚合、认证成功率趋势、证书轮换预测、与提供商发现/元数据配置治理。

### 现状

项目拥有覆盖广泛的联合认证能力：

| 联合方式 | 后端 |
|---|---|
| SAML 2.0 SP | `infrastructure/saml/sp/` |
| SAML 2.0 IdP | `infrastructure/saml/idp/` |
| OIDC 联合 | `domains/authenticators/oidc_federation.go` |
| OpenID Federation 1.0 | `domains/federation/` |
| LDAP | `infrastructure/ldap/` |
| Kerberos | `infrastructure/kerberos/` |

但：

- **无提供商健康聚合**：每个联合提供商独立运行，无整体健康状态面板
- **无认证成功率趋势**：不知道哪个上游 IdP 的失败率在上升（用户误输 vs IdP 宕机）
- **无证书轮换预测**：SAML 签名证书过期无预警；无「证书将在 30 天内过期」的告警
- **无元数据配置治理**：SAML 元数据更新无版本控制；变更无审批流程；回滚困难
- **无提供商发现的可观测性**：每个联合登录涉及多少次重定向、DNS 查找、签名验证——这些延迟无追踪

**grep 实证：**

| 概念 | 代码 | 状态 |
|---|---|---|
| `provider.*health.*dashboard\|provider.*status.*page\|federation.*status` | **0** | 零实现 |
| `cert.*expir\|cert.*forecast\|metadata.*expir\|metadata.*fresh` | SAML IdP/SP 有基本的单个证书检查 | 但无聚合面板和预警 |
| `federation.*latency\|auth.*provider.*latency\|provider.*response.*time` | **0** | 零实现 |
| `provider.*success.*rate\|provider.*failure.*rate\|provider.*uptime` | **0**（`sso_auth_login_total` 按 provider 维度存在，但无 provider 健康面板） | 零实现 |
| `metadata.*govern\|metadata.*version\|metadata.*approval\|metadata.*rollback` | **0** | 零实现 |

### 为什么需要它

1. **运营者盲区**：一个联合 IdP 静默降级（响应慢、间歇性失败、证书即将过期）而 `/readyz` 依然绿色——这是最常见的运营盲区之一。主 IdP 的长期缓慢降级可能经过数周才被发现。
2. **上游依赖可视性**：SSO 的可用性直接依赖于上游 IdP 的可用性。运营者需要在一处看到所有上游提供商的状态——类似「Status Page」但针对身份提供商。
3. **证书/元数据生命周期管理**：SAML 证书过期是 SSO 故障的最常见原因之一。提前 30/60/90 天的自动预警是运营刚需。提供元数据版本控制和变更审批流程可防止错误配置导致的中断。
4. **认证性能基准**：LDAP 的 `bind` 延迟、SAML 的断言解析时间、OIDC 的 token 交换时间——这些性能指标帮助运营者识别退化趋势并规划容量。

### 范围

| 层次 | 组件 | 说明 |
|---|---|---|
| **健康聚合** | Provider Health Registry | 运行期聚合所有配置的联合提供商（SAML SP/IdP、OIDC Federation、LDAP、Kerberos）的健康状态。每个提供商暴露：状态（up/degraded/down）、最近一次健康检查时间、失败率（1h/24h/7d）、平均响应时间 |
| **证书预警** | 证书到期日历 | `sso-ctl` 命令检索所有配置的 SAML 签名/加密证书到期时间 + admin API `GET /api/v1/admin/provider-certificates` 返回到期列表和预警阈值 |
| **元数据治理** | SAML 元数据版本管理 | `POST /api/v1/admin/connections/:id/metadata` 更新元数据时保留历史版本；`GET .../metadata/versions` 列出版本；`POST .../metadata/rollback` 回滚；每次变更产生 `connection_metadata_updated` 审计事件 |
| **运维面板** | 提供商状态页 | Admin Console 新增「Provider Health」页，展示所有联合提供商的状态、失败率、响应时间、证书到期日历。支持按 tenant 过滤 |

### 边界情况

| 场景 | 处理策略 |
|---|---|
| **提供商被配置但从未使用** | 健康状态为 `inactive`；不参与失败率统计 |
| **健康探测增加配置的提供商对上游的负载** | 探测间隔可配置（默认 5m）；一次性探测获取元数据或做轻量 `fetch` 而非完整 SSO 握手 |
| **SAML 元数据内容变化签名验证失败** | `POST .../metadata` 验证新元数据的签名（如果原始元数据有签名）；验证失败则拒绝 |
| **证书即将到期但提供商无法联系** | 告警在到期前 30 天发出；即使无法做健康探测，仍根据上次获取的证书元数据计算到期时间 |
| **大量租户大量提供商的面板性能** | 分页 + 聚合（只返回状态汇总，详细指标鼠标悬浮查看） |

### 价值 · 工作量

- **价值：** **medium-high**（运营者盲区的封闭；证书过期是 SSO 故障 #1 原因；上游可观测性）
- **工作量：** **M**（健康聚合 + 证书面板 + 元数据版本管理，约 2-3 周）
- **依赖：** 现有 `domains/connections/health`（active health probing）+ `domains/federation/health`（federation health checker）+ `interfaces/admin/connections.go`（CRUD）

---

## 优先级总结

| 方向 | 价值 | 工作量 | 建议优先级 | 核心理由 |
|---|---|---|---|---|
| ① KMS 高可用与故障切换 | **high** | **M** | **P0** | 消除签发路径 SPOF；多云采购刚需；SOC2/PCI 合规常见问题 |
| ② 声明式租户即代码与 GitOps | **high** | **L** | **P1** | 多租户 SaaS 运营核心能力；GitOps 合规；环境可复制性 |
| ③ 上游 IdP 故障切换与 HA | **high** | **M** | **P0** | 直接影响登录可用性；企业 RFP 常见项；IdP 迁移必须 |
| ④ 跨协议会话枢纽产品化 | **medium-high** | **M** | **P2** | 用户体验改进 + 安全分析师效率；可复用现有 session hub |
| ⑤ 提供商健康与治理框架 | **medium-high** | **M** | **P1** | 封闭运营者盲区；证书过期是 SSO 故障 #1 原因 |

### 一句话顺序

**先消除基础设施单点故障（① KMS HA + ③ IdP HA）→ 再建设运营与治理能力（⑤ 健康治理）→ 同时启动面向用户的声明式产品能力（② 租户即代码 + ④ 会话管理）。**
