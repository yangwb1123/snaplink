# 全局架构扫描——此前未曾触及的 5 个扩展方向

> 基于 2026-07-01 全代码库深度扫描（1639 个 `.go` 文件、13 个嵌套模块、3 个嵌入式 SPA、完整 OAuth/OIDC/SAML/FAPI/CAEP/SCIM 协议栈）。
>
> 视角：资深架构师 / 产品经理。此前已有 40+ 方向覆盖了协议扩展、实时基建、Edge Cases、代码健康、架构债务、API 产品化、运营治理、供应链韧性、下一代身份模型等。
>
> **本轮聚焦此前从未被系统审视的 5 个高价值方向。** 每条方向经逐项代码核验 + 与既有 40+ 方向交叉比对，确认为真缺口。
>
> 原则：不写代码。

---

## 总体判断

项目已完成从"身份协议 SDK"到"生产就绪 SSO 平台"再到"下一代身份基础设施"的三级跨越。此前 40+ 方向覆盖了协议完备性、性能优化、运维治理、安全防御、企业功能、架构转型。

**但仍有五个跨度更大的战略盲区此前从未被触及：**

1. **令牌治理与生命周期分析**——如何管理已签发出去的数以亿计的令牌（而非仅治理签发过程）
2. **全凭据自动轮换与密钥管理自动化**——签名键之外的凭据如何自动轮换
3. **零信任架构的统合框架**——离散的 ZT 能力如何整合为可执行的策略引擎
4. **业务连续性 / 灾难恢复框架**——生产跑起来了，但宕机了怎么办
5. **协议级攻击面管控与特性门控**——部署形态不同，攻击面应该不同

---

## 方向一：令牌治理与生命周期分析框架（Token Governance & Lifecycle Analytics）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M-L**（~1500 行核心 + 存储层 + admin UI） |
| 价值 | **极高**（大规模部署的安全与运营基础设施） |
| 类型 | 治理平台 + 安全分析 |
| 覆盖检查 | 此前 40+ 方向均未覆盖此主题 |

### 当前状态验证

代码库拥有极佳的令牌签发与吊销基础设施：

```
签发（TokenIssuer → 5 种 JWT Issuer + opaque token）
  ├── 6 种 grant_type（authorization_code / refresh_token / client_credentials /
  │     device_code / token-exchange / ciba）全覆盖
  ├── JWT（Ed25519 / ECDSA / RSA） + opaque
  └── 所有签发事件写入审计日志

吊销（RevocationStore → /revoke / /revoke-all）
  ├── 跨副本撤销广播（cluster.Bus KindTokenRevoked）
  ├── 撤销集持久化（SQLite / Redis / Postgres / memory）
  └── 所有吊销事件写入审计日志
```

但**从签发到吊销之间，存在一个巨大的运营盲区**：

| 缺失的能力 | 代码搜索证据 | 生产影响 |
|-----------|-------------|---------|
| **令牌使用分析** | `grep "token.*usage\|token.*analytics\|token.*pattern"` → 0 命中 | 无法回答"哪些令牌在被使用？哪些从未用过？哪些 client 在大量请求？" |
| **令牌 TTL 策略引擎** | 当前 TTL 是 `Client.AccessTokenTTL` + issuer 级默认值，无策略层级 | 无法对"高敏感 scope 的 access token"设置更短 TTL，无法做"新 OAuth 2.1 场景下 token 只能刷新一次" |
| **可疑令牌行为检测** | 无基于令牌使用模式的异常检测 | 无法发现"令牌泄漏后被异常 IP 使用"、"单个 token 在 1s 内从 3 个不同国家使用" |
| **令牌休眠检测** | 无——审计日志中发了就发了，从未被分析 | 僵尸令牌永久有效（直到 TTL 过期），泄漏窗口 = token TTL |
| **令牌组合治理** | 无——每个 client 独立签发 token，无法查看"用户 X 当前持有多少活跃令牌" | 安全审计无法回答"用户 X 有多少活跃 session？哪些 client？" |
| **令牌撤销风暴防护** | `RevocationStore` 接受任意多撤销 | 审计场景需要"批量撤销旧 client 的所有令牌"——无干预算力保护 |

### 为什么需要

**这不是一个"好看"的功能——当规模增长到一定阈值，没有令牌治理就是安全事件。**

| 规模维度 | 风险 | 发生条件 |
|---------|------|---------|
| 1 万活跃用户 | 无——人工可管理 | — |
| 10 万活跃用户 | 审计开始困难——管理员无法知道"谁有什么令牌" | 至此阈值 |
| 100 万令牌/天 | 令牌泄漏检测完全依赖受害者报告 | 需要被动检测 → 方向一 |
| 1000 万活跃令牌 | 1% 的令牌泄漏率 → 10 万张令牌可用作攻击 | 需要主动治理 → 方向一 |

**竞品对标**：

| 平台 | 令牌生命周期分析 | 令牌使用监控 | 令牌策略引擎 |
|------|----------------|-------------|-------------|
| Auth0 | ✅ 令牌使用日志 + Dashboard | ✅ 异常令牌检测（Anomaly Detection） | ✅ Hooks + Actions 定制策略 |
| Okta | ✅ System Log API 查询令牌事件 | ✅ 通过 SIEM 集成 | ✅ Okta Workflows |
| Curity | ✅ Token Exchange 审计 | ❌ 依赖外部 SIEM | ✅ Token Policy Engine |
| **Snaplink** | **❌ 仅有原始审计日志，无聚合层** | **❌ 完全缺失** | **❌ 完全缺失** |

### 建议方向

```
Phase 1 (M) — 令牌使用遥测：
  ├── TokenUsageStore SPI        — 记录每次令牌使用的摘要（token_kind, client_id, user_id, timestamp, ip_geo, granted_scopes）
  ├── TokenUsageAggregator       — 分桶聚合（每分钟/每小时/每天）避免写入爆炸
  ├── TokenUsageReader           — admin API 查询接口
  └── platform/metrics/metrics_token.go — Prometheus 指标（active_token_count, token_usage_rate_by_client）

Phase 2 (M) — 令牌策略引擎：
  ├── TokenPolicy SPI            — 基于 token 类型 / client / scope / user 的策略评估
  ├── TokenPolicyStore           — 策略存储（YAML 配置 + 动态）
  ├── 策略类型：
  │   ├── max_ttl                — 针对特定 scope/client 的最大 TTL（覆盖 client 设置）
  │   ├── max_refresh_depth      — refresh token 最大轮换次数（OAuth 2.1 场景）
  │   ├── max_active_sessions    — 每用户/每 client 的并发活跃 session 上限
  │   ├── require_renew          — 令牌使用 N% TTL 后必须 refresh 不能续用
  │   └── block_scope_combos     — 阻止危险 scope 组合（如 admin:* + openid）
  └── 策略评估在签发/验证路径上执行

Phase 3 (L) — 令牌行为检测与治理面板：
  ├── TokenAnomalyDetector       — 基于使用模式检测异常（non-threshold, 基于频率/地理/设备）
  ├── interfaces/web/admin/      — "Token Portfolio" 管理面板
  │   ├── 令牌全景图（总数、分布、使用趋势）
  │   ├── 用户令牌视图（某用户的所有活跃令牌）
  │   ├── 可疑令牌列表（异常使用模式）
  │   └── 批量撤销工作流
  └── 令牌治理报告（PDF/CSV 导出）
```

### Edge Cases

- **遥测本身的写入放大**：每个令牌使用都记录 → 高 QPS 下写入是签发量的 2-3 倍。必须使用异步批量写入 + 分桶聚合，避免影响 `/token` 延迟。
- **令牌使用记录中不含 PII**：token_usage 表不应存 token 值本身，仅存 `token_thumbprint（SHA-256(token_jti)）`，避免成为新的数据泄露面。
- **策略变更对已签发令牌的影响**：如果在令牌签发后收紧策略，已签发的令牌应在 refresh/step-up 时重新评估，而非立即强制过期。
- **多副本下的使用计数一致性**：令牌使用计数在多个副本间是异步写入的（cluster.Bus 不保证严格顺序），聚合器应容忍写入延迟和乱序。

---

## 方向二：全凭据自动轮换与密钥管理自动化（Credential Rotation Automation & Secrets Management）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~600 行核心 + 存储层 + 调度器） |
| 价值 | **高**（运营安全基础——对密码学基础设施的零碎管理进行系统化） |
| 类型 | 运营基础设施 + 安全防御 |
| 覆盖检查 | 此前 40+ 方向覆盖了**签名键轮换**（已有）和**客户端密钥轮换**（手动的 admin RPC），但未覆盖**全凭据类型自动轮换框架** |

### 当前状态验证

```bash
# 签名键轮换 ✅ 已实现
$ grep -rn "RotateKey\|rotate.*key\|KeyRotation" --include="*.go" . | grep -v "_test.go" | wc -l
# → 25+ 处，涵盖 leaderless + 协调轮换

# 客户端密钥轮换 ✅ 已实现（手动的 admin RPC）
$ grep -rn "RotateSecret\|rotate.*secret" --include="*.go" . | grep -v "_test.go" | head -5
# → 通过 admin gRPC CreateOrRotateClientSecret / RotateSecret
# → 是手动的——需 admin 显式调用 API

# 但其他凭据类型完全无轮换：
```

**已覆盖（有轮换）：**
- 签名键（signing keys）—— leaderless + coordinated 双模式 ✅
- 客户端密钥（client_secret）—— 手动的 admin RPC ✅

**未覆盖（无轮换）：**

| 凭据类型 | 存储位置 | 无轮换风险 | 当前手动轮换可行性 |
|---------|---------|-----------|------------------|
| **JWE 解密密钥** | `JWTIssuer.WithJWEDecrypter` | 私钥泄漏 → 可解密所有 JAR 请求和加密的 id_token | ❌ 无 API——需重启更换 |
| **CAEP/SSF webhook 签名密钥** | `caep/transmitter.go` | 签名密钥泄漏 → 可伪造安全事件推送 | ❌ 无 API |
| **Admin bearer token / API key** | `admin_token.go` + `admin.APITokenProvider` | 管理员令牌泄漏 → 完全控制 | ❌ 无 API（只能手动删除重建） |
| **审计哈希链密钥** | `audit/chainer.go` | 密钥泄漏 → 可篡改审计链而不被发现 | ❌ 无轮换机制 |
| **Webhook 接收端 HMAC secret** | `webhook_sink.go` | HMAC secret 泄漏 → 可伪造告警 | ❌ 无 API |
| **SAML IdP 签名密钥** | `saml/idp/assertion_signer.go` | 签名密钥泄漏 → 可伪造 SAML 断言 | ❌ 无 API |
| **SAML SP 解密密钥** | `saml/sp/` | 私钥泄漏 → 可解密 SAML 响应 | ❌ 无 API |
| **OIDC Federation 实体私钥** | `federation/` §8 fetch | 实体私钥泄漏 → 可冒充信任锚 | ❌ 无 API |
| **KMS bridge 认证凭据** | `kms/{awskms,gcpkms,azurekeyvault}` | 云 AK/SK 泄漏 → 云上密钥滥用 | ❌ 依赖云原生凭据轮换 |
| **数据库密码（DSN）** | 环境变量 `SSO_DSN` / `SSO_STORE_*` | 数据库密码泄漏 → 全量数据泄露 | ❌ 无——需停机修改 |

### 为什么需要

1. **凭据轮换是任何安全基础设施的基线要求**。PCI-DSS、SOC2、ISO 27001 明确要求定期轮换密钥和凭据。项目在签名键上做对了，但其他凭据类型被忽视了。

2. **凭据泄漏是数据泄露的头号根因**（Verizon DBIR 2025）。一个 SAML 签名私钥泄漏比一个签名键泄漏更严重——SAML 私钥可伪造任何 SAML 断言，而签名键仅影响自签发的 JWT。

3. **手动轮换无法规模化**。一个中等规模的 SSO 部署可能管理 10+ 种不同的凭据类型，每种的轮换周期（90d / 180d / 1y）不同。手动轮换要么被遗忘，要么在运维 windows 中出错。

4. **已有基础设施可复用**：
   - `interfaces/sso/signing_key_aggregation.go` 的轮换调度器框架
   - `cluster.Bus` 的跨副本广播（`KindSigningKeyRotation`）
   - `interfaces/admin/` 和 `interfaces/grpcserver/` 的 admin API 基础设施

### 建议方向

```
Phase 1 (M) — Credential 统一 SPI + 元数据管理：
  ├── shared/core/credential.go  — CredentialType 枚举 + CredentialMeta（kid, version, expires_at, created_at, algorithm）
  ├── shared/core/spi_credential.go — CredentialStore（存储加密的凭据）+ CredentialRotator（轮换策略接口）
  ├── CredentialRegistry         — 凭据类型注册表（每个 Rollable 凭据注册自己的轮换周期 + overlap 窗口）
  └── CredentialStatusStore      — 凭据状态跟踪（active / retiring / retired / compromised）

Phase 2 (M) — 轮换调度器：
  ├── platform/rotation/scheduler.go — 基于 CredentialRegistry 的全局轮换调度器
  │     ├── 支持 cron 表达式（`0 3 * * 0`）或间隔（`720h`）
  │     ├── overlap 窗口管理（新旧凭据在窗口期内共存，客户端逐步迁移）
  │     └── 失败重试与告警（轮换失败 → audit + 指标 + 可选 blocking）
  ├── 各凭据类型的 Rotator 实现：
  │     ├── JWE 解密密钥轮换器
  │     ├── CAEP webhook 签名密钥轮换器
  │     ├── 审计哈希链密钥轮换器
  │     ├── Webhook HMAC secret 轮换器
  │     └── SAML IdP 签名密钥轮换器（含 SAML 元数据更新通知）
  └── admin API + UI：凭据健康仪表盘

Phase 3 (L) — 紧急吊销与凭据受损响应：
  ├── `POST /api/v1/admin/credentials/{type}/compromise` — 立即吊销并签发新凭据
  ├── 自动通知受影响的依赖方（例如：SAML 元数据更新推送、JWKS 变更广播）
  └── 凭据审计追踪（谁、何时、为何轮换/吊销了哪个凭据）
```

### Edge Cases

- **轮换中的窗口管理**：新旧凭据共存窗口（overlap）必须足够长以允许异步传播，但又不能太长以增加泄漏窗口。签名的 overlap > 解密/签发的。
- **轮换失败的回滚**：如果新凭据生成成功但传播失败，系统应保留旧凭据继续服务并重试，而非进入"无可用凭据"状态。
- **外部依赖的凭据轮换**：KMS 桥接、数据库密码等依赖外部系统。轮换调度器应支持外部触发（webhook callback），而非仅内部驱动。
- **凭据库存审计**：系统应能回答"现在有多少个有效的签名键？哪些即将过期？上次轮换是什么时候？"

---

## 方向三：零信任架构集成框架（Zero Trust Architecture Integration Framework）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **L**（~2000 行 + 策略引擎 + admin UI） |
| 价值 | **极高**（行业确定性方向——企业采购身份的决策因素从"支持什么协议"转向"零信任就绪度"） |
| 类型 | 架构转型 + 产品功能 |
| 覆盖检查 | 此前 40+ 方向覆盖了 ZT 的**离散组件**（mTLS、DPoP、SPIFFE、ext_authz、step-up），但未覆盖**整合这些组件为可执行的零信任策略引擎** |

### 当前状态验证

代码库拥有丰富的零信任构建块，但它们是**孤立的**：

| ZT 组件 | 位置 | 当前状态 | 在 ZT 框架中的角色 |
|---------|------|---------|-------------------|
| mTLS（RFC 8705） | `security/mtls.go` + `header_client_cert_extractor.go` | ✅ 可绑定 access token 到客户端证书 | **设备身份**——验证请求来自拥有该证书的设备 |
| DPoP（RFC 9449） | `server_dpop.go` + DPOP | ✅ 可绑定 access token 到客户端密钥 | **用户代理身份**——验证请求来自拥有该私钥的客户端 |
| SPIFFE JWT-SVID | `security/spiffe_svid.go` | ✅ 可签发/验证 SPIFFE JWT | **工作负载身份**——验证请求来自该工作负载 |
| ext_authz（Envoy） | `extauthz/` + `mesh_authz.go` | ✅ Envoy 授权钩子 | **策略执行点**——在网关层执行授权 |
| Step-Up（RFC 9470） | `security/step_up_auth.go` | ✅ 资源服务器可要求升级认证 | **自适应访问**——基于资源敏感度提升认证级别 |
| 连续验证 | ❌ **完全缺失** | 无——只有请求到达时的单点验证 | **持续信任评分**——在会话期间持续验证信任 |
| 设备姿态评估 | ❌ **完全缺失** | 无——不检查客户端设备安全状态 | **设备健康**——验证设备是否符合安全基线 |
| JIT 权限提升 | ❌ **完全缺失** | 无——权限是绑定在角色上静态的 | **即时访问**——基于上下文临时提升权限 |
| 条件访问策略引擎 | ❌ **完全缺失** | 无——基于用户/角色/scope 的静态策略 | **策略编排**——基于用户、设备、位置、风险动态决策 |

**构建块是离散的，缺少的是它们之上的统一策略层**。

### 为什么需要

1. **零信任不是"部署了 mTLS 就可以"——它是一个架构模型**。NIST SP 800-207 定义的零信任七大原则中，Snaplink 当前覆盖了"认证"和"授权"，但缺失了"连续验证"、"设备健康"和"动态策略编排"。

2. **企业采购身份平台时，零信任就绪度已成为核心决策指标**（Gartner：2027 年前 60% 的企业将把零信任就绪度作为 IdP 采购的强制性要求）。

3. **离散的 ZT 组件如果没有策略引擎串联，运营负担反而加重**：
   - 安全团队要在 3 个不同的 UI 中配置 mTLS、DPoP、step-up
   - 没有统一的条件表达式（"如果设备是未管理的 + 请求来自高风险国家 + 资源是 admin API → 需要 step-up"）
   - 审计事件分散在多个事件类型中，无法回答"有多少请求被零信任策略阻塞"

### 建议方向

```
ZT 策略引擎（概念架构）：

[请求] → ┌──────────────────────────────────────────────┐
         │   ZT Strategy Decision Point (ZT-SDP)        │
         │                                              │
         │   1. 认证因子验证                             │
         │      ├── 用户身份（password / WebAuthn / SAML） │
         │      ├── 设备身份（mTLS 证书 / DPoP 公钥）      │
         │      └── 工作负载身份（SPIFFE SVID / JWT）     │
         │                                              │
         │   2. 信任评分                                  │
         │      ├── 设备姿态（MDM 合规 / OS 版本 / 补丁）  │
         │      ├── 位置风险（geo / IP 信誉 / Tor 检测）   │
         │      ├── 行为风险（登录频率 / 异常时间）         │
         │      └── 连续验证（会话中的信任衰减曲线）        │
         │                                              │
         │   3. 策略评估                                  │
         │      ├── 条件（用户 ∈ {group}, 设备 ∈ {compliant}, │
         │      │        风险 ∈ {low|medium|high}, ...）   │
         │      ├── 动作（allow / deny / step-up / mfa /  │
         │      │        restrict-scope / log）            │
         │      └── 会话 token 绑定（session 级别信任标记）  │
         │                                              │
         └───────────┬──────────────────────────────────┘
                     │ 决策
                     ▼
            ┌────────────────┐
            │  PEP (Gateway/  │
            │  ext_authz/    │
            │  middleware)   │
            └────────────────┘
```

```
Phase 1 (M) — 信任评分 SPI + 基础收集器：
  ├── shared/core/spi_trust.go   — TrustScore SPI（范围 0.0-1.0）
  ├── 内置 TrustScorer：
  │     ├── GeoRiskScorer（集成现有 geo 中间件）
  │     ├── IPReputationScorer（集成 anomaly.IPFailureCounter）
  │     ├── DevicePostureScorer（预留——需 MDM 集成）
  │     └── BehaviorScorer（基于 login_frequency / time_of_day）
  └── TrustScoreSerialization（可包含在 session / token 中供下游 PEP 读取）

Phase 2 (M) — 条件访问策略引擎：
  ├── shared/core/spi_cap.go     — ConditionalAccessPolicy SPI
  ├── ConditionalAccessStore     — 策略存储（YAML + admin API）
  ├── 策略文法：
  │     ┌─────────────────────────────────────────────┐
  │     │ policy "restrict-admin-access":             │
  │     │   conditions:                               │
  │     │     - user.member_of: ["admin"]             │
  │     │     - device.managed: false                 │
  │     │     - risk_score: "> 0.5"                   │
  │     │   actions:                                  │
  │     │     - require_step_up: mfa                  │
  │     │     - restrict_scopes: ["admin:read"]       │
  │     └─────────────────────────────────────────────┘
  └── 策略评估在 PEP 路径上同步执行（fail-closed）

Phase 3 (L) — 连续验证与会话信任衰减：
  ├── SessionTrustScore — session 中绑定的信任评分，随时间衰减
  │     ├── 信任评分衰减曲线（如：每 5 分钟 ×0.95）
  │     ├── 低于阈值触发 step-up / 会话刷新
  │     └── 高风险操作（/admin/*）要求 min_trust_score
  ├── ContinuousVerificationAgent — 后台 goroutine 定期验证已建立 session 的设备
  │     ├── Device 心跳（设备定期报告状态）
  │     └── 信任评分下降 → 推送会话刷新 + 审计告警
  └── 与现有 step-up（RFC 9470）集成

Phase 4 (L) — PEP 集成矩阵：
  ├── ext_authz 增强（传递信任评分 + 条件）
  ├── 边缘 nginx/lua 读取 token trust_score claim
  ├── 网关层 min_trust_score 门禁
  └── 可观测性：zero_trust_* 指标系列
```

### Edge Cases

- **信任评分的一致性与延迟**：多副本间信任评分是异步计算的。策略引擎应容忍评分稍微过时（秒级），但对于安全关键决策（deny）应使用实时评分。
- **设备姿态的隐私**：设备信息（OS 版本、已安装的应用）可能是敏感信息。策略引擎应支持设备"不报告姿态"时的降级策略（如：不报告 → max_trust = 0.3）。
- **条件访问的冷启动**：新用户/新设备没有历史行为数据。应使用默认风险级别 + 逐步校准。
- **策略爆炸**：大型组织可能有数百条条件策略。策略引擎应支持优先级、冲突解决和 dry-run 评估模式。
- **与现有 fail-open/closed 策略的协同**：零信任策略本身是 fail-closed 的，但数据源（风险评分、设备姿态）的故障应 fail-open（降级信任评分）而非拒绝所有请求。

---

## 方向四：业务连续性 / 灾难恢复框架（Business Continuity & Disaster Recovery Framework）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~1200 行框架 + 文档 + 测试） |
| 价值 | **极高**（生产系统的生存底线） |
| 类型 | 运营基础设施 + 架构韧性 |
| 覆盖检查 | 此前 40+ 方向覆盖了高可用部署拓扑（方向 17）、混沌工程（方向 12）、韧性验证（方向 22），但**均未覆盖有明确 RPO/RTO 目标的灾难恢复框架** |

### 当前状态验证

```bash
# 搜索 DR、BC、failover、RPO、RTO 相关术语：
$ grep -rn "disaster.*recover\|failover\|RPO\|RTO\|DR.*plan" --include="*.go" . | grep -v "_test.go"
# → 完全 0 命中

$ grep -rn "disaster\|recover.*plan\|continuity\|failover" docs/ --include="*.md" | grep -v "recovery_code\|recovery_codes\|password_recovery\|account_recovery\|recoveryoracle\|recoverySet"
# → 仅 docs/deployment.md 提到 "backup" 和 "restore" 但没有 DR 框架
```

**已存在的韧性基础设施**：

| 韧性能力 | 状态 | 注释 |
|---------|------|------|
| 备份与恢复（Snapshot/Restore） | ✅ | 完整的 `snapshot/` 包——加密快照 + 版本化 + 选择性子恢复 |
| Bootstrap 启动锁 | ✅ | `bootstrap/lock/` — etcd/filesystem 锁防止并发初始化 |
| 跨副本一致性 | ✅ | `cluster.Bus` 事件广播（签名键、撤销、租户失效） |
| 健康探针 | ✅ | `/livez`, `/readyz` 探针 |
| 多副本拓扑 | ✅ | etcd + 签名键聚合 + 跨副本撤销 |
| 故障转移 | ⚠️ 部分 | 签名键在 leaderless 模式下可自动采纳对端键，但数据存储（SQLite）无主从切换 |

**灾难恢复框架的完整缺口：**

| DR 维度 | 当前状态 | 目标状态 |
|---------|---------|---------|
| **RPO（恢复点目标）** | ❌ 未定义 | 可配置（5min / 1h / 24h）并持续监测 |
| **RTO（恢复时间目标）** | ❌ 未定义 | 可配置（5min / 30min / 4h）并定期验证 |
| **故障分级** | ❌ 未定义 | 单副本故障 / 数据存储故障 / 区域级故障 / 全站点故障 |
| **故障切换自动化** | ❌ 无 | 探针 + 流量切换 + 数据提升 + 验证 |
| **数据复制拓扑** | ❌ 无 | 同步复制（同一区域） / 异步复制（跨区域） |
| **DR 测试框架** | ❌ 无 | 定期自动化演练 + 测量实际 RTO/RPO |
| **恢复操作手册** | ❌ 无 | 针对每种故障级别的可操作、已验证的恢复步骤 |
| **降级服务模式** | ❌ 无——要么全部可用，要么全部不可用 | 只读模式 / 功能降级 / 降级但可用的 UI |

### 为什么需要

1. **SSO 是关键基础设施**。SSO 不可用 ≈ 全公司不能登录。对于作为中央身份代理的部署场景（企业 SSO），每小时的停机成本是百万级。

2. **当前的单副本 SQLite + 多副本 etcd 模型缺少跨区域容错**。如果整个 etcd 集群所在的可用区故障，签名键协调和共享状态（撤销集、JTI replay）均不可用。没有跨区域故障切换规划。

3. **现有的快照/恢复机制是系统管理工具，不是 DR 框架**：
   - 快照是手动的（`sso-ctl snapshot`），没有自动调度
   - 恢复是手动的，没有验证步骤
   - 没有"将快照自动传输到灾备区域"的管道
   - 没有"观察到区域故障 → 自动提升灾备 → 路由切换"的自动化

4. **竞品对标**：

| 平台 | RTO 保证 | 跨区域 DR | DR 测试 |
|------|---------|----------|---------|
| Auth0/Okta（SaaS） | 99.99%+（隐含 RTO < 5min） | ✅ 区域冗余 | ✅ 内部定期演练 |
| Keycloak（自建） | 取决于部署 | ⚠️ 外部数据库 + 外部会话存储 | 用户自行负责 |
| Dex（自建） | 取决于部署 | ❌ 无内置 DR | 用户自行负责 |
| **Snaplink** | **未定义** | **❌ 无内置 DR** | **❌ 无 DR 测试** |

### 建议方向

```
Phase 1 (M) — DR 基础：故障分级 + 可观测性：
  ├── docs/dr-framework.md — DR 策略文档
  │     ├── 故障分级与对应 RPO/RTO
  │     │   ├── Level 1: 单副本进程崩溃  → RTO=30s  → 自动重启
  │     │   ├── Level 2: 单节点硬件故障   → RTO=5min → 副本切换
  │     │   ├── Level 3: 可用区/数据中心  → RTO=30min → 区域故障切换
  │     │   └── Level 4: 区域全损         → RTO=4h   → 灾备区域恢复
  │     ├── 数据分类与复制策略
  │     └── 恢复验证流程
  ├── RecoveryTimeTracker — 每次恢复操作计时（自动测量 RTO）
  ├── DataReplicationLagGauge — 数据复制延迟指标（Prometheus）
  └── DRReadinessProbe — /readyz 中增加 DR 就绪度探针

Phase 2 (M) — 灾备区域自动化：
  ├── 被动灾备（Passive DR）：
  │     ├── 灾备区域的 SSO 实例持续运行（但不接收流量）
  │     ├── bootstrap 配置指向灾备数据源
  │     └── 区域 DNS 切换脚本（或不切换——手动触发）
  ├── SnapshotReplicator — 自动将快照从主区域复制到灾备区域
  │     ├── 磁盘级（rsync 到灾备存储）
  │     └── 数据库级（WAL shipping 或逻辑复制）
  └── RecoveryOrchestrator — 恢复编排器
        ├── 步骤 1: 验证灾备数据完整性
        ├── 步骤 2: 提升灾备副本为主副本
        ├── 步骤 3: 将签名键快照恢复到灾备 JQKS
        ├── 步骤 4: 验证灾备探针通过（/livez + /readyz）
        └── 步骤 5: 切换 DNS / 负载均衡器

Phase 3 (L) — DR 自动化演练：
  ├── test/dr/dr_failover_test.go — 模拟场景：kill 主副本 → 验证灾备接管
  ├── test/dr/dr_data_integrity_test.go — 验证故障切换后数据一致性
  │     ├── 检查令牌签发序列号无缝隙
  │     ├── 检查撤销集完整
  │     └── 检查审计哈希链连续
  ├── 与 chaos engineering（方向 22）结合：
  │     ├── chaos-kill-primary → 自动触发 DR failover → 验证 RTO
  │     └── chaos-partition-cross-region → 验证灾备健康
  └── DR Report Card — 每次演练输出一份 RTO/RPO 合规报告

Phase 4 (L) — 降级服务模式：
  ├── DegradationManager — 功能降级管理器
  │     ├── 只读模式（Read-Only）：所有写操作（注册、令牌签发、session 创建）返回 503
  │     ├── 认证降级（Auth-Only）：仅保留 /auth/login 和 /token（无 admin API / SCIM）
  │     ├── 本地模式（Local-Only）：断开 etcd/Redis 依赖，基于本地 SQLite 提供服务
  │     └── 维护模式（Maintenance）：所有请求返回 503 + Retry-After
  └── 降级模式触发条件：
        ├── 数据存储心跳超时 → 自动进入只读模式
        ├── etcd 连接丢失 → 自动进入本地模式
        └── 管理员手动触发维护模式
```

### Edge Cases

- **故障切换期间的令牌验证**：灾备区域激活后，已签发的令牌（以主区域的签名键签发）需要在灾备区域可验证。灾备必须保有主区域签名键的公钥。当前 leaderless 签名键聚合模式为这提供了良好基础——但需验证灾备区域的 JWKS 缓存是完整的。
- **跨区域的数据冲突**：如果灾备区域在故障切换期间接受了写操作，而主区域随后恢复，两个区域的数据可能冲突。简单的方案是"主区域恢复后作为灾备，丢弃差异数据"（即保证 RPO，但接受 RPO 窗口内的数据丢失）。
- **RTO 的组成部分**：RTO 不应仅测量"系统恢复服务的时间"，还应包括"数据验证的时间"。一个损坏的灾备不如不切换。
- **混合部署下的 DR**：SQLite + etcd + Redis + Postgres 的组合需要每种存储的 DR 策略不同，不能一刀切。

---

## 方向五：协议级攻击面管控与特性门控（Protocol-Level Attack Surface Reduction & Feature Gating）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~800 行 + 配置层 + 工具链） |
| 价值 | **高**（安全基线 + 部署灵活性——同一份二进制适配多种部署形态） |
| 类型 | 安全工程 + 架构治理 |
| 覆盖检查 | 此前 40+ 方向覆盖了**配置版本化**（方向 42）和**OAuth 2.1 严格模式**（方向 16），但**均未覆盖协议级攻击面管控和部署形态感知的端点暴露** |

### 当前状态验证

```bash
# 搜索攻击面、特性门控、部署模式相关：
$ grep -rn "attack.surface\|AttackSurface\|feature.gate\|FeatureGate\|deployment.mode\|DeploymentMode" --include="*.go" . | grep -v "_test.go"
# → 0 命中（仅 tenant.go 有一行注释提到 "per-tenant feature flags"，但并无对应的代码设施）

$ grep -rn "endpoint.*inventory\|endpoint.*audit\|exposed.*path\|ExposedAPI" --include="*.go" . | grep -v "_test.go"
# → 0 命中（没有系统性的端点清单）
```

**当前路由注册方式：**

`interfaces/sso/server_routes.go` 和 `server_routes_admin.go` 中，所有路由无条件注册：

```go
// 典型模式——所有端点总是注册的
func (s *Server) registerRoutes(r core.Router) {
    r.Post("/auth/login", s.handleLogin)
    r.Post("/token", s.handleToken)
    r.Post("/par", s.handlePAR)
    r.Get("/.well-known/openid-configuration", s.handleDiscovery)
    r.Post("/register", s.handleRegister)
    r.Post("/register/:client_id", s.handleRegisterUpdate)
    r.Post("/mesh/ext-authz", s.handleMeshExtAuthz)
    r.Any("/api/v1/admin/*", s.adminRouter.ServeHTTP)  // 所有 gRPC-gateway 端点
    r.Post("/backchannel-authentication", s.handleCIBA)  // CIBA
    r.Post("/ssf/receive", s.handleCAEPReceiver)         // CAEP
    // ... 更多
}
```

**存在的风险：**

| 场景 | 当前行为 | 理想行为 |
|------|---------|---------|
| **仅作为 OAuth 2.0 Server 部署**（不使用 OIDC） | `/userinfo`、`/.well-known/openid-configuration`、`/end_session` 仍然暴露 | 端点通过配置隐藏 |
| **仅作为 SAML IdP 部署**（不使用 OAuth/OIDC） | 所有 OAuth/OIDC 端点暴露 | 只暴露 SAML 相关路由 |
| **CIBA 未配置** | `/backchannel-authentication` 仍返回 404——但攻击者可探测到路由存在（404 body 含 minimal info） | 路由不注册——和未配置的模块一样不可见 |
| **CAEP/SSF 未配置** | `/ssf/receive` 同——404 但可探测 | 路由不注册 |
| **FAPI 未启用** | FAPI 验证逻辑在 `WithFAPIProfile` 中存在条件执行，但路由本身不变 | 同 |
| **Admin API 不需要** | `/api/v1/admin/*` 总是可访问（受 admin bearer token 保护） | 可通过配置移除/暴露 |
| **嵌入式库模式** | `interfaces/sso/` 作为库嵌入时，所有端点也自动注册 | 嵌入方可选择端点集 |

**核心问题**：**"功能存在就暴露端点"** 等价于 **"攻击面 = 全功能集"**。

### 为什么需要

1. **安全最小化原则**：每个暴露的端点都是一个攻击向量。认证端的端点可能被暴力破解（`/auth/login`）、DoS 攻击（`/par`、`/token`）、协议混淆（`/backchannel-authentication` 被用作反射放大点）、或用于侦察（探测 `/ssf/receive` 来确认 SSF 是否启用）。

2. **部署形态多样化**：同一份二进制应当支持多种部署形态：

   | 部署形态 | 应暴露的端点集 | 不应暴露的端点集 |
   |---------|--------------|----------------|
   | **全功能 SSO 服务器** | 所有（当前） | — |
   | **API-only 身份服务器**（无 SPA） | `/token`, `/introspect`, `/revoke`, `/par`, `/register` | `/auth/login`, `/end_session`, `/userinfo`, `/web/*` |
   | **OAuth 2.0-only 服务器** | OAuth 端点 | OIDC 端点、Fed 端点、CAEP 端点 |
   | **SAML-only IdP** | SAML 端点 | OAuth/OIDC 端点 |
   | **嵌入式/库模式** | 仅调用方显式注册的 | 所有默认不注册 |
   | **企业网关模式**（仅做 authz 决策） | `/token`, `/introspect`, `/mesh/ext-authz` | 自服务、SPA、well-known |
   | **只读/灾备模式** | `/introspect`, `/userinfo`, `/jwks`, `/.well-known/*` | 所有写端点 |

3. **这不是认证网关的替代品**——这是**在协议层面将攻击面压缩到最小必要集**。与 nginx 限流不同，这是"不存在的路由就是最好的安全"。

4. **已有基础设施可复用**：
   - `config.Config` + 配置节用于各功能模块（`WithAuthentication`, `WithIDTokenIssuer`, `WithCAEP` 等）
   - 这些配置已有的条件分支可以作为路由注册的条件

### 建议方向

```
Phase 1 (S) — 端点清单与审计：
  ├── tools/endpoint-inventory/ — 基于 AST 的路由注册扫描器
  │     ├── 静态分析所有 `r.Post/Get/Put/Delete/...` 调用
  │     ├── 输出 JSON 端点清单（path, method, handler_name, feature_flag）
  │     └── CI 门禁：每个 PR 的端点变更必须经过审阅
  └── /debug/endpoints（admin-only，编译时可选）——运行时端点清单端点

Phase 2 (M) — 特性门控路由注册：
  ├── config/config_gate.go — FeatureGate 配置节
  │     ╔═══════════════════════════════════════════════╗
  │     ║ feature_gates:                                ║
  │     ║   oauth2:    true                             ║
  │     ║   oidc:      false        # OIDC 完全禁用     ║
  │     ║   fapi:      true                             ║
  │     ║   ciba:      false                            ║
  │     ║   caep:      false                            ║
  │     ║   admin_api: false        # 生产环境禁用 admin  ║
  │     ║   federation: false                            ║
  │     ║   scim:      false        # 按需启用            ║
  │     ║   web_spa:   false        # 无 SPA 部署时禁用    ║
  │     ╚═══════════════════════════════════════════════╝
  ├── core.Router.Group（支持条件注册）：
  │     r.Post("/token", s.handleToken)  // always
  │     r.Post("/userinfo", s.handleUserinfo, WithGate("oidc"))
  │     r.Post("/end_session", s.handleEndSession, WithGate("oidc"))
  │     r.Post("/backchannel-authentication", s.handleCIBA, WithGate("ciba"))
  │     r.Post("/ssf/receive", s.handleCAEPReceiver, WithGate("caep"))
  │     r.Any("/api/v1/admin/*", s.adminRouter, WithGate("admin_api"))
  │     r.Get("/.well-known/openid-federation", s.handleFederation, WithGate("federation"))
  └── 兼容性：功能 X 的配置（如 `WithCAEPTransmitter`）自动启用对应的 gate

Phase 3 (L) — 端点协议版本化与弃用治理：
  ├── EndpointLifecycle SPI — 端点元数据管理
  │     ├── 版本（v1.0, v1.1, v2.0）
  │     ├── 状态（active / deprecated / sunset / removed）
  │     ├── 弃用警告头（Sunset, Deprecation）
  │     └── 客户端通告（well-known 中声明支持/不支持的端点）
  ├── Sunset Header 注入：
  │     Deprecation: true
  │     Sunset: Sat, 31 Dec 2027 23:59:59 GMT
  │     Link: </api/v2/token>; rel="successor-version"
  └── 协议版本服务端能力宣告：
        /.well-known/openid-configuration 中新增
        "endpoint_versions": {
          "token": "v1",
          "introspect": "v1",
          "userinfo": "v2"
        }
```

### Edge Cases

- **特性门控的不一致状态**：如果 `oauth2: false` 但某个遗留 client 仍使用 `/token` 端点，系统应返回明确的 404（而非 400——404 表示"端点不存在"而非"请求参数错误"）。
- **Gate 的默认值策略**：对于安全敏感的协议（OAuth 2.1 强制特性），gate 的默认值应为 `true`（与当前行为兼容）。对于新协议/企业特性，默认应为 `false`（最小攻击面）。
- **Gate 变更与已签发的 token**：如果在运行时禁用 OIDC，已签发的 id_token 应在 TTL 窗口内继续可验证。Gate 仅影响新请求的路由，不影响已有 token 的有效性。
- **Gate 的审计追踪**：每次 gate 状态变更（启用/禁用）应产生 audit 事件 + metric，因为攻击面变化是安全关键事件。
- **端点清单的维护**：每次新端点添加必须更新端点清单（CI 门禁强制）。否则端点清单与实际路由会漂移，失去管理价值。

---

## 跨方向相关性

```
方向一（令牌治理）──────方向二（凭据轮换）
        │                       │
        │   方向三（零信任框架）   │
        └──────────┬────────────┘
                   │
      ┌────────────▼─────────────┐
      │    方向四（DR 框架）        │
      │   ─ 所有方向的生存基线     │
      └────────────┬─────────────┘
                   │
      ┌────────────▼─────────────┐
      │ 方向五（攻击面管控）        │
      │ ─ 所有方向的部署契约       │
      └──────────────────────────┘
```

| 组合 | 协同价值 |
|------|---------|
| 方向一 + 方向三 | 令牌治理为 ZT 策略引擎提供输入——令牌使用模式是设备信任评分的信号之一 |
| 方向二 + 方向四 | 凭据轮换必须与 DR 故障切换协调——灾备区域必须掌握最新的凭据材料 |
| 方向三 + 方向五 | 零信任策略依赖于最小攻击面——如果 API 端点未压缩，ZT PEP 需要保护更多的面 |
| 方向四 + 方向五 | 降级服务模式（DR Level 4）通过特性门控实现——只需启用核心认证端点 |
| 方向一 + 方向四 | 令牌治理数据（活跃令牌数、签发率）是 DR 准备度的信号——灾备区域需要同类容量 |

---

## 优先级建议

| 优先级 | 方向 | 工作量 | 投产比 | 启动条件 |
|--------|------|--------|--------|---------|
| **P0** | 🔴 方向五：攻击面管控 Phase 1-2 | S-M（~500 行） | 最高——直接减少攻击面，CI 门禁防止未来膨胀 | 独立，无需依赖 |
| **P1** | 🟡 方向二：凭据轮换 Phase 1-2 | M（~600 行） | 高——凭据泄漏是最高频的安全事件 | 复用签名键轮换调度器 |
| **P1** | 🟡 方向四：DR 框架 Phase 1-2 | M（~800 行 + 文档） | 高——生产运营的生存底线 | 依赖 snapshot/restore 已有设施 |
| **P2** | 🟢 方向一：令牌治理 Phase 1 | M（~600 行） | 中高——规模增长后自动成为必选项 | 依赖审计已就位 |
| **P2** | 🟢 方向三：零信任框架 Phase 1-2 | L（~1200 行） | 战略级——面向未来 3-5 年的差异化 | 需要所有 ZT 组件已就位 |

**一句话结论**：先做攻击面管控（Phase 1 端点清单仅需 AST 扫描，零代码侵入 + 立即可见的生产安全收益），再推进凭据轮换和 DR 框架（日常运营基线），同时规划令牌治理和零信任框架（2027 战略差异化）。

---

*本文件不包含任何代码实现，仅作为架构级分析供后续团队决策参考。所有 grep 搜索和代码分析均基于 2026-07-01 代码库快照。*
