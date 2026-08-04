# 高层架构扩展方向分析 v5

> **复扫时间：** 2026-07-11
> **复扫范围：** 全代码库 2241 个 Go 源文件（含测试），覆盖 `interfaces/`、`protocols/`、`domains/`、`platform/`、`infrastructure/`、`shared/`、`internal/`、`cmd/`、`test/` 各层。
> **前置文档：** ROADMAP.md v5.0（2026-06-11）、feature-matrix.md、AGENTS.md、ARCHITECTURE.md、DIRECTORY_MAP.md
> **本文定位：** 独立复扫 → 提炼 5 个高价值扩展方向，不与已有分析重复。

---

## 前置说明

ROADMAP.md v5.0 已将项目下一阶段定位为"从协议后端收口走向产品化与企业化"，
本文在认可该判断的基础上，聚焦**复扫后仍未被充分覆盖的高 ROI 方向**。
每个方向均包含：

- **Why now**（市场 / 合规 / 竞争力驱动力）
- **Scope**（可独立交付的子任务）
- **Edge cases / 当前实现的具体短板**（逐文件定位）
- **已存在什么 / 缺什么**（避免重复造轮子）
- **Sequencing hint**（依赖关系与并行度）

---

## 方向一：Consent 生命周期管理——从 JSON 协议到可审计的用户授权记录

### Why now

当前 `/auth/login` 的 `prompt=consent` 已能正确返回 `consent_required` 错误
（含 `consent_challenge_id`），且 `ConsentChallengeStore` 接口完备
（`interfaces/sso/sso_selfservice.go`、`options_passwd.go`）。然而，**所有
consent 交互均以 JSON 协议返回给 RP，由 RP 负责渲染**——生产部署中这意味着：

1. 用户从未被展示过 scope 授权页，GDPR 第 7 条（"以清晰明确的方式获得同意"）
   的合规举证链存在缺口。
2. `ConsentStore` 有 `ListByUser` / `GetConsent` / `RevokeConsent` 的管理 API
   （`interfaces/admin/users.go`），但**缺少 per-user-per-client scope 级
   授权记录的持久化和版本化**（当前 `ConsentGrant` 只记录 client+user 二元组，
   不记录 granted_scopes 变更历史）。
3. 用户撤销授权后，CAEP 事件广播（`protocols/caep/`）不联动——已撤销 client
   仍持有有效 access_token 直至自然过期。

### Scope

| 子任务 | 工作量 | 依赖 |
|---|---|---|
| **a. Scope 级授权记录持久化**：扩展 `ConsentGrant` 以记录已授权 scope 列表、授权时间、版本号；新增 `UpdateConsentScopes(ctx, userID, clientID, scopes)` 方法 | L | 无 |
| **b. Consent 页渲染器**：`/auth/consent` 端点 + 内嵌 SPA（或 form-post 降级页面），展示 scope 描述（`WithScopeDescriptions` 已存在）、client 信息、"记住此决定"选项 | XL | (a) |
| **c. 撤销自动联动**：`RevokeConsent` 触发 CAEP `CredentialChange` 事件广播 → RP 收到后自行降权 | M | (a) + CAEP 基础 |
| **d. Admin 合规面**：`/admin/users/:id/consents/history` 审计列表，展示每次授权/变更/撤销的时间戳和 scope 快照 | M | (a) |
| **e. 增量授权（scope 升级）**：client 新增 scope → 旧 grant 标记为 stale → 下次登录要求重新授权 | S | (a) |

### Edge cases

- **并发授权竞态**：用户同时在两个标签页授权 → 挑战原子性（当前 `ConsentChallengeStore` 已用单次消费模式，需验证跨 replica 的原子消耗）
- **scope 描述变化**：`WithScopeDescriptions` 变更后，已授权用户应被重新提示变更的 scope（当前无"scope drift detection"）
- **client 元数据变更**：client name/logo uri 变更 → 已存储的 `consent_required` 对应信息应过期
- **租户级 consent 策略**：某些租户可能要求每次登录必授权（`prompt=consent` 等效强制），当前无 per-tenant 策略入口
- **数据可移植性**：GDPR 要求的 consent 记录导出（`/me/data-export` 应包含授权记录）

### 已存在 / 缺口判定

| 组件 | 状态 | 位置 |
|---|---|---|
| `ConsentChallengeStore` SPI | ✅ 已实现 | `interfaces/sso/sso_selfservice.go` |
| `ConsentStore`（admin 管理） | ✅ 已实现 | `interfaces/admin/deps.go`、`users.go` |
| `prompt=consent` 协议响应 | ✅ 已实现 | `interfaces/sso/server_logout.go` |
| Scope 级授权记录 | ❌ 仅 client+user，缺 scope 粒度和变更历史 | `shared/core/types.go` |
| 用户授权页 UI / SPA | ❌ 纯 JSON 返回 | 无 `/web/consent/` |
| 撤销联动 CAEP | ❌ | 无 `KindConsentRevoked` 事件类型 |
| GDPR consent 审计导出 | ❌ | `protocols/compliance/` 未包含 |
| Per-tenant consent 策略 | ❌ | 无 `Tenant.ConsentPolicy` |

---

## 方向二：Passkey 第一公民化——从 MFA 因子到主认证 + 跨设备同步

### Why now

Apple、Google、Microsoft 在 2022–2026 年间已全线推进 passkey（多设备 FIDO
凭据），iOS/macOS/Android/Windows 的原生 credential manager 均已原生支持
discoverable credentials。行业标准从 WebAuthn MFA 加速转向**以 passkey 为
主认证 + 用 PIN/生物识别解锁的免密码登录**。当前项目：

- WebAuthn 已作为 MFA 因子和 self-service 注册存在（`domains/authenticators/webauthn/`），
- `passwordless_required` client 属性可要求 passkey-only 登录
  （`shared/core/types.go:167` `AllowPasswordlessOnly`），
- 实验性 primary auth（`cmd/sso-server/build_app_selfservice.go` `wireWebAuthnPrimaryAuth`），
- 但**缺失以下 key features**。

### Scope

| 子任务 | 工作量 | 依赖 |
|---|---|---|
| **a. Conditional Mediation（Passkey 自动填充）**：`/auth/login` 支持 `webauthn.conditional=yes` 参数，返回 `mediation=conditional` 的 JSON 信号，使 RP 可发起 Passkey autofill 登录 | M | WebAuthn primary auth 基础 |
| **b. Discoverable Credential 全流程**：注册时声明 `residentKey=required`、登录时用 `allowCredentials=[]`（空 = 任何 discoverable 均可），覆盖 iOS/Android 原生 passthrough | M | (a) |
| **c. Credential 管理 API 扩展**：`/me/mfa/webauthn` 可列、改名、撤销单个 passkey（当前仅支持注册 + 全删）；撤销后 CAEP broadcast | L | CAEP 基础 |
| **d. 跨设备凭据同步描述层**：返回 `credential_prototype` 提示（`{type:"public-key", algorithms:[-7,-257], userVerification:"required"}`），帮助 RP 生成正确的 `navigator.credentials.create` 调用 | S | (b) |
| **e. 防枚举一致性**：passkey 登录中未知 credential ID → 返回与已知 credential 但签名失败**完全相同的**错误（当前可能泄露凭据是否存在） | S | WebAuthn 基础 |

### Edge cases

- **多个 passkey 绑定同一账户**：用户注册了 5 个 passkey（手机、笔记本、安全
  密钥），后台应支持按设备 ID 撤销指定 passkey（当前 `memory.Registry` 按
  `userID` 全量存储，无 per-credential ID 删除入口）
- **Passkey 升级/重注册**：OS 级 passkey 同步后 credential ID 可能变更，需
  `credentialId` → `userHandle` 反向查找
- **无母语 fallback**：当 client 不支持 conditional mediation（老浏览器），
  应优雅降级到普通 WebAuthn 按钮或密码 fallback
- **Passkey 仅用于特定 client**：某些 RP 需要 `passkey_required` 但不是全局
  的 `AllowPasswordlessOnly`，需 per-client 粒度
- **User verification 超时**：硬件 key 的 PIN/生物识别可能超时，当前不处理
  `UnknownError`/`AbortError` 的传播

### 已存在 / 缺口判定

| 组件 | 状态 | 位置 |
|---|---|---|
| WebAuthn MFA 认证 | ✅ | `domains/authenticators/webauthn/mfa.go` |
| WebAuthn 注册（self-service） | ✅ | `interfaces/sso/server_me.go` |
| Primary auth（实验性） | ✅ | `cmd/sso-server/build_app_selfservice.go:294` |
| `AllowPasswordlessOnly` client 属性 | ✅ | `shared/core/types.go:167` |
| Conditional mediation 支持 | ❌ | 无 `webauthn.conditional` 参数处理 |
| Discoverable credential 全流程 | ❌ 部分 | 注册不传 `residentKey` |
| Per-credential 管理 API | ❌ | 无 `/me/mfa/webauthn/:id` DELETE |
| 多 passkey 列表 | ❌ | 仅 `ListFactors("webauthn")` 含混 |
| Passkey CAEP 联动 | ❌ | 撤销 passkey 不广播 SET |
| 防枚举一致性 | ❌ 需验证 | 错误路径可能泄露存在性 |

---

## 方向三：集群级缓存一致性 + 温备快速恢复

### Why now

项目已具备相当完整的集群基础设施：etcd/Redis 后端、cluster bus
（`platform/cluster/`）、跨 replica 撤销广播、coordinated key rotation、
DR orchestrator（`platform/lifecycle/dr/`）。然而，运行一个多 replica
生产集群时仍面临几个明确缺口：

1. **缓存一致性不是强一致的**：`ClientStoreCache`
   （`interfaces/sso/servercache/server_client_cache.go`）通过
   `InvalidateClientCache` bus 事件做最终一致，但在高吞吐下可能发生
   "创建 client → 读请求路由到未收到 invalidation 的 replica → 返回
   404" 的读后写窗口。
2. **温备节点冷启动性能差**：新节点启动时，所有缓存（JWKS body、
   discovery doc、client cache、permissions policy bundle）为空，
   **需逐请求回填**，首分钟 p99 可能上升数个数量级。
3. **SQLite 局限**：SQLite 后端（`infrastructure/defaultimpl/sqlite/`）
   只支持单 writer，无法水平扩展读。使用 SQLite 的部署只能做
   active-standby（standby 零流量），浪费资源且 failover 不透明。
4. **DR 切换后的缓存风暴**：`dr.Replicator` 完成存储层切换后，所有
   内存缓存同时失效 → 瞬间回填风暴打垮后端存储（Thundering herd）。

### Scope

| 子任务 | 工作量 | 依赖 |
|---|---|---|
| **a. 缓存版本号 / 读后写一致性保证**：为 `ClientStoreCache` 加入 stamp-ride（版本号从存储层获取），replica 在写后等待版本号传播的配置项 | L | cluster bus |
| **b. 缓存预热 (Cache Warming)**：新节点启动时从 etcd/Redis 快照加载热门 key 的缓存条目，或从 peer replica 的 serialized cache dump 加载 | L | etcd/Redis |
| **c. 单飞去重 (Singleflight) 兜底**：缓存 miss 时用 `singleflight.Group` 合并回填请求（当前 JWKS body cache 已有 `singleflight`，但 client cache 和 permissions policy 没有） | M | 无 |
| **d. DR 切换的缓存节流**：orchestrator 切换后，加入 adaptive delay + jitter + probabilistic early freshness，避免回填风暴 | M | DR orchestator |
| **e. SQLite 读副本扩展示范**：在 `ops/deploy/baremetal-ha/` 中提供 SQLite 主+只读副本（`:memory:?mode=ro`）的 docker-compose 编排 + 应用层 read-your-writes 保证 | S | (a) |

### Edge cases

- **并发缓存回填锁死**：N 个 replica 同时 miss，各自触发回填，相互竞争锁
  → singleflight 去重（但注意 singleflight 的 `Forget` 再 miss 问题）
- **大规模 client 变更爆发**：批量导入 10k 个 client 时，每个都发一条缓存
  失效事件 → 消息风暴 → 需 batch/bucket 级失效
- **部分缓存过期与部分最新**：`sync.Map` 的条目粒度是每个 key，但 discovery
  doc 是多条记录的聚合（`server_discovery.go`），一轮 List 可能读到新旧混合
- **Replica 加入/离开时 gossip 同步**：新加入的 replica 在收到 bus 事件前
  的窗口期可能响应 stale 数据 → 如配置 `requires_immediate_replication=true`
  则拒绝 serve（fail-closed），否则 serve stale（fail-open）
- **DR 切换数据层温备**：存储层（PostgreSQL/etcd）切换后，业务缓存不清除
  → serve 已不存在的数据 → 加入 recovery marker

### 已存在 / 缺口判定

| 组件 | 状态 | 位置 |
|---|---|---|
| Cluster bus | ✅ | `platform/cluster/memory/bus.go`、`etcd/etcd.go` |
| Client cache invalidation | ✅ | `interfaces/sso/servercache/`、`server_invalidation.go` |
| DR orchestrator | ✅ | `platform/lifecycle/dr/orchestrator.go` |
| Retry/backoff 基础设施 | ✅ 部分 | `protocols/caep/broadcaster_retry.go` 等 |
| Cache 版本号 / read-your-writes | ❌ | 无 stamp-ride 机制 |
| 新节点缓存预热 | ❌ | 无 startup cache warming |
| Singleflight client store | ❌ | 仅 JWKS body 有 singleflight |
| SQLite 读副本 | ❌ | 不提供读副本配置 |
| DR 切换缓存压力控制 | ❌ | 切换事件不联动缓存节流 |

---

## 方向四：可观测性成熟度——从 Prometheus 计数器到 SLO 驱动运维

### Why now

项目已集成 Prometheus 指标（`platform/metrics/`）、OpenTelemetry 追踪
（`platform/tracing/`）、结构化审计日志（`platform/audit/`），基础设施
层面已相当扎实。但在生产运维场景下，以下缺口影响故障排查时效：

1. **无内置 SLO 计算**：无法回答"过去 1 小时 /token 的成功率是否低于
   99.9%"。当前只有 raw counter（`token_issuance_total{status="success"}`），
   需要外部 Prometheus + recording rules 自己做 delta 计算。
2. **无标准健康检查响应**：`/livez` 和 `/readyz` 返回纯文本 `OK` 或错误
   ——不遵循 RFC 9457（Problem Details），不包含组件级详情（"上游 IdP 不可达"
   vs "存储健康"），不适合负载均衡器做精细化流量调度。
3. **告警规则空白**：`/metrics` 端点暴露了丰富的业务指标（token 颁发/吊销计数、
   缓存命中/未命中、认证器延迟分位值、异常检测器输出），但仓库内**零告警
   规则文件**（无 `+kind: PrometheusRule`、无 `alerts/` 目录），运维需自建
   全部 alert 配置。
4. **依赖图 / 服务拓扑缺失**：跨 replica 调用、RP backchannel 调用、上游
   IdP 调用之间的依赖关系没有可视化载体，故障影响面排查靠人工。

### Scope

| 子任务 | 工作量 | 依赖 |
|---|---|---|
| **a. SLO 烧尽率跟踪器**：为 `token_issuance`、`auth_login`、`introspection`、`userinfo` 四个核心指标内置 SLO 对象（窗口=1h/24h/7d，目标=99.9%/99.99%），输出 prometheus `slo_burn_rate` gauge | L | `platform/metrics/` |
| **b. RFC 9457 健康端点**：`/livez` → 200 + `{"status":"pass","checks":[{"component":"storage","status":"pass","observedValue":12,"observedUnit":"ms"}]}`；`/readyz` 加入组件级详细状态 | M | 无 |
| **c. 内置告警规则**：`ops/monitoring/alerts/` 下 PrometheusRule CRD 文件，覆盖：证书即将过期、刷新令牌轮换异常率上升、MFA push 响应延迟 p95 超标、JTI replay 存储错误、集群成员变更、DR 切换事件 | S | (a) |
| **d. 认证流端到端追踪断言**：为 OAuth 2.0 / OIDC 关键协议路径（auth code + PKCE → token exchange → userinfo）嵌入 pre-built TraceID 传播断言，使 Tracer 可自动检测流程断裂 | M | `platform/tracing/` |
| **e. 审计事件到指标关联**：`audit.Recorder` 在写出审计日志的同时，向 `platform/metrics/` 投递结构化指标（已部分实现，缺 `anomaly` 检测输出、`conditionalaccess` 评估结果、`federation` 信任链解析结果等） | L | `platform/metrics/`、`platform/audit/` |

### Edge cases

- **SLO 时间窗口对齐**：烧尽率窗口应可配置（`slo.window=1h,24h`），避免
  Prometheus `rate()` 的混叠效应
- **健康检查不破坏安全约束**：`/readyz` 不暴露 tenant 级数据（所有 tenant
  共享的存储健康 = 公开，per-tenant 状态 = admin 权限）
- **告警噪讯抑制**：MFA push 延迟 p95 在正常业务波动下可能短暂超线，应
  内置 Soak（持续 N 个采集周期再告警）
- **分布式追踪采样率**：高吞吐下的 trace 采样不应遗漏错误路径（尾部采样），
  当前缺少 `sampler.ratio` 和错误路径全采配置

### 已存在 / 缺口判定

| 组件 | 状态 | 位置 |
|---|---|---|
| Prometheus 指标收集 | ✅ | `platform/metrics/` + `interfaces/sso/metrics.go` |
| OpenTelemetry tracing | ✅ | `platform/tracing/` |
| 结构化审计日志 | ✅ | `platform/audit/`（OCSF/CEF/Syslog/SQLite/PG 等） |
| `/livez` `/readyz` | ✅ | `interfaces/sso/server_health.go` |
| SLO 烧尽率 gauge | ❌ | 需新 `platform/slo/` 包 |
| 组件级健康详情 | ❌ | 当前只返回 `OK` / 空 body |
| 内置 PrometheusRule | ❌ | `ops/monitoring/` 不存在 |
| 认证流 TraceID 断言 | ❌ | 无跨组件 TraceID 传导测试 |
| Anomaly/ConditionalAccess 指标 | ❌ 部分 | 缺 `anomaly_detection_score`、`conditional_access_result` |

---

## 方向五：密钥治理——从启动时选型到运行时算法升级 + 后量子预备

### Why now

项目已有业界领先的密钥治理能力：4 种签名算法（EdDSA/ES256/RS256/PS256）、
5 个外部 KMS 后端（AWS/GCP/Azure/PKCS#11/Vault Transit）、leaderless
peer-key adoption、coordinated rotation。但以下方向尚未覆盖：

1. **运行时算法升级路径**：当前 `keys.signing.alg` 配置一旦选定，运行中
   无法切换到新算法。要升级（如从 RS256→ES256）需要**滚动重启所有
   replica**，中间窗口旧 token 签名校验可能失效（旧 JWKS 被提前清除）。
2. **PQC 后量子加密预备**：NIST 已标准化 ML-KEM（FIPS 203）、ML-DSA
   （FIPS 204）、SLH-DSA（FIPS 205）。当前所有签名算法均基于传统非对称
   加密。在证书链、JWT 签名、JWE 密钥封装的场景中，缺乏混合方案
   （hybrid KEM / hybrid signature）的协议扩展点。
3. **Relying Party 密钥切换通知**：JWKS 端点始终返回当前+待退役 key，但
   RP 无法主动获知"某 kid 即将退役"——`JWKS cache` 是在 RP 侧被动地按
   `max-age` 轮询。OAuth 工作组正在讨论 JWK Set Rotation Notification
   机制，当前无适配。
4. **密钥轮换的运营 SOP 自动化**：当前 coordinated rotation 需两节点以上
   手动协调（`sso-ctl rotate-key`），缺少按计划自动轮换的 CRD 控制器
   （如 `RotationPolicy` CR → 自动触发、灰度发布、回滚）。

### Scope

| 子任务 | 工作量 | 依赖 |
|---|---|---|
| **a. 运行时算法热切换**：新增 `IssuerRegistry` 管理多 algorithm issuer 共存，旧算法 issuer 进入"只校验不签名"状态，新登录使用新算法签名 | L | 现有 peer-key adoption 模式扩展 |
| **b. JWK Set Rotation Notification 适配**：响应 RP 的 `Prefer` 头（草案），或在 JWKS 中返回 `rotation_tip_uri`，指向 SSE 或 Webhook 端点 | M | SSE broker（`platform/sse/` 已存在） |
| **c. PQC 签名算法实验支持**：引入 `MLDSA44`/`MLDSA65`/`SLHDSA` 作为候选
  issuer（用 Go 后量子实现，如 `cloudflare/go` 或 `github.com/open-quantum-safe/liboqs-go`），标记为 `use:pqc`，不干扰现有 JWKS | XL | 安全评审 |
| **d. 自动轮换控制器**：`RotationPolicy` CRD + operator controller（复用 `cmd/sso-operator/controller/`），支持 `schedule:"@weekly"`、`gracePeriod:72h`、`requireApproval:true` | L | `platform/lifecycle/rotation/` |
| **e. 密钥库存（Crypto Inventory）完整链路**：当前 `cryptoinventory` 只做 passive 盘点（`platform/lifecycle/cryptoinventory/`），补事件触发：密钥轮换 → 自动审计事件 → 合规报表 | M | (d) + `platform/audit/` |

### Edge cases

- **算法热切换的 token 有效期窗口**：旧算法签发的 token 在 `exp` 前必须能
  被新算法 JWKS 验证——因此旧算法的验证 key 必须**保留至少一个 `max_token_ttl`
  时长**（当前 retire-after-ttl 策略需确认兼容）
- **PQC 签名体膨胀**：ML-DSA 签名约 2.5–4.5 KB（vs ECDSA 64–72 B），
  JWT header 可能超过某些 HTTP 代理的 header 大小限制（8 KB / 16 KB），
  需提供 alternative compact serialization
- **混合方案兼容性**：hybrid JWT 是两个独立签名（传统 + PQC），但
  现有 RP 可能无法识别第二个 `sig` 值——需用 `crit` header 声明
- **自动轮换的 rollback 策略**：`RotationPolicy` 触发的轮换发现新 key
  签名后 RP 出现大规模 `signature_verification_failed` → 应自动回滚
  到上一组 key（fail-safe）

### 已存在 / 缺口判定

| 组件 | 状态 | 位置 |
|---|---|---|
| 4 种签名算法 | ✅ | `infrastructure/defaultimpl/{ed25519,ecdsa,rsa}_*` |
| 5 个 KMS 后端 | ✅ | `infrastructure/kms/{awskms,gcpkms,azurekeyvault,pkcs11}` + `vaulttransit` |
| Peer-key adoption | ✅ | `interfaces/sso/signing_key_aggregation.go` |
| Coordinated rotation | ✅ | `interfaces/sso/coordinated_key_rotation_test.go` |
| 运行时算法热切换 | ❌ | 启动时 `alg` 固定，需重启切换 |
| JWK Rotation Notification | ❌ | 无 SSE/Webhook 通知接口 |
| PQC 签名算法 | ❌ | 无 PQC issuer 实现 |
| 自动轮换 CRD 控制器 | ❌ | 当前需操作员手动 `rotate-key` |
| Crypto inventory 审计联动 | ❌ 部分 | 已盘点（passive），未触发审计事件 |

---

## 优先级建议

| 方向 | 价值面 | 工作量 | 风险 | 建议时序 |
|---|---|---|---|---|
| ① Consent 生命周期管理 | 合规刚需 + 产品旗舰前序 | L–XL | 低（纯后端 + 无协议变更） | **P0 · 先做 (a)，(b)(d) 并行** |
| ② Passkey 第一公民 | 市场竞争差异化 | M–L | 中（需多浏览器/OS 测试） | **P0 · (a)(b) 与方向①并行** |
| ③ 集群缓存一致性 | 生产可靠性 | L | 中（一致性协议选型风险） | **P1 · (c)(e) 可先独立交付** |
| ④ 可观测性成熟度 | 运维效率 + SLA 反馈 | M–L | 低（不改现有协议） | **P1 · (a)(c) 优先** |
| ⑤ 密钥治理 + PQC 预备 | 合规前瞻 + 技术领导力 | XL | 高（PQC 标准尚在演进） | **P2 · (a)(d) 可在窗口内先行** |

---

## 总结

五个方向均经逐文件对抗核验，确认**不是重复已有的功能**，而是基于当前
代码库的具体缺口构造的扩展路径。它们共同的底层逻辑是：项目已具备业界
领先的协议完备度和安全架构，下一步的核心竞争壁垒在**产品体验端**
（方向①+②）、**生产可靠性端**（方向③+④）、以及**合规前瞻端**
（方向⑤）。
