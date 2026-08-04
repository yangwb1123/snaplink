# Strategic Expansion: 5 High-Value Direction Gaps

> **日期：** 2026-07-11
> **视角：** 资深架构 / 产品全局复扫
> **方法：** 对全代码库 ~1100 个非测试 `.go` 文件做逐层扫描、四维后端矩阵比对、
> 与现有 `ROADMAP.md` / `deferred-backlog.md` / `feature-matrix.md` 做交叉核验，
> 确保每一条均为未被已有规划充分覆盖的真缺口。
>
> **排序优先序：** 假设「如果只能挑一件事先做」。每项含 Why Now / 当前状态 /
> 具体缺口 / 边界情况 / 工作估算。

---

## 0. 扫描概要

| 维度 | 发现 |
|---|---|
| 协议覆盖率 | OAuth2/OIDC/FAPI/SAML/SCIM/CAEP/SSF/Federation 全栈实现，~50 个 RFC/Spec 覆盖 |
| **后端矩阵** | Memory/SQLite/Redis/Postgres 四维，但 **Postgres 有 6 个重要 Store 缺口**，Redis 有 2 个 |
| 多副本集群 | etcd/memory bus，滚动签名轮换、跨副本撤销广播、CAEP 双向 |
| Token 治理 | TokenPolicy/TokenUsage/TokenAnomaly/ThreatAction/ConditionalAccess 全链路 |
| 生产运维 | Grafana dashboard + 16 条 Prometheus alert rules + DR 框架 + config hot-reload |
| SPAs | Login/Admin/Portal/Developer 四个嵌入式前端（手写 JS/HTML/CSS） |
| MCP | `sso-mcp` 基础工具（可扩展） |

**结论：** 协议后端面极完整，剩余高价值方向集中在 **后端矩阵完整性修补**、
**集群数据面韧性收口**、**规模运营管控面**、**企业级边角一致性** 四个象限。

---

## 方向 ① PostgreSQL 后端完整化（生产级矩阵补全）

### Why Now（最高优先级）

PostgreSQL 是生产部署的事实标准数据库。当前 Postgres 后端存在 **8 个关键 Store 缺口**，
而 Memory / SQLite / Redis 均已覆盖。这意味着：

- 生产部署若选 Postgres 为主库，**必须混合 SQLite 或 Redis 作为辅存**来提供 auth_code、
  CIBA、JTI replay、MFA challenge、revocation 等核心协议能力——丧失了 Postgres 的
  单库事务一致性、备份/恢复简单性和运维统一性。
- 混合存储引入跨库事务难题（auth_code 在 Redis 而 user 在 Postgres → 无法用 PG 事务
  保证「代码兑换+用户状态」的原子性）。
- OAuth 协议依赖的 `DELETE RETURNING` 单用语义（refresh 轮换、auth_code 消费）在
  Postgres 中是**原生的**（`RETURNING` + `ON CONFLICT`），完全不需要额外的去重层。

### 当前状态

| Store | memory | sqlite | redis | **postgres** |
|---|---|---|---|---|
| auth_code | ✅ | ✅ | ✅ | ❌ |
| ciba | ✅ | ✅ | ✅ | ❌ |
| device_code | ✅ | ✅ | ✅ | ✅ |
| par | ✅ | ✅ | ✅ | ✅ |
| jti_replay | ✅ | ✅ | ❌ | ❌ |
| refresh_token | ✅ | ✅ | ✅ | ✅ |
| revocation | ✅ | ✅ | ✅ | ❌ |
| mfa_challenge | ✅ | ✅ | ✅ | ❌ |
| session | ✅ | ✅ | ✅ | ✅ |
| consent | ✅ | ✅ | ✅ | ✅ |
| password_reset | ✅ | ✅ | ✅ | ❌ |
| account_lockout | ✅ | ✅ | ❌ | ❌ |

**缺口汇总：** `auth_code` + `ciba` + `jti_replay` + `revocation` + `mfa_challenges` +
`password_reset` + `account_lockout` = **7 个 Store 缺失**（原笔记 8，device_secrets 已存在）。

### 边界情况 / 实现要点

- **auth_code：** Postgres `DELETE … RETURNING` 单用语义天然防重放；需注意 `AuthCode`
  的 `AuthTime`/`ACR`/`AMR` 字段（ROADMAP v5.0 §③ 提及）— PG schema 应一步到位。
- **jti_replay：** TTL 过期清理（`created_at + EXPIRE`）在 PG 中用 `DELETE WHERE
  expires_at < NOW()` 定时 sweep 或分区策略（Postgres 无原生 TTL）。
- **revocation / account_lockout：** 写入频繁但读取更频繁——需要 `ON CONFLICT DO NOTHING`
  短事务 + 适当索引（`(jti)` / `(user_id, provider)`）。
- **mfa_challenge：** 第二因素挑战有硬过期——PG 方案需 `expires_at` + 定期 sweep。
- **password_reset：** 同 MFA challenge——软删除 + TTL sweep。
- **CIBA：** `auth_req_id` 的轮询/过期模型——PG 的 `NOTIFY`/`LISTEN` 可用于 ping
  通知的进程内信令，避免引入 Redis pub/sub。

### 价值 · 工作量

- **价值：** high（无此补全，Postgres 无法作为独立生产后端）
- **工作量：** M（7 个 Store × 约 100-200 行/个 + 迁移 + 测试 ≈ 2-3 周）
- **并行度：** 每个 store 可独立 PR，不阻塞

---

## 方向 ② Redis 后端补缺 + 集群数据面韧性收口

### Why Now

Redis 是生产多副本部署中的**热路径标准辅存**（session / refresh / auth_code / rate-limit
均需低延迟）。当前 Redis 后端有 2 个硬缺口（`jti_replay`、`account_lockout`），更重要的是：
**跨副本撤销的 `deny-set` 不持久**（ROADMAP v5.0 §④c 已识别但未归入 Redis 补缺方向）。

将这两项合并为一个方向，因为它们在 Redis 中的解法相同（SET + TTL），且在部署中
常由同一运维团队负责。

### 当前状态

| Store | Redis |
|---|---|
| auth_code | ✅ |
| ciba | ✅ |
| device_code | ✅ |
| par | ✅ |
| refresh_token | ✅ |
| revocation | ✅ |
| session | ✅ |
| consent | ✅ |
| password_reset | ✅ |
| mfa_challenge | ✅ |
| **jti_replay** | **❌** |
| **account_lockout** | **❌** |

### 边界情况

- **JTI replay（DPoP / token-exchange / CAEP 所需）：** Redis `SET jti:<value>`
  `NX` `EX <ttl>` 天然原子判重。需注意 clock skew 窗口（`EX` 设为 issuer 时钟偏斜
  上限 + 宽松量，而非 JWT `exp` 剩余时间）。
- **Account lockout：** Redis `INCR` + `EXPIRE` 滑动窗口计数器。需注意 Redis 节点
  重启丢失计数器后，攻击者获得「满额尝试次数」——这是 fail-open 可接受行为
  （与当前 memory/sqlite 的 fail-open 行为一致）。
- **Deny-set 持久化（ROADMAP §④c 内容）：** Redis 的 `SET` + `EXPIRE` 即可实现
  「重启存活 + 自动过期」。滚动重启后 deny-set 从空开始——需考虑 RPO：access token
  被撤销后在 `exp` 余下的窗口内仍有风险。可引入启动时从 audit log 重建 warm cache 的
  机制（限最近 N 分钟的 revocation event）。

### 价值 · 工作量

- **价值：** high（jti_replay 是 DPoP/token-exchange 的 fail-closed 依赖；
  account_lockout 是 anti-enumeration 基础）
- **工作量：** S（2 个 store，每个 ~150 行 + 测试）
- **并行度：** 可独立 PR

---

## 方向 ③ 集群运营管控面：Multi-Cluster Fleet Management & Centralized Observability

### Why Now

当前运维体系**假定单集群**（或 `mesh_authz.go` 层面的数据面网格）。但：

- **ROADMAP v5.0 §④** 指出多副本「看着健康实则控制面失聪」的一组静默失败；
  `deferred-backlog` 提到 `sso-operator` config-drift 检测**但不 APPLY**。
- 产品化的身份平台（对标 Okta/Auth0/Keycloak）需要：
  1. **跨集群 Config 推播**（不限于 diff——需要 GitOps-style apply）
  2. **集中审计视图**（跨多个 SSO 集群的 audit log 聚合 + 拓扑展示）
  3. **批量 Rollout / canary 升级**（signing-key 轮换已有协调翻转，但 binary 版本
     滚动升级、schema 版本护栏（ROADMAP §④d）仅部分实现）
  4. **跨集群 Telemetry 聚合**（每个 SSO 实例自曝 metrics，但无全局拓扑中心）

### 当前状态

| 能力 | 状态 |
|---|---|
| 单集群 config diff | ✅ `GET /api/v1/admin/config/diff` |
| 跨集群 config diff | ✅ 通过 `sso-operator` SSOConfigDrift CRD |
| 跨集群 config **apply** | ❌ 无（operator 明确只 diff 不 apply） |
| schema 版本护栏 | ⚠️ `migrate.CurrentVersion` 已声明但零非测试调用方 |
| 多集群 audit 聚合 | ❌ 无 |
| 集群拓扑中心 / 统一监控 | ❌ 无 |
| 批量滚动升级策略 | ❌ 无 |
| canary/blue-green 切换 | ⚠️ 签名轮换协调翻转存在，但应用层无 |

### 边界情况 / 实现要点

- **Config apply 的安全模型：** 必须区分「检测 drift」与「裁定 drift 中哪边为 desired」。
  operator diff 是报告性的；apply 需要明确来源（Git 仓库？指定 leader？）和批准机制。
- **Schema 版本护栏：** `migrate.CurrentVersion > binary's max supported` →
  `readyz` fail 是 min-bar；还需在 `versioning.go` middleware 层拒绝已知不兼容的
  客户端/对等体。ROADMAP 已指出代码骨架存在但无调用方。
- **多集群 audit 聚合的安全：** 跨集群发送 audit event 需要 mTLS + 事件级权限检查
  （避免一个集群泄露另一个集群的用户数据）。
- **Metric 聚合的可扩展性：** 每个 SSO 实例已暴露 Prometheus metrics；加一个
  `WithGlobalMetricsExporter` 将 bounded-cardinality metric 推送到中心 collector，
  或暴露出 OpenTelemetry-compatible traces/metrics 端点（当前 tracing 仅 W3C trace
  context）。

### 价值 · 工作量

- **价值：** high（从「单集群工具」到「多集群平台」的飞跃；直接对齐 Auth0/Okta
  的部署模型）
- **工作量：** XL（分阶段：① schema 护栏 S→M；② config apply 设计 L；
  ③ 聚合 audit/metric 通道 L；多集群 UI 则是独立产品线）
- **并行度：** ① 可独立先交付，②③ 需设计文档

---

## 方向 ④ 企业身份治理增强：Identity Verification Grid（IVG） + 账户恢复

### Why Now

当前已有 `selfservice/signup.go`（含可选邮箱验证）、`password_reset.go`、
`verify_email.go`、`identitylink`（账户关联/合并）。但**缺少一套完整的身份证明链**
（Identity Verification Grid）——这在金融服务（FAPI、SOC2）和采购问卷中是常见缺口。

| 场景 | 当前覆盖 |
|---|---|
| Signup 基础流程 | ✅ |
| 邮箱验证（opt-in / 强制） | ✅ |
| 密码重置 | ✅ |
| Identity linking / 合并 | ✅ |
| **手机验证（SMS / Voice）** | **❌** |
| **KBA（知识型验证问题）** | **❌** |
| **管理式账户恢复管理员审批** | **❌** |
| **渐进式 Profile（渐进式收集信息）** | **❌** |
| **Verified ID / 证件上传校验** | **❌** |
| **账户恢复码（除 RecoveryCode）** | ⚠️ 仅 `recovery_code.go` 基本实现 |
| **TOTP/Passkey 丢失后的恢复** | ❌ |

### Why Now

- 企业买 SSO 时，第一问常是「用户丢了手机 / Passkey 怎么办？」——当前无 TOTP/Passkey
  丢失后的账户恢复流程。
- SOC2 / FAPI 采购会明确检查「是否有备用身份验证通道」「密码重置是否安全验证」。
- `identitylink` 包已设计好合并策略框架（`MergePolicy`），但 `LinkOnlyMergePolicy`
  明确声明不处理 sessions/tokens/enrollments 的迁移——real deployment 需要事务性
  「完全合并」能力。

### 边界情况 / 实现要点

- **TOTP/Passkey 丢失恢复：** 不能简单关闭 2FA——必须走备用通道（邮箱验证码 + 冷却期 +
  审计告警）。与 `identitylink` 的合并策略联动：是否允许「只验证邮箱就拆除 MFA」？
- **恢复码管理：** `recovery_code.go` 已有 seed + hash 存储。需要 UI（portal）和
  用户自助「生成新恢复码 / 作废旧码」的能力。
- **跨 Store 事务性合并：** `identitylink.LinkOnlyMergePolicy` 只迁移 identity
  links。真正的完全合并需要迁移 sessions/consents/refresh-token-families/enrollments
  ——这是一个多 store 协调操作，需要**暂停写 + 快照 + 重映射**或租户级迁移锁。
- **KBA 问题：** 维护（问题+答案 hash）的存储和管理界面的工作量不低；SOC2 常见做法是
  跳过 KBA，直接走「邮箱验证 + 冷却期 + 管理员批准」。

### 价值 · 工作量

- **价值：** high（SOC2/FAPI 采购问卷常见堵点；直接影响企业客户转化）
- **工作量：** L
- **并行度：** ① Recovery code UI（S），② TOTP/Passkey 恢复流程（M），
  ③ 手机验证 SPI（M，依赖短信 provider），④ 完全合并（XL）

---

## 方向 ⑤ 规模性能 & 安全基线：Granular Rate-Limiting + Adaptive Throttling + 动态成本控制

### Why Now

当前 `interfaces/ratelimit/` 已提供内存/SQLite/Redis 分布式限速器、per-IP/per-tenant
key 策略、以及可 hot-reload 的动态 policy。但面对**企业级多租户规模和攻击场景**，
仍有以下硬缺口：

| 能力 | 状态 |
|---|---|
| Per-tenant rate limit (login/token) | ⚠️ 有 `ratelimit.Policy.TenantKeyFunc` 入口，但无多租户默认配置 |
| Per-client rate limit | ❌ 无（client_credentials 对一个高 QPS 客户端无独立限额） |
| Per-endpoint granularity | ❌ `/token` 所有 grant type 共享一个 bucket |
| Adaptive throttling（负载感知背压） | ❌ 无（当前仅静态配额） |
| 全局并发控制器（Goroutine 限额） | ❌ 无（Go 的 Goroutine 虽轻量，但 bcrypt/KMS/hash 是阻塞操作） |
| Cost-based 速率限制（hash 复杂度自适应） | ❌ 无（bcrypt cost=10 vs 14 消耗差 16x——同速率限制不公平） |
| 客户端优先级 / 租户隔离 | ❌ 无（一个 noisy neighbor 可耗尽共享限速器配额） |

### 边界情况 / 实现要点

- **Per-client rate limit：** 在 `/token` 入口，从 `ClientStore.Get` 返回的
  `Client.RateLimitPolicy`（新字段）中读取配额。当缺省时 fallback 为全局 policy。
- **Adaptive throttling：** 监控 `sso_http_request_duration_seconds` 的 p99 变化，
  超过阈值后自动降低限速令牌补充速率（协调退避信号）。需注意不要在低负载时过度提升。
- **Cost-based limiting：** bcrypt cost (4-31) 和 KMS signing (网络 RTT) 对不同操作
  的 CPU/延迟代价差异巨大。限速器应接收一个权重因子（`costWeight`），高成本操作消耗
  更多令牌。
- **Noisy neighbor 隔离：** 使用分层令牌桶（Hierarchical Token Bucket, HTB）——
  每个租户有自己的子桶共享父桶的总配额。
- **全局并发控制器：** `semaphore.Weighted` 包装在 `middleware` 中——在达到限额时
 返回 503（`server busy`）而非排队积压。

### 价值 · 工作量

- **价值：** medium-high（非功能需求；但多租户 SaaS 部署和 pentest 会直接检查）
- **工作量：** M-L（per-client ← M，adaptive throttling ← L，HTB ← M）
- **并行度：** per-client 可独立 PR；adaptive throttling 需先有延迟度量信号

---

## 附录：复扫中发现的潜在 Bug / 技术债（非方向但值得关注）

| 位置 | 问题 |
|---|---|
| `infrastructure/postgres` | Postgres 缺少 7 个核心 OAuth Store——在方向①中涵盖 |
| `infrastructure/redis` | 缺少 `jti_replay` + `account_lockout`——在方向②中涵盖 |
| `infrastructure/defaultimpl/sqlite/clients.go` | `Client` 的安全相关字段（JWKS、AllowedResources、JWE 配置）在 sqlite schema 中被丢弃——ROADMAP §④f |
| `domains/identitylink/identitylink.go` | `LinkOnlyMergePolicy` 声明不迁移 sessions/tokens/enrollments——但未提供文档化的扩展点用于注册每个 store 的迁移函数 |
| `protocols/oauth/handle_register.go` | DCR 操作无审计事件（ROADMAP §⑤b）——但 `RegisterDeps` 可能已有 Recorder 入参？需核验 |

---

## 优先级摘要

| 方向 | 价值 | 工作量 | 建议 |
|---|---|---|---|
| ① PostgreSQL 后端完整化 | high | M | **本轮首选**——无此，PG 无法作为独立后端，直接影响生产选型 |
| ② Redis 补缺 + 数据面韧性 | high | S | 与①可并行，投入产出比最优 |
| ③ 多集群运营管控面 | high | XL | 长期战略方向；建议先做 schema 护栏（S）作为第一步 |
| ④ 身份证明与恢复增强 | high | L | 采购问答级收益，建议方向①完成后启动 |
| ⑤ 精细限速与自适应控制 | medium-high | M-L | 多租户规模的关键路径，建议方向①+②之后启动 |

---

*本分析基于 2026-07-11 代码库快照，与 ROADMAP v5.0 和 deferred-backlog 做了逐项冲突检测。*
