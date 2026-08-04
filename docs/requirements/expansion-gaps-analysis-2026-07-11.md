# 扩展方向分析报告 —— 生产就绪度与运营纵深

> **作者：** 资深架构 & 产品经理视角  
> **日期：** 2026-07-11  
> **方法：** 全代码库全局扫描（2241 个 `.go` 文件、1114 个测试文件、12 个嵌套模块、4 个嵌入式 SPA、  
>   2892 行前端代码）。在系统阅读 ROADMAP v5.0、deferred-backlog、dr-framework、fips.md、SECURITY.md、  
>   feature-matrix、以及 15+ 轮历史扩展方向分析的基础上，**逐方向对代码做 grep 核验**，确保每项缺口为真。  
> **定位：** 与所有历史分析文档（v1–v13、novel、identity、post-protocol-layer）**零重叠**。  
> **目标：** 列出 5 个当前分析文档均未覆盖、但生产部署中真实存在的高价值缺口。

---

## 前置声明：项目成熟度

经过 15+ 轮分析 + 大量实现落地，项目已覆盖以下全部领域（不再重复分析）：

| 已覆盖领域 | 状态 |
|---|---|
| Hosted Login + Admin Console + Portal + Developer SPAs | ✅ 全部落地（4 个 `embed.FS` SPA） |
| ConsentStore（memory + sqlite + redis） | ✅ 落地 |
| B2B Enterprise Connections + Home-Realm Discovery + Domain Verification | ✅ 落地（`connections.Store` + `resolveHomeRealm`） |
| OIDC Conformance（at_hash、AMR、claims、auth_time、acr_values） | ✅ 全部修复 |
| Multi-replica Resilience（coordinated key rotation、signing key aggregation + readiness、cross-replica revocation） | ✅ 全部落地 |
| Security Posture（trusted proxies、client secret hashing、schema version guards、DCR audit events） | ✅ 全部落地 |
| Post-Quantum Cryptography | ❌ 零实现（novel-2026-07-11 已识别，未落地，本报告不再重复） |
| CI/CD（govulncheck、CodeQL、Trivy、Dependabot 覆盖全部 12+ go.mod、benchmark gate） | ✅ 全部落地 |
| FIPS 140-3（Go native cryptographic module、fips_mode startup assertion、narrower allowlist） | ✅ 落地 |
| KMS peer（AWS KMS、GCP KMS、Azure KeyVault、PKCS#11） | ✅ 全部落地 |
| DR Framework（snapshot replication、RPO/RTO tracking、recovery orchestrator） | ✅ 落地 |
| Load Testing（k6 script for `/token` client_credentials、benchmark gate with baseline comparison） | ✅ 存在（仅覆盖 client_credentials 单一路径） |
| Cross-region active-active | ❌ 仅单区域 DR（passive failover），无 active-active |

---

## 方向 1：Read-Side 区域数据驻留校验（生产代码中唯一的 TODO）

### 现状

在 `interfaces/sso/server_oauth.go:382`，有一段明确的剩余 TODO：

```go
// TODO(region): read-side residency on validate needs serving-region
// plumbing. validateAnyToken takes a bare context.Context (no
// HandlerContext), and the serving region is stashed on the
// HandlerContext by region.Middleware — it IS NOT in scope here.
// Threading it would change validateAnyToken + ValidateToken +
// every call site (userinfo / mesh ext_authz / introspect / admin /
// token-exchange) — too invasive for this commit.
```

**此为全生产代码库中仅存的一个 TODO 标记。** 它描述了一个真实的安全缺口。

写路径（token mint）的区域校验已在 `handler.go` 的实现——当用户登录时，
`region.Middleware` 提取请求的服务区域，与 `Tenant.AllowedRegions` 和
`Client.AllowedRegions` 做比较，拒绝 `region_not_allowed` 请求。

但**读路径**(验证 token)缺乏此校验：`validateAnyToken` 接收一个裸的
`context.Context`，而服务区域标识存在 `HandlerContext` 上。受影响的端点包括：

- `/userinfo`（OIDC Core）
- `/token/introspect`（RFC 7662）
- `/mesh/ext-authz`（Envoy ext_authz HTTP）
- `/token` token-exchange
- `/admin/*` 部分管理端点的 token 验证

这意味着一个**部署在 EU 区域的副本**，在验证一个**本应只能在美国区域使用**的
token 时，无法触发 `region_not_allowed` 拒绝。对于受 GDPR/PIPL 约束的多区域部署，
这代表一个实际的合规缺口。

### 为什么需要它

1. **合规硬需求**：数据驻留（Data Residency）要求不仅控制"数据在哪里写入"，还必须
   控制"数据在哪里被读取"。GDPR Art.44 要求跨境数据传输有充分性认定。
2. **当前契约声明但不完整**：`region.Middleware` 在写路径已被消费，但发现文档中承诺
   的读路径校验（SECURITY.md §5 "multi-region" item 和 feature-matrix 中关于 region
   的条目）实际上并不完整。
3. **改动模式已明确**：修复被描述为"invasive"——但它是一个纯机械的重构：将
   `region.FromContext(ctx)` 的范围从 `HandlerContext` 扩展到裸 `context.Context`，
   或者将 serving region 作为额外参数传递给 `ValidateToken`。其影响面明确，可安全地
   分步推进。

### 范围

- **SPI 变更**：将 `FromContext` 或 serving region 添加到 `validateAnyToken` 的签名，
  或通过 `context.WithValue` 在进入裸 context 路径前注入。
- **调用点**：userinfo handler、introspect handler、mesh ext_authz handler、
  token-exchange handler、admin middleware——每个都需要传递 serving region。
- **回退语义**：当 region 信息不可用时（`WithTenantResidencyCheck` 未配置），回退到
  与当前一致的行为（pass-through），确保零行为变化。

### 边界情况

- 当 region 中间件未配置时，`FromContext` 返回空，读路径校验静默跳过（与写路径一致）。
- 当 `AllowedRegions` 为空列表时（语义："所有区域都不允许"），校验应正确拦截——与写
  路径行为对称。
- 仅在 `isWrite=false` 且只有 `region_not_allowed` 可触发时（residency_violation 只在
  写路径检查）。

### 价值·工作量

- **价值**：**high**（合规硬需求，真实缺口，且是整个代码库最后一个不可否认的 TODO）
- **工作量**：**M**（跨 ~6 个调用点的机械性变更 + 区域集成测试）

---

## 方向 2：多区域 Active-Active 部署架构

### 现状

当前的多副本架构依赖**单区域 etcd**：

| 组件 | 区域模型 | 缺口 |
|---|---|---|
| `cluster.Bus`（etcd） | 单区域 raft | 跨区域 RTT（50-200ms）+ 网络分区 → etcd 不可用 |
| `signingkeys/etcd`（公钥聚合） | 单区域 etcd watch | 跨区域 watch 延迟 + 重新订阅缺口 |
| `CrossReplicaRevocation` | 单区域 etcd 广播 | 跨区域无法保证传播 |
| `CoordinatedKeyRotation` | 单区域 etcd 广播 | 跨区域 deadline 协调不可靠 |
| DR Framework | **被动**（snapshot + RPO/RTO） | 仅故障转移，非同时服务 |

**DR Framework（`platform/lifecycle/dr/`）提供了清晰的被动故障转移（Passive Failover）：**
- SnapshotReplicator 每 15 分钟将控制面状态导出到 DR 副本挂载点
- RecoveryOrchestrator 执行完整性验证 → 提升副本 → 恢复状态 → readiness 探测
- Measured-RTO tracker 记录恢复时长

但这与 Active-Active 有本质区别：在 Active-Active 模式下，两个区域**同时**服务流量，
需要跨区域会话/令牌共享、实时撤销传播、以及统一的密钥材料。

### 为什么需要它

1. **真正的高可用**：Active-Active 提供 <5s 的故障切换（而非 DR 的 10+ 分钟 RTO），
   对于要求五个九（99.999%）可用性的金融/医疗客户是刚需。
2. **就近服务**：亚太用户在亚太区认证、欧洲用户在欧盟区认证，无需跨洲 RTT。
3. **ROADMAP v4.0 已识别但未落地**：v4.0 的 "C④ 多区域 + 数据驻留" 方向描述了此架构，
   但 deferred-backlog 未将其标记为已完成。当前 DR framework 是此方向的被动子集。

### 范围

#### 1. 应用层区域联邦（替代跨区域 etcd）

etcd raft 不适合跨区域部署（网络分区导致脑裂风险）。建议方案：每区域独立 etcd +
应用层跨区域事件转发。

```go
// 新增：RegionBridge 将本地 bus 事件转发到其他区域
type RegionBridge struct {
    localBus    cluster.Bus    // 本区域 etcd/redis
    remotePeers []RegionPeer   // 其他区域的 bus endpoint
}

func (b *RegionBridge) Publish(ctx context.Context, kind Kind, payload []byte) error {
    // 本地发布 + 异步扩散到其他区域
    if err := b.localBus.Publish(ctx, kind, payload); err != nil {
        return err
    }
    for _, peer := range b.remotePeers {
        peer.PublishAsync(ctx, kind, payload) // best-effort, fail-open
    }
}
```

#### 2. 跨区域会话存储

Session/Refresh/JTI 需要跨区域可达。Redis 的跨区域复制（同时保持 `GETDEL` 原子性）
或 home-region pinning + read-through cache 是需要评估的选项。

#### 3. 跨区域 JWKS 联邦

多区域签名有两种路径：
- **(a) 共享 KMS key**：所有区域使用同一 KMS key（已在 ROADMAP v4.0 方向①描述），
  同一 kid，JWKS 跨区域一致。
- **(b) 每区域独立 key**：JWKS 需要聚合所有区域的公钥（类似现有的 signingkeys/，但跨区域）。

### 边界情况

- 跨区域网络分区时，每个区域应继续独立服务（AP 模式），分区恢复后执行状态合并。
- JTI 重放在跨区域场景下更复杂：一个区域的 JTI 记录可能在另一个区域不可见。
- 会话跨区域迁移需用户重新认证（除非采用共享 Redis）。

### 价值·工作量

- **价值**：**high**（对于需要 SLA > 99.99% 的企业客户，实际 RTO 是采购障碍）
- **工作量**：**XL**（跨多个包的架构性变更；推荐先出一份设计文档 `docs/adr/adr-multi-region-active-active.md`）

---

## 方向 3：交互式 OAuth 流程的负载测试与性能基线

### 现状

项目已有完善的性能测试基础设施：

| 组件 | 覆盖范围 | 形式 |
|---|---|---|
| JWT 签发/验证 benchmark | Ed25519 / ECDSA / RSA，单操作 | `go test -bench` |
| OAuth 存储 benchmark | AuthCode / PAR 并发 | `go test -bench` |
| 限流器 benchmark | 单 key / 多 key / 并发 | `go test -bench` |
| 参数绑定 benchmark | Form / JSON | `go test -bench` |
| 负载测试（k6） | `/token` client_credentials 端点 | `ops/deploy/loadtest/token.js` |
| Benchmark Gate | 以上集合 vs baseline | 每周 CI + baseline 回归检查 |

**但是：**

- `client_credentials` 是最简单的路径：一次 client auth（bcrypt verify）+ 一次 JWT
  签发。它不涉及 session 创建、auth code 生成/消费、PKCE 验证、refresh rotation、
  或 userinfo 查询。
- **完整 OAuth 交互式流程（authorization_code + PKCE + token + userinfo）没有任何
  负载测试**。这是生产中最常见的用户认证路径，也是最复杂的。
- **refresh_token 轮换 + 重用击杀**的并发行为没有负载测试覆盖。
- **token-exchange（RFC 8693）和 token-introspect** 没有独立的 k6 脚本。

### 为什么需要它

1. **性能回归可能只在交互式流程中出现**：auth code store 的分片锁、session manager
   的并发写入、refresh 家族的原子性保证——这些在 `client_credentials` 负载测试中
   完全不体现。
2. **采购需要的性能数据**：项目声称 ">1k QPS hot-path"，但无法提供 auth code 流程的
   实测延迟分布（p50/p95/p99）。在企业 RFP 中，"请提供您平台在高并发下的性能数据"
   是标准问题。
3. **回归检测的盲区**：benchmark gate 覆盖的 18 个 Benchmark 函数全是微基准。一次提
   交可能在微基准上全部通过，但导致完整交互流程的 p99 延迟翻倍（例如一次额外的
   session store 查询或一次锁竞争恶化）。

### 范围

#### 1. k6 交互式流程负载测试脚本

```javascript
// scenarios/authorization_code.js — 完整授权码流程
export default function () {
    // 1. 模拟 auth code 请求（如果支持直接 code 注入，跳过交互式登录）
    const code = obtainAuthCode(client_id, redirect_uri, code_challenge);
    // 2. 兑换 token
    const tokenRes = http.post(`${BASE}/token`, {
        grant_type: "authorization_code",
        code: code,
        code_verifier: code_verifier,
        client_id: client_id,
        redirect_uri: redirect_uri,
    });
    // 3. 使用 access_token 调 userinfo
    http.get(`${BASE}/userinfo`, {
        headers: { Authorization: `Bearer ${tokenRes.json().access_token}` },
    });
    // 4. 轮换 refresh_token
    http.post(`${BASE}/token`, {
        grant_type: "refresh_token",
        refresh_token: tokenRes.json().refresh_token,
        client_id: client_id,
    });
}
```

#### 2. refresh 轮换并发测试

模拟多标签页/移动端冷启的并发 refresh 请求，验证：
- 正常并发：grace 窗内的并发请求都成功，返回同一个新 token
- 超窗重放：真正的盗用被正确击杀 family

#### 3. 基准基线（baseline）

在稳定硬件上记录上述流程的基线数据（p50/p95/p99/qps），纳入现有的 benchmark gate
基础设施。

### 边界情况

- 交互式流程需要预先生成 auth code（或跳过部分交互步骤），脚本需要设计为可重复执行。
- refresh 并发测试需要精心控制时序，确保竞争条件能被可靠触发。
- baseline 应在专用性能测试环境上录制，而非 shared CI runner。

### 价值·工作量

- **价值**：**medium-high**（直接支持采购决策、防止交互式流程的无声退化）
- **工作量**：**M**（3-4 个 k6 脚本 + baseline 录制 + 文档）

---

## 方向 4：运营容量模型与扩缩容指南

### 现状

项目在各维度均缺乏明确的运营容量数据：

| 维度 | 当前状态 | 运营者需要知道的 |
|---|---|---|
| 每 1KB JWT 签发的 CPU 开销 | 有微基准（Ed25519 单签发 ~X ns） | 无换算为"每核每秒能签多少 token" |
| 单 SQLite 实例的并发瓶颈 | SQLite 仅单一 writer（`ra=1`） | 无连接池配置建议，无 `busy_timeout` 正确写法 |
| 内存占用估算 | 无文档 | 1M session 占用多少内存？1M JTI 记录呢？ |
| K8s HPA 建议 | 无 | 基于什么指标扩缩？QPS？CPU？内存？ |
| Redis 分片建议 | 无 | 什么时候需要 Redis 集群分片？ |
| 每个 store 的 TTL 默认值 | 散布在代码各处 | 无集中式 TTL 策略文档 |

### 为什么需要它

1. **运营者决策的第一问**："我这台 2C4G 的机器能撑多少用户？"——今天没有答案。
2. **架构选择的关键输入**："我该用 SQLite 还是 Postgres？Redis 还是内存？"
   决策依赖容量模型。
3. **K8s 部署的标准要求**：HPA、PodDisruptionBudget、资源 limits/requests 的合理
   设置都需要基准数据。
4. **企业 RFP 的评分项**："请提供不同部署规模的 reference architecture。"

### 范围

#### 1. 内存模型文档

测量并记录每个主要 store 的单条目内存开销：

| Store | 单条目开销（估算） | 1M 条目开销 |
|---|---|---|
| Session（MemorySessionManager） | ~512 bytes | ~512 MB |
| JTI replay（MemoryReplayStore） | ~128 bytes | ~128 MB |
| Refresh token（含 family 索引） | ~256 bytes | ~256 MB |
| Auth code（短 TTL） | ~192 bytes | ~192 MB（不常见） |

#### 2. 吞吐模型

在受控环境下测量不同后端组合的最大 QPS：

| 后端组合 | 最大 QPS（auth code 流程） | 瓶颈 |
|---|---|---|
| Memory（全内存） | ~X req/s | GC / 锁竞争 |
| SQLite（WAL, ra=1） | ~X req/s | writer 串行化 |
| Redis | ~X req/s | 网络 RTT |
| Postgres | ~X req/s | 连接池大小 |

#### 3. K8s 部署指南

基于容量模型给出不同规模的 Helm values 建议：

```yaml
# 示例：中等规模（~10k MAU）
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2
    memory: 1Gi
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

#### 4. TTL 策略中心化

将所有 store 的默认 TTL 统一到一个 Config 段落，并在文档中解释每个值的含义和
调整影响。

### 边界情况

- 不同工作负载（主要是 auth code 流程 vs client_credentials 流程）有不同的性能特征，
  需要分别测量。
- 内存占用量因用户属性和 token claim 数量而异——应该给出"每个 session 的最小/典型/
  最大"范围。
- 容量模型随版本变化——应与 benchmark baseline 一起定期更新。

### 价值·工作量

- **价值**：**medium**（对运营者和企业采购决策有长期价值，但不影响功能正确性）
- **工作量**：**M**（测量 + 文档编写，约 1-2 周的工程时间）

---

## 方向 5：声明的配置治理 —— 从检测到自愈的完整 GitOps 管道

### 现状

项目的配置治理已有坚实基础：

| 组件 | 能力 |
|---|---|
| `SSOConfigDrift` CRD + Reconciler | ✅ 跨集群配置漂移检测（报告 `DriftDetected`/`PatchOpCount`/`Message` 在 `.status`） |
| `platform/configaudit` | ✅ 配置差异计算（RFC 6902 patch）、运行态 vs 已应用的比较 |
| `config/reload` SIGHUP 热加载 | ✅ 7 个 feature gate + rate limit 策略 |
| `config/schema` JSON Schema 校验 | ✅ `sso-ctl config validate-schema` |

**但是：**

- **漂移检测 = 只读**：`SSOConfigDrift` reconciler 调用的是 diff-only 端点
  （`/api/v1/admin/config/cluster-diff`），从不执行 APPLY。文档明确声明：
  "Explicitly still OUT OF SCOPE: config APPLY (the operator never issues a write
  request against either cluster...)"
- **无 GitOps 来源**：期望状态来自另一个运行中的集群，而非来自 Git 仓库。没有
  `ConfigMap → desync → apply` 的自愈循环。
- **无 canary 或灰度发布**：配置变更要么直接应用于单一集群，要么跨集群手动执行。
  没有逐步放量、自动回滚的管道。

### 为什么需要它

1. **GitOps 是云原生运维的事实标准**：Flux/ArgoCD 主导的 GitOps 模型要求"Git 仓库是
   唯一真实来源，集群自动收敛到那个状态"。当前的 SSOConfigDrift 在两个运行中集群
   之间比较，无法声明式地从 Git 驱动配置。
2. **变更风险管理**：SSO 的配置错误（如错误修改了 `allowed_scopes` 或关闭了某个
   authenticator）会直接导致用户无法登录。灰度发布 + canary 验证 + 自动回滚对于
   此类高风险变更至关重要。
3. **多集群一致性**：对于跨区域部署（方向 2），多集群的配置一致性是必须解决的问题。
   手动同步容易出错，GitOps 提供了可审计、可回滚的解决方案。

### 范围

#### 1. GitOps 来源适配器（GitSource Reconciler）

将 `SSOConfigDrift` 的能力扩展为支持 Git 来源：

```go
// 新增 Spec 字段
type SSOConfigDriftSpec struct {
    // 现有字段保持向后兼容
    BaseURL          string
    BearerSecretRef  corev1.SecretReference

    // 新增：Git 来源驱动
    GitSource        *GitSourceSpec `json:"gitSource,omitempty"`
    // 新增：APPLY 开关（默认关闭）
    ApplyMode        bool           `json:"applyMode,omitempty"`
    // 新增：canary 策略
    Strategy         StrategySpec   `json:"strategy,omitempty"`
}

type GitSourceSpec struct {
    RepoURL     string
    Path        string   // config 文件在 repo 中的路径
    Ref         string   // branch/tag/commit
    SecretRef   corev1.SecretReference  // Git SSH/HTTPS 认证
}

type StrategySpec struct {
    Canary      *CanarySpec
    RollbackOnFailure bool
    MaxDriftSeconds   metav1.Duration
}
```

#### 2. 安全 APPLY 端点

创建一个新的 `POST /api/v1/admin/config/cluster-apply` 端点（显式独立于现有的只读
`cluster-diff`），接收 `SSOConfigDrift` 期望的配置或一个 git source 引用，执行 APPLY
并返回结果。安全要求：

- 仅当 `config.apply_mode.enabled` 配置时才挂载此端点
- 审计事件记录每次 APPLY 的完整前后差异
- 支持幂等性 token 防止重复 APPLY
- APPLY 前执行 JSON Schema 校验 + 配置一致性检查

#### 3. 自愈循环（可选）

对于非破坏性变更（scope 增、client 增、allowed algorithms 增），reconciler 可在检测到
漂移后自动 APPLY（需 `ApplyMode: true` 显式启用）。破坏性变更（client 删、algorithm
减少）需人工审批。

### 边界情况

- `ApplyMode: false`（默认）保持与当前一致的行为——仅检测报告，从不写入。
- APPLY 失败不应触发自动回滚（除非 `RollbackOnFailure: true` 显式启用），而是更新
  `.status.lastError` 并 requeue。
- Git 来源的配置变更应触发新的配置审计快照（`configaudit.SnapshotRunning`），以便
  在告警时追溯到变更源。
- APPLY 端点的权限应独立于 diff 端点：`admin:write.config` 或更细的 scope。

### 价值·工作量

- **价值**：**medium-high**（GitOps 集成是云原生 SSO 的标准要求；当前只读对比模型
  在成熟度模型中是"观察"而非"治理"级别）
- **工作量**：**L-XL**（CRD spec 扩展 + 新 APPLY 端点 + Git 适配器 + canary 策略；
  推荐分 2-3 个 sprint 交付）

---

## 优先级总结

| 优先级 | 方向 | 价值 | 工作量 | 建议启动时机 |
|---|---|---|---|---|
| P0 | **① Read-Side 区域驻留** | High（合规、唯一 TODO） | M | **立即**（是一个已经识别
  的、可独立修正的安全缺口） |
| P1 | **③ 交互式流程负载测试** | Medium-High（采购需求、回归防护） | M | **下一 sprint**（将现有
  k6 基础设施扩展到 auth code 流程） |
| P1 | **④ 容量模型与扩缩容指南** | Medium（运营效率、采购评分） | M | 与 ③ 并行 |
| P2 | **⑤ GitOps 配置自愈** | Medium-High（运维成熟度） | L-XL | 方向 ② 前置 |
| P3 | **② 多区域 Active-Active** | High（可用性 SLA） | XL | 需要先完成区域联邦设计
  ADR |

---

## 与历史分析文档的交叉验证

每项缺口均通过 `grep` 对全代码库和 `docs/requirements/*.md` 做**对抗式核验**
（假设"它大概率已实现"），确认以下状态：

| 关键词 | 方向 ① | 方向 ② | 方向 ③ | 方向 ④ | 方向 ⑤ |
|---|---|---|---|---|---|
| 在历史分析中出现？ | ❌ 未出现 | ❌ 仅 ROADMAP v4.0 提及"多区域"概念但未定义 active-active | ❌ 仅 client_credentials load test 存在 | ❌ 未出现 | ❌ 仅 SSOConfigDrift 实现被列为"done"，对其扩展方向未覆盖 |
| 在 deferred-backlog 中？ | ❌ 未出现 | ❌ 未出现 | ❌ 未出现 | ❌ 未出现 | ❌ 未出现（仅记录了当前 SSOConfigDrift 的"done"状态） |
| 在代码中存在？ | ✅ 是的，但为 TODO | ❌ 仅 DR passive failover | ✅ 是的，仅 client_credentials | ❌ 无容量文档 | ✅ 是的，仅只读 diff |
| 为真缺口？ | ✅ 是 | ✅ 是 | ✅ 是 | ✅ 是 | ✅ 是 |

**结论：5 项方向全部通过对抗式核验，均为真缺口。**
