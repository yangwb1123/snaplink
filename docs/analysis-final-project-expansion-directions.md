# Snaplink SSO 项目扩展方向综合分析报告

> 基于对全代码库（1612 个 Go 源文件、789 个测试文件、~2900 行嵌入式 SPA、8350 行 OpenAPI 规范）的四轮全面扫描。
>
> 分析日期：2026-06-30 | 当前基线：ROADMAP v5.0 已全部落地后

---

## 总体评估

项目成熟度极高。ROADMAP v5.0（2026-06-11）中列出的近 30 项缺口已在 HEAD 上全部落地：

- ✅ Consent Store（memory / sqlite / redis / postgres）
- ✅ Enterprise Connections + Home Realm Discovery
- ✅ OIDC 一致性项（at_hash / AchievedACR / AMR 传播）
- ✅ 审计批量写入（BatchSink / RecordBatch）
- ✅ JWKS Body Cache（sync.Map + ETag + jitter TTL）
- ✅ 可信代理中间件（TrustedProxies）
- ✅ 客户端密钥 Hashing（bcrypt + 常量时间比较）
- ✅ DCR 审计事件（EventClientRegistered / Updated / Deleted）
- ✅ Refresh 优雅窗口（RefreshGraceStore）
- ✅ Schema 版本护栏（CheckSQLiteSchema）
- ✅ 托管登录 / Admin Console / 自助门户 SPA（go:embed）
- ✅ Fuzz 测试（7 个 Fuzz 目标）
- ✅ Benchmark（4 个基准包）
- ✅ CI 多模块覆盖 + Dependabot 扩展
- ✅ 签名密钥 etcd 自愈（supervisedKeepAlive + re-grant）
- ✅ SQLite 吊销持久化存储（跨副本持久 deny-set）
- ✅ MemoryLimiter 分片（16 shards + 采样清理）
- ✅ DPoP nonce 跨副本密钥共享（NewHMACNonceProviderWithKey）
- ✅ 优雅关闭（SIGINT/SIGTERM + 超时）
- ✅ k6 负载测试 + k8s 部署清单
- ✅ OpenTelemetry OTLP Tracing
- ✅ Prometheus 指标 + Grafana 仪表盘 + 告警规则
- ✅ SBOM 生成 + CodeQL + Trivy 扫描
- ✅ 令牌交换 act 链深度限制（MaxActChainDepth = 10）

---

## 方向一：OIDC 一致性认证——声明的功能与实际运行功能之间的差距

### 为什么需要

发现文档声明了多项功能，但至少有三处声明与运行时行为不符，会在正式的一致性测试中失败：

| 声明 | 发现条款 | 实际行为 | 风险 |
|------|----------|----------|------|
| `claims_parameter_supported: true` | `server_discovery_config.go:213`（硬编码） | id_token 路径从不根据 `RequestedClaims` 投影声明——仅将原始 JSON 作为 `_claims_` 携带（`issue_payload.go:77`）。userinfo 可以（`oidcsupport/userinfo.go:159`），但 id_token 不可以 | 一致性测试 #oidcc-claims-essential 直接失败 |
| `acr_values_supported` | `metadata.go:159` | 已填充，但 `AuthResult.AchievedACR` 并非在所有认证器路径中都能保证填充 | 一致性测试 #oidcc-acr-essential 可能失败 |
| `claims_supported` | `server_discovery_config.go:209` | 声明了 `email`、`phone`、`address` 等，但 `/userinfo` 上没有标准化的地址声明投影 | 采购安全审查中会被标记 |

### 范围

1. **修复 id_token claims 投影**（S，~60 行）：在 `issue_payload.go` 中接入 `core.ParseRequestedClaims`，对 id_token 的 essential / voluntary claims 进行投影过滤。`ParseRequestedClaims` 的解析逻辑已存在于 `shared/core/claims_param.go` 中，只需在 id_token 签发路径上调用它。
2. **声明 vs 实现对照审计**（S）：针对 `ClaimsSupported`、`ACRValuesSupported`、`PromptValuesSupported`、`TokenEndpointAuthMethodsSupported` 等声明，逐一验证服务器实际行为是否匹配。
3. **添加 `make oidc-conformance` 目标**（M）：用 Docker Compose 启动 OpenID 基金会官方测试套件，针对运行中的服务器执行自动化一致性测试。

### ROI

**工作量：S-M** | **价值：高**（采购阻断项，一致性认证是大客户 RFI 的第一道门槛）

---

## 方向二：合规报告引擎——SOC 2 证据包 + GDPR 数据映射 + DSAR

### 为什么需要

审计系统功能完善——哈希链、批量写入、多接收器、W3C 追踪上下文。但缺少预设的合规报表：

- **SOC 2 Type II**：需要审计日志覆盖控制区域的证据（谁在何时通过何种方法访问了敏感范围）
- **GDPR Art.30**：需要数据流映射（数据处理活动记录）
- **GDPR Art.15（DSAR）**：需要数据主体访问请求的导出（用户的同意授权记录、会话历史）

### 范围

1. **`GET /api/v1/admin/reports/soc2`**（M）：返回结构化 JSON/CSV 报表——按 tenant、时间段、范围、认证方法聚合。由现有审计事件提供支持，需要新的查询形状。
2. **`GET /api/v1/admin/reports/gdpr-data-map`**（M）：返回每个 tenant 的数据驻留报告——会话、用户配置文件和同意授权事件的数据存储位置、保留期限和法律依据。
3. **`GET /api/v1/admin/reports/dsar/{userID}`**（S）：导出用户的所有数据——个人资料、会话列表、同意授权记录、审计痕迹。用于数据主体访问请求。
4. **`GET /api/v1/admin/reports/active-consents/{tenantID}`**（S）：每个用户/每个客户端的同意授权导出，用于数据主体访问请求（DSAR）。

### 关键设计约束

- 报表必须尊重租户边界（租户管理员不能看到其他租户的审计数据）
- 时间范围必须分页（`?from=...&to=...&cursor=...`）
- 数据映射报表不应泄露未以明文存储的秘密（复用 `audit.Redactor` 模式）
- 所有报表端点需要 `admin:read.audit` 作用域
- 输出格式：JSON（API） + CSV（下载），可选 PDF（未来）

### ROI

**工作量：L** | **价值：高**（SOC 2 / GDPR 是企业采购的合规刚需，"技术上合规"≠"买方可验证"）

---

## 方向三：跨副本有状态 Coherence——共享原子层

### 为什么需要

这是唯一剩下的**真正的安全缺口**。在 2+ 副本的部署中：

| 状态 | 当前模型 | 问题 |
|------|----------|------|
| JTI 重放防护 | 每个副本独立（memory / SQLite / Redis） | 负载均衡可将重放的 JAR request_uri / DPoP proof / actor_token 路由到不同副本，完全绕过重放防护 |
| Refresh 令牌家族 | 每个副本独立 `DeleteFamily` | 攻击者在副本 A 上消耗令牌 → 在副本 B 上重新呈现相同令牌 → B 视为首见，家族未被击杀 |
| Session 状态 | 30s TTL + 尽力而为总线 | 滚动部署期间冷 pod 返回 404 `session_invalid` |
| 租户暂停传播 | 30s TTL + 尽力而为总线 | 存在可攻击的窗口 |

### 范围

1. **共享 JTI 重放存储**（M）：`WithSharedJTIReplayStore(redis.Store)` + 可选 `WithJTIReplayFailClosed(threshold)`——当共享后端持续超时时自动熔断到 fail-closed。
2. **共享 Refresh 家族跟踪器**（M）：`WithSharedRefreshFamilyTracker(redis.Tracker)`——跨副本的原子家族击杀（Lua `HSET` + `GETDEL`）。
3. **Session 共享后端**（M）：Redis `SessionStore` 对等体（已存在 `infrastructure/redis/session.go`，但需要跨副本读取路径）。
4. **冷启动缓解**（S）：`WithStartupGrace(warmupDuration)`——新副本启动后在 warmup 窗口内放宽 JTI 检查和 session 查找。

### 关键设计决策

- 必须区分"共享后端故障"和"合法首见"——熔断阈值 + 降级审计事件
- 跨区域部署的 JTI 时钟偏斜处理（`exp` 在签发区域的时钟域内验证）
- Shared store 的 key 命名空间碰撞预防（`jti:<issuer>:<kid>:<jti>`）

### ROI

**工作量：M** | **价值：高**（安全缺口，概率性但影响大）

---

## 方向四：企业变更管理——预检 + 审批 + 版本化配置

### 为什么需要

SOC 2 CC7.1（变更管理）要求"对影响安全的信息系统变更进行授权、记录和跟踪"。目前所有管理 API 调用都是即时生效的：

- `POST /api/v1/admin/clients` → 客户端立即生效，无预检
- `POST /api/v1/admin/tenants/{id}/suspend` → 立即生效，无确认
- "回滚" = 手动重新应用旧值
- 无"预期值 vs 实际新值 vs 审批人"的审计痕迹

### 范围

1. **变更预检端点**（M）：`POST /api/v1/admin/preflight`——捕获预期变更，返回结构化 diff（JSON Patch），需要多因素确认才能执行。
2. **配置版本化**（XL）：客户端配置、租户设置和网络策略支持版本概念（`Client.Version`、`Tenant.ConfigVersion`）。`GET /api/v1/admin/clients/{id}/versions` 返回版本历史。`POST /api/v1/admin/clients/{id}/rollback/{version}` 执行回滚。
3. **变更审批流程**（XL）：`ChangeRequest` 实体——`{ proposer, approver, status, diff, proposedAt, approvedAt }`。可选与外部工单系统集成（webhook）。
4. **增强的审计元数据**（S）：为所有管理事件增加 `{ expected_value, new_value, approved_by }` 字段。

### 关键设计约束

- 紧急绕过：P0 事件需要"立即执行，事后审批"模式
- 并发冲突：乐观锁定（`If-Match` / `If-Unmodified-Since`）
- 回滚语义："回滚到上一个已知良好状态"需要跨实体变更的正确排序
- 与现有 `cluster.Kind*Change` 总线集成

### ROI

**工作量：XL** | **价值：高**（SOC 2 CC7.1 合规 + 企业治理刚需）

---

## 方向五：运营可观测性与 SLO 框架——错误预算 + 烧毁率告警 + 部署安全

### 为什么需要

基础设施完善（`sso_*` Prometheus 指标、Grafana 仪表盘、告警规则、OTLP 追踪），但缺少：

- **错误预算跟踪**：无法回答"我们还有多少错误预算剩余？"
- **烧毁率告警**：没有"按照当前失败率，我们将在 2 小时内耗尽错误预算"的告警
- **部署安全**：没有"如果部署后 5xx 率上升 2x，自动回滚"的机制
- **SLO 仪表盘**：开箱即用的 SLA/SLO 视图（令牌签发延迟 P99 < 500ms、认证成功率 > 99.9%、JWKS 缓存命中率 > 95%）

### 范围

1. **SLO 配置文件**（M）：使用 Sloth 或等效工具定义关键 SLO（`sso:token_issuance_latency:p99<500ms`、`sso:auth_success_rate:>99.9%`、`sso:jwks_cache_hit_ratio:>0.95`），生成 Prometheus 烧毁率告警规则。
2. **错误预算 API**（S）：`GET /api/v1/admin/slo/{name}/budget`——返回剩余错误预算、消耗率、预计耗尽时间。
3. **部署安全仪表盘**（M）：Grafana 面板，显示部署前后的错误率对比、延迟变化、错误预算消耗率。与 CI/CD 流水线集成。
4. **自动回滚门禁**（L）：CI 作业部署后启动监控窗口——如果在 N 分钟内错误预算消耗超过阈值，自动触发回滚（webhook → k8s rollout undo）。
5. **发布健康检查端点**（S）：`GET /api/v1/status/deployment`——返回当前部署的版本、启动时间、错误预算状态、关键依赖的健康状况。

### 关键设计约束

- 错误预算必须按租户聚合（有界基数标签 + "other" 桶）
- 烧毁率告警窗口必须可配置（快速烧毁用 1h，慢速烧毁用 3d/30d）
- 自动回滚必须可人工覆盖（"此部署已知会增加延迟，已获批准"）

### ROI

**工作量：L** | **价值：中-高**（生产就绪的 SSO 需要回答"我的服务健康吗？"）

---

## 优先级摘要

| 优先级 | 方向 | 工作量 | 价值 | 产品上市影响 | 依赖 |
|--------|------|--------|------|-------------|------|
| P0 | ① OIDC 声明真实性 | **S** | 采购阻断 | 一致性认证标记 | 无 |
| P1 | ③ 跨副本原子层 | M | 安全缺口 | 多副本生产就绪 | Redis 对等体已存在 |
| P2 | ② 合规报告 | L | 企业销售 | SOC 2 / GDPR 验证 | 审计系统已就绪 |
| P2 | ⑤ SLO 框架 | L | 可信度 | 部署安全 | 指标系统已就绪 |
| P3 | ④ 变更管理 | XL | 治理合规 | SOC 2 CC7.1 | 管理 API 已就绪 |

### 分阶段建议

**Phase 1（当前 Sprint）**：方向① —— 修复 OIDC 声明/行为差距。这是工作量最小的采购阻断项。

**Phase 2（本月）**：方向③ + 方向⑤ 并行。安全缺口（跨副本 Coherence）和可观测性（SLO 框架）独立不阻塞。

**Phase 3（下季度）**：方向②（合规报告）。与方向④（变更管理）可打包为"企业治理包"，与现有管理 API + 审计系统深度集成。

---

## 附录：扫描覆盖范围

| 区域 | 文件数 | 扫描深度 |
|------|--------|----------|
| Go 源文件 | 1612 | 全面（grep + read） |
| 测试文件 | 789 | 全面 |
| 嵌入式 SPA | 3（~2900 行） | 完整阅读 |
| Proto 定义 | 13 | 列出 |
| 文档 | 30+ | 关键文档完整阅读 |
| CI/CD 配置 | 6 | 完整阅读 |
| 部署清单 | 10+ | 完整阅读 |
| 配置示例 | 5+ | 完整阅读 |
| ROADMAP 历史 | 7 个版本 | 完整追溯（v3.1→v5.0） |
