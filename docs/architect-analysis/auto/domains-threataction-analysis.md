已完成全局扫描（`domains/threataction/` 全部 8 个源文件、`domains/anomaly/runner.go`、`domains/tokenanomaly/detector.go`、`cmd/sso-server/anomaly.go`、`cmd/sso-server/serverbuildplatform/build_governance.go`、`interfaces/sso/accessors_threat.go`、`config/config_snapshot.go`、`platform/metrics`、`docs/feature-matrix.md`/`docs/openapi.yaml`）。以下是 3 个最高价值的改进方向。

## 1. 策略存储与限流的持久化、多副本一致性（接线已存在但无人使用的 SQLite store）

**问题**：威胁响应策略是安全控制面，但当前 `BuildThreatAction` 硬编码内存 store：运行时通过 admin CRUD 新增/修改的策略在进程重启后全部丢失、静默回滚到 YAML 种子值；多副本部署时每个副本持有独立的策略视图和独立的进程内限流器，同一威胁在不同副本上可能命中不同策略、限流窗口也按副本分裂。

**证据**：
- `domains/threataction/sqlite/policy_store.go`：完整的 SQLite 后端（`List/Get/Put/Delete` + `migrate` + 全量测试），其包注释明言 "persists them so a threat-response policy list survives a redeploy and is shared across replicas"——但全仓库无任何引用方（grep 仅命中自身与无关注释），是纯死代码。
- `cmd/sso-server/serverbuildplatform/build_governance.go` `BuildThreatAction`：无条件 `threatactionmemory.NewThreatPolicyStore()`，无 backend 选择逻辑。
- `config/config_snapshot.go` `ThreatActionConfig.Policies` 注释："seeds the in-memory ThreatPolicyStore"。
- `domains/threataction/registry.go`：`rateLimit map[string]*rateLimitEntry` + `allow()`，限流状态仅存在于单进程内存，`rateLimitSweepThreshold` 的清扫也是进程内事务。

**为什么需要**：检测→响应是 ITDR 的核心价值主张，策略漂移直接等于安全退化。重启后策略静默丢失会让运营者以为"已配置的挂起规则仍在生效"；多副本不一致意味着对同一攻击者的同一行为，A 副本执行 suspend、B 副本判定 noop——这在安全审计和合规上不可接受。仓库已有成熟先例可循（`domains/connections/sqlite`、`permissions/sqlite`、`configaudit` 的变更追踪），把 SQLite 后端接入 `BuildThreatAction`（如 `threat_action.backend: memory|sqlite`）并顺带解决跨副本限流（共享窗口或至少可配置），是投入产出比最高的一步。

## 2. 多动作响应 Playbook 与显式优先级（组合动作 + 排序语义）

**问题**：包级文档承诺 "Multiple actions can result from one Threat (suspend session AND notify admin)"，但数据模型和执行器都只能产出**单个**动作：`ThreatPolicy` 只有一个 `Action` 字段，`matchPolicy` 按 name 字母序 first-match-wins，一次 `Execute` 返回一个 `ActionResult`。运营者无法表达"critical 级 impossible_travel → suspend + revoke 家族 + notify + step_up_mfa"这类真实阶梯式 playbook；策略间的命中顺序由名字排序偶然决定，而非操作者意图；`WithDefaultAction` 仅在"零策略匹配"时生效，无法作为 catch-all 与具体策略叠加。

**证据**：
- `domains/threataction/threataction.go`：`Threat`/`ActionResult` 文档中的 "Multiple actions can result from one Threat" 与实际模型矛盾；`Action` 是单值类型。
- `domains/threataction/policy.go`：`ThreatPolicy.Action Action`（单值字段）。
- `domains/threataction/registry.go`：`matchPolicy` 注释 "first-match wins, ordered by name"；`Execute` 返回单一 `ActionResult`；`defaultPolicy`/`WithDefaultAction` 只在无匹配时兜底。

**为什么需要**：真实响应场景是组合与分级的——同一威胁通常需要"止血 + 通知 + 后续验证"三件事，且按严重度分级（critical 直接 suspend，warn 仅 step-up）。单动作 + 字母序命中使安全运营者无法表达意图，策略增多后行为不可预测（新增一条 "a_xxx" 策略可能悄悄改变既有策略的命中）。这是从"演示级 demo"走向"可运营产品"的核心能力缺口：建议将 `Action` 扩展为有序动作列表（或允许多策略合并执行），并引入显式 `priority`/`order` 字段替代 name 排序。

## 3. 响应可观测性与反馈闭环（指标、执行历史、真实通知）

**问题**：`ThreatExecutors` 文档宣称错误 "logged, metric'd"，但实现里**没有任何 metrics 出口**——无计数器、无回调选项（对比 `anomaly.WithMetricsCallbacks` 的完整模式），`platform/metrics` 中也没有任何 threat 相关指标；rate-limited、no handler、执行失败只有日志和 audit 事件，无法聚合告警。同时 `ActionNotify` 名不副实：`NotifyExecutor.Execute` 直接返回 OK，不发送任何通知，而平台已有现成的 `notification.Router`/inbox/SSE 通道未被接线；admin 面只有策略 CRUD，无执行历史/状态查询端点，取证只能从散落 audit 事件拼图。

**证据**：
- `domains/threataction/registry.go`：包注释 "logged, metric'd, and the next threat proceeds"，但 `ThreatExecutors` 无 metrics 字段/选项，`recordAudit` 是唯一观测出口。
- `platform/metrics/metrics.go`：grep 无任何 threat 计数器（对比 `AnomaliesDetectedTotal` 等）。
- `domains/threataction/actions.go`：`NotifyExecutor.Execute` 仅构造 `ActionResult{OK:true}`，零副作用。
- `interfaces/sso/accessors_threat.go`：`WithNotificationRouter`/`NotificationBroker` 已存在但未接入 `NotifyExecutor`。
- `domains/threataction/admin.go`：仅有 `HandleAdminList/Get/Put/DeletePolicy`，无执行历史 API。

**为什么需要**：安全响应子系统没有指标就无法回答三个运营必答题——"响应是否真的发生了""限流是否吞掉了动作""哪些策略在失效执行"；`docs/observability.md` 也完全没有威胁响应的可观测性章节。而 "notify" 动作的虚假成功会让策略作者误以为管理员已收到告警，这是安全事故（而非事故响应）级别的误导。补齐三类能力：响应指标（策略命中、动作成功/失败/限流计数）、动作执行历史（可查、可审计）、将 `notify` 接到真实通知管道（audit webhook 之外至少复用 inbox/SSE），才能使该模块从"能执行动作"升级为"可证明、可运营、可告警"的 ITDR 产品组件。
