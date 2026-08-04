分析完成。我全局扫描了代码库（domains/anomaly 及其所有调用方：interfaces/sso 调度点、infrastructure/defaultimpl/detectors 参考实现、cmd/sso-server 装配、config、platform/metrics、domains/threataction、domains/tokenanomaly 对照），确认了三个高价值方向。注意：`docs/requirements/` 下有多份历史分析文档，但以下结论均以当前可执行代码为准。

## 1. 为 anomaly 数据模型补齐 Tenant 维度（多租户隔离是正确性缺陷，不是增强）

**问题**：Snaplink 是明确的多租户平台（`Client.TenantID`、`domains/tenant`、每租户 token 策略、`Threat.TenantID`、tenant 级审计），但 anomaly 子系统整条链路是"无租户"的：`LoginEvent`（`domains/anomaly/types.go:60`）、`LoginEntry`（`domains/anomaly/recent_login.go:69`）、`Signal`、`RecentLoginStore`、`IPFailureCounter` 均无 TenantID；调度点 `interfaces/sso/server_helpers.go` 的 `dispatchLoginAnomaly`（第 299-321 行）甚至没有 tenant 参数可传。失败路径的 SubjectID 是"尝试的用户名/手机号/邮箱"（types.go 注释自述），天然跨租户歧义。

**证据**：
- `domains/anomaly/ip_failure_counter.go`：计数器只按 `ipHash` 聚合——租户 A 的攻击者用同一出口 IP 喷洒 A 的用户名，会直接抬高租户 B 的 credential-stuffing 计数并触发其告警（跨租户信号泄漏），反过来稀释 A 自己的真实信号（假阴性）。
- `domains/anomaly/recent_login.go`：`Recent`/`Append` 仅按 SubjectID 键控——同名用户跨租户污染对方的 new-device/new-country 基线和 impossible-travel 的"上一登录点"。
- 对照面 `domains/threataction/threataction.go`：`Threat` 结构体已有 `TenantID`（执行侧是租户感知的，检测侧不是，两侧契约不对称）。
- `cmd/sso-server/anomaly.go` `buildAnomaly`：装配时拿得到 tenant 上下文但无处下发。

**为什么需要**：这是多租户 SSO 产品的检测正确性 + 数据治理问题。跨租户聚合会让"告警噪音"和"攻击稀释"同时发生，基线污染还会造成误判后的错误自动响应（已有 `WithThreatExecutor` 把 signal 转成 session 挂起/refresh family 撤销——`domains/threataction/actions.go` 的 SuspendSession/RevokeFamily）。补齐 TenantID 需同步改 `LoginEvent`→`LoginEntry` 哈希空间、两个 store 的键与索引、`NewRecorderSink` 的审计事件（tenant 元数据），是一处需在设计期定型的契约变更，越晚做迁移成本越高。

## 2. 收敛重复的检测器实现：`domains/anomaly/detect/` 是零引用的死代码且与线上实现线类型撞名

**问题**：代码库中存在两套平行的 Detector 实现。被 cmd 实际装配的是 `infrastructure/defaultimpl/detectors/`（impossible_travel、velocity、new_baseline、brute_force_shadow，见 `cmd/sso-server/anomaly.go` `buildAnomalyDetectors`）；而 `domains/anomaly/detect/`（NewDeviceDetector、NewCountryDetector、CredentialStuffingDetector、VelocityDetector、FeatureAggregator）连同 `domains/anomaly/signature/`、`domains/anomaly/fingerprint/` 三个子包，全库除自身外**零导入**（grep 验证：无任何生产代码引用 `snaplink/domains/anomaly/detect`），且 `detect/` 目录下没有任何测试文件。git 历史显示它是早期 SDLC wave 的实现，被 `defaultimpl/detectors` 取代后未删除。

**证据**：
- 撞名：`detect/velocity.go` 与 `defaultimpl/detectors/velocity.go` 都发出 `Signal.Type = "velocity_burst"`（`detect/new_device.go` 的 "new_device"、`detect/new_country.go` 的 "new_country" 同理）；`detect/credential_stuffing.go` 的 "credential_stuffing" 与 `defaultimpl` 的 "brute_force_shadow" 语义重叠但线名不同。Signal.Type 是度量标签（types.go 注释明确"keep cardinality bounded"）和 SIEM 规则分支键（`defaultimpl` 各文件声明"renaming silently breaks operator dashboards"）——两套同名不同分值的实现并存是合同漂移。
- 文档漂移：`domains/anomaly/runner.go` 包注释声称参考实现位于 `infrastructure/defaultimpl/anomaly`（实际是 `defaultimpl/detectors`），说明搬迁后遗留未清理。
- 死代码还违背 AGENTS.md 的架构纪律（"Place code by responsibility"、预算/目录纪律），`signature.Store.DistinctCount` 全库无调用者。

**为什么需要**：两套实现意味着未来任何检测逻辑改进（阈值、证据 schema、哈希方案）都面临"改哪一套"的选择，最终必然只改线上那套，死代码继续腐烂并误导 SDK 嵌入者（文档承诺 `WithAnomalyRunner` 可组合任意 Detector，嵌入者很可能发现并装配了这套"看起来官方"的 detect 包，产出与官方 metrics/SIEM 规则冲突的信号）。收敛方向：删除 `detect/`+`signature/`+`fingerprint/`，把 `defaultimpl/detectors` 提升为唯一参考实现（或反向：若 signature.Store 的 DistinctCount 能力值得保留，则合并进 defaultimpl 而非平行存在），并修正 runner.go 包注释。

## 3. 接通已配置但从未启动的 anomaly 数据保留（retention）回路

**问题**：`anomaly.retention.*` 配置（`config/config_anomaly.go` 的 `AnomalyRetentionConfig`：enabled / recent_login_age 默认 90d / ip_failure_age 默认 2h / interval 默认 1h）被解析并存入了 `anomalyRuntime`（`cmd/sso-server/anomaly.go:37-38`、`144-145` 赋值 `rt.recentLoginAge`/`rt.ipFailureAge`），但全库没有任何代码调用 `RecentLoginStore.PruneOlder` / `IPFailureCounter.PruneOlder`——grep 全仓 `.PruneOlder(` 调用点：只有接口定义与实现本身（含 `domains/anomaly/signature/store.go` 的死代码），cmd 与 interfaces/sso 均无调度循环。SQLite 实现已为保留场景建好索引并写明注释"index supports the retention scheduler's PruneOlder call"（`infrastructure/defaultimpl/sqlite/recent_login.go:20`），说明"调度器存在"是预期前提，但从未接线。

**证据**：
- `config/config_anomaly.go:88-95`（配置结构 + 默认值）↔ `cmd/sso-server/anomaly.go:144-145`（仅赋值，无消费）。
- 对照：同类保留循环在其他子系统已实现——audit/snapshot（`build_app_cluster.go` `startSnapshotRetention`）、push-approval（`build_app_selfservice.go:406-411` 启动 prune 循环）、ratelimit pruner（`serverbuildplatform/build_ratelimit_cluster.go:82`）。anomaly 是唯一"配置齐备、循环缺失"的。
- 该配置项也未出现在 `docs/config-reference.md`（grep 无 `anomaly.retention`/`recent_login_age`），违反 AGENTS.md"config knob → docs/config-reference.md"的合同更新纪律。
- 实际影响链路：`backend=sqlite` 时 `recent_logins`/`ip_failures` 无限增长；new-device/new-country 的 `Recent(ctx, subject, since, 0)`（`limit<=0 → backend cap`）随历史膨胀变慢，90 天基线窗口静默退化为"自建库以来"，检测语义漂移；IPFailureCounter 2 小时的短窗口设计（recent_login.go 注释自述）若从不裁剪，`Count` 的聚合成本随全库失败量线性上升。

**为什么需要**：这是"半成品特性"——配置、默认值、索引、注释都声称保留存在，唯独执行回路缺失，属于文档/契约与代码的漂移（AGENTS.md 要求"满足更严格的契约并上报"）。接通方式明确（参照 push-approval 的 `RunPushApprovalPrune` 模式在 `startBackgroundWorkers` 挂一个按 `Interval` 调 `PruneOlder` 的循环），同时补齐 config-reference 文档，属低成本高确定性的修复，能直接避免部署在数周后遭遇无界增长。

---

**补充观察（未列入前三，供参考）**：`Runner.inspect` 的 `inspectTimeout` 是"每事件一个 ctx，所有 detector 共享"（`domains/anomaly/runner.go`），一个慢 detector 会蚕食同事件其他 detector 的预算，与注释宣称的"per-detector"语义不符；此外 detector 链的执行顺序是承重的（velocity/new_device 依赖 impossible_travel 先写入 store，`defaultimpl/detectors/velocity.go` 注释自述"impossible-travel owns the writes"），但没有任何机制保证或校验顺序，若嵌入者重排 detector 列表会静默失效——这两点可并入方向 2 的收敛工作中一并设计（如把"写历史"提升为 runner 的独立职责而非某个 detector 的副作用）。
