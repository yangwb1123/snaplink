# domains/tokenpolicy — 方向 2 需求规格：策略拒绝的审计事件化（DenyReason 从"只进日志"到"进审计流"）

Scope: expansion direction 2 from `docs/auto/domains-tokenpolicy-analysis.md` —
「策略拒绝的审计事件化——DenyReason 只进日志，不进审计流」.

Today the module's `DenyReason` doc claims it is "a metric label + audit detail
ONLY", but neither production deny path touches the audit stream:
`enforceTokenPolicy` (token scope-combo + refresh-depth seams) and
`sessionPolicyCapExceeded` (login session-cap seam) both write
`s.logger.Info` + two metric calls and nothing else, and `platform/audit`
declares no token-policy event type at all. Governance denials — precisely the
security-sensitive events AGENTS.md §3 says belong in the audit trail — are
invisible to CEF/OCSF/webhook/syslog audit sinks, the SOC2 evidence report,
and operator SIEM queries; the only aggregate is
`sso_token_policy_denials_total` labeled by reason alone, which cannot answer
"which rule blocked which client/subject".

This spec contains exactly three evidence-backed improvements:

1. Emit a `token_policy_denied` audit event at both deny seams (the missing
   emission — the root fix).
2. Register the event end-to-end: `KnownEventTypes`, `auditreport` SOC2
   classification, and CEF/OCSF sink mappings (without this the new type
   fails CI and silently lands in "Uncategorized").
3. Carry rule identity + subject into the event (`PolicyDecision.DeniedBy`,
   `policy_name`/subject metadata) so security teams can do impact analysis
   — with bounded cardinality per the platform audit invariant.

## Preserved invariants (non-negotiable)

- Oracle-safe wire contract is untouched: the HTTP response stays the generic
  `invalid_scope` / `invalid_grant` produced by `wireCodeForPolicyDeny`
  (`interfaces/sso/server_helpers.go:110`). The audit event is the ONLY new
  place the `DenyReason` detail may appear — exactly the AGENTS.md §3 pattern
  ("details only in audit") already used by `unsupported_provider` and MFA.
- Byte-identical when no policy store is wired: `tokenPolicyStore == nil`
  short-circuits before evaluation, so zero events are emitted and issuance
  behaves exactly as today (default-off).
- Fail-open stays fail-open: a `Policies()` load error returns `false`
  without any deny → no audit event, token still issued (governance-store
  outage must never block minting, and must not manufacture deny records).
- Zero emission on allow: an evaluation that does not deny records nothing.
  One deny ⇒ exactly one event (both seams; no double-emission via the
  shared helper).
- Audit metadata is added only through `audit.SetMeta` (never
  `e.Metadata = ...`); events carry W3C TraceID/SpanID via the existing
  `EventFromRequest` path, and TenantID enrichment is inherited unchanged.
  Bounded dimensions only: outcome/type/client/provider plus the closed
  `DenyReason` set and operator-authored policy names — never raw scopes,
  client lists, or request input.
- `domains/tokenpolicy` stays pure: no import of `platform/audit`. The new
  event constant/helper live in `platform/audit` (+`auditspi`), and the
  emission sits in `interfaces/sso`, mirroring how
  `RecordFAPIViolation`/`RecordRefreshRotationVelocityExceeded` are already
  called from the same layer.
- Budgets: no new top-level packages; no `layerExemptions`; no `go.mod`
  changes. `interfaces/sso/server_helpers.go` is at 493/500 lines — the deny
  site gains only a 1-line helper call (the helper itself lives in
  `platform/audit/recorder_events.go`, 354/500, which has room).
- Metrics are unchanged: `sso_token_policy_denials_total` keeps its
  reason-only labels (bounded to the closed `DenyReason` set, per
  `platform/metrics/consts.go:165-166`) — no client/subject labels ever.

## Improvement 1: 在两条拒绝路径补发 `token_policy_denied` 审计事件（缺失的发射点）

**Problem**: `DenyReason` 的契约注释自称 "metric label + audit detail ONLY"，
但审计流里根本不存在 token-policy 事件——两条生产拒绝路径
（`enforceTokenPolicy` 与 `sessionPolicyCapExceeded`）都只写
`s.logger.Info` + 两个 metric 调用，`platform/audit` 的 `event_types*.go`
与 `aliases_spi.go` 中没有任何 token-policy 事件常量。对比同包既有先例
（`EventDeviceCodeDenied`、`EventCIBADenied`、`EventRefreshTokenReuse`），
治理拒绝这类安全敏感事件在统一审计出口（CEF/OCSF/webhook/syslog 汇、
hash-chain、SOC2 evidence report）中是空白：安全团队只能翻应用日志，
且日志行不含 subject/规则名，无法回答"哪个 client 因哪种维度被拦"。
AGENTS.md §3 的 oracle-safe 表要求"细节只进 audit"，策略拒绝恰恰是审计
最该承接的治理信号，当前实现只满足了一半（进了日志，没进审计流）。

**Evidence**:
- `interfaces/sso/server_helpers.go:85-104` — `enforceTokenPolicy`：deny 分支
  （约 99-102 行）只有 `s.metrics.ObserveTokenPolicyEvaluation` +
  `s.metrics.ObserveTokenPolicyDenial` + `s.logger.Info("token policy denied
  issuance", "client", in.ClientID, "reason", ...)`，无 `s.auditor` 调用。
- `interfaces/sso/server_oauth.go:151-190` — `sessionPolicyCapExceeded`：
  同一模式（187-189 行），`s.logger.Info("token policy denied session
  creation", ...)` + 两个 metric 调用，无审计；它是独立于
  `enforceTokenPolicy` 的第二条拒绝路径（登录会话上限，经
  `server_logout.go:357` `createSession` 触发），只修一处会漏掉它。
- `platform/audit/auditspi/event_types.go:199` — `EventDeviceCodeDenied
  EventType = "device_code_denied"` 先例；`platform/audit/aliases_spi.go:118`
  对应别名；`platform/audit/recorder_events.go:80` —
  `RecordDeviceCodeDecision`（nil-safe Record 辅助函数先例，注释明确
  "every helper short-circuits on a nil recorder"）。
- `platform/audit/auditspi/event_types.go:270-271` — `KnownEventTypes` 已含
  `EventDeviceCodeApproved/Denied` 等，唯独没有任何 token-policy 条目。
- `interfaces/sso/server_token.go:168`、`internal/handler/tokengrant/token_refresh.go:116` —
  两个经 `enforceTokenPolicy` 的调用点（scope-combo 与 refresh-depth），
  全部拒绝都汇聚到 `enforceTokenPolicy` 的单一 deny 分支。

**Proposed behavior**:
1. 新增事件类型：`platform/audit/auditspi/event_types.go` 增加
   `EventTokenPolicyDenied EventType = "token_policy_denied"`（放在
   "Refresh token rotation security events" 附近的治理/拒绝分组），并在
   `platform/audit/aliases_spi.go` 增加同名列别名（保持 SPI 别名表完整）。
2. 新增 nil-safe 辅助函数 `audit.RecordTokenPolicyDenied(rec, ctx,
   clientID, subjectID, policyName, reason string)` 于
   `platform/audit/recorder_events.go`：`Type = EventTokenPolicyDenied`、
   `Outcome = OutcomeFailure`、`ClientID`/`ActorID` 分别承载 client 与
   subject（可为空）、`Reason = reason`（闭集 `DenyReason` 字符串），
   `policyName` 非空时 `SetMeta(e, "policy_name", policyName)`。
3. 在两个 deny 分支各加一行调用（emit 后仍是现有 `ctx.JSON` 写 wire
   错误，顺序不变）：
   - `enforceTokenPolicy`（server_helpers.go:99-102 处）：传
     `in.ClientID`、`in.Subject`（refresh seam 已携带；scope-combo seam
     为空则留空）、`dec.Reason`。
   - `sessionPolicyCapExceeded`（server_oauth.go:187-189 处）：传
     `clientID`、`userID`、`dec.Reason`。
4. 事件在 deny 判定成立后、返回 true 前发射一次；allow / fail-open /
   未接 store 三条路径不发射。

**Acceptance check**:
- 单元测试（`interfaces/sso/rootcov_admin_token_policies_test.go` 风格，
  `audit.NewMemorySink` 断言）：接入 `Memory*` store + Recorder 后，
  (a) scope-combo 拒绝请求恰好产生 1 条 `token_policy_denied`，字段
  `Reason=scope_combo_blocked`、`Outcome=failure`、`ClientID` 正确；
  (b) refresh-depth 拒绝（经 `EnforceRefreshDepthPolicy`）同样恰好 1 条且
  `ActorID=subject`；(c) 会话上限拒绝（`createSession` 路径）恰好 1 条且
  `ActorID=userID`；(d) allow 请求 0 条；(e) 未接 store / store 报错
  （fail-open）0 条。
- `go build ./... && go vet ./...`、
  `go test -run 'TestMaintainability_|TestArchitecture_' .` 全绿；
  `go test ./platform/audit/... ./interfaces/sso/ -race` 全绿。
- Wire 不变：拒绝响应的 body 仍是通用 `invalid_scope`/`invalid_grant`
  （对照 `wireCodeForPolicyDeny` 现有测试）。

## Improvement 2: 事件全链路登记——KnownEventTypes、SOC2 分类、CEF/OCSF 映射

**Problem**: 只加 `EventType` 常量并发射是不够的——新事件类型必须同时
完成三处登记，否则 (a) `platform/audit/auditspi/event_types_completeness_test.go`
的 `TestKnownEventTypesIsComplete` 会 AST 扫描到未登记常量并让 CI 失败；
(b) `platform/audit/auditreport/drift_test.go` 的
`TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` 会强制每个
`KnownEventTypes` 条目要么被 `controlAreaDefs` 认领、要么显式列入
uncategorized 名单——漏登记的事件会静默掉进 SOC2 evidence report 的
"Uncategorized" 桶，治理拒绝信号在合规证据里不可见；(c) CEF/OCSF 汇
（`auditsink/cef.go`、`auditsink/ocsf.go`）没有签名映射就渲染不出可读
事件，webhook 订阅过滤也会把真实事件当 typo 标记。方向一里
`EventNetPolicyApply/Delete`（cef.go:37-38、ocsf.go:85-86）与
`EventFAPIComplianceViolation`、`EventRefreshTokenReuse`（cef.go:82-85、
ocsf.go:130-133）都是"事件类型 + 全链路登记"一次到位的先例。

**Evidence**:
- `platform/audit/auditspi/event_types_completeness_test.go:33` —
  `TestKnownEventTypesIsComplete`：AST 解析 `event_types*.go` 中每个
  `EventType` 常量，缺失于 `KnownEventTypes` 即失败并点名。
- `platform/audit/auditreport/drift_test.go` — `wantUncategorizedEventTypes`
  + `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`：要求
  `controlAreaDefs` 认领 ∪ 显式 uncategorized 名单 = `KnownEventTypes`
  恰好一次。
- `platform/audit/auditreport/control_areas.go:158-169` — CC7.2 "Anomaly and
  lockout monitoring" 桶已收纳 `EventRefreshTokenReuse`、
  `EventRefreshRotationVelocityExceeded`、`EventFAPIComplianceViolation`——
  治理拒绝事件的自然归宿（同为"策略/异常导致的访问受限"证据）。
- `platform/audit/auditsink/cef.go:37-38` / `ocsf.go:85-86` —
  `EventNetPolicyApply/Delete` 映射先例；`cef.go:82-85` / `ocsf.go:130-133`
  — `EventFAPIComplianceViolation`/`EventRefreshTokenReuse` 均映射为
  `{ocsfClassAuthentication, ocsfCategoryIAM, 99, ...}`。
- `docs/observability.md` "Audit" 节（60-75 行）— 事件类型语义文档的既定
  位置（如 `feature_gates_disabled`、`auth_hook_executed` 条目）。

**Proposed behavior**:
1. `KnownEventTypes`（`event_types.go:270` 附近的分组注释区）加入
   `EventTokenPolicyDenied: {}`。
2. `controlAreaDefs` 的 CC7.2 桶加入 `audit.EventTokenPolicyDenied`（治理
   拒绝 = 访问控制/异常监控证据，与 refresh-reuse、FAPI 同类）；不放入
   uncategorized 名单。
3. `auditsink/cef.go` 增加 `auditspi.EventTokenPolicyDenied: "Token Policy
   Denied"`；`auditsink/ocsf.go` 增加
   `{ocsfClassAuthentication, ocsfCategoryIAM, 99, "Token Policy Denied"}`。
4. `docs/observability.md` Audit 节补充条目：`token_policy_denied` —— 策略
   引擎在发行/刷新/会话路径拒绝令牌时每个拒绝恰好一条；`Reason` 为闭集
   `DenyReason`；metadata 键 `policy_name`（规则名，运营配置，有界基数）；
   wire 响应保持通用 `invalid_scope`/`invalid_grant`（oracle-safe）。

**Acceptance check**:
- `go test ./platform/audit/...` 全绿：`TestKnownEventTypesIsComplete`、
  `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`、
  `TestControlAreaDefs_NoEventTypeClaimedTwice` 均通过（新常量被恰好认领
  一次，不 double-count）。
- `platform/audit/auditsink` 的 CEF/OCSF 测试覆盖新映射：CEF 渲染出的
  `token_policy_denied` 事件含可读签名 "Token Policy Denied"，OCSF 输出
  含 `class_uid`/`category_uid`/`type_uid` 正确组合。
- SOC2 report 单元测试（`auditreport/soc2_test.go` 风格）：含
  `token_policy_denied` 的 bundle 被归入 CC7.2 且 `TotalEvents` 计数正确，
  不出现在 Uncategorized 桶。
- `docs/observability.md` 已更新（`make ci` 的 docs 检查通过）。

## Improvement 3: 事件携带规则身份与主体——可归因的影响面分析（`DeniedBy` + `policy_name`/subject）

**Problem**: 即使事件发射了，当前数据面也无法回答"哪条具体规则拦了谁"：
metric `sso_token_policy_denials_total` 只有 `reason` 标签
（`metrics_token.go:85-91`，`LabelReason` 有界设计，注释明言"never on
client/subject labels"），日志行也只有 client+reason。而
`Policy.Name` 字段的注释自称 "human label for governance display + audit;
not used in matching"——声明了审计用途却全库无消费方；`Evaluate` 返回的
`PolicyDecision` 只有 `Deny`/`Reason`，不含命中的规则名。拒绝事件若无法
归因到规则与人群，安全团队只能按 reason 聚合，无法做"这条规则影响了
多少个 client/subject、波及哪些租户"的影响面分析，也无法反向定位误拦
（规则写宽/写错）的源头。

**Evidence**:
- `domains/tokenpolicy/tokenpolicy.go` — `Policy.Name` 注释 "human label for
  governance display + audit; not used in matching"（审计用途声明，零消费方）。
- `domains/tokenpolicy/evaluate.go:16-32` — `Evaluate`/`PolicyDecision`：
  无 `DeniedBy`/规则名字段；deny 时只设 `Reason`（首个命中 deny 的策略，
  policy order 确定性）。
- `platform/metrics/metrics_token.go:85-91` — `TokenPolicyDenialsTotal`
  仅 `LabelReason` 标签；`platform/metrics/consts.go:165-166` 注释确认
  reason-only 是有界设计（该约束保留，不改 metric）。
- `interfaces/sso/server_helpers.go:99-102` — deny 日志行只有
  `client`+`reason`；`sessionPolicyCapExceeded`（server_oauth.go:187-189）
  日志行也只有 client+user+active。`EnforceRefreshDepthPolicy`
  （server_helpers.go:139-149）与 session seam 已拿到 `Subject` 却未用于
  任何归因输出。

**Proposed behavior**:
1. `domains/tokenpolicy/evaluate.go`：`PolicyDecision` 增加
   `DeniedBy string`（命中首个 deny 的策略 `Name`；无 deny 时为空）。
   纯增量——与 `Reason` 在同一分支同一策略上赋值，保持确定性，不改变
   现有任一字段语义；`Evaluate` 依旧无 I/O。
2. `platform/audit/recorder_events.go`：`RecordTokenPolicyDenied` 的
   `policyName` 参数在非空时 `SetMeta(e, "policy_name", policyName)`；
   subject 落到 `ActorID`（`EventFromRequest` 已自动带 W3C trace 与
   TenantID 富化）。scope-combo seam 无 subject 时 `ActorID` 留空——
   有界且诚实，不伪造主体。
3. 两个发射点把 `dec.DeniedBy` 传给辅助函数（server_helpers.go 的
   `in.Subject`、server_oauth.go 的 `userID` 作为 subject）。
4. 有界基数约束：metadata 仅含 `policy_name`（运营配置的规则名，数量
   = 规则数，天然有界）+ 闭集 reason；绝不写入原始 scopes、client 列表
   或请求输入。metric 保持 reason-only，不动 `metrics_token.go`。

**Acceptance check**:
- `domains/tokenpolicy/evaluate_test.go` 新增用例：两条重叠规则中第二条
  触发 deny ⇒ `DeniedBy` = 第二条规则名、`Reason` 不变；首条 deny 的
  策略顺序确定性保留；无 deny 时 `DeniedBy` 为空；零值策略（Name 空）
  时 `DeniedBy` 为空字符串。
- 审计断言（沿用 Improvement 1 的 MemorySink 测试）：refresh-depth 拒绝
  事件的 metadata 含 `policy_name` 且 `ActorID=subject`；scope-combo 拒绝
  事件含 `policy_name`、`ActorID` 为空；事件 `Reason` 仍为闭集值。
- `go test ./domains/tokenpolicy/ ./platform/audit/ ./interfaces/sso/ -race`
  全绿；`make ci`（含嵌套模块、docs、module 校验）全绿。
- 回归：`sso_token_policy_denials_total` 标签集合与
  `docs/observability.md` 的 metric 表不变（reason-only）。

## Contract updates (same change, per AGENTS.md §5.6)

| 变更 | 落点 |
|---|---|
| 新审计事件类型 `token_policy_denied` | `platform/audit/auditspi/event_types.go` + `aliases_spi.go` |
| 发射辅助函数 | `platform/audit/recorder_events.go` |
| 两个拒绝点接线 | `interfaces/sso/server_helpers.go`（enforceTokenPolicy）、`interfaces/sso/server_oauth.go`（sessionPolicyCapExceeded） |
| `PolicyDecision.DeniedBy` | `domains/tokenpolicy/tokenpolicy.go` + `evaluate.go` |
| SOC2 分类 / CEF / OCSF | `platform/audit/auditreport/control_areas.go`、`platform/audit/auditsink/cef.go`、`ocsf.go` |
| 可观测性契约 | `docs/observability.md`（Audit 节新增事件条目） |

Wire 契约（openapi.yaml / error-codes.md）无变化：对外仍是通用
`invalid_scope` / `invalid_grant`。
