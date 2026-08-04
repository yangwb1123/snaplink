全局扫描完成。`domains/tokenpolicy` 是"令牌治理第二阶段"的纯函数策略引擎：`Evaluate`（确定性、无 I/O）＋ `Store` SPI（仅 `Policies()`，memory COW 实现）＋ YAML 加载，通过四个接缝接入：`ClampingIssuer`（TTL 钳制装饰器，`server_helpers.go` issuerForClient）、`/token` 作用域组合门（`server_token.go:168`）、刷新深度门（`internal/handler/tokengrant/token_refresh.go:116`）、登录会话上限（`server_oauth.go sessionPolicyCapExceeded`），外加 introspection 的 `RenewExceeded/RenewAt`。对比同层兄弟域（conditionalaccess 严格 YAML、threataction/tokenexchange 的 sqlite+admin 写入、audit 事件体系）后，以下三个方向价值最高。

## 方向一：治理生命周期闭环——可写管理 API、持久化后端与规则校验

**问题**：tokenpolicy 目前是"启动时灌入、只读展示"的静态治理面。`Store` 接口只有 `Policies()`，唯一的写入口 `memory.Store.Replace`（`domains/tokenpolicy/memory/store.go`）在全库无任何调用方（无配置热重载、无 admin 写端点），admin 侧仅有 `GET /api/v1/admin/token-policies`（`admin.go`、`openapi.yaml` 6836 行）。同时规则加载无校验：`yaml.go` 用非严格 `yaml.Unmarshal`（`conditionalaccess/yaml.go` 用 `DisallowUnknownField` 严格解析，两者漂移），`MaxTTL > 发行方默认 TTL` 的配置会被静默吞掉（`evaluate.go clampTTL` 的注释自认"engine cannot see that default"），`RequireRenewAfter>1`、负深度等非法值也不拦截。

**证据**：`domains/tokenpolicy/memory/store.go`（`Replace` 无调用方）、`domains/tokenpolicy/admin.go`（GET-only）、`domains/tokenpolicy/yaml.go` vs `domains/conditionalaccess/yaml.go`（严格性漂移）、`config/config_snapshot.go` `TokenPolicyConfig`（仅 File/Policies 二选一）、`docs/openapi.yaml` 6836 行。

**为什么需要**：治理规则的典型生命周期是"评估→灰度→调整→回滚"，纯静态配置迫使运维在每次调策略时改配置、重启/重推全部副本，且多副本各自持有独立内存快照，无单点真相。tokenexchange（sqlite）、threataction（sqlite）都已有持久化先例；缺失的 PUT/DELETE 端点 + 持久化 + 启动/写入时双重校验（含 MaxTTL vs 发行方默认的告警）是把这个模块从"配置项"升级为"治理产品"的最小闭环，也是后续方向二、三落地的地基。

## 方向二：策略拒绝的审计事件化——DenyReason 只进日志，不进审计流

**问题**：`tokenpolicy.go` 的注释宣称 DenyReason 是"metric label + audit detail ONLY"，但实际拒绝路径只写 `s.logger.Info` + metrics（`server_helpers.go enforceTokenPolicy`），`platform/audit` 中不存在任何 token-policy 事件类型——对比同域已有 `EventDeviceCodeDenied`、`EventCIBADenied`（`recorder_events.go`）、`EventNetPolicy*`，治理拒绝这类安全敏感事件在审计体系中是空白的。结果是：CEF/OCSF/webhook/syslog 审计汇（`platform/audit/auditsink/`）看不到"哪个 client 因哪种维度被拦"，安全团队只能翻应用日志，且 `sso_token_policy_denials_total` 只有 reason 标签（`metrics_token.go`），无法定位到具体规则/client 做影响面分析。

**证据**：`interfaces/sso/server_helpers.go` `enforceTokenPolicy`（`logger.Info` + 两个 metric 调用，无 `audit.Recorder`）、`platform/audit/aliases_spi.go`（无 token-policy 事件常量）、`platform/audit/recorder_events.go`（`EventDeviceCodeDenied`/`EventCIBADenied` 先例）、`metrics_token.go` 标签设计。

**为什么需要**：AGENTS.md §3 的 oracle-safe 契约要求"细节只进 audit"，策略拒绝恰恰是审计最该承接的治理信号——谁、何时、被哪条规则以什么原因拒绝。补齐 `token_policy_denied` 事件（bounded 原因集 + client/subject，与 `audit.SetMeta`/auditreport 分类一致）让拒绝进入统一审计出口与 SIEM，是合规与安全运营的直接诉求，成本低且完全不动 wire 契约（对外仍是通用 invalid_scope/invalid_grant）。

## 方向三：租户维度与主体感知的选择器——治理单元从"客户端"升级到"租户/人群"

**问题**：`Policy` 选择器只有 `ClientID`（精确匹配）＋ `Scopes`（`tokenpolicy.go`、`evaluate.go matches()`），既无 `TenantID`，也无 subject/group 维度，client_id 也不支持通配。而 Snaplink 是多租户平台：`server_helpers.go` 有 `tenantTokenStrategies` 租户级密钥隔离、tenant 域负责挂起/驻留、信任边界按租户 XFH 收敛。现实运营中"该租户所有客户端 TTL 压到 5 分钟""某服务账号人群禁止 refresh 轮换超过 N 次""租户 A 禁止 admin:* 与 openid 组合"这类需求，现在只能逐 client 枚举规则或写全局默认规则——前者不可维护，后者会误伤其他租户。`sessionPolicyCapExceeded` 与刷新深度门虽然拿到了 `Subject`，但选择器根本不用它。

**证据**：`domains/tokenpolicy/tokenpolicy.go` `Policy` struct（无 TenantID/Subject 选择器）、`domains/tokenpolicy/evaluate.go` `matches()`（仅 client+scopes）、`interfaces/sso/server_helpers.go` `issuerForClient`/`sessionPolicyCapExceeded`（平台已有租户与主体上下文却未传入）、`config/config_snapshot.go` `TokenPolicyConfig`（无按租户配置段）。

**为什么需要**：治理规则的价值在于"用最少规则覆盖最大合规面"。租户是 SaaS 身份平台天然的分层单元——加一个 `tenant_id`（空=全局默认，租户规则覆盖全局规则，保持现有"只收紧不放宽"语义）就能把规则数从 O(客户端数) 降到 O(租户数)，且与平台既有的租户密钥隔离、租户挂起、租户级条件访问（conditionalaccess）叙事一致；再补 subject/group 通配即可支持服务账号与人类用户的差异化策略。这是把 tokenpolicy 从"单租户玩具"推向"多租户产品"的分水岭，纯增量扩展 `Policy` struct 与 `Evaluate`，不破坏任何现有语义。
