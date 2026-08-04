# domains/tokenpolicy — 方向 3 需求规格：租户维度与主体感知的选择器（治理单元从"客户端"升级到"租户/人群"）

Scope: expansion direction 3 from `docs/auto/domains-tokenpolicy-analysis.md` —
「租户维度与主体感知的选择器——治理单元从"客户端"升级到"租户/人群"」.

Today the policy SELECTOR is only `ClientID`（精确匹配）＋ `Scopes`（超集 +
尾部 `*` 前缀通配）：`matches()`（`domains/tokenpolicy/evaluate.go`）对
client_id 做字符串全等比较，`Policy`/`PolicyInput` 既无 `TenantID` 也无
subject/group 维度，`PolicyInput.Subject` 在 refresh 与会话两条接缝已被填充
却从未参与匹配。Snaplink 是多租户平台（`Client.TenantID`、租户中间件、
`tenantTokenStrategies` 租户级密钥隔离、`TenantUserStore` 成员角色），现实
运营中"该租户所有客户端 TTL 压到 5 分钟""服务账号禁止 refresh 轮换超过 N
次""租户 A 禁止 admin:* 与 openid 组合"这类需求，现在只能逐 client 枚举
规则或写全局默认规则——前者不可维护，后者误伤其他租户。

本规格含恰好三个证据支撑的改进：

1. `TenantID` 选择器：`Policy`/`PolicyInput` 增加租户维度，四条接缝
   （ClampingIssuer、scope-combo 门、refresh 深度门、会话上限门）把租户
   语境传入求值器；空 = 全局默认规则，租户规则与全局规则共存，沿用现有
   "每维度最严者胜"的组合语义（只收紧不放宽）。
2. 主体感知选择器：`Subject` 精确/通配匹配 ＋ 租户角色
   （member/admin/guest）维度，让"服务账号 vs 人类用户""租户 A 管理员"
   这类人群级差异化策略成为可能。
3. `ClientID` 通配匹配 ＋ 新选择器字段的严格 YAML 校验：租户规则可覆盖
   命名约定下的客户端群；拼写错误的选择器字段在加载期失败告警，而不是被
   非严格 YAML 静默丢弃后把"租户规则"降级成"全局规则"（空 tenant_id =
   全租户生效，属静默安全扩张）。

## Preserved invariants（不可协商）

- Oracle-safe wire 契约不变：拒绝响应仍是 `wireCodeForPolicyDeny`
  （`interfaces/sso/server_helpers.go:110-115`）产出的通用
  `invalid_scope`/`invalid_grant`。新选择器只改变"哪条规则命中"，不改变
  "命中了之后对外说什么"。租户信息是策略求值的输入，绝不进入拒绝响应体。
- 单租户部署字节级向后兼容：`PolicyInput.TenantID` 为零值时，任何非空
  `tenant_id` 规则都不命中，全局规则（空 `tenant_id`）行为与今天完全一致；
  未接 store / store 报错仍然 FAIL OPEN（发行照常）。
- 组合语义不变：匹配是"加性"的——一个请求同时命中其租户的租户规则与所有
  全局规则；每维度最严者胜（`Evaluate` 现有 `clampTTL`/`stricterRenew` +
  任一 deny 即拒），因此租户规则只能收紧全局规则放行的上限，绝不能放宽
  （分析文档"租户规则覆盖全局规则，保持现有'只收紧不放宽'语义"的落点）。
- `domains/tokenpolicy` 保持纯函数、无 I/O、无新依赖：租户/角色解析发生在
  调用方（`interfaces/sso`），域层只接收字符串选择器；不 import
  `domains/tenant`、`platform/audit` 或任何存储。
- 预算约束：不新增顶层/内部包，不加 `layerExemptions`；`Policy` 增加字段
  是纯增量（`tokenpolicy.go` 160 行、`evaluate.go` 176 行，均有余量）。
  `interfaces/sso/server_helpers.go` 已 493/500 行——租户透传只改
  `EnforceRefreshDepthPolicy` 签名（调用点在 `token_refresh.go`，client 在
  作用域内），不在该文件新增逻辑。`core.Subject.TenantID` 在既有
  `ClientID` 的同一批发行调用点盖章（与 `ServingRegion` 的 mint-time 盖章
  先例一致），不改发行语义。
- 失败模式沿用 §3：角色解析（`TenantUserStore`）报错/未接时按"无角色"
  处理（fail-open，仅角色选择器不命中，subject 精确/通配规则不受影响）。

## Improvement 1: `TenantID` 选择器——治理单元升级到租户维度

**Problem**: `Policy` 的选择器只有 `ClientID`（精确）＋ `Scopes`，
`PolicyInput` 连租户字段都没有，而平台处处以租户为治理边界：`Client.TenantID`
把客户端绑定到租户（`shared/core/types.go:39-47`）、租户中间件按 host 解析
租户、`issuerForClient` 用 `tenantTokenStrategies` 做租户级密钥隔离
（`server_helpers.go:37-40`）、`TenantScopedClientStore.ListByTenant`
（`shared/core/spi.go:93`）是租户维度存储访问的先例。结果"租户 A 所有客户端
TTL ≤ 5 分钟""租户 A 禁止 admin:*+openid 组合"只能写成逐 client 枚举
（规则数 O(客户端数)，新客户端上线即漏配）或全局规则（误伤租户 B）。
配置面同样没有租户段：`TokenPolicyConfig` 只有 `File`/`Policies` 二选一
（`config/config_snapshot.go:298-310`），租户维度只能进规则字段本身。

**Evidence**:
- `domains/tokenpolicy/tokenpolicy.go:53-98` — `Policy` struct：选择器仅
  `ClientID` + `Scopes`（"Empty = every client (a fleet-wide default rule)"），
  无 `TenantID`。
- `domains/tokenpolicy/tokenpolicy.go:112-127` — `PolicyInput`：无
  `TenantID` 字段，四条接缝无处传租户。
- `domains/tokenpolicy/evaluate.go:53-63` — `matches()`：
  `p.ClientID != "" && p.ClientID != in.ClientID` 精确全等，无租户维度。
- `interfaces/sso/server_helpers.go:39-40` — `tenantTokenStrategies[c.TenantID]`
  租户级密钥隔离先例：平台治理单元已是租户，唯独 tokenpolicy 选择器不是。
- `shared/core/types.go:39-47` — `Client.TenantID`："binds this client to one
  tenant in multi-tenant deployments"；`shared/core/spi.go:93` —
  `TenantScopedClientStore.ListByTenant` 租户维度存储访问先例。
- `domains/tenant/middleware.go:138-143` — `FromHandlerContext`：租户中间件
  把解析结果 stash 在 `HandlerContext`，`interfaces/sso` 各接缝可得。
- `internal/handler/tokengrant/token_refresh.go:116` —
  `d.EnforceRefreshDepthPolicy(ctx, client.ID, info.UserID, ...)`：`client`
  在作用域内（`*core.Client` 带 `TenantID`），只是没传。
- `interfaces/sso/server_token.go:168` — `s.denyTokenScopeCombo(ctx,
  client.ID, scopes)`：同前，`client` 在 `dispatchTokenGrant` 作用域内。
- `domains/tokenpolicy/clamp_issuer.go:44-52` — `ClampingIssuer.Issue` 只取
  `subject.ClientID`；`shared/core/types_token.go:161-170` — `core.Subject`
  无 `TenantID`（TTL 钳制路径今天连租户都看不到）。

**Proposed behavior**:
1. `Policy` 增加 `TenantID string`（`yaml:"tenant_id,omitempty"` +
  `json:"tenant_id,omitempty"`）；空 = 全局默认规则（对任意租户生效，向后
  兼容现有语义）。`PolicyInput` 增加 `TenantID string`（零值 = 无租户语境，
  单租户部署字节级不变）。
2. `matches()` 增加租户判断：`p.TenantID != "" && p.TenantID != in.TenantID`
  ⇒ 不命中。组合语义不变：请求命中"本租户规则 ∪ 全局规则"，每维度最严者
  胜——租户规则天然只能收紧全局上限，绝不放宽（`Evaluate` 现有逻辑零改动）。
3. 四条接缝透传租户（全部在调用方取值，域层零 I/O）：
   - `enforceTokenPolicy`/`denyTokenScopeCombo`：`dispatchTokenGrant`
     （server_token.go:168）传 `client.TenantID`。
   - `EnforceRefreshDepthPolicy`：签名增加 `tenantID string` 参数，
     `token_refresh.go:116` 调用点传 `client.TenantID`（helpers 文件只改
     签名，不新增逻辑，守住 500 行预算）。
   - `sessionPolicyCapExceeded`（server_oauth.go:177-185）：调用点
     （`createSession`，client 在作用域内）传 `client.TenantID`。
   - `ClampingIssuer.Issue`：`core.Subject` 增加 `TenantID`（mint-time 字段，
     与 `ServingRegion` 同批语义），在既有盖章 `ClientID` 的 ~10 个发行
     调用点一并盖章（`token_authcode.go:118`、`token_client_credentials.go:40`、
     `token_refresh.go:247`、`token_device.go:82`、`token_ciba.go:99`、
     `token_jwt_bearer.go:95`、`token_saml2_bearer.go:103`、
     `token_exchange_stages.go:390`、`server_login.go:112`、
     `server_native_sso.go:190`——每个调用点 `client` 均在作用域内），
     `clamp_issuer.go` 把 `subject.TenantID` 填入 `PolicyInput`。
4. 管理读 API 无新增端点：`HandleAdminPolicies` 本就逐字序列化 `Policy`，
   新字段自动出现在 `GET /api/v1/admin/token-policies` 响应中；同步更新
   `docs/openapi.yaml:6836` 的响应 schema。

**Acceptance check**:
- `domains/tokenpolicy/evaluate_test.go` 新增表驱动用例：
  (a) `Policy{TenantID:"ta", MaxTTL:5m}` 对 `PolicyInput{TenantID:"ta"}`
  命中、对 `{TenantID:"tb"}` 与 `{TenantID:""}` 不命中；(b) 租户规则 +
  全局规则同时命中时取最严（如全局 MaxTTL 10m + 租户 5m ⇒ 5m；反向组合
  租户 10m + 全局 5m ⇒ 仍 5m，证明租户规则不能放宽）；(c) 全局规则对任意
  租户输入行为与旧版逐字节一致（回归对照现有 `TestEvaluate_SelectorMatching`）。
- 接缝级测试（`interfaces/sso`，Memory store 风格）：租户 A 的 client 请求
  命中 `tenant_id:"ta"` 的 scope-combo 拒绝 → 通用 `invalid_scope`；同规则
  对租户 B 的 client 零影响（allow）；refresh 深度门在 `EnforceRefreshDepthPolicy`
  传 `client.TenantID` 后租户规则正确生效。
- TTL 钳制：`ClampingIssuer` 测试（`clamp_issuer_test.go` 扩展）证明
  `subject.TenantID` 盖章后租户 MaxTTL 只钳制本租户客户端；`core.Subject`
  无 TenantID（旧调用点漏盖章）时行为与今天一致（规则不命中、发行照常）。
- `go build ./... && go vet ./...`、`go test -run 'TestMaintainability_|TestArchitecture_' .`
  全绿；`go test ./domains/tokenpolicy/ ./interfaces/sso/ -race` 全绿。
- `docs/openapi.yaml` admin token-policies schema 已含 `tenant_id` 可选字段
  （`make ci` 的 OpenAPI 检查通过）。

## Improvement 2: 主体感知选择器——Subject 精确/通配 ＋ 租户角色，区分服务账号与人群

**Problem**: `PolicyInput.Subject` 注释自称 "the resource owner (may be empty
for client_credentials)"，refresh 深度门（`EnforceRefreshDepthPolicy`）与会话
上限门（`sessionPolicyCapExceeded`）都已填充它，但 `matches()` 根本不用
subject——`MaxRefreshDepth`/`MaxActiveSessions` 对所有主体一视同仁。
"某服务账号禁止 refresh 轮换超过 N 次""租户 A 管理员会话上限收紧"
"人类用户与机器身份差异化 TTL"这类需求只能按 client 枚举。平台已有主体
维度先例：`TenantUserStore` 是 "is this user in this org" 的单一事实源，
`TenantRole` 有 member/admin/guest 三个有界取值（`shared/core/tenant_user.go:
9-26`），且注释明确 SCIM groups 是 client-scoped 的应用角色、与组织成员
正交——所以人群维度应落在租户角色而非 SCIM 组上。

**Evidence**:
- `domains/tokenpolicy/tokenpolicy.go:117-118` — `PolicyInput.Subject`：
  "may be empty for client_credentials"——字段已存在、被接缝填充、选择器
  零消费。
- `domains/tokenpolicy/evaluate.go:53-63` — `matches()`：只看
  ClientID+Scopes，subject 不参与；`denyReason` 同理。
- `interfaces/sso/server_helpers.go:139-149` — `EnforceRefreshDepthPolicy`
  把 `subject` 传入 `PolicyInput`（refresh 接缝已有主体语境）；
  `interfaces/sso/server_oauth.go:177-185` — `sessionPolicyCapExceeded` 传
  `Subject: userID`（会话接缝已有主体语境）。
- `shared/core/tenant_user.go:9-26` — `TenantRole` 有界枚举
  （member/admin/guest）＋ `TenantUserStore` 单一事实源注释。
- `interfaces/sso/server_logout.go:322-330` — `s.tenantUserStore.Get(rctx,
  client.TenantID, userID)` 调用先例：`interfaces/sso` 已持有
  `TenantUserStore`，角色解析不需要新依赖。
- `domains/tokenpolicy/evaluate.go:69-78` — `scopePresent` 尾部 `*` 前缀通配
  先例：subject 通配复用同一语义，域内一致性。

**Proposed behavior**:
1. `Policy` 增加两个选择器字段（纯增量，零值 = 不约束）：
   - `Subject string`（`yaml:"subject,omitempty"`）：精确主体 ID；尾部 `*`
     为前缀通配（与 `scopePresent` 同一语义）。空 = 任意主体。
   - `SubjectRoles []string`（`yaml:"subject_roles,omitempty"`）：要求主体的
     租户角色命中其一（闭集 `member`/`admin`/`guest`，取值校验见
     Improvement 3）。空 = 不限角色。
   `PolicyInput` 增加 `SubjectRoles []string`（调用方解析后传入）。
2. `matches()` 增加：`p.Subject` 非空时按精确/前缀通配匹配
   `in.Subject`；`p.SubjectRoles` 非空时要求与 `in.SubjectRoles` 有交集。
   两条接缝原有输入不丢失——refresh 接缝只传 `Subject`（`tokengrant` 包无
   角色解析能力，角色为空则角色选择器不命中，subject 规则照常生效）；
   会话接缝在 `s.tenantUserStore` 已接时用 `Get(ctx, client.TenantID, userID)`
   解析角色填入 `SubjectRoles`，store 未接/报错时按无角色处理（fail-open，
   只影响角色选择器）。
3. `MaxActiveSessions` 语义不变（仍是 per-subject 计数），但选择器现在可以
   把它限定到"该租户的管理员人群"或"该服务账号"，人群级差异化由选择器
   承担，维度本身零改动。

**Acceptance check**:
- `evaluate_test.go` 新增用例：(a) `Subject:"svc-*"` 命中 `"svc-payments"`、
   不命中 `"alice"`；(b) `SubjectRoles:["admin"]` 命中
   `SubjectRoles:["member","admin"]`、不命中 `["member"]`；(c) 角色为空输入
   时角色选择器不命中（fail-open 语义）；(d) 空 `Subject`+空 `SubjectRoles`
   的规则对任意主体行为与旧版一致。
- 会话接缝集成测试（Memory store + `TenantUserStore` memory 实现）：
   租户 ta 下角色 admin 的用户触达 `MaxActiveSessions` 上限被拒
   （`access_denied`），同租户 member 角色不受影响；`TenantUserStore` 未接
   时角色规则不命中、会话照常创建（fail-open）。
- refresh 接缝：`Subject:"svc-*"` 的 `MaxRefreshDepth` 规则对
   `svc-payments` 家族在深度达到上限时拒绝（wire 仍为通用
   `invalid_grant`），对人类主体零影响。
- 回归：`go test ./domains/tokenpolicy/ ./interfaces/sso/ -race` 全绿；
  单租户/未盖章 subject 场景与旧版字节一致。

## Improvement 3: `ClientID` 通配匹配 ＋ 新选择器字段的严格 YAML 校验（防"拼写错误变全局规则"）

**Problem**: 选择器对 client_id 只做全等比较（`matches()`：
`p.ClientID != in.ClientID`），租户级规则无法按命名约定覆盖客户端群——
"租户 A 所有 payments-* 客户端 TTL 5 分钟"仍需逐 client 枚举，与方向目标
"用最少规则覆盖最大合规面"相悖。更严重的是加载面：`ParseYAML` 用非严格
`yaml.Unmarshal`（`tokenpolicy/yaml.go:19-24`），未知字段被静默丢弃——在
方向三新增 `tenant_id`/`subject`/`subject_roles` 之后，拼错字段
（如 `tennat_id: ta`）会让规则被解析成"空 tenant_id 的全局规则"：运营者
以为只约束租户 ta，实际对全平台生效。这是新增租户选择器引入的独特静默
安全扩张面（conditionalaccess 同层兄弟域已用 `DisallowUnknownField` 严格
解析，两者漂移）。通配符本身也需要语法校验：裸 `*` 与空选择器等价但混淆
两种拼写，前缀通配应为非空前缀。

**Evidence**:
- `domains/tokenpolicy/evaluate.go:53-63` — `matches()`：client_id 精确全等，
  无通配；对比同文件 `scopePresent`（69-78 行）已有尾部 `*` 前缀通配先例。
- `domains/tokenpolicy/yaml.go:19-24` — `yaml.Unmarshal(data, &f)` 非严格；
  对照 `domains/conditionalaccess/yaml.go:33` —
  `yaml.UnmarshalWithOptions(data, &doc, yaml.DisallowUnknownField())`
  严格解析，同层兄弟域已收敛到严格模式（分析文档点名的漂移）。
- `domains/tokenpolicy/evaluate.go:60-63` — 空 `ClientID` = "every client"
  的既有语义：未知字段被丢弃后规则静默降级为全局规则，正是"拼写错误 ⇒
  全租户生效"的机制。
- `docs/openapi.yaml:6845-6851` — admin 读 API 描述仅声明 client_id/scopes
  选择器；`docs/config-reference.md:588` — 规则 schema 行同样只列
  `client_id`/`scopes` 选择器（两份契约需同步新字段）。

**Proposed behavior**:
1. `matches()` 的 client_id 判断改为：尾部 `*` 前缀通配（复用
   `scopePresent` 同一实现，抽为共享 helper `prefixOrExact(a, want)`），
   非通配保持精确全等；空 = 任意客户端不变。
2. `ParseYAML` 改用 `yaml.UnmarshalWithOptions(..., yaml.DisallowUnknownField())`
   严格解析（与 conditionalaccess 对齐），并对选择器字段做加载期校验：
   - 通配符（`client_id`/`subject`）必须形如非空前缀 + 尾部 `*`；裸 `*`
     拒绝（"任意"的唯一拼法是空字段）。
   - `subject_roles` 取值必须属于闭集 `{member, admin, guest}`（对齐
     `core.TenantRole` 三值；域层以字符串常量校验，不 import
     `domains/tenant`）。
   - 校验失败 ⇒ 解析报错，启动/写入即失败（fail loud），绝不静默丢弃。
3. 内联配置路径（`TokenPolicyConfig.Policies`，经 config 快照）同样经过
   严格解析校验——`tokenpolicy` 暴露一个 `Validate([]Policy) error` 纯函数，
   `ParseYAML` 与 config 加载共用。
4. 契约同步：`docs/openapi.yaml:6836` 响应 schema 增加 `tenant_id`、
   `subject`、`subject_roles` 可选字段；`docs/config-reference.md:588` 规则
   schema 行补充新选择器与通配语义。

**Acceptance check**:
- `evaluate_test.go` 新增用例：`ClientID:"payments-*"` 命中
   `"payments-checkout"`、不命中 `"billing"`；非通配精确匹配回归不变。
- `yaml_test.go` 新增用例：(a) `tennat_id: ta`（拼错）⇒ 解析报错，明确
  指出未知字段；(b) `client_id: "*"` ⇒ 报错；(c) `subject_roles: ["owner"]`
   ⇒ 报错；(d) 合法文档（含 `tenant_id`/`subject`/`subject_roles` 全字段）
  解析成功且字段正确落位。对照 `conditionalaccess/yaml_test.go` 的严格
  解析测试风格。
- config 快照测试：`TokenPolicyConfig.Policies` 内联一条带非法
  `subject_roles` 的规则 ⇒ 配置加载失败（boot-time fail loud），不留
  "看似生效实则全局"的中间态。
- `go build ./... && go vet ./...`、`go test -run 'TestMaintainability_|TestArchitecture_' .`
  全绿；`go test ./domains/tokenpolicy/ ./config/ -race` 全绿。
- `docs/openapi.yaml` / `docs/config-reference.md` 已更新（`make ci` 的
  docs 检查通过）。

## Contract updates（同一变更内完成，AGENTS.md §5.6）

| 变更 | 落点 |
|---|---|
| `Policy.TenantID` / `PolicyInput.TenantID` | `domains/tokenpolicy/tokenpolicy.go` |
| `Policy.Subject` / `Policy.SubjectRoles` / `PolicyInput.SubjectRoles` | `domains/tokenpolicy/tokenpolicy.go` |
| 选择器匹配（租户 + subject/角色 + client 通配） | `domains/tokenpolicy/evaluate.go`（`matches` 重构 + `prefixOrExact` helper） |
| 严格 YAML 解析 + `Validate` 纯函数 | `domains/tokenpolicy/yaml.go`（`DisallowUnknownField`）、新增校验 |
| `core.Subject.TenantID` mint-time 盖章 | `shared/core/types_token.go` + 10 个既有发行调用点（与 `ClientID` 同批） |
| 四条接缝租户透传 | `interfaces/sso/server_token.go`（scope-combo）、`internal/handler/tokengrant/token_refresh.go`（refresh 深度门，改 `EnforceRefreshDepthPolicy` 签名）、`interfaces/sso/server_oauth.go`（会话上限门）、`interfaces/sso/server_helpers.go`（仅签名/`PolicyInput` 填充） |
| 角色解析（会话接缝，fail-open） | `interfaces/sso/server_oauth.go`（`sessionPolicyCapExceeded` 经 `s.tenantUserStore`） |
| 管理读 API schema | `docs/openapi.yaml:6836`（新增三个可选选择器字段） |
| 配置规则 schema 文档 | `docs/config-reference.md:588`（选择器行补充租户/主体/通配语义） |

Wire 契约（拒绝响应、openapi 端点形状、error-codes）无变化：对外仍是通用
`invalid_scope` / `invalid_grant`，租户与主体信息只进入策略求值，绝不进入
拒绝响应体（oracle-safe，AGENTS.md §3）。
