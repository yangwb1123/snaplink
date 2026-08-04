全局扫描完成（`domains/region/` 全部 8 个文件、`interfaces/sso` 强制执行层、`cmd/sso-server` 装配、admin gRPC、`platform/{audit,cluster,metrics}`、config、OpenAPI/错误码/feature-matrix/observability 文档及 `test/` 的 5 个 e2e 文件）。现状一句话：`region` 是一个设计克制、oracle-safe 的驻留治理层——解析器（pinned/header/chain + peertrust）、非致命中间件、写入门（login/prompt=none/MFA/token grant//me/WebAuthn）、读门（/userinfo、mesh ext_authz）、60s 缓存 + 失效总线、两个 403 线码，均已落地且有 e2e 覆盖。以下 3 个方向基于真实缺口，非堆功能。

## 1. 可观测性：为 fail-open 的治理控制补齐决策指标与失效告警

**问题**：residency 是显式的 fail-open 控制（tenant-store 分区时静默放行，`checkTenantResidency` 注释明言"宁可越区服务也不 4xx 全世界"），但整条路径**零指标**。`platform/metrics/` 没有任何 residency 计数器；`docs/observability.md` 只有 Metrics/Audit/Tracing 三节，无 region 内容。控制被静默关闭（store 故障）时，唯一痕迹是 `resolveResidencyPolicy` 里的一行 Error 日志；`/userinfo` 与 mesh 的读门拒绝不产生任何计数（mesh DENY 刻意二进制）；解析失败只有 `MiddlewareOptions.OnError`（cmd 侧仅打日志）。

**证据**：`interfaces/sso/server_tenant_residency.go`（fail-open 决策 + 单行日志）、`domains/region/middleware.go:14-19`（OnError 是唯一 hook）、`cmd/sso-server/build_app_selfservice.go:256-262`（OnError→logger）、`platform/metrics/conditional_access.go` 与 `dr_collector.go`（现成的 CounterVec / `DegradedRejectionsTotal` 模式）、`docs/observability.md`（无 region 章节）。

**为什么需要**：一个**默认静默降级**的合规控制没有计数器，等于不可验证——运营者无法发现"控制失效窗口"、无法按 region/租户量化拒绝流量来规划路由、审计时无法举证 `region_not_allowed` 确实被强制执行。按代码库既有模式补 `residency_decisions_total{code,region,surface}`、`residency_failopen_total`、缓存命中率即可闭合，风险极低、价值直接对应合规取证。

## 2. 把 serving region 写进令牌与发现契约：让驻留约束延伸到资源服务器边界

**问题**：serving region 目前只是 (a) 登录响应的 UX 标记（`server_finish_login.go:320-330` 注释自认 "UX, not a security signal"）、(b) audit `region.serving` 元数据、(c) 进程内强制输入。它**不在 ID token/access token 里，也不在 OIDC discovery 里**。因此强制边界止于 SSO 服务器自身：一个 eu-west-1 铸造的令牌可被呈交给 us-east 的资源服务器，而 RS 无从验证铸造区域——但租户数据恰恰住在 RS 后面。同时 `docs/error-codes.md:88` 给 `region_not_allowed` 的处置建议是"Route the request to an allowed region"，客户端却没有任何机器可读的方式得知"本部署服务 eu-west-1"。

**证据**：`shared/core/consts_wire.go:141-145`（KeyServingRegion 仅登录响应）、`interfaces/sso/server_finish_login.go`（applyLoginResponseExtras）、`protocols/oidc/metadata.go`（discovery 无 region 字段）、`docs/openapi.yaml:12156`（serving_region 仅存在于登录响应 schema）、`docs/error-codes.md:88-89`。

**为什么需要**：对数据驻留产品而言，**铸造区域是首要证据**，目前它只存在于审计与 UX。在 ID token 增加可审计的 serving-region claim（或 discovery 中广告 regional issuer），下游 RP/RS 才能验证并强制驻留，运营者才能以标准形态暴露区域端点。这是线缆契约变更（AGENTS.md §2 的 claim 纪律要求走 token 投影路径 + 测试），正因为有约束，才应作为有规划的方向而非临时加塞。

## 3. 激活死代码 SPI：让 `PolicyStore` 成为真实扩展点，补耐用后端与区域 ID 校验

**问题**：`region.PolicyStore` 接口与 `memory.Store` 实现存在，但全库除自身测试外**零引用**——强制执行硬编码走 `tenantStore.GetTenant` + `residencyPolicyFromTenant` 字段映射。后果：(a) SDK 嵌入者无法插拔自定义策略源；(b) 没有独立于 tenant 行的耐用后端（tenant 有 sqlite，region policy 没有）；(c) admin 边界明确不校验区域 ID——`trimRegions` 注释自认 "does NOT validate region identity"，`"EU-WEST-1"` 与 `"eu-west-1"` 的拼写错误会静默产生**失约束（fail-open）或过约束**的策略，直接凿穿默认 fail-open 的合规底线。

**证据**：`domains/region/region.go`（PolicyStore）、`domains/region/memory/memory.go`（唯一消费者是自身测试）、`interfaces/sso/server_tenant_residency.go:388-401`（residencyPolicyFromTenant 直接读 tenant 字段）、`interfaces/grpcserver/grpcadmin/admin_tenants.go:439-452`（trimRegions）、AGENTS.md §4（"Every storage concern is an interface plus a real Memory* implementation and optional durable backends"）。

**为什么需要**：模块自己的扩展点在生产路径上从未被调用，比没有更糟——后来者会再写一个平行实现。对 embeddable SDK 产品，策略来源（config 种子 / admin / 外部注册表）是第一类扩展维度；而 admin 边界做区域 ID 格式/白名单校验是成本极低的正确性修复，直接加固"拼写错误 = 静默失约束"这一当前最危险的失败模式。

三者互不重叠：**可运营**（指标）、**可扩展**（线缆契约）、**可加固**（SPI + 校验），且均不改动现有 oracle-safe 语义与 fail-open 决策序。
