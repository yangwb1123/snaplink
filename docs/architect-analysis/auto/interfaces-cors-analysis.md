已全局扫描（interfaces/cors、interfaces/sso 的接线、config、docs、ratelimit、DPoP 相关），以下是分析结论。

## 方向一：CORS 策略热更新 + origin 判定单一事实来源（消除登录 CSRF 门与中间件的逻辑漂移）

**问题**：CORS 策略在启动时被烘焙进闭包，运行期完全不可变；同时"某 origin 是否被允许"存在两套独立实现，安全语义可能不一致。

**证据**：
- `interfaces/cors/cors.go`：`Middleware()` 在构造时调用 `buildConfig` 预计算全部头字符串与 origin 集合，策略从此固定；`interfaces/sso/server_routes.go` 的 `buildMiddlewareChain` 在 `Handler()` 挂载时一次成型，`sso.corsPolicy`（`interfaces/sso/sso_protocol.go:139`）是 boot-only 指针，无 setter。
- 对比：`interfaces/ratelimit` 有 `PolicyStore` + `SetRateLimitPolicy`（`interfaces/sso/server_routes.go` 中注释明确"config/reload SIGHUP 热替换"），`docs/config-reference.md` 的 Hot Reload 表只覆盖 `logging.level`、`security.rate_limit.*`、`feature_gates.*`，CORS 缺席——SPA 域名轮换或新增 staging 前端域必须整机重启。
- 逻辑重复：`interfaces/sso/origin_validation.go:91-124` 的 `isOriginAllowed` 用线性扫描 + 硬编码 `"*"` 字面量重新实现了一遍 `cors.corsConfig.originAllowed`（map + `cors.OriginWildcard` 常量）；`rejectDisallowedLoginOrigin`（`server_login.go:158`）只查默认策略的 `AllowedOrigins`，完全无视 `PathOverrides`——若运维通过 path override 放宽 `/.well-known/*`，中间件放行但登录门仍 403，两个执行点行为分叉且无任何文档说明这是有意的纵深防御。

**为什么需要**：CORS 属于"改错代价高"的配置（放行过宽是 CSRF 面扩大，过窄是线上故障），热更新能力与 rate_limit 对齐是运维刚需；而登录门与中间件判定逻辑分叉是安全回归的漂移点——未来任何通配语义调整（子域匹配、`null` origin 处理）都必须同步改两处，任何一处遗漏都会造成 CSRF 防护与 CORS 放行不一致。应把 origin 判定收敛为 `cors` 包单一实现，登录门复用同一判定并显式声明"仅用默认策略"的语义。

## 方向二：配置面完整性——`PathOverrides` 对 YAML 运维不可达，`security.cors` 未入契约文档，默认头列表存在"追加"陷阱

**问题**：`cors.Policy` 最强大的特性（按路径差异化策略）在配置层被静默截断；配置项本身违反 AGENTS.md 的"config knob → docs/config-reference.md"契约；默认允许头列表与产品一等公民 DPoP 不匹配。

**证据**：
- `config/config_admin.go:103-111` 的 `CORSConfig` 只有 `enabled/allowed_origins/allowed_methods/allowed_headers/exposed_headers/allow_credentials/max_age`，没有 `path_overrides` 字段；`config/config_load.go:472` 的 `toPolicy()` 不映射 `PathOverrides`。而 `interfaces/cors/cors.go:58-66` 的文档明确以"`/.well-known/jwks.json` 宽松 vs `/token` 严格"作为该特性的卖点——YAML 运维永远无法使用它。
- `docs/config-reference.md` Security 表（63-70 行）列了 mtls/trusted_proxies/security_headers/rar_limits/scope_limit/max_token_bytes/client_registration_rate_limit，唯独没有 `security.cors` 行。
- `interfaces/cors/consts.go` 默认 `AllowedHeaders` 仅 `Authorization, Content-Type`，而 DPoP 是代码库一等方案（`interfaces/ssoclient/rs/dpop.go`、`server_oauth.go`）；由于"空字段回退默认值"的语义，SPA 想加 `DPoP` 头必须全量枚举，只写 `["DPoP"]` 会静默丢掉 `Authorization`，表现为难以排查的 401。
- 契约漂移：`cors.go:44` 文档举例 `X-RateLimit-Remaining` 可被读取，但 `interfaces/ratelimit` 全包只发 `Retry-After`，该头不存在；另 `shared/core/consts_wire.go:25-27` 已定义 `HeaderAccessControl*`，`interfaces/cors/consts.go` 因"不能 import sso"的循环担忧重复声明——但 cors 完全可以直接 import 更底层的 `shared/core`，无需双源。

**为什么需要**：功能与配置入口不对称 = 已实现能力不可交付，属于产品层 ROI 最高的修复（只差一个 YAML 字段映射）；未入参考文档违反仓库自身的变更契约；"空=默认"的隐式语义在凭据类头（Authorization/DPoP）上是一个静默故障源，需要"追加到默认值"或显式校验的语义。

## 方向三：CORS 执行可观测性——被拒 origin 无指标无审计，跨域探测信号完全不可见

**问题**：整个 CORS 边界的安全事件（拒绝的跨域请求、被拦预检）不产生任何指标或审计记录，运维无法区分"配置写错"与"攻击探测"。

**证据**：
- `interfaces/cors/cors.go` 的 `Middleware` 对不匹配 origin 走 `next.ServeHTTP` 静默放行（仅不写头），零计数、零日志；预检 204 被 rate limit 覆盖但"被拒绝的 origin"无任何计数器。
- 唯一的信号是 `interfaces/sso/server_login.go:174` 的 `origin_blocked`，且只是 `logger.Info`，不递增指标、不发审计事件——全局 grep `origin_blocked|cors_blocked` 仅此一处。
- 对照代码库基线：`platform/metrics` 中间件覆盖每个请求、`origin_validation.go` 同文件就挂着 CIBA 的 `sso_ciba_ping_total{outcome}` 计数与 `ciba_ping_failed` 审计事件模式（`deliverCIBAPing`），`docs/observability.md` 明确中间件顺序含 CORS——安全执行点无观测是例外而非常态。

**为什么需要**：被拒跨域请求（尤其 `POST /auth/login`、`/token` 上的）是 CSRF 尝试与凭据探测的早期信号；同时 CORS 配置错误（如漏配 staging 域名）在浏览器端表现为"静默失败"，服务端若无计数，排障只能靠抓包。补一个 `sso_cors_blocked_total{origin,path}` 指标 + 可选审计事件，成本极低，却能同时覆盖安全告警与配置排障两个场景，与平台既有的 metrics/audit 惯例对齐。

**次要观察**（不构成独立方向）：`cors` 包 242 行、函数均远低于预算，模块本身实现质量良好；测试覆盖了通配/凭据/预检/路径分派，但缺 `PathOverrides` 与 login 门联动的集成测试（`test/` 层），方向一落地时应补上。
