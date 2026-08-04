# interfaces/sso 模块架构分析

已完成全局扫描：`interfaces/sso` 共 60 个生产文件 / 约 48,600 行（全部贴着 500 行预算线）、993 个 `Server` 方法、约 223 个唯一 `With*` 选项、970 处选项引用；并交叉核对了 `docs/config-reference.md`、`docs/feature-matrix.md`、`docs/deferred-backlog.md`、`docs/observability.md`、`ops/build/capabilities.json`、`infrastructure/{postgres,redis,sqlite}` 与各门禁测试。以下为 3 个最高价值的扩展/改进方向。

## 方向一：SDK 选项面与 stock-server 配置面的一致性缺口

**问题**：`interfaces/sso` 作为产品 SDK 暴露约 223 个唯一 `With*` 选项（`options*.go` 七个文件、970 处引用），但 stock `cmd/sso-server` 的组装根只接线了约 240 处，`docs/config-reference.md` 仅有 42 个配置章节。`docs/deferred-backlog.md` 明确写着 "An SDK option is not automatically a stock-binary YAML feature"——即大量已实现、已测试的能力（如 `WithIntrospectionSigning`、`WithTokenExchangePolicy`、`WithDataRetentionSweep` 等）对部署 `sso-server` 的运营者不可达，只能通过写 Go 组装代码获得。

**证据**：`interfaces/sso/options*.go`（223 个唯一 `With*`）；`docs/config-reference.md`（42 节，`oauth.backend` 等）；`cmd/sso-server/build_app_*.go`、`build_stores.go`（仅部分选项被接线）；`docs/deferred-backlog.md` "Product-surface boundary" 表；`ops/build/capabilities.json` 的 `config_keys` 是手工维护的。对比之下，路由面已有自动化闭环（`python cli.py check-routes` 保证运行时路由与 OpenAPI 锁步，`sdk-surface check` 保证生成 SDK 与契约锁步），唯独"选项→配置"这一维没有任何机器可校验的清单。

**为什么需要**：这是产品面与运营面的双向失真——feature-matrix 按 `sdk`/`stock-binary` 四维标注能力，但缺少一个"该选项是否可经 YAML 触达"的机器可查事实源；企业评估/试用走的是 stock 二进制，能力兑现率远低于 SDK 面，直接影响销售与落地。参照既有 `cli.py sdk-surface check` 模式，新增一个"选项→配置映射"注册表与校验门禁（每个 SDK 选项要么有配置路径、要么显式声明 SDK-only），成本低、与现有工具链同构，且让"缺口"从隐性变成可治理的决策项。

## 方向二：Postgres 成为 OAuth 热存储一等后端

**问题**：`oauth.backend` 仅支持 `memory|sqlite|redis` 三选一（`docs/config-reference.md` "Storage Backend Toggles"），`infrastructure/postgres/` 覆盖了 identity/session/consent/clients/audit 等持久层，但**零个** OAuth 协议热存储（auth_code / refresh_token / device_code / PAR）。最"企业级"的后端在 OAuth 核心路径上是最弱的：标准化 Postgres 的部署必须额外引入并运维 Redis，才能跑通授权码/刷新/设备流——多一个有状态服务、多一份凭据面、多一套备份与容灾编排。

**证据**：`infrastructure/postgres/` 文件清单（无 `auth_code.go`/`refresh_token.go`/`device_code.go`/`par.go`，而 `infrastructure/redis/` 与 `infrastructure/defaultimpl/sqlite/` 均有）；`docs/config-reference.md` 第 90-100 行（`oauth.backend` 枚举不含 postgres，而 `identity.session_backend` 已含 postgres，形成不对称）；`infrastructure/defaultimpl/sqlite/auth_codes_test.go` 证明 SQLite 参考实现完备，本质是 DDL 翻译 + 事务语义适配，无协议研究风险。`docs/architecture/architect-analysis-expansion-v10-directions.md` 局限性 A 已点名此缺口，当前代码仍未补。

**为什么需要**：多副本部署本就需要共享存储，Postgres 方案可提供单存储事务一致性（如原子消费与家族删除本就依赖 `DELETE RETURNING` 语义）、与持久层统一的 DR/备份故事、以及受管控环境（禁 Redis、审计约束）的合规入场券。SQLite 实现可平移、SPI 接口（`oauth.AuthCodeStore` 等）不变、`interfaces/sso` 无需改动——是"低成本、高企业价值"的典型扩展，且能同时消除 feature-matrix 中"postgres 仅持久层"的产品叙事短板。

## 方向三：`interfaces/sso` 天花板下的系统性瘦身（薄委托下沉）

**问题**：包已到冻结的 60 文件上限（`AGENTS.md` §2 明文 "at its 60-file ceiling"），60 个生产文件全部顶在 500 行预算线（48,600 行），`Server` 是 10 个匿名嵌入子结构（`wiringState`…`notificationState`）构成的 god-struct，共 993 个方法、其中至少 104 个是 `func (s *Server) handleX(ctx) { pkg.HandleX(s, ctx) }` 形式的单行薄委托。`sso.go` 注释已出现 "Relocated from server_helpers.go (which was at the line budget)" 这类为凑预算而搬家的痕迹；`architecture_layer_test.go` 对 `domains/authenticators -> interfaces/sso` 等边的豁免注释自述为 "god-package fan-in"。任何新能力（方向一、方向二落地时必然涉及）都只能在已满的文件里再挤，或在领域层另起炉灶——天花板已成为结构性瓶颈。

**证据**：`maintainability_budget_test.go`（`TestMaintainability_FileSizeBudget`，每文件 500 行）；`AGENTS.md` §2（60 文件上限、豁免只减不增）；`interfaces/sso/sso.go`（"Relocated from..." 注释、`apply*` 系列 wiring）；`interfaces/sso/handlers.go`（`handleIntrospect → oauth.HandleIntrospect(s, ctx)` 单行委托模式）；`architecture_layer_test.go` 第 119-122 行（fan-in 豁免）。

**为什么需要**：这决定了模块未来的演进速率。现有单行委托模式本身就是可推广的"下沉范式"——把 104 个薄委托对应业务整体迁往 `protocols/`、`domains/` 的已有收口（`HandleIntrospect`、`HandleRevoke`、`HandlePAR` 等已在 `protocols/oauth`），让 `Server` 回归"选项组装 + 路由编排"的瘦门面，即可在不动豁免表的前提下为未来特性腾出文件预算。其价值是解锁性的：不先解决它，方向一与方向二的每一次增量都会撞上"往哪个已满的文件里放"的无效争抢，且 god-struct 的认知负载会随每次新嵌入子结构继续恶化。

---

**取舍说明**：流量级可观测性（`flow_id` 跨 auth→token 多请求关联，全库确无此概念）与 OIDF 官方认证列名（`ROADMAP.md` P0 剩余项）同样成立，但前者已被 `docs/architecture/` 既有分析覆盖、后者属流程证据而非模块扩展；上述三个方向均以当前代码状态为据、相互独立且互有放大效应（先做三可释放一二的落地空间）。
