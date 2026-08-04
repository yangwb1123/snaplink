# interfaces/apidocs 模块分析

## 全局扫描结论

`interfaces/apidocs` 是"嵌入式文档门户"半成品：`apidocs.go` 在进程启动时解析一次内嵌的 `docs.OpenAPISpec`（`docs/openapi.yaml`，15849 行），通过 `sso.WithAPIDocsUI` 以 `admin:read` 权限挂在 `/api/v1/admin/docs` 与 `/docs/openapi.json` 两个路由下（`interfaces/sso/server_routes.go` 的 `mountAPIDocsUI`/`WithAPIDocsUI`）。它与 `cmd/gensdk`（TypeScript/Python SDK 生成器）共享同一份内嵌 spec，构成"SDK 生成 + 开发者门户"backlog 项（`docs/deferred-backlog.md`）的已实现部分。它自研 HTML/vanilla-JS 渲染器（`template.go`），零外部依赖、CSP nonce 合规、可离线保存，工程上相当克制。但作为"开发者门户"，它在三个维度上存在高价值缺口：

---

## 1. 提供部署感知（runtime-faithful）的 OpenAPI 投影：按已挂载选项过滤路由 + 注入真实 base URL/版本

**问题**：`WithAPIDocsUI` 被明确描述为"the full live endpoint + schema inventory"（`interfaces/sso/server_routes.go` 中 `WithAPIDocsUI` 的注释，也是它被放在 admin 网关之后、按运维敏感信息对待的理由），但实际交付的是一份与部署无关的静态文件：`apidocs.handleSpec` 原样序列化内嵌 spec，`mountAPIDocsUI` 不做任何过滤。而 `python cli.py check-routes` 显示当前运行时只有 **241 条路由，spec 却声明了 322 个 operation**——约 81 个 operation（`/api/v2alpha/version` 预览路由、`/api/v1/setup` 向导、WASM authz、crypto inventory、CAEP、federation 等）在本部署未挂载时返回 404，文档却照常展示。同时 `servers` 硬编码 `http://localhost:8080` / `https://sso.example.com` 占位符（`docs/openapi.yaml` 第 52–60 行），`info.version` 是静态 `0.1.0`，而服务器明明有真实版本（`platform/buildinfo` 的 ldflags 注入版本）。开发者把 `openapi.json` 导入 Postman/Insomnia 后，要么打到错误的 host，要么调用不存在的端点。

**证据**：`interfaces/apidocs/apidocs.go` 的 `handleSpec`（verbatim 输出）；`interfaces/sso/server_routes.go` 的 `mountAPIDocsUI` + `WithAPIDocsUI` 注释；`checks/route_contract.py` 的 "241 runtime routes, 322 documented operations" 不对称输出；`docs/openapi.yaml` 的 `servers:`/`info.version`；`platform/buildinfo`。

**为什么需要**：该模块的两个机器可读消费者——工具导入（Postman/curl）与 gensdk 交叉校验——恰好是最需要"与当前服务器一致"的场景。admin 网关的存在已经表明产品认为这份清单是敏感且精确的；文档与运行时不对称会直接侵蚀集成者对契约的信任。服务器已有全部素材（`Server` 的 option 状态、路由表、`resolveIssuer`、buildinfo），缺的只是一个"静态 spec 为源、按挂载状态投影"的薄层——这是把"文档"变成"本部署事实"的最小成本改进。

---

## 2. 让查看器渲染安全与错误契约：per-operation 认证要求（security/securitySchemes）与按端点错误码目录

**问题**：`template.go` 的渲染器只展示 method/path/参数/请求体/响应 schema，对 `security`、`securitySchemes`、`servers`、`examples` 完全没有处理（全文件 grep 无一处渲染逻辑）。对一个 OAuth/OIDC 服务器来说，这恰恰是开发者集成时最需要的信息：每个端点的认证方式差异极大（`bearerAuth` JWT 之外，`/token` 家族还有 HTTP Basic 优先、DPoP、mTLS、`private_key_jwt`，且 Basic 覆盖 body 凭据）；而本产品最独特的契约就是 oracle-safe 错误分类——`invalid_grant`、`unsupported_provider`、`mfa_invalid` 等稳定错误码（`docs/error-codes.md`、AGENTS.md 的 oracle-safe 表）。spec 里这些信息都在：`securitySchemes`（`docs/openapi.yaml` 11843 行）、每个 operation 的 `security: [{bearerAuth: []}]` 块（1252 行起遍布全文）、`ErrorResponse` schema（14277 行，"Stable error code (catalog in consts.go)"）——但查看器把 ErrorResponse 渲染成一个普通 object，开发者看不到本端点可能返回哪些 `error` 码、需要哪种认证。SDK 生成器（`cmd/gensdk`）以编程方式编码了 surface，而人类可读的 viewer 却隐藏了决策最关键的两类字段。

**证据**：`interfaces/apidocs/template.go`（`operationBody`/`paramsTable`/`renderSchema` 无 security/servers/examples 分支）；`docs/openapi.yaml` 的 `securitySchemes`、per-op `security:` 块、`ErrorResponse` schema；`docs/error-codes.md`；`docs/deferred-backlog.md` 第 34 行对该模块的定位。

**为什么需要**：这是"多语言 SDK 生成 + 开发者门户"backlog 项中门户侧的实质内容。当前 viewer 是一个 schema 浏览器，不是参考文档；补上认证标注与错误码目录（纯 `template.go` 改动 + 测试，不动服务端契约）后，它才成为集成者真正可依赖的、自托管的权威参考——这对"不发布到第三方托管文档平台"的产品是核心价值。

---

## 3. 把文档管线从"单向校验"升级为"双向锁步 + 自动 API 变更日志"：反向 route 契约、嵌入一致性、operationId 级语义 diff

**问题**：当前有三份需同步的产物——`docs/openapi.yaml`（源）、`cmd/gensdk` 输出（`docs/sdks/{typescript,python}`）、运行时路由——但防护是单向且局部的：`make docs-validate` 只验 spec 语法；`route-contract`（`checks/route_contract.py`）只保证"运行时路由 ⊆ 文档"，从不检查"文档 operation 在运行时真实存在"（因此 322 vs 241 的差距无人告警）；没有检查 `docs/openapi_embed.go` 内嵌的字节是否与提交的文件一致（构建期嵌入即吞掉差异）；`ops/build/sdk-surface.json` 的策略文本明确写道"renaming or removing an operationId is a breaking change requiring a minor-version bump and a CHANGELOG entry"，但仓库里没有任何自动 diff 工具来产生这份 changelog——它只能靠人工。`docs/deferred-backlog.md` 第 35 行承认 SDK"尚未作为版本化包发布"，而版本化发布的第一步就是可审计的变更历史。

**证据**：`Makefile` 的 `docs-validate`/`route-contract`（178–181 行）；`checks/route_contract.py` 的输出不对称性；`docs/openapi_embed.go`；`ops/build/sdk-surface.json` 的 compatibility/policy 文本；`docs/deferred-backlog.md` 第 35 行；`cmd/gensdk/main.go`（复用同一解析器与 operationId 命名）。

**为什么需要**：surface 已到 322 个 operation 且持续增长，手工维护的交叉引用（错误码表、feature-matrix、route 例外）必然漂移。复用已有资产（kin-openapi 已在 Makefile 中、gensdk 的 schema 解析器已存在）做两件事——反向路由契约检查（文档 operation 未挂载即失败或标注 opt-in）和 operationId 级前后版本语义 diff（产出 changelog 草稿）——让 `make ci` 真正证明"文档、SDK、运行时三者锁步"，同时为版本化 SDK 发布免费提供发布说明。这是现有管线的自然下一步，不引入新依赖，也不触碰安全边界。

---

**优先级建议**：方向 1（运行时保真）是信任问题，影响所有消费者，建议先行；方向 2（安全/错误契约渲染）是纯前端增益、成本最低，可与方向 1 同批交付；方向 3（双向校验 + changelog）是工程基建，适合作为下一轮 CI 增强。三者互不阻塞，且都不需要放宽任何现有 gate。
