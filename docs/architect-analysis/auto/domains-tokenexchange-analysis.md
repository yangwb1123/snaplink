已完成全局扫描（`domains/tokenexchange/` 全量、`internal/handler/tokengrant`、`interfaces/sso`、`interfaces/admin`、`cmd/sso-server`、`platform/audit`、`config`、`docs/` 相关契约）。模块现状：`Policy`/`Rule` 跳授权 SPI + `memory.Store`；`ChainStore`/`ChainHop` 纯追加观测 + memory/sqlite 双后端（仅暴露 `GetChain` 管理端点）；`agentidentity` 委托令牌 grant（`delegation_token`，含 Agent/AgentSession/RevokeAllForHuman）；外加链龄上限、跨租户协作、JTI 重放、RFC 9470/9396 等。以下为 3 个高价值方向。

## 1. 委托链级联撤销：把 ChainStore 从"只读观测"升级为"撤销控制面"

**问题**：`ChainStore` 目前被刻意限定为 append-only 观测（`chainstore.go` 文档自述 "no cascade-revocation ... scoped deliberately narrower than those, as follow-on work"），但委托场景最关键的响应动作恰恰是"这颗令牌变成了什么、全部作废"。当前 `GetDescendants`（按 JTI 前向遍历整条派生链）在整个生产代码库中 **零调用**——SPI 和两个后端都实现了，却没有一个消费方。同时 `agentidentity` 的撤销语义在首次 mint 之后即失效：`RevokeSession` 只阻止"下一次" mint，已发放的 delegation token 存活至 TTL（`grant.go` 明示 "narrows or kills the token on its very NEXT mint"）。被撤销会话/被泄露根令牌的派生令牌只能干等到期，这与仓库内 refresh-family 撤销（`RefreshTokenFamilyTracker.DeleteFamily`）的既有纪律形成落差。

**证据**：`domains/tokenexchange/chainstore.go`（`GetDescendants` 定义、文档自限声明）；`domains/tokenexchange/sqlite/chain_store.go:185` 与 `memory/chain_store.go:82`（已实现的 BFS 前向遍历，`idx_tokenexchange_chain_hops_parent` 索引已就位）；`interfaces/admin/lifecycle.go:109`（`HandleTokenExchangeChain` 只暴露 `GetChain` 祖先查询）；`domains/tokenexchange/agentidentity/revoke.go`（仅会话级撤销）；`protocols/oauth/handle_revoke.go:152`（`revokeAccess` 按 token 撤销，无链意识）。

**为什么需要**：RFC 8693 委托链的威胁模型（服务 A 冒用 B、链式传播、break-glass 泄漏）下，"撤销根 + 级联杀死全部后代"是唯一与攻击传播速度匹配的响应原语；`GetDescendants` + parent 索引已经为此铺好了全部数据面，缺的只是一个 fail-closed 的消费方（撤销时沿链标记后代 JTI 进 `JTIReplayStore`/撤销存储）和一个管理端到端入口（"某令牌已衍生出什么、一键级联撤销"）。同时把 agent 委托 mint（`mintDelegationToken`）纳入 `RecordExchangeHopFailOpen` 同一链路，才能让"撤销人类会话"自然传播到其 agent 令牌。这属于 AGENTS.md §3 中 fail-closed 撤销家族的自然补全。

## 2. 跳授权策略的运营闭环：管理 API + 持久化 + 匹配维度扩展

**问题**：`Policy` SPI 是模块的核心卖点——"operator who knows their own topology can block a specific hop"——但规则只能**构造期注入**，无法运营。`memory.Store.Replace` 的文档自称 "the dynamic-update path (e.g. an admin API or config reload)"，然而全库生产代码对该方法 **零调用**（无管理端点、无配置重载、无 cmd 装配）；配置面只支持 `max_chain_lifetime`（`config/config_oauth2.go`），策略本身只能 `WithTokenExchangePolicy` 硬编码注入。更甚：`Rule` 的匹配维度只有 subject/actor/client，而 `Hop` 上已经解析好的 `Scopes`、`Resources`、`RequestedTokenType` 在 `ruleMatches` 中被直接忽略——"service A 不得以 scope X 冒用 B"这类最常用的最小权限表达无法书写。对比 `domains/tokenpolicy`（有 admin `GET /api/v1/admin/token-policies` + sqlite 后端），本模块连规则列表的管理只读端点都没有。

**证据**：`domains/tokenexchange/memory/store.go`（`Replace`/`Rules` 无生产调用方）；`domains/tokenexchange/tokenexchange.go`（`Hop` 携带 Scopes/Resources/RequestedTokenType，`ruleMatches` 只用三字段）；`config/config_oauth2.go:26-32`（`OAuthTokenExchangeConfig` 仅有链龄旋钮）；`cmd/sso-server/build_app_oauth.go:276`（`wireTokenExchangeChainLifetime`，无规则装配）；对照 `cmd/sso-server/build_app_security.go:278` 的 token-policies 管理端点先例。

**为什么需要**：一个随进程启动而存在的策略不是"运营"而是"配置"。安全团队治理服务间委托的标准做法是 default-deny 白名单 + 运行时按需放行/阻断（应急封禁某 client-subject 组合、按 scope 敏感度收紧），这要求管理 API（含变更审计）、持久化后端，以及能表达 scope/resource 维度敏感度的匹配能力——三者缺一，`Policy` 只能停留在"演示级"能力，无法支撑生产最小权限治理。这也直接关系到第 3 点的 deny 可观测性（谁、何时、因哪条规则阻断）。

## 3. 委托决策的审计盲区：deny 事件缺失 + 令牌↔授权会话不可反查

**问题**：`tokExEnforcePolicy` 的 deny 只写 `SrvLogger().Error`，**没有 audit 事件**——`platform/audit/auditspi/event_types.go` 全表没有任何 token-exchange 专属的 deny/issuance 事件（仅有 `EventCrossTenantTokenExchange` 与 SPIFFE accepted）。而 AGENTS.md 的 oracle-safe 纪律明确要求"details only in audit"：wire 上所有失败必须坍缩为同一 `invalid_grant`，**审计是承载原因的唯一天然通道**（对比 `mfa_failure`、`device_code_denied`、`ciba_denied` 均有专属事件）。本模块存在的全部意义就是"阻断委托"，而被阻断的委托恰是 SIEM 最高信号的事件，目前完全盲区。另一面：`agentidentity` 的 mint 审计（`auditDelegationMint`）记录了 session ID 与 scope，却不记录新令牌的 `jti`；`ChainHop` 也不携带 scopes/resources——事故响应时无法从"一颗可疑令牌"反查它的授权会话、权限范围与命中规则。

**证据**：`internal/handler/tokengrant/token_exchange.go:391`（deny 路径仅 `d.SrvLogger().Error`）；`platform/audit/auditspi/event_types.go:179,319`（事件分类表中无 token-exchange deny 类）；`domains/tokenexchange/agentidentity/grant.go`（`auditDelegationMint` 无 jti）；`domains/tokenexchange/chainstore.go`（`ChainHop` 仅 7 个字段，无 scopes/resources/session 引用）；`docs/error-codes.md` 的 oracle 表（原因只许进审计）。

**为什么需要**：委托链攻击的检测与取证完全依赖事后追溯，而当前"原因 → 审计"通道在模块最核心的 deny 决策处断裂，SIEM 看不到"谁在试图冒用谁、被哪条策略阻断"，也无法把日志、链记录、令牌三者互相关联。补齐 deny 审计事件（含命中规则、subject/actor/client 元数据）+ 在 mint 审计与 `ChainHop` 中携带 jti/scopes/session 关联键，是让整个模块达到与 `mfa_failure` 同级可观测纪律的最小必要动作，也是第 1、2 点落地后"撤销、策略、审计"三面闭环的最后一块。
