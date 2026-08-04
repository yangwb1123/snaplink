扫描完成。我通读了 `domains/tokenanomaly/`（detector.go、detect.go、admin.go、tokenanomaly.go、memory/store.go）、其上游 `domains/metering`（Event/Store/Recorder）、下游 `domains/threataction`（Threat/FamilyRevoker/SubjectRevoker）、对照 `domains/anomaly`（登录侧检测）、以及接线层 `interfaces/sso`（recordTokenIssued / Offer 点、RunTokenAnomalyDetection、WithGeoProvider）和 `cmd/sso-server/serverbuildplatform/build_governance.go`。以下是最有价值的 3 个方向：

## 1. 打通 Geo 信号链路：multi_geo / velocity 两个旗舰信号在生产路径上是死代码

**问题**：`tokenanomaly` 模块最核心的卖点是"token 在多国被使用 / 不可能旅行"，但生产代码中没有任何一个 `metering.Event` 的 `GeoCountry` 字段被填充——全仓库对 `GeoCountry:` 的赋值只存在于测试文件（`detector_test.go`、`token_usage_test.go`、`detector_adversarial_test.go`）。`detectGeoVelocity`（`domains/tokenanomaly/detect.go`）要求 `len(o.geos) >= 2` 才会产出 `multi_geo`/`velocity` finding，因此真实部署中这两个信号永远不可能触发，只有 per-client 的 `rate_spike` 能工作。

**证据**：
- 所有生产 Offer 点均省略 `GeoCountry`：`interfaces/sso/server_helpers.go:428-453`（`recordTokenIssued`/`recordRefreshTokenIssued`/`recordIDTokenIssued`）、`protocols/oauth/handle_introspect.go:357`、`protocols/oauth/introspect_body.go:21`。
- 同层已存在可用的 geo 增强：`interfaces/sso/options_misc.go:55-58`（`WithGeoProvider` 安装 GeoMiddleware）和 `server_login_client.go:148-158`（`GeoFromHandlerContext` → `signals.Geo.CountryCode`），但只喂给了登录侧 `anomaly` 子系统，从未接到 token 遥测上。
- 下游威胁动作同样悬空：`domains/threataction/threataction.go` 定义了 `ThreatMultiGeo`/`ThreatVelocity`，`dispatchThreat`（detector.go）也支持转发，但生产上永远收不到这类 Threat。

**为什么需要**：这是检测器"检测能力"与"数据源"之间的断线——模块文档宣称的隐私承诺（只存粗粒度国家码）、严重度分级（velocity=critical）和 ITDR 响应链全部建立在永远不会发生的事件上。运维按文档开启 `token_anomaly` + `threat_action` 后会得到"有覆盖"的错误安全感。修复方向单一且成本低：在 `recordTokenIssued`/introspect 等握手点从 `GeoFromHandlerContext`/ClientIP 取粗粒度国家码填入 Event（注意保持"粗粒度、非 PII"边界）。这是本模块 ROI 最高的改进。

## 2. Finding 全生命周期缺失：无持久化、无 triage 状态、无过期/分页/租户维度，多副本部署下整链失效

**问题**：`FindingStore` 只有 `domains/tokenanomaly/memory`（上限 1024、FIFO 驱逐）一种实现，而同生态的 `metering/sqlite`、`threataction/sqlite` 都有持久化版本。这带来四个操作性问题：(a) 重启即丢——安全事件记录不可审计追溯；(b) 无 triage 状态——`Finding` 没有 acknowledged/resolved 字段，SOC 无法区分"已处置"与"待处置"，`FindingQuery`（tokenanomaly.go）只有 `Type/Severity/Limit` 三个过滤维度，且管理端 `GET /api/v1/admin/tokens/suspicious` 无游标分页，容量内一次性全量返回；(c) 无生命周期——severity 只会升级不会降级（`memory/store.go` 的 `mergeFinding`），token 已被撤销/轮换后 finding 仍滞留到被容量驱逐，形成持续噪声；(d) 多副本失效——`Detector.obs` 是进程内观察表，横向扩展时每个副本只看到自己分到的 token 使用切片，geo 基数被稀释（token 在副本 A 见 US、副本 B 见 EU，永远凑不齐 `>= 2`），而 `Analyze` sweep 也是每副本各跑一份、写各自的内存 store。

**证据**：`domains/tokenanomaly/memory/store.go:22-60`（唯一实现）、`admin.go:20-45`（无游标、无状态字段）、`detector.go:59-68`（进程内 `obs` map）、`config_snapshot.go:429` 的 `TokenAnomalyConfig` 无持久化选项。

**为什么需要**：检测系统的价值在"可处置、可追溯、可扩展"。当前形态是单机内存演示态：告警列表无法支撑 SOC 工作流（标记、关闭、复查），审计合规要求事件留存，而多副本部署是 `docs/config-reference.md` 描述的 sqlite 后端的标准拓扑——不解决则模块在真实生产规模下静默降级为"只在本副本上检测"。

## 3. 响应精度不足：FamilyID 未贯穿检测→响应链，revoke 退化为整用户兜底；rate_spike 只盯"最后一分钟"

**问题**：`velocity`/`multi_geo` 是针对"单个被窃 token"的信号，但检测端到响应端的链路中 `FamilyID` 全程缺失：`metering.Event` 没有 FamilyID 字段，`observation` 不记录，`Finding` 不携带，`dispatchThreat`（detector.go:138-155）构造的 `threataction.Threat` 留空 `FamilyID`。后果是 `BuildThreatAction` 里配的 `ActionRevoke`（`threataction.NewRevokeFamilyExecutor`）永远走 `SubjectRevoker.DeleteAllForSubject` 兜底——一条"某个 token 被偷用"的告警会撤销该用户在此 client 下的**全部** refresh token，既是对合法用户的误伤（DoS），也丢失了"只断被窃凭证"的精度。`threataction.SubjectRevoker` 的文档自己承认这是"common case in production"，恰好暴露了该缺口。另外 `spikeForClient`（detect.go）只比较"最新分钟"与历史均值：若突发在最近一分钟前开始、或最后一分钟回落，`Analyze` sweep 就漏报；且 spike 按 client 而非按 subject/token 聚合，攻击者在一个 client 内轮换多个 token 的突发不可见。

**证据**：`domains/metering/token_usage.go:57-76`（Event 无 FamilyID）、`tokenanomaly.go:50-72`（Finding 无 FamilyID）、`detector.go:138-155`（dispatchThreat 不填 FamilyID）、`domains/threataction/actions.go`（SubjectRevoker 语义）、`detect.go:100-136`（spikeForClient 仅看最新分钟）。

**为什么需要**：安全响应的核心原则是"最小伤害、精确处置"。当前实现要么不动（noop），一动就是整用户级别的重锤，导致运维不敢把 `default_action` 配成 `revoke`——检测精度被响应粒度拖累。而刷新令牌族（FamilyID）在 refresh rotation 里本就是一等公民（AGENTS.md 的 OAuth 不变式），把 FamilyID 从 grant/rotate 握手点带进 Event 并贯穿到 Threat，是低成本高收益的改进；同时把 spike 检测从"最后一分钟"推广到"窗口内任意连续突发"，并增加 subject 维度，能显著提升检出率与误报比。
