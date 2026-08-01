# 架构分析报告：系统韧性、SPA 治理、出站保护与并发控制

> **分析师：** 资深架构师 Agent  
> **日期：** 2026-07-12  
> **基于：** `docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.md` + 代码核验反馈  
> **核验状态：** 5/5 方向全部经代码级确认（方向 3 部分确认，已修正）  
> **前置分析参考：** `docs/feature-spec-architecture-analysis-five-verified-directions.md`  
> **状态：** 本文件为独立架构级分析，后续可拆分为 `docs/feature-spec-*.md` 供 Implement Agent 使用

---

## 1. 架构评估

### 1.1 当前架构的核心优势

与本报告五个方向直接相关的架构优势：

| 优势 | 表现 | 对本报告的直接影响 |
|------|------|-------------------|
| **SessionHub Coordinator 已完整实现** | `platform/lifecycle/sessionhub/coordinator.go:128` 的 `Logout()` 方法已具备 OIDC BCL、SAML SLO 的 fan-out 能力 | 方向 1 只需在登出路径中调用它——SPI 层零变更，纯接线工作 |
| **SSRF 防护已验证实现** | `domains/federation/fetcher.go` 已有 `dialWithSSRFCheck`——DNS 解析后 IP 校验、CheckRedirect 阻断、防 TOCTOU | 方向 3 可提取这些已验证的逻辑到共享包，而非从头设计 |
| **后端 i18n 基础设施完整** | `shared/i18n` 包提供完整的 Localizer 接口、Bundle 加载器、Accept-Language 协商 | 方向 2 的 i18n 工作只需 SPA 层扩展，后端已就绪 |
| **Admin API 路由与 Handler 架构清晰** | `admin/handler.go` 注册模式一致，所有 CRUD 操作在同一路由层级 | 方向 4 的乐观锁 ETag 可在 handler 中间件层注入，不侵入业务逻辑 |
| **已有事件总线基础设施** | `cluster.Bus` 支持多种 `Kind*` 事件，`KindTokenRevoked` 已实现 | 方向 5 的 LinkRecord 清理可通过已有总线机制触发 |

### 1.2 关键设计决策合理性分析

#### 决策一：SessionHub 作为独立的协调层（合理，但有遗漏）

**决策：** 将跨协议登出协调抽象为 `Coordinator` 结构体 + `LinkStore` 接口，与 OIDC/SAML 协议层解耦。

**评估：** ✅ 架构决策正确，但实现有遗漏——创建侧（登录时注册链接）已集成，但消费侧（登出时调用 `Logout()`）从未接线。这不是设计问题，而是集成遗漏。修复成本极低（~30 行）。

#### 决策二：SPA 作为 `embed.FS` 原始文件提供（存在权衡）

**决策：** 4 个 SPAs 以手写原生 JS/CSS/HTML 编译进 Go 二进制文件。

**评估：** ⚠️ 正确的前提是"项目不把 SPA 作为一等产品界面"。当 Admin Console 成为管理生产系统的必要组件时，此决策变为负债：
- 零测试 = 任何 JS 错误无声影响生产运维
- 零构建步骤 = 前端代码无法享受现代工具链（TypeScript、压缩、hash 缓存）
- 零 i18n = 后端 i18n 投入浪费

**建议重新评估"SPA 的角色定位"**。如果 Admin Console 被定义为管理员必需界面（而非调试工具），应升级为其分配工程资源。

#### 决策三：出站 HTTP 调用采用分散管理（历史合理，当前不足）

**决策：** 各个协议模块（SAML、Federation、CAEP、Webhook）各自管理其出站 HTTP 客户端。

**评估：** 早期合理的模块自治决策。但随着出站调用增长到 7+ 种，缺乏统一的安全基线已成为攻面聚集问题。需要新增一个共享抽象层——不是替代现有客户端，而是在外层提供安全包装器。

#### 决策四：Admin API 采用最后写入者获胜（LWW）模式（合理但需演进）

**决策：** Admin API 的 `PUT` 操作直接替换存储中的资源，无版本控制。

**评估：** ✅ 单管理员运维场景下完全合理。当项目进入企业多管理员运维场景时，需要升级为乐观锁。`ETag`/`If-Match` 作为可选增强可以 100% 向后兼容——不提 `If-Match` 的旧请求继续 LWW 行为。这是正确的演进路径。

#### 决策五：LinkStore 无 TTL 和清理机制（设计疏忽）

**决策：** `LinkStore` 仅提供 `Set/Get/Delete` 接口，无 TTL、无 reaper、无 `DeleteLeg`。

**评估：** ❌ 这是架构设计中的疏忽——SessionHub 的设计意图是为跨协议登出协调积累链接数据，但登录时积累的数据如果没有自动清理机制，会形成无界增长的存储。一个设计良好的协调器应同时考虑"积累"和"释放"两个方向，当前只实现了前者。

### 1.3 架构债务与技术债汇总

| 类型 | 位置 | 严重性 | 来源方向 |
|------|------|--------|---------|
| **只写不读代码** | `Coordinator.Logout()` 方法存在但零调用方 | **高** | 方向 1 |
| **零测试前端** | 4 个 SPA 共 2892 行 JS，0 个测试文件 | **高** | 方向 2 |
| **安全攻面聚集** | 7+ 种出站 HTTP 调用各有独立的防护逻辑，标准不一 | **中** | 方向 3 |
| **丢失更新敞口** | 所有 Admin API PUT 无版本控制，LWW 模式 | **中** | 方向 4 |
| **存储无限增长** | LinkRecord 无 TTL、无 reaper、无单条删除能力 | **中** | 方向 5 |
| **CMS 审批盲区** | 审批工作流仅覆盖破坏性操作，日常配置编辑（client/tenant/user）无保护 | **低** | 方向 4 |
| **硬编码重复** | `isHTTPSURL` 函数在 `saml/idp/fanout.go:111` 和 `saml/sp/config.go:261` 重复实现 | **低** | 方向 3 |
| **GlobalSID 不可达** | 登出路径中无法从 bearer token/session cookie 反向映射到 global_sid | **高** | 方向 1 |

---

## 2. 扩展方向

### 2.1 方向 1：跨协议统一登出集成（P0）

#### 为什么需要

安全价值 + 系统完整性。SOC2/SOX 控制要求 SSO 系统"一次登出即全部登出"。当前 `/logout` 和 `/end_session` 只销毁核心 session，不向 SAML SP、OIDC BCL 接收端 fan-out。攻击者可在用户"登出"后继续使用未过期的 SAML 会话访问下游 SP。

技术价值：消除"只写不读"的架构债务——Coordinator 的 Logout 方法已等待消费。

#### 核心挑战和技术难点

1. **GlobalSID 解引用**：登出路径的入口是 cookie/bearer token，需要反向找到 `global_sid`。当前 `core.Session` 没有 `GlobalSID` 字段，`SessionManager` 没有 `LookupByToken` 方法。需要确定方案：
   - 方案 A：Session 嵌入 GlobalSID（需迁移所有存储后端，侵入性高）
   - 方案 B：独立 token→gsid 映射 store（零侵入，额外一次 store read）
   - 方案 C：登录响应中设关联 cookie（零存储变更，需管理额外 cookie）

2. **登出异步化**：Coordinator 的 `OIDCLogoutTrigger.TriggerBackchannelLogout` 和 `SAMLLogoutTrigger.Fanout` 是异步的最佳努力——不应阻塞 `/logout` 的 HTTP 响应。需要优雅处理部分链接超时。

3. **`resolveSession` 中间件的复用**：当前中间件已能从 cookie/token 解析出 `Session` 对象，但没有 GlobalSID。需要评估是否在 `Session` 中增加 `GlobalSID` 字段，或在中间件中额外从 LinkStore 查询。

#### 预期的架构变更

- `core/session.go`：Session 结构体增加 `GlobalSID string` 字段
- `core/manager.go`：`SessionManager` 接口保持不变（session load 后通过 LinkStore 反向获取 gsid）
- `interfaces/sso/server_logout.go`：`handleLogout` 中调用 `s.sessionHub.Logout(gsid, userID)`
- `protocols/oidc/handle_end_session.go`：`handleEndSession` 中调用 `s.sessionHub.Logout(gsid, userID)`
- `platform/lifecycle/sessionhub/coordinator.go`：`Logout` 方法增加 nil-check（SessionHub 未配置时安全 no-op）

#### 对现有系统的影响

| 方面 | 影响 |
|------|------|
| 向后兼容 | ✅ 零影响——所有现有行为不变 |
| 存储迁移 | 仅 GlobalSID 字段增加，不影响现有 session 数据 |
| 性能 | 登出路径增加一次 LinkStore.Get + 异步 fan-out（可接受） |
| 错误处理 | Coordinator 逐链接尝试，单链接失败不中止全局登出 |

#### 选项与权衡

| 选项 | 优势 | 代价 | 推荐 |
|------|------|------|------|
| Session 嵌入 GlobalSID | 登出时零额外查询 | 需迁移 Memory/SQLite/Redis SessionStore | **方案 A（推荐）**——长期正确 |
| 独立 token→gsid 映射 | 零存储迁移 | 每次登出多一次 store read | 过渡方案 |
| 关联 cookie | 零存储变更 | cookie 管理复杂性 | 不推荐（引入状态外溢） |

---

### 2.2 方向 2：前端 SPA 安全治理与工程化（P0）

#### 为什么需要

业务价值：
1. **运维安全**：Admin Console (1385 行 JS) 是管理 OAuth 客户端、租户、用户的管理门户。任何 JS bug 可能导致无声的配置丢失或泄露。
2. **采购合规**：WCAG 2.1 AA 是欧洲公共采购（EN 301 549）的硬要求，Section 508 是美国政府的硬要求。
3. **产品质量**：4 个 SPAs 是管理员/开发者/终端用户看到的第一界面，质量直接影响客户采购评估。

技术价值：消除项目中最大的技术债集中区域（2892 行无测试、无构建、无 i18n 的前端代码）。

#### 核心挑战和技术难点

1. **测试基础设施从零开始**：需要引入 Playwright/Cypress 等 E2E 框架，与 Go 构建系统集成。挑战点：
   - E2E 测试需要运行中的 SSO 服务器实例——需要 wire `bufconn` 或真实 HTTP 服务器
   - 4 个 SPAs 各有不同的认证上下文（Admin Console 需 admin 级 token，Login SPA 需未认证用户）
   - 测试必须能在 CI 中 headless 运行

2. **渐进式引入构建步骤**：当前 JS 以 `.html` 中的 `<script>` 标签直接嵌入。引入 esbuild/Vite 等构建工具需要：
   - 重新设计静态资源目录结构（`src/` vs `dist/`）
   - 将 Go `embed.FS` 指向构建产物目录
   - 版本 hash 以实现缓存失效

3. **CSP report-to 端点**：需要服务端新增 `/csp-report` 端点，收集和审计 CSP 违规。要注意：
   - 端点应 ratelimit 防止 log flood
   - 违规信息应进入审计日志（`audit.EventCSPViolation`）

#### 预期的架构变更

```
interfaces/web/
├── login/          # 现有，原地增强
├── admin/          # 现有，增加 E2E 测试
├── portal/         # 现有，增加 E2E 测试
├── developer/      # 现有，增加 E2E 测试
├── csp_report.go   # 新增：CSP report-to 端点
└── e2e/            # 新增：Playwright 测试套件
```

#### 对现有系统的影响

| 方面 | 影响 |
|------|------|
| 向后兼容 | ✅ 零影响——前端改造不影响 API 契约 |
| 部署 | 构建步骤增加但 Go embed 最终产物体积不变 |
| 开发流程 | 前端开发流程增加构建步骤（esbuild watch 模式可缓解） |
| 响应头 | 新增 CSP report-to 端点（需加入路由表） |

#### 分层建议（P0/P1/P2）

| 优先级 | 工作项 | 策略 |
|--------|--------|------|
| **P0** | CSP report-uri/report-to + XSS 审计 | 后端 1 个新端点 + 前端 1 天审计 |
| **P0** | Playwright E2E 覆盖 Admin Console 核心 CRUD | 引入测试框架 + 核心路径测试 |
| **P1** | esbuild 构建管线（压缩 + hash） | 1-2 天工具链配置 |
| **P2** | i18n + a11y WCAG 2.1 AA | 按功能模块逐步覆盖 |

---

### 2.3 方向 3：出站身份协议 SSRF 统一防护框架（P1）

#### 为什么需要

安全价值：SSRF 是 OWASP A10:2021，云环境下的内部元数据端点（169.254.169.254）暴露风险极高。随着项目扮演越来越多的"出站身份协议发起方"角色（Federation、CAEP、SAML、Webhook、JAR），攻面持续扩大。

技术价值：消除 3+ 处重复的 URL 校验逻辑，建立统一的出站 HTTP 安全基线。

#### 核心挑战和技术难点

1. **DNS 重新绑定攻击防护**：最难的 SSRF 场景——攻击者在 DNS 解析时返回合法 IP，在实际 HTTP 请求时切换到内网 IP。现有 Federation 实现已有 `dialWithSSRFCheck`，其机制是：在 `DialContext` 中 DNS 解析后检查 IP 地址。但这不能完全消除 TOCTOU 窗口（DNS 解析和 HTTP 连接之间仍有窗口）。要完全消除需：
   - 在连接建立后再次验证远程 IP 是否与 DNS 结果一致
   - 或使用 `DialTLS` 中的 ServerName 验证

2. **Whitelist 与 Allowlist 管理**：不同 URL 来源需要不同校验级别。Operator 配置（config.yaml）可以信任，Client 属性需要更严格校验。allowlist 需要：支持通配符（`*.example.com`）、支持端口后缀、支持 ignore path。

3. **本地开发豁免**：严格的 SSRF 防护会阻止连接 `http://localhost` 和 `http://127.0.0.1`。需要显式的开发模式配置。

4. **代理感知**：企业部署中出站 HTTP 可能经过内部代理。SSRF 检查应在代理处理后进行，还是在代理前？如果是代理前，检查目标 URL；如果是代理后，代理本身已经是安全边界。

#### 预期的架构变更

```
shared/outbound/                    # 新增包
├── outbound.go                     # HardenedClient 工厂
├── urlpolicy/
│   ├── policy.go                   # URL 来源分级 + 校验策略
│   ├── whitelist.go                # 白名单匹配（支持 glob/pattern）
│   └── internalip.go               # InternalIP check（从 Federation 提取）
├── dnsrebind/
│   └── guard.go                    # DNS rebind 检测
└── audit.go                        # 出站请求审计事件
```

迁移路径：
```
Phase 1: 新增 shared/outbound（可选使用，不强制）
Phase 2: Federation → shared/outbound（已验证逻辑提取）
Phase 3: CAEP → shared/outbound
Phase 4: SAML meta refresh → shared/outbound
Phase 5: Webhook, JAR, OIDC federation → shared/outbound
```

#### 对现有系统的影响

| 方面 | 影响 |
|------|------|
| 向后兼容 | ✅ 最小——初始版本是可选包装器，不改变现有代码行为 |
| 性能 | 每次出站请求增加一次 DNS 后验证（毫秒级，可接受） |
| 配置 | 新增 `outbound.allowed_domains` 和 `outbound.local_dev_mode` 配置 |
| 迁移 | 非阻塞——模块可逐步迁移，每个迁移独立验证 |

#### 代码复用策略

现有 `domains/federation/fetcher.go` 中的 `dialWithSSRFCheck` 和 `isInternalIP` 是已验证的防护逻辑。应：

1. **提取 `isInternalIP` → `shared/outbound/urlpolicy/internalip.go`**（导出，加 IPv6 覆盖）
2. **提取 DNS rebind 防护模式 → `shared/outbound/dnsrebin/guard.go`**（统一策略，导出）
3. **保留 Federation 的调用不变**，等新包稳定后再迁移（或 Federation 直接复用新包）

**不要重写**——复用已有验证过的逻辑。

---

### 2.4 方向 4：管理 API 乐观并发控制（P1）

#### 为什么需要

业务价值：企业多管理员运维场景下的数据完整性。两个管理员同时编辑同一 OAuth client 配置时，LWW 模式无声覆盖对方的变更。这是 IAM 系统中已知的企业级需求（Auth0、Okta 均已实现版本化 API）。

技术价值：资源版本号也是审计和变更回滚的基础设施——知道"这个 client 的配置在版本 N 时被修改"比"某个时间点有一次 PUT 请求"更有价值。

#### 核心挑战和技术难点

1. **SPI 签名兼容性**：`ClientStore.Update(ctx, client)` 增加 `expectedVersion` 参数会破坏现有所有实现。建议：
   ```go
   // 不破坏现有签名，新增版本化方法
   Update(ctx, client) error                               // 现有，LWW 模式
   UpdateWithVersion(ctx, client, version) error            // 新增，乐观锁
   ```
   这样零破坏，但接口膨胀（每个 store 接口增加一个方法）。

2. **存储层原子条件更新**：SQLite 实现需要 `UPDATE ... WHERE id=? AND version=?`——当版本不匹配时不更新并报告 0 行受影响。Memory 实现需要带锁的版本比较。Redis 实现需要事务 WATCH 版本 key。

3. **ETag 格式选型**：
   - 方案 A：纯版本号整数（`ETag: "42"`）——简单，但弱 ETag
   - 方案 B：版本号 + 资源哈希（`ETag: W/"42-a3b8c9"`）——弱 ETag，支持内容校验
   - 方案 C：内容哈希（`ETag: "a3b8c9..."`）——强 ETag，但后续升级到 If-Match 时需要内容比对

4. **适用范围裁剪**：乐观锁不应所有资源一刀切。建议：
   - `ClientStore`：实现（client 配置丢失影响最大）
   - `TenantStore`：实现（tenant 配置变更影响全局）
   - `UserStore`：可暂缓（用户属性变更冲突概率低，且回滚难度高）
   - `SessionStore`：不需要（session 是运行时状态，非配置）

#### 预期的架构变更

- `core/client_store.go`：新增 `UpdateWithVersion(ctx, client, version) error` + `ErrVersionConflict`
- `defaultimpl/memory/client.go`：实现版本检查（`version int64` 字段 + 原子自增）
- `defaultimpl/sqlite/client.go`：`UPDATE clients SET ... WHERE id=? AND version=?` + `ErrVersionConflict` 转型
- `defaultimpl/redis/client.go`：`WATCH` + `version` key 的事务
- `admin/handler.go` client handler：增加 `ETag` 响应头 + `If-Match` 请求头解析
- `admin/handler.go` tenant handler：同上

#### 对现有系统的影响

| 方面 | 影响 |
|------|------|
| 向后兼容 | ✅ 100%——不提版本号的旧请求继续以 LWW 模式工作 |
| 性能 | Memory/SQLite 增加一次版本比较（可忽略） |
| 存储 | Memory 增加 `version int64`，SQLite 增加 `version INTEGER` |
| API 契约 | `PUT` 响应增加 `ETag` 头部（下游忽略旧头部无影响） |

---

### 2.5 方向 5：SessionHub 链接生命周期管理 —— TTL + 清理（P2）

#### 为什么需要

可扩展性价值：一个 100K MAU 的 SSO 部署，如果 LinkRecord 没有 TTL 和清理，1 年累积 3650 万条死链接。Memory 实现会导致显著 GC 压力，SQLite 实现会导致查询退化。

一致性价值：Session 过期（销毁）与 LinkRecord 删除是独立的操作。缺少协调意味着 LinkStore 中存在"幽灵链接"——声称存在的 session_id 实际已销毁。

#### 核心挑战和技术难点

1. **TTL 值从何处派生**：LinkRecord 的 TTL 不应独立设定，而应派生自 session 的 `AuthResult.MaxAge`。但 `MaxAge` 是在登录时确定的，登录后可能因管理员操作而改变（强制会话过期）。

2. **跨副本清理一致性**：TTL 清理在每个副本本地执行（无需广播、无需分布式协调）。但需要保证清理不干扰正在进行的 `Logout()` 操作——清理 goroutine 与 Get/Set 之间需要免锁的过期标记。

3. **清理周期与延迟之间的权衡**：清理周期过短（< 1s）会导致不必要的锁争用；过长（> 1h）则 TTL 过期后的可见性窗口太大。建议 5 分钟为默认周期。

#### 预期的架构变更

- `core/linkrecord.go`：`LinkRecord` 增加 `expiresAt time.Time` 字段
- `platform/lifecycle/sessionhub/linkstore.go`：增加 `DeleteLeg()` + `ListByUser()` + `GC()` 方法
- `platform/lifecycle/sessionhub/memorylinkstore.go`：实现 TTL 过期 + `GC()` goroutine
- `platform/lifecycle/sessionhub/sqlitelinkstore.go`：实现 TTL 过期 + 清理 SQL
- `platform/lifecycle/sessionhub/options.go`：增加 `WithTTL(duration)` 配置
- `cluster/bus.go`：复用 `KindTokenRevoked` 事件触发链接清理

#### 对现有系统的影响

| 方面 | 影响 |
|------|------|
| 向后兼容 | ✅ 零影响——TTL 是附加的，现有 LinkRecord 迁移时 expiresAt 可设为 NULL |
| 存储 | LinkRecord 增加 `expires_at` 列 |
| 性能 | reaper goroutine 每 5 分钟运行一次，可忽略 |
| 配置 | 新增 `sessionhub.ttl` 和 `sessionhub.gc_interval` 配置 |

---

## 3. 接口设计原则与建议

### 3.1 关键原则

#### 原则一：向后兼容优先

方向 4（乐观锁）和方向 3（SSRF 框架）必须保证 100% 向后兼容。风格：

```go
// ✅ 好：新增方法，保留旧方法
Update(ctx, client) error               // 现有 LWW
UpdateWithVersion(ctx, client, v) error // 新增乐观锁
```

而不是：

```go
// ❌ 差：破坏性参数变更
Update(ctx, client, v *int64) error     // 所有调用方需要修改
```

#### 原则二：可选而非强制

方向 3 的 SSRF 客户端应作为可选包装器，而非全局替换。各模块可在准备好后逐步迁移。

```go
// 可选包装器模式
outboundClient := outbound.NewHardenedClient(
    outbound.WithDefaultTimeout(15*time.Second),
    outbound.WithBlockInternalIPs(true),
)
// 仍可继续使用裸 http.Client
```

#### 原则三：切片分离，逐步演进

方向 2 的 SPA 改造应分 P0/P1/P2 切片，每个切片可独立发布。P0 安全 + 测试不依赖 P2 i18n + a11y。

#### 原则四：复用已验证逻辑

方向 3 的 SSRF 防护应基于 Federation 现有已验证的 `dialWithSSRFCheck`，提取共享，而非重写。Federation 应作为 SSRF 框架的第一个消费者和验证者。

### 3.2 是否需要新的抽象层

| 方向 | 需要新抽象层？ | 理由 |
|------|---------------|------|
| 方向 1 | ❌ 不需要 | 只需接线，Coordinator 已存在 |
| 方向 2 | ❌ 不需要（但需要新工具链） | Playwright + esbuild 是工具链增强，非架构抽象 |
| 方向 3 | **✅ 需要** | `shared/outbound` 是新包 |
| 方向 4 | ❌ 不需要 | SPI 方法增加，无需新包 |
| 方向 5 | ❌ 不需要 | LinkStore 接口扩增，无需新包 |

唯一需要新抽象层的是方向 3（`shared/outbound`）。其他方向均在现有架构内扩展。

### 3.3 SessionManager 接口是否需要扩增

方向 1 的关键问题：登出时如何从 token 反查 GlobalSID？

现有中间件 `resolveSession` 已能从 cookie/bearer token 解析出 `*core.Session` 对象。如果 Session 增加 `GlobalSID` 字段，则登出路径只需：

```go
// 现有代码（已在 resolveSession 中完成）
session, err := resolveSession(r)

// 新增一行
gsid := session.GlobalSID
s.sessionHub.Logout(ctx, gsid, session.UserID)
```

**推荐：Session 增加 GlobalSID 字段**，因为：
1. Session 的生命周期与 GlobalSID 对齐（登录时生成，销毁时删除）
2. 零额外 store read（相比独立映射方案）
3. 存储迁移成本低——现有 Memory/SQLite/Redis SessionStore 只需在创建 Session 时设置 GlobalSID

### 3.4 LinkStore 接口演进的兼容性策略

方向 5 需要扩增 LinkStore 接口。应采用"新增方法 + 默认 no-op 实现"模式：

```go
type LinkStore interface {
    // 现有
    Set(ctx, gsid, protocol, id, userID) error
    Get(ctx, gsid) ([]LinkRecord, error)
    Delete(ctx, gsid) error

    // 新增 V2
    DeleteLeg(ctx, gsid, protocol) error  // 实现可选
    ListByUser(ctx, userID) ([]LinkRecord, error) // 实现可选
    GC(ctx) error // 后台清理
}
```

对于未实现 `DeleteLeg` 的 store（如 Redis 尚未迁移），返回 `ErrNotImplemented`。

---

## 4. 技术选型建议

### 4.1 是否需要引入新的技术栈或框架

| 方向 | 技术选型 | 建议 | 理由 |
|------|---------|------|------|
| 方向 2 测试 | Playwright vs Cypress | **Playwright** | 支持 Go + 多浏览器 + 网络拦截 + CI 友好 |
| 方向 2 构建 | esbuild vs Vite vs Webpack | **esbuild** | 极速、零配置、Go 亲和（esbuild 用 Go 编写） |
| 方向 2 a11y | axe-core vs Lighthouse CI | **axe-core** | 作为 Playwright 插件集成，CI 中自动化 |
| 方向 3 DNS rebind | 自建 vs 库 | **提取 + 自建** | 现有 Federation 已有已验证实现，提取即可 |
| 方向 4 ETag | 整数 vs hash vs 弱 ETag | **整数版本号** | 简单、可比较、可排序、适合乐观锁场景 |
| 方向 5 后台清理 | goroutine vs cron vs 分布式调度 | **goroutine + ticker** | SessionHub 不是独立服务，分布式调度过重 |

### 4.2 第三方依赖评估标准

引入新依赖的决策树：

```
需要引入新依赖吗？
├→ 可用 50 行以内自建？→ 自建（强偏好）
├→ Go 标准库已有？ → 使用标准库（如 net/http、crypto/tls）
├→ 安全关键功能？ → 优先经过审计的库（如 FIPS 验证的加密库）
└→ 其余 → 评估：许可证兼容性 + 维护活跃度 + 依赖树大小
```

对于本报告各方向：

| 候选依赖 | 评估 |
|----------|------|
| Playwright (测试框架) | ✅ 推荐——Go 项目已有 E2E 测试先例，Playwright 支持多浏览器 |
| esbuild (JS 构建) | ✅ 推荐——Go 编写，无 Node 运行时依赖，'go generate'可调用 |
| axe-core (a11y 检查) | ⚠️ 可选——Playwright 已有 `@axe-core/playwright` 集成，但需 Node 运行时 |
| 自定义 SSRF 库 | ❌ 自建——Federation 已有已验证实现，提取到 shared 包即可 |

### 4.3 自建 vs 采购的决策依据

本报告的 5 个方向全部是**架构的内部增强**，不涉及外部系统集成——方向 3 是统一内部出站安全策略，不是采购第三方安全代理。因此自建是唯一合理的选择。

潜在的外部依赖讨论：
- 方向 3 的 DNS rebind 防护：如要使用商业 DNS 防火墙服务（如 Akamai Edge DNS），那是部署运维问题，不在本架构范围。
- 方向 2 的 CSP report-to：如要使用第三方 CSP 监控（如 report-uri.com），那是可选增强，不是架构依赖。项目应先自建，后续可考虑外部服务。

---

## 5. 实施路线图

### 5.1 优先级排序

```
P0 (立即开始)         P1 (并行启动)        P2 (方向 1 后)
────────────────────  ───────────────────  ───────────────────
方向 1: 登出侧集成   方向 3: SSRF 框架    方向 5: Link 清理
方向 2 P0: CSP+测试  方向 4: 乐观锁
方向 2 P1: 构建管线
```

#### P0 为何选择方向 1 + 方向 2 P0

- **方向 1**: 改动量极小（~30 行），安全影响明确，消除最大的架构债务（"只写不读"代码）
- **方向 2 P0 (CSP + E2E 测试)**: 安全基线 + 质量基线，消除最大的技术债区域
- **方向 2 P1 (构建管线)**: 构建管线是 i18n 和 a11y 的前提——无构建管线就无法引入翻译文件编译

#### P1 为何方向 3 + 方向 4 可以并行

- 方向 3（SSRF 框架）和方向 4（乐观锁）**零依赖冲突**——一个改出站安全，一个改 Admin API 数据完整性
- 两者的代码修改位置不重叠（`shared/outbound` vs `admin/handler.go`）
- 两者都需要存储层适配但影响不同的存储接口（`http.Client` vs `ClientStore`）

#### P2 为何方向 5 在方向 1 之后

- 方向 5 解决的是 LinkRecord 的清理问题（TTL + reaper）
- 方向 1 解决的是 LinkRecord 的消费问题（登出时删除）
- 方向 1 先实施后，LinkRecord 的消费路径打通，方向 5 再补 TTL 作为兜底清理
- 两者不互相阻塞，但方向 1 的安全影响更直接

### 5.2 阶段划分与里程碑

#### 阶段 1：安全与质量基线（第 1-2 周）

| 周 | 工作项 | 交付物 | 验证方式 |
|----|--------|--------|---------|
| 1 | 方向 1：登出侧集成 | Session 增加 GlobalSID + 2 个调用点接线 | `go test ./...` 全绿 |
| 1 | 方向 2 P0a：CSP report-to | `/csp-report` 端点 + 审计日志 | curl 手动验证 |
| 2 | 方向 2 P0b：Playwright E2E | Admin Console CRUD 核心路径 E2E | `make e2e` CI green |
| 2 | 方向 2 P1：esbuild 构建 | 4 个 SPA 压缩 + hash + `go:generate` | 构建产物验证 |

**里程碑 1：** `make acceptance` + `make e2e` 全绿。所有 SPAs 可验证版本号。

#### 阶段 2：出站安全与数据完整性（第 3-4 周）

| 周 | 工作项 | 交付物 | 验证方式 |
|----|--------|--------|---------|
| 3 | 方向 3 Phase1：`shared/outbound` | `HardenedClient` 工厂 + `IsInternalIP` 导出 | `TestHardenedClient_*` |
| 3 | 方向 3 Phase2：Federation 迁移 | Federation fetcher 复用 shared/outbound | `TestFederation_NoRegression` |
| 4 | 方向 4：乐观锁 ClientStore | `UpdateWithVersion` + Memory/SQLite 实现 + Admin ETag | `TestOptimisticLock_*` |

**里程碑 2：** 所有出站身份协议经过统一安全基线。Admin API 可检测丢失更新。

#### 阶段 3：清理与可扩展性（第 5-6 周）

| 周 | 工作项 | 交付物 | 验证方式 |
|----|--------|--------|---------|
| 5 | 方向 5：LinkStore TTL + DeleteLeg | `LinkRecord.expiresAt` + `GC()` goroutine | `TestLinkStore_TTL` |
| 5 | 方向 5：事件总线集成 | `KindTokenRevoked` → LinkStore 清理 | `TestSessionDestroy_ClearsLinks` |
| 6 | 方向 2 P2a：i18n 试点（Login SPA） | Login SPA 中文/日文 bundle | `Accept-Language: zh-CN` 验证 |
| 6 | 方向 2 P2b：a11y 首轮（Login SPA） | ARIA + 键盘导航 + 焦点管理 | axe-core 报告 |

**里程碑 3：** LinkStore 可清理旧链接，零无限增长风险。Login SPA 支持中/日/英文。

#### 阶段 4：全面覆盖（第 7-8 周）

| 周 | 工作项 | 交付物 | 验证方式 |
|----|--------|--------|---------|
| 7 | 方向 3 Phase3-4：CAEP + SAML 迁移 | CAEP/SSF 推送、SAML 元数据刷新使用 shared/outbound | `TestCAEP_NoRegress` |
| 8 | 方向 4：乐观锁 TenantStore | Tenant `UpdateWithVersion` + ETag 集成 | `AdminAPI_ETag_*` |

**里程碑 4：** 5 个方向全部实现。`make acceptance` + `make e2e` 全绿。代码核验确认零新增技术债。

### 5.3 风险点与缓解策略

| 风险 | 影响方向 | 概率 | 影响 | 缓解策略 |
|------|---------|------|------|---------|
| Session 增加 GlobalSID 字段导致现有存储迁移故障 | 方向 1 | 中 | 高 | 使用 optional 语义（NULL 表示无关联）；Memory 实现零迁移 |
| Playwright E2E 测试与 Go test runner 集成困难 | 方向 2 | 中 | 中 | 使用 `//go:generate` + shell script 调用 npx playwright；先用 Postman/curl 做备选 |
| esbuild 构建管线改变现有 `embed.FS` 路径 | 方向 2 | 低 | 高 | 保持输出目录与现有嵌入路径一致（`interfaces/web/*/dist`→`embed.FS`） |
| DNS rebind 防护导致合法请求被误拦 | 方向 3 | 中 | 高 | 实现 `localDevMode` 配置豁免；allowlist 覆盖已知合法端点 |
| `UpdateWithVersion` 在 Redis 实现中的原子性 | 方向 4 | 中 | 中 | 使用 Redis `WATCH` + 事务；或退化为 LWW（记录审计日志） |
| LinkRecord TTL 过短导致活跃用户的链接被误清理 | 方向 5 | 低 | 中 | TTL 派生自 session `MaxAge`，不独立设定；reaper 默认 5 分钟周期 |

### 5.4 不做清单（明确排除）

以下事项虽然可以增强系统，但属于"额外功能"而非"缺口修复"，不在本路线图范围内：

| 事项 | 原因 |
|------|------|
| SPA 框架迁移（React/Vue/Svelte） | 引入框架增加维护成本，Vanilla JS + esbuild 足够 |
| 全局 Configuration Management 数据库 | 资源版本号已经提供审计基础，CMDB 是独立产品 |
| 出站流量代理（如 egress proxy） | 运营商/基础设施问题，非 SSO 软件问题 |
| LinkRecord 分布式 reaper（如 distributed cron） | 本地 periodic goroutine 足够，无需分布式协调 |
| Admin API 批量操作的事务支持 | 方向 4 的乐观锁不解决批量原子性问题，那是独立特性 |

---

## 6. 与历史分析的关系

| 本报告方向 | 相关历史分析 | 差异说明 |
|-----------|-------------|---------|
| 方向 1 | `deferred-backlog.md` 将 SessionHub 标记为 "done" | 登录侧 done，登出侧从未审计——首次披露 |
| 方向 2 | 22 轮分析均标记 4 个 SPAs 为 "✅ 全部落地" | 从功能存在性角度"落地"，非质量角度——首次做代码质量审计 |
| 方向 3 | `expansion-production-hardening-analysis.md`（Circuit Breaker 方向） | 那篇聚焦通用 CB/bulkhead——本方向聚焦身份协议特有的 SSRF 防护 |
| 方向 4 | 无 | 22 轮分析未涉及 Admin API 并发控制——首次披露 |
| 方向 5 | 无 | SessionHub LinkStore 生命周期从未被分析——首次披露 |

---

## 7. 结论

这 5 个方向共同揭示了 Snaplink 项目中一个系统性的模式：**"连接点"的缺失**。

SessionHub 有 Coordinator 但无人调用登出（连接点缺失）→ 方向 1  
4 个 SPAs 有完整功能但无测试和安全治理（质量治理连接点缺失）→ 方向 2  
7+ 出站调用有各自防护但无统一框架（安全基线连接点缺失）→ 方向 3  
Admin API 有完整 CRUD 但无并发控制（写入一致性连接点缺失）→ 方向 4  
LinkStore 有写入和读取但无生命周期管理（资源释放连接点缺失）→ 方向 5  

这些不是独立的 bug，而是一个共同架构债务模式的不同表现：项目在功能完整度上已达行业顶级水平，但在**横切系统边界的基础设施**上尚未完成系统化的构建。

**推荐的实施顺序：** 方向 1 + 方向 2 P0 并行启动（最低成本、最高收益）→ 方向 3 + 方向 4 并行（安全纵深 + 数据完整性）→ 方向 5（可扩展性兜底）。所有方向均可在 8 周内完成，零破坏现有功能，100% 向后兼容。
