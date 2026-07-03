# 第十一轮分析：mTLS 客户端认证、许可证合规、优雅关闭与可观测性缺口

> 基于全局代码库扫描产生的全新视角，此前十轮未覆盖。

---

## 方向一：DCR 缺少 `tls_client_auth` 客户端认证方式——mTLS 支持半截

**问题：** `protocols/oauth/oauthvalidate/dcr_validate.go:72` 的 DCR 验证只接受以下 `token_endpoint_auth_method`：

```go
case "", "client_secret_basic", "client_secret_post", "none":
    return ErrDCR("unsupported token_endpoint_auth_method: " + req.TokenEndpointAuthMethod)
```

`tls_client_auth` 和 `self_signed_tls`（RFC 8705 §2）**缺失**。与此同时，token 绑定确实支持 mTLS——`shared/core/types_token.go:59` 定义了 `ConfirmationX5TS256` 用于 mTLS 绑定的 access token，`interfaces/sso/server_token.go` 也会在 `/token` 验证 mTLS 客户端证书。所以：

- mTLS **作为 token 绑定机制**：✅ 支持（cnf.x5t#S256）
- mTLS **作为客户端认证方法**：❌ 不支持（DCR 拒绝 `tls_client_auth`）
- OIDC 发现中 **`tls_client_auth` 不在 `token_endpoint_auth_methods_supported`**：❌

**实际影响：** 金融机构和受监管行业（PSD2、HIPAA、PCI）通常要求 mTLS 客户端认证。目前，客户端只能使用 `client_secret_basic`、`client_secret_post` 或 `private_key_jwt`——都不具备 mTLS 防重放和传输级保证。

**修复：** 添加 `tls_client_auth` 和 `self_signed_tls` 到 DCR 验证的允许列表中。在 `TokenHandler` 中添加 mTLS 客户端认证验证（从请求中提取客户端证书，与存储的注册证书指纹进行比对）。更新发现文档以声明支持。

**工作量：** M（验证 + 注册存储字段 + 处理程序中的 mTLS 认证 + 发现更新）| **影响：** **高**（受监管行业合规性要求）| **类型：** 功能/合规

---

## 方向二：用户自助 WebAuthn 凭据管理缺失——无法列出/重命名/删除通行密钥

**问题：** `domains/authenticators/webauthn/` 提供了完整的通行密钥注册和认证流程，并在 `webauthn_memory_store.go` 中提供了 `WebAuthnUser.Credentials` 映射来存储凭据。但**没有面向用户的凭据管理 API**。

**具体缺口：**
- 无 `GET /me/webauthn-credentials`——列出已注册的通行密钥（带有创建时间、最后使用时间、设备名称）
- 无 `PATCH /me/webauthn-credentials/:id`——重命名通行密钥（别名）
- 无 `DELETE /me/webauthn-credentials/:id`——删除单个通行密钥
- 无 `GET /me/webauthn-credentials/:id/update`——更新通行密钥（例如更新 AAGUID 信息后的友好名称）

**为什么这是一个问题：** 用户注册了多个通行密钥（手机 FaceID、笔记本 TouchID、YubiKey）。当手机丢失时，他们想：
1. 看看注册了哪些密钥 → **不行**（无列表端点）
2. 删除丢失手机上的通行密钥 → **不行**（无删除端点）
3. 给通行密钥取个友好的名字 → **不行**（无重命名端点）

**修复：**
1. 添加 `CredentialStore.ListByUser(userID) ([]Credential, error)` SPI
2. 添加 `CredentialStore.DeleteByID(userID, credentialID) error`
3. 添加 `POST /me/webauthn-credentials`（注册新通行密钥）——已有
4. 添加 `GET /me/webauthn-credentials`（列出）
5. 添加 `DELETE /me/webauthn-credentials/:credentialID`（删除）
6. 添加 `POST /me/webauthn-credentials/:credentialID/rename`（重命名）

**工作量：** M（后端存储 + 4 个端点 + 管理 UI 集成）| **影响：** 中（UX 完整性）| **类型：** 功能

---

## 方向三：缺少运行时依赖许可证合规审计——企业采购障碍

**问题：** 该项目有 97+ 个 Go 依赖项（13 个 `go.mod` 文件中的根模块 + 基础设施子模块），许可协议包括 Apache-2.0、MIT、BSD、LGPL 和 **GPL**。但没有：

- **没有 `go-licenses` 或 `licensei` CI 步骤**来验证所有依赖项都使用允许的许可证
- **没有 `THIRD_PARTY_NOTICES` 文件**用于分发（Apache 2.0 §4 要求衍生作品包含通知）
- **没有 SBOM 生成**（例如 `syft` 或 `spdx-sbom-generator`）——操作员无法轻松生成 CycloneDX 或 SPDX SBOM 用于漏洞管理
- **没有 `LICENSE.dependencies` 文件**列出依赖项及其许可证

**企业影响：** 财富 500 强公司的法律/合规团队在部署前需要完整的第三方许可证清单。没有它，采购审查会阻塞或推迟数月。

**快速检查需要注意的内容：**
- `modernc.org/sqlite`：LGPL（需要动态链接合规性考量）
- `golang.org/x/crypto`：BSD
- `github.com/go-webauthn/webauthn`：Apache-2.0
- `github.com/crewjam/saml`：Apache-2.0

**修复：**
1. 添加 `make licenses` 目标 → `go-licenses csv ./...` 生成依赖 → 许可证映射
2. 在 CI 中添加 `licenses-check` 步骤，拒绝 GPL/AGPL/SSPL 许可证（除非明确允许）
3. 添加 `.github/workflows/sbom.yml` → 每次发布时用 `syft` 生成 SBOM
4. 自动化生成 `NOTICE.txt` 以包含所有 Apache-2.0 依赖项的通知

**工作量：** S（~50 行 CI + Makefile 配置）| **影响：** **中高**（企业采购的关键阻碍）| **类型：** 合规/法律

---

## 方向四：关键路径指标可观测性缺口——哪些未被测量

**问题：** `platform/metrics/metrics.go` 定义了一个干净的 `Metrics` 结构体，包含 12 个 Prometheus 指标向量。但多个关键路径**完全没有被仪器化**：

| 关键路径 | 已测量？ | 问题 |
|----------|---------|------|
| HTTP 请求 + 延迟 | ✅ | `HTTPRequestsTotal` + `HTTPRequestDuration` |
| 登录尝试 | ✅ | `LoginAttemptsTotal` |
| 发放的令牌 | ✅ | `TokensIssuedTotal` |
| 按租户发放的令牌 | ✅ | `TokensIssuedByTenantTotal` |
| MFA 挑战/完成 | ✅ | `MFAChallengesTotal` + `MFACompletionsTotal` |
| **refresh_token 旋转** | ❌ | 无法知道 refresh family 重放或旋转率 |
| **授权码消耗** | ❌ | 无法知道 `/auth` → `/token` 转化率 |
| **OIDC 静默续期** | ❌ | 无法衡量静默 vs 交互式续期比率 |
| **token 内省/吊销** | ❌ | 无法知道内省 vs 发放比率 |
| **PAR 使用率** | ❌ | 无法知道 PAR vs 非 PAR 授权比率 |
| **数据库操作延迟** | ❌ | 无法按存储测量 p50/p99 延迟 |
| **上游 IdP 健康状态** | ❌ | 无法知道联邦上游的可用性 |
| **集群总线消息** | ❌ | 无法知道跨副本事件延迟 |
| **会话活动计数** | ❌ | 无法按租户知道活动会话的基数 |
| **速率限制器触发** | ❌ | 无法知道有多少请求被限制 |
| **缓存命中率** | ✅（部分） | `ClientStoreCacheTotal` 存在但内省缓存/JWKS 缓存未测量 |

**影响：** 如果没有这些指标，操作员在排查时只能盲目猜测："用户的刷新令牌旋转是否异常？"、"内省速率是否激增？"、"数据库连接池是否存在瓶颈？"——这些都只能通过日志搜索（而非仪表盘）来回答。

**修复：**
1. 为每个关键路径添加 `CounterVec`/`HistogramVec`
2. 添加数据库调用包装器以注入延迟直方图
3. 在仪表盘（Grafana）JSON 中添加注释，标明哪些面板依赖新指标

**工作量：** M（每个关键路径增加 5-15 行 + 仪表盘更新）| **影响：** 中（可观测性深度）| **类型：** 可观测性/运维

---

## 方向五：优雅关闭未覆盖后台 goroutine——滚动重启时可能丢失工作

**问题：** `cmd/sso-server/main.go:293-302` 正确地捕获 SIGINT/SIGTERM，并在 5 秒超时内调用 `shutdownServers(ctx, ...)`。但存在多个后台 goroutine 和定时器，它们在关闭期间**可能被截断或忽略**：

| 后台任务 | 位置 | 关闭处理 |
|----------|------|----------|
| HTTP 服务器 | `main_shutdown.go:43` | ✅ `Shutdown(ctx)` |
| gRPC 服务器 | `main_shutdown.go:54` | ✅ `GracefulStop()` |
| **签名密钥轮换定时器** | `defaultimpl/rsa_rotation_scheduler.go` / `ecdsa_rotation_scheduler.go` | ❌ 没有明确的关闭信号 |
| **审计旧数据清理定时器** | `audit/sqlite/maintenance.go:Prune()` 的调度器 | ❌ 没有关闭钩子 |
| **异常运行器工作者** | `anomaly.go:23-86`（AsyncAnomalyRunner 工作者） | ❌ `Close()` 在 `main.go` 中未调用 |
| **集群总线订阅** | `server_invalidation.go:80-81`（取消 ctx → 退出） | ✅ 通过 ctx 取消 |
| **MDS 刷新循环**（当实现时） | 尚不存在（来自第 8 轮的方向 1） | ❌ 尚不存在 |
| **留存定时器** | `platform/audit` 的 `RetentionPruneTotal` 指标 | ❌ 没有关闭钩子 |

**具体风险：**
1. `anomaly.go` 的 `AsyncAnomalyRunner` 有 `Close()` 方法，但在 `main.go` 中**never called**——工作程序在服务器退出时被截断，可能会丢失尚未刷新的行为事件
2. RSA/ECDSA 签名密钥轮换调度器使用 `time.NewTicker`——在滚动重启期间，如果轮换恰好发生，则计时器被丢弃且新副本需要 24 小时才能触发轮换

**修复：**
1. 添加 `shutdownContext` 传递给所有后台 goroutine
2. 在 `main.go:302` 的 `shutdownServers` 之前调用 `anomalyRunner.Close()`
3. 向每个后台定时器循环添加 `select { case <-ctx.Done(): return; case <-ticker.C: ... }` 模式

**工作量：** M（审计~8 个后台循环 + 添加 ctx 传播 + 在 main 中排序关闭序列）| **影响：** 中（优雅关闭可能是数据完整性差异的关键）| **类型：** 运维/弹性

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | `tls_client_auth` DCR 缺失（mTLS 认证） | **高**（金融合规性要求） | M | 合规/功能 |
| 2 | 依赖许可证合规审计（SBOM + 企业采购） | **中高**（企业采购阻碍） | S | 合规 |
| 3 | 优雅关闭后台 goroutine 覆盖缺失 | 中（滚动重启的数据丢失） | M | 运维 |
| 4 | 关键路径可观测性缺口（15+ 未测量路径） | 中（生产排故盲区） | M | 可观测性 |
| 5 | WebAuthn 凭据自助管理（列出/重命名/删除） | 中（UX 完整性） | M | 功能 |

**按 ROI 排列：** 方向 1（mTLS 客户端认证——对于受监管行业是一项硬性要求，阻止了整个客户群体）→ 方向 2（许可证合规——5 行配置可能消除企业采购障碍）→ 方向 3（优雅关闭——正确的关闭顺序可防止滚动部署期间的数据丢失）→ 方向 4（可观测性——使生产排故更快）→ 方向 5（WebAuthn 管理——用户体验增益，但安全优先级低于合规性）。
