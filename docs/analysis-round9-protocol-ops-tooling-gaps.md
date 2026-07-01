# 第九轮分析：协议桥接、运维工具链与安全自动化缺口

> 基于全局代码库扫描产生的全新视角，此前八轮未覆盖。

---

## 方向一：缺少 SAML 2.0 Bearer Assertion Grant（RFC 7522）——OIDC 与 SAML 之间存在协议孤岛

**问题：** 代码库拥有完整的 OAuth 2.0 / OIDC 协议栈 **以及** 一个强大的 SAML 2.0 IdP（`infrastructure/saml/idp/`）和 SP（`infrastructure/saml/sp/`）实现。但这两者之间**没有桥接**——无法接收 SAML 断言并将其交换为 OAuth 访问令牌。

具体缺失：
- 无 `urn:ietf:params:oauth:grant-type:saml2-bearer` grant type 处理程序
- 无 `GrantTypeSAML2Bearer` 常量（与 `GrantTypeAuthorizationCode`、`GrantTypeRefreshToken` 等并列）
- 无 `SAMLAssertionValidator`——解析并验证传入的 SAML 2.0 断言（验证签名、受众限制、条件、SubjectConfirmation）
- 无将已验证的 SAML NameID 映射到本地用户的身份连接解析

**为什么这是一个缺口：** 这是企业 SSO 中最常见的联合模式之一——一个平台接受来自合作伙伴 IdP 的 SAML 断言，并为下游 API 请求发放 OAuth 令牌。没有它，部署人员必须运行两个独立的 SSO 系统，或者编写自定义 shim。

**修复：** 大约 300 行代码的新 grant 处理程序 + SAML 断言解析器（利用现有的 `crewjam/saml` 依赖）。重复现有的 grant 模式：`bind → validate → resolveUser → issueTokens`。

**工作量：** M（一个新 grant 处理程序 + 断言验证 + 连接查找）| **影响：** **高**（解锁 SAML→OAuth 企业用例）| **类型：** 功能

---

## 方向二：缺少 JWT 声明投影（裁剪令牌大小）——id_token 随每个新声明线性增长

**问题：** `shared/core/types_token.go:193` 定义了 `RequestedClaims map[string]interface{}`——客户端可以请求额外的声明。但服务器**始终发放所有可用的声明**，无论客户端是否需要。

具体来说：
- `TokenClaims` 结构体包含 `ClientID`、`JTI`、`AuthTime`、`ACR`、`AMR`、`SID`、`Sub`、`Aud`、`Exp`、`Iat`、`Nonce`、`Extra`（任意声明）——每个 id_token 都包含所有这些字段
- 对于仅需要 `sub` 和 `aud` 的 RP（例如简单的 API 网关），id_token 仍包含 `amr`、`acr`、`auth_time`、`sid`、`jti`——增加 200-300 字节
- 没有声明投影/过滤机制——没有白名单，没有 `claims` 参数过滤
- cookie 大小很重要：id_token 作为 session cookie 传递给 RP。一个 1024 字节的 id_token 意味着每次请求都有 1024 字节的 cookie 开销。对于每次请求额外携带 200 字节的不必要声明（AMR、ACR、JTI），会累积成显著的带宽损失。

**RFC 相关：** OIDC Core §5.6.2 定义了 `claims` 参数，用于客户端指定它们想要哪些声明。客户端 DCR 中的 `Claims` 字段定义了发布声明时的默认投影。目前两者都没有被使用。

**修复：**
1. 添加 `id_token_claims` 客户端元数据字段（`{"sub": true, "email": true, "groups": true}`）作为白名单
2. 实现 `claims` 授权请求参数过滤——仅发放客户端请求的声明
3. 为隐式流和混合流添加 `response_type=token id_token` 的 JARM + 声明投影

**工作量：** M（客户端注册字段 + 请求参数解析 + 发放时的过滤逻辑）| **影响：** L-M（cookie 大小 + 带宽）| **类型：** 性能

---

## 方向三：sso-ctl 无法管理会话——管理 API 的 CLI 覆盖不完整

**问题：** gRPC `TokenAdminService` 公开了 `ListSessions`、`Revoke` 和 `IssueTempToken` RPC。但 `sso-ctl`（`cmd/sso-ctl/`）**没有这些操作的子命令**。

`sso-ctl` 目前可以执行的：

| 命令 | 状态 |
|------|------|
| `migrate` | ✅ |
| `snapshot` create/restore | ✅ |
| `import` | ✅ |
| `audit-verify` | ✅ |
| `config` | ✅ |
| `hash` | ✅ |
| **`sessions list`** | ❌ |
| **`sessions revoke`** | ❌ |
| **`tokens revoke`** | ❌ |
| **`tokens issue-temp`** | ❌ |
| **`clients list/create/update/delete`** | ❌ |
| **`users list/create/disable`** | ❌ |

操作员必须：
1. 从 `infrastructure/defaultimpl/sqlite/sessions.go` 找到正确的 SQLite 数据库
2. 运行 `sqlite3 /var/lib/sso/sso.db "SELECT * FROM sessions WHERE user_id = ?"` 
3. 确认 `revoke` 应调用 `TokenAdminService.Revoke` 而不是 `DELETE FROM sessions`

**修复：** 向 sso-ctl 添加子命令：
- `sso-ctl sessions list [--user=] [--limit=]`
- `sso-ctl sessions revoke <sessionID>`
- `sso-ctl tokens revoke <tokenJTI>`  
- `sso-ctl clients list --format=json|table`
- 使用 gRPC 网关 HTTP 客户端（`gen/proto/admin/v1/tokens.pb.gw.go` 已经生成 HTTP 存根）

**工作量：** M（每个子命令约 50 行 + 共享的 gRPC 客户端设置）| **影响：** 中（生产运维）| **类型：** 运维

---

## 方向四：缺少依赖更新自动化——13 个 go.mod 文件全部需要手动 Dependabot 配置

**问题：** 有 13 个独立的 `go.mod` 文件（根模块 + 12 个基础设施子模块）。CI 中存在 `govulncheck`（`.github/workflows/ci.yml:142`）和 `trivy`（`.github/workflows/trivy.yml`）。但：

- **没有 Dependabot 配置**（无 `.github/dependabot.yml`）
- **没有 Renovate 配置**（无 `renovate.json`）
- 每个新的 CVE 都必须手动检测：运行 `cd infrastructure/saml/ && go list -m all`，手动检查已知的 CVE
- 即使 CVE 被 `govulncheck` 发现，**也没有自动创建 PR**——它只会在 CI 中失败
- 13 个 `go.mod` 文件意味着上游库有 13 个不同的版本集——CVE 补丁必须应用于每个文件的依赖项

**当前状态：**
```yaml
.github/workflows/ci.yml:168:      - name: govulncheck
.github/workflows/ci.yml:191:        run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
.github/workflows/trivy.yml:2:# Trivy filesystem + config scan, run weekly via schedule
```

`govulncheck` 是只报告的（`exit-code: 1` 如果发现漏洞），但**它不能修复它们**。没有 `dependabot` 或 `renovate` PR 意味着补丁是手动且容易被遗忘的。

**修复：**
1. 在 `.github/dependabot.yml` 中添加 Dependabot 配置，指向所有 13 个 `go.mod` 文件
2. （或）添加 `renovate.json`——Renovate 更好地支持 monorepo 和多个 `go.mod` 文件
3. 添加一个带有 `on: schedule: weekly` 的 `go-mod-tidy` CI 工作流，以确保 `go.sum` 文件保持最新

**工作量：** S（约 30 行的 Dependabot/Renovate 配置）| **影响：** **高**（安全）| **类型：** 安全

---

## 方向五：租户管理员的会话管理盲点——无法按租户范围查看会话

**问题：** `SessionManager` SPI（`shared/core/spi.go:130`）定义了：
- `ListByUser(ctx, userID)`——返回用户的所有会话
- `ListAll(ctx)`——返回所有会话

但**没有**：
- `ListByTenant(ctx, tenantID)`——返回租户下的所有用户会话
- `RevokeByTenant(ctx, tenantID)`——使租户的所有会话失效

这意味着：多租户部署中的租户管理员无法回答"我的租户中有多少个活动会话？"或"让我的所有用户退出登录"——除非枚举每个用户。

**具体场景：**
1. `AcmeCorp` 租户的管理员登录管理控制台
2. 他们想查看其租户的活动会话 → 不行（`ListAll` 返回所有租户的会话）
3. 他们想将攻击者从其租户中踢出 → 不行（`RevokeSession` 需要特定的 `sessionID`——他们怎么找到它？）
4. 他们想执行安全策略（"所有用户在密码轮换时必须退出"）→ 不行（没有 `RevokeByUser` 或 `RevokeByTenant` 的批量操作）

**修复：**
1. 向 `SessionManager` 接口添加 `ListByTenant(ctx, tenantID) ([]*Session, error)`
2. 向 `SessionManager` 接口添加 `RevokeByTenant(ctx, tenantID) error`
3. 更新 SQLite 和 Redis 实现以支持按租户的会话索引
4. 在管理 API 中为租户管理员添加 gRPC RPC + HTTP 端点

**工作量：** M（SPI 变更 + 存储实现 + gRPC + HTTP + 授权检查）| **影响：** 中（多租户管理）| **类型：** 功能

---

## 优先级排行

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | SAML Bearer Assertion Grant (RFC 7522) | **高**（解锁企业 SAML→OAuth 用例） | M | 功能 |
| 2 | Dependabot/Renovate 自动化（13 个 go.mod） | **高**（安全—自动 CVE 补丁 PR） | S | 安全 |
| 3 | sso-ctl 会话/令牌/客户端管理命令 | 中（生产运维） | M | 运维 |
| 4 | 按租户范围的会话管理（ListByTenant + RevokeByTenant） | 中（多租户管理） | M | 功能 |
| 5 | JWT 声明投影（id_token cookie 大小优化） | 低-中（性能/带宽） | M | 性能 |

**按 ROI 排列：** 方向 2（Dependabot 约 30 行配置，提供自动安全补丁 PR）→ 方向 1（SAML→OAuth 桥接开启了一个全新的企业用例类别）→ 方向 3（CLI 覆盖将操作员从原始 SQLite 查询中解放出来）→ 方向 4（多租户会话管理是 SaaS 管理员的痛点）→ 方向 5（声明投影减少 cookie 大小，但影响小于其他项）。
