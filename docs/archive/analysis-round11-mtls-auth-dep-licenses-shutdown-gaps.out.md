基于详尽的代码库验证，以下是我对每一方向的**现场核查结果**：

---

## 方向一：mTLS `tls_client_auth` DCR → ✅ **已完全实现**

分析称其为缺失，但实际代码已经覆盖了全路径：

| 层次 | 状态 | 位置 |
|------|------|------|
| DCR 验证 | ✅ 已接受 | `dcr_validate.go:72` — `"tls_client_auth", "self_signed_tls"` 已列入 switch |
| 发现文档 | ✅ 已声明 | `server_discovery_config.go:180-194` — 两者均在 `token_endpoint_auth_methods_supported` 中 |
| Token 处理程序 | ✅ 已验证 | `server_token.go:240-390` — 完整的 `authenticateMTLSClient`，支持 SubjectDN/SAN/JWK 指纹匹配 |
| 客户端注册字段 | ✅ 已存在 | `TLSClientAuthSubjectDN`、`TLSClientAuthSANDNS`、`TLSClientAuthSanEmail`、`TLSClientAuthSanURI`，以及自签名证书的 `TLSClientAuthJWK` |

**结论：** 方向一为**过时分析**——mTLS 客户端认证在受监管行业中已具备部署条件。

---

## 方向二：WebAuthn 凭据管理 → ⚠️ **基本准确**

确认：
- `webauthn_memory_store.go` 有 `RemoveCredential` ❌ **但没有** 列出用户凭据的方法（`ListByUser` 仅存在于 `SessionManager` 上，而非 `CredentialStore`）
- 没有用户面向的 REST 端点用于列出/重命名/删除通行密钥
- `UserStore` 接口只暴露了 `GetByName`/`GetByHandle`，缺少按用户列出凭据的方法

**差异：** `RemoveCredential` 确实存在（按 credentialID 删除），所以**删除功能**的存储层已经有了。缺口在于：
1. 缺少 `UserStore.ListCredentials(userID)` 或等效方法
2. 没有挂载 HTTP 端点
3. 没有重命名/别名端点

---

## 方向三：许可证合规性 → ⚠️ **部分已覆盖，CI 存在缺口**

已存在的内容：
- **`Makefile`** — 有 `licenses`、`licenses-check`、`licenses-notice` 目标（第 278-307 行），包含：
  - `go-licenses csv ./...` → 依赖许可证报告
  - `go-licenses check ./...` → 拒绝 GPL/AGPL/SSPL
  - `awk` 脚本为 Apache-2.0 依赖生成 `NOTICE.txt`
- **`.goreleaser.yaml`** — 有 `sboms:` 配置（syft，SPDX-JSON 格式），按归档附带
- **`release.yml`** — 下载 syft 供 goreleaser 使用

仍然缺失的内容：
| 项目 | 状态 | 详情 |
|------|------|------|
| CI 中的 `licenses-check` | ❌ | `ci.yml` 没有将其作为门禁步骤 |
| 提交的 `NOTICE.txt` | ❌ | 仅按需生成，但根据 Apache 2.0 §4(b) 要求，发行版应附带 |
| `ci.yml` 中的 SBOM | ❌ | 仅存在于 goreleaser（发布时），不在 CI 中 |
| `LICENSE.dependencies` | ❌ | 未生成 |

---

## 方向四：可观测性缺口 → ⚠️ **大幅过度声明**

实际指标覆盖范围远超分析所声称的。计入的指标：

| 分析称缺失 | 实际状态 |
|-----------|----------|
| **refresh_token 旋转** | ✅ **已测量** — `sso_refresh_rotation_velocity_exceeded_total` |
| **授权码消耗** | ❌ 确实缺失 — 无 `/auth` → `/token` 转化指标 |
| **OIDC 静默续期** | ❌ 确实缺失 — 无静默 vs 交互式比率 |
| **Token 内省/吊销** | ✅ **已部分测量** — `sso_token_revocations_propagated_total` |
| **PAR 使用率** | ❌ 确实缺失 — 无 PAR vs 非 PAR 计数 |
| **数据库延迟** | ❌ 确实缺失 — 无按存储的 p50/p99 |
| **上游 IdP 健康状态** | ✅ **已测量** — `sso_signing_backend_up`（KMS/HSM），以及异常检测指标 |
| **集群总线消息** | ✅ **已测量** — `sso_invalidation_bus_up`、重新连接计数、`sso_signing_key_cutover_total` |
| **会话活动计数** | ❌ 确实缺失 — 无按租户的活跃会话计数 |
| **速率限制器触发** | ❌ 确实缺失 |
| **缓存命中率** | ✅ **已测量** — `sso_client_store_cache_total` |
| **WebAuthn** | ✅ **已测量** — `sso_webauthn_registrations_total` 和 `sso_webauthn_assertions_total` |
| **CAEP/SSF** | ✅ **已测量** — `sso_caep_sets_total`、`sso_ssf_sets_received_total` |
| **CIBA 留存** | ✅ **已测量** — `sso_ciba_ping_total`、`sso_retention_pruned_total` |
| **异常检测** | ✅ **已测量** — 5 个独立的 anomaly 指标 |

**实际未测量的路径：** 授权码消耗、OIDC 静默续期、PAR 使用率、数据库延迟、速率限制器命中次数、活跃会话计数、JWKS 缓存命中率。

---

## 方向五：优雅关闭 → ⚠️ **大部分已实现**

分析中的三个具体主张：

| 主张 | 实际状态 |
|------|----------|
| `anomalyRunner.Close()` 从未被调用 | ❌ **错误** — 在 `main_shutdown.go:74-75` 的 `shutdownSubsystems` 中**有调用** |
| RSA/ECDSA 轮换定时器缺失关闭信号 | ❌ **错误** — `rsa_rotation_scheduler.go:38-49` 使用 `select { case <-ctx.Done(): return; case <-ticker.C: ... }`。取消由 `build_app_cluster.go:295` 的 `keyRotationCancel` 处理，并通过 `shutdownWatchLoops` 等待完成 |
| 审计留存定时器缺失关闭钩子 | ❌ **错误** — `shutdownSchedulers` 处理 5 个带有 `cancel`/`done` 通道的调度器：审计留存、快照留存、推送审批、CIBA 请求、刷新宽限期 |

**实际仍存在的缺口：**
1. **`scheduleRetire` goroutine**（`rsa_rotation_scheduler.go:73-82`）——未追踪/等待。它会在 `ctx.Done()` 上取消，但如果退出时间恰好落在 `timer.C` 和 `ctx.Done()` 之间，它可能会在关闭期间运行 `RetireKey`。
2. **MDS 刷新循环**（当添加时）——尚不存在，但可预先准备。
3. **`closeAppStores` 在服务器关闭之前运行**——`main.go:290` 的 `defer closeAppStores(a)` 在 `shutdownServers` 之前运行（存在风险：`defer` 在函数返回时触发，即 `sigCh` 之后，但服务器是在 `defer` 运行之前关闭的。实际上顺序是没问题的，因为 `run()` 在返回前会顺序执行 `shutdownServers` → `shutdownSubsystems`，然后 `defer` 才会触发）。

---

## 更正后的实际优先级

| 优先级 | 方向 | 实际影响 | 工作量 | 备注 |
|--------|-------|----------|--------|------|
| 1 | 许可证合规性 → CI 门禁 | 中高（企业采购） | **S**（+5 行 CI YAML） | 最简变更：在 `ci.yml` 中添加 `make licenses-check` |
| 2 | 可观测性：6 个真正缺失的路径 | 中（运维盲区） | S-M | 授权码消耗、PAR 使用率、数据库延迟、速率限制、会话数、JWKS 缓存 |
| 3 | WebAuthn 凭据管理 | 中（UX） | M | 优先考虑 `ListCredentials` + HTTP 路由 |
| 4 | 关闭：`scheduleRetire` goroutine 泄露 | 低（竞争窗口极小） | **S**（+1 个等待通道） | 预生产准备 |
| — | mTLS DCR / 发现 / 认证 | ✅ **已完成** | 0 | 无需操作 |

您希望我基于这份更正后的评估，开始实施实际剩余的缺口吗？
