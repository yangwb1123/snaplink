Here is my complete assessment and implementation summary.

---

## 评估报告 & 实施总结

### 🔍 代码核验发现

在逐行核验所有引用的源文件后，我修正了分析文档中的若干不准确之处：

| 方向 | 分析结论 | 实际代码状态 |
|------|---------|------------|
| **① 单调时钟** | "约30+处裸`time.Now()`风险" | ⚠️ **风险高估** — 所有 `IsExpired()` 已使用 `time.Since(t) > 0`（Go 单调安全模式），JWT 验证器有明确注释说明跨进程时间戳必须用墙钟，Rate limiter 的 `pruneLocked` 使用 `time.Since()` 也是安全的 |
| **② etcd 自愈** | "撤销持久化缺失" | ❌ **证伪** — `infrastructure/defaultimpl/sqlite/revocations.go` 已实现完整 SQLite 持久化，通过 `keys.signing.revocation_backend: sqlite` 配置接线，启动时 `SeedRevocations` 回填 |
| **③ Postgres 后端** | "Hot stores 无 Postgres" | ✅ **缺口真实** — 已验证 clients/users/tenants/permissions 等 durable 层完备，但 AuthCode/RefreshToken/PAR/DeviceCode/CIBA/JTIReplay/Session 确实缺失 |
| **④ 撤销持久化** | "重启后 `revoked` map 为空" | ❌ **完全证伪** — `BuildRevocationStore` + `SeedRevocations` 全链路已投产 |
| **⑤ Discovery** | "只声明 prompt=none" | ✅ **缺口真实** — 已修复 |

---

### ✅ 已完成实施

#### 1. 方向⑤：Discovery `prompt=consent` 声明
**文件：** `interfaces/sso/server_discovery_config.go`
- 当 `consentStore != nil` 时，向 `PromptValuesSupported` 追加 `consent`
- `prompt=login` 和 `prompt=select_account` 不声明（RP 驱动交互流，服务器按需认证）
- 已通过 `go build ./...` 验证 ✅

#### 2. 方向③：Postgres Session Store（热路径 PoC）
**新文件：** `infrastructure/postgres/session.go`

Postgres 后端 SessionManager 实现，覆盖 `sso.SessionManager` 接口全部方法：
- `Create` / `CreateWithMeta` — 带设备上下文和 tenant 绑定
- `Get` — 过期/已撤销 session 返回 `ErrSessionNotFound`
- `Destroy` — 物理删除
- `Refresh` — `UPDATE ... RETURNING` 原子扩展，拒绝过期/已撤销
- `ListByUser` / `ListAll`
- `ListByTenant` / `DeleteByTenant` — tenant 级索引

**更新文件：**
- `cmd/sso-server/serverbuildstore/build_identity_stores.go` — `BuildSessionManager` 新增 `postgres` case，移除原来的拒绝逻辑
- `cmd/sso-server/build_app_core.go` — 传入 `b.pgDB` / `b.pgDialect`
- `cmd/sso-server/*_test.go` — 更新 5 处测试调用签名

**测试文件：** `infrastructure/postgres/session_test.go` — 7 个测试覆盖 CRUD、Meta、Refresh、ListByUser、DeleteByTenant、ListByTenant、过期检测

#### 3. 方向① & ② & ④：已核验无需代码变更
所有 claims 经逐行核验确认代码已正确实现。

---

### 📊 最终验证

| 检查 | 状态 |
|------|------|
| `go build ./...` (根模块) | ✅ 通过 |
| `go vet ./...` | ✅ 通过（仅预存在 `example_test.go` 问题） |
| `go build ./...` (postgres 子模块) | ✅ 通过 |
| `go vet ./...` (postgres 子模块) | ✅ 通过 |
| 维护性测试 (`TestMaintainability_`) | ✅ 无新违规 |
| 架构测试 (`TestArchitecture_`) | ✅ 无新违规 |
