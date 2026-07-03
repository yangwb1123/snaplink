---

## 验证结论：方案 A ✅ 已交付

我对所有声明进行了逐行核验，以下是完整验证报告。

### ✅ 通过：代码变更核验

| 检查项 | 状态 | 证据 |
|--------|------|------|
| `RefreshGrantDeps` 接口含 `SessionManager()` | ✅ | `token_refresh.go:23` |
| `refreshCheckSessionLiveness()` 函数 | ✅ | `token_refresh.go:301-320` |
| `HandleRefreshGrant` 调用 liveness check | ✅ | `token_refresh.go:90` — 在 Consume/ClientID/DPoP 之后，scope 解析之前 ✅ |
| `refreshCheckSessionLiveness` 返回 true → 400 invalid_grant + 日志 | ✅ | `token_refresh.go:316-319` |
| compile-time guard `var _ tokengrant.RefreshGrantDeps = (*Server)(nil)` | ✅ | `accessors_handlers.go:273` |
| `*Server.SessionManager()` 返回 `core.SessionManager` | ✅ | `server_signup.go:71` + `aliases.go:107` type alias |
| fallback: `sessionMgr == nil` 跳过检查 | ✅ | `token_refresh.go:305-307` |
| fallback: `info.SID == ""` 跳过检查 | ✅ | `token_refresh.go:302-303` |
| fail-closed: `sm.Get()` error → 拒绝 | ✅ | `token_refresh.go:311-312` |
| fail-closed: session nil/expired/revoked → 拒绝 | ✅ | `token_refresh.go:313-316` |
| `DefaultSessionDuration` = 24h, `DefaultRefreshTokenTTL` = 30d | ✅ | `shared/core/consts_oauth.go:113,116` |
| `Session` 结构含 `ID/ExpiresAt/Revoked` 字段 | ✅ | `shared/core/types_auth.go:10-15` |
| `IsExpired()` 方法 | ✅ | `shared/core/types_auth.go:38-40` |
| `SessionManager` 接口含 `Get(ctx, sessionID)` | ✅ | `shared/core/spi.go:135` |
| 编译通过 | ✅ | `go build ./internal/handler/tokengrant/ ./interfaces/sso/` |
| 相关测试通过 | ✅ | `TestSID_StableAcrossRefreshRotation`, `TestRefreshToken_ExpiredTokenRejected`, `TestRefreshToken_ScopeNarrowingAccepted`, `TestRefreshToken_ExchangeMismatchedClient` 等 26 个测试均 PASS |

### ⚠️ 发现的一处瑕疵（已修复）

**文档中的 4.2.1 节代码片段**的注释中引用了旧的函数名 `checkSessionLiveness`，而实际函数名为 `refreshCheckSessionLiveness`。已于 `token_refresh.go:89` 修复：

```
- // the checkSessionLiveness contract.
+ // the refreshCheckSessionLiveness contract.
```

### 📋 其他观察

| 观察 | 说明 |
|------|------|
| `go build ./...` 预存在 `admin/v1/clients_grpc.pb.go` proto 生成问题 | 与本次变更无关 |
| `go vet ./...` 因 `example_test.go` 中 `static/login` 模式问题报错 | 与本次变更无关 |
| 缺少"session 过期 → refresh 被拒"的端到端测试 | 新增行为仅有 `refreshCheckSessionLiveness` 单元逻辑，但无集成测试覆盖 session 过期后 refresh 被拒的完整路径。建议新增 `TestRefreshToken_SessionExpiredTokenRejected`（约 30 行） |

### 🧠 心智模型验证

```
时间线             事件
0h    用户登录 → 创建 Session(ID=S1) + 签发 Refresh Token(RT1, SID=S1)
24h   Session 过期 (ExpiresAt = T0+24h)
25h   提交 RT1 → HandleRefreshGrant
       → Consume(RT1) ✅
       → ClientID 绑定 ✅
       → DPoP 绑定 ✅
       → refreshCheckSessionLiveness():
           → sm.Get("S1") → Session{ExpiredAt=24h, IsExpired()=true}
           → 返回 true → HandleRefreshGrant 日志并返回 400 invalid_grant
       → refresh 被拒，用户需重新登录
```

**方案 A 已正确交付。** 文档内容与代码完全一致（除已修复的注释笔误）。
