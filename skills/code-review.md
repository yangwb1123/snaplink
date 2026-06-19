# Skill: Code Review

目标：在提交前检查代码质量和架构合规性。

## 检查清单

### 架构合规

- [ ] 无循环导入（`oauth/` 不导入 `oidc/`，反之亦然）
- [ ] 无 `cmd/` 被其他包导入
- [ ] 根目录无新增业务代码（`python cli.py check-root`）
- [ ] 新文件位于正确的 domain 包

### 代码质量

- [ ] 无 God Object（单文件承担 > 2 个职责）
- [ ] 无 God Function（> 50 行）
- [ ] 无深层嵌套（> 3 层 if）
- [ ] 无大 switch（> 10 个 case）
- [ ] 无 `TODO: refactor later`（必须立即重构）

### 安全约束

- [ ] 无 Oracle-leak（所有错误路径返回相同响应）
- [ ] 无枚举漏洞（未知用户/令牌不泄露存在性）
- [ ] 审计元数据使用 `SetMeta()`，不直接赋值 `e.Metadata`
- [ ] 凭证端点设置 `Cache-Control: no-store`
- [ ] 401 响应包含 `WWW-Authenticate` 头

### 测试

- [ ] 新增代码有对应单元测试
- [ ] 测试使用 `Memory*` 实现，不使用 mock
- [ ] Race 测试通过（`go test -race`）
- [ ] 集成测试（若涉及 HTTP 端点）在 `test/` 包

### 文档

- [ ] 新增 `Err*` 错误码已更新 `docs/error-codes.md`
- [ ] 新增/修改的 HTTP 端点已更新 `docs/openapi.yaml`
- [ ] 注释解释 WHY（非 WHAT）

## 常见问题模式

### 1. 违反依赖方向

```
❌ oauth/ 导入 oidc/
❌ oidc/ 导入 oauth/
❌ 任何包导入 cmd/

✅ 通过 handlers.go 路由
✅ 通过 core/ 定义共享接口
```

### 2. 审计元数据覆盖

```go
// ❌ 错误：覆盖 enrichment
evt.Metadata = map[string]string{"key": "value"}

// ✅ 正确：追加
audit.SetMeta(evt, "key", "value")
```

### 3. Oracle-leak

```go
// ❌ 错误：不同错误返回不同响应
if err == ErrNotFound {
    return 404, "not found"
} else if err == ErrExpired {
    return 400, "expired"
}

// ✅ 正确：统一响应
if err != nil {
    return 400, "invalid_grant"  // 所有失败路径相同
}
```

## 输出格式

Review 完成后输出：

```
## Code Review Summary

### 通过
- 架构合规
- 代码质量
- 测试覆盖

### 问题
- [严重] oauth/handler.go:45 违反依赖方向（导入 oidc/）
- [警告] server_login.go:120 函数超过 50 行（当前 65 行）

### 建议
- 考虑将 validateRequest() 提取到独立函数
- 建议为新增的 HandleFoo 添加边界测试
```
