# 示例需求：实现用户 API

## 功能描述
实现一个完整的用户管理 REST API，支持创建、查询、更新和删除用户。

## 需求

### 创建用户
- **端点**: `POST /api/v1/users`
- **请求体**:
  ```json
  {
    "username": "string (3-50字符, 字母数字下划线)",
    "email": "string (有效邮箱格式)",
    "password": "string (至少8位, 包含数字和字母)",
    "display_name": "string (可选, 最多100字符)"
  }
  ```
- **成功响应**: `201 Created`
  ```json
  {
    "id": "string",
    "username": "string",
    "email": "string",
    "display_name": "string",
    "created_at": "timestamp"
  }
  ```

### 查询用户
- **端点**: `GET /api/v1/users/{id}`
- **成功响应**: `200 OK` + 用户对象

### 更新用户
- **端点**: `PUT /api/v1/users/{id}`
- **请求体**: 可更新字段（email, display_name）
- **成功响应**: `200 OK` + 更新后的用户对象

### 删除用户
- **端点**: `DELETE /api/v1/users/{id}`
- **成功响应**: `204 No Content`

### 列表用户
- **端点**: `GET /api/v1/users?page=1&limit=10`
- **成功响应**: `200 OK` + 分页用户列表

## 技术要求

### 验证规则
- **用户名**: 3-50字符，只允许字母、数字、下划线，系统唯一
- **邮箱**: 有效邮箱格式，系统唯一
- **密码**: 至少8位，必须包含数字和字母
- **显示名称**: 可选，最多100字符

### 错误处理
- `400 Bad Request`: 参数验证失败
- `401 Unauthorized`: 未认证
- `403 Forbidden`: 无权限
- `404 Not Found`: 用户不存在
- `409 Conflict`: 用户名或邮箱已存在
- `500 Internal Server Error`: 服务器错误

### 安全要求
- 密码必须加密存储（使用 bcrypt）
- 响应中不包含密码字段
- 需要认证才能访问（Bearer Token）
- 需要 admin 权限才能创建/删除用户

### 集成要求
- 使用现有的 `UserProvider` 接口
- 使用现有的 `PasswordCredentialStore` 存储密码
- 集成到现有的认证中间件
- 添加 Prometheus 指标监控
- 添加审计日志记录

### 性能要求
- 列表查询支持分页
- 响应时间 < 100ms (p95)
- 支持并发请求

## 验收标准

- [ ] 所有 API 端点实现完成
- [ ] 输入验证完整（用户名、邮箱、密码格式）
- [ ] 错误处理完整（所有错误码）
- [ ] 单元测试覆盖率 > 80%
- [ ] 集成测试通过
- [ ] 安全审查通过（无漏洞）
- [ ] 文档更新（API 文档、README）
- [ ] Prometheus 指标添加
- [ ] 审计日志记录

## 示例

### 创建用户
```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecurePass123",
    "display_name": "John Doe"
  }'
```

**响应**:
```json
{
  "id": "user-123",
  "username": "john_doe",
  "email": "john@example.com",
  "display_name": "John Doe",
  "created_at": "2026-07-01T14:00:00Z"
}
```

### 查询用户
```bash
curl http://localhost:8080/api/v1/users/user-123 \
  -H "Authorization: Bearer <token>"
```

## 参考资料

- 现有 UserProvider 接口: `shared/core/spi.go`
- 现有认证中间件: `interfaces/middleware/`
- API 规范: `docs/openapi.yaml`
- 测试示例: `test/admin_user_mgmt_test.go`
