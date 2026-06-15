# Skill: Add New Handler

## 归属判断
| 类型 | 目标包 | 文件名 |
|---|---|---|
| OAuth 2.0 grant | `oauth/` | `handle_<grant>.go` |
| OIDC 端点 | `oidc/` | `handle_<endpoint>.go` |
| 自助服务 | `sso` | `handle_<feature>.go` |
| 管理 API | `grpcserver/` | `<service>.go` |

## 步骤
1. 确定归属 → 2. 检查目标文件大小 → 3. 创建新文件
4. 在 `sso.go` 的 `Mount()` 注册路由
5. 编写测试（单元 + 集成）
6. 更新 `docs/openapi.yaml`（如需新端点）
7. 更新 `docs/error-codes.md`（如需新 `Err*`）
8. 验证: `make harness` + `go test ./...`
