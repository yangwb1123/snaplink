# HARNESS.md — 自动检查与拒绝策略

每道 GATE 失败 = 立即停止当前任务。修复优先级高于功能开发。

---

## GATES

| # | 检查 | 命令 | 失败处理 |
|---|---|---|---|
| 1 | 文件 ≤ 500 行 | `.check-filesize.sh` | 拆分文件 |
| 2 | 圈复杂度 ≤ 15 | `.check-complexity.sh` | 提取函数 |
| 3 | 函数 ≤ 60 行 | `golangci-lint funlen` | 提取函数 |
| 4 | 依赖方向合规 | `.check-architecture.sh` | 重构依赖 |
| 5 | 测试通过 | `go test -count=1 ./...` | 修复测试 |
| 6 | 零 vet/lint 警告 | `go vet + golangci-lint` | 修复警告 |

## 工作流

```
修改 → [pre-commit: filesize + vet]
         → [pre-push: make harness + build + test]
         → [CI: full suite]
```

## 豁免注册表

### 文件大小（SPLIT_NOW）
- `handlers.go` (3901) — 当前 sprint 拆分
- `server_extensions.go` (3055) — 当前 sprint 拆分
- `sso.go` (2993) — 当前 sprint 拆分
- `handler.go` (2549) — 当前 sprint 拆分

### 文件大小（SPLIT_NEXT）
- `config/config.go` (3014)、`cmd/sso-server/main.go` (5489)
- `core/types.go` (777)、`core/consts.go` (725)、`signing_key_aggregation.go` (776)

### 复杂度豁免
- `handleLogin` in `handler.go` — 主编排器，待拆分
