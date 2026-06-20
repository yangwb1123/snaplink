# Skill: Project Reorganization

**Trigger:** Root directory file count > 15 non-exempt files, or `python cli.py check-root` fails.

**Usage:** `python skills/project-reorganization/run.py [--analyze-only] [--dry-run]`

## Principles

1. **Root minimum** — only README, build config, agent docs, entry dirs (`cmd/`)
2. **Feature-first grouping** — by business domain, not by technical layer
3. **File size hard gates** — file ≤ 500, function ≤ 50, cyclo ≤ 15
4. **Entry file minimization** — one entry per binary (`cmd/<name>/main.go`)
5. **Anti-patterns** — no `utils/`, `helpers/`, god files, banned filenames (`util.go`, `helper.go`, `fix.go`, `temp.go`)

## Phase 1: Analyze

```bash
python skills/project-reorganization/run.py --analyze-only
python cli.py check-root
```

输出：
- 当前违规文件列表
- 每个文件的行数和职责
- 建议的目标目录结构

**等待确认后再执行 Phase 2。** 若发现以下风险，暂停并提出方案：
- 循环依赖（A 导入 B，B 导入 A）
- 公共模块过度耦合（> 5 个包依赖同一个 internal 包）
- 跨领域引用（oauth/ 引用 tenant/ 内部类型）

## Phase 2: Migrate

按批次迁移，每批 ≤ 5 个文件：

```
1. 创建目标目录（如 internal/auth/login/）
2. 移动文件（git mv）
3. 更新 package 声明
4. 更新所有 import 引用
5. 运行 post-edit 验证
6. 确认通过后继续下一批
```

**迁移策略（按优先级）：**

| 优先级 | 文件类型 | 目标位置 |
|---|---|---|
| 1 | `*_handler.go`（handler 逻辑） | `oauth/`, `oidc/`, `selfservice/` |
| 2 | `*_types.go`（类型定义） | `internal/auth/<module>/types.go` |
| 3 | `*_helpers.go`（纯函数） | domain 包的 `helpers.go` |
| 4 | `*_service.go`（业务逻辑） | 对应 domain 包 |
| 5 | 其他业务代码 | `internal/<module>/` |

**禁止操作：**
- 不移动 `sso.go`（Server struct + routes）
- 不移动 `handler.go`（登录编排器）
- 不移动 `handlers.go`（Discovery 委托）
- 不移动 `accessors.go`（Deps 接口访问器）
- 不移动 `aliases.go`（类型重导出）
- 不移动 `options*.go`（配置选项）
- 不移动 `server_*.go`（薄包装方法）

## Phase 3: Verify

每批迁移后执行：

```bash
go build ./...
go vet ./...
go test ./... -race
python cli.py check-root
go test -run TestMaintainability ./...
go test -run TestArchitecture ./...
```

全部通过后才能继续下一批。

## Phase 4: Report

每批完成后输出：

```
## Reorganization Summary

### 移动文件
- server_login_types.go → internal/auth/login/types.go
- server_logout.go (consent challenge) → internal/auth/consent/challenge.go

### 新增目录
- internal/auth/login/
- internal/auth/consent/

### 架构影响
- 解决问题：根目录业务代码减少 N 个文件
- 仍存在问题：server_extensions.go (489行) 接近阈值
- 后续优化：提取 DPoP/mTLS 逻辑到 security/

### 验证结果
- build: ✅
- vet: ✅
- test: ✅
- check-root: ✅
- file budget: ✅
- import boundaries: ✅
```

## Risk Detection

遇到以下情况必须暂停，不得盲目继续：

| 风险 | 信号 | 应对 |
|---|---|---|
| 循环依赖 | `go build` 报 import cycle | 提取共享接口到 `core/` |
| 过度耦合 | 一个包被 > 10 个包导入 | 拆分为更小的包 |
| 测试断裂 | > 3 个测试文件需要更新 import | 考虑保留兼容别名 |
| 性能退化 | 基准测试 > 2x 变慢 | 调查原因，可能是包初始化开销 |
