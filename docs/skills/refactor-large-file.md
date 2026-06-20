# Skill: Refactor Large File

目标：将超过 500 行的文件拆分到合规大小。

## 触发条件

- 文件行数 > 500 行（未豁免）
- 编辑后预计文件超过 500 行

## 分析步骤

### 1. 识别文件职责

用 Grep/Read 列出文件中的所有顶层声明：

```bash
grep -n "^func \|^type \|^const \|^var " path/to/file.go
```

按以下类别标注每个声明的职责：
- **类型定义**（struct/interface/alias）
- **常量/变量**
- **处理器方法**（`(s *Server) handleXxx`）
- **辅助函数**（纯逻辑、无状态）
- **配置方法**（Option 函数、构造函数）

### 2. 识别拆分边界

优先按职责拆分：

```
单文件 > 500 行
  ├─ 类型定义多 → 提取 types.go
  ├─ 常量/变量多 → 提取 consts.go
  ├─ 多个 handler → 按领域分组到子文件
  ├─ 辅助函数多 → 提取 helpers.go 或到 domain 包
  └─ 混合职责 → 按 concern 拆分
```

### 3. 执行拆分

**模式 A：同包拆分（简单）**

将代码移到同包的新文件，导入不变：

```
server_login.go (600行)
  → server_login.go (300行)  — handler 方法
  → server_login_types.go (150行) — 类型定义
  → server_login_helpers.go (150行) — 辅助函数
```

**模式 B：跨包提取（hexagonal）**

将业务逻辑提取到 domain 包，保留薄包装：

```
server_login.go (600行)
  → server_login.go (200行)  — 薄包装 (s *Server) 方法
  → internal/auth/login/types.go (150行) — 类型
  → internal/auth/login/validate.go (250行) — 纯验证函数
```

### 4. 更新引用

```bash
# 查找旧符号的所有引用
grep -rn "oldFunctionName\|OldTypeName" --include="*.go"

# 若跨包提取：更新所有导入和调用点
```

### 5. 验证

```bash
go build ./...
go vet ./...
go test ./... -race
python cli.py check-root  # 若涉及根目录文件
```

### 6. 更新豁免列表（仅在必要时）

若拆分不可行（如 `sso.go` 核心 Server struct），添加到豁免：

```go
// maintainability_budget_test.go
var exemptFiles = map[string]bool{
    "new_large_file.go": true,
}
```

**注意：豁免是最后手段。优先拆分。**

## 本项目目标位置

| 内容类型 | 目标包 |
|---|---|
| OAuth handler 逻辑 | `oauth/` |
| OIDC handler 逻辑 | `oidc/` |
| 安全逻辑 | `security/` |
| 自服务（注册/邮箱/密码/导出） | `selfservice/` |
| 登录相关类型/工具 | `internal/auth/login/` |
| 同意相关工具 | `internal/auth/consent/` |
| 通用 handler 工具 | `internal/handler/` |
| 集群协调 | `cluster/` |
| 租户逻辑 | `tenant/` |
