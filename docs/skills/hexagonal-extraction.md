# Skill: Hexagonal Extraction

目标：将根目录 handler 方法提取到 domain 包，保留薄包装。

## 触发条件

- 根目录存在业务逻辑文件（`*_handler.go`、`*_service.go` 等）
- `python cli.py check-root` 报告违规
- Server 方法包含可独立测试的纯逻辑

## 模式

```
修改前（根目录）：
  server_foo.go
    func (s *Server) handleFoo(ctx HandlerContext) {
        // 50 行参数绑定 + 业务逻辑
    }

修改后：
  server_foo.go（薄包装，~10 行）
    func (s *Server) handleFoo(ctx HandlerContext) {
        foo.HandleFoo(s, ctx)
    }

  foo/handler.go（业务逻辑）
    func HandleFoo(d Deps, ctx core.HandlerContext) {
        // 50 行参数绑定 + 业务逻辑
    }

  foo/deps.go（依赖接口）
    type Deps interface {
        // Server 通过 accessors.go 满足此接口
    }
```

## 步骤

### 1. 识别提取目标

```bash
# 列出根目录非豁免文件
ls *.go | grep -v "_test.go"
python cli.py check-root
```

优先提取：
- 纯业务逻辑（不依赖 Server 内部状态）
- 可独立测试的函数
- 已有 domain 包可归入的逻辑

### 2. 设计 Deps 接口

查看 handler 方法使用了哪些 Server 字段：

```go
func (s *Server) handleFoo(ctx HandlerContext) {
    s.logger.Error(...)          // → Logger() spi.Logger
    s.auditor.Record(...)        // → Auditor() *audit.Recorder
    s.userProvider.Get(...)      // → UserProvider() core.UserProvider
    s.meSubjectOrChallenge(...)  // → MeSubjectOrChallenge(ctx) (string, bool)
}
```

创建 `foo/deps.go`：

```go
package foo

import (
    "github.com/snaplink/sso/audit"
    "github.com/snaplink/sso/core"
    "github.com/snaplink/sso/spi"
)

type Deps interface {
    Logger() spi.Logger
    Auditor() *audit.Recorder
    UserProvider() core.UserProvider
    MeSubjectOrChallenge(ctx core.HandlerContext) (string, bool)
    ErrorBody(errCode string) map[string]any
    TokenNoStoreHeaders(ctx core.HandlerContext)
}
```

### 3. 提取 Handler 函数

将 `(s *Server)` 方法体复制到 domain 包，替换 `s.xxx` 为 `d.xxx`：

```go
// foo/handler.go
func HandleFoo(d Deps, ctx core.HandlerContext) {
    d.TokenNoStoreHeaders(ctx)
    userID, ok := d.MeSubjectOrChallenge(ctx)
    if !ok {
        return
    }
    // ... 业务逻辑 ...
    if aud := d.Auditor(); aud != nil {
        // ... audit ...
    }
}
```

### 4. 添加 Server 访问器

若 Deps 接口需要新访问器，添加到 `accessors.go`：

```go
// accessors.go
func (s *Server) FooStore() foo.Store { return s.fooStore }
```

### 5. 更新根目录包装

```go
// server_foo.go
package sso

import "github.com/snaplink/sso/foo"

func (s *Server) handleFoo(ctx HandlerContext) {
    foo.HandleFoo(s, ctx)
}
```

### 6. 验证

```bash
go build ./...
go vet ./...
go test ./... -race
python cli.py check-root
```

## 已有示例

参考以下已完成的提取：

| 文件 | 提取到 | 模式 |
|---|---|---|
| `server_signup.go` | `selfservice/signup.go` | `HandleSelfRegister(d Deps, ctx)` |
| `server_email_change.go` | `selfservice/email_change.go` | `HandleMyEmailChange(d Deps, ctx)` |
| `server_password_reset.go` | `selfservice/password_reset.go` | `HandleForgotPassword(d Deps, ctx)` |
| `server_data_export.go` | `selfservice/data_export.go` | `HandleMyDataExport(d Deps, ctx)` |
| `server_logout.go` | `internal/auth/consent/challenge.go` | `ChallengeStore` 类型提取 |
| `server_login_types.go` | `internal/auth/login/types.go` | `Request` 类型提取 |

## 注意事项

- `Deps` 接口尽量小：只声明 handler 实际使用的方法
- 避免循环导入：domain 包不得导入 `sso` 包
- 根目录包装方法保持 `(s *Server)` 签名，路由注册不变
- 若 handler 强依赖 Server 内部状态（无法通过访问器暴露），保留在根目录
