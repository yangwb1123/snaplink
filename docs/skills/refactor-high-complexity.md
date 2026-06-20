# Skill: Refactor High Complexity

目标：降低函数圈复杂度（≤ 15）和认知复杂度（≤ 20）。

## 触发条件

- 函数圈复杂度 > 15
- if 嵌套深度 > 3 层
- switch/if-chain 分支 > 10 个

## 策略

### 1. Guard Clauses（提前返回）

```go
// 修改前（嵌套深）
func process(req Request) error {
    if req.Valid() {
        if req.Authorized() {
            if req.HasData() {
                // 核心逻辑
            } else {
                return ErrNoData
            }
        } else {
            return ErrUnauthorized
        }
    } else {
        return ErrInvalid
    }
}

// 修改后（Guard Clauses）
func process(req Request) error {
    if !req.Valid() {
        return ErrInvalid
    }
    if !req.Authorized() {
        return ErrUnauthorized
    }
    if !req.HasData() {
        return ErrNoData
    }
    // 核心逻辑
}
```

### 2. 提取子函数

```go
// 修改前（单函数 60 行）
func handleRequest(ctx context.Context, req Request) error {
    // 10 行验证
    // 20 行业务逻辑
    // 15 行持久化
    // 15 行通知
}

// 修改后（提取子函数）
func handleRequest(ctx context.Context, req Request) error {
    if err := validate(req); err != nil {
        return err
    }
    result, err := processBusinessLogic(ctx, req)
    if err != nil {
        return err
    }
    if err := persist(ctx, result); err != nil {
        return err
    }
    return notify(ctx, result)
}
```

### 3. 策略模式（替换大 switch）

```go
// 修改前（switch 12 个 case）
func dispatch(kind string, data []byte) error {
    switch kind {
    case "A": return handleA(data)
    case "B": return handleB(data)
    // ... 10 个 case ...
    }
}

// 修改后（策略表）
var handlers = map[string]func([]byte) error{
    "A": handleA,
    "B": handleB,
    // ...
}

func dispatch(kind string, data []byte) error {
    h, ok := handlers[kind]
    if !ok {
        return ErrUnknownKind
    }
    return h(data)
}
```

### 4. 合并条件

```go
// 修改前
if a && b {
    if c || d {
        // ...
    }
}

// 修改后
if (a && b) && (c || d) {
    // ...
}
```

## 验证

```bash
# 检查函数行数（应 ≤ 50）
grep -c "^" path/to/file.go

# 构建 + 测试
go build ./...
go test ./... -race
```
