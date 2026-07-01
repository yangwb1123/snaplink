Based on my thorough investigation of the codebase, here is my assessment of each direction with corrections where prior rounds were inaccurate:

---

## 第二十二条分析：验证与校正

### 方向一：`go.mod` replace 阻止 `go install` — ✅ 确认

实际代码确认：
```
go.mod:111  replace github.com/snaplink/sso/redis => ./infrastructure/redis
go.mod:113  replace github.com/snaplink/sso/postgres => ./infrastructure/postgres
```

`cmd/sso-server/` 下 21 个文件导入了这两个模块。远程 `go install` 确实会失败。分析准确。

---

### 方向二：Go Runtime 调优 — ⚠️ 部分已实现（需更正）

**分析声称 "无 Go Runtime 调优"——这不准确。** 代码中已有 `applyRuntimeTuning()`：

```go
// cmd/sso-server/main.go:117-125
func applyRuntimeTuning() {
    if os.Getenv("GOGC") == "" {
        debug.SetGCPercent(200)
    }
}
```

**GOGC=200 已就位。** 缺失的是：
- `GOMAXPROCS` 的 cgroup 感知（容器中的 CPU 限制问题仍存在）
- `debug.SetMemoryLimit()` 的 cgroup 感知（OOM 防护仍存在）

**更正后的工作量：** XS（添加 ~15 行 cgroup 检测代码）| **影响：** 中（仅影响容器部署）

---

### 方向三：`//go:build` 标签 — ✅ 确认

整个非测试代码库仅 1 处：
```
platform/bootstrap/lockfile/file.go:13: //go:build unix
```

分析准确。

---

### 方向四：示例未在 CI 中编译 — ❌ 已实现（需更正）

**分析声称 "CI 不编译这些示例"——这完全不准确。** 两处证据：

1. **Makefile 已有 `examples` target：**
   ```makefile
   examples: ## Compile example apps to ensure they stay buildable.
       $(GO) build ./docs/examples/...
   ```

2. **CI workflow (`ci.yml`) 已有显式步骤：**
   ```yaml
   - name: compile examples
     # docs/examples/ import the SDK; compile them so API drift is
     # caught before a user tries to follow the quickstart.
     run: go build ./docs/examples/...
   ```

**此方向无效——CI 已经编译示例。** 无需任何修改。

---

### 方向五：无云 Secret Manager — ✅ 确认

配置源仅有：
- `config/source_file.go` — YAML 文件
- `config/source_env.go` — 环境变量
- `config/source_flag.go` — CLI 标志
- `config/etcd/source.go` — etcd v3

无 `secret://` URL 方案，无 AWS/GCP/Azure/Vault 集成。分析准确。

---

## 校正后优先级

| # | 方向 | 影响 | 工作量 | 状态 |
|---|------|------|--------|------|
| ~~4~~ | ~~示例 CI 编译~~ | ~~中~~ | ~~S~~ | ❌ **已实现——删除此项** |
| 2' | Runtime 调优（补全 cgroup 感知） | 中 | **XS**（非 S） | 部分已做 |
| 3 | 构建标签 | 低-中 | S | 待做 |
| 1 | `go install` 修复 | 高 | L | 待做 |
| 5 | Secret Manager 源 | 中高 | L | 待做 |

**关键校正：**
1. **方向四应删除** —— CI 已编译示例，这不是问题。
2. **方向二的工作量应从 S 降为 XS** —— GOGC 已就位，只需补 cgroup 感知的 GOMAXPROCS + SetMemoryLimit（约 15 行代码，可能借助 `go.uber.org/automaxprocs` 或直接读 `/sys/fs/cgroup/`）。

需要我实现其中任何一项吗？
