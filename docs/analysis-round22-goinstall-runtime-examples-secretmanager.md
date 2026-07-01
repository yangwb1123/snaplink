# 第二十二轮分析：go install、Runtime 调优、构建标签、示例 CI、Secret Manager

> 基于全局代码库扫描产生的全新视角，此前二十一轮未覆盖。

---

## 方向一：go.mod 中 replace 指令阻止 `go install`——外部用户无法不克隆仓库而安装

**问题：** 根模块 `go.mod` 包含 `replace` 指令：

```
replace github.com/snaplink/sso/redis => ./infrastructure/redis
replace github.com/snaplink/sso/postgres => ./infrastructure/postgres
```

**为什么这是一个问题：** 任何尝试使用标准 Go 工具安装服务器或 CLI 的人都会失败：

```bash
$ go install github.com/snaplink/sso/cmd/sso-server@latest
# 失败：replace 指令指向本地路径，不在 git 上
```

`go install` 需要解析 `github.com/snaplink/sso/redis` → `./infrastructure/redis`，这在远程 go.mod 中无法解析。

**影响：**
- 操作员无法执行 `go install github.com/snaplink/sso/cmd/sso-ctl@latest` 获取 `sso-ctl` CLI
- CI 制品（goreleaser）是获取二进制文件的唯一途径——但发布管道被禁用（第 19 轮）
- 任何在没有克隆整个仓库的情况下想要使用 CLI 工具的人都需要手动编译

**修复：**
1. 将 `redis` 和 `postgres` 包移动到根模块中（它们目前已经位于 `infrastructure/` 下→更改导入路径）
2. 或者将 replace 的模块发布为独立的 Go 模块（`github.com/snaplink/sso-redis`、`github.com/snaplink/sso-postgres`）
3. 或者为用户发布 Docker 镜像作为主要分发机制（方向 19.1）

**工作量：** L（移动导入路径或提取新模块——需要协调更改 20+ 个文件）| **影响：** **高**（可分发性——当前无法从外部安装）| **类型：** 运维/基础设施

---

## 方向二：无 Go Runtime 调优——SSO 服务器使用 GC/调度器的默认设置

**问题：** `cmd/sso-server/main.go` 不在启动前设置任何 Go runtime 参数：

```go
func main() {
    // 没有 runtime.GOMAXPROCS()
    // 没有 debug.SetGCPercent()
    // 没有 debug.SetMemoryLimit()
    // 没有 GOMEMLIMIT 环境变量
    // 没有 GODEBUG 设置
    flags := parseRuntimeFlags()
    // ... 启动服务器 ...
}
```

默认 vs 推荐的 SSO 服务器设置：

| 参数 | 默认值 | 为什么 SSO 需要不同的值 |
|------|--------|------------------------|
| `GOGC` | 100 | 令牌签发创建了许多短期对象——较高的 GOGC（200-400）减少 GC 暂停 |
| `GOMEMLIMIT` | 无限制 | 容器内存不足——应设置为主机内存的 90% |
| `GOMAXPROCS` | 主机 CPU 核心数 | 在容器中，应设置为 cgroup CPU 配额，而非主机核心数 |
| `GODEBUG=http2server=0` | http2 开启 | 如果部署在 Envoy/NGINX 后面，http2 是多余的 |

**为什么这是一个问题：**
- 在 Kubernetes 中，GOMAXPROCS 默认为**主机**核心数，而非容器限制——导致 CPU 节流抖动
- 无 GOMEMLIMIT → Go GC 看到所有主机内存 → 无限堆 → OOM
- 默认 GOGC=100 → GC 在每 100% 新堆上运行 → 高吞吐量令牌签发生过频繁的 GC 周期

**修复：**
1. 添加 `runtime.GOMAXPROCS(limit)` 从 cgroup 检测 CPU 限制
2. 添加 `debug.SetMemoryLimit(limit)` 从 cgroup 检测内存限制
3. 可选：添加 `debug.SetGCPercent(200)` 以减少 GC 频率
4. 记录 Kubernetes 部署中 `GOMEMLIMIT` 和 `GOMAXPROCS` 的推荐值

**工作量：** S（~5 行启动代码 + 文档）| **影响：** 中（大部分在高吞吐量场景下的延迟稳定性）| **类型：** 性能/运维

---

## 方向三：全网代码只有 1 个 `//go:build` 标签——无功能标志构建系统

**问题：** 整个非测试代码库中只有一个 `//go:build` 构建标签：

```go
// platform/bootstrap/lockfile/file.go:13
//go:build unix
```

**缺少的构建标签场景：**
- `no_pkcs11`：在无 CGO 构建中排除 PKCS#11 KMS
- `no_kms_aws` `no_kms_gcp`：排除不需要的 KMS 提供者以减少二进制大小
- `experimental_*`：在默认构建中隐藏实验性功能

**为什么这是一个问题：** 当前，所有功能始终编译到二进制文件中。这通过条件导入（PKCS#11 在 `CGO_ENABLED=0` 构建中失败）或运行时拒绝（功能启用了但未配置）来管理。

**现有解决方法（从 CI 中）：** 注释说明 `pkcs11` 不能在 `CGO_ENABLED=0` 下编译，因此 CI 使用 `CGO_ENABLED=0 go build ./cmd/sso-server`，希望 PKCS#11 模块永远不会被无意中选中。

**修复：**
1. 添加 `no_pkcs11` 构建标签以显式排除 PKCS#11（当前依赖隐式 CGO 排除）
2. 为大型 KMS SDK 添加 `no_kms_awskms`、`no_kms_gcpkms`、`no_kms_azurekeyvault` 以减小二进制大小
3. 添加 `make build-small` 目标，使用最小功能集

**工作量：** S（每个标签 ~3 行 + 文档）| **影响：** 低-中（二进制大小优化 + CGO_ENABLED=0 清晰性）| **类型：** 构建/基础设施

---

## 方向四：示例应用未在 CI 中编译——SDK API 改动的无声漂移

**问题：** `docs/examples/` 包含 6 个导入 SSO SDK 的示例 Go 程序：

```
docs/examples/basic/main.go        ← 11316 字节，导入 15+ 个 SDK 包
docs/examples/embedded-app/main.go ← 嵌入 SSO 服务器
docs/examples/grpc-client/main.go  ← gRPC 管理客户端
docs/examples/playground/main.go   ← API 探索
docs/examples/quickstart/main.go   ← 快速入门
docs/examples/remote-app/main.go   ← 远程应用
```

**为什么这是一个问题：** CI 不编译这些示例：

```yaml
# ci.yml —— 没有 "compile examples" 步骤
# `go build ./...` 涵盖 cmd/sso-server 和 cmd/sso-ctl，但不涵盖 docs/examples/
```

如果 `interfaces/sso.Option` 签名更改或包被重命名，示例会无声地损坏——直到某个用户尝试遵循 `quickstart/main.go` 并得到：

```
$ go run docs/examples/quickstart/main.go
# github.com/snaplink/sso/docs/examples/quickstart
./main.go:42:12: undefined: sso.WithBodyLimit
```

**修复：**
1. 将 `go build ./docs/examples/...` 添加到 CI 的 `test` 或 `build` 作业中
2. 或者添加 `make examples` 目标
3. 添加 CI 步骤，运行 `docs/examples/quickstart/main.go` 并验证它返回退出码 0

**工作量：** S（CI 中的 ~3 行）| **影响：** 中（示例可靠性——主要文档面）| **类型：** 质量/文档

---

## 方向五：无云 Secret Manager 配置源——生产凭据硬编码在 YAML/Env 中

**问题：** 配置从以下位置加载：1️⃣ `YAML 文件` → 2️⃣ `SSO_* 环境变量`。**没有与云 Secret Manager 集成：**

- ❌ 无 AWS Secrets Manager / Parameter Store 源
- ❌ 无 GCP Secret Manager 源
- ❌ 无 Azure Key Vault 源
- ❌ 无 HashiCorp Vault 源

也有 `etcd` 配置源（`config/etcd/source.go`），但 etcd 是操作员必须自行管理的额外基础设施。

**为什么这是一个问题：** 当前，敏感配置值必须放入 YAML 文件或环境变量中：

```yaml
# config.yaml —— 包含明文密钥
redis:
  password: "super-secret"       # ❌ 在 YAML 中
postgres:
  dsn: "postgres://user:pass@..." # ❌ 在 YAML 中
clients:
  - id: "svc"                    # ❌ 客户端密钥在 YAML 中
    secret: "client-secret-value"
```

**操作的期望：**
```yaml
postgres:
  dsn: "secret://aws/postgres/prod/dsn"  # ✅ 运行时解析
redis:
  password: "secret://aws/redis/prod/password"
```

**修复：**
1. 添加 `config/sources/source_aws.go`——集成 AWS Secrets Manager + Parameter Store
2. 添加 `config/sources/source_gcp.go`——集成 GCP Secret Manager
3. 添加 `secret://` URL 方案解析器，在配置加载期间替换值
4. 可配置回退策略（如果 Secret Manager 不可用则失败 vs 回退到 env）

**工作量：** L（每个云提供者 ~100 行 + URL 解析器 + 文档）| **影响：** **中高**（安全性——YAML 中的明文密钥不符合 SOC2/GDPR）| **类型：** 安全/运维

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | go.mod replace 阻止 `go install`（外部无法安装） | **高**（可分发性） | L | 运维/基础设施 |
| 2 | 无云 Secret Manager 源（凭据在 YAML/Env 中） | **中高**（安全性——SOC2 合规） | L | 安全/运维 |
| 3 | 示例应用未在 CI 中编译（无声漂移） | 中（文档可靠性） | S | 质量/文档 |
| 4 | 无 Go Runtime 调优（GC/内存/CPU 默认值） | 中（高吞吐量下的延迟稳定性） | S | 性能/运维 |
| 5 | 全网仅 1 个 `//go:build` 标签（无功能标志） | 低-中（二进制大小优化） | S | 构建/基础设施 |

**按 ROI 排列：** 方向 3（示例编译——CI 中的 3 行确保 6 个示例始终保持最新）→ 方向 4（Runtime 调优——5 行启动代码优化高吞吐量 GC 行为）→ 方向 5（构建标签——为 PKCS#11 和 KMS SDK 添加显式排除）→ 方向 1（`go install`——高影响但需要重大的 go.mod 重构）→ 方向 2（Secret Manager——高安全价值但需要每个云提供者的集成工作）。
