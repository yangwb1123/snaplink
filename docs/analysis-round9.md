# 分析第 9 轮 — Dependabot 覆盖缺口 / 测试顺序执行 / Helm Chart 缺失 / 镜像发布 / SSO-MCP 发布

> 扫描日期：2026-06-29
>
> 前八次路线：① 产品/协议 → ② `time.Now()`/集群 → ③ 刷新令牌并发 → ④ 安全头/KDF → ⑤ 会话管理/密码策略 → ⑥ session 硬上限/SAML → ⑦ 注册防滥用/Fuzz → ⑧ 邮箱验证/Device UX/TTL/审计版本
>
> 本次聚焦：之前八轮从未触及的 CI/CD 安全供应链、测试效率、K8s 部署体验、发布工程、单体/微服务边界

---

## 方向一：Dependabot 仅覆盖 14 个 go.mod 中的 4 个 — 10 个嵌套模块无自动化依赖更新

**代码验证：**

```yaml
# .github/dependabot.yml — 当前配置
updates:
  - package-ecosystem: gomod
    directory: "/"               # ✅ 根 go.mod
  - package-ecosystem: gomod
    directory: "/kms/awskms"     # ✅ awskms go.mod
  - package-ecosystem: gomod
    directory: "/kms/gcpkms"     # ✅ gcpkms go.mod
  - package-ecosystem: docker
    directory: "/ops/deploy/compose"  # ✅ Docker
```

**未被覆盖的 go.mod 文件：**

| 模块 | 风险等级 | 关键外部依赖 |
|------|----------|-------------|
| `infrastructure/saml/go.mod` | 🔴 **高风险** | `crewjam/saml`, `goxmldsig` |
| `infrastructure/redis/go.mod` | 🔴 **高风险** | `go-redis/v9` |
| `infrastructure/ldap/go.mod` | 🟡 中 | `go-ldap/ldap/v3` |
| `infrastructure/kerberos/go.mod` | 🟡 中 | `gokrb5` |
| `infrastructure/radius/go.mod` | 🟢 低 | `layeh.com/radius` |
| `infrastructure/extauthz/go.mod` | 🟡 中 | gRPC 外部授权 |
| `infrastructure/postgres/go.mod` | 🔴 **高风险** | `jackc/pgx` |
| `infrastructure/kms/azurekeyvault/go.mod` | 🟡 中 | Azure SDK |
| `infrastructure/kms/pkcs11/go.mod` | 🟢 低 | `miekg/pkcs11`（CGO） |
| `cmd/sso-mcp/go.mod` | 🟡 中 | `modelcontextprotocol/go-sdk` |

**影响：**
- `infrastructure/saml/go.mod` 依赖 `github.com/crewjam/saml`，该库有已知的 XML 解析攻击面。当 crewjam/saml 发布安全修复时，Dependabot **不会**为此模块创建 PR
- `infrastructure/redis/go.mod` 依赖 `go-redis/v9`。当 go-redis 发布重要修复时，不会被自动化发现
- `cmd/sso-mcp/go.mod` 依赖 MCP SDK，需要跟踪上游协议变更

**建议修复：**
- 在 `.github/dependabot.yml` 中为全部 14 个 go.mod 文件添加 `gomod` section（每行配置增加 ~7 行）
- 如果单个仓库超过 Dependabot 的 open-PR 限制（默认 5），考虑使用 Renovate 或 GitHub Actions 自定义扫描

---

## 方向二：Integration 测试套件完全顺序执行 — 1012 个测试函数无 `t.Parallel()` 调用

**代码验证：**

```bash
$ grep -rn "func Test" test/*_test.go | wc -l
# 1012 个测试函数（150+ 文件，package ssotest）
$ grep -rn "t\.Parallel\|\.Setenv\|TestMain" test/*_test.go | head -5
# test/main_test.go: TestMain（设置 bcrypt MinCost）
# test/bcl_parallel_test.go: TestBCLFanOut_RunsInParallel（唯一使用 t.Parallel 的地方— 在辅助函数中，非主测试）
```

**问题分析：**

1. **全部测试在 `package ssotest` 中** — 同一包内无法并行（Go 按包串行执行测试）
2. **共享服务器状态** — 每个测试使用 `testkit` 创建的 `*httptest.Server`，有共享状态（用户、客户端、token）
3. **`TestMain` 设置全局变量** — `defaultimpl.BcryptCost = bcrypt.MinCost` 是包级全局变量，不能并行
4. **环境变量冲突** — 无 `t.Setenv()`（Go 1.17+ 自动 cleanup），测试间环境变量可能泄漏

**当前 CI 耗时估算：**
- 1012 个测试 × 平均 300ms（含服务器启动 + bcrypt hash + 网络请求）≈ 5 分钟
- 加上 15+ 分钟嵌套模块编译 + race 检测 ≈ 20+ 分钟 total CI
- 如果并行化到 4 个包：耗时可降至 ~6-8 分钟

**建议修复：**
- 将 `test/` 拆分为多个 test package（`test/auth/`、`test/token/`、`test/admin/`、`test/oidc/` 等）
- Go 在不同 package 下可以并行执行测试（`go test -parallel=4 ./test/...`）
- 每个子 package 有自己的 `TestMain`（设置 bcrypt MinCost 可以通过环境变量而非全局变量传递）
- 使用 `t.Setenv()` 替代 `os.Setenv()` 确保环境变量不会泄漏到其他测试

---

## 方向三：Kubernetes 部署缺少 Helm Chart — 生产级配置管理和版本发布需手动 Kustomize 覆盖

**代码验证：**

```bash
$ find ops/deploy -name "Chart.yaml" -o -name "values.yaml"
# 零命中 — 无 Helm Chart

$ ls ops/deploy/k8s/
config.yaml  deployment.yaml  kustomization.yaml  namespace.yaml  README.md  service.yaml
# 只有原始 Kustomize 清单
```

**Kustomize 与 Helm 的能力差距：**

| 维度 | Kustomize（当前） | Helm（缺失） |
|------|------------------|-------------|
| 值模板化 | ❌ 需要每个环境手动 overlay | ✅ `values.yaml` |
| 版本管理 | ❌ 无 chart version | ✅ `Chart.yaml` + 版本语义化 |
| 依赖管理 | ❌ 无 subchart | ✅ Redis、etcd、Postgres 可声明为依赖 |
| 参数文档 | ❌ 散落在 README 中 | ✅ `values.schema.json` |
| 回滚 | ❌ 手动 `kubectl rollout undo` | ✅ `helm rollback` |
| 生命周期 hook | ❌ 无 | ✅ Pre/post-install hooks（DB migration） |
| 生态集成 | 🔧 Kubernetes 原生 | ✅ ArtifactHub、ArgoCD 原生支持 |

**为什么需要：**
- `ops/deploy/k8s/README.md` 明确列出 HPA、NetworkPolicy、PodDisruptionBudget 为"留给 overlay"
- 对于有 5+ 环境（dev/staging/prod/eu/us）的全球部署，Kustomize overlay 的管理成本显著高于 Helm values
- 当前 `config.yaml` 配置散落在 K8s ConfigMap 和 SSO 配置文件中，Helm 可以统一管理

**建议修复：**
- 在 `ops/deploy/helm/sso-server/` 目录创建 Helm chart
- `values.yaml` 暴露：replicaCount, image.tag, resources, stores (sqlite/redis/etcd/postgres), config, ingress
- `templates/` 覆盖现有的 deployment.yaml + service.yaml + namespace.yaml
- 可选 subchart：`redis`（Bitnami）、`etcd`（Bitnami）、`postgresql`
- Chart 版本与 SSO 版本解耦：Chart 1.0.x 支持 SSO v1.x

---

## 方向四：Docker 镜像不自动推送到任何 Registry — 每次部署必须从源码构建

**代码验证：**

```yaml
# .github/workflows/ci.yml — Docker job
jobs:
  docker:
    name: docker build
    steps:
      - name: docker build
        run: docker build . -t snaplink/sso-server:dev
        # ↑ 只构建，不推送
```

```yaml
# .goreleaser.yaml — release pipeline（release.disable=true）
release:
  disable: true
  # ↑ 显式禁用：不创建 GitHub Release，不上传 artifacts
```

**当前状态：**
- CI `docker` job 构建镜像但不推送
- goreleaser release pipeline 完整运行但 `release.disable=true` short-circuit
- Dockerfile 使用 `gcr.io/distroless/static:nonroot`，镜像约 20MB
- `ops/deploy/k8s/deployment.yaml` 使用 `image: snaplink/sso-server:latest`（注释要求生产环境用 sha256 pin）

**缺失的发布通道：**

| 通道 | 状态 |
|------|------|
| GitHub Container Registry（`ghcr.io`） | ❌ 无 |
| Docker Hub | ❌ 无 |
| ECR / GCR / ACR | ❌ 无 |
| GitHub Release（binary artifacts） | ❌ `release.disable=true` |
| SBOM 附件 | 🟡 syft 已安装但未使用 |
| Cosign 签名 | 🟡 cosign 已安装但未使用 |

**影响：**
- 每个生产部署必须自建 CI pipeline 做 `docker build`
- 无法复现"官方构建"（每个组织构建的二进制可能有细微差异）
- 没有 ta 签名 → 无法验证镜像/二进制来源
- 没有 SBOM → 无法审计镜像中打包的依赖

**建议修复（分层推进）：**
1. **第 1 层**：在 `.github/workflows/release.yml` 中设置 `release.disable=false` + 配置 goreleaser 上传到 GitHub Releases
2. **第 2 层**：CI `docker` job 在 tag push 时推送镜像到 `ghcr.io/${{ github.repository }}`（使用 GitHub OIDC token 认证，无需 secrets）
3. **第 3 层**：启用 cosign 签名 + SBOM 附件（syft + cosign 已安装，只需配置）

---

## 方向五：`cmd/sso-mcp` 二进制未纳入发布流程 — 单独编译部署无分发渠道

**代码验证：**

```yaml
# .goreleaser.yaml — builds 列表
builds:
  - id: sso-server
    main: ./cmd/sso-server
    binary: sso-server
    # ↑ 只有这一个 binary
    # ❌ cmd/sso-mcp 不在列表中
```

```yaml
# .github/workflows/ci.yml — modules matrix
modules:
  strategy:
    matrix:
      module:
        - infrastructure/kms/awskms
        - infrastructure/kms/gcpkms
        - infrastructure/redis
        - infrastructure/saml
        - ...
        # ❌ cmd/sso-mcp 不在 matrix 中
```

**还有 Dockerfile：**
```dockerfile
# Dockerfile — 只构建 sso-server
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/sso-server ./cmd/sso-server
# ❌ cmd/sso-mcp 不在 Dockerfile 中
```

**sso-mcp 当前的部署方式：**
- `go run ./cmd/sso-mcp`（开发调试）
- 需要 SSO 服务器的 JWKS URL 和 MCP 资源标识符
- 无 Docker 镜像
- 无 CI 测试（`Makefile` 无相关 target）
- 无二进制发布

**影响：**
- `sso-mcp` 是 MCP 协议的 SSO 资源服务网关，对想用 MCP 工具与 SSO 交互的用户是核心组件
- 当前 `feat/sso-mcp` 分支完成 5 个任务（nested module + config、client wrapper、5 个工具、OAuth RS gate、server assembly + E2E），但没有发布计划
- 如果用户想使用 `sso-mcp`，必须自己编译二进制或构建 Docker 镜像
- 当 `feat/sso-mcp` 合并到 main 后，这些缺口会成为迭代阻塞

**建议修复：**
- `.goreleaser.yaml` 新增 `sso-mcp` build（`id: sso-mcp, main: ./cmd/sso-mcp, binary: sso-mcp`）
- 多阶段 Dockerfile 增加 `sso-mcp` 目标（`docker build --target sso-mcp`）
- `.github/workflows/ci.yml` 的 `modules` matrix 添加 `cmd/sso-mcp`
- `.github/dependabot.yml` 添加 `cmd/sso-mcp/go.mod`

---

## 优先级排序

| 方向 | 价值 | 工作量 | 建议顺序 |
|------|------|--------|----------|
| **① Dependabot 覆盖缺口** | 高（供应链安全） | S（~20 行配置） | **最优先** |
| **② 测试并行化** | 中（CI 效率） | M | 第 2 |
| **③ Helm Chart** | 中（运维标准化） | L | Roadmap |
| **④ Docker 镜像发布** | 中-高（部署流程） | M | **第 1 Sprint** |
| **⑤ sso-mcp 发布** | 中（新功能发布） | S | **与 feat 合并同步** |

**一句话：** ① 10 个嵌套 go.mod 不在 Dependabot 范围内意味着 SAML（DSig/XML）、Redis、Postgres 等关键外部依赖的安全更新会被静默错过 → ② 1012 个测试全部在 `package ssotest` 中顺序执行，CI 耗时过长 → ③ Helm Chart 的缺失使生产部署的配置管理、版本语义化、依赖管理、生命周期 hook 都需要手动 Kustomize overlay → ④ Docker 镜像只在 CI 中构建不推送，每次部署必须从源码构建——无官方二进制意味着不可复现构建和缺乏签名/SBOM → ⑤ `sso-mcp` 是完整的 MCP 协议 + OAuth RS 网关，完成度很高但没纳入 goreleaser、CI matrix、Dockerfile 三件套。
