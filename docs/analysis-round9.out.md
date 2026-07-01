好的，我现在已经有了完整的图景。让我结合代码验证结果提供一份深入分析报告。

---

## 第 9 轮验证报告：分析文档准确性 + 实际缺口

### ⚡ 矩阵速览

| 方向 | 分析文档结论 | 实际验证结果 | 状态 |
|------|-------------|-------------|------|
| ① Dependabot 覆盖 | 仅 4/14 go.mod，10 个缺失 | **全部 13 个 go.mod 已覆盖** | ❌ **错误** |
| ② 测试顺序执行 | 1012 测试，零 `t.Parallel()` | 1057 测试，**8 个 `t.Parallel()`** 存在，单包瓶颈有效 | ⚠️ 部分正确 |
| ③ Helm Chart 缺失 | 无 Chart.yaml/values.yaml | ✅ 确认无误 | ✅ 正确 |
| ④ 镜像发布 | `release.disable=true`，无发布通道 | **已改为 `false`**，ghcr.io 配置就绪 | ⚠️ 过时 |
| ⑤ sso-mcp 发布 | 未纳入 goreleaser/CI/Dockerfile | ✅ 确认无误 | ✅ 正确 |
| **⑥ CI 路径断裂** | **未提及** | **`modules` job 短路径 `kms/awskms` 指向不存在目录** | 🔴 **新增发现** |
| **⑦ postgres 盲区** | **未提及** | **`infrastructure/postgres` 完全不在任何 CI 矩阵中** | 🔴 **新增发现** |

---

### ① Dependabot 覆盖 — ❌ 分析文档完全错误

**文档声称：** 只有根、awskms、gcpkms、Docker 四个 section，SAML/Redis/Postgres 等 10 个嵌套模块缺失。

**实际代码验证：**

```yaml
# .github/dependabot.yml — 实际配置涵盖全部 13 个 go.mod
updates:
  - directory: /                     # ✅ 根
  - directory: /infrastructure/saml  # ✅ SAML (高风险)
  - directory: /infrastructure/ldap  # ✅ LDAP
  - directory: /infrastructure/redis # ✅ Redis (高风险)
  - directory: /infrastructure/postgres # ✅ Postgres (高风险)
  - directory: /infrastructure/kerberos # ✅ Kerberos
  - directory: /infrastructure/radius   # ✅ Radius
  - directory: /infrastructure/extauthz # ✅ ExtAuthz
  - directory: /infrastructure/kms/awskms     # ✅ AWS KMS
  - directory: /infrastructure/kms/gcpkms     # ✅ GCP KMS
  - directory: /infrastructure/kms/azurekeyvault # ✅ Azure KMS
  - directory: /infrastructure/kms/pkcs11     # ✅ PKCS#11
  - directory: /cmd/sso-mcp       # ✅ SSO-MCP
  - package-ecosystem: github-actions  # ✅ Actions
  - package-ecosystem: docker          # ✅ Docker
```

文件注释也明确写着：**"Adding or removing a go.mod? Add/remove its entry here. Every module must be listed."**

**结论：** 分析文档基于过期状态编写。当前配置已经覆盖了所有模块，包含 `groups`、`open-pull-requests-limit`、`labels` 等最佳实践。**此方向当前无需任何操作。**

---

### ② 测试并行化 — ⚠️ 文档细节有误但核心问题成立

**验证结果：**

| 维度 | 文档声称 | 实际 |
|------|---------|------|
| 测试函数数量 | 1012 | **1057**（接近） |
| `t.Parallel()` 调用 | **0，唯一在 `bcl_parallel_test.go` 辅助函数** | **8 个**分布在真实测试函数中 |
| `TestMain` 全局变量 | ✅ 正确 | `defaultimpl.BcryptCost = bcrypt.MinCost` |
| `t.Setenv()` | 说无使用 | ✅ 正确（无环境变量测试） |
| 单包瓶颈 | ✅ 正确 | `package ssotest` 确实在同一个包 |

**现有 8 个 `t.Parallel()` 的位置：**
- `test/caep_integration_test.go:202` — `TestCAEP_FullServer_TenantRevokeDeliversScopedSET`
- `test/federation_registration_test.go:302,327,345` — 3 个注册测试
- `test/federation_test.go:64,172,232,337` — 4 个 federation 测试

这些是**真实测试函数**，不是辅助函数。文档的"唯一在辅助函数"说法错误。

**核心瓶颈仍然存在：** 所有 1057 个测试在同一个 `package ssotest` 中，Go 按包串行执行。`TestMain` 设置包级全局变量进一步阻止拆包。解决方案：
- 拆分为子包 `test/auth/`、`test/token/`、`test/admin/` 等
- 每个子包各自 `TestMain`（通过环境变量传递 bcrypt cost）
- 使用 `t.Setenv()` 替代包级全局变量

---

### ③ Helm Chart — ✅ 确认

**验证结果：** 确实没有 `Chart.yaml` 或 `values.yaml`。

当前设置：
```
ops/deploy/k8s/          # Kustomize base
  ├── kustomization.yaml
  ├── namespace.yaml
  ├── deployment.yaml
  ├── service.yaml
  ├── config.yaml
  └── README.md
ops/deploy/k8s-prod/     # Production overlay
  ├── kustomization.yaml
  ├── hpa.yaml
  ├── pdb.yaml
  ├── patch-deployment.yaml
  └── config.yaml
```

README 明确标注 Ingress、TLS、HPA、NetworkPolicy、PDB、ServiceMonitor、RBAC 都 "intentionally NOT in the base"。

**建议：** 创建 `ops/deploy/helm/sso-server/`。这是有价值的 roadmap 项目，但作为基础设施改进，不需要立即执行。

---

### ④ 镜像发布 — ⚠️ 分析文档基于过时代码

**逐项对比：**

| 文档声称 | 实际 `.goreleaser.yaml`（最新） | 状态 |
|---------|-------------------------------|------|
| `release.disable=true` | **`release.disable: false`** | ❌ 已于提交 696959b（7月1日）改为 false |
| 无 registry | **ghcr.io 配置就绪**（`ghcr.io/snaplink/sso-server:{{ .Version }}`） | ❌ ghcr.io 已配置 |
| CI 只构建不推送 | 仍正确 — CI `docker` job 是 smoke build | ⚠️ 仍正确 |
| Cosign 未使用 | 正确 — `signs:` 块仍被注释 | ✅ 正确 |
| SBOM 未使用 | **已启用** — `sboms:` 配置 `artifacts: archive` SPDX-JSON | ❌ SBOM 已在运行 |
| goreleaser release pipeline 短路径 | release.yml 完整，当前只缺 tag 触发 | ⚠️ 基本正确 |

**当前状态：** 一旦推送 `vX.Y.Z` tag，release workflow 会：
1. 构建 sso-server + sso-ctl 二进制（linux/darwin/windows × amd64/arm64）
2. 生成 SHA256 checksums
3. 生成 SPDX-JSON SBOM
4. 构建 ghcr.io Docker 镜像（multi-arch: linux/amd64 + linux/arm64）
5. 创建 GitHub Release 并上传所有 artifacts

**仍需手动：** Docker smoke 推送（CI 不推）；cosign 签名；CD pipeline

---

### ⑤ sso-mcp 发布 — ✅ 确认

**验证结果全部确认：**

| 缺口 | 验证 |
|------|------|
| 不在 `.goreleaser.yaml` builds 列表 | ✅ `sso-server` 和 `sso-ctl` 是唯二 build ID |
| 不在 CI matrix | ✅ `cmd/sso-mcp` 在所有 4 个矩阵（modules/govulncheck/gosec/lint）中均缺失 |
| Dockerfile 不构建 sso-mcp | ✅ 只下载了 sso-mcp 依赖，没有 `go build -o /out/sso-mcp` 步骤 |
| 无 CI 测试 | ✅ 本地有 `*_test.go` 但 CI 不运行 |
| 无 Docker 镜像 | ✅ 无多阶段构建目标 |

`cmd/sso-mcp` 模块完成度很高：
- 嵌套 go.mod + 配置 ✅
- client wrapper ✅
- 5 个 MCP tools ✅
- OAuth RS gate ✅
- Server assembly + E2E ✅
- 已编译二进制 `sso-mcp` (21MB) ✅
- `.golangci.yml` 配置文件存在 ✅
- Dependabot 已覆盖 ✅

但缺失发布三件套：goreleaser build ID、CI matrix 条目、Dockerfile 多阶段构建目标。

---

### 🔴 ⑥ CI 路径断裂 — 新增发现（分析文档未提及）

**`modules` job 的 matrix 使用短路径，但实际目录在 `infrastructure/` 下：**

```yaml
# .github/workflows/ci.yml — modules job (L103-112)
matrix:
  module:
    - kms/awskms           # ❌ $PWD/kms/awskms/go.mod 不存在
    - redis                # ❌ $PWD/redis/go.mod 不存在
    - saml                 # ❌ $PWD/saml/go.mod 不存在
    - ...
```

实际路径：
```
✅ infrastructure/kms/awskms/go.mod
✅ infrastructure/redis/go.mod
✅ infrastructure/saml/go.mod
```

**所有 10 个模块的 entry 都无法解析。** 同时其他 3 个矩阵（govulncheck、gosec、lint）在 9c28152 提交中**已正确修复**使用 `infrastructure/` 前缀。只有 `modules` job 遗漏了。

这意味着 `go build ./...` + `go test -race -count=1 ./...` 对这 10 个嵌套模块**从未在 CI 中真正运行**。该 job 实际上对所有条目静默失败——因为 `setup-go` 找不到 `go-version-file` 时会报错。

---

### 🔴 ⑦ `infrastructure/postgres` 和 `cmd/sso-mcp` CI 盲区 — 新增发现

**在所有 4 个 CI 矩阵中均缺失：**

| 模块 | modules (build+race) | govulncheck | gosec | lint |
|------|:---:|:---:|:---:|:---:|
| `infrastructure/postgres` | ❌ | ❌ | ❌ | ❌ |
| `cmd/sso-mcp` | ❌ | ❌ | ❌ | ❌ |

这两个模块有独立的 go.mod 和源代码，但 CI 从不编译、不测试、不扫描它们。`infrastructure/postgres` 依赖 `jackc/pgx`（高风险 SQL 驱动），无 CVE 扫描覆盖。

---

### 修正后优先级排序

| # | 方向 | 严重性 | 工作量 | 说明 |
|---|------|--------|--------|------|
| **P0** | **⑥ CI `modules` 路径断裂** | 🔴 **所有模块 CI 失效** | S（~5 行） | 给 `modules` matrix 加 `infrastructure/` 前缀 |
| **P1** | **⑦ `postgres`+`sso-mcp` CI 盲区** | 🔴 **0% CI 覆盖** | S（~10 行） | 四组 matrix 各加两项 |
| **P2** | **⑤ sso-mcp 发布三件套** | 🟡 新功能阻塞 | S/M | goreleaser + CI matrix + Dockerfile |
| **P3** | **② 测试并行化** | 🟡 CI 效率 | M | 拆包 + 子 TestMain |
| **P4** | **③ Helm Chart** | 🟢 运维标准化 | L | Roadmap 项目 |
| — | **① Dependabot** | ✅ **已解决** | 0 | 无需操作 |
| — | **④ 镜像发布** | ✅ **大部分已解决** | S | 仅需 cosign + CI push tag 流程 |

需要我开始修复这些缺口吗？建议顺序是先修 P0（6 行配置修复 modules job 路径），再修 P1（添加 postgres + sso-mcp 到所有 CI matrix），然后 P2（sso-mcp 发布集成）。
