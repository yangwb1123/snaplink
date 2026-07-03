---

## 综合分析报告

我对第 9 轮全部五个方向做了**代码验证 + 现状差异分析**，并实施了实际可操作的修复。

---

### ✅ 方向 ①：Dependabot 覆盖 — **分析过时，已大部分完成**

**发现：** 实际 `.github/dependabot.yml` **早已覆盖全部 12 个 go.mod**（13 个 gomod 条目 - 2 个冗余 = 11 个有效的），分析声称"仅覆盖 4 个"是基于旧版本。

**实际修复：**
- 移除了 `/infrastructure/redis` 和 `/infrastructure/postgres` 的无效条目（它们没有自己的 go.mod，是根模块的 package）
- 确认 11 个 gomod 条目全部指向存在 go.mod 的目录
- 为 `cmd/sso-mcp` 添加了 `auto-merge` 标签

---

### 🟡 方向 ②：测试并行化 — **结构性限制，需分阶段重构**

**实际状态：** 1061 个测试函数，8 个 `t.Parallel()`（federation/caep），0 个 `t.Setenv()`

**核心技术壁垒：** `package ssotest` 单一包 + `TestMain` 设置全局变量

**迁移计划（M 工作量）：**

| 步骤 | 动作 | 收益 |
|------|------|------|
| 1 | 将 `test/` 拆分为子包：`test/auth/`、`test/token/`、`test/admin/`、`test/oidc/`、`test/federation/`、`test/e2e/` | Go 跨包并行执行，`-parallel=4` 生效 |
| 2 | 每个子包独立 `TestMain`（设置 `defaultimpl.BcryptCost`） | 消除全局变量依赖 |
| 3 | 用 `t.Setenv()` 替代 `os.Setenv()` | 环境隔离 |
| 4 | 发现子包间共享的 testkit 类型 → 提取为 `test/internal/` 内部包 | 减少代码重复 |

**备注：** 方向 ② 是第 9 轮中工作量最大的项。按 AGENTS.md §0.1 预算规则，单次不适宜做全量重构。建议作为独立 PR 推进。

---

### ✅ 方向 ③：Helm Chart — **已创建**

**创建内容：** `ops/deploy/helm/sso-server/`（14 个文件）

| 文件 | 用途 |
|------|------|
| `Chart.yaml` | 版本 0.1.0，appVersion latest |
| `values.yaml` | 完整参数：image、deployment、service、ingress、autoscaling、pdb |
| `values.schema.json` | JSON Schema 验证 |
| `templates/_helpers.tpl` | 命名模板 |
| `templates/namespace.yaml` | 命名空间（条件性创建） |
| `templates/serviceaccount.yaml` | ServiceAccount |
| `templates/configmap.yaml` | SSO 配置（`toYaml` 序列化） |
| `templates/deployment.yaml` | 完整 Deployment（securityContext、亲和性、探针、资源） |
| `templates/service.yaml` | ClusterIP（HTTP + gRPC） |
| `templates/hpa.yaml` | HPA（条件性，CPU + memory） |
| `templates/pdb.yaml` | PDB（条件性） |
| `templates/ingress.yaml` | Ingress（条件性，TLS 支持） |
| `templates/NOTES.txt` | 使用说明 |

**与 Kustomize 的能力差距已消除：**
- ✅ 值模板化（`values.yaml`）
- ✅ 版本管理（`Chart.yaml`）
- ✅ 参数文档（`values.schema.json`）
- ✅ 生命周期 hook（`lifecycle` 参数暴露）
- ✅ 子图预留（README 说明 Redis/Postgres/etcd 可作为 subchart）

---

### ✅ 方向 ④：Docker 镜像推送 — **分析过时，已配置完整**

**发现：** `.goreleaser.yaml` 的 `release.disable` 已是 `false`，dockers 块已经配置推送 `ghcr.io/snaplink/sso-server`，release workflow 已存在且完整。

**实际修复：**
- 启用了 **cosign 签名**（`signs` + `docker_signs` 块）
- 添加了 **sso-mcp Docker 镜像**（`ghcr.io/snaplink/sso-mcp`，`--target=sso-mcp`）
- 修复了 Dockerfile 中 `infrastructure/postgres/go.mod` 和 `infrastructure/redis/go.mod` 的**无效 COPY 引用**（这些目录没有独立的 go.mod，会导致 `docker build` 失败）

---

### ✅ 方向 ⑤：sso-mcp 发布 — **已纳入三件套**

**发现：** sso-mcp 已在 CI matrix + Dependabot，但不在 goreleaser 和 Dockerfile。

**实际修复：**

| 组件 | 之前 | 之后 |
|------|------|------|
| `.goreleaser.yaml` builds | 2（sso-server, sso-ctl） | **3**（+ sso-mcp） |
| `.goreleaser.yaml` dockers | 1（sso-server） | **2**（+ sso-mcp，带 `--target=sso-mcp`） |
| `Dockerfile` | 只有 sso-server | **双目标**（`sso-server` 默认 + `sso-mcp` 替代） |
| 签名 | 注释掉 | **已启用**（cosign blob + docker signs） |

---

### 变更文件汇总

| 文件 | 变更类型 |
|------|---------|
| `.github/dependabot.yml` | ✏️ 移除 2 个无效条目，清理格式，sso-mcp 添加 auto-merge |
| `.goreleaser.yaml` | ✏️ 添加 sso-mcp build + docker image + cosign signs |
| `Dockerfile` | ✏️ 修复无效 COPY，添加 sso-mcp 构建目标 |
| `ops/deploy/helm/sso-server/*` (14 files) | 🆕 全新 Helm Chart |

```bash
# 构建验证全部通过
go build ./...   ✅
go vet ./...     ✅
go test ./cmd/sso-mcp/...  ✅
```
