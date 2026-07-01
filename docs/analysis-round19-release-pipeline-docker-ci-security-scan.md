# 第十九轮分析：发布管道、安全扫描覆盖率、Docker CI、Admin HTTP 测试

> 基于全局代码库扫描产生的全新视角，此前十八轮未覆盖。

---

## 方向一：Release Pipeline 被禁用——CI 触发 Tag 后不发布任何产物

**问题：** `.goreleaser.yaml:9` 明确注释 `release.disable=true`，且 CI 的 `release.yml` 末尾**没有任何上传/发布操作**：

```yaml
# .goreleaser.yaml
# Today release.disable=true keeps that target empty until a git
# remote + GitHub Releases (or a private registry) is wired.
```

CI 的 `release.yml` 会：
1. 安装 syft（SBOM 生成）和 cosign（签名）
2. 运行 `goreleaser release --clean`
3. **结束**——不推送到 ghcr.io、Docker Hub、GitHub Releases、或任何目标

**缺少的产物：**
- ❌ 无 Docker 镜像推送（无 `ghcr.io/snaplink/sso-server:latest`）
- ❌ 无发布二进制文件（无 GitHub Release 下载页）
- ❌ 无 SBOM 发布（syft 生成了但未存储）
- ❌ 无容器签名（cosign 安装但未运行）
- ❌ 无 RPM/Deb/Homebrew 包

**为什么这是一个问题：** 项目有一个完整 GoReleaser 配置 + CI 工作流 + 构建矩阵，但**实际上没有发布渠道**。操作员无法执行 `docker pull snaplink/sso-server:latest`。唯一的构建方式是从源码 `make docker` 本地构建。

**修复：**
1. 选择注册表（ghcr.io 首选——OCI + GitHub 原生）
2. 添加 `docker push` 到 goreleaser 配置（`dockers:` 块）
3. 启用 `release.disable=false` 以发布到 GitHub Releases
4. 添加自动 Docker 多架构 manifest（`--platform linux/amd64,linux/arm64`）

**工作量：** M（配置 goreleaser + CI 密钥 + 首次发布测试）| **影响：** **高**（部署能力——操作员只能从源码构建）| **类型：** 运维/基础设施

---

## 方向二：Nested Modules 未受安全扫描——12 个 go.mod 中的 CVE 悄然潜伏

**问题：** CI 中的 `govulncheck` 和 `gosec` 安全扫描器仅对 `./...` 运行，这只覆盖**根模块**。12 个以上嵌套模块未扫描：

```
infrastructure/saml/         ← go.mod
infrastructure/ldap/         ← go.mod (LDAP 协议库常有 CVE)
infrastructure/redis/        ← go.mod
infrastructure/kms/awskms/   ← go.mod
infrastructure/kms/gcpkms/   ← go.mod
infrastructure/kms/azurekeyvault/ ← go.mod
infrastructure/kms/pkcs11/   ← go.mod
infrastructure/radius/       ← go.mod
infrastructure/extauthz/     ← go.mod
infrastructure/postgres/     ← go.mod
infrastructure/kerberos/     ← go.mod
cmd/sso-mcp/                 ← go.mod
```

**为什么这是一个问题：** 依赖树漏洞**不在**根模块的 `go.sum` 中，因此扫描器不会发现它们。具体威胁：
- `saml/` 可能导入具有已知 CVE 的 XML 解析器
- `ldap/` 和 `kerberos/` 导入 LDAP/Kerberos 协议的库——这些通常携带高危 CVE
- `pkcs11/` 与硬件安全模块桥接——这些模块中的 CVE 直接暴露加密密钥

**当前状态（`ci.yml:193` 的注释）：**
> "Scans the ROOT module — the credential-handling core; the nested modules are separate go.mod roots that `./...` does not descend into."

注意，`govulncheck` 作业会运行 `govulncheck ./... && pushd $module && govulncheck ./... && popd` 以覆盖嵌套模块，但 `gosec` 仅限根模块。

**修复：**
1. 向 CI 矩阵添加 `find . -name go.mod -execdir` 循环以在每个嵌套模块上运行 `govulncheck` + `gosec`
2. 添加聚合 SARIF 上传（每个模块的 SARIF 合并成一个上传）
3. 在 `gosec` 作业中添加 `-exclude-dir=vendor` 以避免重复

**工作量：** S（CI 矩阵中的 ~20 行循环 + `exclude-dir` 标志）| **影响：** **中高**（安全可观测性——CVE 发现）| **类型：** 安全

---

## 方向三：Docker 镜像未自动发布——无 CI/CD 注册表推送

**问题：** 即使发布管道已启用，`make docker` 仅在本地构建：`docker build -t snaplink/sso-server:dev .`。没有 CI 作业将镜像推送到注册表。

**缺少的 CI 作业：**
- 无 `docker buildx build --platform ./... --push`
- 无多架构构建（amd64 + arm64）
- 无自动标记（`main-abc123` 表示 dev，`v1.2.3` 表示 release）
- 无 SBOM 在镜像标签上签名和附加
- 无 `docker compose` 或 `helm chart` 集成测试

**为什么这是一个问题：** Ops 和 SRE 团队期望发布的工件。`docker pull` 是 SSO 的预期部署模式（根据 Dockerfile 中的 `EXPOSE 8080` 和 `EXPOSE 8081`），但**尚未实现**。

**修复：**
1. 向 `release.yml` 添加 Docker 推送步骤（或向 `ci.yml` 添加 `docker-push` 作业）
2. 使用 `docker buildx build --platform linux/amd64,linux/arm64` 用于多架构
3. 添加 CI 生成的标签：`git tag` → Docker tag，`main branch` → Docker `:main` + `:sha-xxxx`
4. 在推送之前运行 `trivy image` 扫描以验证镜像安全性

**工作量：** M（CI 作业 ~50 行 + 注册表凭据 + 多架构构建器）| **影响：** **高**（运维——第一次有人可以通过 `docker pull` 部署）| **类型：** 运维/CI

---

## 方向四：Admin 端点测试不覆盖 gRPC-gateway HTTP 路径——仅测试原生 gRPC

**问题：** Admin API 端点（客户端 CRUD、用户 CRUD、会话管理、令牌吊销）主要针对原生 gRPC 进行测试（通过 `bufconn` 或直接调用服务实现）。gRPC-gateway 生成的 HTTP REST 层**未在集成测试中作为 HTTP API 进行测试**。

**缺少的测试：**
- `GET /api/v1/admin/clients` 作为 HTTP `curl` —— 绕过 gRPC
- `POST /api/v1/admin/clients` 作为 JSON 负载 —— 测试 JSON → protobuf 映射
- `ListClients` 的分页限制 —— 测试 gRPC-gateway HTTP 分页
- HTTP 401/403 在 Admin 中间件层 —— 测试 gRPC-gateway 前的中间件链
- CORS 标头 —— 测试 gRPC-gateway 是否通过正确的 CORS 标头

**为什么这是一个问题：** gRPC-gateway 将 HTTP JSON 转换为 protobuf。这个转换可能失败：
- 枚举值映射错误（`TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC` 作为字符串与整数）
- 字段名大小写（`client_id` 与 `clientId`）
- HTTP 标头到 gRPC 元数据的传播
- 错误的 HTTP 状态码（gRPC 错误码不会 1:1 映射到 HTTP 状态码）

如果 gRPC-gateway 端点是主要的 admin API 表面（可能如此——大多数操作员使用 `curl` 或 REST 客户端），那么它应该作为 HTTP API 进行测试。

**修复：**
1. 通过 `httptest.NewServer` 编写针对 HTTP gRPC-gateway 路由的测试
2. 使用 `test.HTTPServer(t, server)` 辅助函数创建一个引导 HTTP 服务器，暴露 gRPC-gateway mux
3. 为每个 admin 端点添加一个 HTTP 集成测试（JSON 输入 → 预期 JSON 输出）
4. 验证 HTTP 状态码与 gRPC 状态码是否一致

**工作量：** M（gRPC-gateway HTTP 测试辅助函数 + 为每个 admin 端点添加 ~5 个 HTTP 集成测试）| **影响：** 中（API 可靠性——确保 REST 入口按预期工作）| **类型：** 测试/质量

---

## 方向五：Makefile 缺少核心开发目标——proto-gen、security-scan-all、docker-push 缺失

**问题：** Makefile 有 155 行和 40 个 `.PHONY` 目标，但缺少开发流程的关键目标：

**已存在：** `test`、`race`、`bench`、`vet`、`fmt`、`build`、`docker`、`lint`、`proto-lint`、`proto-breaking`、`docs-validate`

**缺失：**
- ❌ `proto-gen`——开发者必须手动运行 `buf generate` 或 `protoc`
- ❌ `security-scan-all`——当前 `security-scan` 仅扫描根模块
- ❌ `docker-push`——无推送方式
- ❌ `docker-multiarch`——无多架构构建方式
- ❌ `docker-scan`——推送前扫描镜像
- ❌ `mod-tidy-all`——在所有 13 个模块上运行 `go mod tidy`
- ❌ `test-e2e`——与集成测试区分单位测试
- ❌ `clean-all`——清理所有构建产物 + 依赖缓存

**为什么这是一个问题：** 新的贡献者（或六个月的自己）不知道如何：
- 修改 `.proto` 文件后重新生成 Go 代码（`proto-gen` 缺失）
- 在所有模块上运行安全扫描（`security-scan-all` 缺失）
- 发布 Docker 镜像（`docker-push` 缺失）
- 打包发布二进制文件（`release` 缺失——参考而非目标）

**修复：**
1. 为缺失的目标添加 Makefile 配方
2. 添加 `help-group` 注释以按区域对目标进行分组（dev、proto、ci、release）

**工作量：** S（在 Makefile 中添加 ~20 行目标）| **影响：** 中（贡献者入门速度）| **类型：** 开发体验

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | 发布管道被禁用（没有实际发布到任何平台） | **高**（运维——操作员只能从源码构建） | M | 运维/基础设施 |
| 2 | Docker 镜像未自动发布（无注册表推送） | **高**（部署能力） | M | 运维/CI |
| 3 | 嵌套模块未受安全扫描（12 个 go.mod 中的 CVE） | **中高**（安全可观测性） | S | 安全 |
| 4 | Admin 端点测试不覆盖 gRPC-gateway HTTP 路径 | 中（API 可靠性） | M | 测试/质量 |
| 5 | Makefile 缺少核心开发目标 (proto-gen、docker-push) | 中（贡献者入门速度） | S | 开发体验 |

**按 ROI 排列：** 方向 1（发布管道——单个配置选项 `release.disable=false` + Docker 推送配置 = 项目第一次有可消费的产物）→ 方向 3（嵌套模块 CVE 扫描——20 行 CI 循环暴露 12 个隐藏模块的安全漏洞）→ 方向 2（Docker 镜像 CI 推送——enable releases 的自然延伸）→ 方向 4（gRPC-gateway HTTP 测试——确保 REST admin API 按预期工作，而不仅仅是 gRPC）→ 方向 5（Makefile 目标——增量改进，优先级较低但成本低）。
