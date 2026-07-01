# 第二十轮分析：配置验证、烟雾测试、负载基线、IaC、Kustomize 差异层

> 基于全局代码库扫描产生的全新视角，此前十九轮未覆盖。

---

## 方向一：7 份 config.yaml 文件无法交叉验证——环境配置漂移无检测

**问题：** 项目在 7 个不同的地方维护着 `config.yaml`：

| 路径 | 用途 |
|------|------|
| `cmd/sso-server/config.yaml` | 本地开发默认配置 |
| `bin/config.yaml` | 构建产物参考配置 |
| `ops/deploy/compose/config.yaml` | Docker Compose 开发环境 |
| `ops/deploy/baremetal-ha/sso/config.yaml` | 裸金属 HA 部署 |
| `ops/deploy/k8s/config.yaml` | K8s 测试部署 |
| `ops/deploy/k8s-prod/config.yaml` | K8s 生产部署 |
| `docs/examples/basic/config.yaml` | 文档中用于快速开始 |

**问题：**
- **没有交叉验证工具**——无法回答"这 7 个配置是否都与当前服务器模式兼容？"
- **没有 `config validate` 子命令**——`sso-ctl`（或 `sso-server --validate-only`）不能在不启动服务器的情况下验证配置
- **没有要求所有配置文件通过服务器模式检查的 CI 作业**
- **配置漂移**——如果 `k8s-prod/config.yaml` 中缺少必填字段，直到部署后才会发现

**为什么这是一个问题：** 配置错误是生产中停机的主要原因。如果 `k8s-prod/config.yaml` 指定了一个过时的 `backend:`（服务器不再识别），部署可以成功但行为不正确。

**修复：**
1. 添加 `sso-server --validate-only <config>` 标志——加载、验证并退出，无副作用
2. 添加 CI 作业，遍历所有 7 个配置并在服务器上运行 `--validate-only`
3. 添加 `make config-validate-all` Makefile 目标
4. 添加验证钩子到 CI 的 `config validate` 步骤

**工作量：** S（~30 行标志 + CI 中的循环）| **影响：** **高**（防止配置漂移——当前在不同环境中未被注意到）| **类型：** 运维

---

## 方向二：烟雾测试过于基础——不验证令牌发放、OIDC 或 Admin API

**问题：** `ops/deploy/baremetal-ha/smoke.sh` 是一个部署后烟雾测试：

```sh
# 1. 检查发现端点是否提供 JSON
curl -ks "$BASE/.well-known/openid-configuration" | grep -q '"issuer"'
# 2. 检查 /readyz 是否返回 200
curl -ks -o /dev/null -w '%{http_code}' "$BASE/readyz"
# 3. 多次点击 readyz 以检查复制
```

**它不做**：
- ❌ `POST /token` 并进行 `client_credentials` 授权（验证签名密钥已加载 + 端到端令牌发放）
- ❌ `POST /token` 并进行 `authorization_code`（验证 auth_code 存储 + 重定向传递）
- ❌ `GET /userinfo`（验证 OIDC 用户信息端点已连接）
- ❌ Admin API（`GET /api/v1/admin/clients`——验证 gRPC-gateway 健康）
- ❌ `POST /token/revoke`（验证令牌吊销不返回 500）
- ❌ 检查自省端点返回 `{"active": false}` 用于已吊销的令牌

**为什么这是一个问题：** 如果启动后存在以下问题，烟雾测试会通过：
- 签名密钥加载失败（令牌发放静默失败）
- gRPC-gateway 未连接（admin API 返回 404）
- 存储后端连接但为空（auth_code 不持久化）
- 中间件返回 500（未测试）

**修复：** 扩展 `smoke.sh` 以包含：
1. `client_credentials` → 检查 `access_token` 是否包含 `iss` 和 `sub`
2. `GET /userinfo` 使用 access_token → 检查 JSON 响应体
3. Admin API 健康检查（尝试 `/api/v1/admin/clients` 并预期 401 或 200）
4. 令牌吊销循环（颁发 → 自省 → 吊销 → 自省 → 验证不活跃）

**工作量：** S（~40 行 shell 脚本）| **影响：** 中（部署信心——当前烟雾测试仅测试 HAProxy 的存在）| **类型：** 运维/质量

---

## 方向三：负载测试没有 CI 集成或性能基线——回归未被发现

**问题：** `ops/deploy/loadtest/token.js` 是一个正确的 k6 脚本，用于对 `/token` 进行 `client_credentials` 负载测试。但**它不在 CI 中运行，没有基线作为基准，没有回归检测机制**。

**缺失的：**
- ❌ 没有 `make load-test-ci` 目标来运行 k6 并记录结果
- ❌ 没有 `ops/deploy/loadtest/baseline.json` 基线指标（p50、p95、p99 延迟）
- ❌ 没有 `make bench` 与 `load-test` 之间的 CI 作业关联
- ❌ 没有自动的性能回归警报（如果 p95 > 基线 + 20%，标记）
- ❌ 没有服务器端资源概况的 `pprof` 捕获自动化

**为什么这是一个问题：** 性能回归在合并前没有被发现：
- 新的签名缓存层可能提高 p95 → 没有性能故事可以讲述
- SQLite 中的新 `RETURNING` 查询可能降低吞吐量 → 未检测到
- 新的 grant 处理程序中的 `time.Sleep(10ms)` 可能将 QPS 减半 → 直到崩溃才注意到

**修复：**
1. 添加 `make load-test-record` → 运行 k6 测试并将结果保存到 `ops/deploy/loadtest/baseline.json`
2. 添加 `make load-test-compare` → 运行 k6 并将结果与 `baseline.json` 进行比较
3. 添加 `make load-test-ci` → 在 CI 中运行负载测试（作为基准或是比较，取决于分支）
4. 添加 CI 作业，在 PR 的目标与基准分支之间比较 p95 延迟

**工作量：** M（k6 结果解析 + 比较脚本 + CI 作业配置）| **影响：** 中（性能可观测性——回归在合并前被捕获）| **类型：** 性能/测试

---

## 方向四：K8s 部署使用裸 Kustomize——环境间无差异层，手动同步

**问题：** `ops/deploy/k8s/` 和 `ops/deploy/k8s-prod/` 是独立的 Kustomize 目录，必须**手动保持同步**。当 `deployment.yaml` 中添加了新容器端口时，两个目录中的文件都必须更新。没有单一的真相来源。

**当前结构：**
```
ops/deploy/k8s/
  ├── config.yaml      ← 独立
  ├── deployment.yaml   ← 独立
  ├── service.yaml      ← 独立
  ├── kustomization.yaml
  └── namespace.yaml
ops/deploy/k8s-prod/
  ├── config.yaml       ← 独立（与 k8s/ 重复）
  ├── hpa.yaml          ← prod 专用的 HPA
  ├── patch-deployment.yaml
  ├── pdb.yaml
  ├── kustomization.yaml
  └── README.md
```

**为什么这是一个问题：** 如果 `deployment.yaml` 向容器添加了 `--feature-flag` 标志，`k8s/` 和 `k8s-prod/` 都必须手动更新。两个环境之间的差异隐藏在重复文件的差异中。

**修复：**
1. 重构为 Kustomize 基础/覆盖模式：
   ```
   ops/deploy/kustomize/
   ├── base/
   │   ├── deployment.yaml
   │   ├── service.yaml
   │   ├── namespace.yaml
   │   └── kustomization.yaml
   ├── overlays/
   │   ├── dev/
   │   │   └── kustomization.yaml  ← 仅覆盖内容
   │   └── prod/
   │       ├── hpa.yaml
   │       ├── pdb.yaml
   │       └── kustomization.yaml
   ```
2. 添加 `make k8s-render` 目标，将每个覆盖渲染为审计就绪的平面 YAML
3. 添加 `make k8s-diff` 目标，比较环境之间的渲染输出

**工作量：** M（Kustomize 重构 + 脚本 + Makefile 目标）| **影响：** 中（操作员效率——环境之间的配置差异在代码审查中是可见的）| **类型：** 运维

---

## 方向五：无声明式基础设施（IaC）用于云部署——部署依赖于 K8s YAML + SSH

**问题：** 项目有 K8s 清单和裸金属 HA `docker-compose.yml`，但**没有声明式基础设施代码**：

- ❌ 没有 Terraform/Pulumi/Crossplane 配置
- ❌ 没有用于 `aws`、`gcp` 或 `azure` 的 provider 配置
- ❌ 没有 VPC、子网、ELB/NLB、RDS/Cloud SQL 数据库、Redis 服务或 IAM 角色的 IaC
- ❌ 没有从 IaC 生成 K8s Kubeconfig 的自动化
- ❌ 没有 `make deploy` 或 `make deploy-prod` 目标

**为什么这是一个问题：** 部署 SSO 生产环境需要：
1. 手动创建 VPC + 子网 + 安全组（或使用默认值——在生产中不安全）
2. 手动创建 PostgreSQL RDS/Cloud SQL 实例（或使用裸金属 Postgres）
3. 手动创建 Redis Elasticache/Memorystore
4. 手动设置 etcd 层
5. 手动创建 OIDC 身份提供者
6. 应用 K8s 清单并希望网络策略正确

在 2026 年，不提供 Terraform 模块的 SSO 项目严重阻碍了采纳——操作员需要快速部署。不需要 IaC 作为入门步骤（`docker compose up` 已足够），但生产就绪的部署应该提供。

**修复：**
1. 添加 `ops/deploy/terraform/` 目录
2. 为 AWS 创建 Terraform 模块（最常见的云）：VPC、RDS（Postgres）、Elasticache（Redis）、ECS Fargate 或 EKS
3. 添加 `terraform/environments/{dev,prod}` 目录覆盖
4. 添加 `README.md` 文档化使用 `terraform apply` 部署生产 SSO
5. 在 CI 中添加 `terraform validate` 和 `terraform plan`

**工作量：** L（Terraform 模块是复杂的——数百行 HCL + 文档）| **影响：** **中高**（采纳——操作员可以用一个命令部署生产 SSO）| **类型：** 运维/基础设施

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | 7 份 config.yaml 无法交叉验证（配置漂移） | **高**（预防停机） | S | 运维 |
| 2 | 烟雾测试不验证令牌发放（部署后 FALSE PASS） | **高**（部署信心） | S | 运维/质量 |
| 3 | 声明式 IaC 缺失（无 Terraform 模块） | **中高**（采纳——操作员需要一键部署） | L | 运维/基础设施 |
| 4 | 负载测试无 CI/基线（性能回归漏检） | 中（性能可观测性） | M | 性能/测试 |
| 5 | K8s 环境间无差异层（裸 Kustomize 手动同步） | 中（操作员效率） | M | 运维 |

**按 ROI 排列：** 方向 1（配置验证——30 行标志 + CI 循环 = 防止所有 7 份 deploy config 中的配置漂移）→ 方向 2（烟雾测试——40 行 shell = 从"HAProxy 存活测试"升级到"SSO 工作测试"）→ 方向 4（负载测试基线——捕获性能回归，否则直到崩溃才被注意到）→ 方向 5（Kustomize 差异层——设置基础/覆盖模式，使环境差异在代码审查中可见）→ 方向 3（Terraform IaC——最高的操作员价值但需要最大的投入）。
