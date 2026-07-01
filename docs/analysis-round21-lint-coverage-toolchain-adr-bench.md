# 第二十一轮分析：Lint 覆盖率、工具链测试、ADR 合规、Benchmark 可发现性

> 基于全局代码库扫描产生的全新视角，此前二十轮未覆盖。

---

## 方向一：golangci-lint 仅覆盖根模块——12 个嵌套模块未被静态分析

**问题：** CI 的 `lint` 作业（`ci.yml:230-249`）在根模块上运行 `golangci-lint`，并作为**硬性门禁**。但嵌套模块**没有自己的 `.golangci.yml`**，且未被 CI 检测：

```yaml
lint:
  name: golangci-lint
  steps:
    - uses: golangci/golangci-lint-action@v6
      with:
        version: v2.1.0
# 仅根模块！嵌套模块未被 lint
```

**未受 lint 的模块：**
```
infrastructure/saml/      ← XML 解析（XXE、实体解析）
infrastructure/ldap/      ← LDAP 注入（过滤转义）
infrastructure/redis/     ← 命令注入（EVAL 脚本）
infrastructure/kms/*/     ← 加密密钥处理
infrastructure/kerberos/  ← 权限提升
infrastructure/radius/    ← RADIUS 协议解析
infrastructure/extauthz/  ← 外部 HTTP 授权（SSRF）
```

**为什么这是一个问题：** errcheck（未处理的错误）、staticcheck（死代码）、unused（未使用的变量）、gosec 风格的路径遍历和 SQL 注入检查**仅适用于根模块**。一个在 `infrastructure/redis/` 中的 `_, _ = conn.Do(ctx, cmd)` 会静默忽略错误。

**修复：**
1. 向每个嵌套模块添加 `.golangci.yml`（或复用根模块的配置）
2. 将 `lint` CI 作业扩展为矩阵（每个模块一个）
3. 添加 `make lint-all` Makefile 目标

**工作量：** S（每个模块一个 `.golangci.yml` 符号链接 + CI 中的 ~10 行矩阵扩展）| **影响：** **中高**（未检测的 Lint 违规——即嵌套模块中的 `errcheck` 漏洞）| **类型：** 质量/安全

---

## 方向二：checks/ Python 模块无自测试——14 个工程门禁是未经测试的代码

**问题：** `checks/` 目录包含 14 个强制执行工程门禁的 Python 模块：

```
checks/filesize.py       ← 文件行数预算检查
checks/complexity.py     ← 圈复杂度 + 认知复杂度检查
checks/architecture.py   ← 导入方向检查
checks/invariants.py     ← 安全不变式（禁止的导入模式）
checks/coverage.py       ← 测试覆盖率阈值
checks/root_business_code.py  ← 根目录业务代码检查
checks/root_files.py     ← 根目录文件计数
checks/exemptions.py     ← 豁免列表检查
...
```

**为什么这是一个问题：** 如果其中任何一个模块包含 bug，门禁会产生**误报**（阻止合法代码）或**漏报**（让违规通过）：

- `filesize.py` 中的行计数错误 → 501 行的文件被批准
- `architecture.py` 中的导入路径解析错误 → 允许 `oidc → oauth` 导入
- `invariants.py` 中的正则表达式不完整 → 允许禁止的导入模式

当前，没有 `python -m unittest checks/test_*.py` 作业在 CI 中运行。

**修复：**
1. 向每个 `checks/*.py` 模块添加 `test_*.py`
2. 添加 `make check-test` 目标
3. 在 CI 的 `engineering` 作业中添加 `python -m pytest checks/`

**工作量：** M（~20 行测试/模块 × 14 个模块 = ~280 行测试）| **影响：** 中（门禁可靠性——确保不会静默通过无效代码）| **类型：** 质量

---

## 方向三：skills/ Python 自动化脚本无测试覆盖——修改代码的代码未经验证

**问题：** `docs/skills/` 中的 6 个技能包含 `run.py` 脚本，这些脚本**自动修改 Go 代码库**：

| 技能 | run.py | 风险 |
|------|--------|------|
| `split-large-file` | 将 Go 文件拆分为多个文件 | 生成损坏的 Go 语法 |
| `refactor-high-complexity` | 提取子函数 | 生成无法编译的代码 |
| `oracle-leak` | 添加 oracle-leak 防护 | 生成不正确的错误处理 |
| `add-new-handler` | 构架新的 OAuth 处理程序 | 错误的 import 路径 |
| `architecture-fix` | 修复导入方向 | 错误的包引用 |
| `project-reorganization` | 重新组织目录 | 重复的文件路径 |

**为什么这是一个问题：** 这些技能在代码审查中被使用，但：
- 没有 `python -m unittest docs/skills/*/test_*.py` 测试
- 没有 CI 作业验证技能输出可以通过 `go build`
- 在技能运行后没有验证（没有 `go vet ./...` 后置条件检查）
- 一个在 `oracle-leak/run.py` 中的回归会在没有警告的情况下将不正确的错误处理引入代码库

**修复：**
1. 为每个 `run.py` 添加 `test_*.py`，使用固定输入测试输出
2. 添加 CI 作业，运行每个技能并验证输出可以通过 `go build`
3. 添加 `make skill-test` Makefile 目标

**工作量：** M（每个技能 ~30 行测试 + CI 管道）| **影响：** 中（质量保证——自动化代码修改需要自动化验证）| **类型：** 质量/开发体验

---

## 方向四：8 个 ADR 无 CI 执行——架构决策已记录但未强制

**问题：** 项目在 `docs/adr/` 中有 8 个架构决策记录，记录了重要的架构规则：

| ADR | 规则 | CI 强制？ |
|-----|------|-----------|
| ADR-0001 | 根目录 ≤15 个非豁免文件 | ✅（通过 `root_files.py`） |
| ADR-0002 | 导入方向向下，不向上 | ✅（通过 `architecture.py`） |
| ADR-0003 | 协议分组在 `protocols/` 下 | ❌ 无 CI 检查 |
| ADR-0004 | 域边界，真实实现优先于 mock | ❌ 无 CI 检查 |
| ADR-0005 | 文件 ≤500 行，函数 ≤50 行 | ✅（通过 `filesize.py` + 测试） |
| ADR-0006 | 认知架构（六边形提取） | ❌ 无 CI 检查 |
| ADR-0007 | 目录扇出和单体型豁免 | ❌ 无 CI 检查 |
| ADR-0008 | Proto 版本控制（不删除字段） | ✅（通过 `buf breaking`） |

**缺少的 CI 检查示例：**
- ADR-0003：一个在 `protocols/` 下创建 `internal/` 目录（或其他违反分组规则）的 PR 不会被 CI 拒绝
- ADR-0004：使用 mock 而不是 `MemoryProvider` 的测试不会被 CI 检测到
- ADR-0007：超过目录扇出限制（每目录 ≤15 个子目录）不会被 lint 门禁捕获

**为什么这是一个问题：** ADR 是"已同意的架构"，但没有持续执行的机制。代码库可能在未经审查的情况下偏离同意的架构。

**修复：**
1. 添加 `checks/adr_compliance.py` 模块检查：
   - ADR-0003：所有 `protocols/` 子目录必须是已识别的协议
   - ADR-0004：扫描测试文件中的 mock 使用情况
   - ADR-0007：检查目录扇出 ≤15
2. 在 `python cli.py check` 门禁中包含 ADR 合规性

**工作量：** M（~60 行 Python 检查 + CI 集成）| **影响：** 中（架构完整性——防止 ADR 悄然违反）| **类型：** 架构/质量

---

## 方向五：Benchmark 目标硬编码为 4 个包——新增的 Benchmark 被静默忽略

**问题：** Makefile 的 `bench` 目标使用硬编码的包列表：

```makefile
bench: ## Run benchmarks.
	$(GO) test -run='^$$' -bench=. -benchmem ./infrastructure/defaultimpl/ ./protocols/oauth/ ./interfaces/ratelimit/ ./shared/security/
```

当前，代码库中有 **4 个 Benchmark 文件**，与 `make bench` 覆盖的 4 个包匹配：

```
infrastructure/defaultimpl/issuer_bench_test.go
shared/security/jwks_verify_bench_test.go
protocols/oauth/bind_bench_test.go
interfaces/ratelimit/ratelimit_bench_test.go
```

**缺少的 Benchmark：**
- `protocols/oidc/` → IDToken 签发、Userinfo 签名应是性能关键的
- `domains/permissions/` → 通配符匹配 Benchmark（`user:*` 与 `user:read`）
- `shared/security/` → JWE 加密 Benchmark 缺失（只有 JWKS 验证）
- `audit/` → 审计链验证 Benchmark
- `protocols/federation/` → 信任链解析 Benchmark

**为什么这是一个问题：** 任何开发者在 `protocols/oidc/` 中添加 Benchmark 都不知道 `make bench` 不会运行它。Benchmark 覆盖率随着代码库的增长而悄悄转移。

**修复：**
1. 用 `./...`（所有包）替换硬编码的路径
2. 或者添加会自动检测 Benchmark 文件的 `make bench-all`
3. 或者在 `make bench` 上方添加带有基准结果的 CI 作业，以检测回归

**工作量：** S（将 `./...` 更改为 `./...` 或在 Makefile 中添加一行）| **影响：** 低-中（Benchmark 可发现性——新 Benchmark 未被注意到）| **类型：** 性能/测试

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | golangci-lint 仅覆盖根模块（嵌套模块未 lint） | **中高**（未检测的 lint 违规——errcheck、deadcode） | S | 质量/安全 |
| 2 | checks/ Python 模块无自测试（门禁可靠性未知） | 中（门禁 bug → 漏报/误报） | M | 质量 |
| 3 | skills/ Python 自动化脚本未测试（修改代码的代码） | 中（自动重构生成无效 Go） | M | 质量/开发体验 |
| 4 | 8 个 ADR 无 CI 执行（已同意的架构可能被违反） | 中（架构完整性） | M | 架构/质量 |
| 5 | Benchmark 目标硬编码为 4 个包（新 Benchmark 静默忽略） | 低-中（性能可发现性） | S | 性能/测试 |

**按 ROI 排列：** 方向 1（嵌套模块 lint——将现有 CI 作业扩展为矩阵 = 在没有新工具的情况下覆盖整个代码库）→ 方向 2（checks 测试——添加 ~280 行测试确保 14 个工程门禁可靠）→ 方向 5（Benchmark 可发现性——将 `./...` 更改为 `./...`，不损失任何东西）→ 方向 3（技能测试——验证自动化 Go 修改产生可编译的输出）→ 方向 4（ADR 合规性——高价值但需要解析非正式决策文件）。
