Now I have a complete picture of the codebase. Let me provide an accurate assessment of each direction.

---

## 第二十一轮分析 — 验证结果

在实施之前，我逐一核对了每个方向的事实基础。**5 个方向中，3 个与当前代码库状态不符**，1 个部分有效，1 个完全有效。

---

### ❌ 方向一：golangci-lint 仅覆盖根模块 — **已过时**

**实际状态：已修复。** CI 的 `lint` 作业（`ci.yml:245-278`）已经是矩阵结构，覆盖根模块 + 全部 11 个嵌套模块：

```yaml
lint:
  name: golangci-lint (root + modules)
  strategy:
    matrix:
      module:
        - "."
        - infrastructure/kms/awskms
        - infrastructure/kms/gcpkms
        - infrastructure/kms/azurekeyvault
        - infrastructure/kms/pkcs11
        - infrastructure/redis
        - infrastructure/saml
        - infrastructure/ldap
        - infrastructure/kerberos
        - infrastructure/radius
        - infrastructure/extauthz
```

每个嵌套模块都有自己的 `.golangci.yml`（继承根配置），Makefile 还有 `lint-all` 目标。**无需行动。**

---

### ⚠️ 方向二：checks/ Python 模块无自测试 — **部分有效**

**实际状态：已有 `checks/self_test.py`**，且已在 CI 中作为硬性门禁运行（`engineering.yml` 的 "Self-test (harness integrity)" 步骤）。它覆盖了：
- `filesize.py` 的超大文件检测
- `gocyclo`/`gocognit` 工具安装
- `architecture.py` 的导入方向（oauth↔oidc 检查）
- 文档存在性

**但仍然有效的是：** `self_test.py` 是单文件集成测试，不是每个 `checks/*.py` 模块的独立单元测试。例如，`complexity.py`、`coverage.py`、`root_business_code.py`、`exemptions.py` 等的边界条件未被测试。

**影响评估：** 低-中。自测试已存在且捕获了关键路径；缺少的单元测试是防御纵深，不是紧急缺口。

---

### ✅ 方向三：skills/ Python 自动化脚本无测试 — **完全有效**

**实际状态确认：** 7 个 `run.py` 脚本存在于 `docs/skills/*/` 中，**没有任何 `test_*.py`**：

| 技能 | 风险 |
|------|------|
| `split-large-file/run.py` | 分析 Go 文件导出函数 |
| `refactor-high-complexity/run.py` | 修改 Go 源码提取子函数 |
| `oracle-leak/run.py` | 添加 oracle-leak 防护 |
| `add-new-handler/run.py` | 生成 OAuth handler 模板 |
| `architecture-fix/run.py` | 修复导入方向 |
| `project-reorganization/run.py` | 重新组织目录结构 |
| `post-edit-check/run.py` | 编辑后验证 |

这些脚本**修改代码库**，但没有测试验证输出的正确性。

---

### ❌ 方向四：8 个 ADR 无 CI 执行 — **事实错误**

**实际状态：所有 8 个 ADR 都已有 CI 强制。** 分析遗漏了关键的执行机制：

| ADR | 声称未执行 | 实际执行机制 |
|-----|-----------|-------------|
| ADR-0001 | ❌ | ✅ `root_files.py` + `root_business_code.py` |
| ADR-0002 | ❌ | ✅ `architecture.py` + `architecture_layer_test.go` |
| ADR-0003 | ❌ | ✅ ADR-0003 的决策是**保持扁平**，现有 architecture gate 已阻止未经授权的分组 |
| ADR-0004 | ❌ | ✅ `invariants.py` + code review + `check-invariants` gate |
| ADR-0005 | ❌ | ✅ `filesize.py` + `maintainability_budget_test.go` + `maintainability_complexity_test.go` |
| ADR-0006 | ❌ | ✅ `directory_fanout_test.go`（`TestArchitecture_LayerBoundaries`）|
| ADR-0007 | ❌ | ✅ `directory_fanout_test.go`（`package archgate`，≤10 文件/≤15 子目录）|
| ADR-0008 | ❌ | ✅ `buf breaking` + `buf lint` in CI |

**无需行动。**

---

### ❌ 方向五：Benchmark 目标硬编码为 4 个包 — **已过时**

**实际状态：已修复。** Makefile 中的 `bench` 和 `bench-all` 目标都已使用 `./...`：

```makefile
bench: ## Run benchmarks.
	$(GO) test -run='^$$' -bench=. -benchmem ./...

bench-all: ## Run benchmarks on all packages (same as bench).
	$(GO) test -run='^$$' -bench=. -benchmem ./...
```

**无需行动。**

---

## 总结

| # | 方向 | 分析结论 | 实际状态 | 需要行动？ |
|---|------|---------|---------|-----------|
| 1 | golangci-lint 覆盖 | 中高影响 | **已修复**（矩阵 CI + 每模块 `.golangci.yml`） | ❌ |
| 2 | checks/ 自测试 | 中影响 | **部分已有**（`self_test.py` 已运行于 CI） | ⚠️ 可选增强 |
| 3 | skills/ 无测试 | 中影响 | **有效**（7 个 `run.py` 无测试） | ✅ |
| 4 | ADR 无 CI 执行 | 中影响 | **事实错误**（全部 8 个已有执行机制） | ❌ |
| 5 | Benchmark 硬编码 | 低-中影响 | **已修复**（使用 `./...`） | ❌ |

**唯一明确可操作的改进是方向三（skills 测试）。** 方向二是可选的防御纵深增强。

---

## 建议实施

如果你同意这个评估，我可以：

1. **方向三（推荐）**：为 `docs/skills/*/run.py` 脚本添加单元测试
2. **方向二（可选）**：扩展 `checks/self_test.py` 覆盖更多模块的边界条件

要继续吗？
