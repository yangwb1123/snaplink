# Git 自动提交工具使用指南

## 📦 工具列表

### 1. `git-auto-commit.sh` - 交互式自动提交脚本

**功能**:
- 检测未提交的更改
- 自动生成提交信息（包含时间戳和更改统计）
- 支持自定义提交信息
- 显示更改文件列表
- 交互式确认
- 可选推送到远程仓库

**使用方法**:

```bash
# 方法 1: 自动生成提交信息
./ai-dev/git-auto-commit.sh

# 方法 2: 自定义提交信息
./ai-dev/git-auto-commit.sh "feat: 添加用户认证功能"
./ai-dev/git-auto-commit.sh "fix: 修复登录问题"
./ai-dev/git-auto-commit.sh "docs: 更新文档"
./ai-dev/git-auto-commit.sh "refactor: 重构代码结构"
```

**示例输出**:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
即将提交以下更改:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 M config/config.go
?? new-feature.go
?? tests/new_test.go
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
提交信息: feat: 添加新功能 (2026-07-01 15:00:00) [新增: 2] [修改: 1]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
是否继续提交? (y/n) y
正在添加文件...
正在提交...
✓ 提交成功!
提交信息: feat: 添加新功能
提交哈希: abc1234
是否推送到远程仓库? (y/n) y
正在推送...
✓ 推送成功!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ 完成!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### 2. 快速提交命令（一行命令）

```bash
# 添加所有更改并提交（自动生成信息）
git add -A && git commit -m "chore: update $(date +%Y-%m-%d)"

# 添加所有更改并提交（自定义信息）
git add -A && git commit -m "feat: 新功能描述"

# 提交并推送
git add -A && git commit -m "docs: 更新文档" && git push
```

---

### 3. 批量提交脚本

如果你需要频繁提交，可以创建一个简化版本：

```bash
# 创建别名（添加到 ~/.bashrc 或 ~/.zshrc）
alias gac='git add -A && git commit -m "chore: update $(date +%Y-%m-%d)"'
alias gacp='git add -A && git commit -m "chore: update $(date +%Y-%m-%d)" && git push'

# 使用
gac           # 提交所有更改
gacp          # 提交并推送
```

---

## 🎯 提交信息规范

推荐使用 **Conventional Commits** 规范：

### 类型前缀

| 前缀 | 说明 | 示例 |
|------|------|------|
| `feat:` | 新功能 | `feat: 添加用户登录功能` |
| `fix:` | 修复 Bug | `fix: 修复内存泄漏问题` |
| `docs:` | 文档更新 | `docs: 更新 API 文档` |
| `style:` | 代码格式 | `style: 格式化代码` |
| `refactor:` | 重构 | `refactor: 重构认证模块` |
| `perf:` | 性能优化 | `perf: 优化数据库查询` |
| `test:` | 测试 | `test: 添加单元测试` |
| `chore:` | 构建/工具 | `chore: 更新依赖` |
| `ci:` | CI/CD | `ci: 添加 GitHub Actions` |
| `build:` | 构建系统 | `build: 优化 Docker 镜像` |

### 完整格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

**示例**:
```
feat(auth): 添加 OAuth2 支持

- 实现 OAuth2 授权码流程
- 添加 Google 和 GitHub 提供商
- 添加单元测试和集成测试

Closes #123
```

---

## 📝 最佳实践

### 1. 频繁提交

```bash
# 每完成一个小功能就提交
./ai-dev/git-auto-commit.sh "feat: 完成用户注册"
./ai-dev/git-auto-commit.sh "feat: 完成邮箱验证"
./ai-dev/git-auto-commit.sh "feat: 完成密码重置"
```

### 2. 有意义的提交信息

```bash
# ❌ 不好的提交信息
./ai-dev/git-auto-commit.sh "更新"
./ai-dev/git-auto-commit.sh "修复"
./ai-dev/git-auto-commit.sh "wip"

# ✅ 好的提交信息
./ai-dev/git-auto-commit.sh "feat: 添加 JWT 令牌刷新机制"
./ai-dev/git-auto-commit.sh "fix: 修复并发登录时的竞态条件"
./ai-dev/git-auto-commit.sh "perf: 优化数据库连接池配置"
```

### 3. 原子提交

每个提交应该是一个完整的、可独立理解的更改：

```bash
# ❌ 不推荐：混合多种类型的更改
./ai-dev/git-auto-commit.sh "feat: 添加登录和修复登录问题"

# ✅ 推荐：分开提交
./ai-dev/git-auto-commit.sh "feat: 添加登录功能"
./ai-dev/git-auto-commit.sh "fix: 修复登录验证逻辑"
```

### 4. 提交前检查

```bash
# 查看将要提交的文件
git status

# 查看更改内容
git diff

# 确认无误后再提交
./ai-dev/git-auto-commit.sh "docs: 更新 README"
```

---

## 🔧 高级用法

### 1. 撤销最后一次提交

```bash
# 保留更改
git reset --soft HEAD~1

# 丢弃更改
git reset --hard HEAD~1
```

### 2. 修改最后一次提交信息

```bash
git commit --amend -m "新的提交信息"
```

### 3. 合并多个提交

```bash
# 交互式变基
git rebase -i HEAD~5

# 在编辑器中修改 pick 为 squash
```

### 4. 查看提交历史

```bash
# 简单视图
git log --oneline

# 图形视图
git log --oneline --graph --all

# 搜索提交
git log --grep="关键词"
```

---

## 🚀 自动化工作流

### 1. 开发流程

```bash
# 1. 开始新功能
git checkout -b feature/new-feature

# 2. 编码...
# 3. 完成后提交
./ai-dev/git-auto-commit.sh "feat: 完成新功能"

# 4. 推送到远程
git push -u origin feature/new-feature

# 5. 创建 Pull Request
```

### 2. 修复流程

```bash
# 1. 创建修复分支
git checkout -b fix/issue-123

# 2. 修复问题...
# 3. 提交
./ai-dev/git-auto-commit.sh "fix: 修复 #123 问题"

# 4. 推送并创建 PR
git push -u origin fix/issue-123
```

### 3. 文档更新流程

```bash
# 1. 更新文档...
# 2. 提交
./ai-dev/git-auto-commit.sh "docs: 更新 API 文档"

# 3. 推送
git push
```

---

## 📊 提交统计

### 查看项目提交统计

```bash
# 提交总数
git rev-list --count HEAD

# 按作者统计
git shortlog -sn

# 按月份统计
git log --format='%ad' --date=format:'%Y-%m' | sort | uniq -c
```

### 查看文件统计

```bash
# 查看文件更改历史
git log --follow -p config/config.go

# 查看谁最后修改了某行
git blame config/config.go | grep "关键代码"
```

---

## ⚠️ 注意事项

1. **提交前检查**: 确保代码可以编译通过
   ```bash
   go build ./...
   go test ./...
   ```

2. **不要提交敏感信息**:
   ```bash
   # 添加到 .gitignore
   echo "*.env" >> .gitignore
   echo "*.key" >> .gitignore
   ```

3. **大文件处理**:
   ```bash
   # 使用 Git LFS 管理大文件
   git lfs track "*.pdf"
   ```

4. **分支策略**:
   - `main`: 生产分支
   - `develop`: 开发分支
   - `feature/*`: 功能分支
   - `fix/*`: 修复分支
   - `release/*`: 发布分支

---

## 🔗 相关资源

- [Conventional Commits 规范](https://www.conventionalcommits.org/)
- [Git 官方文档](https://git-scm.com/doc)
- [Pro Git 书籍](https://git-scm.com/book/zh/v2)

---

## 💡 提示

- 使用 `./ai-dev/git-auto-commit.sh --help` 查看帮助
- 可以修改脚本自定义提交信息格式
- 建议设置 Git 别名简化常用命令
- 定期清理未跟踪的文件
