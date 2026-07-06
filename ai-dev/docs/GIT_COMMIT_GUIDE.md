# Git 自动提交脚本使用指南

## 📦 已提交的变更

本次提交包含了完整的多角色审查系统和代码实现 Pipeline：

**提交信息**: `feat: 添加多角色审查系统和代码实现 Pipeline`

**统计**:
- 221 个文件变更
- 32,521 行新增
- 2,833 行删除

## 🚀 自动提交脚本

创建了 `git-auto-commit.sh` 脚本，用于快速提交修改：

### 基本用法

```bash
# 使用自定义提交信息
./ai-dev/git-auto-commit.sh "feat: 添加新功能"

# 使用自动生成的提交信息
./ai-dev/git-auto-commit.sh

# 指定类型前缀
./ai-dev/git-auto-commit.sh "docs: 更新文档"
./ai-dev/git-auto-commit.sh "fix: 修复问题"
```

### 功能特性

✅ 自动检测文件变更（新增/修改/删除）  
✅ 智能生成提交信息（包含时间戳和统计）  
✅ 彩色输出，易于阅读  
✅ 提交前确认提示  
✅ 可选推送到远程仓库  
✅ 显示提交哈希  

### 使用示例

#### 1. 完成一个功能后提交

```bash
# 编写代码后
./ai-dev/git-auto-commit.sh "feat: 实现用户认证模块"

# 更新文档后
./ai-dev/git-auto-commit.sh "docs: 更新 API 文档"

# 修复问题后
./ai-dev/git-auto-commit.sh "fix: 修复内存泄漏问题"
```

#### 2. 快速提交（使用默认信息）

```bash
./ai-dev/git-auto-commit.sh
```

脚本会自动生成类似以下的提交信息：
```
chore: 更新 15 个文件 (2026-07-01 15:00:00) [新增: 5] [修改: 8] [删除: 2]
```

#### 3. 推送到远程

脚本会询问是否推送到远程仓库，选择 `y` 即可自动推送。

## 📋 Pipeline 快速参考

### 代码实现 Pipeline（6 阶段）

```bash
# 准备需求
cat > docs/requirements/feature.md << 'EOF'
# 功能名称
## 功能描述
...
EOF

# 执行 Pipeline
./ai-dev/pi-batch.py --pipeline ai-dev/pipelines/pipeline-code-impl.yaml --mode parallel -w 3

# 提交结果
./ai-dev/git-auto-commit.sh "feat: 完成功能实现"
```

### 完整 SDLC Pipeline（10 阶段）

```bash
# 执行完整审查
./ai-dev/pi-batch.py --pipeline ai-dev/pipelines/pipeline-full-sdlc.yaml --mode parallel -w 4

# 提交审查结果
./ai-dev/git-auto-commit.sh "docs: 完成完整 SDLC 审查"
```

## 🎯 推荐工作流程

```bash
# 1. 编写代码或文档
vim path/to/file.go

# 2. 测试代码
go test ./...

# 3. 提交修改
./ai-dev/git-auto-commit.sh "feat: 实现 XXX 功能"

# 4. 或使用 Pipeline 进行多角色审查
./ai-dev/pi-batch.py --pipeline ai-dev/pipelines/pipeline-code-impl.yaml

# 5. 提交审查结果
./ai-dev/git-auto-commit.sh "docs: 完成代码审查"

# 6. 重复上述流程
```

## 📊 查看 Git 历史

```bash
# 查看提交历史
git log --oneline -10

# 查看最近一次提交的详情
git show HEAD

# 查看文件变更统计
git diff --stat HEAD~1

# 查看特定文件的修改历史
git log --follow -p -- path/to/file.go
```

## 💡 提示

1. **频繁提交**: 每完成一个小功能就提交，便于回滚和追踪
2. **清晰的提交信息**: 使用有意义的提交信息，便于团队协作
3. **使用脚本**: 使用 `git-auto-commit.sh` 可以节省时间
4. **Pipeline 结果**: Pipeline 生成的分析文档也应该提交
5. **备份**: 定期推送到远程仓库

## 🔧 高级用法

### 批量提交

```bash
# 提交所有分析文档
./ai-dev/git-auto-commit.sh "docs: 添加多轮分析报告"

# 提交所有角色模板
./ai-dev/git-auto-commit.sh "feat: 添加 16 个专家角色模板"
```

### 查看未提交的更改

```bash
# 简短格式
git status -s

# 详细格式
git status

# 查看具体修改
git diff
```

### 撤销操作

```bash
# 撤销工作区的修改
git restore path/to/file.go

# 撤销暂存的修改
git restore --staged path/to/file.go

# 撤销最后一次提交（保留修改）
git reset --soft HEAD~1
```

## 📚 相关文档

- `ROLES_SUMMARY.md` - 角色清单

## 🎉 总结

现在你拥有了：

✅ **221 个文件已提交** - 完整的审查系统和 Pipeline  
✅ **自动提交脚本** - `git-auto-commit.sh` 快速提交  
✅ **3 个 Pipeline 配置** - 代码实现、快速审查、完整 SDLC  
✅ **16 个角色模板** - 覆盖完整软件开发生命周期  

**立即开始**：
```bash
# 1. 准备需求
echo "# 新功能" > docs/requirements/my-feature.md

# 2. 执行 Pipeline
./ai-dev/pi-batch.py --pipeline ai-dev/pipelines/pipeline-code-impl.yaml

# 3. 提交结果
./ai-dev/git-auto-commit.sh "feat: 完成新功能实现"
```

Happy Coding! 🚀
