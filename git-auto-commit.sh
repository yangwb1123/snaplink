#!/bin/bash
# git-auto-commit.sh - 自动化 Git 提交脚本
# 用法: ./git-auto-commit.sh [提交信息前缀]
# 示例: ./git-auto-commit.sh "feat: 添加新功能"
#        ./git-auto-commit.sh "docs: 更新文档"
#        ./git-auto-commit.sh "fix: 修复问题"

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查是否有 git 仓库
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}错误: 当前目录不是 git 仓库${NC}"
    exit 1
fi

# 检查是否有未提交的更改
if [[ -z $(git status -s) ]]; then
    echo -e "${GREEN}✓ 没有需要提交的更改${NC}"
    exit 0
fi

# 获取提交信息
if [[ -n "$1" ]]; then
    COMMIT_MSG="$1"
else
    # 生成默认提交信息
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    CHANGED_FILES=$(git status -s | wc -l | tr -d ' ')
    
    # 分析更改类型
    ADDED=$(git status -s | grep "^??" | wc -l | tr -d ' ')
    MODIFIED=$(git status -s | grep "^ M\|^M " | wc -l | tr -d ' ')
    DELETED=$(git status -s | grep "^ D\|^D " | wc -l | tr -d ' ')
    
    COMMIT_MSG="chore: 更新 ${CHANGED_FILES} 个文件 (${TIMESTAMP})"
    
    if [[ $ADDED -gt 0 ]]; then
        COMMIT_MSG="${COMMIT_MSG} [新增: ${ADDED}]"
    fi
    if [[ $MODIFIED -gt 0 ]]; then
        COMMIT_MSG="${COMMIT_MSG} [修改: ${MODIFIED}]"
    fi
    if [[ $DELETED -gt 0 ]]; then
        COMMIT_MSG="${COMMIT_MSG} [删除: ${DELETED}]"
    fi
fi

# 显示将要提交的文件
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}即将提交以下更改:${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
git status -s
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}提交信息: ${COMMIT_MSG}${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# 确认提交
read -p "是否继续提交? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消提交${NC}"
    exit 0
fi

# 执行提交
echo -e "${BLUE}正在添加文件...${NC}"
git add -A

echo -e "${BLUE}正在提交...${NC}"
git commit -m "$COMMIT_MSG"

echo -e "${GREEN}✓ 提交成功!${NC}"
echo -e "${BLUE}提交信息: ${COMMIT_MSG}${NC}"

# 显示提交哈希
COMMIT_HASH=$(git rev-parse --short HEAD)
echo -e "${BLUE}提交哈希: ${COMMIT_HASH}${NC}"

# 询问是否推送到远程
if git remote | grep -q .; then
    echo
    read -p "是否推送到远程仓库? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}正在推送...${NC}"
        if git push; then
            echo -e "${GREEN}✓ 推送成功!${NC}"
        else
            echo -e "${RED}✗ 推送失败${NC}"
            exit 1
        fi
    fi
fi

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ 完成!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
