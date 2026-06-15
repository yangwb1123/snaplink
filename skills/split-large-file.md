# Skill: Split Large File

## 步骤
1. **识别职责**: `grep -n '^type \|^func \|^const \|^var ' target.go`
2. **分组**: 按语义分（类型/选项/路由/Handler/Builder/常量）
3. **创建文件**: 同包、前缀命名 `target_<group>.go`
4. **移动声明**: 纯移动，不修改函数体
5. **补全 import**: 确保编译通过
6. **验证**: `go build ./... && go test -count=1 ./pkg/... && make harness`

## 验收
- [ ] 每个新文件 ≤ 500 行
- [ ] 编译通过
- [ ] 测试通过
- [ ] `make harness` 通过
