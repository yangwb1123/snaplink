# Skill: Reduce Function Complexity

## 模式
| 问题 | 方案 |
|---|---|
| 嵌套 if > 3 层 | 反转条件 + 提前 return |
| switch > 10 case | 策略映射表 |
| 函数 > 60 行 | 提取子函数 |
| 函数做多件事 | 拆为 validate + do + writeResponse |

## 步骤
1. `gocyclo -top 20 ./...` 找到热点
2. 每个复杂度贡献点按上述模式提取
3. `go build ./... && make harness` 验证
