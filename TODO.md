# TODO.md — Agent 任务追踪

## 进行中
_当前任务在此_

## 待办
_待开始任务在此_

## 重构队列
| 任务 | 原因 | 涉及文件 |
|---|---|---|
| 拆分 handlers.go | 3901 行 > 500 | handlers.go |
| 拆分 server_extensions.go | 3055 行 > 500 | server_extensions.go |
| 拆分 sso.go | 2993 行 > 500 | sso.go |
| 拆分 handler.go | 2549 行 > 500 | handler.go |
| 降低 handleLogin 圈复杂度 | > 15 | handler.go |

## 已完成
_已完成任务在此_

## 规则
- 开始 → 移入「进行中」，完成 → 移入「已完成」
- 发现重构需求 → 加入「重构队列」（优先级 HIGH）
- 每 3 个功能任务 → 至少 1 个重构任务
