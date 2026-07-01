文档已生成并保存为 `docs/architecture-analysis.md`（723 行，30 个章节）。

## 输出概述

**文档组织结构：**

```
0. Executive Summary              — 推荐的执行顺序与分层
1. Architecture Assessment        — 优势、局限性、架构债务（3项）
2. Extension Directions (A-E)     — 五个方向的深入分析
3. Interface Design Proposals     — CSP中间件 / 配置验证 / Async Span传播
4. Technical Selection            — 技术选型对比表（6项决策）
5. Implementation Roadmap         — 三个阶段 + 风险登记表 + 依赖地图
Appendices                        — 预算表 / 配置键 / 豁免影响
```

**核心架构决策要点：**

| 决策 | 选择 | 原理 |
|------|------|------|
| CSP 实现位置 | Go 中间件（Echo），非 nginx | `form_post.html` nonce 注入需要 Go 模板引擎 |
| Config 验证层次 | JSON Schema + Go Validator Chain 双层 | Schema 无法表达跨字段互斥约束 |
| Async Span 策略 | Hybrid：audit 用延迟销毁，cluster 用新根 | 审计 ops 有界低延迟，cluster 可能长生存 |
| Benchmark 预算 | `allocations/op` 作为主信号，P99 为辅助 | 共享 runner 上分配数比延迟更稳定 |
| FIPS 基础镜像 | 双策略：CI 用 `golang:1.24-fips-alpine`，生产推荐 UBI | 公共镜像可及性与生产级验证的平衡 |
| 密码哈希 | 非 FIPS 用 bcrypt，FIPS 用 PBKDF2-HMAC-SHA256 | 条件编译，构建时切换 |

**推荐执行顺序：** 方向一（CSP）+ 方向四（Benchmark CI）并行启动（Phase A）→ 方向二（Config Schema）+ 方向三（Async Trace）在 Phase B → 方向五（FIPS）作为市场驱动触发器（Phase C）。

**关键变更：** 无新层目录、无新维护性豁免、无向上导入。所有新文件 ≤200 行，所有新函数 ≤10 cyclo。
