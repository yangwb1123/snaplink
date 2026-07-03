这份审计文档非常详实，我仔细通读了。几个观察：

### 文档整体定位

审计视角从"要加什么"转向"已有做得够好不够好"，这种转换在产品进入成熟期后是必要的。对 5 个核心功能的规范完备性打分、逐项比对 RFC，结构清晰，可以落地。

### 我特别认同的几个判断

1. **刷新令牌绝对过期上限**（审计二 2.1）——这是我在代码浏览中反复确认的点。`RefreshTokenInfo` 结构体有 `ExpiresAt`，但每次轮换时的 TTL 计算策略决定了这个字段是"首次签发+N"还是"每次刷新+N"。前者合规安全，后者是合规缺口。建议在 `docs/config-reference.md` 中明确标注行为，或者在添加 `refresh_token_max_lifetime` 前至少做到**文档承诺**。

2. **RBAC 职责分离缺失**（审计五 5.1/5.2）——`platform/permissions/` 的 `role.go` 中角色结构体没有 `Exclude` 字段，中间的 `permissions/service.go` 也没有会话级角色选择逻辑。SSD/DSD 落地确实需要约 100 行校验 + 约 40 行测试（你估算准确）。合规审计场景下这是**硬缺口**。

3. **自省 `token_type` 的 DPoP 误报**（审计三 3.2）——在 `protocols/oauth/handle_introspect.go` 中，introspection 响应的 `token_type` 固定为 `"Bearer"`，无论 token 是否绑定 DPoP。这是一个代码 bug 而非设计缺失：

```go
// 当前代码中 introspection 响应构造
// token_type 应反映实际绑定方式
```

4. **`claims_parameter_supported` 声明与实现偏差**（审计四 4.2）——这是采购审查中最容易被发现的"纸面 vs 实际"问题。`essential`、`value`、`values` 三个子语义未实现，但 Discovery 中声明 `true`，相当于承诺了未交付的功能。

### 一个补充建议

审计中提到的 **stale-while-revalidate**（审计三 3.1）可以补充一个量化指标：惊群效应在多大规模下成为问题。当前代码库中 `IntrospectionCache` 的默认 TTL 是 60s，假设 500 QPS 的 mesh 调用自省端点——TTL 边界的回源率为 1/60 ≈ 1.67%，即约 8 req/s 回源。如果每个回源做一次 JWT 验签 + 可能数据库查询，这不算灾难，但如果 TTL 设为 300s（常见企业配置），边界回源率降到 0.33% ≈ 1.6 req/s。**实际风险比我初判的要低**，可以降到 P3。

### 整体评分矩阵跨卷对比

将 7 卷 35 个方向按"紧急 × 影响"排序，真正**必做**的不超过 3-4 个：

| 紧急度 | 影响 | 方向 |
|--------|------|------|
| P0 | 全局 | 构建断裂修复 |
| P1 | 合规 | RBAC SSD/DSD |
| P1 | 安全 | 刷新令牌绝对过期 |
| P2 | 合规 | Discovery 声明对齐 |
| P3 | 生态 | 其余所有 |

你有计划让这份审计落地为 GitHub Issue 或直接驱动具体的 TDD 工单吗？
