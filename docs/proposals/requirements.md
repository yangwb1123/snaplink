Spec written to `docs/auto/interfaces-cors-direction2-spec.md`. All evidence was verified against the code before writing.

## Summary

**决定 1：`security.cors.path_overrides` YAML 映射**
- Problem: `Policy.PathOverrides`（`cors.go:58-66` 卖点特性）在配置层被截断；`CORSConfig` 无字段、`toPolicy()` 不映射，且 stock binary 有**第二处**内联映射（`build_app_security.go:170-179`，因 `WithCORS` 指针覆盖而为生效点），只修 `toPolicy()` 也投递不出去
- Proposed: `CORSConfig` 加 `path_overrides` 字段 + 提取映射 helper + 内联映射改调 `toPolicy()` + 接线门放宽为 `origins > 0 || overrides > 0`（`/` 前缀校验 fail loud）

**决定 2：`security.cors` 入契约文档**
- Problem: `config-reference.md:63-70` Security 表列了 8 个键唯独没有 `security.cors`（违反 AGENTS.md §5）；且 `cors.go:44` 文档举例的 `X-RateLimit-Remaining` 在整个 ratelimit 包中不存在（只发 `Retry-After`），测试固件 `cors_test.go:193` 传播同一虚构
- Proposed: 补全 Security 表行（覆盖每个 leaf + 空 origins 语义 + 需重启无热更新），示例改为真实头 `X-Request-Id`/`Retry-After`，全库零残留

**决定 3：允许头列表"追加到默认值"语义 + 常量单一来源**
- Problem: `buildConfig`（`cors.go:88`）空=默认、非空=整体替换；DPoP 是头等公民（`server_oauth.go:19-20` 读取 `HeaderDPoP`），运维写 `allowed_headers: [DPoP]` 会静默丢掉 `Authorization` → 难排查的 401；另 `consts.go` 因不成立的循环担忧重复声明 `shared/core` 已有的头常量
- Proposed: 非空列表合并进默认值（去重、确定性顺序）+ `allowed_headers_exclusive` 逃生舱；`consts.go` 改 import `shared/core`（层级上无环）

每个决定含验收检查（针对性单测/集成测试 + 构建/维护性门 + `make ci`）。文末附影响面与约束：无安全语义变更、无新 Err*/端点、`config/` 文件数冻结内扩展、明确非目标（方向一/三的热更新、origin 单一事实来源、可观测性）。
