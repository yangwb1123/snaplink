# Connection health degraded UX — bounded design

## 当前证据

- `domains/connections/health.go` 定义了 `HealthUnknown`、`HealthHealthy`、
  `HealthDegraded` 和 `HealthUnreachable`；记录来自 admin-triggered probe，
  不是登录请求触发的探针。
- `domains/connections/probe.go` 将上游错误状态或 malformed metadata 记录为
  `HealthDegraded`，将握手无法完成或没有可探测配置记录为
  `HealthUnreachable`。
- 当前 HEAD 的 `interfaces/sso/server_oauth.go` 为 500 行，
  `respondLoginProviders` 已读取 `Store.Health`，但只把
  `HealthUnreachable` 映射为 `unavailable: true`。`HealthHealthy`、
  `HealthUnknown`、nil health 和 `Health` 读取错误都不设置该键。
- `server_login_resolve.go` 的 `resolveHomeRealm` 只解析已存储的连接和租户
  边界；它不发起网络请求。直接 `/auth/home-realm` 的路由解析保持原有行为。

## 状态映射

仅在 `/auth/login` 未指定 provider、已解析 home-realm connection 且读取到
非 nil health 时消费已存储状态：

| 已存储状态 | `unavailable` |
| --- | --- |
| `HealthDegraded` | `true` |
| `HealthUnreachable` | `true` |
| `HealthHealthy` | absent |
| `HealthUnknown` | absent |
| nil health | absent |
| `Health` 返回 error | absent，继续返回原有 `200`、`connection_required` 和 `connection_id` |

这是 UI 的 advisory 显示信号；它不改变连接解析、provider dispatch、认证、
备用路径或最终错误。

## Fail-open 与 oracle 边界

Health 读取失败按现有 fail-open 处理：不泄漏存储错误或 probe 详情，也不把
stale/missing health 转成认证依赖。unknown、disabled、cross-tenant 或 broken
provider 的既有 `unsupported_provider` oracle 语义不变；显式 provider login
也不因该字段被拒绝。

## Wire compatibility

`unavailable` 是可选的 additive JSON property，只在既有 home-realm login
response 的 degraded/unreachable 显示场景为 `true`；healthy/unknown/default
响应继续省略它，不发送 `false`。响应仍为 HTTP 200，既有
`connection_required`、`connection_id` 和其他路由字段保持不变。OpenAPI 与独立
frontend contract 会说明它是最近一次 admin probe 的 stale/advisory 结果，不
代表账号存在性或最终认证结果；不增加 route、error、event 或 config。

## 本批次明确不做

不添加按需或后台探针、TTL、连续失败计数、熔断/半开、备用 IdP、本地
fallback、隐藏连接、显式 provider 拒绝，也不把 stale health 变成同步认证
依赖。既有 probe 与存储仍是唯一状态来源。

## Rollback

回滚只需撤销 `HealthDegraded` 到 `unavailable` 的条件及对应契约/测试说明；
无需数据迁移、配置变更或状态清理。此前记录的 health 状态可原样保留，回滚后
仅恢复为不消费 degraded 状态的旧显示行为。
