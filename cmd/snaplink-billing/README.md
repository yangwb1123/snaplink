# snaplink-billing

`snaplink-billing` 是独立、API-only 的多租户商业化组合根。它挂载套餐、订阅、
Entitlement、钱包、充值订单和对账 API，并初始化 invoice-grade usage ledger。
它不会托管 `snaplink-console` 或任何静态资源。

## 安全与部署边界

- 生产模式必须配置 PostgreSQL；只有显式 `--dev-memory` 才会使用非持久内存，且
  仅用于本机开发。
- 进程当前不终止 TLS，因此所有模式都强制监听 loopback。生产环境应由同机或同
  Pod 的受信 TLS 边缘代理暴露；边缘必须剥离并重新设置转发头。
- `issuer`、billing API `audience` 和 JWKS URL 都是必填信任边界。JWKS 在本地缓存
  后验证签名、issuer、audience 和令牌时间；HTTP 上游仅可通过显式开关用于 loopback。
- `/livez` 和依赖型 `/readyz` 位于 bearer 认证之外。不要把探针直接暴露到公共网络；
  只允许 kubelet、同 Pod 边缘或受限运维网络访问。
- PostgreSQL DSN 和 Audit OAuth client secret 只从环境变量读取，避免出现在进程
  参数和命令历史中。

生产示例（先复制并替换 [`config.example.env`](config.example.env) 中的占位值）：

```sh
set -a
. ./cmd/snaplink-billing/config.example.env
set +a
go run ./cmd/snaplink-billing
```

本地开发示例要求本机 Snaplink issuer 已在 `127.0.0.1:8080` 运行：

```sh
go run ./cmd/snaplink-billing \
  --dev-memory \
  --issuer http://127.0.0.1:8080 \
  --audience billing-api \
  --allow-insecure-loopback
```

构建独立、静态的 distroless 容器目标：

```sh
docker build --target snaplink-billing -t snaplink/billing .
```

容器内仍强制监听 loopback，不能用 `-p` 把明文端口直接发布到公网。在 Kubernetes 中
与受信 TLS edge 放入同一 Pod；Linux 单机验证可使用 host network，并通过本机反向代理
访问。catalog 与 source-binding 文件应只读挂载，环境变量文件不要打进镜像。

构建产物支持无需加载运行配置的供应链检查：`snaplink-billing version` 输出版本与
VCS/build time，`snaplink-billing modules --json` 输出编译期 profile、lock digest、模块
和 capability 清单。未知 modules 参数以退出码 2 拒绝。

## API 授权

所有业务路由先经过本地 JWKS 验证，再按 `interfaces/commerce.RouteContracts()` 的
精确契约授权：

- `GET /api/v1/admin/commerce/**` 要求精确 `admin:read`。
- 管理端 `POST`/`PATCH` 的路由契约要求 `admin:write`；`admin:write` 不隐式获得读权限，
  但共享权限语义中的 `admin:*`/`*` 可覆盖更窄权限。
- `GET /api/v1/commerce/tenants/:tenant_id/payments/orders/:order_id`
  要求 `billing:payment:order:read`，只向绑定到同 tenant 和同 `payment:<provider>`
  的 client_credentials 身份返回可信订单金额与状态；provider 不匹配与订单不存在同为 404。
- `POST /api/v1/commerce/tenants/:tenant_id/payments/orders/:order_id/events`
  要求 `billing:payment:write`，并且令牌必须是 `sub == client_id` 的
  client_credentials 身份。
- `POST /api/v1/metering/usage`、reservation 创建/提交/释放要求
  `metering:write`；`GET /api/v1/metering/entitlement` 要求
  `billing:entitlement:read`。这些固定、无 tenant path 的机器路由还要求
  `sub == client_id`，并由服务端 binding 把 client 映射到 tenant/source。

支付事件端点只接收外部 provider adapter 归一化后的事实。Provider 签名、API key、
卡数据和 raw webhook 必须留在独立进程；该 adapter 先验证 provider，再使用 Snaplink
client_credentials 调用上述机器端点。支付 adapter 的 source binding 使用
`payment:<provider>`（例如 `payment:stripe`）且不声明计量维度；服务端据此固定
`client_id → tenant → provider`，请求体不能选择其他租户或支付渠道。解析出的 binding
`id/revision` 只是待复核证据：PostgreSQL 会在同一个 serializable 财务事务里用
`FOR SHARE` 重新验证 client、tenant、`payment:<provider>`、enabled、空
`allowed_dimensions` 和 revision。未知、禁用、过期 revision、跨租户或跨 provider 的
binding 全部折叠为相同的 `403 insufficient_scope`，不会暴露哪一项不匹配。

## PostgreSQL 与目录种子

启动时会在同一 PostgreSQL pool 上执行 tenant-commerce 与 usage-ledger 的版本化迁移。
连接失败或任一迁移失败都会阻止 readiness 和启动。`SNAPLINK_BILLING_CATALOG_FILE`
可选；为空时不发布套餐。配置后，文件必须是小于 2 MiB 的严格 JSON `Plan` 数组：

- 未知字段、尾随 JSON、`null` 和缺少稳定 `created_at` 都会使启动失败；
- `(id, version)` 不可变，相同内容可在重启时幂等发布；
- 价格、额度和功能完全由运营目录提供，二进制不内置默认价格。

`SNAPLINK_BILLING_SOURCE_BINDINGS_FILE` 是可选的 machine-source desired-state
启动文件，格式见 [`source-bindings.example.json`](source-bindings.example.json)。文件同样
使用严格 JSON 和 2 MiB 上限；请求 body、query 和转发头都不能覆盖其中的 tenant、source
或允许维度。应用规则是：

- 新 binding 只能从 `revision: 1` 创建；完全相同的已存记录幂等通过；
- 更新必须保持 `id/client_id/tenant_id/source_system/created_at` 不变，revision 连续加一，
  且 `updated_at` 必须前进；只有 `enabled`、`allowed_dimensions` 和 `updated_at` 可变；
- 一个 client 最多只能有一条 enabled binding；多副本并发写冲突后仅在持久化结果与
  文件完全一致时视为成功，其他漂移、跳版本或冲突都阻止启动。
- 支付 adapter binding 的 `source_system` 必须严格为 `payment:<provider>` 且
  `allowed_dimensions` 必须为空；计量 adapter 才使用非空的允许维度列表。

滚动变更时，先以连续 revision 发布 binding desired state 并让 billing 实例完成启动，
再启动使用该 client_credentials 的 Aero/adapter 调用方。旧 binding 的禁用和新 binding
的启用应放在同一 desired-state 文件中；服务会先执行禁用，避免瞬时双重授权。

## 自动订阅续费

自动续费 worker 默认关闭；设置 `SNAPLINK_BILLING_RENEWALS_ENABLED=true` 或
`--renewals-enabled` 后才会在启动时立即扫描，并按配置周期继续扫描。每个订阅在创建或
显式换套餐时把 interval、价格、币种和宽限期快照到订阅；自动续费不再查询当前目录，
因此后续套餐发布、退役或改价不会悄悄改变既有合同。

创建订阅是受 `admin:write` 保护的合同授予，不是匿名购买或自动首期扣款接口；运营方应
在调用前完成首期结算或显式授予。钱包 worker 在当前周期边界预扣下一周期。配置了未来
`trial_end` 时，该时刻就是首个结算边界；扣款成功后才从试用切换为一个完整的月/年付周期。
换套餐当前不做自动按日折算，需由运营方用明确的 wallet adjustment 处理差额并保留引用。

PostgreSQL worker 通过持久 lease 和 `FOR UPDATE SKIP LOCKED` 支持多副本并发。成功分支把
钱包扣款、`subscription` 账本项、订阅周期、Entitlement 和 outbox 事件放在同一个事务；
相同订阅周期使用确定性幂等键。余额不足不会写扣款账本，而是原子进入 `past_due`、设置
一次性的固定 `grace_until` 和重试时间，并写
`snaplink.billing.subscription.renewal_failed`。重试不会延长宽限期；到期仍未充值时原子
转为 `expired` 并关闭 Entitlement。`cancel_at_period_end` 则在到期时转为 `canceled`，不会
扣款。过期或被其他副本重新领取的 lease generation 不能提交。

默认参数为 scan `1m`、lease `2m`、余额不足重试 `1h`、batch `50`（硬上限 500）。可用
`SNAPLINK_BILLING_RENEWALS_{OWNER,INTERVAL,LEASE,RETRY_DELAY,BATCH_SIZE}` 或对应
`--renewals-*` flag 调整。owner 为空时使用主机名和 PID 派生；显式设置时必须保证每个
进程唯一；启用时 scan interval 必须小于固定 15 分钟 readiness 容忍窗。memory store
保持相同状态语义，但仅供单进程本地开发。period-close/usage
invoice 生成仍不属于该 worker。

`GET /metrics` 暴露无租户/订阅/错误字符串标签的有界 Prometheus 指标，包括 durable
due count、oldest backlog age、最近一次完整成功周期时间和 cycle error。启用 worker 后，
`/readyz` 增加 `subscription_renewals`：单次错误只告警，不立即摘流；只有 oldest due 或
距离最近完整成功周期（含启动等待）超过固定 15 分钟才返回 `error`。被摘流的 worker
不会停止，依然会在依赖恢复后排空 backlog 并自动恢复 readiness。

## Audit Governance relay

设置 `SNAPLINK_BILLING_AUDIT_BASE_URL` 后，会分别启动 commerce outbox 与 usage
outbox 的 durable at-least-once relay。OAuth token source 使用 Basic
client_credentials，只请求 `audit:event:write` 和配置的 Audit resource；令牌按 OAuth
client 配置安全缓存并提前刷新，不会按租户重复请求语义相同的令牌。

该中继是 `billing` profile 中预编译的安全热启用模块。默认在启动时启用；也可设置
`SNAPLINK_BILLING_AUDIT_RUNTIME_FILE`，文件必须是不可被 group/other 写入的普通文件，
内容严格为 `{"revision":1,"enabled":true}`。进程每 5 秒轮询，`SIGHUP` 可触发立即读取：
只接受更大的 revision；相同 revision 的相同内容幂等，相同 revision 异值或回滚会保留当前代际并使
`/readyz` 的 `audit_relay_module` 失败，直到与已应用状态相同或更新的有效状态被应用。配置只控制
预编译 worker 的启停，不加载代码，也不热换 OAuth 凭据、端点或主审计链。

热替换为新代际生成独立的 outbox lease owner。旧代际停止领取新批次，完成已领取批次
后才 quiesce/stop；失败候选不会替换当前代际。禁用中继不会丢弃业务事实，待重新启用后
仍从 durable outbox 继续投递。

上线前必须在 Audit Governance 中完成以下控制面注册：

1. 对每个租户执行 `snaplink-billing audit-source-id --tenant <tenant_id>`，以
   `SNAPLINK_BILLING_AUDIT_SOURCE_PREFIX` 和租户 ID 的 SHA-256 派生唯一、固定长度的
   `source_system`；
2. 在该租户下注册上一步的 source，并在 `allowed_client_ids` 中精确加入
   `SNAPLINK_BILLING_AUDIT_CLIENT_ID`；
3. Audit Governance 只能依据验签后的 `client_id` 和该注册关系授权，绝不能依据事件
   body 中的 `source_system` 或 `tenant_id` 建立授权。

当前 Snaplink client_credentials token 不携带 `tenant_id` claim，因此每个事件的 source
只由可信 outbox tenant 在服务端派生，多租户授权来自 Audit Governance 的
client → tenant-scoped source → tenant 注册映射。相同 relay client 可以服务多个租户，
但同一个派生 source 只能注册到对应租户；不能配置一个跨租户共享 source。401/403 会持久化重试时间并
暂停对应 relay，业务事实仍保留在 PostgreSQL outbox 中；修复凭据或 source 注册后 worker
会继续投递。

## Entitlement 到 SSO 配额投影

设置 `SNAPLINK_BILLING_QUOTA_BASE_URL` 后，Billing 会从独立的 durable quota
outbox 把最新 Entitlement revision 投影到 SSO 的
`PUT /api/v1/internal/tenant-quota/projection`。未激活、已过期或未授权
`core_sso` 的 Entitlement 会发送带四个 `*Limited=true` 的显式 hard-zero，绝不把
商业禁用误解释为 legacy zero-as-unlimited。Audit Governance 投递状态与 quota cursor
相互独立，任一目的端成功都不会消费另一目的端的事实。

该 relay 使用单独的 client_credentials 客户端，只允许精确 scope
`tenant-quota:projection:write` 和配置的唯一 SSO resource。每租户
`source_system` 由 `snaplink-billing-quota` 前缀和租户 ID 的 SHA-256 稳定派生；SSO
仅依据验签后的 `client_id` 加 exact source binding 解析租户，请求 body 没有授权力。
用以下命令生成并预注册每个 source：

```sh
snaplink-billing audit-source-id \
  --prefix snaplink-billing-quota --tenant <tenant_id>
```

base URL 为空时完全不构造 worker；任何孤立 endpoint、credential、resource 或调优
参数都会使启动失败。Base URL 和 token URL 只接受 HTTPS，显式本地开发才允许
loopback HTTP。Secret 仅从环境读取；命令行没有 secret flag。多副本通过独立 owner、
PostgreSQL `SKIP LOCKED` claim 和 lease fencing 并行投递，失败按事件次数做带 jitter 的
指数退避并封顶，worker 自身永不因暂时错误永久退出。取消进程后 worker 停止领取并在
数据库关闭前完成 drain；遗留 claim 在 lease 到期后可安全接管。

`/readyz` 的 `tenant_quota_projection` 检查独立 outbox 最老未完成事实的年龄；超过
`SNAPLINK_BILLING_QUOTA_MAX_LAG` 才降级。HTTP/凭据/receiver binding 的更换属于冷
配置并需滚动重启；只有 SSO 侧预编译 source registry 支持 revision 化 SIGHUP 更新。

## 当前能力边界

- 套餐、订阅、Entitlement、钱包、充值订单、支付事实与对账管理 API 已挂载。
- usage ledger、reservation、Entitlement 查询和治理 outbox 已组合；只通过上述固定的
  认证 machine API 接入，tenant/source/计费周期均由服务端证据决定，未定义的内部方法
  不会被临时暴露。
- 自动续费/余额扣款和可选 quota projection relay 由本二进制提供；Console、支付 provider
  adapter、usage period-close 和 invoice 生成仍是独立部署单元。
