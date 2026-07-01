你的分析非常透彻，与代码库高度吻合。我验证了每一个关键文件，确认以下几点：

**✅ 验证通过的关键事实：**

| 分析声称 | 代码库实测 |
|----------|-----------|
| `cluster.Bus` 接口 15 行核心契约 | ✅ `bus.go` 中 `type Bus interface` 正好 15 行（Publish/Subscribe/Close） |
| 事件种类 7 种 | ✅ 8 种（多了一个 `KindConnectionChange`），你的分析是写分析时的快照 |
| `broadcaster.go` 434 行 | ✅ 精确 434 行 |
| `Broadcaster.deliver` goroutine 模式 | ✅ 每接收者一个 `go t.deliver` + `recover()` + 10s 超时 |
| `ClusterBusConfig` backend 模式 | ✅ `"memory"` / `"etcd"` / `""` 三选一，MQTT 可加为第四种 |
| 内存 Bus 约 110 行 | ✅ 精确 111 行 |
| 架构层约束 `etcd/*` 在 `platform/cluster/` 下 | ✅ MQTT 放在 `platform/cluster/mqtt/` 完全合规 |

**尚未实现的组件：**
- `platform/cluster/mqtt/` — 不存在
- `domains/authzwasm/` — 不存在
- `domains/authenticators/wasm/` — 不存在
- `go.mod` 中无 `paho.golang` 或 `wazero` 依赖

---

## 核心建议：从 P1 的 MQTT Bus 开始实现

你的分析准确地指出 MQTT Bus 是**最短路径（1 Sprint）**— `cluster.Bus` 接口已完美抽象，实现的复杂度与 `memory/` 或 `etcd/` 同级。

### MQTT vs etcd 实现差异

| 关注点 | etcd 实现 | MQTT 实现会有的差异 |
|--------|-----------|-------------------|
| 消息发送 | `Put` 到唯一 key + 短租约 | `Publish` 到 topic |
| 消息接收 | `Watch(prefix)` | `Subscribe(topic filter)` |
| 连接管理 | `clientv3.New()` | `paho.NewClient()` + `Connect()` |
| 断开恢复 | 内置 watch 重连 | MQTT `AutoReconnect` + `CleanSession=false` |
| 部署依赖 | etcd 集群 | Mosquitto (apt/yum/docker) |

### 架构一致性检查

`platform/cluster/mqtt/bus.go` 放在 `platform/cluster/mqtt/` 目录下：
- 符合层级架构（`platform/` 层，`cluster/` 子域）
- 目录深度 = 3 ✅（`platform/cluster/mqtt/bus.go`）
- 不引入 CGO（paho.golang 纯 Go）✅
- 不改变任何现有事件消费代码 ✅
- Config 扩展可放在现有 `config/config_keys.go` 的 `ClusterBusConfig` 结构体中 ✅

---

要不要我开始实现 `platform/cluster/mqtt/bus.go`？以及同时更新 `ClusterBusConfig` 配置结构和 `BuildInvalidationBus` 工厂函数——全部在你分析的框架内，约 200 行 Go 代码，零修改现有 `cluster.Bus` 消费者。
