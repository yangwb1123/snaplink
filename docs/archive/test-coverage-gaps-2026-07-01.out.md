`admin/v1/` 是 protobuf 生成的 `.pb.go` 代码——文档正确将其排除在外。完整清单的 20 个包需过滤掉 generated code、examples、CLI 工具等。

---

## 我的反馈

这份分析质量很高——**数据驱动的测试缺口量化**，精准定位了风险。以下是我基于代码库实际的补充意见：

### ✅ 发现一：你漏了一个——`serverbuildsign/`（641 行, 零测试）

```
cmd/sso-server/serverbuildsign/
├── build_readiness.go      (139 行)
├── build_signing.go        (158 行)
├── build_signing_issuers.go (113 行)
└── external_signer.go      (231 行)
```

这是**签名密钥组装层**——JWKS 签发器、外部 KMS 桥接、readiness probe 的初始化。与 `serverbuildstore/authn/platform` 同属启动路径，且 `external_signer.go` 涉及 KMS（AWS KMS / GCP KMS / Azure Key Vault / PKCS#11）的配置映射，错误会导致签名密钥不可用→生产宕机。

**建议提升到 P2**，与 `serverbuildstore` 同级。

### ✅ 发现二：`grpcadmin` 的真实结构比文档所列更复杂

有 `admin_shared.go`（40 行）存放共享逻辑，共 8 个源文件。你的 1,825 行数字完全准确。

### ✅ 发现三：`test/` 目录的间接测试是"假安全"

以 `memorystoreoauth`（996 行, 零包级测试）为例——虽然 `test/` 有 5 个集成测试文件（~2,147 行总测试），但集成测试通过 HTTP 层驱动，**无法直接测试**：

- **并发竞态**：集成测试的单线程 HTTP 请求无法触发 map 的并发读写
- **nil map panic**：如果 memory store 初始化遗漏，集成测试不会覆盖
- **TTL 边界条件**：1ms 精度的过期测试不能在集成测试中实现
- **`go test -race`**：没有包级单元测试，`-race` 检测无效

这是一个 **P3 但高风险低**的合适定位。

### ⚠️ 值得补充的一个方向：`platform/cluster/`（187 行, 零测试）

```
platform/cluster/
├── bus.go            # 跨副本事件总线 SPI
├── memory_bus.go     # 内存实现
└── etcd_bus.go       # etcd 实现 ← 生产关键
```

`etcd_bus.go` 处理 `Publish/Subscribe` 的 etcd 租约、watch、重连逻辑——任何 bug 意味着跨副本的事件广播（token revoked、signing key rotation）丢失。**建议作为 P2.5 补充。**

### 📊 修正后的优先级总表

| # | 包 | 行数 | 风险 | 文档优先级 | 我的修正 |
|---|----|------|------|-----------|---------|
| **1** | `grpcadmin/` | 1,825 | 极高 | **P1** | ✅ 同意 |
| **2** | `selfservice/` + 子包 | 1,838 | 高 | **P1** | ✅ 同意 |
| **3** | `serverbuild*`（含 sign） | **4,069** | 高→极高 | P2 | ⬆️ **P1.5**（3方向合在一起风险放大器） |
| **4** | `auditspi/` + `auditsink/` | 824 | 中 | P2 | ✅ 同意 |
| **5** | `memorystoreoauth/` | 996 | 中 | P3 | ✅ 同意 |
| **6** | **`serverbuildsign/`** | **641** | 高 | 文档未列出 | **新增 P2** |
| **7** | **`platform/cluster/`** | **187** | 中高 | 文档未列出 | **新增 P2.5** |

最关键的修正：`serverbuild*` 四个子包合计 **4,069 行零测试的启动路径**，比文档估算的 3,491 高出 578 行。如果加上 `serverassets`（65 行）= **4,134 行**——这是启动时执行的第一批代码，零测试意味着配置错误→启动 panic→生产宕机。

---

需要我做什么下一步？比如：

1. 🔍 **深度核实数据**——列出所有 20 个无测试生产包的完整清单
2. 📝 **将这份分析写入 AGENTS.md**——作为测试覆盖的参考基线
3. 🏗️ **规划实施路径**——将 P1 发现分解为具体的测试文件/用例清单
4. 🚫 你说"不写代码"——如果需要，我可以**只生成测试框架文件而不实现逻辑**
