这份报告的内容已存在于 `/home/dwp/snaplink/docs/expansion-v2-2026-07-01.md` 中，且索引表（`dx-and-build-infra-2026-07-01.md:315`）已将其引用为卷九。

---

## 架构师反馈：补充 5 个跨方向洞察

### 1. 方向①（Passkeys）的隐藏前提：无密码引导流程（Passwordless Onboarding）

报告中提到"Passkeys 注册需要先验证身份"，这是正确的。但还有一个更微妙的问题：**首次使用的用户既没有密码也没有 Passkey——如何引导他们创建第一个 Passkey？**

现有的 `/auth/login` 管道假设用户已有某种凭证。对于纯 Passkey 场景，需要一条独立的**注册引导路径**：

```
访问 /auth/login?client_id=xxx&prompt=create
  → 系统检测该客户端启用了 Passwordless 策略
  → 展示"创建你的 Passkey"（而非密码输入框）
  → 用户通过平台原生 Passkey UI（Touch ID / Windows Hello / 手机）
  → 注册成功 → 自动签发 token
```

这不是 WebAuthn 注册器的工作——注册器假设用户已在认证后。需要的是一个**首次凭据创建流程**，本质上是一种"自注册 + 凭据绑定"的混合路径。这个流程与 JIT 预配（`WithJITMembership`）有天然的集成点——用户首次创建 Passkey 时自动成为组织成员。

**建议**：在方向①的范围内增加 ~100 行描述此引导流程，否则 Passkeys 只能服务于已有帐号的用户。

### 2. 方向②（生命周期）与方向④（设备信任）的交叉：幽灵设备

生命周期管理关注"没有身份的用户"，但同样重要的是**没有用户的设备**——当用户离职后，其设备注册记录仍存在于系统中。方向②的 `disabled → archived` 转换应考虑级联删除/匿名化设备记录：

- `disabled` → 设备信任降级为 `untrusted`，所有受信 cookie 过期
- `archived` → 设备指纹 hash 擦除，设备记录匿名化（仅保留 `{user_id, device_count, last_seen}` 用于审计）

**建议**：方向②的状态转换器中明确加入设备记录的级联逻辑。

### 3. 方向③（事件 Webhook）与 CAEP 的关系：两种不同类型的"事件"

报告中提到"CAEP 可作为系统内建的一个订阅"，这个方向是对的，但要厘清语义差异：

| 维度 | CAEP / SSF | 通用 Webhook |
|------|-----------|-------------|
| 触发者 | 安全事件（凭据吊销、会话终止） | 任何身份事件（user.created, client.updated） |
| 推送到 | 受影响的 RP（RP 的 CAEP receiver endpoint） | 任意配置的 HTTPS 端点 |
| 协议规范 | RFC 8417 SET + 可选反向通道 | 自定义 JSON payload |
| 保证级别 | 必须送达（安全事件） | 尽力投递 |
| 幂等性 | SET jti 天然幂等 | 使用 event.id |

这意味着**通用 Webhook 系统**不应用于替代 CAEP——CAEP 的送达保证、规范格式和 receiver endpoint 认证机制是安全事件的刚性要求。最佳架构是：

```
EventBus（内部）
  ├── AuditRecorder（持久化审计日志）
  ├── EventRouter → Webhook 投递器（通用事件）
  └── CAEP Transmitter（安全事件，专门路径）
```

**建议**：在方向③的设计中明确划界——通用 Webhook 系统不关注安全关键事件，安全事件走 CAEP 独立路径。

### 4. 方向⑤（ReBAC）的落地路径：从 RBAC 到 ReBAC 的桥梁模式

报告中的 MVP 范围合理，但有一个实际的集成问题需要提前设计：**当调用方使用 `PermissionsProvider.Check(user, "document:read")` 时，系统何时选择 RBAC 路径 vs. ReBAC 路径？**

建议使用"两层检查"模式：

```go
func (p *CompositeProvider) Check(ctx, subjectID, permission string) (bool, error) {
    // 第一层：快速 RBAC 检查（O(1) 缓存命中）
    if p.rbac.QuickCheck(subjectID, permission) {
        return true, nil
    }
    // 第二层：ReBAC 回退（慢路径，带缓存）
    // 将 permission "document:read" 解析为关系检查
    // objectType="document", relation="read"
    // 但 ReBAC 需要知道是"哪篇文档"
    // → 调用方必须提供 ObjectRef 上下文
    return p.rebac.Check(ctx, ReBACRequest{
        Subject: subjectID,
        Permission: permission,
        Resource: /* 需要调用方传入 */,
    })
}
```

这里隐藏的问题：现有的 `Check(subjectID, permission)` 签名缺少 `resource` 参数。RBAC 可以这样工作（权限是全局的），但 ReBAC 必须知道"对哪个资源"。这意味着：

- **现有 API 不能直接桥接**——`PermissionsProvider.Check` 的接口需要扩展（或者新增一个 `CheckOnResource(subject, permission, resource)` 方法）
- **RBAC 到 ReBAC 的迁移路径**是：先新增 `CheckResource` 接口，然后逐步将调用方迁移过去

**建议**：在方向⑤的 MVP 阶段就定义好 `CheckResource(ctx, subject, permission, objectType, objectID)` 接口，即使初期 ReBAC 回退返回 `false`。这为未来的无缝迁移提供 API 稳定性。

### 5. 五个方向的依赖图

报告中的阶段建议整体合理，但我看到的依赖图有更细微的边：

```
方向① (Passkeys) ──独立的，无前置依赖──
方向② (Lifecycle) ───依赖── 方向③ (Events)
                         └── 生命周期事件（user.disabled）需要事件系统投递
方向③ (Events) ───依赖── 已有审计事件类型（已有，不需要前置方向）
方向④ (Device)  ───依赖── 方向① (Passkeys)
                         └── Passkeys 的设备绑定是设备信任的自然入口
                            └── 也依赖方向②（用户删除后擦除设备记录）
方向⑤ (ReBAC)   ───依赖── 方向③ (Events)
                         └── 关系元组变更需要事件广播
                            └── 也依赖方向②（用户 suspended 后自动删除其关系元组）
```

**关键发现**：方向③（事件 Webhook）是方向②和方向⑤的**传递依赖**——它本身不依赖其他方向，但其他方向需要它来投递事件。这意味着方向③的实际优先级可能应该提升到 Phase 1 末尾（与方向①并行），而不是 Phase 2 并行。

### 修正后的阶段建议

```
Phase 1a（此刻 → 2 周）：方向① Passkeys 主认证（~600 行）
Phase 1b（与 1a 并行）：方向③ 事件 Webhook 系统设计 + SPI 定义（~400 行核心模型，投递引擎可后置）
Phase 2a（下月）：方向② 身份生命周期（依赖方向③的事件投递能力）
Phase 2b（与 2a 并行）：方向③ 投递引擎 + 管理 API 完成
Phase 3（季度）：方向④ 设备信誉（依赖方向①的 Passkey 设备绑定入口）
Phase 4（待定）：方向⑤ ReBAC（依赖方向③的事件投递 + 方向②的级联清理）
```

这样方向③的等待时间不会阻塞方向②——方向②可以在 Core SPI 定义完成后立即开始，不依赖投递引擎完成。

---

总结：**这份报告的质量非常高**——grep 核验方法严格，ROI 判断务实，与既有路线图的交叉检查全面。以上 5 条反馈是对已扎实的分析做补充，而非修正。若需要我依据其中任一方向编写具体的设计文档或实现计划，请告知。
