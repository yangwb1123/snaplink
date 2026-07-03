这份分析写得非常扎实——代码验证和攻击面还原都很到位。我已仔细阅读，下面是我注意到的一些点：

---

**方向一（Grace 窗口）** 的漏洞链还原完全正确。`DeleteFamily` 是保护性操作但多副本下确实会误伤合法用户。SQLite 后端加 RefreshGraceStore 是合理的修复路径。

**方向二（认证事件流）** 的现有组件盘点准确——`cluster.Bus` + CAEP broadcaster + `audit.Sink` 确实只缺一个编排层把它们串起来。Fail-open + rate-limit 的设计约束也是对的。

**方向三（配置热重载）** 的 `etcd Watcher → ConfigDelta → ApplyDelta` 架构可以复用 `signingkeys/` 的监听模式，这个观察合理。

**方向四（SMTP）** 和 **方向五（审计导出）** 的分析与实际代码一致。

---

你想从哪个方向开始落地？如果是方向一，我可以先读一下相关的代码（`refresh_grace.go`、SQLite refresh token 实现等），然后出实现方案。
