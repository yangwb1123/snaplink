这份第 8 轮分析报告非常详尽，感谢分享。我已经仔细阅读了全部五个方向的内容。

看起来您已经做完了代码级的验证分析，但尚未提出具体的操作请求。我可以帮您做以下几件事，需要您指明方向：

---

## 选项 A：立即实施修复

如果您想落地这些建议，我可以按优先级依次工作。

根据分析报告的排序，**第 1 Sprint** 包含三个可以并行推进的任务：

| 优先级 | 任务 | 预估动作 |
|--------|------|----------|
| **① 注册邮箱验证** → `post /auth/register` 两步骤 | 新增注册端点 + 验证码存储 + 邮箱唯一性延迟确认 |
| **③ TTL 生命周期一致性** → 幽灵 Token 检测 | 新增审计事件 + 可选选项 + `docs/ttl-matrix.md` |
| **④ `server_version` in audit** | 在 `Event` 结构体中加一个字段 + `Recorder.Record` 自动填充 |
| **⑤ 自服务审计事件** | 新增 `password_changed` / `factor_removed` / `webauthn_removed` + handler 中调用 |

方向 **② Device Flow HTML 页面** 工作量中等（需要模板 + 路由 + 内容协商），适合第 2 Sprint。

---

## 选项 B：深入验证特定方向

您可能想在动手前先确认一些细节，比如：

- 验证 `handlePasswordChange` 和 `handleMFAFactorRemove` 的具体位置与实现
- 检查 `EventType` 注册文件中的确缺少哪些类型
- 确认 `ReadBuildInfo()` 在构建时的行为（是否已注入版本）
- 检查 Device Flow 是否有 `Content-Type: text/html` 的分支处理

---

## 选项 C：更新文档/归档本次分析

- 将分析写入 `docs/scan-round8.md` 或其他归档位置
- 创建对应的 GitHub Issues 或 ADR

---

请问您希望从哪个方向开始？
