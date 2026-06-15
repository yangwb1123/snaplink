# BOOTSTRAP.md — 项目引导

## 项目身份
- **名称**: snaplink/sso
- **描述**: OAuth 2.0 + OIDC SSO 服务器 SDK + 可运行二进制
- **外部依赖**: 零外部 SaaS 依赖

## 技术栈
- **语言**: Go 1.26
- **数据库**: SQLite (modernc.org/sqlite, 纯 Go 无 CGO)
- **缓存**: Redis (>1k QPS 多副本)
- **协调**: etcd
- **KMS**: AWS/GCP/Azure KMS + PKCS#11 + Vault Transit
- **遥测**: Prometheus + OpenTelemetry
- **API**: Protobuf + gRPC + REST gateway
- **前端**: 自包含 SPA (embed)

## 核心原则
1. 接口先行 (SPI-first)
2. 零外部 SDK 依赖（嵌套模块独立 go.mod）
3. 防 Oracle-Leak
4. 反枚举（bcrypt 虚拟哈希）
5. 明确的 Fail-Open/Fail-Closed 策略
6. 无 Mock 测试（使用 Memory* 实现）
7. 文件 ≤ 500 行，函数 ≤ 60 行，圈复杂度 ≤ 15

## 关键 ADR
| ID | 决策 | 理由 |
|---|---|---|
| ADR-001 | 核心模块零外部 SDK | 避免供应商锁定 |
| ADR-002 | 存储可插拔 SPI | 测试/生产/热路径灵活切换 |
| ADR-003 | 无 go.work | 保持依赖图纯净 |
| ADR-004 | 六边形 handler 提取 | 防止 sso.go 膨胀 |
| ADR-005 | 无 Mock | Memory* 即测试替身 |
| ADR-006 | Discovery 派生 | 新功能自动发布 |
| ADR-007 | DELETE … RETURNING | 原子单次消费 |
