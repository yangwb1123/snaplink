# AI-SDLC 角色模板完整清单

## 📊 概览

我们创建了 **16 个专家角色模板**，覆盖完整的软件开发生命周期（SDLC）。每个角色都有专门的审查重点和输出格式。

## 🎭 角色清单

### 核心决策角色

| 角色 | 文件 | 职责 | 关键输出 |
|------|------|------|----------|
| **CTO** | `cto.md` | 技术战略、ROI、最终决策 | Go/No-Go 决策、资源承诺、风险评估 |
| **Principal Reviewer** | `principal_reviewer.md` | 最终审批、权衡决策 | 批准/拒绝决定、风险矩阵、验收标准 |
| **Product Manager** | `pm.md` | 需求验证、用户故事 | 用户故事、验收标准、MVP 范围 |
| **Tech Lead** | `tech_lead.md` | 任务拆解、实现计划 | 任务清单、依赖图、实施时间表 |

### 架构与设计角色

| 角色 | 文件 | 职责 | 关键输出 |
|------|------|------|----------|
| **Architect** | `architect.md` | 架构设计、技术决策 | ADR、架构图、接口设计、风险评估 |
| **Business Analyst** | `business_analyst.md` | 业务流程、领域建模 | 领域模型、业务流程、数据需求 |
| **UX Designer** | `ux_designer.md` | 用户体验、交互设计 | 用户旅程、可访问性检查、UX 改进 |

### 工程实现角色

| 角色 | 文件 | 职责 | 关键输出 |
|------|------|------|----------|
| **Staff Engineer** | `staff_engineer.md` | 代码质量、可维护性 | 代码质量指标、技术债务清单、重构计划 |
| **Security Engineer** | `security_engineer.md` | 安全审查、威胁建模 | STRIDE 分析、安全发现、修复建议 |
| **Protocol Expert** | `protocol_expert.md` | 协议合规、RFC 检查 | RFC 合规矩阵、互操作性风险 |
| **Database Architect** | `database_architect.md` | 数据库设计、查询优化 | Schema 审查、索引建议、性能分析 |

### 运维与质量角色

| 角色 | 文件 | 职责 | 关键输出 |
|------|------|------|----------|
| **SRE Engineer** | `sre_engineer.md` | 可靠性、可观测性 | 运营检查清单、监控需求、运行手册 |
| **QA Lead** | `qa_lead.md` | 测试策略、质量保证 | 测试覆盖率分析、关键测试场景 |
| **DevOps Engineer** | `devops_engineer.md` | CI/CD、部署自动化 | Pipeline 分析、部署检查清单 |
| **Performance Engineer** | `performance_engineer.md` | 性能优化、容量规划 | 性能预算、瓶颈分析、优化建议 |
| **Distributed Engineer** | `distributed_engineer.md` | 分布式系统、一致性 | 故障场景分析、一致性模型、锁策略 |
| **Compliance Officer** | `compliance_officer.md` | 合规审查、GDPR/SOC2 | 合规矩阵、文档检查清单、审计准备 |

## 🔄 SDLC 阶段映射

### 阶段 0：产品发现
- **Product Manager** - 需求是否值得做？
- **Business Analyst** - 业务流程和领域模型
- **UX Designer** - 用户体验和工作流

### 阶段 1：架构审查
- **Architect** - 整体架构和模块边界
- **CTO** - 技术战略和 ROI

### 阶段 2：安全与协议审查
- **Security Engineer** - 安全审查和威胁建模
- **Protocol Expert** - OAuth2/OIDC/WebAuthn 合规

### 阶段 3：分布式系统审查
- **Distributed Engineer** - 一致性、并发、网络
- **Database Architect** - Schema、索引、迁移

### 阶段 4：实现审查
- **Staff Engineer** - 代码质量、可维护性
- **Tech Lead** - 任务拆解、实现计划

### 阶段 5：性能审查
- **Performance Engineer** - 延迟、吞吐量、内存

### 阶段 6：生产就绪审查
- **SRE Engineer** - 可观测性、部署、回滚
- **DevOps Engineer** - CI/CD、发布流程
- **QA Lead** - 测试策略、回归测试
- **Compliance Officer** - GDPR、SOC2、ISO27001

### 阶段 7：Sprint 规划
- **Product Manager** - 需求优先级
- **Architect** - 技术约束
- **Tech Lead** - 任务拆解

### 阶段 8：Sprint 后审查
- **Staff Engineer** - 代码回顾
- **QA Lead** - 测试回顾
- **SRE Engineer** - 运营回顾

### 阶段 9：CTO 执行审查
- **CTO** - 最终 Go/No-Go
- **Principal Reviewer** - 最终批准和权衡

## 🚀 使用方式

### 1. 单角色审查

```bash
./pi-batch.py -p "@docs/analysis.md 请以安全工程师角色审查这个模块" \
  --model claude-sonnet \
  -o docs/security-review.md
```

### 2. 多角色并行审查

```bash
./pi-batch.py --pipeline pipeline.example.yaml --mode parallel -w 4
```

### 3. 完整 SDLC 审查

创建一个包含所有阶段的 pipeline：

```yaml
# pipeline-full-sdlc.yaml
stages:
  - name: stage-0-discovery
    from_dir: docs/requirements
    mode: serial
  
  - name: stage-1-architecture
    from_outputs: stage-0-discovery
    tasks:
      - prompt_template: prompts/architect.md
        output: docs/results/{input_stem}.arch.md
      - prompt_template: prompts/cto.md
        output: docs/results/{input_stem}.cto.md
    mode: parallel
  
  - name: stage-2-security
    from_outputs: stage-1-architecture
    tasks:
      - prompt_template: prompts/security_engineer.md
        output: docs/results/{input_stem}.security.md
      - prompt_template: prompts/protocol_expert.md
        output: docs/results/{input_stem}.protocol.md
    mode: parallel
  
  # ... 更多阶段
```

## 💡 最佳实践

### 选择合适的角色组合

**小型项目（1-2 周）：**
- Architect
- Security Engineer
- Tech Lead
- QA Lead

**中型项目（1-2 月）：**
- 小型项目角色 +
- SRE Engineer
- Performance Engineer
- Compliance Officer

**大型项目（3+ 月）：**
- 完整 SDLC 所有角色

### 角色审查顺序

1. **先战略后战术**：CTO → Architect → 其他
2. **先安全后性能**：Security → Performance → 其他
3. **先设计后实现**：Architect → Staff Engineer → 其他

### 输出文件组织

```
docs/
├── requirements/          # 阶段 0 输入
├── results/
│   ├── *.arch.md         # 架构审查
│   ├── *.security.md     # 安全审查
│   ├── *.cto.md          # CTO 决策
│   └── ...               # 其他角色输出
└── decisions/            # 最终决策文档
```

## 📋 角色模板结构

每个角色模板都包含：

1. **角色定义** - 你是谁，你的职责
2. **输入上下文** - `{input_content}` 占位符
3. **审查清单** - 系统化的检查项目
4. **输出格式** - 结构化的发现报告
5. **最终总结** - 整体评估和建议
6. **指导原则** - 审查时的注意事项

## 🎯 下一步

1. **创建完整 SDLC Pipeline** - 将所有阶段组织成 pipeline
2. **创建角色组合模板** - 针对不同项目规模的推荐组合
3. **创建审查报告模板** - 整合多个角色输出的汇总报告
4. **创建自动化脚本** - 一键执行完整 SDLC 审查

## 📚 相关文档

- `PI_CLI_AUTOMATION_GUIDE.md` - Pi CLI 自动化指南
- `PI_QUICK_REFERENCE.md` - 快速参考
- `pipeline.example.yaml` - Pipeline 示例
- `prompts/` - 所有角色模板

---

**总计：16 个专家角色，覆盖完整 SDLC，支持任意组合和并行执行。**
