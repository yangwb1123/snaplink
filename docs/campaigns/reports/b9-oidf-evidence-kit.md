全部完成。以下为执行与核验报告。

## 交付内容

**Commit `e390810c`** — `docs(conformance): package the OIDF certification-readiness evidence kit`（2 files, +229/−134，含 AI co-author trailer，post-commit hook 已同步 origin/main）

### 1. docs/sso/oidc-conformance.md 重构为认证就绪证据包（314 行）

- **§1 认证状态**：保留 "Implemented ≠ certified" 边界；无 OIDF listing、无官方结果；本地证据不可作官方认证声明。
- **§2 证据表**：4 次运行（日期/commit/拓扑/统计/归档路径/复现命令），全部统计**重新从归档 log.json 读取**：
  | 运行 | 日期(UTC) | commit | 拓扑 | 结果 |
  |---|---|---|---|---|
  | HTTP 基线(初始) | 2026-07-31 | 34ea1d3d | HTTP | 59+1 FAILURE, 2 WARNING |
  | HTTP 基线(gRPC 修复后) | 2026-08-15 | af3bc485 | HTTP | 59+1 FAILURE, 3 WARNING |
  | HTTP 同 commit 复跑 | 2026-08-15 | 7400ba0c | HTTP | 59+1 FAILURE, 3 WARNING |
  | HTTPS 里程碑 | 2026-08-15 | 7400ba0c | HTTPS 自签代理 | **60+0 FAILURE**, 3 WARNING |

  （34ea1d3d 只有 2 个 WARNING——仅 `ext` claim；后三次为 `ext`+`scope`+通用说明，已如实写明，纠正了旧文 "same three WARNINGs" 的含糊表述。）
- **§3 复现手册**：逐条对照 run-headless.sh 实际代码——`docker compose --env-file config.env run --rm --no-deps sso-server --validate-only -grpc-listen "" --config /etc/sso/conformance.yaml` → `./run-headless.sh [--issuer-https]`（含 `--module/--timeout/--issuer-https` 用法与默认值 450/归档用 900）→ 归档校验（ls + commit.txt + Python 计数）。
- **§4 模块覆盖矩阵**：README allowlist ↔ 实际 plan 覆盖。`basic`/`config`/`dynamic` ✅ 已覆盖（discovery+dynamic_client 变体，38 个 plan 模块，oidcc-server 已执行）；`formpost`/`session`/`logout` ⚠️ 未跑（需各自 plan+run）；`jarm`/`fapi`/`ciba` ❌ 需特殊接线；implicit/hybrid ❌ 运行期拒绝。
- **§5 剩余阻塞清单**：① 外部可达 HTTPS 发行者官方运行（需部署）② OIDF 账户 + listing 提交流程 ③ 自签证书限制说明 ④ 归档上传策略。
- 能力清单、响应类型边界、加密边界、引用等有效内容保留；无 harness/allowlist 改动，无新增认证声明。

### 2. ROADMAP P0 #2 状态更新（仅该段）

标题改为 `PARTIAL (headless + local HTTP/HTTPS topologies landed; external official run + OIDF listing + archive upload strategy remain)`；正文加入 HTTP 基线三连 59+1、HTTPS 60+0（`results/7400ba0c-https/`）、证据包链接与"剩余 = 外部官方运行 + OIDF listing + 归档上传策略"；其他段零改动。

## 证据真实性核验（实际执行）

| 核验项 | 命令 | 结果 |
|---|---|---|
| 归档完整性 | `ls` 各归档 + `cat commit.txt` | 4 个归档均含 plan.json/oidcc-server.log.json/oidcc-server.info.json/config.yaml/commit.txt/worktree.txt；commit.txt 与目录名全部 MATCH（34ea1d3d5a5d…/af3bc485bec…/7400ba0c724…） |
| config 校验 | `docker compose --env-file config.env run --rm --no-deps sso-server --validate-only -grpc-listen "" --config /etc/sso/conformance.yaml` | `{"msg":"config valid","build_profile":"standard","required_capabilities":null}` EXIT=0（与 run-headless.sh 内部命令一致） |
| 无生产代码变更 | `git status --porcelain` + `git diff --stat` | 本次 commit 仅 2 个文档文件；工作区其余改动（cmd/sso-ctl audit DSN 等）为既有 in-flight 任务遗留，未触碰、未提交 |
| 构建 | `go build ./... && go vet ./...` | BUILD+VET OK |
| 维护性/架构 | `go test -run 'TestMaintainability_|TestArchitecture_' .` | ok |
| docs 文件大小 | `python cli.py check` | PASS: filesize |
| config.yaml 一致性 | md5sum 4 归档 | 全部 `932b860b…`（pinned 配置） |
| 套件版本 | info.json `version` | 全部 5.2.1（image pinned release-v5.2.1） |

## 边界遵守

未改 harness 行为、未改 allowlist、未新增认证声明；commit 前清理了 14:39 遗留的 0 字节 `.git/index.lock`（无存活 git 进程持有，属标准恢复操作，未动 git config/未 force-push）。

## 前置/遗留说明

- 工作区中的 `cmd/sso-ctl/audit*`、`cmd/auditstore/`、`infrastructure/postgres/audit_readonly.go` 等未提交改动属于另一在途任务（b9 sso-ctl audit DSN），按 AGENTS.md "Preserve unrelated worktree changes" 保留原样。
- 阻塞项本身（外部 HTTPS 部署、OIDF listing、归档上传）不在本任务可执行范围，已如实写入证据包 §5 与 ROADMAP。
