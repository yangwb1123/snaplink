完成。已提交并推送 `d89e682e`（15 files, +705/-16）。此前存在于工作树的无关改动（`docs/architect-analysis/auto/state.jsonl`、`docs/campaigns/campaign-snaplink-b4.yaml` 及批处理工具文件）原样保留，未触碰。

## 设计裁决（写入代码注释）

1. **单注册器**：`ssoext.ExternalSignerRegistry` 是 `keys.signing.external` 的规范注册器（消费契约是单一 name→factory 查表，四个厂商以不同名字注册进去，saml 模板）；`ExternalSignerFactory` 复用现有形状 `func(ctx) (crypto.Signer, string, error)`——crypto.Signer 是 stdlib、`ExternalSignerDeps{Logger spi.Logger}` 只含根模块类型，零外部依赖不变式成立。
2. **serverbuildsign 委托而非双注册表**：`ExternalSignerFactory` 是类型别名、`ExternalSignerRegistry` 别名同一 registrar 指针、`RegisterExternalSigner`/`lookupExternalSigner`/`registeredExternalSigners` 委托到 ssoext。兼容性：存量 fork 调 `serverbuildsign.RegisterExternalSigner` 编译不变、行为逐字节不变（错误文本、panic 纪律、`resolveExternalSigner` 调用形状均未动）；健康/指标包装（`InstrumentSigner`/`SignerHealth`/readyz）保留在 cmd 层。
3. **模块侧适配**：四模块各加 `build.go`（带 `!no_kms_*`/`!no_pkcs11` 构建标签，与 stub 兼容），`Deps` 嵌入 `ssoext.ExternalSignerDeps`，`Build` 镜像各自主构造器（`New(client,keyID)` / `New(client,keyName)` / `NewSigner(client,keyName,keyVersion)` / `New(Config)`），`BuildResult{Signer,KeyID}`；fork main 闭包持有厂商 SDK 客户端。
4. **硬边界**：零豁免、零 skipDirs 变更；ssoext 5 个非测试文件（≤10）；每个新文件 <500 行、函数 ≤50 行；嵌套模块经既有 go.mod+replace 引用 ssoext。

## 验证输出（全部实际运行）

- `go build ./... && go vet ./...` → OK
- `go test ./interfaces/ssoext/... -count=1` → ok
- `go test ./cmd/sso-server/serverbuildsign/... -count=1` → ok
- 四模块 `go test ./... -count=1`（awskms/gcpkms/azurekeyvault/pkcs11）→ 全部 ok（含新增 build_test；stub 构建 `-tags no_kms_*/no_pkcs11` 亦通过）
- `go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .` → ok
- 四模块 `go mod tidy -diff` → 无变更（退出码 0）；`python cli.py modules check` → 全部 OK
- `make ci`（fmt/vet/race/build/examples/modules/config/route-contract/sdk-surface/profiles/adapters 全链）→ 通过至最后一个 target
- ssoext + serverbuildsign `-race -count=1` → ok

## 文档同步（同提交）

- `docs/deferred-backlog.md`：嵌套模块行从 **Partial** 翻转为 **Implemented**，KMS 已迁移、无剩余迁移工作
- `docs/architecture/DIRECTORY_MAP.md`：ssoext 行标注规范外部签名器注册器
- `CHANGELOG.md`：Unreleased → Added 新增条目

仓库当前仅有此前已存在的无关工作树改动（未提交）。
