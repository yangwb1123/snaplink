完成。工作已提交（`3fe9e959`，已推送）且工作树干净（仅保留先前会话中无关的 campaign 文件）。

## 总结

**设计**（`docs/design/prototype-minimal-physical-isolation.md`，先编写）裁定：
1. **提取形状** — 双 cmd 根 + 一个共享库（"三包"方案）：`cmd/sso-prototype` 新根，`cmd/sso-minimal` 保留为 minimal，版本通用的组合代码下沉至 `internal/composition`（cmd 包不可被导入，因此共享代码必须位于库中；按第一段规则，`internal/composition` 被分类为 composition 层）。
2. **共享代码** — 下沉，绝不复制：`op_session.go`/`logger.go`/`server.go`/`grant_filter.go` 等版本通用代码按单一事实来源存在于库中，并由 `Edition` 描述符 + 按根注入的选项钩子参数化；每个版本特定的 `surface.go`/`edition.go`/`app.go` 保留在各根中。prototype 根中 OIDC 表面的引用为零——它已从 prototype 二进制中编译掉。
3. **Profile 接线** — `prototype.json` 现在选择 `./cmd/sso-prototype`；两个 `configure --build` 均成功；更新了 checks 和 `.goreleaser.yaml`。
4. **隔离证据** — `profile-isolation.json` 将 `small` 行拆分为 `prototype`/`minimal` 行；`profiles evidence` 证明每个二进制只链接自己的 cmd 根（prototype 为 `cmd/sso-prototype`，0 个 `cmd/sso-minimal`，反之亦然）。诚实的残余：`protocols/oidc` 通过共享 SDK 保留在两个版本中（与现有的 `profile-isolation.md`/`profile_release.py` 契约一致）。
5. **硬边界** — 无运行时行为变化（通过构建的二进制和逐版本的 smoke 测试验证），full/standard 未受影响（所有 6 个 profile 均构建），无维护豁免，目录预算满足（10 个库文件，每个根 4 个）。

**验证已运行**：`configure --profile prototype --build` ✓，`configure --profile minimal --build` ✓，`profiles evidence` ✓（0 个违规），`go build ./... && go vet ./...` ✓，`go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .` ✓，`modules smoke`（所有 6 个 profile）✓，203 个 pytest checks ✓，`-race` 针对受影响包 ✓，docs/route/capability/sdk-surface/config gates ✓。文档已同步（README/DIRECTORY_MAP/deferred-backlog/plugin-system/RELEASE/deployment/feature-matrix/fips/ROADMAP/profile-isolation），CHANGELOG 已新增条目，`dist/`/`bin/` 保持忽略。
