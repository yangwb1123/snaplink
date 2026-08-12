Done. B4-4 的 sibling F1 decoder 已落地并提交（`a1b0f943`）。

## 改动内容

**`protocols/oauth/oauthwire/bind.go`** — 共享表单绑定器的 F1 解码分支：
- `setFormField` 新增 `json.RawMessage` 分支（按 `reflect.TypeOf(json.RawMessage{})` 精确匹配，不误伤普通 `[]byte`）：表单值原样写入（verbatim），先用 `json.Valid` 校验——与 JSON body 解析路径对齐（该路径在 decode 时拒绝非法 JSON）。非法 JSON 现在是绑定错误 → 凭证端点 400 `invalid_request`，不再是静默丢弃。
- 同时覆盖同类的 `authorization_details`（RFC 9396 §3）以及 `/auth/login` 表单路径的 `login.Request.Claims`——`BindParams` 与 `BindParamsFormOnly` 共享 `bindForm`，两个绑定器行为字节一致（oracle-safe 与 415 语义不变）。

**`protocols/oauth/oauthwire/bind_rawmessage_test.go`**（新）— 5 个单元测试钉住新分支：verbatim 绑定（双绑定器）、percent-encoded JSON 往返、非法 JSON 拒绝（`{`/`not-json`/空/`[1,`/`{"a":`）、缺键保持 nil、JSON 字符串值按原文保留。

## 线程化确认
链路已全部接线，无需改动：`POST /par` → `issuePARRequest` 存 `Claims` → `/auth/login` `consumePARRequest` → `mergeStoredPARRequest` 合并 `stored.Claims` → `AuthRequest.RequestedClaims` → 认证器快照。缺的只是 binder 这一环。

## 验证（全绿）
```
go test ./test/ -run 'TestSdkForm' -count=1           → ok（含 TestSdkForm_PARClaimsThreaded，未 skip）
go test ./test/ -run 'TestCredential' -count=1        → ok
go test ./protocols/oauth/... -count=1                → 6 包 ok
go test ./interfaces/sso/ -run 'Claims|PAR' -count=1  → ok
go build ./... && go vet ./...                        → 通过
go test -run 'TestMaintainability_|TestArchitecture_' . → ok
go test ./protocols/oauth/... ./test/ -race -count=1  → 全 ok（含完整 test 包 72s）
```

## 提交边界
按 G5b 只提交 binder 侧：`bind.go`（含前序未提交的双模式绑定器重构）、`bind_strict.go`、`bind_strict_test.go` + 新测试文件；未触碰 `cmd/gensdk/*`、`docs/sdks/*`。文档无需更新——`docs/openapi.yaml` 已将 `claims`/`authorization_details` 声明为 JSON-encoded string，实现现在才与契约一致（原先属于代码落后于文档的 drift）。
