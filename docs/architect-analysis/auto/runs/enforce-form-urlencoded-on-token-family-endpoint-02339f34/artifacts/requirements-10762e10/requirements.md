Spec complete and verified. Final summary:

## Evidence-backed requirements spec produced

**Artifact:** `docs/architect-analysis/cmd-gensdk-tokenfamily-form-spec.md`

### Verification results (all 15 citations checked)

Every cited file/symbol was verified against the tree, with two corrections flagged per the AGENTS.md drift rule:

- **C1:** `gen_ts.go:101` `tsUsesClientAuth` is a client-auth marker (Basic injection + `client_id`/`client_secret` stripping), not the JSON emitter — the JSON emission lives in the shared runtime (`gen_ts_runtime.go` `tsRuntime`, mirrored in `gen_py.go:100-103` and the committed clients at `client.ts:1848-1850` / `client.py:1453-1454`). The spec's REQ-2 fixes the runtime + a per-operation form flag, not that function.
- **C2:** the acceptance's `jwks_uri==/jwks` is factually wrong — `PathJWKS = "/.well-known/jwks.json"` (`shared/core/jwks.go:9`); the truthful assertion is `jwks_uri == base+PathJWKS`.

Also confirmed: `BindParams` JSON default + missing-CT fallback (`bind.go:28-53`, pinned at `bind_extra_test.go:148-150`); form-only openapi declarations for all four ops (`openapi.yaml:1102/1280/1347/1477`); the stale "Form + JSON … `oauth_bind.go`" text at `openapi.yaml:1063-1065` (no such file exists); `localhost:8080` at `:55`; `token_endpoint = base+PathToken` (`server_discovery_config.go:146`); legacy defect tests absent (0 matches); constant-time precedents (`mesh_authz.go:443`, `server_native_sso.go:102`, plus the untouched `CompareClientSecret` seam); the four bind sites (`server_token.go:29`, `handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`) all mapping to `400 invalid_request` with no-store set before binding; and a **34-call-site JSON migration surface across 14 test files** (including device-code polls on `/token`) that the direction did not enumerate.

### Spec contents

- **REQ-1** — form-only `BindFormParams` in `oauthwire` + switch of exactly the four handlers; `BindParams` and all other endpoints untouched (no scope expansion); byte-identical `400 invalid_request` for JSON/missing-CT/other-CT (oracle-safe, no new error code).
- **REQ-2** — gensdk `Operation.FormBody` for exactly the four ops (mirroring the `tsUsesClientAuth` precedent); TS/Python runtime form modes (repeated-key encoding); emit tests + committed `client.ts`/`client.py` regeneration via `python cli.py sdk-surface generate`; openapi description fix.
- **REQ-3** — discovery sweep in `cmd/sso-minimal/edition_test.go` (per-edition: `token_endpoint` suffix `/token`, `jwks_uri` suffix `PathJWKS`, no `/authenticate`, no `:8080`/`:0` port pinning), deploy-tree guard, `openapi.yaml:55` servers-list cleanup.
- **REQ-4** — invert `TestFormEncoded_JSONStillWorks` (test/oauth_bind_test.go:272), migrate the 34 JSON posts, unit + regression tests (no-store on rejections, Basic precedence, introspect caller auth, query-credential rejection).
- **AC-1..AC-4** preserve the supplied T-9/T-2 acceptance checks in testable form; verification commands; explicit out-of-scope list (device/MFA ops, `postRevokeAll`, other B4 items).
