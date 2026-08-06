Design complete. Summary:

## Verification (all evidence claims checked against HEAD `ea351a86`)

Every citation confirmed — `GrantedScopes` rules (scope.go:80-118), the empty-allowlist pass-through (token_client_credentials.go:34-38), the single `/token` seam (server_token.go:121-125, covering all 8 grant branches), the billing `contractRouter`→403 machine map (auth.go:27-58, :159-166), the campaign row (implementation-gate.md:12), the seven sourced scopes across three constants files, login-only scope cap (server_login_gates.go:317), `openid`/`device_sso` bypass constants, and the `anything`/`api:read` regression fixtures.

**Two corrections that shape the design:**
1. **Body-drift hazard**: the allowlist rejection emits `core.ErrorBody(...)` (`{"error":"invalid_scope"}`, no trace_id), but the sso helper `errorBody(ctx,...)` wraps `ErrorBodyWithTrace` — the registry seam must emit `core.ErrorBody` directly or the identical-body/oracle-safety property breaks. Pinned as test A-1b.
2. **Eighth matrix scope**: commerce(4)+metering(2)+`audit:event:write`(1) = 7; the eighth is `admin:*` (interfaces/admin/middleware.go:31) with prefix-match semantics (tokenpolicy/evaluate.go:203, permissions.Matches).

## Design (written to `docs/architect-analysis/auto/runs/b4-2-.../artifacts/design-a77de8a6/task-1-design.md`)

- **API**: new `protocols/oauth/scoperegistry` (generic `Registry` interface + build-once `Memory` with `admin:*` prefix patterns), new `interfaces/scopecontract` (the eight-scope matrix, importable by cmd/test without violating the cmd-import ban or upward-import rules), `sso.WithScopeRegistry` option + `rejectUnregisteredScopes` seam in `dispatchTokenGrant` (with empty-request allowlist guard so the default path can never mint an unregistered scope), config `scope_registry.enabled`/`extra_scopes` (default off = byte-compatible), and `cmd/sso-server` wiring.
- **Budget discipline**: `interfaces/sso` at its 60-file ceiling → no new files (field in `wiringState`, option in `options_misc.go`, seam in `server_token.go`); every file at ~500 lines has a concrete split-first plan (extract `WithTokenUsageRecorder` → options_admin.go; extract `wireSessionTrustDecay` → build_app_trust.go).
- **9 failure modes** (config drift fail-closed, OIDC standard scopes not in matrix, wildcard semantics, pre-wiring authcodes, `extra_scopes` misconfig, race misuse, multi-replica future), **8 ordered migration steps** ending in `make ci`, and **6 acceptance rows** mapping T-8(d) to named tests — including the byte-identical-body proof, eight-scope mint 200s, protocol-trigger bypass, default-path guard, the unchanged-regression anchor, and billing no-403 via the `serveWithClaims` pattern.
