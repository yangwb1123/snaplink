Requirements specification complete: `docs/architect-analysis/auto/cmd-sso-ctl-apiclient-requirements.md` (doc-only; no `.go` edits, so no build gates triggered).

## Evidence verification — all 8 citations checked

| Citation | Verdict |
|---|---|
| `apiclient.go` (Do, DefaultAddr, 188 lines) | ✅ verified (DefaultAddr:24, New:47, Do:81, ReadBody:134; zero test files) |
| `main.go:45-62` subcommands map | ✅ verified (map at 46-63, 16 entries) |
| `auditverify/main.go:414` live-API pattern | ✅ verified (`--from-url`/`--bearer` at 102-103; readFromURL 403-448) |
| `test/oidc_discovery_test.go:61-88` | ✅ verified (tests at exactly 61/80/88; no 404-sweep test exists) |
| `server_discovery_config.go:139-152` buildBaseMetadata | ✅ verified (at 142; TokenEndpoint=base+PathToken; userinfo/end_session gated) |
| `shared/core/consts.go:21` PathToken="/token" | ✅ verified (exactly line 21) |
| `server_token.go:190-207` rejectUnregisteredScopes | ✅ verified (at 203; plain `{"error":"invalid_scope"}` at scoperegistry/reject.go:37) |
| `implementation-gate.md` T-2 definition | ✅ content verified ("sweep 全绿（广告端点绝不 404）；token_endpoint==/token") |

## Load-bearing findings that shaped the spec

1. **Canonical-method probing is mandatory**: `StdRouter.ServeHTTP` collapses method mismatch to `http.NotFound` (router.go:376-412) — a GET on a mounted POST-only route 404s, so the T-2 sweep must probe each endpoint with its wire method (specified per-endpoint table with verified deterministic statuses).
2. **T-8a claims are wiring-conditional**: `roles` is only emitted on user-token paths (server_login.go:120 etc.), never cc; `tenant_id`/`aud` likewise conditional. The acceptance's claim list became an expectation-flag matrix (REQ-3), keeping it testable without lying about the server.
3. **T-8d needs client auth + restricted client**: the scope seam runs post-auth; empty `AllowedScopes` = unrestricted pass-through (scope.go:94-99) — a 200 probe response is defined as an "enforcement absent" failure. Byte-exact body pinned as `{"error":"invalid_scope"}\n` (ctx.JSON's `json.Encoder.Encode` newline), same bytes from both enforcement layers.
4. **T-9 probe needs a parseable body + bare client**: empty body → 400 before client auth; `apiclient.New` inherits `SSO_ADMIN_TOKEN` (verified) so the probe uses a bare `http.Client` (the auditverify precedent the direction itself cites).
5. **Two corrections to the direction's claims**: `ops/deploy/baremetal-ha/smoke.sh` *does* exist (discovery "issuer" grep + curl cc round trip — but no 404-sweep/claims/invalid_scope/401 probes, so the gap stands); and `cmd/sso-ctl/` is at the 16-directory fan-out ceiling (`maxSubdirsPerDir = 16`), so the subcommand must live inside `apiclient` (the direction's "natural carrier") — a new subpackage would trip `TestArchitecture_DirectorySubdirFanout`.

The spec preserves all supplied acceptance checks (A1–A8 mapping table), each made testable with concrete criteria, plus budgets (§4 — no new subpackage, files ≤500 lines), file plan (§5), verification plan (§6), and non-goals (§7 — typed apiclient helpers and T-8b/c/e explicitly excluded as other directions' scope).
