All checks complete. Here is the validation verdict.

---

# Validation: acceptance mapping T-8a, T-C, E-1..E-6, R-1/R-2

**Verdict: executable as specified, with 3 blocking corrections (B1–B3) and 5 precision gaps (G1–G5).** Every mechanism the mapping relies on exists and compiles; two of the design's own precedents are broken in the current worktree, and one verification command cannot run as written.

## 1. Deployment pattern compiles against current APIs — CONFIRMED (with one composition note)

Every component verified individually; all are library packages importable from `test/` (package `ssotest`):

| Component | Verified at | Status |
|---|---|---|
| Real `sso.NewServer` + `WithIssuer(addr)` + `WithClientStore` + `WithTokenIssuer("jwt", …)` + `WithDefaultTokenStrategy("jwt")` + `WithIDTokenIssuer` | `cmd/sso-ctl/apiclient/check_test.go:71-97` (`newLiveServer`) | Compiles |
| `grpcadmin.NewClientAdminService(clients, rec, nil, nil)` over the **same** `MemoryClientStore` | `test/admin_grpc_base_test.go:84` (bufconn), already used in `test/` | Compiles |
| `runtime.NewServeMux()` + `adminv1.RegisterClientAdminServiceHandlerServer(ctx, gw, svc)` | production precedent `cmd/sso-server/build_http.go:228,426`; gateway paths `/api/v1/admin/clients` (:405) and `/api/v1/admin/clients/{id}` (:445) — E-1's exact `GET /api/v1/admin/clients/client-1` matches | Compiles |
| `sso.NewAdminMiddleware(stubValidator{good,claims}, adminProvider)` + `mw.HTTPMiddleware(gw)` | `test/admin_middleware_test.go:13-38`; `IsProtectedPath` gates `/api/v1/admin/*` (`interfaces/admin/middleware.go:438-450`), passes `/token` through | Compiles |
| E-1 bearer flow: `"good"` → `stubValidator` → `user-alice` + `admin:*` provider → 200 | `TestAdminGRPC_ValidTokenWithScopeReachesHandler` + `TestAdminHTTP_ValidTokenWithScope_200` (pass) | Verified |

**Composition note:** `adminGatewayExactPaths()` lives in `cmd/sso-server` (unimportable from `test/`). E-1 must hardcode the two client paths (or mount the gateway under `/api/v1/admin/`) in its own outer mux + `/` catch-all to `srv.Handler()`. The design's "same package" wording doesn't require `cmd/`, so this is an implementation detail, not a blocker.

## 2. Precedents exist — CONFIRMED

- `decodeJWTPayload` — `test/oidc_test.go:31-43`, exact as cited.
- `captureStdout` — `cmd/sso-ctl/clientscmd/clients_test.go:15-35`; `TestRunList_DecodesGatewayCamelCaseShape` (:45) and `TestRunList_TableFormat` (:100) exist with exactly the fixture shape T-8a extends.
- R-1 pin — `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto` (`admin_clients_test.go:399`), `t.Parallel`, **passes**; `clientToProto` :394-415 and the "intentionally absent from the admin wire protocol" comment at :59-60 match R2/R3 targets.
- `verifyTenantID` — actually at `token.go:227-235` (design said `check.go`; file drift, lines exact). Diagnostics at :233/:235 — `claims: tenant_id absent` / `claims: tenant_id %q != %q` — E-6's claim is byte-exact.
- EmitUnpopulated/camelCase — behavior **confirmed** against the pinned module (`grpc-gateway/v2@v2.28.0/runtime/marshaler_registry.go:20-30`), but the design cites `interfaces/grpcserver/marshaler_registry.go:22-23`, **which does not exist in the repo** (the file is inside the dependency). Evidence-audit drift; the claim itself holds.

## 3. T-C invariant — mechanism confirmed, enforcement lands with the tests

- Mint leg: `token.go:61` `"grant_type": "client_credentials"` (body creds via `probeClient`). Exact.
- `rejectDisallowedGrantType` at `server_token.go:110-116` (design cited :107-111, off by a few), called at `:56` **before every token grant dispatch**; non-empty `GrantTypes` without `client_credentials` → `400 unauthorized_client` (`ErrUnauthorizedClient`). Empty = unrestricted. Confirmed.
- Enforcement is sound but only materializes once E-1/E-5 land: the checker surfaces `mint: status 400 …` on stderr → exit 1 → test fails. Nothing enforces it today (expected — the tests don't exist yet), and no compile-time guard is needed.

## 4. Verification plan vs F1–F7, race-safety — 3 defects

| Mode | Coverage | Status |
|---|---|---|
| F1 | `go build ./...` fails on stale gen | Detector works — **remedy broken, see B2** |
| F2 | extended T-8a pin under `-race` | Covered; clientscmd `-race` suite passes today |
| F3 | `make docs-validate` (exit 0, verified; kin-openapi + route-contract PASS 241/348) + grep | **grep is a false-negative detector, see B3** |
| F4 | T-C mechanism (above) | Covered once tests land |
| F5 | existing pin test | Covered, passes |
| F6 | documented, no test | Consistent with design |
| F7 | T-8a.2 table extension | Covered |

Race-safety: clientscmd line runs `-race` (passes; `captureStdout` is serial, no `t.Parallel`); the `test/` line lacks `-race` but `make ci`'s `race` step covers the whole tree — acceptable; recommend adding it for parity.

## Blocking corrections

**B1 — the real-server sweep precedent is RED (13 failing tests).** `go test ./cmd/sso-ctl/apiclient/ -count=1` fails: `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestMint_ClaimsMatrix/ScopeContainsRequested/AudContainsResource/RolesConditional/ExpectNoRoles`, `TestRevoke_RoundTrip`, plus stub-based rows. Two confirmed classes: (a) `newLiveServer` builds the Ed25519 issuer **without** `WithEd25519Issuer(addr)` → minted `iss: "snaplink-sso"` (`sso.DefaultIssuer`, `shared/core/consts_oauth.go:139`) ≠ discovery issuer → `claims: iss` mismatch; the correct kit shape is `test/oidc_test.go:54-56`; (b) `TestCheck_AddrValidation`'s "stderr echoes raw addr" assertion collides with the substring `8443` in the usage default `http://127.0.0.1:8443`. The design's evidence audit marked `newLiveServer` "Exact" without noting the suite is red — and **E-5/E-6 inherit (a)**: the E-1 given must add `WithEd25519Issuer(addr)` to the JWT issuer, or the sweep fails on `iss` before ever reaching `tenant_id` assertions.

**B2 — `buf generate` cannot run here.** No `buf` binary (only `proto-lint`/`proto-breaking` use `go run`; `proto-gen` uses bare `buf`, as does the design's F1 step — `buf: No such file or directory`). `buf.gen.yaml` declares local plugins `protoc-gen-go`, `protoc-gen-go-grpc`, `protoc-gen-grpc-gateway` — none installed, no install procedure in the repo (CI only lints via `bufbuild/buf-setup-action` 1.69.0, never generates). Worse: committed gen/ was produced by **protoc-gen-go v1.34.1 + protoc-gen-go-grpc v1.5.1** (all 15 files) while go.mod pins protobuf v1.36.11 — installing at go.mod versions rewrites all 15 gen files. Required: `go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.1 google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1 github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.28.0` + buf 1.69.0. F1's detection still works; only the remedy is tool-gated.

**B3 — F3's grep is broken as written.** `grep -A20 '^    AdminClient:'` covers lines 15972–15991 of `docs/openapi.yaml`; the `AdminClient` properties block runs to :16004 (`active`). Fields appended after `active` (the natural edit) land outside the window → `grep -c` returns 0 even after a correct change. Use a wider window or a block-aware awk.

## Precision gaps (non-blocking)

- **G1:** E-1's seed must also carry non-empty `AllowedScopes` (else T-8d skips → `check INCOMPLETE` → exit 1 — a third way E-5 fails) and `Active: true`/jwt strategy; the design's given clause omits both (they're only in the `newLiveServer` citation).
- **G2:** the verification plan omits `go test ./cmd/sso-ctl/apiclient/...` despite R-2 requiring that suite "pass unchanged" — today it fails 13; `make ci`'s race step would catch it, but the plan should make it explicit and the pre-existing failures must be fixed or reported separately (AGENTS.md §5.7).
- **G3:** `go test ./test/ -run 'TestClientTenantBinding'` lacks `-race` (covered via `make ci`; parity recommended).
- **G4:** `marshaler_registry.go` citation is a dependency file, not a repo file (behavior verified anyway).
- **G5:** T-C is a documented invariant enforced only by the future E-tests — the enforcement path is verified sound, but nothing enforces it today.

**Baselines run:** `go build ./... && go vet ./...` OK; clientscmd `-race` OK; grpcadmin pin OK; `test/` admin subset + `TestE2E` OK; `make proto-lint` OK; `make docs-validate` exit 0; apiclient 13 FAIL (pre-existing, in untracked campaign files).
