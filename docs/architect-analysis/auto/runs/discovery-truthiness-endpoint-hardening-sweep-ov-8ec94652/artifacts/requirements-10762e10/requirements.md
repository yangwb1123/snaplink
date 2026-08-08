The requirements specification is complete at:
`docs/architect-analysis/auto/runs/cmd-sso-ctl-auditverify-discovery-truthiness-and-endpoint-hardening-sweep-e0e1fbf0/artifacts/requirements-10762e10/requirements.md`

## Verification summary — every cited symbol checked

| Citation | Verdict |
|---|---|
| `auditverify/main.go` `fetchEventPage` hardcodes `/api/v1/audit/events` + Bearer; `--bearer` required (exit 2) | **Exact** |
| `options_security.go:473-481` `WithAuditAPI` "unauthenticated by default" | **Exact**; confirmed the SDK `srv.Handler()` installs no auth — `cmd/sso-server` gates only when `admin.enabled` (`build_app.go:292`, `build_http.go:85-97` logs "served UNAUTHENTICATED" otherwise) |
| `rootcov_misc_test.go:222` existing route test | **Exact line**; it pins only the explicitly-middleware-wrapped gated posture, status-only 401 — no byte identity, no CLI trust path |
| `rootcov_discovery_test.go` truthiness tests | **Verified**; zero 404-sweep probes in both discovery test files |
| `implementation-gate.md` B4-3/B4-4 rows (T-2, T-8(b)(c)(e), T-9) | **Verified** |
| `TestOIDCDiscovery*` absent | **Verified** — zero matches; `8080:0` appears only in an unrelated scaffold test |
| B4-4 enforcement "no regression lock" | **Verified** — zero `.go` hits for every seam name; `test/handle_token_test.go` still live-tests JSON `/token` → 200 |
| Constant-time compare | **Verified existing** (`CompareClientSecret`/`ConstantTimeStringEq`) with unit tests only, no `/token`-level pin |

## Drift findings that shape the requirements (all evidence-backed)

1. **D1:** `authenticateHTTP` returns `missing_token` vs `invalid_token` for missing vs wrong bearer — the acceptance's "byte-identical 401 invalid_token" requires converging the shared admin middleware (only production change demanded; no test pins `missing_token` on admin-gated surfaces).
2. **D2:** the B4-4 strict Content-Type flip is design-gate **PASS** (`enforce-form-urlencoded-credential-strict-mode-0a8df02f`) but unimplemented; REQ-4 lands its `/token` slice with the `{"error":"invalid_request"}` golden + no-store, and migrates the JSON-acceptance legs at `handle_token_test.go:59,87`.
3. **D3:** sibling designs disagree on seam names/defaults (`WithStrictCredentialContentType` vs `WithCredentialFormOnly`) — spec anchors on the gate-passed run and writes tests relative to the option so they stay green under either default.
4. **D5:** in-process `Run` can't carry load errors (`errorf` → `os.Exit`), so the wrong-bearer leg is pinned at `readFromURL` level and the success leg through `Run`.

The five REQs map 1:1 to the four supplied acceptance checks (REQ-1→T-2 sweep incl. gate-off 404 negative control + path-equality pin; REQ-2→byte-identical 401; REQ-3→real-gated-server `--from-url` e2e with `WithHashChain` recorder; REQ-4→`/token` JSON rejection; REQ-5→constant-time seam pin), each with Given/When/Then assertions, exact test placement, and the `make ci` gate list.
