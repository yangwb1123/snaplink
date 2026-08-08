## Verdict: NOT fixed, NOT enumerated — all six M0 root causes reproduce on the working tree, and the design contains zero mention of any of them

Report written to `docs/architect-analysis/auto/runs/align-sso-ctl-check-probes-with-b4-4-form-urlenc-30afe1ff/artifacts/verification-3a1f5b2e/m0-fix-verification.md`. The 330-line design at HEAD is unmodified (diffed against the run artifact), and `go test ./cmd/sso-ctl/apiclient/` fails **11 tests**, each traceable to one of the six causes:

| # | Root cause | Working-tree evidence | Fixed? |
|---|---|---|---|
| 1 | Live-fixture `iss` mismatch | `newLiveServer` (check_test.go:71-92) passes `WithIssuer(addr)` but **not** `defaultimpl.WithEd25519Issuer(addr)`; token `iss` = `sso.DefaultIssuer "snaplink-sso"` (consts_oauth.go:139) ≠ discovery URL. Production wiring does pass it (serverbuildsign/build_signing_issuers.go:43). Red in 6 tests + 1 subtest | **NO** |
| 2 | `TestCheck_AddrValidation` no-echo trip | Test asserts `!Contains(errOut, tc.addr)` for `"8443"`/`"http://"`; exit-2 usage banner embeds default `"http://127.0.0.1:8443"` — both inputs are banner substrings | **NO** |
| 3 | `TestSweep_TokenEndpointSuffix` HasSuffix | sweep.go:192 `HasSuffix(u.Path, "/token")` accepts `/oauth2/token` → 404 row, suffix diagnostic unreachable. Fix lives in sweep.go — which the design's §7 "Do not modify" list freezes | **NO** |
| 4 | `TestSweep_AdvertisedURLRejection` concatenation | `advertiseDoc` (check_test.go:183) does `srv.URL + suffix` unconditionally → `http://127.0.0.1:PORTfile:///x` garbage; 4 subtests fail (relative exits 0) | **NO** |
| 5 | `TestMint_ResponseFail` never-sends-400 | Only `redirect-302` sets non-200; `status-400` row sends its body at 200 → `mint: response has no access_token` | **NO** |
| 6 | `TestIntrospect_Non401Fails` `%q` | token.go:368 `expected 401 %q` → quoted `"{\"error\":...}"` vs test's unquoted expectation | **NO** |

**Re-checks against the corrected baseline:**

- **Stay-green lists** — all §6 line citations are line-exact, but **six listed stay-green tests are in the red cohort** (`GreenPath`, `StdoutDeterministic`, `Mint_ClaimsMatrix`, `Mint_ScopeContainsRequested`, `Mint_AudContainsResource` live subtest, `Revoke_RoundTrip`). They run `newLiveServer` and assert exit 0; at M1 they emit `content_type: FAIL` + `mint: FAIL`. "Follow automatically" (§2.4) and "stays green throughout" (§5 M2) are false. `TestSweep_3xxTruthinessPasses` (check_test.go:678, custom minting `/token` handler) is in **no** list and breaks at M1 — 7 red tests, not 1.
- **Pin premise** — "every other row OK" is false at M0 (mint red on iss) and stays false at M1 as scoped; the fix isn't in any scope.
- **9-row mapping** — confirmed: design §6 has exactly 9 data rows (requirements §4 = 5); no 19-row table exists. All 9 rows have named tests; FM-8/FM-7/FM-11 gaps stand unamended.
- **Design's verification commands** — the §6 `-run` command fails 9 tests on the corrected baseline today; at M1 as scoped it still fails on the six live-server tests, so `make ci` is red in the M1→M2 window.

The claim "fixed and enumerated in M1 scope" holds on neither axis; the report's §6 lists the five amendments (fixture issuer opt-in, AddrValidation reconciliation, sweep.go suffix tightening + lifting the freeze, advertiseDoc prefix-only, 400 row, `%q` fix, plus 3xxTruthiness harness scope and pin-premise/flip-owner statements) required before it can.
