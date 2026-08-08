Audit complete. Report written to `docs/architect-analysis/auto/runs/form-urlencoded-probe-path-content-type-enforcem-51bdae73/artifacts/adversarial_review-9c87f3a7/meta/req0_baseline_stabilization_audit.md`.

## Verdict: all six REQ-0 fixes + the sweep.go change are pure drift-alignment. No assertion weakening, no hidden root cause, no FAIL-semantics change.

**Critical state finding first:** the working tree is the **unmodified red baseline** — none of the six fixes is applied yet (this is the design stage). I reproduced the baseline: 11 top-level + 9 subtest failures, matching design V5 exactly, all six root causes visible. The audit therefore verified each *claimed* "stricter contract the test already pins" against the actual test and golden files.

**Per-site results (all verified empirically):**

| Fix | Claimed test-pinned contract | Verified | Verdict |
|---|---|---|---|
| 0.1 `WithEd25519Issuer` | `iss == discovery issuer` | `verifyClaims` strict equality; red output `iss "snaplink-sso" != discovery issuer`; prod wiring passes it at build_signing_issuers.go:43 | Fixture→production alignment; assertion untouched |
| 0.2 AddrValidation inputs | never-echo + exit 2 + zero requests | Banner contains `http://127.0.0.1:8443` (exactly 1× each); only `no-scheme`/`empty-host` red; code diagnostics never echo input | Test-data collision fixed; assertion retained |
| 0.3 + sweep.go `checkTokenSuffix` | exact `/token` suffix + pinned diagnostic | Test pins `path suffix "/oauth2/token" != "/token"`; loose `HasSuffix` makes the 404 row fire first; no test pins loose acceptance | Code tightened to test; **only** production change, strictly expands FAIL detection |
| 0.4 `advertiseDoc` | row-2 rejection diagnostics | Observed corrupted `http://127.0.0.1:PORThttp:///token`; relative `/token` became valid → exit 0 | Fixture fix; 4 assertions unchanged |
| 0.5 `TestMint_ResponseFail` | `mint: status 400` | Row writes body at 200 → wrong diagnostic observed | Fixture fix; assertion unchanged |
| 0.6 `runT9` diagnostic | unquoted `expected 401 {"error":"invalid_client"}` | `%q` at token.go:368 vs pinned unquoted text; no test pins the quoted form | Diagnostic-only alignment |

**Golden:** no separate golden file — `goldenGreenStdout` (check_test.go:32), pinned by 5 tests. None of the six fixes touches green-path stdout, so the REQ-0 "green with CURRENT golden" exit criterion is coherent; the `content_type: OK` extension is REQ-7.

**Key arguments:**
- Fixes 1/2/4/5/6 are test-harness or stderr-diagnostic only — they cannot change what the sweep reports as FAIL.
- The only production change (`checkTokenSuffix`) tightens the check: `/oauth2/token` deployments already FAILed via the 404 row, and the fix closes the silent-pass hole for *mounted* non-`/token` endpoints — enforcement, never masking.
- Pre-fix, the live cohort was red-for-the-wrong-reason — itself a masking hazard (fixture drift indistinguishable from server drift). Stabilizing makes the claims gate exercisable.

**Watch-items for implementation:** fix 3 must be exact-match (`/token` or `<base>/token`), not prefix+suffix (which would re-allow `/oauth2/token` under a prefixed base); fix 2's replacements must stay invalid shapes and keep the `user:pass@` row; fix 1 must pass the same `addr` to both `WithIssuer` and `WithEd25519Issuer`.
