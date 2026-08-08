Re-validation complete. The F1 correction is folded into the design doc (`§5` steps 3/4/5/7 rewritten, new `§9` with the precise spec and gates; Go files untouched — only the pre-existing WIP state remains). Summary of what was verified and what changed:

## 1. The `handleIntrospect` change, specified precisely (ships in step 3)

Replaces the JSON-only `bytes.Contains(body, []byte(`"client_id"`))` check at `check_test.go:249-258` with a wire-agnostic discriminator (design §9.1):

```go
func introspectHasClientID(body []byte) bool {
	if vals, err := url.ParseQuery(string(body)); err == nil {
		if _, ok := vals["client_id"]; ok {
			return true
		}
	}
	return bytes.Contains(body, []byte(`"client_id"`))
}
```

Verified empirically over all seven real body shapes (T-9 form/JSON, post-revoke form/JSON incl. JWT values, mint/T-8d form, paranoid `=`-in-JSON): the two checks are **disjoint** — a JSON body never yields a `client_id` key under `ParseQuery` (no `&`/`=` separators → whole JSON collapses to one key), and a form body never contains the quoted substring. The change is a strict superset of today's routing: identical on every JSON wire (so it can be landed first inside step 3 as a green checkpoint), correct on the form wire. `url.ParseQuery` errors are tolerated; partial maps still key correctly.

## 2. Every stub-based test affected (the review's ~10 is actually 12)

**Verdict-flipping without the fix** — the review's 10 plus **two it missed**:
- `TestMint_AudContainsResource/stub-string-form` (:870, exit-0 sweep)
- `TestSweep_RedirectNotFollowed/truthiness-302-not-followed` (:793, exit-0 sweep)

Full list: `TestIntrospect_NoCreds401`, `TestIntrospect_NoAuthHeaderLeak`, `TestInvalidScope_ByteExact`, `TestSweep_3xxTruthinessPasses`, `TestSweep_AdvertisedOnly`, `TestSweep_DecoyFieldNotFetched`, `TestCheck_EnvAddrValidation/valid-env-steers-sweep`, `TestRevoke_StillActiveFails` (exit-1 but its asserted diagnostic only appears when the post-revoke introspect reaches the `postRevoke` override), `TestMint_TenantIDExpectation/present-matches`, `TestMint_RolesExpectationFailsOnCC/stub-with-roles-passes`, + the 2 above.

**Tolerate-class** (verdict unchanged, stderr gains one revoke-leg line): `TestClaimsMatrix_FailureDiagnostics` (8 subtests), `TestInvalidScope_ExtraFieldFails/EnforcementAbsent/WrongCode`, `TestIntrospect_Non401Fails` (3 subtests), `TestMint_TenantIDExpectation/absent-fails`, `TestSweep_3xxContentRowFails` (6 subtests) — all assert exit 1 + a substring that survives the misroute; no edits needed. **Untouched**: misuse/discovery-fail rows, `TestIntrospect_SkipWhenNotAdvertised` (zero introspect requests), `TestMint_ResponseFail`/`TestRevoke_Non200Fails`/`TestDiagnostics_NeverEchoSecrets`/`TestMint_RandReadFailure` (fail before the post-revoke leg), and all live-server tests (real `handleIntrospect` binds via `BindParams` — wire-neutral).

## 3. Corrected order keeps each step's gate green

- **Step 1 (REQ-0)**: green with current golden. One intra-step completeness gap: REQ-0.4's prefix-only-relative fixture restores only 4 of the 5 `TestSweep_AdvertisedURLRejection` subtests — a relative value is *always* prefixed into a valid URL, so the "relative" subtest needs its data/assertion reworked (bypass `advertiseDoc` with a hand-written doc) or it stays red.
- **Step 2 (REQ-1)**: green — `PostForm` is dead code until step 3.
- **Step 3 (flips + F1)**: green with current golden *only if* the discriminator ships in the same step (12 tests break otherwise). Land discriminator → green checkpoint → flips → green.
- **Step 4 (wiring + golden + fixture rework)**: **this is the hidden dependency the fold-in exposed** — I verified empirically that both T-8e legs mint **200** against the current permissive `newLiveServer`, so wiring `runT8e` alone turns every exit-0 sweep red by design: **6 live tests** (GreenPath, StdoutDeterministic, ClaimsMatrix, ScopeContainsRequested, AudContainsResource/live, Revoke_RoundTrip) **and 11 stub tests** (the §9.2 exit-0 set; `TestSweep_3xxTruthinessPasses` additionally needs its *custom* `/token` handler CT-aware since it bypasses the stub's gate). The step must include the enforcing fixtures: a test-side form-only wrapper around `srv.Handler()` (non-form CT + non-empty body on the three credential paths → `400 {"error":"invalid_request"}`; empty bodies pass through so the T-2 nil-body rows survive) and the same gate in the healthy stub's three handlers — which is exactly REQ-8.2's FormOnlyGreen stub. Golden update is atomic with wiring (exactly 5 tests compare `goldenGreenStdout`: :433/:453/:475/:534/:721). Safe sub-order 4a (fixtures, old golden, green) → 4b (wiring+golden+`TestSweep_ContentTypeRowFailsToday`, extended golden, green). All exit-1 tests survive step 4 unedited (verified per test, including the never-echo pins).

## 4. Remaining hidden-ordering audit

- **Golden ↔ wiring**: atomic (5 golden-comparing tests); fixtures alone are safe before, wiring alone breaks everything.
- **REQ-0 internal**: 0.1/0.2/0.5/0.6 are fixture/diagnostic-only with no cross-step coupling; 0.6's `%s` diagnostic is wire-independent (only `TestIntrospect_Non401Fails/wrong-bytes` pins it); 0.3 is the sole production change and is flip-independent.
- **Rollback**: the design's "five sites + wiring + golden" is insufficient — `TestSweep_ContentTypeRowFailsToday` asserts `content_type: FAIL` and *fails* once the wiring is reverted. The rollback unit is steps 3–5 wholesale (flips, discriminator, wiring, golden, fixture reworks, T-8e tests); steps 1–2 stay (REQ-0 is the stabilized baseline — reverting re-breaks the 11-test cohort; `PostForm` is additive dead code). Fixture reworks alone are rollback-neutral (enforcement invisible without the row). No persisted state.
- **Sibling/strict-mode landing mid-migration**: no hazard — same-five-flip merges stay idempotent, and `TestSweep_ContentTypeRowFailsToday` flips green when the strict server lands, regardless of which step we're in.

The baseline (11 top-level + 9 subtest failures, six root causes) was reproduced before the doc edit and is unchanged by it; the working tree has no new Go modifications.
