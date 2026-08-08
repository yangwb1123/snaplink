# Audit: acceptance mapping × FM-1..FM-11, red-today pin mechanics, golden-stdout determinism/race

Baseline measured: `cmd/sso-ctl/apiclient` is **uncommitted working-tree state** (the prior T-2 direction's implementation); the B4-4 design doc is the deliverable at HEAD. All line numbers verified against the working tree.

## 1. The "19-row" mapping is actually a 9-row mapping

Measured counts in the deliverable chain: direction acceptance = 5 checks in one string (`cmd-sso-ctl-7e52c2bb.json`); requirements §4 = 5 rows; **design §6 = 9 data rows**. No 19-row table exists anywhere in the chain. I audited the design's 9-row table as the acceptance mapping.

**Row → named test completeness: all 9 rows have named tests.**
| Row | Named tests | Verdict |
|---|---|---|
| T-8a form mint | `TestSweep_FormWireMint` + 7 stay-green | ✓ |
| T-8a revoke/introspect | `TestSweep_FormWireRevoke` | ✓ |
| T-8b wrong-CT | 7 named (`…Row`, `…TraceID`, `…ExtraFieldFails`, `…WrongStatusFails`, `…200NoEcho`, `…Skip`, `…FailsToday`) | ✓ |
| T-8d form | `TestSweep_FormWireT8d` + 4 stay-green | ✓ |
| T-8e | `TestMint_ResponseFail` (:961 row, verified exact) | ✓ |
| T-9 form | `TestSweep_FormWireT9` + 4 stay-green | ✓ |
| Sweep contract | golden + `TestSweep_GreenPath` (:446) + `TestStdoutDeterministic` (:463) + pin | ✓ |
| PostForm API | 3 named | ✓ |
| Regression guards | 5 stay-green | ✓ |

**FM-1..FM-11 enforcement: 7/11 fully named; 4 with gaps.**

| FM | Enforcing test | Status |
|---|---|---|
| FM-1 unhardened→200 | `…Row200NoEcho` (stub) + `…RowFailsToday` (live) | ✓ |
| FM-2 stale binary vs hardened | **No sweep-side test** — enforced cross-direction by strict-mode R8/AC-1/AC-3 + M3 rollout constraint | ⚠ acceptable, must be stated as cross-direction |
| FM-3 trace_id | `…RowTraceID` | ✓ |
| FM-4 extra field | `…RowExtraFieldFails` | ✓ |
| FM-5 wrong status/code | `…RowWrongStatusFails` (401 named) | ✓ |
| FM-6 skip | `…RowSkip` (INCOMPLETE semantics; `TestIntrospect_SkipWhenNotAdvertised` precedent) | ✓ |
| FM-7 redirect pin | **Partial.** Mechanics by construction (shared `rejectRedirect` on the bare client, apiclient.go:111); never-forward pinned only at mint level (`TestSweep_RedirectNotFollowed` :793). **No named T-8b-leg 3xx case** — `WrongStatusFails` names only 401 | ⚠ gap: add 3xx case + target-hit counter |
| FM-8 network error | **No named enforcing test.** `TestSweep_TransportErrorRow` covers only the T-2 discovery row; `TestRedactURL_RedactsUserinfo` pins the printer, not the leg path | ✗ gap (explicitly flagged in brief) |
| FM-9 mint regressions | `TestSweep_FormWireMint` recorded-request assertions | ✓ |
| FM-10 stub misrouting | `TestSweep_FormWireRevoke` + `TestSweep_FormWireT9` pin the wire-agnostic `handleIntrospect` | ✓ |
| FM-11 unsorted/whitespace | Admit direction named (TraceID); **reject direction unnamed** (canonical re-encode enforces it, no case) | ⚠ minor: fold cases into `ExtraFieldFails` |

## 2. Adjudication: `TestSweep_ContentTypeRowFailsToday` pinning

**Mechanism (sound in isolation).** The pin asserts the *observed* state: exit 1 + `content_type: FAIL` + all other rows OK against `newLiveServer`. In M1 the permissive parser (bind.go:43-46 default → JSON) mints for the JSON-bodied legs → deterministic 200 → the test passes while pinning the red sweep. In M2 the same assertions become false → the test goes red until expectations flip. **A test that asserts red cannot flip green by itself** — "flips green … with zero sweep-side edits" (design §5 M2) is true only for production code (`token.go`/`check.go`/`token_contenttype.go`). The flip requires **two check_test.go edits**: (a) `newLiveServer` must gain `sso.WithStrictCredentialContentType()` — strict mode is **config-gated default-off** (strict-mode R1/R3/AC-3), so the fixture must opt in or the pin stays red forever; (b) pin expectations flip to exit 0 + `content_type: OK`.

**Who owns the flip: currently nobody.** The strict-mode direction's requirements (`enforce-…-strict-mode-0a8df02f/requirements.md`) contains **zero mention of the sso-ctl sweep** — R8/AC-1..AC-6 cover only oauthwire unit tests + `test/` integration tests. The flip obligation exists only in this design's prose (D2/M2/§8.5). Cross-module obligation must be filed into the strict-mode direction's acceptance, or declared here as an M2 follow-up with a named owner.

**Blast radius under-declared (material).** M1 turns red not just the pin but the whole live exit-0 cohort — `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestMint_ClaimsMatrix`, `TestMint_ScopeContainsRequested`, `TestMint_AudContainsResource` (live subtest), `TestRevoke_RoundTrip` (6) — **plus `TestSweep_3xxTruthinessPasses`**, whose custom `/token` handler (check_test.go:691-724) mints for T-8b legs (design §2.5's harness rework covers only the *default* `handleToken`). That's 7 red tests; the requirements' §8.6 parenthetical admits "TestSweep_GreenPath red at T-8b only", but the design's §5 M2 claims "TestSweep_GreenPath stays green throughout" — a contradiction. Consequences: the design's **own verification command** (`go test ./cmd/sso-ctl/apiclient/ -run 'TestSweep_|TestMint_|…'`) fails at M1, and `go test ./... -race` + `make ci` fail in the M1→M2 window. M1 is not independently shippable as specified; either document the full red set + flip owner, or land M1/M2 together (consistent with the design's own M3 rollout coupling).

**newLiveServer dependency (material hidden dependency).** The pin's "every other row OK" premise requires the live fixture to pass claims/revoke/T-8d/T-9 — **which it does not at M0** (see §4, F1: `iss` mismatch → `mint: FAIL`). The fixture fix must be in M1's harness scope, and the design's "stay green" list corrected. Secondary dependencies: the strict option's `[PROPOSED]` naming (strict-mode R2); Tracing must stay off in the fixture for byte-determinism (default off ✓).

## 3. stdout determinism and race-safety

- **Determinism ✓ (mechanically).** Group lines are constants; the randomized probe scope and minted `jti`/`iat`/`exp` never reach stdout; green-run stderr asserted empty; `url.Values.Encode()` is sorted/stable; `runCheck` restores streams before reading pipes (correct ordering). `TestStdoutDeterministic`'s two-run byte-equality is sound.
- **Race-safety ✓ (today), with an unstated precondition.** The golden comparisons are pure string equality. The race surface is `runCheck`'s process-global `os.Stdout`/`os.Stderr` swap and `TestMint_RandReadFailure`'s global `rand.Reader` swap: safe **only** while the package has no `t.Parallel()` (verified: none) and `CheckRun` stays synchronous. The design never states the no-parallel constraint for its ~14 new tests; it should. Confirmed empirically: `-race` failures are byte-identical to non-race failures — deterministic, not race-induced.
- **Recorded-body assertions are mechanically impossible as designed.** `dispatch` records `r.Clone(r.Context())`, and Go's `Request.Clone` *shallow-copies the Body* (net/http/request.go: "Clone only makes a shallow copy of the Body field") — the record shares the body with the live handler, which consumes it. The design's `url.ParseQuery`-on-recorded-body assertions require a body-snapshot in `dispatch` (read + rewrap + store copy) that the design omits.

## 4. Baseline reality: the design's "stay green" premise is false at M0

`go test ./cmd/sso-ctl/apiclient/` is **red at the working tree**: 11 tests / 9 subtests, deterministic. Six root causes, all pre-existing (none touched by this design):
1. **Live fixture `iss` mismatch** (6 tests + 1 subtest): `newLiveServer` omits `defaultimpl.WithEd25519Issuer(addr)`; the token issuer defaults to `sso.DefaultIssuer = "snaplink-sso"` (consts_oauth.go:139) while discovery says the httptest URL → `claims: iss … != discovery issuer` → `mint: FAIL`. Production wiring syncs it (`build_signing_issuers.go:43`). Affects `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestMint_ClaimsMatrix`, `TestMint_ScopeContainsRequested`, `TestMint_AudContainsResource`, `TestRevoke_RoundTrip`.
2. `TestCheck_AddrValidation` no-scheme/empty-host: usage banner's default `http://127.0.0.1:8443` contains the case inputs → no-echo assertion trips.
3. `TestSweep_TokenEndpointSuffix`: `strings.HasSuffix(u.Path, "/token")` accepts `/oauth2/token`; the expected diagnostic can't fire.
4. `TestSweep_AdvertisedURLRejection` (4 subtests): `advertiseDoc` concatenates `srv.URL + suffix` for already-absolute URLs → garbage URL; expected diagnostics unreachable.
5. `TestMint_ResponseFail/status-400`: the test never sends 400 (status stays 200 for all non-302 cases).
6. `TestIntrospect_Non401Fails/wrong-bytes`: token.go:368 `%q`-quotes `wantBody` vs the test's unquoted expectation.

Seven of these are in the design's §6 "stay green" lists and all but `TestCheck_*` match the design's verification `-run` pattern — **the design's verification commands fail at M0**, and the pin's M1 "all other rows OK" cannot hold until cause 1 is fixed.

## 5. Other citation checks

All design citations re-verified: mint :59-72, T-8e :96-99, revoke POSTs :244/:259, runT8d :286/:310, runT9 :338/:352/:357, CheckRun :119-122, probeClient :269, golden :32, handleToken :231, all test line numbers — exact or within stated drift. bind.go:28-46 exact. `ErrorBodyWithTrace` omits `trace_id` when empty, and Go's sorted-key marshal emits `error` before `trace_id` — the canonical re-encode check admits exactly `{"error":"invalid_request","trace_id":"x"}\n` ✓. The "AC-2 b2" citation exists **in the strict-mode run's design artifact** (task-1-design.md:196, amended by S-F5), not its requirements artifact — substance confirmed, pointer loose.

## Verdict

- **Acceptance mapping**: all 9 rows named ✓; FM coverage has three genuine gaps — **FM-8 has no enforcing test** (named explicitly in the brief), **FM-7 lacks a T-8b-leg 3xx case**, **FM-11's reject direction is unnamed**; FM-2 is cross-direction by design (acceptable if stated).
- **Pin mechanics**: assert-observed-state is coherent, but the flip is **unowned** (absent from the strict-mode direction's contract), the M1 red blast radius is 7 tests not 1, "stays green throughout" is contradicted by the design's own requirements doc, and the flip needs a fixture option edit — "zero sweep-side edits" holds only for production code.
- **Determinism/race**: golden comparisons deterministic and race-free today; the no-parallel precondition is unstated; the stub's body-recording must be reworked (Clone shares Body) for the FormWire assertions.

Recommendations (ranked): file the flip (fixture option + expectation edit) into the strict-mode direction's acceptance with a named owner; fix the `newLiveServer` issuer and enumerate the M1 red set (7 tests + pin) with a landing plan for M1/M2; add named FM-8 (closed-listener leg) and FM-7 (3xx + zero target hits) cases; fold FM-11 deviation cases into `ExtraFieldFails`; snapshot bodies in `dispatch`; state the no-parallel constraint; fix the 6 M0 failure classes before treating any "stay green" as a contract.
