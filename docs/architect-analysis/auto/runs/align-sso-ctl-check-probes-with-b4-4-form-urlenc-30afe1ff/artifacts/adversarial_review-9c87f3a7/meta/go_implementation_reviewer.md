Validation complete. Report written to `docs/architect-analysis/auto/runs/align-sso-ctl-check-probes-with-b4-4-form-urlenc-30afe1ff/artifacts/adversarial_review-9c87f3a7/meta/go_net_http_semantics_reviewer.md`.

**Verdict: REVISE** — every claim verified against go1.26.5 stdlib source, the working-tree harness, and three throwaway reproductions (in `/tmp`, removed; working tree untouched).

## Blocking defects (all empirically confirmed)

**1. Recorded-body assertions are mechanically impossible** — `Request.Clone` (request.go:378-412) does `*r2 = *r`: the Body is a shallow copy (doc :381) while Header/URL/Form are deep-copied. `dispatch` (check_test.go:126-135) records a clone sharing the live Body; handlers `io.ReadAll` it and net/http then *closes* it. My repro of this exact shape failed with `http: invalid Read on closed Body` (worse than EOF). The design's `url.ParseQuery`-on-recorded-body assertions cannot work. Required fix (verified working in repro): dispatch reads the body, rewraps the live request (`io.NopCloser(bytes.NewReader(body))`), and stores an independent snapshot per record. Header/CT assertions already work (deep-copied Header).

**2. §2.5's `handleToken` predicate misroutes the T-2 truthiness row** — empirically, the truthiness row sends `CT="" body=""` (sweep.go:158-162 → apiclient.go:114-122). "Every non-form-CT request is a T-8b leg" is false; benign for pass/fail but pollutes the "legs carry JSON bodies" recorded-request assertions. Predicate needs a non-empty-body qualifier.

**3. Custom-/token-handler collision not covered** — enumerated all six `/token` overrides. `TestSweep_3xxTruthinessPasses` (handler :685-700) is the **only exit-0** stub test with its own handler: its mint branch serves 200 to the T-8b legs → `content_type: FAIL` → exit 1 → breaks. The five exit-1 overrides survive with stderr drift.

## Gaps

- **FM-7/FM-8 mechanisms correct, tests missing**: reproduced that `GetBody` is set (307/308 *could* replay the JSON credential body) and `rejectRedirect` observes the 3xx with **zero target hits**; closed-listener errors are deterministic. But no named T-8b-leg 3xx or closed-listener cases exist in §6.
- **No-parallel constraint absent**: zero `t.Parallel()` today; `runCheck` (global `os.Stdout`/`os.Stderr`) and `TestMint_RandReadFailure` (global `rand.Reader`) make it load-bearing; must be pinned. The additions are race-safe under the constraint (`-race` clean; the 11 baseline failures are byte-identical with/without `-race`).

## Sound as designed

runT8b/token_contenttype.go spec (skip/preflight/bare client/JSON legs/canonical re-encode/diagnostic rules/exit wiring) and the golden/stdout determinism — all validated. Also re-measured the M0 baseline (11 pre-existing failures incl. the `iss` mismatch from `newLiveServer` omitting `WithEd25519Issuer`), which blocks the pin's "every other row OK" premise at M1.
