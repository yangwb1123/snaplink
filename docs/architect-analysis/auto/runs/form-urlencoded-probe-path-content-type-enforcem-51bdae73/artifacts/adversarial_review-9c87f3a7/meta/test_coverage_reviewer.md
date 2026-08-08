Report written to `docs/architect-analysis/auto/runs/form-urlencoded-probe-path-content-type-enforcem-51bdae73/artifacts/adversarial_review-9c87f3a7/meta/acceptance_mapping_reviewer.md`. Summary:

## The four asked items — verdict

**8-case T-8e matrix + skip:** All 9 rows are specified, but three are under-specified: the matrix/skip tests are **unnamed** (requirements' own `-run '…|TestContentType'` regex implies `TestContentType_Matrix` / `TestContentType_SkipWhenNotAdvertised`); the 200-no-echo row doesn't state the literal-token-absent assertion (precedent: `TestInvalidScope_EnforcementAbsent`'s `eyJ` check at check_test.go:1112); the non-JSON row collapses three distinct branches (HTML page, `{"error":42}` — unmarshal fails, `{}`/`{"error":""}` — empty-error check).

**Five flip byte pins:** All five have explicit tests that stay green on the form wire (pins are response-side): `TestInvalidScope_ByteExact` :1084 + rows 19/21, `TestIntrospect_NoCreds401` :1149 + `Non401Fails` :1183 + `NoAuthHeaderLeak` :1162, `TestRevoke_RoundTrip` :1039 + `StillActiveFails` :1067. The real gap is **form-shape**: design §6's table omits the T-8(d)/T-9 form-shape assertions (REQ-8 covers all five), and mint's shape needs multi-`resource` repeated keys + scope-absent/`scope=read+write` variants. Also: the `handleIntrospect` wire-agnostic fix (REQ-8) must ship **with** the flips, not step 5 (F1) — the form body `client_id=demo&…` misses the JSON-only substring check at :251 and misroutes, breaking ≥10 stub tests.

**Golden extension order:** Explicit by construction — the :32 constant is byte-compared at 5 sites (:433, :453, :475, :534, :721); the single constant pins both the old golden (step 1) and the extended one (step 4). No new test needed.

**REQ-0 gate:** Executable form is `TestSweep_GreenPath` + `TestStdoutDeterministic` (exit 0 + golden + silent stderr) — exactly the tests red today. The "before any transport change" sequencing is process, not a test; the enforceable rule is *don't touch the golden constant through steps 1–3*.

## PostForm untested branches

- **Header set** (form CT, Accept, no JSON CT) — covered by `TestPostForm_FormEncoding`. OK.
- **Key-sort determinism** — **GAP**: "body bytes equal `values.Encode()`" is order-blind; nothing pins the sorted wire bytes the design claims (§3). Verified empirically: insertion-order-independent, `client_id < client_secret < grant_type`.
- **Bearer guard false path** — **GAP**: REQ-8.1 names only the preserved case; add the no-token → no-Authorization branch (mirror `TestDo_BearerHeader`).
- **No-redirect pin** — transitively covered after the flips by `TestSweep_RedirectNotFollowed/mint-307`; recommend one direct 307 subtest on PostForm (cheap, pins the body-forwarding vector at method level). NewRequest-error and nil-values branches: accepted (parity with `Do`).

## 429/415 decisions — both PASS

- **415 + JSON envelope → pass** (already pinned in REQ-8.4): 415 *is* an enforcement signal; a carve-out would false-fail legitimately enforcing deployments. 415 without envelope fails via the non-JSON path.
- **429 + JSON envelope → pass** (currently implicit): keep the class rule — excluding 429 would false-fail enforcing servers behind rate limiters, and a false-PASS is structurally impossible (the same per-grant limiter 429s mint/T-8d → sweep already red). Add one §4 table line + one matrix sub-case.

## Checklist

14 items in landing order, top three: **(1)** move the `handleIntrospect` fix into migration step 3 (F1); **(2)** fix design §3's `%20` → `+` (verified `scope=read+write`); **(3)** extend `TestPostForm_FormEncoding` with sorted-wire-bytes, no-token, and 307 sub-cases — then G5–G12 (test names, explicit no-echo/mixed-legs/red-today-stdout assertions, FormOnlyGreen stub CT-first routing incl. the T-2 nil-body no-CT 400 interplay, 415/429 table rows) and the F2/F3 doc nits.

No changes were made to production code — this is a pre-implementation audit; the tree remains the unmodified red baseline.
