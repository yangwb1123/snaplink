All verification complete. Here is the assessment.

# 1. Engineering-gate assessment of the design's insertion points

## File budgets (500 lines) — all pass, large headroom

Measured current + projected post-design (no new files anywhere; all edits are in-place):

| File | Current | +Design | Budget | Verdict |
|---|---|---|---|---|
| `gen_ts.go` | 306 | ~309 (+3: `form: true` part) | 500 | ✓ |
| `gen_ts_runtime.go` | 197 | ~218 (+1 `form?: boolean;`, ~20 lines form branch inside the `tsRuntime` const) | 500 | ✓ |
| `gen_py.go` | 361 | ~370 (+1 `form` param, +5 branch in const, +3 in `pyEmitMethod`) | 500 | ✓ |
| `operations.go` | 237 | ~252 (+1 field, ~13 `usesFormBody`, +1 in `extractOne`) | 500 | ✓ |

## Function budgets (50 lines / cyclo 15) — all pass (measured with the gate's own algorithm)

| Function | Now | After | Limits |
|---|---|---|---|
| `tsEmitRequestOpts` | 20 ln / cyclo 6 | 23 ln / cyclo 7 (+1 `if`) | 50/15 ✓ |
| `pyEmitMethod` | 24 ln / cyclo 6 | 27 ln / cyclo 7 | ✓ |
| `extractOne` | 23 ln / cyclo 3 | 24 ln / cyclo 3 (struct-literal assignment, no branch) | ✓ |
| `usesFormBody` (new) | — | ~8 ln / cyclo 3 (4 comma-joined values in one `case` + `default`; identical shape to `tsUsesClientAuth`, measured cyclo 3) | ✓ |

Key structural point: the TS/Python runtime edits land inside Go **const strings** (`tsRuntime`, `pyClientHeader`), so the Go gates measure only the file line count — the embedded TS/Python is invisible to the cyclo/line gates. No exemption lists touched (all empty/capped at zero).

**Nesting 3:** the added Go `if op.FormBody` sits at depth 1; the TS form branch is `if (authenticatedBody !== undefined) { if (opts.form && isRecord(...)) }` = depth 2, matching the existing query-builder branch. Note: the "if nesting 3" budget is an AGENTS.md convention only — HARNESS.md enumerates the committed gates (file size, fn length/cyclo, import rules, layer, dir fanout, dir depth) and none enforce if-nesting.

## interfaces/sso 60-file ceiling — not implicated

Directory currently holds **exactly 60 non-test .go files** (111 test files) — at the frozen ceiling (`dirFileCountExemptions["interfaces/sso"] = 60`; the ratchet fails at 61, and the 12-entry exemption cap is also full). The design touches zero files there; all changes are in `cmd/gensdk` + `docs/sdks/` + `emit_test.go`. ✓

## Architecture-layer classification — no action needed

`cmd/gensdk` → first segment `cmd` → **composition** (rank 6, may import anything). The design creates no new top-level/internal package, no new directory, and no new import (package currently imports only `github.com/yangwb1123/snaplink/docs`, rank 0). No `layerName()` addition, no `layerExemptions` entry, and the `architecture_gate_test.go` rules (oauth↛oidc, oidc↛oauth, shared/core leaf) are untouched. ✓

## Pre-existing gate failures (reporting separately per AGENTS.md §5)

`go test -run 'TestMaintainability_|TestArchitecture_' .` currently FAILS on unrelated, pre-existing drift — the design's step-7 gate run would inherit these, not introduce them:
- `infrastructure/defaultimpl/ed25519_jwt_issuer.go` — 539 lines > 500
- `docs` subdir fanout 18 > 16; `docs/architect-analysis/auto/runs` 260 subdirs > 16; depth-5 dirs
- root `.` subdir count 24 > frozen ceiling 21 (pbatch artifacts)

## Minor citation errors (insertion points still unambiguous)

- `extractOne` cited at operations.go:171-190; it is at **:116-138** (the cited range is inside `splitParams`/`contentSchema`). The substantive instruction — add `FormBody: usesFormBody(id)` after `RequiresAuth:` in the struct literal (:124-130) — is correct.
- `pyEmitMethod` cited :163-178; actual :151-174 (`auth=True` part at :169-171).
- `tsUsesClientAuth` cited :99-109; actual :99-106.
- Exact: `requestOptions` :35-41, `authenticatedBody` :154, JSON branch :157-160, `withClientAuthentication` :183, `Operation` :58-70, `_request` :87-93, body path :102-104.

# 2. Would T-9(a)-(e) actually fail on each failure mode?

| Failure mode | T-9(a) emit tests | T-9(b) regen+check | T-9(c) diff review | T-9(d)/(e) server | Verdict |
|---|---|---|---|---|---|
| **F1 strip ordering** | **Partial** — pins the branch *condition* (`isRecord(authenticatedBody)`) + Content-Type + `delete withoutCredentials.client_secret;`, but nothing pins the *encode input inside the branch*. A buggy `if (opts.form && isRecord(authenticatedBody)) { ...Object.entries(opts.body)... }` passes every listed assertion | No — verified `sdk_surface.py` validates operationId membership + output-file existence only, never content | Yes, but manual | No — hand-built form bodies, never exercises the generated clients | **Needs additional coverage** |
| **F2 missing doseq** | **Yes** — §3.6 asserts the exact `urlencode(body, doseq=True)` string in generated output | No | Manual | No | Covered (static only; `docs/sdks/python/` has no test harness) |
| **F3 `"undefined"` literals** | **No** — neither the §3.6 containment list nor the T-9(a) row pins the `v !== undefined && v !== null` skip; an unconditional `params.append(k, String(v))` passes all assertions | No | Manual only | No | **Not covered — needs coverage** |
| **F5 fixture drift** | **Yes** — the exact-string `{ body, clientAuth: true, form: true });` assertion fails loudly when the fixture lacks `FormBody` (design's claim verified; the fixture is hand-built at emit_test.go:214-232). Predicate truth-table also pins the boundary | No | Manual | No | Covered for Go-side drift; openapi↔predicate media-type drift (F7) remains uncovered, as the design itself documents |

**T-9(d)/(e) catch none of the four client-side failure modes** — they are server-behavior tests (form→200/JSON→400, no-store on 400s) driving the server directly. They only gate sequencing (F8). One wording correction: T-9(e) says "Rejection tests assert `Cache-Control: no-store`" — those assertions **do not exist yet** in `test/oauth_bind_test.go` (zero `Cache-Control`/`no-store` strings there today); the header mechanism at the four handler sites is verified, so T-9(e) describes new assertions to add in the B4-4 phase, not existing ones.

# 3. Gap found: the design misses a committed behavioral test that will break

`docs/sdks/typescript/client.test.mjs` (hand-written, NOT generated) test #2 asserts `assert.deepEqual(JSON.parse(seen.body), { grant_type: "client_credentials" })` on a `postToken` call. After the form flip, `seen.body` is `"grant_type=client_credentials"` → `JSON.parse` throws → **the test fails**. The design's test inventory (§3.6, step 6) covers only `emit_test.go`.

This is also exactly where the missing F1/F3 regression coverage belongs — the repo already has a fetch-capturing behavioral harness:

1. **Required update**: the JSON.parse assertion becomes a form-body assertion (`Content-Type: application/x-www-form-urlencoded`, parse with `URLSearchParams`).
2. **F1 pin (behavioral)**: assert the sent body string contains no `client_id`/`client_secret` when `clientSecret` is configured — this closes the strip-ordering hole the string-containment pins leave open.
3. **F3 pin (behavioral)**: call with a body carrying an `undefined`-valued key and assert no `"undefined"` substring in the sent body.

Caveat: `client.test.mjs` runs only via local `bun test`/`npm test` — verified it is **not** wired into `make ci` or workflows, so it won't block CI; but as the only behavioral test of the generated runtime, updating it is mandatory regardless, and it is the strongest available regression net for F1/F3.

**Bottom line**: budgets/layer/ceiling all clear with headroom (one citation fix: `extractOne` is at :116, not :171-190); T-9(a) covers F2 and F5 but only partially F1 and not at all F3; T-9(d)/(e) cover none of the four (server-side by design). Add: (a) update `client.test.mjs` — it breaks, (b) F1 behavioral pin there (stripped body), (c) F3 behavioral pin there (no `"undefined"` literal), optionally (d) a containment assertion on the skip predicate as a static belt-and-braces.
