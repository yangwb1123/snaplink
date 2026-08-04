# Principal Review — `interfaces-adapters-direction2-design.md`

Synthesis of four reviews (security engineer, protocol expert, QA lead, staff
engineer) plus independent re-verification of every load-bearing claim against
the working tree, the six committed root gates, and the pinned framework
sources (gin v1.12.0, echo v4.15.2). Design-stage artifact; no code changed by
any reviewer (`git log` head `9cdc22c2` "Stage: design").

## Checks that actually ran for this review

`go build ./...`, `go vet ./...`,
`go test -run 'TestMaintainability_|TestArchitecture_' .` (green at baseline);
source reads of `architecture_gate_test.go`, `maintainability_budget_test.go`,
`directory_fanout_test.go`, `maxdepth_test.go`, `architecture_layer_test.go`,
`engineering.yaml`, `checks/{config,filesize}.py`, `shared/core/router.go`
(440 lines, incl. `gatedRegistrar` :343–350, `GateHandler` :311, `GatedRouter`
:386), both adapters (gin 160 / echo 140 lines; request-time middleware reads
at `wrapHandler`), `server_routes.go` mount order, module-cache sources for
gin (`gin.go` `default404Body` :33, `New()` defaults :197–213, `serveError`
:764–772) and echo (`echo.go` package-level `NotFoundHandler`/`MethodNotAllowedHandler`
:352/:358, `DefaultHTTPErrorHandler` :426–470, `response.go` unguarded `Write`
:71–82, `router.go` dispatch :630–755, `RouteNotFound` :544); `wc -l` and
Python line-count emulation of both size gates. No suite run (nothing changed).

## 1. Advisory recommendation

**Conditionally ready** — the direction, the three-decision structure, and the
byte-equality suite concept are sound and independently verified as a security
strengthening for SDK embedders (nosniff + newline normalization, echo JSON
404 removal, gate-indistinguishability extended to gin/echo, race fix). But
the design **as written cannot land a single step green**: four verified
defects — two committed-gate violations (C1, C2), one compile-level error
(H1), one incomplete pin (H2). All four have small, localized fixes that do
not change the design's shape. Confidence in the findings: **High** — every
one was re-verified directly against source or gate code in this review, and
the three reviewers' independent empirical reproductions (301 redirect,
echo byte classes, `Abort()` chain semantics) are mutually consistent and
consistent with source.

## 2. Consolidated findings

### Critical

**C1 — `aliases.go` is at exactly 500 lines; Decision 3a's one-line alias fails the committed file-size gate.**
[Security F1 + Protocol M1 + Staff F5 — three independent; dedup to one]
*Evidence (Verified):* `wc -l interfaces/sso/aliases.go` = 500, file ends in
`\n`, so `countFileLines` (`maintainability_budget_test.go:117`) counts 500.
`TestMaintainability_FileSizeBudget` fails any non-test `.go` file > 500 and
`fileSizeExemptions` is empty with a frozen zero cap (:140). `checks/filesize.py`
(`MAX_LINES=500`, `filesize.exemptions` empty; `engineering.yaml` `root_policy.exempt_files`
listing `aliases.go` is a **root-policy** exemption and does not touch the
size gate — verified in `checks/config.py:60-68`). +1 line → 501 → both gates
FAIL. The repo already documents this pressure ("to keep that file within the
per-file line budget" in `server_routes.go:25`, `origin_validation.go:25`,
`server_routes_admin.go:7`). The design's "budget headroom verified, no
exemptions" claim is false for the one file it proposes to touch — exactly its
own risk item 10.
*Fix:* place `type GatedRegistrar = core.GatedRegistrar` in an existing
`interfaces/sso` file with headroom (`origin_validation.go` 236, `server_userinfo.go` 157,
`quota.go` 177), or remove one line from `aliases.go`. 60-file ceiling
untouched either way (verified: exactly 60 non-test files).
*Validation:* `go test -run 'TestMaintainability_FileSizeBudget' .` and
`python cli.py check-filesize`.

**C2 — `routertest` under `shared/core/` violates the committed import-boundary gate (rule 3).**
[Staff F1 — only one reviewer found this; verified here]
*Evidence (Verified):* `architecture_gate_test.go` rule 3 (`fromDir: "shared/core/"`,
`forbidden: "github.com/yangwb1123/snaplink/"`, `exempt` nil) forbids any
non-test file under `shared/core/` from importing any Snaplink package. The
design's `shared/core/routertest/conformance.go` imports `core.Router` →
`TestArchitecture_ImportBoundaries` fails on step 1. Precedent confirms the
constraint: `corecredential` (the existing subpackage) imports no Snaplink
package; `permissionstest` lives under `domains/permissions/`. The design
fixed the spec's import-cycle error (hookup moved out of `package core`'s
`router_test.go` — verified correct) but the non-test suite file still trips
the gate; the spec's own justification (spec line 42) covers `shared/core`
importing nothing, not files *under* it importing `core`.
*Fix:* relocate the suite to `interfaces/adapters/routertest/` (rank
`interfaces` via `layerName()` first-segment rule, imports `core` downward —
layer-legal; depth 3; `interfaces/adapters` 2→3 subdirs, 3→5 files; all under
budget, no exemptions) or `shared/routertest/`.
*Validation:* `go test -run TestArchitecture_ImportBoundaries .` with the
relocated package; `importRules` untouched.

### High

**H1 — Decision 2's echo wiring does not compile; the only normalization mechanism is invalid.**
[Staff F2 + QA F-1 — two independent; dedup]
*Evidence (Verified):* `e.NotFoundHandler = ...` / `e.MethodNotAllowedHandler =
...` — in echo v4.15.2 these are **package-level vars** (`echo.go:352,358`),
not `Echo` struct fields; `type Echo struct` has no such fields. Compile
failure. Mutating the package vars would also be globally visible — breaking
the per-router opt-out model and cross-router isolation. The spec prescribes
the same broken API (spec line 97) — spec drift the design inherited.
*Fix (verified working by two independent empirical harnesses):*
`e.RouteNotFound("/*", notFound)` — the per-node `notFoundHandler` wins over
the 405/OPTIONS branches (`router.go:745-755`), giving byte-identical
`"404 page not found\n"` + nosniff for all five unmatched classes. Document
two caveats: install before the engine serves its first request (late
registration panics on pooled contexts), and a later embedder
`RouteNotFound`/`Group.Use` overwrites (same later-wins precedence the design
already documents for gin `NoRoute`).
*Validation:* `go vet ./interfaces/adapters/echo/...`; suite scenarios 3–7 on
echo.

**H2 — gin trailing-slash 301 defeats scenario 7 after Decision 2; the pin is incomplete.**
[Protocol H1 + Staff F3 + QA F-2 — three independent; dedup]
*Evidence (Verified):* gin `New()` sets `RedirectTrailingSlash: true`
(`gin.go:197-213`); `handleHTTPRequest` redirects before the NoRoute path.
`GET /known/` → **301** `Location: /known`, not a 404 of any byte shape. The
design's baseline cell ("red: gin/echo byte level") and its step-2 promise
("scenarios 3–7 turn green on all backends") are both false for gin; scenario
7 stays red after step 2. Protocol impact: OAuth client libraries that follow
redirects could silently replay a wrong-path token request at the canonical
path — interop-visible divergence from StdRouter's 404.
*Fix:* pin `engine.RedirectTrailingSlash = false` (and confirm
`RedirectFixedPath` stays false, the default) in the gin constructor beside
`HandleMethodNotAllowed = false`; correct the baseline cell to "red: gin
(301)"; note in release notes that embedders relying on gin TSR redirects use
`WithFrameworkNotFound`.
*Validation:* scenario 7 on gin after the pin; adapter test asserting
`/known/` → 404 bytes, not 301.

### Medium

**M1 — Baseline-record cells are factually wrong in four places; step 1's proof is corrupted.**
[QA F-3 + Staff F6 + Protocol L1/L2]
*Evidence (Verified):* (a) echo OPTIONS on a known path → **204 + `Allow`**
via `optionsMethodHandler` (`router.go:753-754`), not "405 JSON" — the
design's scenario 6 baseline and its delivery-order statement ("scenarios
3/4/6 red on echo") are wrong; (b) echo HEAD on a GET-only route → **405 with
empty body** (`DefaultHTTPErrorHandler` sends `NoContent` for HEAD, echo.go
Issue #608), not "405 JSON" — scenario 5 cell wrong; (c) gin scenario 7 is a
301 (H2), not byte-level; (d) scenario 4 (wrong-method POST → echo 405 JSON)
is correct as stated. The baseline record is step 1's whole proof; wrong cells
make the red record unfalsifiable.
*Fix:* correct the four cells; re-derive the step-2 "green" set per backend.

**M2 — "Suite lands red" and "each step leaves the tree green" are mutually exclusive.**
[QA F-5 — process]
The design mandates recording the red baseline (step 1) *and* asserts every
step lands green. A commit containing red gin/echo conformance tests fails
`make ci`. *Fix:* record the red baseline from a scratch worktree (design's
own "record" language supports this), then land the suite + fixes atomically
(step 1 = suite + StdRouter hookup, green; step 2 = gin/echo wiring + fixes
together, green). The suite keeps its teeth; every commit stays green.

**M3 — The design misstates gin's 404 mechanism/headers; QA's counter-claim also misstates them.**
[Protocol L1; QA F-4 conflict — resolved here in L1's favor]
*Evidence (Verified):* gin's `serveError` (`gin.go:764-772`) sets
`Header()["Content-Type"] = mimePlain` (`text/plain`, **no charset**) and
writes `default404Body` via `c.Writer.Write` — not `c.String`, no
`; charset=utf-8`. The design's claim is wrong on both mechanism and header;
its conclusion (gin red at baseline) stands and is *stronger* (newline +
nosniff + no-charset-vs-charset). QA F-4's "gin adds `; charset=utf-8`" is
contradicted by the same source; its underlying point stands as an
implementation checklist item: scenarios 1/8/14 (matched routes) only compare
cleanly across backends if the suite handlers set headers explicitly (no
backend sniffs/rewrites matched-route bytes — gin and echo response writers
write through unchanged), so the suite's test handlers must pin
`Content-Type` explicitly.
*Fix:* correct the design text; add the explicit-header rule to the suite's
handler conventions.

**M4 — `WithFrameworkNotFound()` silently degrades the gating oracle guarantee.**
[Security F2 — only one reviewer; real, embedder-only]
Gate-off writes stdlib 404 bytes; under the opt-out the never-mounted path
writes framework bytes (echo JSON 404) — byte-distinguishable, exactly the
oracle `StdRouter`'s `live` doc and scenarios 11–13 exist to forbid. The
design's failure-mode table classifies this as "embedder owns the divergence"
— a security-property loss mischaracterized as cosmetic. In-repo production
unaffected (StdRouter, default config).
*Fix (documentation-level):* state in the design, the option's doc comment,
and the failure-mode table that gating and `WithFrameworkNotFound()` are
incompatible for indistinguishability; optionally route the gate's 404 through
the configured not-found regime under the opt-out. No code behavior change to
the default path.

**M5 — Registration-time snapshots are a silent security-relevant behavior change for gin/echo embedders.**
[Security F3]
Today both adapters read `middlewares` per request in `wrapHandler`
(verified: `adapter.go:66` gin, echo analog), so `Use(authzMW)` after
registration retroactively protects earlier routes — and is a genuine data
race (unlocked append at `Use`, request-time read; verified). Decision 3c's
snapshot aligns with StdRouter's contract and fixes the race structurally —
the right direction — but an upgrade silently drops retroactive authz/audit
coverage for embedders who `Use()` late. No in-repo caller does this
(verified: `mountMiddleware` `Use()`s before routes).
*Fix:* release note + `Use()` doc comments on both adapters stating
"middleware added via `Use()` no longer applies to previously-registered
routes; register security middleware before routes." Scenario 10 pins the
semantics. Owner: SDK release owner (public contract change).

### Low / Info

**L1 — Gate scenarios prove gate-off by wire bytes, not handler non-execution.**
[Security F5] A regression that drops `c.Abort()` produces handler bytes
appended to the 404 (gin writes through even after commit) → scenarios 11–13
fail red for any response-writing handler (all production gated handlers do).
A side-effect-only handler (audit write, store mutation) would not be caught.
*Fix (cheap):* gate scenario handlers increment a `t`-visible counter;
assert 0 when gate-off.

**L2 — Constructors mutate embedder-supplied engines silently.**
[Security F4] `NewGinRouter(e)` flips `HandleMethodNotAllowed` (already
`false` by default — a pin, no-op today) and replaces `NoRoute`;
`NewEchoRouter(e)` replaces handlers. With H2's fix the gin constructor also
pins TSR off — more mutation. Pre-construction embedder configuration is
overwritten without notice. *Fix:* document the adopt-and-normalize rule on
both constructors and in the design's precedence table.

**L3 — Estimate inconsistencies; budgets still hold.**
[Staff F6] Adapter line arithmetic doesn't compose (160→~235 vs +75 vs <260;
step 3 realistically lands gin near ~270 — all under 500). Re-derive at
implementation.

**L4 — Echo virtual-host routers escape normalization.**
[Staff evidence gap] `e.findRouter(r.Host)` — `RouteNotFound` normalizes only
the default host router; an embedder using `e.Host(...)` gets unnormalized
404s on those hosts. One line in the engine-boundary caveat.

**L5 — Gin `Default()` Logger/Recovery header behavior is load-bearing but unverified.**
[Staff evidence gap] The claim that engine-level middleware stamps no response
headers (scenarios 11–13) rests on standard knowledge. Verify empirically at
step 1 (a probe on `gin.Default()` mounting the suite).

**I — Correct-as-is.**
Protocol I1 (HEAD-on-GET → 404: deviation from RFC 9110 §9.3.2 common
practice, not a MUST violation, matches today's wire — document), I2
(OPTIONS → 404 consistent with sso-server CORS placement outside the router —
document; note the deliberate semantic choice: echo's native 204+Allow is
arguably more correct HTTP, StdRouter's 404 is the pinned contract), I3 (the
design correctly resolves the spec's `router_test.go` import-cycle
contradiction), I4 (recorder-level byte comparison sound; state it so bytes
are never hardcoded). Security abuse-case table verified sound; the 
"probes outside rate limiting / middleware order" invariants are untouched by
the design (operates only between router and engine). The `-race` tripwire
test, echo sentinel delegation wrapper, and `permissionstest` precedent are
all verified sound.

## 3. Trade-off ledger

| # | Conflict | Options | Recommendation | Consequence | Decision owner |
|---|---|---|---|---|---|
| T1 | Suite placement: `shared/core/routertest` (design, C2 gate violation) vs `interfaces/adapters/routertest` | (a) relocate; (b) exemption (forbidden: ratchet, shrink-only) | Relocate to `interfaces/adapters/routertest/` | Import path changes for a test-support package only; no production consumers | Design owner + gate reviewer; maintainers ratify |
| T2 | Echo normalization: package-var assignment (doesn't compile; also global) vs `RouteNotFound("/*")` | (a) RouteNotFound; (b) mutating package vars (breaks isolation) | RouteNotFound at construction; document first-request and later-wins caveats | Embedder late `RouteNotFound`/`Group.Use` overrides normalization (documented, same as gin) | Implementation lead; protocol reviewer ratifies bytes |
| T3 | gin TSR: framework-native 301 vs StdRouter 404 contract | (a) pin `RedirectTrailingSlash=false`; (b) keep 301 and accept suite-red on gin | Pin off (H2) | Embedders relying on TSR redirects must opt out via `WithFrameworkNotFound` | Design owner; protocol authority (redirect-following OAuth clients) |
| T4 | Snapshot vs retrofit middleware: race safety + StdRouter consistency vs silent authz/audit regression on embedder upgrade | (a) snapshot (design); (b) keep request-time read + lock (retrofit, racy-free but diverges from StdRouter) | Snapshot + explicit release note / doc comments (M5) | Embedder-facing behavior change; in-repo unaffected | Maintainers / SDK release owner (public contract) |
| T5 | Opt-out × gating oracle | (a) document incompatibility; (b) gate-404 follows configured regime | Document (M4); no default-path change | Embedders who combine both lose indistinguishability, knowingly | Security authority ratifies documentation |
| T6 | Red-baseline record vs green-tree invariant | (a) scratch-worktree baseline, atomic landing; (b) land red commit (breaks `make ci`) | (a) (M2) | Baseline evidence lives outside the commit history; suite teeth preserved | Implementation lead; maintainers ratify process |
| T7 | OPTIONS on known path: StdRouter 404 (pinned) vs echo native 204+Allow | (a) pin 404 via RouteNotFound; (b) preserve 204 and special-case scenario 6 | Pin 404 (matches StdRouter and the oracle contract); document the deliberate choice | Suite diverges from echo's native semantics by design; opt-out exists | Protocol/product authority |
| T8 | Gin 404 header claim (design vs QA) | — | Adopt L1's verified mechanism (`text/plain`, no charset, `Write` not `c.String`) | Text-only correction; conclusion unchanged | — |

## 4. Preconditions, acceptance, rollback, monitoring

**Preconditions (before implementation starts):**
1. C1: alias relocation off `aliases.go` (or one-line trim) — design amended.
2. C2: suite relocated to `interfaces/adapters/routertest/` — design amended.
3. H1: echo mechanism rewritten to `RouteNotFound("/*")` — design amended.
4. H2: gin TSR pins added — design amended.
5. M1: baseline cells corrected; M2: baseline-recording process decided and
   stated in the design.

**Executable acceptance checks (per step, in order):**
- `go build ./... && go vet ./...`
- `go test -run 'TestMaintainability_|TestArchitecture_' .` — must be green at
  every commit; `python cli.py check-filesize` before any `interfaces/sso` edit.
- Step 2 green set (per backend): gin scenarios 3–7 (after TSR pins), echo
  3–7 (after RouteNotFound); scenario 7 asserts bytes, not status.
- Step 3: scenarios 10–14 green; scenario 10 with `-race` including
  concurrent `Use`+`ServeHTTP`; scenario 12 must keep full byte equality
  (never `strings.Contains`).
- Handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
  `make ci`; no new `interfaces/sso` files; no exemptions anywhere.
- Echo fix caveat tests: normalization installed before first request;
  embedder-replaced `HTTPErrorHandler` cannot double-write.

**Rollback triggers:** any dep bump of gin/echo flips scenarios 3–7 red →
upgrade review required (design's designed loud failure); scenario 12
weakened to substring matching → revert; any new file under `interfaces/sso`
(60-file ceiling) or any Snaplink import under `shared/core/` → gate red;
late `RouteNotFound` panic reproduced on echo → reinstall-at-construction
invariant broken.

**Monitoring:** the suite itself is the monitor (byte-level, runtime-derived
reference tracking stdlib drift). No runtime observability changes.

**Explicit exclusions:** OIDF certification (correctly not claimed); engine-level
framework middleware (`gin.Default()` Logger/Recovery, embedder `engine.Use`)
outside the byte guarantee; framework-native 404/405/Allow/OPTIONS/TSR behind
`WithFrameworkNotFound`; third-party routers without `GatedRegistrar` (degraded
handler-wrapping guarantee, unchanged from today); production wiring and all
sso-server surfaces (StdRouter-only, verified) — zero production behavior
change in any step.

**Residual risks:** (a) review-enforced Factory rule and `GatedRegistrar`
"evaluate live() before middleware" convention have no machine enforcement
(same as `permissionstest` — accepted, documented); (b) echo virtual-host
routers unnormalized (L4); (c) embedder opt-out × gating oracle degradation
(M4, documented); (d) the `-race` test is a tripwire, not proof — the
structural argument (ServeHTTP never touches the slice) is the guarantee.

## 5. Missing reviews/evidence and next actions

1. **Empirical check of `gin.Default()` Logger/Recovery response-header
   behavior** (L5) — load-bearing for scenarios 11–13; do at step 1 with the
   baseline harness. **Missing.**
2. **`-race` on current adapters** (pre-fix race is source-verified, not
   exercised). Optional; the fix's tripwire test covers it. **Partial.**
3. **Re-verify echo `RouteNotFound("/*")` against OPTIONS/HEAD classes
   through the adapter** (both reviewers verified via harness; the mechanism
   at `router.go:745-755` supports it; confirm with the suite at step 2).
   **Partial — two independent empirical claims, no committed test yet.**
4. **E2E/production impact** — not needed at design stage (verified
   StdRouter-only wiring); re-confirm at handoff. **Not applicable.**
5. **Spec correction pass** for the two inherited errors (spec lines 41–42
   placement, line 97 echo API) when the design lands. **Open.**
6. **Performance review** — not required: suite is stateless,
   factory-per-subtest, no hot paths touched; normalization adds one
   not-found handler. **Not applicable.**

No sign-offs, deadlines, or owners beyond the accountable decision owners
listed above are asserted; this review is advisory.
