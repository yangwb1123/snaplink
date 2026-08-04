# QA Review: interfaces/cors — Direction 2 (config-surface completeness)

Review of `docs/auto/interfaces-cors-direction2-design.md` against
`docs/auto/interfaces-cors-direction2-spec.md`, current code, and the pinned
gates. Every design claim cited below was re-verified empirically on the
current tree. **No code was changed; this is advisory analysis of a design
artifact.** Severity per `ai-dev/prompts/README.md`.

## 1. Test inventory and commands actually run (this revision)

Revision state: design staged (`9ea0cc4f [pi-batch] Stage: design`); no
implementation. All measurements below are from this tree.

| Command | Result |
|---|---|
| `go build ./... && go vet ./...` | clean |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | pass |
| `go test -race -count=1 ./interfaces/cors/ ./config/` | pass |
| `go test -count=1 -cover ./interfaces/cors/ ./config/` | cors 84.1%, config 83.6% (statement) |
| `go test -race -count=1 ./test/ -run 'TestCORS' -v` | 4/4 pass (legacy `sso.CORS` in `test/middleware_test.go`) |
| `go test -count=1 ./interfaces/sso/ -run 'TestLogin_OriginBlocked' -v` | pass |
| `go list -deps ./shared/core` | only stdlib + `shared/core` — zero Snaplink deps; `cors → core` import acyclic (Verified) |
| `go test ./... -race`, `go test ./test/ -run TestE2E`, `make ci` | **not run** — no code changed; pending at implementation per proportionality |

Existing tests touching this surface (all pass today):

| File | Coverage of this direction |
|---|---|
| `interfaces/cors/cors_test.go` (8 tests) | identity, no-Origin passthrough, exact allow/disallow, wildcard, wildcard+credentials echo, preflight 204 + methods/headers/max-age, plain-OPTIONS passthrough, exposed headers. `:140/157` is the **only test encoding the old replacement contract** (`"X-Custom, Authorization"`); `:193/202` is the `X-RateLimit-Remaining` fixture |
| `config/security_test.go` | CORS YAML parse (origins/max_age only — no `AllowedHeaders` assertion, so D3 merge does **not** break it); `ServerOptions` opt-count = 4 with populated security block (`:70-90`) |
| `interfaces/sso/origin_validation_test.go` | login origin gate: exact match pass, mismatch 403, no-policy = allow-all, wildcard = allow-all. **No PathOverrides / empty-origins case** |
| `interfaces/sso/login_early_gate_headers_test.go` | 403 from the origin gate carries no-store + `iss` |
| `test/cors_e2e_test.go` (3) | `WithCORS` wired through `minServer`: allow-origin, disallow-no-header, preflight 204. `:56` passes `AllowedHeaders: ["Authorization"]` but asserts only Allow-Methods — survives D3 merge unchanged |
| `test/middleware_test.go:118-160` | legacy router-level `sso.CORS` (out of scope; unaffected) |

Design claims re-verified (all **Verified**): `cors.Policy{` literal exists only
at `cmd/sso-server/build_app_security.go:171`; CORS `toPolicy()` consumed only
at `config/config_load.go:316`; `cors.Middleware` mounted only at
`interfaces/sso/server_routes.go:452`; append order `build_app_core.go:154`
(`ServerOptions()`) before `build_stores.go:259`
(`wireMTLSLockoutProxiesCORS()`) — the cmd inline site wins, so the design's
pointer-overwrite analysis is correct; `validate()` runs inside the loader
(`config/source.go:144`) — the right hook for D1's `/`-prefix + nesting
checks; `DefaultAllowedHeaders` used only at `cors.go:89`; `HeaderAccessControl*`
shared names used only in `interfaces/cors`; import surface of `interfaces/cors`
= cmd, config, sso + tests (D3 blast radius as claimed); `config/` has 26
non-test files (frozen ceiling is real — zero new files holds);
`PathOverrides` has zero occurrences outside `interfaces/cors/` (D1's
"silently truncated" premise holds); `wireMTLSLockoutProxiesCORS` = 52 lines
incl. doc comment (replacement is line-negative; gate currently passes).

## 2. Requirement-to-test matrix

| Spec acceptance check | Test (existing → planned) | Status |
|---|---|---|
| D1: YAML `path_overrides` parses; captured `WithCORS` policy carries override; non-`/` key fails `LoadFromSources` | new `config/security_test.go` case: path_overrides YAML → `ServerOptions()` opt-count (widened gate ⇒ 4 with path_overrides-only block) + captured policy assert; bad-key + nested-override YAML → `LoadFromSources` error via `validate()` (`config/source.go:144`) | **Missing** — to add |
| D1: no literal `cors.Policy{` in `cmd/` | `grep -rn 'cors.Policy{' cmd/` → zero; `go build ./...` (orphan-import catcher) | **Missing** (grep is a manual step; only build is executable today) |
| D1: integration preflight `/.well-known/jwks.json` → `*`, `/token` → no headers | extend `test/cors_e2e_test.go` (package ssotest): `WithCORS(Policy{PathOverrides:{...}})`; origin outside default policy; assert header absence (incl. `Vary`) on `/token`, never a status | **Missing** — to add (see Finding 3 for the traps) |
| D1: gates, budgets, `make ci` | `TestMaintainability_/TestArchitecture_` + ci (ran today: pass on untouched tree) | **Verified** (baseline) |
| D2: `security.cors.*` doc row with all leaves + 3 pinned semantics | manual grep of `docs/config-reference.md`; no markdown checker in `make ci` (`docs-validate` = openapi only) | **Missing** (manual; see CI gaps) |
| D2: `X-RateLimit-Remaining` zero occurrences | `grep -rn 'X-RateLimit-Remaining' --include='*.go' --include='*.md'` scoped to code (minus `dist/`) + contract docs; historical docs exempt per design ruling (occurrences re-verified: `cors.go:44`, `cors_test.go:193,202`, `docs/requirements/expansion-*.md`, `docs/results/PEER_REVIEW_*.md`, `docs/architect-analysis/`, `docs/proposals/requirements.md` — the ruling is sound) | **Missing** (manual; fixture + doc comment change in same commit) |
| D3: merge → `Authorization, Content-Type, DPoP`; exclusive → `DPoP`; empty → defaults | update `cors_test.go:140/157` (old contract **must** change in the same commit — only occurrence repo-wide); add merge + exclusive + empty + case-insensitive-dedup + blank-entry-skip cases | **Missing** — to add |
| D3: config round-trip of `allowed_headers: [DPoP]` through merged header string | new `config/security_test.go` case: `toPolicy()` → `cors.Middleware(p)` preflight → assert Allow-Headers string (merge happens in `buildConfig`, not `toPolicy` — assert at the middleware boundary) | **Missing** — to add |
| D3: shared names gone from `consts.go`; `go list -deps` contains `shared/core`; no import cycle | grep + `go list -deps ./interfaces/cors` + `go build` (mechanical; compile-error backstop) | **Missing** (mechanical) |
| Behavior change: SDK direct callers of `WithCORS` with non-empty `AllowedHeaders` | no in-tree production caller exists (verified: sso mount, config, cmd only); external SDK users affected — escape hatch `AllowedHeadersExclusive` + doc row | **Verified** (in-tree), **Proposed** (external) |

## 3. Findings (severity-sorted)

### F1 — High: D1's gate widening can close the `/auth/login` origin gate for every origin

**Evidence (all Verified)**. The widened gate
`Enabled && (len(AllowedOrigins) > 0 || len(PathOverrides) > 0)` at
`config/config_load.go:315` and `cmd/sso-server/build_app_security.go:170`
exists precisely so a `path_overrides`-only config installs the middleware.
But `rejectDisallowedLoginOrigin` (`interfaces/sso/server_login.go:30,
166-180`) treats any non-nil `corsPolicy` as an active allowlist:
`isOriginAllowed` (`origin_validation.go:103-113`) iterates
`s.corsPolicy.AllowedOrigins` and returns **false for every origin when that
list is empty**. Consequences for `enabled: true` + empty top-level
`allowed_origins` + non-empty `path_overrides` (the exact class the widening
enables):

1. Every browser `POST /auth/login` with an `Origin` header → **403
   `invalid_request`**, even from origins explicitly allowed by a
   `/auth/login` override — the gate never consults `PathOverrides`.
2. The middleware and the login gate disagree: preflight to an overridden
   path gets CORS headers, the login handler on the same path 403s.
3. The D2 doc row's pinned semantic "empty `allowed_origins` disables CORS
   (middleware identity)" becomes **false** whenever overrides exist.
4. Today this YAML is inexpressible (no field) and an empty-origins config
   never calls `WithCORS` ⇒ `corsPolicy == nil` ⇒ gate open. The widening
   converts "gate open" into "gate fully closed" for this config class.

The design's failure-mode table covers only the both-empty case and never
analyzes the top-level-empty + overrides-non-empty case; its own YAML example
happens to keep top-level origins non-empty, so it dodges the corner.

**Impact**: availability regression for SPA login with a plausible,
direction-sanctioned config; security-adjacent inconsistency (middleware
allow vs handler deny).

**Recommendation** (design owner's call, but one of):
- (a) `isOriginAllowed`/the login gate resolves the path override for the
  request path before falling back to the top-level list; or
- (b) empty top-level `AllowedOrigins` keeps the gate open (preserves the
  pre-change "no top-level allowlist ⇒ no origin restriction" invariant,
  matching the no-policy behavior pinned by `origin_validation_test.go:106`);
  or
- (c) if deliberately fail-closed, the D2 doc row must state it and the
  config reference must require non-empty top-level origins when using
  overrides.

Options (a)/(b) are `interfaces/sso` production changes — they collide with
the design's "zero sso changes" constraint; AGENTS.md §5's stricter-contract
rule takes precedence over the constraint, and the constraint should be
updated to record the exception. Option (c) keeps the constraint but ships a
footgun.

**Executable validation**: new integration test (ssotest): server wired with
`WithCORS(cors.Policy{PathOverrides: {"/auth/login": {AllowedOrigins:
[origin]}}})`; `POST /auth/login` with `Origin: origin`,
`Content-Type: application/json` → assert the decided status (must NOT be 403
for (a)/(b)); plus config-side test asserting `ServerOptions()` includes
`WithCORS` for a path_overrides-only YAML (pins the widening itself).

### F2 — Medium: the "equal-length prefix nondeterminism" is behaviorally inert; risk is test determinism only

**Evidence**. `buildOverrideConfigs` (`cors.go:180-196`) bubble-sorts by
prefix length only; equal lengths keep map-iteration order — the design's
observation is accurate. But two distinct equal-length prefixes can never
both match one request path (`path[:L] == p1 == p2` is impossible for p1 ≠ p2),
and the swap condition `len(cfgs[j]) > len(cfgs[i])` guarantees longer
prefixes sort first. `resolveCORSConfig` first-match-wins is therefore fully
deterministic today; the "operator-reachable nondeterminism" framing
overstates exposure.

**Impact**: no behavioral flake; the only flake would be a unit test
asserting the *order of the sorted list* for equal-length prefixes. The
spec's "longest-prefix-first, first-match-wins" acceptance is satisfiable
without the tie-break.

**Recommendation**: keep the ~4-line tie-break only if a list-order test is
desired (test hygiene), and land it in the same commit as that test;
otherwise write the resolution-level test with unequal lengths (`/token` vs
`/tokenizer` — also documents the documented prefix-bleed).

**Executable validation**: `Policy{PathOverrides: {"/token": {…strict},
"/tokenizer": {…loose}}}` + `OPTIONS /tokenizer` → loose policy; run
`-count=50` to prove determinism.

### F3 — Medium: the D1 integration test has three assertion traps the design names only partially

**Evidence/impact**: (1) the `/token` empty-origins override drops **all**
CORS headers and falls through to the router — the acceptance must assert
header absence only (both `Access-Control-Allow-Origin` **and `Vary`**), never
a status, since the router's OPTIONS answer (404/405) is outside scope; (2)
the test origin must be outside the default policy, or the override is never
observed; (3) wildcard + credentials in the same policy triggers the
echo-origin branch (`cors.go:112-124`) and `*` assertion fails. Design flags
(2)/(3); (1) needs the `Vary` addition.

**Executable validation**: `OPTIONS /token` from the disallowed-by-default
origin → assert `Allow-Origin == ""` and `Vary` does not contain `Origin`
(no partial header set).

### F4 — Medium: the stock-binary wiring path has zero executable coverage

**Evidence**: `cmd/sso-server` is `package main` with no tests; the cmd-side
gate widening (`build_app_security.go:170`), the `toPolicy()` substitution,
and the boot-log override count are verified only by grep + compile. The
two-site drift the design describes (SDK vs stock binary) is guarded
asymmetrically: config-side unit test covers the `config_load.go:315` site;
the cmd site relies on the acceptance grep.

**Impact**: a future edit re-introducing an inline mapping or a one-sided
gate widening passes all gates.

**Recommendation**: keep the grep as a committed, scripted acceptance step
(document the exact command in the commit message, per the design's own
ruling); optionally add `security.cors.path_overrides` to one validated
deploy example (`docs/examples/basic/config.yaml`) so `make config-validate-all`
exercises the new key through the full load path — currently **no** example
config uses `security.cors` at all (verified in the 7 `config-validate-all`
targets' inputs), so CI never parses the new field.

**Executable validation**: `grep -rn 'cors.Policy{' cmd/` → zero hits;
`make config-validate-all` after adding the example block; manual boot of a
path_overrides-only YAML and observe the boot log's `path_overrides` count.

### F5 — Low: D3 blast radius verified; four new unit cases needed, one fixture must change

**Evidence**: the old replacement contract is encoded in exactly one
assertion (`cors_test.go:157`); `test/cors_e2e_test.go:56` is unaffected
(asserts methods only); `config/security_test.go` never asserts
`AllowedHeaders`; no in-tree production `WithCORS` caller besides sso mount,
config, cmd. The design's "exactly one test must change" claim holds.

**Recommendation**: in `interfaces/cors/cors_test.go`, alongside the `:140`
rewrite, add: merge (`["DPoP"]` → `Authorization, Content-Type, DPoP`),
exclusive (`["DPoP"]` → `DPoP`), empty (defaults, unchanged), case-insensitive
dedup (`["authorization"]` → `Authorization, Content-Type`, default casing
first), blank-entry skip (`["", "X-Custom"]` → defaults + `X-Custom`). The
merge implementation must be seen-set + ordered slice (design already
mandates; a map-iteration join would flake `-count=10+` runs).

### F6 — Low: `X-RateLimit-Remaining` ruling verified; mind the header casing in the fixture

**Evidence**: occurrences re-verified exactly as the design lists; the
contract-doc scope is the right call. One trap the design names but the
implementer will hit: the fixture's current `X-Request-ID` casing differs
from the real constant `HeaderRequestID = "X-Request-Id"`
(`shared/core/consts_wire.go:21`). After the fix the fixture should use the
core constants and the assertion must match the join order:
`"X-Request-Id, Retry-After"`.

### F7 — Info: `validate()` is the correct D1 validation hook; existing opt-count test is safe

`config/source.go:144` calls `validate()` inside the loader, so
`LoadFromSources` fails loud as the design requires; `TestSecurityConfig_ServerOptionsWiresThree`
(4-opts) is unaffected by the widened gate (its YAML keeps origins non-empty);
add a sibling case for the path_overrides-only shape asserting the count is
still 4 (proves the config-side widening on the exact case that needs it).

### F8 — Info: `wireMTLSLockoutProxiesCORS` sits at 52 lines incl. doc comment

Replacement is line-negative (8-line literal → call + log); maintainability
gate currently passes and will re-check. If the gate counts the comment, the
function is already at the edge — the design's `wireCORS()` extraction
fallback is the right escape.

## 4. Prioritized scenario list

P0 (release blockers — all **Missing**, to be added with implementation):
1. Path_overrides-only YAML: login POST with allowed-by-override origin — decided status per F1 (happy + fail-closed variants).
2. Path_overrides-only YAML: `ServerOptions()` includes `WithCORS` (config-side gate widening), count = 4.

P1 (spec acceptance — **Missing**):
3. Unit: preflight with override → override policy headers win over default (`/.well-known/jwks.json` wildcard vs strict default); disallowed-by-default origin; no credentials/wildcard mix.
4. Unit: empty-origins override → no CORS headers, **no `Vary`**, handler reached; preflight falls through (not 204).
5. Unit: longest-prefix resolution `/token` vs `/tokenizer` (+ `-count=50` determinism; optional tie-break + list-order test).
6. Unit: merge / exclusive / empty / case-insensitive dedup / blank-skip for `buildConfig`.
7. Config: bad key (`foo`) → `LoadFromSources` error; nested `path_overrides` → error (fail-loud ruling); `enabled: false` override entry still applied; `allowed_headers: [DPoP]` round-trip through `Middleware` preflight.
8. Integration (ssotest): `OPTIONS /.well-known/jwks.json` → `*`; `OPTIONS /token` → header absence only (F3 traps).
9. Fixture/doc: `cors_test.go:140/157` new merged expectation; `:193/202` → `X-Request-Id, Retry-After`; `cors.go:44` comment; docs row with all leaves + 3 pinned semantics.

P2 (hardening):
10. Existing gates re-run: `go build/vet`, `TestMaintainability_/TestArchitecture_`, `go test ./... -race`, `go test ./test/ -run TestE2E`, `make ci`.
11. Grep acceptances: `cors.Policy{` in `cmd/` = 0; scoped `X-RateLimit-Remaining` = 0; `HeaderAccessControl` shared names gone from `consts.go`; `go list -deps ./interfaces/cors` contains `shared/core`.
12. Optional: example config with `path_overrides` → `make config-validate-all`; manual stock-binary boot log check.

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**CI gaps** (default CI = `make ci`: fmt vet race build examples proto-lint
ci-modules config-validate-all modules-check modules-smoke route-contract
capabilities-check sdk-surface-check profiles-evidence):
- `make ci` contains no markdown/config-reference validation (`docs-validate`
  = OpenAPI only), so the D2 doc row and both grep acceptances are **manual
  steps**; script them in the commit (exact commands) or as a `check-invariants`
  addition.
- `config-validate-all` never parses `security.cors` today (no example uses
  it); the new YAML key's load-path is CI-invisible without an example block
  (F4).
- Tagged/manual suites distinguished: chaos (`test/chaos`: clock jump, JTI
  replay), backend-semantics (`test/backendsemantics`), load (`ops/deploy/loadtest`,
  k6 + baseline), conformance (`test/oidc-conformance`) — **none applicable**
  to this direction (no stores, no crypto, no new endpoints; config-surface
  only). Re-run only if a change unexpectedly touches those surfaces.
- No migration concerns: no persistence, no schema, no new packages; restart
  semantics (not SIGHUP-reloadable) must be stated in the doc row — CORS is
  already outside the Hot Reload subset (`docs/config-reference.md:433`).

**Flake risks**: (1) a list-order test for equal-length prefixes without the
tie-break — do not write it until the tie-break lands (F2); (2) a
map-iteration join in the dedup — must be seen-set + slice (F5); (3) the
integration test asserting a router status on the fall-through path (F3).

**Fixtures needed**: none new — `test/cors_e2e_test.go` extension reuses
`minServer`; config cases reuse `writeTemp`/`securityYAML` patterns in
`security_test.go`; `cors_test.go` fixtures are inline.

**Exit criteria**: P0 + P1 all green; `cors_test.go:140/157` updated in the
same commit as the `buildConfig` change (a cherry-picked D3 change without it
fails CI); F1 resolved with a pinned, asserted decision; `make ci` green;
both grep acceptances executed with the documented scoped commands.

**Advisory only**: no release approval implied; the F1 decision is the
design owner's to make, and it may legitimately revise the "zero sso
production changes" constraint.
