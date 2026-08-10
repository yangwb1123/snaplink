# Design: structural validation of cluster-diff/running responses in `cmd/sso-operator/controller`

Companion to `docs/architect-analysis/cmd-sso-operator-controller-b4-3-truthiness-requirements.md`.
This document treats that spec (and the direction it cites) as untrusted
evidence, records what was independently verified against HEAD, and turns the
requirements into a concrete, ordered design with API changes, compatibility
constraints, failure modes, migration steps, and testable acceptance mapping.

## 1. Evidence verification verdict

Every citation was re-checked against HEAD (source files, Makefile, go.mod,
campaign YAML). All claims confirmed; the only sharpenings are noted in E5.

| # | Claim | Verdict |
|---|---|---|
| E1 | `postClusterDiff` at `http.go:82-114`, zero structural validation (unmarshal/return at 109-113) | Confirmed — func at 82, ends 114; `var parsed`/`json.Unmarshal` into `clusterDiffResponse`/`return parsed.Patch` block at 109-113 with no op/path/resolution check |
| E2 | `fetchRunningConfig` at `http.go:49-78`; only checks are decode and `parsed.Running == nil` (74-76) | Confirmed — func at 49, ends 78; a body of `{"running": {}}` passes and yields an empty snapshot |
| E3 | `runCheck` at `ssoconfigdrift_controller.go:130-162`; `driftDetected: len(patch) > 0` at 158 | Confirmed — exact line numbers; a 200 `{"patch":[]}` yields "no drift" |
| E4 | `applyResult` at 177-186 writes `DriftDetected`/`PatchOpCount` only when `!result.failed` | Confirmed — func at 177, guarded write at 182; failed checks keep prior values, so "never reset to false" needs no `applyResult` change |
| E5 | Server emit set: "Only add/replace/remove ops" at `diff.go:27`; `add` at 59, `remove` at 61, `replace` at 79; escaped `/`-rooted child paths (`diff.go:36,57-58`); strict escaping at 86-92 | Confirmed — all exact. **Sharpening (E5a):** `childPath = path + "/" + escapePointerSegment(k)` with root `""` means an empty-string snapshot key `""` emits the path `"/"` (one empty segment). The validation must therefore treat `"/"` as resolvable when the snapshot has an empty-string key, not reject short paths by rule. The spec's rule 2 ("non-empty, starts with `/`") already permits this; the design below makes it explicit |
| E6 | `RedactOps` (`redact.go:33-45`) rewrites only `Value`; op/path pass through; `make([]Op, len(ops))` at 34 makes the wire patch non-nil (`[]`, never `null`) | Confirmed — the emit set is observable at the wire; `Diff` may return nil but `RedactOps` normalizes it |
| E7 | `HandleClusterDiff` 400s `len(req.Snapshot) == 0` (`handlers.go:105`) | Confirmed — `if err := ctx.Bind(&req); err != nil \|\| len(req.Snapshot) == 0` at 105. Anchors acceptance (b): a real server never 200s an empty patch for an empty snapshot |
| E8 | 8 `TestReconcile_*` at lines 139, 168, 188, 211, 232, 287, 305, 327; hand-rolled `runningServer`/`diffServer`/`buildReconciler` helpers; no invalid-shape case | Confirmed — exact lines; helpers at 55/105/120; `TestReconcile_DriftDetected` fixture is exactly `replace /issuer` + `add /new_field` against `{"issuer": "https://a.example"}`; `TestReconcile_NoDrift` uses a non-empty running body + empty patch |
| E9 | `cmd/sso-operator/go.mod`: k8s.io/api, apimachinery, client-go, controller-runtime only; root import test-only (`adminpaths_parity_test.go:14`, via `replace => ../../`); no `go.work` | Confirmed — `find` for go.work: 0 hits; the replace directive means a root import *would* compile, but the structural check stays stdlib-only to preserve the out-of-process module posture |
| E10 | `Makefile:263` = `cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...` inside `ci-modules` | Confirmed — exact line and text |
| E11 | Campaign mapping: B4-3 deploy-tree sweep/truthiness assertions, `campaign-snaplink-b4.yaml` 64-68 | Confirmed — "(3) discovery truthiness … deploy tree gets sweep/truthiness assertions"; sibling half landed (`adminpaths_parity_test.go`) |
| E12 | Pre-existing conditions: operator module green at HEAD; decode-fail pins (`{"running": [1,2,3]}`, `{"running": "x"}`) fail in `fetchRunningConfig` today | Confirmed — decode into `map[string]interface{}` rejects both; controller 0.090s baseline |

Net: no claim invalidates the scope. E5a is a design sharpening, not a spec
contradiction. The spec's 12-case acceptance is implementable as written with
the design below.

## 2. Scope and non-goals (unchanged from the spec)

- Surface: `cmd/sso-operator/controller/` only — new `validate.go`, two call
  sites in `runCheck`, two new test files. Read-only report-only behavior
  preserved; validation adds no write path.
- Non-goals (do not implement): no import of `platform/configaudit` or any
  root package in production code; no changes to `http.go` transport
  semantics, `applyResult`, `summarize`, `checkResult`, the CRD, `doc.go`,
  `main.go`, RBAC, audit, config keys, `Err*`, OpenAPI; no value-shape
  checks; no "add at an existing key" rejection; no op-order checks; no
  `patch: null` vs `[]` distinction; no schema-level config knowledge.

## 3. API changes

No wire, CRD, config, or status-surface API changes. The only API surface is
two unexported free functions plus two call sites, all inside the package.

### 3.1 New production file: `cmd/sso-operator/controller/validate.go`

`package controller`, stdlib only (`errors`, `fmt`, `strings`). ~110 lines,
three helpers, no function over 30 lines.

```go
// validatePatch reports whether patch could have been emitted by the
// server's documented cluster-diff contract: only add/remove/replace ops
// (platform/configaudit diff.go:27), /-rooted RFC 6901 paths whose segments
// the server's escapePointerSegment produced, and paths that resolve into
// snapshot with object-only intermediates (diffMaps recurses only into
// objects; arrays are whole-value replaced, never traversed). The check is
// a strict superset of the emit set (see design doc section 4): it rejects
// only shapes the server cannot have produced, so a legitimate response is
// never mislabeled. Errors are static reason strings plus the op index;
// response-derived bytes (op values, paths) are never echoed, and the
// functions receive neither tokens nor requests, so nothing server-authored
// or credential-bearing can reach Status.Message (see D-D).
func validatePatch(patch []patchOp, snapshot map[string]interface{}) error
```

Per-op behavior (each violation returns a non-empty error naming the op index
and a STATIC reason; error text format `op[%d]: <reason>`, e.g.
`op[2]: unsupported operation`, `op[0]: remove path does not resolve into the
snapshot`). Reasons are fixed strings — the offending op value and path are
deliberately NOT echoed (see D-D), so Message content on these paths never
contains bytes authored by cluster B.

1. `op.Op` in `{"add", "remove", "replace"}`; anything else (`move`, `copy`,
   `test`, `""`, unknown) is an error.
2. `op.Path` non-empty and first byte `'/'`.
3. `splitPointerPath`: split on `/` (escaped slashes are `~1`, so splitting
   first is safe), then per segment strict RFC 6901 unescape left-to-right:
   `~0` → `~`, `~1` → `/`, any other `~x` or a trailing `~` is an error. The
   server's escape (`diff.go:87-92`, `~` first, then `/`) produces only
   `~0`/`~1`, so every server-emitted segment passes strict unescape, and
   strict unescape is injective on emitted segments (escape(k1)==escape(k2)
   implies k1==k2).
4. Resolution over `map[string]interface{}` only, by key presence (values
   including `null` are irrelevant to existence):
   - `remove`/`replace`: `resolveFull` must find the leaf. Intermediates are
     enforced to be objects by requiring each intermediate node to be a
     `map[string]interface{}` before descending; the leaf node itself may be
     any type (the server emits `replace` at a map-valued path when the
     value type changed, `diff.go:71-82`). Existence is `m[k], ok`.
   - `add`: `parentIsObject` — walk all segments except the last, requiring
     each to resolve through an object; the parent itself must be a
     `map[string]interface{}`. The added key may be present or absent. A
     single-segment path (e.g. `"/x"` or the empty-key `"/"`) has the
     snapshot root as parent, which is always an object.
   - Empty patch (`nil` or empty slice): nil. An empty patch is exactly how
     "no drift" is truthfully reported today; `TestReconcile_NoDrift`
     depends on it.
5. `"-"` segments are ordinary object keys (RFC 6901's `-` special case is
   defined only for arrays, which this resolver never traverses; a snapshot
   key literally named `"-"` would emit `/-`).

Resolution helpers (pseudo-code, exact shapes to be settled in code review):

```go
func splitPointerPath(path string) ([]string, error)        // strict unescape per segment
func resolveFull(snapshot map[string]interface{}, segs []string) (interface{}, bool)
    // cur := snapshot; for each seg: cur must be map, key must exist;
    // leaf (last iteration) returns the value before the object check.
func parentIsObject(snapshot map[string]interface{}, segs []string) bool
    // walk segs[:len(segs)-1]; final cur must be map.
```

```go
// validateRunningSnapshot rejects an empty running snapshot. The server's
// own contract answers 400 to len(snapshot)==0 (handlers.go:105), so a 200
// empty-patch-for-empty-snapshot pair is unverifiable by definition.
// Object-ness is already enforced by the decoder in fetchRunningConfig.
func validateRunningSnapshot(running map[string]interface{}) error {
    if len(running) == 0 {
        return errors.New("running snapshot is empty")
    }
    return nil
}
```

### 3.2 `runCheck` call sites (the only production edit outside validate.go)

`ssoconfigdrift_controller.go`, inside `runCheck` (130-162), two guards in
order — R2 fires before the POST to cluster B so an empty snapshot never
reaches the wire and case 10's "POST never happens" assertion holds:

```go
	running, err := fetchRunningConfig(ctx, r.httpClient(), cr.Spec.ClusterA.BaseURL, tokenA)
	if err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("fetch cluster A running config failed: %s", err)}
	}
	if err := validateRunningSnapshot(running); err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("cluster A running config failed structural validation: %s", err)}
	}

	patch, err := postClusterDiff(ctx, r.httpClient(), cr.Spec.ClusterB.BaseURL, tokenB, running)
	if err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("cluster B diff request failed: %s", err)}
	}
	if err := validatePatch(patch, running); err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("cluster B diff response failed structural validation: %s", err)}
	}
```

No changes to `checkResult`, `applyResult`, `summarize`, the success path, or
the requeue logic: valid patches still yield `driftDetected = len(patch) > 0`,
`patchOpCount = len(patch)`, `message = summarize(len(patch))`; the new
failure paths yield `failed=true` → `applyResult` preserves
`DriftDetected`/`PatchOpCount` (design doc E4) and `requeueInterval` returns
`shortRequeueInterval` (30s). `runCheck` grows from 33 to ~41 lines — inside
the 50-line function budget.

### 3.3 New test files

- `cmd/sso-operator/controller/validate_test.go` — table-driven unit tests of
  the two functions, no HTTP (acceptance cases 1-7 plus design extras).
- `cmd/sso-operator/controller/ssoconfigdrift_truthiness_test.go` — same
  package, reuses `buildReconciler`/`runningServer`/`diffServer` from
  `ssoconfigdrift_controller_test.go` (acceptance cases 8-12). Adds two
  file-local helpers only, leaving the existing test file byte-identical:
  - `rawRunningServer(t, wantToken, rawBody string) *httptest.Server` —
    returns the raw body verbatim (the existing `runningServer` takes a
    `map[string]interface{}` and cannot express the decode-fail pins
    `{"running": [1,2,3]}` / `{"running": "x"}`).
  - `buildReconcilerWithStatus(t, serverA, serverB, status) ...` — seeds a
    pre-set `Status.DriftDetected=true, PatchOpCount=3` for the sharp
    "never reset to false" variant of case 8.
  - A `mustNotContact(t)` httptest handler that fails the test if reached,
    for case 10's POST-never-happens assertion.

### 3.4 Internal design decisions (sharper than the spec where it was silent)

- **D-A (empty-key path).** `"/"` is a legal server emission for a snapshot
  containing the empty-string key (E5a). Validation resolves it like any
  other path: `splitPointerPath("/")` → `[""]`, and key `""` lookup decides.
  Do not reject by segment count.
- **D-B (superset direction).** Validation is deliberately an
  over-approximation of the emit set — it accepts anything the server
  *could* have emitted, rejects only what it *could not*. Completeness
  (rejecting every non-emittable shape, e.g. `add` at a parent that is an
  object in the snapshot but a scalar in running) is out of scope: it would
  require the operator to know cluster B's running config, which is exactly
  what the diff is for. One-directional checking is what keeps the rule
  sound (no false rejects) while still catching the canned-response class.
- **D-C (leaf type freedom).** `remove`/`replace` leaves may be maps,
  scalars, arrays, or `null`; only *intermediates* must be objects. A
  `replace` at a map-valued path is genuinely emittable (type change,
  `diff.go:71-82`), so restricting leaf types would over-reject.
- **D-D (error text discipline).** Errors name `op[i]` and a STATIC reason
  class only — never the offending op value or path. `validatePatch`'s
  inputs are entirely response-derived (`patch`) plus the snapshot, so
  echoing paths or op values would put cluster-B-authored bytes into the
  persisted `Status.Message` (today only `len(patch)` and a 200-byte-capped
  `describeAPIError` echo reach it); static reasons keep the new messages
  free of response bytes, strictly smaller than today's echo, and
  grep-able.
  Quoting/truncating instead would still persist attacker-chosen bytes on a
  shared surface and keep the security claim hedged, while the diagnostic
  delta (which op value/path) does not change remediation — the superset
  property rules out false rejects, so every violation means the server
  left its documented emit set. The op index (a bounded integer,
  content-free) is retained so a human can locate the offending entry when
  re-running by hand. Case 8 pins the exact static message end-to-end.
- **D-E (round-trip consistency).** The operator validates against its own
  decoded copy of cluster A's running body — the same bytes the server
  re-decodes. `json.Marshal` HTML-escaping and float64 rounding are
  round-trip-stable (the server unmarshals the operator's re-marshaled
  snapshot), so server-side resolution and operator-side resolution see the
  same keys. No cross-process mismatch is possible for emitted paths.

## 4. Compatibility constraints

- **Server-legitimate patches pass unchanged (soundness).** For any patch
  the documented server could emit for the actual snapshot pair, all four
  checks pass: (i) ops are in `{add,remove,replace}` (E5); (ii) paths are
  `""`-rooted with ≥1 segment (E5); (iii) strict unescape succeeds and is
  injective on emitted segments (3.1 rule 3); (iv) `diffMaps` recursed into
  every intermediate (so each is an object in the snapshot) and emitted
  `add` only under a recursed parent / `remove`+`replace` only at existing
  keys — exactly the resolution rules. Acceptance (c) and the 8 existing
  tests pin this at reconcile level.
- **Existing observable behavior preserved on every current path.** All
  success, HTTP-failure, decode-failure, secret-failure, and baseURL-failure
  paths produce byte-identical `Status.Message`/`DriftDetected`/
  `PatchOpCount`/`RequeueAfter` as today; the new wording appears only for
  shapes the server cannot emit. The 8 `TestReconcile_*` tests are the
  regression lock and are not edited.
- **Module posture preserved.** Production code stays root-free and
  stdlib-only; `cmd/sso-operator/go.mod`/`go.sum` unchanged (no new module
  paths, no `go.work`); the `replace => ../../` directive remains test-only
  via `adminpaths_parity_test.go`.
- **Budgets.** `controller/` 2 → 3 non-test files (cap 10), 4 → 7 total
  (no total-file gate; the caps are the non-test fan-out of 10 and the
  subdirectory limits of 16 gate / 15 intended); `validate.go` ~110 lines,
  `runCheck` 33 → ~41 lines (limit 50); no `if` nesting beyond 3;
  complexity trivial; no new packages, no `layerExemptions`.
- **Wire/security invariants untouched.** No routes, `Err*`, config keys,
  audit events, credential surfaces, or oracle-safe tables; no SSRF surface;
  no new HTTP behavior. Fail-open doctrine preserved: the new checks turn a
  false "no drift" into a truthful `failed=true` + Message — strictly more
  conservative, never less. New failure messages are fully static (D-D), so
  the persisted `Status.Message` carries strictly fewer server-derived bytes
  than today's `describeAPIError` 200-byte echo on non-2xx bodies.

## 5. Failure modes

| # | Mode | Behavior | Mitigation |
|---|---|---|---|
| FM1 | False "no drift" on unverifiable data (the defect) | Eliminated for: unknown ops, unresolvable paths, empty running snapshots, decode-invalid running bodies | The two validators; cases 8-10 pin each shape at Status level |
| FM2 | Over-rejection of a legitimate server that grows outside its documented contract (e.g. future `move`/`copy` or array-element paths) | `failed=true`, Message names the op index and reason class, DriftDetected preserved, 30s requeue | Visible and truthful, never silent; acceptance (c) pins the current set so the change is deliberate; rollback is a 2-line revert (see §6) |
| FM3 | Panic on malicious input (deep/nested paths, `~` floods, huge patches) | None possible: map lookups + `ok`-checked type assertions only; no index arithmetic; no recursion | Design rule; unit tests include adversarial path strings |
| FM4 | Response-derived bytes in `Status.Message` | None: `validatePatch` errors carry only op index + static reason; `validateRunningSnapshot` is a static string; `runCheck` prefixes are static. Stricter than today's `describeAPIError` 200-byte echo of non-2xx bodies; no token can appear (validators receive neither tokens nor requests; the snapshot is never echoed) | Case 8 asserts the exact static message end-to-end |
| FM5 | Requeue storm from repeated validation failures | Bounded: `shortRequeueInterval` 30s, identical to every existing failure path | No change needed; documented |
| FM6 | Empty snapshot + empty patch pair 200s "no drift" | Impossible: `validateRunningSnapshot` fires before the POST | Case 10 asserts cluster B is never contacted |
| FM7 | Pre-existing, out of scope (documented, not fixed): unbounded `io.ReadAll` on response bodies; float64 precision beyond 2^53; HTML-escape round-trip | Unchanged; all benign (round-trip-stable, see D-E; body size bounded only by the 15s client timeout) | Note for a future transport hardening change, not this one |
| FM8 | CR status-update failure after a validation failure | Unchanged: `Reconcile` returns the error to controller-runtime backoff, exactly as today | None needed |

## 6. Migration steps (ordered)

1. Add `cmd/sso-operator/controller/validate.go` (§3.1) and
   `validate_test.go` (unit cases 1-7 + design extras). Run unit tests —
   they pass without touching the controller. Then module-local
   `cd cmd/sso-operator && go build ./... && go vet ./...` (AGENTS.md
   fail-fast after every `.go` edit).
2. Add `ssoconfigdrift_truthiness_test.go` (reconcile cases 8-12 with the
   three file-local helpers). Run — cases 8-10 fail on HEAD by design
   (the false "no drift" they pin), 11 passes, 12 is the untouched
   existing suite. Then module-local `cd cmd/sso-operator && go build ./...
   && go vet ./...` (fail-fast).
3. Wire the two `runCheck` call sites (§3.2). All 12 cases now pass. Then
   module-local `cd cmd/sso-operator && go build ./... && go vet ./...`
   (fail-fast).
4. Gates: `cd cmd/sso-operator && go build ./... && go vet ./...`, then
   `cd cmd/sso-operator && go test -race -count=1 ./...` (the exact
   `ci-modules` command, `Makefile:263`), then focused
   `go test -race -count=1 ./controller/ -v`.
5. Root-module verification (no root `.go` edits, expected green):
   `go build ./... && go vet ./...` and
   `go test -run 'TestMaintainability_|TestArchitecture_' .`
   plus `python cli.py modules check`.
6. `make ci` (full gate, includes `ci-modules`).
7. Release the operator image. No CRD, RBAC, config, or storage changes;
   no cluster-side rollout ordering. Observe `Status.Message` on live CRs:
   the new prefixes (`...failed structural validation:`) should never
   appear against a genuine server pair; if they do, FM2's escalation
   path applies (upgrade server or roll back).
8. Rollback: revert the two `runCheck` call sites — HEAD behavior is
   restored exactly; the new tests then fail (the intended tripwire, same
   pattern as the CRD-parity change).

## 7. Testable acceptance mapping

All cases run under `cd cmd/sso-operator && go test -race -count=1 ./...`.
Every case is a Go test; none is review-only. 12/12 spec cases + 6 design
extras (D-A through D-C coverage), all machine-checked.

| # | Test (proposed name) | Level | Acceptance | Asserts |
|---|---|---|---|---|
| 1 | `TestValidatePatch_RejectsUnknownOps` | unit | (a) op set | error non-nil for `move`/`copy`/`test`/`""`/`unknown`; message contains the op index and the static reason, and does NOT contain the offending op string |
| 2 | `TestValidatePatch_RejectsUnresolvablePaths` | unit | (a) resolution | `remove`/`replace` at `/nonexistent` and `/no_such_parent/x` `add` → error |
| 3 | `TestValidatePatch_RejectsUnresolvablePaths` (table row) | unit | (a) | `add` under unresolvable parent → error |
| 4 | `TestValidatePatch_RejectsInvalidPaths` | unit | (a) | `"issuer"`, `""`, `/iss~2uer`, `/issuer/nested` (scalar intermediate), `/clients/0/name` (array intermediate) → error for each |
| 5 | `TestValidatePatch_AcceptsServerLegitimate` | unit | (c) | the `TestReconcile_DriftDetected` fixture and the nested fixture (`/clients/c1/redirect_uris` replace, `/old_key` remove) → nil |
| 6 | `TestValidatePatch_AcceptsEmptyPatch` | unit | (c)/regression | nil and empty slice → nil |
| 7 | `TestValidateRunningSnapshot` | unit | (b) | `{}` → error; non-empty → nil |
| 8 | `TestReconcile_InvalidOpSet_FailsPreservingStatus` | reconcile | (a) + never-reset | `move` op → `failed=true`, `Message == "cluster B diff response failed structural validation: op[0]: unsupported operation"` exactly (static, response-byte-free, token-free), `DriftDetected`/`PatchOpCount` unchanged (fresh: false/0; pre-seeded `true`/3 via `buildReconcilerWithStatus`: still true/3), `RequeueAfter == shortRequeueInterval` |
| 9 | `TestReconcile_UnresolvablePath_FailsPreservingStatus` | reconcile | (a) | `remove /no_such_key` → same failure shape |
| 10 | `TestReconcile_EmptyRunning_FailsWithoutContactingClusterB` | reconcile | (b) | `{"running": {}}` + `{"patch":[]}` → failed, Message NOT the "no drift" summary, status preserved, cluster B handler fails the test if contacted; pins `{"running": [1,2,3]}` and `{"running": "x"}` (raw body helper) still fail |
| 11 | `TestReconcile_ServerLegitimatePatch_AcceptedUnchanged` | reconcile | (c) | exact `TestReconcile_DriftDetected` fixture → `DriftDetected=true`, `PatchOpCount=2`, `Message == "drift detected: 2 patch operation(s) needed on cluster B"` |
| 12 | Existing 8 `TestReconcile_*` untouched | reconcile | regression | byte-identical behavior, in particular `NoDrift` and `DriftDetected` |
| X1 | `TestValidatePatch_EmptyKeyPath` | unit | D-A | `"/"` resolves when snapshot has key `""`; `remove "/"` on snapshot without it → error |
| X2 | `TestValidatePatch_EscapedKeyRoundTrip` | unit | D-A/D-B | snapshot keys `a/b` and `a~b` resolve via `/a~1b`, `/a~0b`; `~2`, trailing `~`, `~01`→`~1` strictness |
| X3 | `TestValidatePatch_DashSegmentIsObjectKey` | unit | D-B | key `"-"` resolves via `/-`; no array semantics |
| X4 | `TestValidatePatch_NullValuedLeaf` | unit | D-C | `{"issuer": null}` — `replace /issuer` passes (key presence, not value) |
| X5 | `TestValidatePatch_MapValuedLeafReplace` | unit | D-C | `replace /obj` where snapshot `obj` is a map passes (type-change emission is legitimate) |
| X6 | `TestValidatePatch_AdversarialPaths` | unit | FM3 | deeply nested, `~`-flooded, `/`-only paths: error values only, no panic |

## 8. Verification plan (exact commands)

```bash
cd cmd/sso-operator && go build ./... && go vet ./...
cd cmd/sso-operator && go test -race -count=1 ./...      # ci-modules gate (Makefile:263)
cd cmd/sso-operator && go test -race -count=1 ./controller/ -v   # focused: 12 + 6 cases
go build ./... && go vet ./...                           # root module (no root .go edits)
go test -run 'TestMaintainability_|TestArchitecture_' .  # root gates
python cli.py modules check                              # unchanged surface
make ci                                                  # full gate incl. ci-modules
```

Pre-existing conditions to report separately: none found — the operator
module builds, vets, and tests green at HEAD (controller 0.090s); the
acceptance's failure modes (move op, unresolvable path, empty running body
+ empty patch) all currently produce the false "no drift" the direction
describes, i.e. the new reconcile-level tests fail on HEAD by design until
step 3 of §6 lands.
