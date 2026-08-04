# Design: domains/anomaly — Detector Convergence

Design for `docs/requirements/domains-anomaly-detect-convergence.md`. Every
claim was re-verified against the working tree before writing: the dead
subtree's zero-importer status, the `Type:` collision table, the stale
`runner.go:13` pointer, and the `buildAnomalyDetectors` order.

Scope: exactly the three evidence-backed improvements (dead-subtree removal,
domain-owned `SignalType*` constants, runner doc + ordering contract). The
tenant dimension is designed in
`docs/design/domains-anomaly-tenant-dimension.md`; the unwired retention loop
has no spec yet. **Runtime behavior change: zero.** This design deletes
unreachable code, moves constant declarations, and edits comments — the
compiled production graph is byte-identical in behavior.

Data flow after the change (unchanged from today):

```text
/auth/login → dispatchLoginAnomaly
  → Runner.Dispatch(LoginEvent)              # async, bounded queue
  → Detector.Inspect(ctx, event)             # registration order (contract, decision 3)
      impossible_travel (write-owner) → velocity / new_baseline (read-only)
  → Signal{Type: anomaly.SignalType* const}  # wire string, decision 2
  → Sink.Record (audit) + metric + ThreatExecutor
```

One acceptance-check defect was found and reconciled in this design: decision
3's acceptance grep includes `--include="*.md"`, but the stale path string is
quoted inside the intent records this same spec says are *not* rewritten (the
spec itself, the tenant-dimension spec, `docs/architect-analysis/auto/domains-anomaly-analysis.md`,
`docs/proposals/requirements.md`). The executable acceptance must therefore be
scoped to `*.go`; see "What could break the design" item 1.

---

## Decision: delete the dead subtree `domains/anomaly/{detect,signature,fingerprint}`

**What.** `git rm` the three subpackages — `detect/` (five detectors + feature
aggregator), `signature/` (a third, parallel storage SPI), `fingerprint/` (a
device-fingerprint helper) — including their test files. `defaultimpl/detectors`
is the sole reference implementation; it is untouched (its package doc,
`impossible_travel.go:1-10`, already states the composition model).

**Why.** Two implementations emitting the same wire-stable `Signal.Type` keys
with different thresholds and evidence schemas is contract drift on exactly the
strings operators branch on in SIEM rules and dashboards. The subtree also
couples every future `RecentLoginStore`/`IPFailureCounter` SPI change to a
mechanical update of compiled-but-unreachable code — proven once already
(`docs/proposals/design.md:21` records that the v2 store migration had to
account for it). Deletion is the convergence; keeping it and merely documenting
"don't use this" leaves the trap for SDK embedders, since `WithAnomalyRunner`
(`interfaces/sso/options_misc.go:233-243`) accepts any `anomaly.Detector` and
the subtree's package doc presents itself as official.

**API surface.**

- Removed exported surface (the complete list, from the tree):
  - `detect`: `CredentialStuffingDetector` + `CredentialStuffingConfig` +
    `DefaultCredentialStuffingConfig`, `FeatureAggregator` +
    `NewFeatureAggregator`, `NewCountryDetector` + `NewCountryConfig` +
    `DefaultNewCountryConfig`, `NewDeviceDetector` + `NewDeviceConfig` +
    `DefaultNewDeviceConfig`, `VelocityDetector` + `VelocityConfig` +
    `DefaultVelocityConfig` (all five implement `anomaly.Detector`).
  - `signature`: `Store` interface (`Record`/`Seen`/`DistinctCount`/`PruneOlder`),
    `Entry`, `MemoryStore` + `NewMemoryStore`. `DistinctCount` has zero callers
    anywhere (`signature/store.go:30`; only `signature/memory_test.go`).
  - `fingerprint`: `Input`, `Derive`.
- No replacement API and no new package: `defaultimpl/detectors` already
  covers the same detection space with the production thresholds, evidence
  schemas, and wire names.
- Zero in-repo importers (grep of every `*.go` under the root module *and* the
  nested modules: only intra-subtree imports at `detect/feature_aggregator.go:11-12`,
  `detect/new_country.go:8`, `detect/new_device.go:8-9`). `detect/` has zero
  test files; the only tests are `signature/memory_test.go` and
  `fingerprint/device_fingerprint_test.go`, which test dead support code.
- No config surface: `config/config_anomaly.go` references only the
  `defaultimpl/detectors` constructors (impossible_travel, velocity,
  new_device, new_country, brute_force_shadow); the `detect/` config structs
  are never wired.
- `interfaces/sso` is untouched (60-file ceiling preserved); `go list
  ./domains/anomaly/...` collapses from four packages to one.

**Storage model.**

- The subtree owns a **third** storage SPI — `signature.Store` — parallel to
  `RecentLoginStore` and `IPFailureCounter`, with only a `MemoryStore`
  implementation and no durable backend. Deleting it removes a storage
  contract that never had a production consumer.
- Production storage is untouched: `RecentLoginStore` + `IPFailureCounter`
  (memory + sqlite backends) keep their schemas, indexes, and retention
  semantics. No SQLite migration, no `maxversions.go` change, no salt change —
  none of the tenant-dimension design's storage mechanics apply here.
- The retention loop (`PruneOlder` scheduling) is direction #3's separate spec;
  this change neither wires nor alters it.

**Failure modes.**

| Failure | Behavior | Class |
|---|---|---|
| A file elsewhere imports the subtree that grep missed (build tags, generated code) | `go build ./...` fails loudly in CI; the acceptance grep is the first tripwire | fail-closed, immediate |
| Out-of-repo SDK embedder imported the subtree | Their build breaks on upgrade | documented API removal: single initial-wave commit (`d3c0f4be`), never referenced by any docs or wiring, superseded before first release; release-note it |
| Claimed test coverage loss | `signature/memory_test.go` + `fingerprint/device_fingerprint_test.go` tested dead support code only; live detectors keep their full test suites (`defaultimpl/detectors/*_test.go`, unchanged) | none |
| Nested modules (`cmd/sso-mcp`, `cmd/sso-operator`, `infrastructure/{kms,saml,ldap,kerberos,radius,extauthz,kafka,mqtt}`) import the subtree | Verified: zero imports; `make ci` module validation re-proves it | none |

**Acceptance.** `grep -rn "domains/anomaly/detect\|domains/anomaly/signature\|domains/anomaly/fingerprint" --include="*.go" .` → empty; `go build ./... && go vet ./...`; maintainability + architecture gates; `go test ./domains/anomaly/... ./infrastructure/defaultimpl/detectors/...`; `go list ./domains/anomaly/...` shows only the domain package; `make ci`.

---

## Decision: single source of truth for wire-stable `Signal.Type` constants

**What.** New `domains/anomaly/consts.go` defining the five wire strings as
untyped string constants, each with the wire-stability warning (renaming
silently breaks operator dashboards and SIEM rules):

```go
const (
    SignalTypeImpossibleTravel = "impossible_travel"
    SignalTypeVelocity         = "velocity_burst"
    SignalTypeNewDevice        = "new_device"
    SignalTypeNewCountry       = "new_country"
    SignalTypeBruteForceShadow = "brute_force_shadow"
)
```

`infrastructure/defaultimpl/detectors` keeps its exported `DetectorType*`
constants as **aliases** (`const DetectorTypeVelocity = anomaly.SignalTypeVelocity`)
so embedder imports keep compiling; all emission sites already reference the
constants, never literals. The deleted subtree's `credential_stuffing` name is
not re-registered (its emitter dies with decision 1).

**Why.** The domain type these strings label (`anomaly.Signal.Type`, documented
as a stable wire string at `types.go:112-114`) has no constants, while the
normative values live private-to-implementation in `defaultimpl/detectors` —
and until decision 1, a second implementation emitted the same names from
different logic (`velocity_burst`, `new_device`, `new_country` collided
byte-for-byte; `credential_stuffing` was a semantic twin of
`brute_force_shadow`). Domain-owned constants make the five names a reviewable,
importable contract: any future detector (official or embedder-supplied) that
re-introduces a near-colliding literal is now visibly wrong at review time
instead of silently drifting.

**API surface.**

- New file `domains/anomaly/consts.go` (AGENTS.md consts.go discipline);
  `domains/anomaly` non-test files go 7 → 8, under the 10-file budget.
  Constants are **untyped** strings so `Signal{Type: anomaly.SignalTypeVelocity}`
  and the alias `DetectorTypeVelocity` remain interchangeable with today's
  literals (no typed-string conversion surface for embedders).
- `DetectorType*` aliases: `DetectorTypeImpossibleTravel`,
  `DetectorTypeVelocity`, `DetectorTypeNewDevice`, `DetectorTypeNewCountry`,
  `DetectorTypeBruteForceShadow`. `Name()` methods and emission sites are
  unchanged in behavior (they already return the constants).
- The five drift-guard tests that assert constants against literals
  (`impossible_travel_test.go:325`, `velocity_test.go:201`,
  `new_baseline_test.go:172,296`, `brute_force_shadow_test.go:216`) stay and
  become the value-level tripwire for any future rename. Detector test suites
  are otherwise untouched.
- Comment update (one line) at `types.go:112-114` pointing `Signal.Type`'s doc
  at the new constants, so the field doc and the constants cannot drift.
- **`domains/threataction` is deliberately NOT aliased.** Its `Threat*`
  constants (`threataction.go:105-112`) hold the same values for the four
  shared names, and its comment already states why it cannot import
  `domains/anomaly`: the runner bridge (`domains/anomaly/runner.go` imports
  `threataction`) would make that a cycle. They are a separate namespace for
  policy matching; the runner copies `a.Type` → `Threat.Type` verbatim. A
  cross-package equality test (test-only, one table: `anomaly.SignalType* ==
  threataction.Threat*` for the four overlapping names) prevents silent drift
  without coupling the packages. Pre-existing adjacent inconsistency, noted
  not fixed: `ThreatBruteForce = "brute_force_spray"` differs from
  `SignalTypeBruteForceShadow` — they name different threat producers
  (tokenanomaly vs the shadow detector) and policy matching uses prefix rules.

**Storage model.** None. The constants label metric dimensions
(`sso_anomalies_detected_total{anomaly_type=...}`), the audit `Reason`, and the
threat `Type` — no storage schema, index, or migration is touched, and
cardinality is unchanged (the same five values, now defined once). The collision
removal's storage-side effect is the disappearance of the parallel
`signature.Store` evidence schema for the same wire names (decision 1).

**Failure modes.**

| Failure | Behavior | Class |
|---|---|---|
| A future detector emits a raw-string `Type:` literal | Inside `defaultimpl/detectors`: the acceptance grep catches it. Elsewhere: review-time visibility — the domain constants are now the obvious import; the colliding-literal pattern is visible against a five-name namespace | fail-closed by review; grep covers the reference impl |
| Rename of a constant *value* (not identifier) | The drift tests (`... != "velocity_burst"` etc.) fail loudly | fail-closed, test-enforced |
| `threataction.Threat*` drifts from `SignalType*` | Equality test fails (if adopted); otherwise the runner bridge copies `a.Type` verbatim, so the *emitted* threat type is always the detector's wire string — policy `Match` still works on it; only hand-constructed threats could diverge | fail-open, observable in review |
| Alias removal (someone "simplifies" `DetectorType*` away) | Embedder compile break — the aliases are the compatibility contract; the acceptance grep (`DetectorType*` alias declarations referencing `anomaly.SignalType*`) is the tripwire | fail-closed, grep-enforced |

**Acceptance.** `grep -rn 'Type:\s*"' infrastructure/defaultimpl/detectors/` →
empty; `DetectorType*` declarations are aliases of `anomaly.SignalType*`;
detector unit tests unchanged and green; `go build ./... && go vet ./...`;
`make ci`.

---

## Decision: fix the reference-pointer drift and codify the detector ordering/write-ownership contract

**What.** Two doc corrections plus one documented contract, zero production
code changes outside comments:

1. `domains/anomaly/runner.go:13` — replace the nonexistent
   `infrastructure/defaultimpl/anomaly` path with the real canonical package
   `infrastructure/defaultimpl/detectors`.
2. Same package doc block states the ordering/write-ownership contract: (a)
   detectors are processed in **registration order** (`NewRunner` stores the
   slice as given, `options.go:122-134`; `Runner.inspect` iterates it); (b)
   **exactly one write-owning detector** — the impossible-travel detector —
   must be registered **before** any read-only history consumers (velocity,
   new-device, new-country), because it is the only writer of
   `RecentLoginStore` (`impossible_travel.go` "SHIPS WRITES TOO"; the others
   are read-only per `velocity.go:21-26`); (c) omitting the write-owner
   silently disables the read-only consumers — a **documented composition
   constraint, not a runtime error**, consistent with the package's fail-open
   async philosophy.
3. One comment at `cmd/sso-server/anomaly.go` `buildAnomalyDetectors`
   (impossible-travel appended first) pointing back at the runner doc contract.
4. The known `inspectTimeout` caveat is recorded in the same doc block: the
   timeout is a **per-event budget shared by all detectors** in the sweep
   (`runner.go` `inspect` creates one `context.WithTimeout` before the loop),
   not per-detector as the field comment implies; a slow detector consumes
   siblings' budget. Recorded only — no code change.

**Why.** The stale pointer is verified drift (`ls infrastructure/defaultimpl/`
shows no `anomaly` directory; the detectors live in `detectors/`). The order is
genuinely load-bearing — velocity/new-baseline read history that only
impossible-travel writes (verified: `impossible_travel.go:179` is the *only*
production `Append` caller of `RecentLoginStore`; omit the write-owner and the
store is never written) — and today it is enforced by nothing: the
`buildAnomalyDetectors` builder order is silently load-bearing, and
`WithAnomalyRunner` invites embedders to compose "any subset" without stating
the constraint. With the dead subtree gone, the runner package doc is the one
place the contract can be discovered without reading one detector's source.

**API surface.** None — `Detector`, `Runner`, `NewRunner`, `Dispatch`,
`Inspect`, and the option knobs are unchanged. This is a documentation
contract, which is why it must live in the package doc (the discoverable
surface for `WithAnomalyRunner` embedders) rather than in a detector's
internal comment.

**Storage model.** None. The contract describes the write path into
`RecentLoginStore` (who appends, who only reads) — it changes no schema,
index, or store interface. Sequencing note: this contract is what the
tenant-dimension design's tenant-scoped store signatures will be layered on
top of; the two changes are orthogonal (decision 3 edits comments, the tenant
change edits signatures) but should land in that order (see "What could break
the design" item 2).

**Failure modes.**

| Failure | Behavior | Class |
|---|---|---|
| Embedder registers velocity/new-baseline without impossible-travel | Read-only consumers see empty history → silent no-signal; now discoverable in the runner doc (documented constraint, no runtime error, per fail-open philosophy) | documented limitation |
| Embedder reorders the slice (write-owner after the consumers) | In-sweep effect only: the consumers' `Recent` reads run before the current event is appended, so their counts exclude it — exactly the model `countWindows`'s unconditional `+1` assumes (`velocity.go` countWindows comment: "impossible-travel appends after Inspect"). Cross-sweep history is unaffected (the append lands before the next sweep). Mirror quirk, pre-existing and untouched: the *production* order (write-owner first, `buildAnomalyDetectors`) means the store already contains the current event when velocity reads, so the `+1` over-counts it by one — a constant bias that shifts the effective threshold down by one attempt (fires at `limit` real attempts in the window instead of `limit+1`). Do not "fix" the `+1` in this spec; zero behavior change is the contract | documented limitation (the spec fixes the contract text: write-owner registered *before* read-only consumers) |
| Embedder registers two write-owners | Duplicate appends → each event appears twice in history; `Recent` (bounded by limit) covers half the time span → truncated windows and inflated velocity counts | documented constraint: "exactly one write-owning detector" |
| `buildAnomalyDetectors` builders reordered in a future refactor | Same silent degradation; the new comment at the wiring is the review-time tripwire | documented limitation |
| `inspectTimeout` shared-budget misread | A slow detector starves siblings' time in the same sweep; now recorded in the package doc as a known limitation | documented limitation (no code change per spec) |

**Acceptance.** `grep -rn "defaultimpl/anomaly" --include="*.go" .` → empty
(the executable form; see item 1 of "What could break the design" for why the
`*.md` variant is unsatisfiable); runner package doc names
`infrastructure/defaultimpl/detectors`, states registration-order processing,
the write-ownership rule, and the read-only dependency; `buildAnomalyDetectors`
carries the ordering comment; `go test ./domains/anomaly/...
./infrastructure/defaultimpl/detectors/... -count=1` green with zero production
code changes outside comments; `go build ./... && go vet ./...`; `make ci`.

---

## What could break the design

1. **Decision 3's `--include="*.md"` acceptance grep is unsatisfiable as
   written.** The stale path string appears in the intent records this spec
   itself declares not rewritten: the spec
   (`docs/requirements/domains-anomaly-detect-convergence.md:103,117,129`), the
   tenant-dimension spec (`:115`), `docs/architect-analysis/auto/domains-anomaly-analysis.md:21`,
   and `docs/proposals/requirements.md:12`. Executable acceptance must be
   `--include="*.go"` (which returns nothing after the runner doc fix); the
   markdown mentions are historical evidence of the defect, not live pointers.
   Do not rewrite intent records to satisfy the literal grep.
2. **Sequencing with the tenant-dimension change (both touch the same
   packages).** The tenant design's compile-break inventory explicitly includes
   the dead `detect/` package ("must get the same mechanical tenant-threading
   as the live detectors"). If this convergence lands **first**, that
   obligation disappears — the deletion removes the only parallel implementation
   that would need mechanical SPI updates. Landing tenant-dimension first makes
   the `detect/` update throwaway work. Both also edit `domains/anomaly`
   (`consts.go` here vs `TenantID` fields there) — additive and conflict-free.
   Recommendation: convergence first, tenant dimension second, retention third.
3. **Out-of-repo embedder break (public module API removal).** The subtree is
   exported Go surface in a public SDK module, and `WithAnomalyRunner` accepts
   any `anomaly.Detector`; an embedder who found and wired the
   "official-looking" `detect` package breaks at build time. Mitigation: zero
   in-repo importers, a single initial-wave commit (`d3c0f4be`) predating the
   reference implementation, no documentation or config referencing it, and a
   release note. This is the *point* of the change (the trap is being removed),
   not a regression in shipped behavior.
4. **`threataction` constant drift.** The four shared wire names live in two
   packages that cannot alias each other (import cycle through the runner
   bridge). The runner copies `Signal.Type` verbatim into `Threat.Type`, so
   emitted threats always carry the detector's wire string and policy matching
   stays correct even if the `Threat*` constants drift; the risk is confined to
   hand-constructed threats in tests/admin code. The optional equality test
   closes it. Do not attempt to unify the namespaces — that is a domain-graph
   change, out of scope.
5. **Docs-only ordering contract can be silently violated later.** No runtime
   enforcement exists (deliberate: the spec fixes the contract as a documented
   composition constraint under the fail-open philosophy). A future refactor of
   `buildAnomalyDetectors` (e.g., sorting builders alphabetically) or an
   embedder composing detectors from docs alone can reintroduce the silent
   degradation. The runner package doc + wiring comment are the tripwire; a
   startup assertion or `NewRunner` validation was considered and rejected as a
   behavior change the spec explicitly excludes.
6. **`DetectorType*` alias removal.** An "unused constant" cleanup could delete
   the aliases (embedder compat surface). The acceptance grep on alias
   declarations guards it; the drift tests guard the values. No `go vet`
   failure occurs for exported constants, so this is review-enforced.
7. **Test-suite churn illusion.** Decision 2's acceptance requires detector
   tests "unchanged and green" — the five drift-guard tests *assert raw
   literals* and must stay (they are the value tripwire); "unchanged" means
   no assertion edits, which is exactly what the alias preserves.
8. **Budget/exemption risk.** `domains/anomaly` gains one non-test file
   (8/10 — fine); `interfaces/sso` untouched (60-file ceiling); no
   `layerExemptions` entry; no new top-level package (the `layerName()`
   classification table is untouched). Deletion can only shrink gate
   surface.

## Verification and gates

| Gate | Command | When |
|---|---|---|
| G1 | `go build ./... && go vet ./...` | after every `.go` edit (AGENTS.md §2) |
| G2 | `go test -run 'TestMaintainability_|TestArchitecture_' .` | after every `.go` edit |
| G3 | `go test ./domains/anomaly/... ./infrastructure/defaultimpl/detectors/... -count=1` | after every `.go` edit touching these packages |
| G4 | `go test ./... -race` | handoff |
| G5 | `go test ./test/ -run TestE2E -v` | handoff |
| G6 | `make ci` | handoff |

Regression tests (all encode target behavior; none should be red against the
pre-change tree except the greps — this is a zero-behavior-change design):

- **T1 (dec. 1)**: grep — no `*.go` file references the three subtree paths;
  `go list ./domains/anomaly/...` yields exactly one package.
- **T2 (dec. 2)**: grep — no raw-string `Type:` emission in
  `infrastructure/defaultimpl/detectors/`; alias declarations reference
  `anomaly.SignalType*`; existing drift tests (literal-vs-constant assertions)
  stay green.
- **T3 (dec. 2, optional)**: cross-package equality — `anomaly.SignalType* ==
  threataction.Threat*` for the four shared names (test-only; add only if the
  maintainers accept the extra assertion, since it is outside the spec's
  letter).
- **T4 (dec. 3)**: grep `defaultimpl/anomaly` over `*.go` → empty; runner
  package doc contains `defaultimpl/detectors`, registration-order, and
  write-ownership statements; `buildAnomalyDetectors` has the ordering comment.

Contract updates in the same change (AGENTS.md §5): none of the public
contracts (OpenAPI, config-reference, error-codes) are touched — the constants
are internal Go identifiers over the same wire strings, and the deleted subtree
was never a documented contract. Embedder-facing SPI docs updated: runner
package doc (decision 3), `Signal.Type` field doc (decision 2, one line),
`consts.go` (new). `docs/config-reference.md` is unaffected (the retention
knobs' documentation belongs to the retention spec). Release notes must call
out the deleted subtree for out-of-repo embedders.
