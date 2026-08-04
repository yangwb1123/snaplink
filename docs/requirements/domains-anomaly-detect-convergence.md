# Requirements Spec: domains/anomaly — Detector Convergence

> Expansion direction (from `docs/architect-analysis/auto/domains-anomaly-analysis.md` #2):
> 收敛重复的检测器实现：`domains/anomaly/detect/` 是零引用的死代码且与线上实现线类型撞名。
> Exactly three evidence-backed improvements; scope is the detector-implementation
> convergence contract only. Direction #1 (tenant dimension) is specified in
> `docs/requirements/domains-anomaly-tenant-dimension.md` and explicitly lists this
> convergence as its own non-goal; direction #3 (unwired retention loop) is a
> separate spec.

Problem class: the repository carries two parallel detector implementations. The
production one is `infrastructure/defaultimpl/detectors/` (impossible_travel,
velocity, new_baseline, brute_force_shadow), wired by `cmd/sso-server/anomaly.go`
`buildAnomalyDetectors`. The other is `domains/anomaly/detect/` (NewDeviceDetector,
NewCountryDetector, CredentialStuffingDetector, VelocityDetector, FeatureAggregator)
plus its two support subpackages `domains/anomaly/signature/` and
`domains/anomaly/fingerprint/` — zero imports outside the subtree, no tests, a
single initial-wave commit in history, and it emits `Signal.Type` wire names that
collide with the production detectors' wire-stable names. Two implementations
with the same metric-label/SIEM-branch keys but different thresholds and evidence
schemas is contract drift; the dead subtree also couples every future
`RecentLoginStore`/`IPFailureCounter` SPI change to a mechanical update of code
nothing runs (proven once already, see decision 1 evidence).

## 1. Delete the dead detector subtree `domains/anomaly/{detect,signature,fingerprint}`

**Name**: Dead-subtree removal; `defaultimpl/detectors` becomes the sole
reference implementation.

**Problem**: Three subpackages implement detectors, a signature store, and a
device-fingerprint helper that no production or test code outside the subtree
imports. They consume `anomaly.Detector`/`RecentLoginStore`/`IPFailureCounter`
SPIs whose signatures are still evolving (the v2 migration changed both stores),
so every SPI change forces a mechanical update of compiled-but-unreachable code —
or `go build ./...` breaks. Keeping them also makes "which implementation is
real?" a permanent trap for SDK embedders, since the subtree's package doc
(`detect/feature_aggregator.go:1-2`, "implements anomaly detectors ... for the
anomaly runner") presents it as official, and `WithAnomalyRunner`
(`interfaces/sso/options_misc.go:233-243`) is public API that accepts any
`anomaly.Detector`.

**Evidence**:
- Repo-wide grep: `grep -rn "domains/anomaly/detect\|domains/anomaly/signature\|domains/anomaly/fingerprint" --include="*.go" .` matches only intra-subtree imports (`detect/feature_aggregator.go:11-12`, `detect/new_country.go:8`, `detect/new_device.go:8-9`). No importer in `cmd/`, `interfaces/`, `infrastructure/`, `test/`, or `shared/`.
- `find domains/anomaly/detect -name '*_test.go'` → empty. Zero tests for the five detector types; only `signature/memory_test.go` and `fingerprint/device_fingerprint_test.go` test dead support code.
- `docs/proposals/design.md:21` — "the dead `domains/anomaly/detect/` package still compiles against the changed interfaces and must be mechanically updated, or `go build ./...` fails" (the design review for the v2 store migration had to account for it).
- `signature.Store.DistinctCount` (`domains/anomaly/signature/store.go:30`) has no callers outside the subtree; `git log --oneline -- domains/anomaly/detect` shows a single commit (`d3c0f4be`, initial wave) predating the replacement wired at `cmd/sso-server/anomaly.go:258-349`.
- `cmd/sso-server/anomaly.go:15-16,299-347` — production wiring imports `infrastructure/defaultimpl/detectors` exclusively; no config key references the `detect/` constructors' config structs.

**Proposed behavior**:
- Delete the three directories (`detect/`, `signature/`, `fingerprint/`) including their test files.
- Leave `infrastructure/defaultimpl/detectors/` untouched functionally; it is already the unique reference implementation (its own package doc, `impossible_travel.go:1-10`, already states the composition model).
- No new package, no budget or `layerExemptions` change; `interfaces/sso` (60-file ceiling) is untouched. Historical proposal docs (`docs/proposals/*`, `docs/requirements/*`) are intent records and are not rewritten.

**Acceptance check**:
- `grep -rn "domains/anomaly/detect\|domains/anomaly/signature\|domains/anomaly/fingerprint" --include="*.go" .` returns nothing.
- `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .` pass.
- `go test ./domains/anomaly/... ./infrastructure/defaultimpl/detectors/...` green; `make ci` green (nested modules, config, module validation unaffected).
- `go list ./domains/anomaly/...` shows only the domain package itself (no subpackages).

## 2. Single source of truth for wire-stable `Signal.Type` constants

**Name**: Hoist `SignalType*` constants into `domains/anomaly`; implementation
packages alias them.

**Problem**: `Signal.Type` is the stable wire key used as a metric label and as
the branch key in operator SIEM rules; the production detectors document it as
wire-stable ("renaming silently breaks operator dashboards"). Today the
normative values exist only as private-to-implementation constants in
`infrastructure/defaultimpl/detectors/`, while the domain type they label
(`anomaly.Signal`) has no constants at all — and the dead subtree emits the same
names from different logic. Two implementations sharing one wire name with
different thresholds/evidence is exactly the drift the wire-stability comment
warns about; the deletion in decision 1 removes the collision, but without
domain-owned constants nothing prevents a future detector (official or
embedder-supplied) from re-introducing a colliding or near-colliding literal.

**Evidence**:
- Collision table (dead `detect/` vs. production `defaultimpl/detectors/`):
  - `detect/velocity.go:96` `Type: "velocity_burst"` vs. `velocity.go:15` `const DetectorTypeVelocity = "velocity_burst"`.
  - `detect/new_device.go:62` `Type: "new_device"` vs. `new_baseline.go:16` `DetectorTypeNewDevice = "new_device"`.
  - `detect/new_country.go:58` `Type: "new_country"` vs. `new_baseline.go:17` `DetectorTypeNewCountry = "new_country"`.
  - `detect/credential_stuffing.go:77` `Type: "credential_stuffing"` vs. `brute_force_shadow.go:16` `DetectorTypeBruteForceShadow = "brute_force_shadow"` — same semantics (per-IP spray across many subjects), different wire name.
- Wire-stability contract: `defaultimpl/detectors/velocity.go:12-14` ("wire-stable `[anomaly.Signal.Type]` ... renaming silently breaks operator dashboards") and `impossible_travel.go:25-27` ("Operators alerting on this detector branch on this string in their SIEM rules").
- `domains/anomaly/types.go:112-114` — `Signal.Type` documented as "stable wire string ... Used as a metric label — keep cardinality bounded", but no constants exist in the domain package; the string values live in the implementation layer.

**Proposed behavior**:
- Add `SignalTypeImpossibleTravel = "impossible_travel"`, `SignalTypeVelocity = "velocity_burst"`, `SignalTypeNewDevice = "new_device"`, `SignalTypeNewCountry = "new_country"`, `SignalTypeBruteForceShadow = "brute_force_shadow"` to `domains/anomaly` (new `consts.go` per AGENTS.md "put ... error codes in consts.go" discipline), each with the wire-stability warning comment.
- `infrastructure/defaultimpl/detectors` keeps its exported `DetectorType*` constants as aliases of the domain constants (`const DetectorTypeVelocity = anomaly.SignalTypeVelocity`) so existing embedder imports keep compiling; emission sites reference the constants, never string literals.
- The deleted subtree's names (`credential_stuffing` and any colliding ones) are not re-registered; decision 1 already removes their emitters.

**Acceptance check**:
- `grep -rn 'Type:\s*"' infrastructure/defaultimpl/detectors/` returns nothing (no raw-string emissions).
- `grep -rn "DetectorTypeVelocity\|DetectorTypeNewDevice\|DetectorTypeNewCountry\|DetectorTypeBruteForceShadow\|DetectorTypeImpossibleTravel" --include="*.go" infrastructure/defaultimpl/detectors/` shows alias declarations referencing `anomaly.SignalType*`.
- Detector unit tests (`infrastructure/defaultimpl/detectors/*_test.go`) unchanged and green; `go build ./... && go vet ./...` pass; `make ci` green.

## 3. Fix the reference-pointer drift and codify the detector ordering/write-ownership contract

**Name**: Correct `runner.go` package documentation; make the load-bearing
detector order an explicit contract.

**Problem**: Two documentation defects in the convergence area. (a)
`domains/anomaly/runner.go:13` claims "Reference detectors ship in
`.../infrastructure/defaultimpl/anomaly`" — that directory does not exist; the
canonical location is `defaultimpl/detectors/`. (b) The detector chain has an
implicit, load-bearing order: impossible-travel owns the history writes and
velocity/new-baseline are read-only consumers of those writes
(`defaultimpl/detectors/velocity.go:21-26`: "impossible-travel writes; velocity
is read-only ... Centralizing writes in impossible-travel keeps the SPI flat").
`Runner.Dispatch` (domains/anomaly/runner.go) fans out to whatever detector
slice the embedder registers, in registration order, with no stated ordering
rule — an embedder who reorders the list (or omits impossible-travel) gets
silently degraded or dead velocity/new-baseline detection with no error. With
the dead subtree gone, `defaultimpl/detectors` is the one place this contract
must be stated so future detectors and embedders follow it.

**Evidence**:
- `domains/anomaly/runner.go:13` — "Reference detectors ship in `github.com/yangwb1123/snaplink/infrastructure/defaultimpl/anomaly`"; `ls infrastructure/defaultimpl/` shows no `anomaly` directory (detectors live in `defaultimpl/detectors/`).
- `infrastructure/defaultimpl/detectors/velocity.go:21-26` — write-ownership invariant documented only as an informal comment on one detector ("(Centralizing writes in impossible-travel keeps the SPI flat and matches the 'writes too' invariant documented there.)").
- `cmd/sso-server/anomaly.go:258-349` — `buildAnomalyDetectors` appends impossible-travel first, then velocity/new-device/new-country; the order is load-bearing but nothing validates or documents it.
- `infrastructure/defaultimpl/detectors/impossible_travel.go:3` and `interfaces/sso/options_misc.go:233-243` — composition model is "operators wire any subset via `WithAnomalyRunner`", so the ordering rule must be discoverable from the runner's docs, not from reading one detector's source.

**Proposed behavior**:
- Fix `domains/anomaly/runner.go:13` to point at `infrastructure/defaultimpl/detectors` (the actual canonical package).
- In the runner package doc (same comment block), state the contract: (1) detectors are processed in registration order; (2) exactly one write-owning detector (the impossible-travel detector) must be registered before any read-only history consumers (velocity, new-baseline); (3) omitting the write-owner silently disables read-only consumers — this is a documented composition constraint, not a runtime error (consistent with the fail-open/async philosophy).
- Add a one-line comment at `cmd/sso-server/anomaly.go` `buildAnomalyDetectors` (the canonical wiring) pointing back at the runner doc contract. No behavior change: detectors, thresholds, and tests are untouched.
- Out of scope (noted, not fixed): `Runner.inspect`'s `inspectTimeout` is a per-event budget shared by all detectors (`domains/anomaly/runner.go:58-61,194`), not per-detector as the comment implies; a slow detector consumes siblings' budget. Record it as a known limitation in the same doc block only if the ordering rewrite touches that area — no code change.

**Acceptance check**:
- `grep -rn "defaultimpl/anomaly" --include="*.go" --include="*.md" .` returns nothing (stale pointer gone).
- `domains/anomaly/runner.go` package doc names `infrastructure/defaultimpl/detectors`, states registration-order processing, the write-ownership rule, and the read-only-consumer dependency.
- `grep -n "write" cmd/sso-server/anomaly.go` shows the ordering comment at `buildAnomalyDetectors`.
- `go test ./domains/anomaly/... ./infrastructure/defaultimpl/detectors/... -count=1` green with zero production-code changes outside comments; `go build ./... && go vet ./...` pass; `make ci` green.
