# Design: CRD types + manifest verification for `cmd/sso-operator` (DeepCopy round-trip + YAML↔Go parity)

Companion to `docs/architect-analysis/cmd-sso-operator-b4-3-crd-parity-requirements.md`.
This document treats that spec (and the direction it cites) as untrusted
evidence, records what was independently verified, and turns the requirements
into a concrete, ordered design with API changes, compatibility constraints,
failure modes, migration steps, and testable acceptance mapping.

## 1. Evidence verification verdict

Every citation was re-checked against HEAD (source files, Makefile, k8s.io/api
module cache, and a live throwaway test). One minor line-number drift found;
the central finding (D1) was empirically reproduced.

| # | Claim | Verdict |
|---|---|---|
| E1 | `apiv1alpha1/ssoconfigdrift_types.go` is exactly 255 lines, single non-test file, zero `_test.go` | Confirmed — `wc -l` = 255; `go test ./apiv1alpha1/` → `[no test files]` |
| E2 | YAML baseURL pattern `^https://.+` at lines 66/99; required clusterA/clusterB | Confirmed — pattern at 66 and 99; spec `required: [clusterA, clusterB]` at 51–53; endpoint requireds at 60–62/93–95; `bearerSecretRef` `required: [name, key]` at 77–79/102–104. The spec's own ~2-line drift correction is accurate |
| E3 | `Makefile:263` = `cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...` inside `ci-modules` (sso-mcp at 262) | Confirmed — exact line and text |
| E4 | Controller test 29–42: scheme registration is the only exercise of the types | **Corrected (minor line drift)** — actual: comment at 38–39, `func newScheme` at 40, `corev1.AddToScheme` at 43, `drift.AddToScheme(s)` at **46** (spec said 29–31/32–42/38–40). Substance confirmed: no DeepCopy or manifest assertions anywhere in the module |
| E5 | `DefaultPollInterval = "5m"` at types.go:21; controller fallback at 211–215; no `default:` key in YAML | Confirmed — const at line 21; fallback body at 211–213 (`time.ParseDuration(drift.DefaultPollInterval)`); grep for `default:` in the YAML: 0 hits |
| E6 | k8s.io/api@v0.36.0 `SecretKeySelector.DeepCopyInto` (zz_generated.deepcopy.go:5719–5728) copies `Optional`; HEAD `types.go:147–148` aliases it | Confirmed — source read at exactly 5719–5728 (`*out = new(bool); **out = **in`); HEAD has `*out = *in; out.BearerSecretRef = in.BearerSecretRef` |
| E7 | D1: `*copy.Spec.ClusterA.BearerSecretRef.Optional` flip fails on HEAD | **Empirically reproduced** — throwaway `zz_verify_d1_test.go` in the package: flipping the copy's `*Optional` left `reflect.DeepEqual(in, out)` true (mutation leaked). Test removed after the run; worktree clean |
| E8 | yaml.v3 v3.0.1 (go.mod:58 indirect, go.sum:146–147) and sigs.k8s.io/yaml v1.6.0 already in the nested module graph | Confirmed — both present; a `go.yaml.in/yaml/v3 v3.0.4` fork also sits in the graph but is irrelevant (we import `gopkg.in/yaml.v3`) |
| E9 | Baseline green; zero existing coverage of this surface | Confirmed — build OK, `go test -race -count=1 ./...` OK (controller 1.459s); repo-wide grep: no `.go` file references `crd-ssoconfigdrift`; CHECKS_REGISTRY: 0 hits for crd/operator/k8s |
| E10 | CRD identity block, status shapes, subresource, printer columns as enumerated in R3 | Confirmed — names/shortNames/scope/served/storage at YAML 10–34; status shapes at 118–129; `subresources.status: {}` and the three columns at 27–40 |

Net: no claim invalidates the scope. E4's line numbers drift by 6–8 lines
(cosmetic). D1 is real, benign today (nothing mutates `*Optional` — the
controller only reads `BearerSecretRef` at `ssoconfigdrift_controller.go:138,142`),
and exactly the ship-silent aliasing class the direction targets.

## 2. Scope and non-goals (unchanged from the spec)

- Surface: two new test files in `cmd/sso-operator/apiv1alpha1/` + one
  pinned 1-line production fix (D1a) in the same package.
- Non-goals: no controller/route/CRD-schema changes, no `default:` added to
  the YAML, no controller-gen, no changes to `doc.go`, `main.go`,
  `controller/*`, `Makefile`, the CRD YAML, or the root module.

## 3. API changes

### 3.1 Production change (the only one) — D1a

`cmd/sso-operator/apiv1alpha1/ssoconfigdrift_types.go:148`:

```go
// before
*out = *in
out.BearerSecretRef = in.BearerSecretRef
// after
*out = *in
in.BearerSecretRef.DeepCopyInto(&out.BearerSecretRef)
```

Restores the "exact mechanical shape controller-gen would emit" promise the
file's own doc comment makes (types.go:143–145). No other production line
changes. There is no public API surface change: same types, same fields,
same JSON tags, same scheme registration.

### 3.2 go.mod promotion

`gopkg.in/yaml.v3 v3.0.1` moves from the indirect require block (go.mod:58)
to the direct block after `go mod tidy` — same version, no go.sum additions
(hashes already at go.sum:146–147).

### 3.3 New test files (API in the test sense)

1. `cmd/sso-operator/apiv1alpha1/ssoconfigdrift_types_deepcopy_test.go`
   (`package v1alpha1`, white-box) — R1 + R2.
2. `cmd/sso-operator/apiv1alpha1/ssoconfigdrift_crd_parity_test.go`
   (`package v1alpha1`) — R3, parses `../crd-ssoconfigdrift.yaml`.

### 3.4 Internal design decisions (sharper than the spec where it was silent)

- **Reflection key-set derivation (R3 property sets).** One precise rule, no
  exceptions-by-observation: walk every exported field; skip `json:"-"` and
  unexported fields; the JSON name is the tag text before the first comma,
  falling back to the Go field name when empty (encoding/json semantics);
  **inline embeds (empty JSON name) are recursed/flattened, EXCEPT the three
  metadata types which are skipped by type name — `TypeMeta`, `ObjectMeta`,
  `ListMeta`** — while **named embeds are single keys** (`ObjectMeta` is
  `json:"metadata,omitempty"`). This one rule covers both cases the spec
  split: TypeMeta (`json:",inline"`) is skipped by type name, and the
  `bearerSecretRef` block recurses into `corev1.SecretKeySelector`'s inline
  `LocalObjectReference` (verified `json:",inline"` at
  k8s.io/api@v0.36.0 core/v1/types.go:2586) whose `name` is a first-class
  property there. The exclusion is a **pin to the hand-maintained YAML
  shape** (it has no `metadata`/`apiVersion`/`kind` root properties), NOT a
  Kubernetes convention: controller-gen-generated CRDs do emit those root
  keys, so wiring controller-gen in later is expected to trip this
  assertion by design. The YAML side of the walk reads only `properties`
  nodes (never `description`/`type`/`required`). Sets are compared in both
  directions (`goKeys − yamlKeys == ∅` and `yamlKeys − goKeys == ∅`) so a
  rename on either side fails loudly.
- **Required-list assertions are explicit literals, not derived.** Deriving
  required-ness from `omitempty` fails for `bearerSecretRef.name`
  (`LocalObjectReference.Name` is `json:"name,omitempty"` yet required in
  the manifest). The test asserts the literals `[clusterA, clusterB]`,
  `[baseURL, bearerSecretRef]`, `[name, key]` with comments citing the
  `+kubebuilder:validation:Required` markers at types.go:34/46/54/60/65.
- **YAML decoding.** `gopkg.in/yaml.v3` into `map[string]interface{}` (nested
  maps decode as `map[string]interface{}`); a typed struct for the identity
  block (`metadata.name`, `spec.group`, `spec.names`, `spec.scope`,
  `spec.versions[0]` served/storage) keeps the identity assertions readable,
  and a generic map walk covers the schema tree. `versions` is asserted to
  have exactly one entry before indexing.
- **`subresources.status: {}` assertion** (NOT the schema `status` node,
  which has five properties). yaml.v3 decodes the empty mapping to an empty
  `map[string]interface{}`; assert non-nil and `len == 0`.
- **CWD assumption.** `go test` runs each package with CWD = package source
  dir (documented Go behavior), so `../crd-ssoconfigdrift.yaml` is stable
  under the `Makefile:263` gate command.
- **Test layout.** Round-trip equality, nil-shape, and DeepCopyObject
  concreteness in one file; mutation isolation as a table-driven test with
  per-region subtests (ObjectMeta maps/slices, Items slice append + element
  overwrite, ListMeta pointer, Spec fields incl. the D1 `Optional` flip,
  Status `metav1.Time`); registration checks in the same file.
- **Tripwires vs canaries in the mutation table.** Only writes THROUGH a
  shared reference can detect aliasing: map writes (`copy.Labels[k] = v`),
  element/field writes into a shared backing array
  (`copy.Items[0].Spec... = ...`, `copy.OwnerReferences[0].UID = ...`,
  `copy.ManagedFields[0] = ...`), and dereference writes
  (`*copy.ListMeta.RemainingItemCount = ...`, the D1
  `*copy.Spec.ClusterA.BearerSecretRef.Optional` flip). Slice `append`
  forms (Items, Finalizers) and whole-value assignments
  (`Status.LastCheckedAt`, `SpecClusterB.Key`) are CANARIES: appending to
  the copy never changes the source's `[0:len)` view even when the backing
  array is shared (it either reallocates or writes past the source's
  length), and struct-value assignment replaces the copy's field outright.
  The aliasing tripwire rows must therefore be the map/element/dereference
  writes; keep the append rows as length-growth shape canaries only.

## 4. Compatibility constraints

- **DeepCopy semantics are behavior-neutral for every existing caller.**
  `*out = *in` still runs first, so value fields and the
  `LocalObjectReference` copy are byte-identical; only the `Optional *bool`
  pointer gains isolation. Verified: the controller only *reads*
  `BearerSecretRef` (resolveBearer at `ssoconfigdrift_controller.go:138,142`);
  no code anywhere mutates `*Optional`, so no caller can observe a change.
- **Compile-time coupling.** The fix calls
  `corev1.SecretKeySelector.DeepCopyInto`, generated and stable across
  k8s.io/api versions; if a future dependency bump ever removed it, the
  module fails to compile (loud failure, not silent drift). Pinned at
  v0.36.0 in the nested go.mod.
- **Manifest and const contracts untouched.** The YAML stays hand-maintained
  and unmodified; `DefaultPollInterval = "5m"` stays the single source of
  the fallback; no `default:` key is introduced (the Go-side fail-open
  default is a deliberate design, mirrored from platform/configaudit/drift).
- **Module graph.** No new module paths; yaml.v3 promoted indirect→direct
  with zero version change; `go.yaml.in/yaml/v3` fork and sigs.k8s.io/yaml
  remain indirect. Root `go.mod`/`go.sum` untouched.
- **Gate boundaries.** Root gates (`go build ./...`, `TestMaintainability_|TestArchitecture_`) do not descend into nested modules; `ci-modules` (`Makefile:263`) is the detection boundary, same as every other nested module.
- **No wire/security surface.** No routes, `Err*`, config keys, audit
  events, credential handling, or SSRF surface; oracle-safe response tables
  unaffected. `python cli.py modules check` unaffected.
- **Worktree hygiene.** Unrelated modified files already present in the
  worktree are preserved untouched; the change touches only the two test
  files, one types.go line, and go.mod.

## 5. Failure modes

| Failure mode | Detection | Severity |
|---|---|---|
| Future hand-edit reintroduces aliasing in any DeepCopyInto (Optional, ObjectMeta maps, Items slice, ListMeta pointer) | R1 mutation-isolation subtests fail under `go test -race` — the map-write, element-overwrite, and dereference-write rows (append/whole-value rows are canaries and do not trip) | Catches the exact class D1 exemplifies |
| Field renamed/added/removed in Go structs without mirroring YAML (or vice versa) | R3 both-direction key-set comparison fails | Tripwire for the hand-maintained lockstep contract |
| baseURL pattern, required lists, or pollInterval optionality drift in YAML | R3 literal assertions fail | Admission-time schema drift caught in CI |
| Someone adds a `default:` for pollInterval to the YAML | R3 "no default key" assertion fails | Pins "default lives in Go" design |
| `DefaultPollInterval` const renamed/changed | R3 `DefaultPollInterval == "5m"` fails | Pins the controller-visible fallback |
| Status shapes/format drift (date-time, int64) | R3 shape assertions fail | Kubernetes API-conversion drift |
| Printer columns or subresource removed/changed | R3 columns/subresource assertions fail | UX + status-write contract drift |
| Scheme registration regressions (GroupVersion, kind names) | R2 `Recognizes`/`ObjectKinds`/`GroupVersion` fail | Controller-runtime client breaks |
| DeepCopy nil-shape regression (nil Items → empty slice, nil receiver panics) | R1 shape assertions fail | controller-runtime `DeepCopyObject` paths |
| yaml.v3 version bump with breaking decode | go.mod pin; decode panics fail the test loudly | Low (pinned) |
| Test run from wrong CWD | `../crd-ssoconfigdrift.yaml` open fails | Not a real mode: `go test` always runs in the package dir; the gate command is fixed |
| D1a itself misapplied | Test `TestDeepCopy_MutationIsolation/Spec` fails pre-fix, passes post-fix | The intended tripwire; one-line revert restores HEAD exactly |

## 6. Migration steps (ordered)

1. **Land the two test files first, on unmodified types.go.** Run
   `cd cmd/sso-operator && go test -race -count=1 ./apiv1alpha1/` — exactly
   the Spec-isolation case fails (case 14's pre-fix evidence, reproducible
   today; D1 was independently reproduced during this review). This is the
   tripwire demonstration, not a commit checkpoint.
2. **Apply D1a** (the one-line `types.go:148` change).
3. **`cd cmd/sso-operator && go mod tidy`** — promotes yaml.v3
   indirect→direct. Verify only the yaml.v3 line moved from the indirect
   block to the direct block at the same version (v3.0.1) and that no
   yaml.v3 lines were added to `go.sum` — **do not judge the diff against a
   clean checkout**: the worktree `go.mod`/`go.sum` already carry the
   sibling path-parity edits (root-module `replace`/`require` and version
   bumps), and those hunks must remain untouched (AGENTS.md worktree
   discipline). The promotion is MVS-safe: the root module has no
   `gopkg.in/yaml.v3` requirement, so the sibling's root-module require
   cannot bump it.
4. **Run the full gates**:
   ```bash
   cd cmd/sso-operator && go build ./... && go vet ./...
   cd cmd/sso-operator && go test -race -count=1 ./...        # Makefile:263 gate
   cd cmd/sso-operator && go test -race -count=1 ./apiv1alpha1/ -v
   go build ./... && go vet ./...                             # root, unchanged
   go test -run 'TestMaintainability_|TestArchitecture_' .    # root gates
   python cli.py modules check
   make ci                                                    # full handoff gate
   ```
5. **Commit** — conventional, imperative ("test: pin sso-operator CRD
   deepcopy and manifest parity"), body explains the D1 aliasing find, add
   AI co-author trailer. No binaries. Do not touch unrelated worktree
   modifications.
6. **Rollback** — reverting the single types.go line restores HEAD behavior
   byte-for-byte while the new tests fail (the designed tripwire). Test
   files are additive and safe to revert independently.

## 7. Testable acceptance mapping

All 14 spec cases map to named Go tests under the `Makefile:263` gate
(`cd cmd/sso-operator && go test -race -count=1 ./...`). Cases 1–6 are
net-new coverage for a package with zero tests today; 7–13 are net-new
manifest-parity coverage (nothing parses the CRD YAML repo-wide); 14 is the
single bounded production change.

| Case | Given/When/Then (spec §5) | Test (file: function) | Assertion mechanics |
|---|---|---|---|
| 1 | Full SSOConfigDrift fixture round-trips, copy not identical pointer | `ssoconfigdrift_types_deepcopy_test.go: TestDeepCopy_RoundTrip/Root` | `reflect.DeepEqual(src, copy)` + `src != copy` on pointer; TypeMeta GVK, ObjectMeta (Labels, Annotations, Finalizers, OwnerReferences, ManagedFields), Spec (both endpoints incl. `Optional` set), Status (non-zero `LastCheckedAt` with sub-second precision + non-local location) |
| 2 | List + Spec + Status + ClusterEndpoint round-trip | `TestDeepCopy_RoundTrip/{List,Spec,Status,ClusterEndpoint}` | Same; List fixture has `Continue` + `RemainingItemCount` pointer + ≥2 Items |
| 3 | Per-region mutation isolation, both directions | `TestDeepCopy_MutationIsolation/*` (table with subtests: ObjectMetaMaps, ObjectMetaSlices, OwnerReferences, ManagedFields, ItemsAppend, ItemsElement, ListMetaPointer, SpecClusterBKey, SpecClusterAOptional, StatusTime) | Snapshot source, mutate copy region, `reflect.DeepEqual` vs snapshot; and reverse. Tripwire rows are map/element/dereference writes (see §3.4): `SpecClusterAOptional` flips `*copy...Optional` — **fails on HEAD, passes after D1a**; `ItemsAppend`/`ObjectMetaSlices`/`SpecClusterBKey`/`StatusTime` are length-growth/value canaries only |
| 4 | nil Items stays nil; nil receivers return nil, no panic | `TestDeepCopy_NilShape` | `DeepCopy()` on `SSOConfigDriftList{nil Items}` keeps `Items == nil`; nil-receiver `DeepCopy()` on all five types and `DeepCopyObject()` on the two root types (only `SSOConfigDrift`/`SSOConfigDriftList` implement `runtime.Object`) return nil |
| 5 | `DeepCopyObject` returns concrete type | `TestDeepCopy_RoundTrip/Root` (type assert) | `copy.(*SSOConfigDrift)`, `.(*SSOConfigDriftList)` succeed |
| 6 | Scheme registration | `TestSchemeRegistration` | `AddToScheme(runtime.NewScheme())` nil err; `Recognizes` true for both kinds; `ObjectKinds` returns exactly `[{sso.snaplink.io v1alpha1 SSOConfigDrift}]` (and List); `GroupVersion` equals the literal; `scheme.New(GroupVersion, &SSOConfigDrift{}, &SSOConfigDriftList{})` round-trips (metav1.AddToGroupVersion positive control) |
| 7 | Identity block parity | `ssoconfigdrift_crd_parity_test.go: TestCRDParity_Identity` | Typed YAML struct; asserts `metadata.name == "ssoconfigdrifts."+GroupVersion.Group`, group, single version `v1alpha1` served+storage, kind/listKind/plural/singular/shortNames `[ssocd]`, scope Namespaced |
| 8 | Property key sets both directions at root/spec/clusterA/clusterB/bearerSecretRef/status | `TestCRDParity_PropertyKeySets` | Reflection walk (see §3.4) vs YAML map walk; `setdiff` empty in both directions; root exactly `{spec, status}` (TypeMeta + ObjectMeta excluded), bearerSecretRef exactly `{name, key, optional}` (recursed from LocalObjectReference) |
| 9 | Required lists | `TestCRDParity_RequiredLists` | Literals `[clusterA, clusterB]` / `[baseURL, bearerSecretRef]` ×2 / `[name, key]`; `pollInterval` in no required list |
| 10 | baseURL type+pattern both clusters | `TestCRDParity_BaseURLPattern` | `type == "string"`, `pattern == "^https://.+"` at both cluster endpoints |
| 11 | pollInterval optional, no default, const 5m | `TestCRDParity_PollInterval` | `type == "string"`; no `default:` key under pollInterval; `DefaultPollInterval == "5m"` (types.go:21) |
| 12 | Status field shapes | `TestCRDParity_StatusShapes` | `lastCheckedAt` string+`date-time`; `driftDetected` boolean; `patchOpCount` integer; `message` string; `observedGeneration` integer+`int64` |
| 13 | Subresource + printer columns | `TestCRDParity_SubresourceAndColumns` | `subresources.status` non-nil, `len == 0`; columns exactly Drift/boolean/`.status.driftDetected`, Ops/integer/`.status.patchOpCount`, LastChecked/date/`.status.lastCheckedAt` |
| 14 | D1 pre-fix failure + post-fix green | `TestDeepCopy_MutationIsolation/SpecClusterAOptional` (plus full-suite run) | Pre-fix: fails (reproduced during this review with a throwaway test). Post-D1a: cases 1–13 all pass |

## 8. Verification plan (exact commands)

```bash
cd cmd/sso-operator && go build ./... && go vet ./...
cd cmd/sso-operator && go mod tidy && go test -race -count=1 ./...    # ci-modules gate, Makefile:263
cd cmd/sso-operator && go test -race -count=1 ./apiv1alpha1/ -v       # focused: 14 cases
go build ./... && go vet ./...                                        # root unaffected
go test -run 'TestMaintainability_|TestArchitecture_' .               # root gates unaffected
python cli.py modules check
make ci                                                               # full handoff gate
```

Pre-existing conditions: none found — operator module builds and is green at
HEAD; the pre-fix aliasing at types.go:147–148 is the defect the tests are
designed to surface (D1), now independently reproduced.
