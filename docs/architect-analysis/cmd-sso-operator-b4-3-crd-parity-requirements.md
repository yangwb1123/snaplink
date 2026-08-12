# Requirements Spec: verification tests for the hand-written CRD types and hand-maintained manifest (DeepCopy round-trip + YAML↔Go parity)

- Direction: "Verification tests for hand-written CRD types and hand-maintained manifest (DeepCopy round-trip + YAML↔Go parity)" (source: `docs/architect-analysis/auto/analyses/cmd-sso-operator-apiv1alpha1-1d574b40.json`, entry 2)
- Analysis module: `cmd/sso-operator/apiv1alpha1`; change surface: new `_test.go` files in `cmd/sso-operator/apiv1alpha1` only, plus one pinned 1-line production fix inside the same package (decision D1, below).
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-operator/apiv1alpha1/ssoconfigdrift_types.go` — 255 lines, DeepCopyInto/DeepCopyObject/AddToScheme/GroupVersion, no test file | File is exactly 255 lines. `DeepCopyInto` at 146 (ClusterEndpoint), 162 (Spec), 179 (Status), 196 (SSOConfigDrift), 226 (List); `DeepCopyObject` at 217, 250; `AddToScheme` at 135 via `SchemeBuilder` (132) + `addKnownTypes` (137–140); `GroupVersion` at 128 (`sso.snaplink.io` / `v1alpha1`). Directory listing: only `ssoconfigdrift_types.go` — **zero `_test.go` files** | Confirmed |
| `cmd/sso-operator/crd-ssoconfigdrift.yaml:64-71,97-101` — baseURL pattern | `pattern: '^https://.+'` at lines 66 (clusterA) and 99 (clusterB), inside blocks 64–71 and 97–101 | Confirmed (exact) |
| `cmd/sso-operator/crd-ssoconfigdrift.yaml:58-61,91-94` — required clusterA/clusterB | Spec-level `required: [clusterA, clusterB]` at lines 51–53; clusterA `required: [baseURL, bearerSecretRef]` at 60–62; clusterB at 93–95. bearerSecretRef `required: [name, key]` at 77–79 and 102–104 | Confirmed (2-line drift on the endpoint-required citation; the clusterA/clusterB pair itself is at 51–53) |
| `Makefile:263` — nested-module gate command | Line 263 is exactly `cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...` inside `ci-modules` | Confirmed (exact) |
| `cmd/sso-operator/controller/ssoconfigdrift_controller_test.go:29-42` — scheme registration is the only exercise today | `newScheme` (comment 29–31, func 32–42) calls `drift.AddToScheme(s)` at 38–40; controller tests exercise the types' scheme registration but never DeepCopy semantics or the CRD manifest | Confirmed |
| "no controller-gen in this environment"; hand-written DeepCopy "following the exact mechanical shape controller-gen would emit" | Package doc at `types.go:2`; DeepCopyInto doc promise at `types.go:143–145` | Confirmed |
| `DefaultPollInterval = "5m"` (types.go:21); consumed by `requeueInterval` fallback | `controller/ssoconfigdrift_controller.go:211–215`: empty or unparseable `PollInterval` falls back to `time.ParseDuration(drift.DefaultPollInterval)`. The YAML schema has **no `default:` key anywhere** (grep: 0 hits); pollInterval is optional (`+optional` at `types.go:65`, `json:"pollInterval,omitempty"` at 66) | Confirmed |
| B4-3 "deploy tree gets sweep/truthiness assertions" | `docs/campaigns/implementation-gate.md` row 3: 部署仓测试 补 sweep/真值断言; T-2 = sweep 全绿. This direction is the operator half (CRD types + manifest), sibling to the already-landed path-parity half (`controller/adminpaths_parity_test.go` present at HEAD, module green) | Confirmed |
| No existing check covers this surface | `docs/agent-os/CHECKS_REGISTRY.md`: 0 hits for crd/operator/k8s; repo-wide grep for `crd-ssoconfigdrift` in `.go` files: 0 hits; `python cli.py` has no CRD validation | Confirmed — net-new coverage |
| YAML parser availability for the parity test | `gopkg.in/yaml.v3 v3.0.1` (go.mod:58, `// indirect`; go.sum:146) and `sigs.k8s.io/yaml v1.6.0` (go.mod:66) are already in the nested module's graph — no new module path needed | Confirmed |
| **New finding (surfaced by the direction's own acceptance):** `ClusterEndpoint.DeepCopyInto` aliases `BearerSecretRef.Optional` | `types.go:147–148`: `*out = *in; out.BearerSecretRef = in.BearerSecretRef` — a value copy that **shares the `Optional *bool` pointer**. `corev1.SecretKeySelector` has a generated `DeepCopyInto` in `k8s.io/api@v0.36.0` `core/v1/zz_generated.deepcopy.go:5719–5728` that copies `Optional` (`*out = new(bool); **out = **in`); controller-gen shape would emit `in.BearerSecretRef.DeepCopyInto(&out.BearerSecretRef)`. The hand-written line therefore diverges from the file's own documented promise ("exact mechanical shape controller-gen would emit", types.go:143–145). Benign today (nothing mutates `*Optional`), but exactly the "subtle deep-copy aliasing bug … ships silently" class the direction names | Confirmed — see decision D1 |
| Pre-existing conditions at HEAD | `cd cmd/sso-operator && go build ./...` OK; `go test -race -count=1 ./...` OK (controller 1.45s); `go test ./apiv1alpha1/` reports `[no test files]` | Confirmed (run at spec time) |

## 2. Goal and user outcome

`apiv1alpha1` is the operator's CRD contract: hand-written types whose DeepCopy methods and `+kubebuilder` markers are the only spec of what the API server enforces, plus a hand-maintained `crd-ssoconfigdrift.yaml` that must track those markers by hand. Neither is exercised by any test today: a deep-copy aliasing bug (Items slice, ObjectMeta maps, ListMeta pointer, `BearerSecretRef.Optional`) or a marker/manifest drift (baseURL pattern, required lists, pollInterval optionality/default) ships silently through `Makefile:263`'s `go test -race -count=1 ./...` because the package is `[no test files]`. The controller tests touch only `AddToScheme` (controller test:38–40).

Completion marker: two new test files under `cmd/sso-operator/apiv1alpha1/` pass under `go test -race ./...` (ci-modules, `Makefile:263`) —

1. DeepCopy round-trip with mutation-isolation assertions for `SSOConfigDrift`, `SSOConfigDriftList`, `SSOConfigDriftSpec`, `SSOConfigDriftStatus`, `ClusterEndpoint`, plus `AddToScheme`/`GroupVersion` registration checks.
2. A parsed-`crd-ssoconfigdrift.yaml` parity test asserting every YAML field name, required list, and pattern matches the Go structs and kubebuilder markers: baseURL pattern `^https://.+` (both clusters), required `clusterA`/`clusterB`/`baseURL`/`bearerSecretRef`/`name`/`key`, pollInterval optional with `DefaultPollInterval == "5m"`, status subresource, and the three printer columns.

## 3. Product boundary

- Surface: verification coverage only — new test files in `cmd/sso-operator/apiv1alpha1/`; one pinned 1-line production correction (D1) inside the same 255-line file, required for the acceptance's Spec isolation assertion to hold.
- Explicit non-goals (do not implement):
  - No behavior change to the operator: no controller changes, no route/CRD-schema changes, no `default:` added to the YAML (the 5m default lives in the Go const and the controller's fallback, by design — the YAML description already documents it).
  - No controller-gen introduction, no generated-code pipeline, no new kubebuilder markers, no manifest regeneration.
  - No new tests outside `cmd/sso-operator/apiv1alpha1/` (the controller's poll-interval fallback behavior is already implemented and out of this direction's surface; this direction pins the const + manifest contract only).
  - No RBAC manifests, no audit events, no `Err*`, no config keys, no OpenAPI surface (other analysis entries cover RBAC and the path-parity half separately).
  - No `go.work`; no new module path (yaml.v3 is already in the module graph; tidy only promotes it from indirect to direct).
  - No changes to `cmd/sso-operator/controller/*`, `doc.go`, `main.go`, `crd-ssoconfigdrift.yaml`, the root module, or `Makefile`.

## 4. Module classification

- [x] Infrastructure/config/deployment (deploy-tree CRD contract truthiness — the operator half of B4-3)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer: `cmd/sso-operator/apiv1alpha1` (nested module, white-box tests, `package v1alpha1`). Dependency direction: test-only imports of `k8s.io/apimachinery`, `k8s.io/api`, and `gopkg.in/yaml.v3` — all already in the nested module's go.mod/go.sum; no root-module import, so no new graph edge beyond the pre-existing yaml.v3 promotion.

## 5. Requirements

### R1 — DeepCopy round-trip with mutation isolation

New file `cmd/sso-operator/apiv1alpha1/ssoconfigdrift_types_deepcopy_test.go` (`package v1alpha1`, white-box). Fixtures are fully populated: `SSOConfigDrift` with TypeMeta GVK, ObjectMeta (Labels, Annotations, Finalizers, OwnerReferences, ManagedFields), Spec (both ClusterEndpoints with `BearerSecretRef.Optional` set, PollInterval), Status (non-zero `LastCheckedAt` with sub-second precision and non-local location, DriftDetected, PatchOpCount, Message, ObservedGeneration); `SSOConfigDriftList` with ListMeta (`Continue` set, `RemainingItemCount` pointer set) and ≥2 Items.

- Round-trip: `DeepCopy()` result is `reflect.DeepEqual` to the source for all five types (SSOConfigDrift, SSOConfigDriftList, Spec, Status, ClusterEndpoint).
- Mutation isolation, both directions (mutate copy → source unchanged; mutate source → copy unchanged), covering every reference-bearing region:
  - `ObjectMeta`: Labels/Annotations map writes, Finalizers append, `OwnerReferences[0].UID` overwrite, `ManagedFields[0]` overwrite.
  - `Items`: append to the copy's slice (length grows, source's length unchanged); `copy.Items[0].Spec.ClusterA.BaseURL` overwrite; `copy.Items[0].Status.Message` overwrite.
  - `ListMeta`: `*copy.ListMeta.RemainingItemCount` overwrite.
  - `Spec`: `copy.Spec.ClusterB.BearerSecretRef.Key` overwrite; `*copy.Spec.ClusterA.BearerSecretRef.Optional` flip — **this assertion fails on HEAD** (D1).
  - `Status`: `copy.LastCheckedAt.Time` value replacement (regression pin).
- Shape assertions: nil `Items` stays nil (never an empty non-nil slice); nil-receiver guards — `(*SSOConfigDrift)(nil).DeepCopy()`, `DeepCopyObject()`, and the Spec/Status/ClusterEndpoint/List equivalents return nil.
- `DeepCopyObject` returns a `runtime.Object` of the concrete type (`SSOConfigDrift`, `SSOConfigDriftList`).

### R2 — Scheme and GroupVersion registration

Same file (or a small sibling `ssoconfigdrift_scheme_test.go` at implementer's discretion — one file is fine):

- `AddToScheme(s)` succeeds; `s.Recognizes(GroupVersion.WithKind("SSOConfigDrift"))` and `...WithKind("SSOConfigDriftList")` are both true.
- `s.ObjectKinds(&SSOConfigDrift{})` returns exactly `[{sso.snaplink.io v1alpha1 SSOConfigDrift}]`; same for the List kind.
- `GroupVersion == schema.GroupVersion{Group: "sso.snaplink.io", Version: "v1alpha1"}` (the identity the parity test in R3 also checks against the manifest).
- Positive control for `metav1.AddToGroupVersion` (types.go:139): `scheme.New(GroupVersion, &SSOConfigDrift{}, &SSOConfigDriftList{})` round-trips without error.

### R3 — CRD manifest ↔ Go parity

New file `cmd/sso-operator/apiv1alpha1/ssoconfigdrift_crd_parity_test.go`. Parse `../crd-ssoconfigdrift.yaml` with `gopkg.in/yaml.v3` (`go test` runs each package with CWD = the package source dir, so the relative path is stable). Typed struct for the identity block + generic map walk for the schema tree.

- Identity block: `metadata.name == "ssoconfigdrifts."+GroupVersion.Group`; `spec.group == GroupVersion.Group`; `versions[0].name == GroupVersion.Version` with `served: true`, `storage: true`; `names.kind == "SSOConfigDrift"`, `listKind == "SSOConfigDriftList"`, `plural == "ssoconfigdrifts"`, `singular == "ssoconfigdrift"`, `shortNames == ["ssocd"]`; `scope == "Namespaced"`.
- Property key sets — reflection-derived from the Go structs' `json` tags (renames on either side fail the test), compared as sets in **both** directions (an extra YAML key or an extra Go tag is drift):
  - root: exactly `{spec, status}` — the inline `metav1.TypeMeta` (`json:",inline"`, types.go:110) must NOT appear as `apiVersion`/`kind` schema properties;
  - `spec`: exactly `{clusterA, clusterB, pollInterval}` (tags at types.go:55, 61, 66);
  - `clusterA`/`clusterB`: exactly `{baseURL, bearerSecretRef}` (tags at 36, 47);
  - `bearerSecretRef`: exactly `{name, key, optional}` (corev1 `SecretKeySelector` tags — the embedded LocalObjectReference's `name` plus `key`/`optional`);
  - `status`: exactly `{lastCheckedAt, driftDetected, patchOpCount, message, observedGeneration}` (tags at 76, 82, 86, 92, 97).
- Required lists: `spec.required == [clusterA, clusterB]` (markers at 54, 60); `clusterA.required == clusterB.required == [baseURL, bearerSecretRef]` (markers at 34, 46); `bearerSecretRef.required == [name, key]`; `pollInterval` absent from every required list (optional per marker at 65 + `omitempty`).
- baseURL: `type: string` and `pattern == "^https://.+"` in **both** clusters (marker at 35; yaml lines 66, 99).
- pollInterval: `type: string`, **no `default:` key** in the schema; `DefaultPollInterval == "5m"` (types.go:21) — pins "empty → DefaultPollInterval 5m" at the const level that the controller actually consumes (controller.go:211–215).
- Status field shapes: `lastCheckedAt` string + `format: date-time`; `driftDetected` boolean; `patchOpCount` integer; `message` string; `observedGeneration` integer + `format: int64`.
- `versions[0].subresources.status == {}` (marker at 105); `additionalPrinterColumns` equals exactly the three marker-derived columns (types.go:106–108): `Drift/boolean/.status.driftDetected`, `Ops/integer/.status.patchOpCount`, `LastChecked/date/.status.lastCheckedAt`.

### D1 — Decision: the surfaced `BearerSecretRef.Optional` aliasing (the single production touchpoint)

The R1 Spec-isolation assertion `*copy.Spec.ClusterA.BearerSecretRef.Optional` flip **fails on HEAD**: `types.go:147–148` (`*out = *in; out.BearerSecretRef = in.BearerSecretRef`) shares the `Optional *bool` pointer, while the file's own doc promise (types.go:143–145) is controller-gen mechanical shape — and controller-gen would emit `in.BearerSecretRef.DeepCopyInto(&out.BearerSecretRef)` because `corev1.SecretKeySelector` has a generated DeepCopyInto (k8s.io/api@v0.36.0, zz_generated.deepcopy.go:5719–5728, which copies `Optional`).

- D1a (recommended): change `types.go:148` to `in.BearerSecretRef.DeepCopyInto(&out.BearerSecretRef)`. One line, same package, restores the documented contract, and lets the full Spec isolation assertion hold. No other production change.
- D1b (rejected): keep HEAD code and document `Optional` as known-aliased in the test, asserting round-trip equality only. This leaves the acceptance's "mutation-isolation assertions for … Spec" partially unmet and enshrines the exact drift class the direction exists to remove.

### Testable acceptance (Given/When/Then)

All cases run under `cd cmd/sso-operator && go test -race -count=1 ./...` (the exact `Makefile:263` gate command; `make ci` → `ci-modules`). The root-module gates (`go build ./...`, `TestMaintainability_|TestArchitecture_`) do not descend into nested modules — `ci-modules` is the detection boundary, precedented by every nested module (mcp at Makefile:262, saml/ldap/etc.).

R1 round-trip:

1. Given a fully populated `SSOConfigDrift` fixture, when `DeepCopy()` runs, then `reflect.DeepEqual` holds and the copy is not identical (`!=` pointer comparison) to the source.
2. Given a fully populated `SSOConfigDriftList` (ListMeta + 2 Items) and `SSOConfigDriftSpec`/`SSOConfigDriftStatus`/`ClusterEndpoint` fixtures, when `DeepCopy()` runs, then `reflect.DeepEqual` holds for each.
3. Given any DeepCopy result, when Labels/Annotations maps, Finalizers slice, OwnerReferences, ManagedFields, Items slice (append + element mutation), ListMeta.RemainingItemCount, Spec fields, or Status fields are mutated on the copy, then the source is byte-for-byte unchanged (`reflect.DeepEqual` to a pre-mutation snapshot); and vice versa.
4. Given a List with nil `Items`, when `DeepCopy()` runs, then `Items` is still nil. Given nil receivers, when `DeepCopy()`/`DeepCopyObject()` runs, then nil is returned (no panic).
5. Given `DeepCopyObject()` on either root type, when the result is type-asserted, then it is `*SSOConfigDrift` / `*SSOConfigDriftList`.

R2 registration:

6. Given `AddToScheme(runtime.NewScheme())`, when `Recognizes` runs for `GroupVersion.WithKind("SSOConfigDrift")` and `("SSOConfigDriftList")`, then both are true; when `ObjectKinds` runs on both types, then each returns exactly its `{sso.snaplink.io, v1alpha1, Kind}` triple; when `GroupVersion` is compared, then it equals `schema.GroupVersion{Group: "sso.snaplink.io", Version: "v1alpha1"}`.

R3 parity:

7. Given `../crd-ssoconfigdrift.yaml` parsed, when the identity block (name/group/version/served/storage/names/shortNames/scope) is compared with `GroupVersion` and the Go type names, then every value matches.
8. Given the schema tree, when the property key sets at root/spec/clusterA/clusterB/bearerSecretRef/status are compared with the reflection-derived Go `json` tags, then each set is equal in both directions (no extra YAML key, no extra Go tag).
9. Given the schema tree, when required lists are compared with the `+kubebuilder:validation:Required`/`+optional` markers, then `spec.required == [clusterA, clusterB]`, both cluster endpoints require `[baseURL, bearerSecretRef]`, `bearerSecretRef` requires `[name, key]`, and `pollInterval` is in no required list.
10. Given the schema tree, when `baseURL` is inspected in both clusters, then `type == "string"` and `pattern == "^https://.+"`.
11. Given the schema tree and the Go const, when pollInterval is inspected, then it is `type: string` with no `default:` key, and `DefaultPollInterval == "5m"`.
12. Given the schema tree, when status fields are inspected, then `lastCheckedAt` is string+`date-time`, `driftDetected` boolean, `patchOpCount` integer, `message` string, `observedGeneration` integer+`int64`.
13. Given the schema tree, when subresources and printer columns are inspected, then `subresources.status == {}` and the three columns equal the `types.go:106–108` markers exactly.

D1 fix:

14. Given HEAD's `types.go:147–148`, when the R1 Spec-isolation assertion runs, then it fails (pre-fix evidence, captured at spec time: the aliasing is mechanically verified against k8s.io/api@v0.36.0 zz_generated.deepcopy.go:5719–5728). Given the D1a one-line change, when the full suite runs, then all of cases 1–13 pass.

### Acceptance mapping grade: 14/14 machine-checked

Every case is a Go test failing loudly under the named gate (`ci-modules`, `Makefile:263`); none is review-only. Cases 1–5 are net-new coverage (the package has zero tests today); cases 7–13 are net-new manifest parity coverage (nothing parses `crd-ssoconfigdrift.yaml` repo-wide). Case 14 is the single bounded production change, itself justified and enforced by case 3's Spec assertion.

## 6. Engineering-gate constraints (verified)

- **Budgets**: `apiv1alpha1` holds 1 non-test file (fan-out gate counts non-test files; `_test.go` exempt). The two new test files land at ~150–190 lines each — no file approaches 500 lines, no function approaches 50, complexity trivial. No `layerExemptions`, no new packages, no upward imports (nested module; root-module gates never descend).
- **Nested-module go.mod**: no new module path. `gopkg.in/yaml.v3 v3.0.1` and `sigs.k8s.io/yaml v1.6.0` are already in go.mod (indirect) and go.sum; `go mod tidy` after the test import moves yaml.v3 to the direct require block — a one-line go.mod move, zero go.sum additions. The root `require`/`replace` added by the sibling path-parity direction stays untouched.
- **D1a production surface**: one line in the nested module. Root gates (`go build ./... && go vet ./...`, `TestMaintainability_|TestArchitecture_`) are unaffected; `make ci` picks up the nested change only via `ci-modules`.
- **Wire/contract invariants untouched**: no routes, `Err*`, config keys, audit events, or credential surfaces; oracle-safe response tables unaffected; no SSRF surface (tests use no outbound fetches).
- **`python cli.py modules check`**: unaffected (validates module manifests/profiles, not nested go.mod contents); passes at baseline.

## 7. Files

### Create

```text
cmd/sso-operator/apiv1alpha1/ssoconfigdrift_types_deepcopy_test.go — R1 + R2
    (package v1alpha1; round-trip equality, mutation isolation per region,
    nil-Items/nil-receiver shape, DeepCopyObject concrete type, AddToScheme/
    Recognizes/ObjectKinds/GroupVersion registration checks).
cmd/sso-operator/apiv1alpha1/ssoconfigdrift_crd_parity_test.go — R3
    (package v1alpha1; parses ../crd-ssoconfigdrift.yaml via gopkg.in/yaml.v3;
    identity block, reflection-derived property-key sets, required lists,
    baseURL pattern, pollInterval optionality + DefaultPollInterval, status
    field shapes, subresource + printer columns).
```

### Modify (single line, decision D1a)

```text
cmd/sso-operator/apiv1alpha1/ssoconfigdrift_types.go:148 —
    out.BearerSecretRef = in.BearerSecretRef
  → in.BearerSecretRef.DeepCopyInto(&out.BearerSecretRef)
    (restores the controller-gen mechanical shape the file's own doc
    comment promises; k8s.io/api@v0.36.0 SecretKeySelector.DeepCopyInto
    copies Optional — zz_generated.deepcopy.go:5719–5728).

cmd/sso-operator/go.mod — one-line promotion of gopkg.in/yaml.v3 from
    indirect to direct after tidy (no version change, no go.sum addition).
```

### Do not modify

```text
cmd/sso-operator/crd-ssoconfigdrift.yaml, doc.go, main.go,
cmd/sso-operator/controller/*, Makefile, root go.mod/go.sum, interfaces/sso/*,
shared/core/*.
```

## 8. Dependencies and compatibility

- New/changed SPI: none (test-only plus D1a's one-line DeepCopyInto correction; runtime behavior of the copy is unchanged for every caller — `*out = *in` still precedes the call, so value fields and the LocalObjectReference copy are identical; only the `Optional` pointer gains isolation, which nothing currently relies on sharing).
- New option/store wiring: none. New YAML/env keys: none. Storage migration: none.
- HTTP/proto compatibility: none.
- Module graph: no new module paths; yaml.v3 promoted indirect→direct in the nested go.mod.
- Rollout/rollback: additive tests; reverting D1a's single line restores HEAD behavior exactly while the tests then fail (the intended tripwire).

## 9. Documentation

- [ ] `docs/config-reference.md` — not applicable (no config knob).
- [ ] `docs/openapi.yaml` — not applicable (no endpoint change).
- [ ] `docs/error-codes.md` — not applicable (no new `Err*`).
- [x] Campaign bookkeeping: `docs/campaigns/implementation-gate.md` row 3 (B4-3) — this completes the operator half of the deploy-tree sweep/truthiness contract for the CRD types and manifest (DeepCopy semantics + YAML↔Go parity), sibling to the landed path-parity half; the "不得带入部署仓" constraint is untouched (no legacy defect assertions anywhere).

## 10. Verification plan

```bash
cd cmd/sso-operator && go build ./... && go vet ./...
cd cmd/sso-operator && go mod tidy && go test -race -count=1 ./...   # ci-modules gate command (Makefile:263)
cd cmd/sso-operator && go test -race -count=1 ./apiv1alpha1/ -v      # focused: 14 acceptance cases
go build ./... && go vet ./...                                       # root module unaffected (no root .go edits)
go test -run 'TestMaintainability_|TestArchitecture_' .              # root gates unaffected
python cli.py modules check                                          # baseline passes; unchanged surface
make ci                                                              # full gate incl. ci-modules
```

Pre-existing conditions to report separately: none found — the operator module builds and `go test -race ./...` is green at HEAD (controller 1.45s, `apiv1alpha1` `[no test files]`), and the pre-fix aliasing at `types.go:147–148` is the defect this direction's tests are designed to surface (D1).
