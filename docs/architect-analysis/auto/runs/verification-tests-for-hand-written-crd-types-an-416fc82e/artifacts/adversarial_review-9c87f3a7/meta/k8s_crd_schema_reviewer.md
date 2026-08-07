All six areas are now grounded against the actual sources: `k8s.io/api@v0.36.0` (corev1 types + generated deepcopy), `k8s.io/apimachinery@v0.36.0` (`runtime.Scheme.New`), `k8s.io/apiextensions-apiserver@v0.36.0` (structural + status-subresource validation), the YAML, types.go, controller, and both spec/design docs. controller-tools is not in the module graph anywhere, so controller-gen semantics below are grounded in observable generated-CRD behavior plus the kubebuilder markers embedded in the k8s.io/api sources themselves.

# Validation verdict

The design's API-machinery assumptions are **mostly correct, with three real defects**: one wrong marker citation (justifying `[name, key]`), one API misuse in case 6 that would not compile, and one mischaracterized brittleness profile (two assertion families trip on a *legitimate* controller-gen regeneration, and the doc frames them as generic drift detection).

## 1. TypeMeta/ObjectMeta/ListMeta exclusion — correct, but the walk spec is under-specified

- The exclusion itself matches controller-gen: it skips embedded `metav1.TypeMeta`/`ObjectMeta`/`ListMeta` *by type identity*, and generated CRDs never contain `apiVersion`/`kind`/`metadata` in `openAPIV3Schema.properties`. Your root assertion `{spec, status}` is exactly what controller-gen would emit for `SSOConfigDrift` (Spec and Status are both `omitempty` → not required, still properties).
- **Hazard:** the design text says "skips inline embedded fields for the root walk's purposes (TypeMeta `json:",inline"`)" *and* "recurses into inline-embedded structs". `corev1.SecretKeySelector` embeds `LocalObjectReference` with `json:",inline"` too — inline-ness is **not** the discriminator. A tag-shape-based implementation drops `name` from the bearerSecretRef walk and false-fails on the green YAML. The skip must be fully-qualified type identity (`k8s.io/apimachinery/pkg/apis/meta/v1.{TypeMeta,ObjectMeta,ListMeta}`), and the doc should say so.
- **Second hazard:** `metav1.Time` (types.go:76) is `struct { time.Time \`protobuf:"-"\` }` — a walk that recurses into any struct field descends into `time.Time`'s all-unexported fields. It only works because the design asserts key sets at exactly the six YAML-`properties` levels and never at `lastCheckedAt`. State the rule explicitly: **recurse only into fields whose YAML counterpart has a `properties` map; treat everything else (incl. `metav1.Time`) as a leaf; skip unexported fields**.

## 2. `metadata` key absence — confirmed

Root `properties` is exactly `{spec, status}`; no `metadata` anywhere in the schema tree. The root assertion pins this correctly, and `yamlKeys − goKeys` catches a YAML-side `metadata` insertion.

## 3. Required-vs-omitempty — literals are correct and necessary; the justification is wrong

- Verified: `LocalObjectReference.Name` is `json:"name,omitempty"` **and** carries `+optional`, `+default=""`, `+kubebuilder:default=""` (k8s.io/api v0.36.0 `core/v1/types.go:7498–7506`). So omitempty-derivation would wrongly mark `name` optional — the design's literal-assertion decision is right.
- **Defect 1 (citation error):** §3.4 says the `[name, key]` literal is backed by "the `+kubebuilder:validation:Required` markers at types.go:34/46/54/60/65". Those markers are on `BaseURL`, `BearerSecretRef`, `ClusterA`, `ClusterB` (verified at those exact lines) and justify nothing about `name`/`key`. The actual justification is corev1's own contract — the source comment says Name is "effectively required, but due to backwards compatibility … allowed to be empty" — i.e., the hand-written YAML is **deliberately stricter than controller-gen's structural derivation** (`omitempty` → optional). This distinction matters for area 6.

## 4. x-kubernetes-* handling — absent today, invisible-by-design, correctly so

- The YAML has zero `x-kubernetes-*` keys, and a regeneration would emit none either: no slices/maps in the root schema (the only slice, `Items`, lives in the List type, which controller-gen never schematizes), no `IntOrString`/`RawExtension`/`metav1.LabelSelector`, no CEL markers. `metav1.Time` is the only special-case type and the YAML already matches its shape (`string`/`date-time`, asserted by case 12).
- The blind spot is the *siblings* of `properties`: the walk compares only property key sets plus the enumerated values. A hand-edit adding `x-kubernetes-validations`, `additionalProperties`, `nullable`, or flipping a container's `type` passes all 14 cases. That is acceptable for a parity tripwire, but the failure-mode table's "Admission-time schema drift caught in CI" overstates it: these tests catch *parity* drift, never *structural validity* drift (a self-consistent-but-non-structural YAML passes here and fails at the API server). One sentence in the doc should scope the claim.

## 5. Status-subresource rules — grounded, compliant, correctly asserted

From `apiextensions-apiserver@v0.36.0` `validation.go`:
- With the status subresource enabled, the root schema must be `type: object` and only `allowedFieldsAtRootSchema` (Description, Type, Format, …, Required, Items, Properties, ExternalDocs, Example, XPreserveUnknownFields, XValidations — lines 1585–1594) may appear at root (lines 916–942). The YAML's root (type/description/properties) is compliant.
- `subresources.status: {}` is the exact controller-gen shape for the marker without conditions; yaml.v3 decodes it to a non-nil `len==0` map — the case-13 assertion is sound.
- `status` as a root property is legal with the subresource enabled (nothing forbids it). No conflict with any assertion.

## 6. Regeneration brittleness — bounded, but mischaracterized

Full delta inventory if `crd-ssoconfigdrift.yaml` were regenerated by controller-gen from the current types.go:

| Regeneration delta | Parity-test impact |
|---|---|
| `bearerSecretRef.required` `[name, key]` → `[key]` (name is omitempty) | **Case 9 trips** |
| `name` gains `default: ""` (from corev1's `+kubebuilder:default=""`; corev1's own TODO cites kubebuilder issue #3896 for exactly this) | Invisible — no assertion pins default-absence under `name` (case 11 only checks pollInterval). This is the admission-defaulting landmine: CRs would get `name: ""` defaulted |
| `shortNames: [ssocd]` dropped — **types.go has no `+kubebuilder:resource:shortName` marker** (only `object:root`, `subresource:status`, `printcolumn`) | **Case 7 trips** |
| Descriptions everywhere (doc comments) | Invisible; correctly unasserted |
| Property ordering becomes alphabetical (controller-gen YAML output sorts keys) | Invisible; the set-comparison design correctly avoids it |
| Identity, key sets, baseURL pattern (emitted verbatim), pollInterval, status shapes (incl. `int64`→`format: int64`), columns (marker order), `subresources.status: {}` | Survive |

So cases 7 and 9 pin **deliberate divergences from controller-gen output** (stricter admission semantics for `name`; a shortname with no marker backing), not controller-gen parity — while the package doc's promise of "exact mechanical shape controller-gen would produce" applies only to the DeepCopy methods and case 13's columns. The design should: fix the `[name, key]` citation (corev1 "effectively required" semantics + explicit decision to reject name-less refs at admission and to avoid `default: ""`), note `ssocd` needs a `+kubebuilder:resource` marker if controller-gen is ever wired in, and add a failure-mode row "YAML regenerated by controller-gen → cases 7/9 trip; expected, reconcile deliberately". Without that, a future maintainer will read a legit regeneration as drift.

## Additional defects (in-scope, not among your six)

- **Case 6 API misuse (in both docs):** `scheme.New(GroupVersion, &SSOConfigDrift{}, &SSOConfigDriftList{})` — `runtime.Scheme.New` takes a **single** `schema.GroupVersionKind` (`apimachinery@v0.36.0 pkg/runtime/scheme.go:306`), not a GV plus objects. As written it does not compile. Correct form: `scheme.New(GroupVersion.WithKind("SSOConfigDrift"))`, and the `metav1.AddToGroupVersion` positive control should be `scheme.New(GroupVersion.WithKind("ListOptions"))`.
- **Migration step 3 imprecision:** "verify `git diff cmd/sso-operator/go.mod` is exactly the one-line block move" — the worktree go.mod already carries the sibling path-parity diff (replace directive, snaplink require, 7 dependency bumps; go.sum has 19 pre-existing additions). Scope the verification to yaml.v3 hunks. Also note: the worktree go.mod is currently live-mutating (a standalone `require gopkg.in/yaml.v3 v3.0.1` direct block observed at line 15 earlier in this session has since disappeared, leaving only the `// indirect` entry at 58) — a concurrent process is touching this module; re-verify go.mod state immediately before step 3. The E8 citations (go.mod:58, go.sum:146–147) are accurate for the current tree.
- **Confirmations:** E4's correction (comment 38–39, `newScheme` 40, `corev1.AddToScheme` 43, `drift.AddToScheme` 46) is exact; controller reads only `BearerSecretRef` at 138/142; D1a's `in.BearerSecretRef.DeepCopyInto(&out.BearerSecretRef)` is the exact controller-gen shape and `SecretKeySelector.DeepCopyInto` does copy `Optional` (zz_generated.deepcopy.go:5719–5728); nil-shape, CWD, single-version, and `status: {}` decode assumptions all hold.

**Bottom line:** the parity-test architecture is sound and its tripwire philosophy is right — but three things must change in the design doc before implementation: (1) fix the case-6 `Scheme.New` call, (2) replace the `[name, key]` marker citation with the real corev1 semantics and label the assertion a deliberate-divergence pin, (3) add the explicit "controller-gen regeneration" row to the failure-mode table (cases 7 and 9) so the tripwires are understood as intentional, and scope the go.mod verification in step 3 to yaml.v3 hunks.
