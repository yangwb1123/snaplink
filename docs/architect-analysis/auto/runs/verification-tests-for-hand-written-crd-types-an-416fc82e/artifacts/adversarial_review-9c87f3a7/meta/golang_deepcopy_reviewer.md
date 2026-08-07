Audit complete. I verified every claim against source (types.go, CRD YAML, k8s.io/api@v0.36.0 module cache, apimachinery, controller, go.mod/go.sum diffs) and patched the design doc. Findings by axis:

## 1. Reflection walk — one self-contradiction (fixed)

**F2 (medium): the walk rule as written is contradictory.** §3.4 said the walk "skips inline embedded fields" (TypeMeta) *and* "recurses into inline-embedded structs where properties genuinely nest" (LocalObjectReference). A literal "skip all inline embeds" implementation drops `name` from `bearerSecretRef` → both-direction setdiff fails on the green YAML, and the "fix" becomes a hand-tuned special case. The rule must be single: inline embeds flatten, **except TypeMeta/ObjectMeta/ListMeta skipped by type name**; named embeds are single keys. Verified the underlying facts: `SecretKeySelector` embeds `LocalObjectReference` with `json:",inline"` (types.go:2586) and `LocalObjectReference.Name` is `json:"name,omitempty"` (7506) — so both the recursion and the literal-required-list decision are right; only the stated rule was ambiguous. Also corrected the exclusion rationale: "Kubernetes convention that server-managed metadata never appears in properties" is **false for controller-gen output** (kubebuilder CRDs emit apiVersion/kind/metadata at root). It's a pin to the hand-maintained YAML shape — which matters because the package doc contemplates wiring controller-gen later; that legitimate drift will trip the root `{spec, status}` assertion by design.

## 2. D1a one-liner mechanics — sound

`SecretKeySelector.DeepCopyInto` at zz_generated.deepcopy.go:5719–5728 is exactly as cited: `*out = *in`, `out.LocalObjectReference = in.LocalObjectReference` (value — Name is a string, no aliasing), `Optional` via `new(bool)`. The replacement line is verbatim controller-gen shape; `*out = *in` still precedes it; `BearerSecretRef` is a value field so no nil-receiver hazard; coupling is compile-time loud. `metav1.Time.DeepCopyInto` is `*out = *t` (time.go:40–42), so `Status.DeepCopyInto`'s call is also correct shape.

## 3. Nil-shape / nil-receiver — one factual error (fixed)

All five `DeepCopy()` methods have nil guards; `DeepCopyInto` preserves nil Items. But §7 case 4 claimed "nil-receiver `DeepCopyObject()` on all five types" — `DeepCopyObject` exists on **only 2 of 5** (SSOConfigDrift, SSOConfigDriftList); literal implementation = compile error. Fixed the row; R1 in the requirements was already correctly scoped.

## 4. Mutation isolation vs the 12-row table — one structural false negative (fixed)

**F1 (high): slice-`append` mutations cannot detect aliasing, ever.** `copy.Items = append(copy.Items, x)` — even with `out.Items = in.Items` sharing the backing array — either reallocates or writes at index ≥ len(source); `reflect.DeepEqual` compares `[0:len)` only, so the source is always unchanged. Same for Finalizers append. Only **writes through the shared reference** trip: map writes, element/field writes into the shared array (`Items[0].Spec...`, `OwnerReferences[0].UID`, `ManagedFields[0]`), dereference writes (`*RemainingItemCount`, the D1 `Optional` flip). `SpecClusterBKey`/`StatusTime` (whole-value assignment) are likewise canaries. The doc and requirements both list the append forms as tripwires. Patched §3.4 (tripwires vs canaries), §5 row 1, and §7 case 3. All other 11 rows have working detection mechanisms — I re-checked each against the actual YAML (required lists at 51/60/77/93/102, patterns 66/99, `format: int64` on observedGeneration, `subresources.status: {}`, 3 columns, single version, identity block) — all match, so no assertion fails on the green side.

## 5. Over-coupling — two worktree-scoped defects (fixed)

**F5 (medium): migration step 3's verification is stale.** "Verify `git diff ...go.mod` is exactly the one-line block move and `go.sum` is unchanged" is false in this worktree — go.mod/go.sum already carry the sibling path-parity edits (replace, root require, cbor/x-net bumps, go.sum hash changes). Following it literally misreports, or risks reverting sibling edits. Rewrote the step to scope verification to the yaml.v3 line movement; confirmed the promotion is MVS-safe (root go.mod has no yaml.v3 require). Also renamed the ambiguous "`status: {}` assertion" to `subresources.status` (§3.4) — the schema status node has five properties.

**Deliberate pins (acceptable, now documented as pins):** `DefaultPollInterval == "5m"`, columns exactly three, root exactly `{spec, status}`, `[name, key]` stricter than controller-gen would emit — all required by R3 and correctly framed as tripwires, not conventions.

**Sound:** all 10 evidence rows re-confirmed (E4's drift, D1's reproduction, go.sum:146–147, controller reads at 138/142 only), no false negatives beyond F1–F6. Seven edits applied to the design doc; no other files touched.
