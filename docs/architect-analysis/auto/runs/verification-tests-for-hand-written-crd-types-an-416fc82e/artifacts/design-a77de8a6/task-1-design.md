All pre-existing worktree changes (including the sibling path-parity direction's `go.mod`/`go.sum` edits) were already in the tree before I started — my verification used only a throwaway test that was removed, and `apiv1alpha1/` is back to its single original file.

## Deliverable

**`docs/architect-analysis/cmd-sso-operator-b4-3-crd-parity-design.md`** — written, containing:

**Evidence verification (10/10 checked, 1 corrected):** Every citation in the spec was re-checked against source, Makefile, module cache, and a live throwaway test. All confirmed except E4 (controller-test line numbers drift 6–8 lines: comment at 38–39, `drift.AddToScheme` at 46, not 38–40). The central finding **D1 was empirically reproduced**: flipping `*copy.Spec.ClusterA.BearerSecretRef.Optional` left `reflect.DeepEqual(in, out)` true — the copy aliases the source, exactly as claimed.

**API changes:** one production line (`types.go:148`: `out.BearerSecretRef = in.BearerSecretRef` → `in.BearerSecretRef.DeepCopyInto(&out.BearerSecretRef)`), one go.mod promotion (yaml.v3 indirect→direct, zero go.sum additions), two new test files, zero wire/CRD/config surface.

**Design decisions sharper than the spec:** reflection walk must exclude `ObjectMeta`/`ListMeta` (spec only names TypeMeta, but YAML has no `metadata` key); required-list assertions must be literals, not `omitempty`-derived (`LocalObjectReference.Name` is `omitempty` yet required); `versions` must be asserted single-entry before indexing; `status: {}` decodes to an empty map.

**Compatibility:** behavior-neutral for all callers (verified — the controller only reads `BearerSecretRef` at `ssoconfigdrift_controller.go:138,142`, nothing mutates `*Optional`); compile-time coupling to k8s.io/api v0.36.0; `ci-modules` (`Makefile:263`) is the detection boundary; root module untouched.

**Failure modes:** 12-row table — every tripwire (aliasing regressions, field renames, pattern/required/default drift, const rename, nil-shape regressions, scheme drift) with detection mechanism and severity.

**Migration:** 6 ordered steps — tests land first and fail on HEAD (tripwire), then D1a, tidy, full gates (`Makefile:263` command, root gates, `cli.py modules check`, `make ci`), conventional commit, one-line rollback.

**Acceptance mapping:** all 14 Given/When/Then cases mapped to concrete named test functions with assertion mechanics, marking cases 1–6 net-new (package has zero tests), 7–13 net-new manifest parity, 14 the bounded production change.
