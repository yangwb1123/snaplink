Requirements specification written: `docs/architect-analysis/cmd-sso-operator-b4-3-crd-parity-requirements.md`.

## Summary

**Evidence verification (all cited facts re-checked against HEAD):**

| Citation | Verdict |
|---|---|
| `apiv1alpha1` 255-line single file, zero `_test.go` | Confirmed — `go test ./apiv1alpha1/` reports `[no test files]` |
| `crd-ssoconfigdrift.yaml` baseURL pattern (64–71, 97–101), required clusterA/clusterB (58–61, 91–94) | Confirmed — pattern at lines 66/99; spec-level `required: [clusterA, clusterB]` at 51–53 (~2-line drift on the endpoint-required citation) |
| `Makefile:263` gate command | Confirmed — exact line in `ci-modules` |
| Controller test 29–42 (only `AddToScheme` exercised) | Confirmed — `drift.AddToScheme` at 38–40 |
| `DefaultPollInterval = "5m"` (types.go:21), controller fallback (211–215), no `default:` key in YAML | Confirmed |
| Baseline | Green — operator module builds, `go test -race ./...` passes; CHECKS_REGISTRY has zero coverage for this surface |

**New finding surfaced (D1):** `ClusterEndpoint.DeepCopyInto` (types.go:147–148) does `out.BearerSecretRef = in.BearerSecretRef`, aliasing the `Optional *bool` pointer — while `corev1.SecretKeySelector` has a generated `DeepCopyInto` (k8s.io/api@v0.36.0, zz_generated.deepcopy.go:5719–5728) that copies it. This diverges from the file's own promise of "exact mechanical shape controller-gen would emit" and is precisely the aliasing class the direction names. The spec's R1 Spec-isolation assertion fails on HEAD; D1a pins the one-line fix, D1b (document-as-known) is rejected as partially unmet acceptance.

**Requirements:** R1 DeepCopy round-trip + per-region mutation isolation (ObjectMeta, Items, ListMeta, Spec, Status, nil-shape, nil-receiver guards), R2 `AddToScheme`/`Recognizes`/`ObjectKinds`/`GroupVersion` registration, R3 parsed-`crd-ssoconfigdrift.yaml` parity (identity block, reflection-derived JSON-tag key sets compared both directions, required lists, `^https://.+` pattern, pollInterval optional + `DefaultPollInterval == "5m"`, status field shapes, subresource + printer columns). 14/14 machine-checked Given/When/Then cases under the `Makefile:263` gate; no root-module changes, no new module paths (yaml.v3 v3.0.1 already in go.sum — one-line indirect→direct promotion only).
