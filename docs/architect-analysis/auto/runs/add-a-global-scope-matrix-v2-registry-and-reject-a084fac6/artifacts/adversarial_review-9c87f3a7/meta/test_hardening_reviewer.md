Audit complete. Deliverable: `docs/architect-analysis/auto/runs/add-a-global-scope-matrix-v2-registry-and-reject-a084fac6/artifacts/test-migration-pin-audit/task-1-test-migration-pin-audit.md` (344 lines, every claim re-verified against the worktree; `go build ./... && go vet ./...` green).

## Verdict

| Mode | Status | Gap |
|---|---|---|
| **1. Silent partial gate (config ahead of code)** | Partially pinned | `TestLoadUnknownKeysWarnsAndIgnores` pins the generic WARN mechanism and the wiring test pins the zero-value side, but nothing pins the flip config being honored by the current binary with **zero self-warn**, and nothing pins the generated JSON schema knowing the block (the strict pre-flight surface) |
| **2. Canary-config-final equality** | Unpinned | `TestScopeRegistry_MixedReplicaDivergence` pins only the enablement axis; no registry-**content** divergence (two enabled replicas, different `extra_scopes`) — the Q3.5 self-inflicted-drain mechanism |
| **3. Post-rollback mint byte-identity** | Partially pinned | Default-path pin is a fresh unwired server; no sequential reject→accept for the same request/credential (with the honesty constraint: 200 mint bodies aren't byte-comparable across servers — jti/exp — so the pin is rejection-body byte-identity + structural restoration) |
| **4. Refresh reject-then-rollback retryability** | Unpinned | The ON-side 400 is pinned, but never non-consumption (second 400 must stay `invalid_scope`, not `invalid_grant`) or the same token rotating at an OFF replica — the migration's key survivability claim |
| **5. Rejection-counter assertions** | Missing entirely | **The metric does not exist** — no `NameScopeRegistry*` anywhere; code + assertions must both be added |

## Proposed in-repo additions (6 named pins + 1 harness)

- `TestScopeRegistry_FlipConfigDecodesWithoutWarn` + `TestSchemaDocumentIncludesScopeRegistryKeys` (config layer, existing files — 26-file ceiling)
- `TestScopeRegistry_CanaryConfigDivergence_SelfInflictedDrain`, `TestScopeRegistry_PostRollbackRestoresMintPath`, `TestScopeRegistry_RefreshRejectThenRollbackRetryable`, `TestScopeRegistry_RejectionCounter_Scrape` (new `test/scope_registry_migration_test.go` — current file is 394/500 lines)
- `newScopeRegistryFleetHarness` — two replicas over **shared** client+refresh stores, mirroring the distributed deploy's shared postgres/redis
- Metric: `sso_scope_registry_rejections_total{branch}` with a **bounded 9-value branch label** — per-scope labeling rejected as attacker-controlled cardinality (violates the §5 bounded-label discipline); folded into existing `platform/metrics` files (10/10 fan-out ceiling)

Key finding worth flagging: item 5's per-scope counter (as recommended by the migration reviewer) is **not in-repo-viable** in its raw form due to unbounded label cardinality — the audit proposes the bounded branch-label substitute, which preserves the dispatch-vs-store-bound axis the migration actually needs. Pre-existing `TestArchitecture_*` gate failures under `docs/architect-analysis/auto/**` reported separately as environmental.
