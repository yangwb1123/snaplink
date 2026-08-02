All verification complete. Here is my gatekeeper cross-check.

---

# Gatekeeper Review — `docs/auto/domains-region-observability-design.md`

**Inputs**: 6 review deliverables (security, QA, SRE, principal, performance, compliance) vs. the design at its current on-disk state (mtime 2026-08-01 16:59, unchanged since HEAD `36d0527c`; no revision markers, no corrective edit pass present). I independently re-verified the load-bearing mechanics behind every blocking finding against source.

## Independent re-verification of the blocking mechanics

| Claim | My verification |
|---|---|
| Options apply in slice order | `sso.go:88-89` `for _, opt := range opts { opt(s) }` ✓ |
| `WithTenantResidencyCheck` appended before `WithMetrics` in stock build | `build_stores.go:68` `wireDomains()` → `wireGeoRegionRisk` → `wireRegion` (`build_app_selfservice.go:262`); `build_stores.go:71` `wireEdge()` → `wireMetricsCollector` → `WithMetrics` (`build_app_oidc.go:414`) ✓ |
| `WithMetrics` is the sole writer of `s.metrics` | `options_misc.go:331-333` ✓ |
| Precedent `SetFeatureGateEnabled` runs post-options | `sso.go:311` inside `recordFeatureGateStartup()` (post-options tail) ✓ |
| Alert gate requires `summary` AND `description` | `platform/metrics/alert_rules_test.go:91-98` ✓ |
| No stock resolver ever errors (dead `SSORegionResolutionDegraded`) | `domains/region/resolver.go:62-87` — absent/rejected values fall back to `(Default, nil)`; `ChainResolver` only propagates ✓ |

## Finding-by-finding cross-check (blocking list from the principal review §4 preconditions)

| # | Finding (severity) | In the design today | Status |
|---|---|---|---|
| C1 | Boot gauge set in `WithTenantResidencyCheck` no-ops under stock option order → `SSOResidencyFailOpen` dead in the stock binary | Design still mandates: "set to 1 by `WithTenantResidencyCheck` via the nil-safe setter" (Decision 2, API surface §2) and sequencing step 2: "`ResidencyEnabled` setter in `WithTenantResidencyCheck`". No post-options `applyMetricsWiring` hook, no order-independence test, no cmd-level option-order check. | **UNRESOLVED** |
| H1 | Alert YAML fails `TestDeployAlerts_ConventionsHold` | Snippet still uses `# description:` YAML comments, no `summary` annotation (Decision 2, §4). | **UNRESOLVED** |
| H2 | "Enabled but never enforcing" (silent-inert) is unobservable | No guard alert (`enabled==1 and sum(rate(decisions[1h]))==0`), no boot-time validation in `wireRegion`, no dropped-region counter. The design's only reference to this failure class is the problem restatement itself. | **UNRESOLVED** |
| M1 | Mesh-path `region_denied` per-request durable amplification | Design still asserts "The `region_denied` event is rare by construction (denial-only)" (Decision 3, Storage model) with unbounded per-request emission; no token bucket, no sampled event, no suppression counter. | **UNRESOLVED** |
| M2 | `region` label cardinality unbounded in legacy config | Design still states "an attacker who can influence the region label can already influence the policy itself, so no new trust boundary" and defers to "Documented in the observability section as an operator obligation". No `region="unlisted"` bucketing, no boot warning for empty allowlist + unset `trusted_proxies`. | **UNRESOLVED** |
| M3 | No cmd test covers `wireRegion` OnError closure; design's hedge is void | Design still hedges: "The unit test on the closure (`build_app` test path) is what pins this" — the review verified no such test path exists. | **UNRESOLVED** |
| H3 | "Gauge guards both alert expressions" self-contradicted; `SSORegionResolutionDegraded` unreachable | Design still claims "the existence guard on both alert expressions" (Decision 2, API surface §2) while its own YAML guards only `SSOResidencyFailOpen`; no re-key onto a reachable signal, no embedder-facing documentation. | **UNRESOLVED** |
| L1 | "No `test/` e2e wires `WithMetrics`" is false | Design still carries "Test-harness gap: … if no `test/` e2e currently wires `WithMetrics` … the one acceptance item with a real unknown" (Decision 4, What could break) — refuted by `test/metrics_e2e_test.go:73`, `ratelimit_e2e_test.go:74`, `tenant_metrics_e2e_test.go:89`, `ciba_ping_test.go:182`. | **UNRESOLVED** |
| L2 | "`me` surface: GET `/me`, `/me/data-export` only — verified" inaccurate | Still says "consumed by `protocols/selfservice` for GET `/me`, `/me/data-export` only — verified" (Decision 1, API surface §2) — omits `selfservicenotification/handlers.go` (3 sites) and `profile.go:58`. | **UNRESOLVED** |
| L3 | Observe ladder has no unmapped-error default | Design says only "must not inherit a future default's label"; does not pin the default branch (observe nothing + log) the review requires. | **UNRESOLVED** |
| L4 | `docs/auto/` must not ride the implementation commit | Directory still untracked; `TestArchitecture_DirectorySubdirFanout` red on disk (docs 17 > 16). Process gate for the implementation commit, not fixable in the doc — but must be enforced at commit time. | **UNRESOLVED (process)** |
| T1 | SDK break decision | Design does decide: param version preferred, fallback seam documented, release note called. | Resolved (only decision item with a committed position) |
| T2/T3/T5/T6/T8 | Bounded emission / silent-inert choice / cardinality enforcement / dead-alert re-key / gauge placement | No decision recorded for any. | **UNRESOLVED** |

## Assessment

The design is unchanged from the state the reviewers examined. **None of the three blocking defects (C1, H1, H2) is addressed**, none of the four medium items (M1, M2, M3, H3) is resolved, and the low-severity evidence errors (L1, L2, L3) are still present verbatim. The principal reviewer's precondition list (§4: "all must land in the design before coding") is entirely unfulfilled, and the compliance officer's final posture — "as written today, half of that claim — the detection half — fails verification in the default build" — still holds.

Most critically, C1 remains a **test-reality divergence**: the design's own proposed acceptance test ("gauge 1 after option / absent without") would pass with hand-picked option order while the stock binary ships the alert dead — the exact failure the review consensus flagged as Critical.

There is no delta to re-review; the corrective edit pass never happened. The implementation stage must not start from this document.

VERDICT: FAIL - blocking issues: C1 (gauge set inside WithTenantResidencyCheck no-ops under stock option order; must move to a post-options step e.g. applyMetricsWiring with an order-independence test), H1 (alert YAML fails TestDeployAlerts_ConventionsHold; needs real summary+description annotations), H2 (silent-inert "enabled but never enforcing" gap unresolved; pick guard alert / boot validation / dropped-region counter and document), plus unresolved M1 (unbounded mesh region_denied emission), M2 (unbounded region label cardinality), M3 (void cmd-test hedge), H3 (self-contradicted gauge-guard claim + dead SSORegionResolutionDegraded), and doc corrections L1-L3. The design must be revised to close these and re-reviewed (delta) before implementation.
