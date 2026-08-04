# Principal Review — `domains/tokenanomaly` Direction 3 design (FamilyID chain + windowed rate_spike)

**Stage:** design (`35dee544`, "Stage: design"). Advisory only; binds no
maintainer. Synthesizes the four supplied deliverables (design author,
performance engineer, protocol expert, security engineer, QA lead) plus my own
spot-verification of their load-bearing claims against the worktree. No `.go`
file was changed by any review, so no Go gate ran on the proposal itself; QA
ran the baseline gates for the tree (see §5).

## 1. Advisory recommendation

**Conditionally ready to implement** — high evidence confidence.

- Every decision-critical claim across all four reviews was independently
  re-verified against source: the six-interface/five-call-site seam surface
  (plus `token_ciba_test.go:70` fake), Decision 2's reachability gap and its
  `handle_introspect.go` fix (`info` is the full `*RefreshToken`), the
  `rate_spike\x00<client>` DedupKey collision, budgets (493/155/442), the
  defaults (4096 / 15m / 3.0 / 20), the openapi schema lacking `family_id`,
  and both pre-existing `make ci` fmt blockers.
- No **Critical** and no **High** finding in any deliverable; the design
  changes no grant/introspect wire behavior, is off the request path, bounded,
  fail-open, and oracle-safe as verified.
- The conditions are: three design decisions the doc must make explicitly
  (subject-fold semantics, `WithMaxTrackedSubjects` config surface, dispatch
  re-amplification acceptance), one change-map addition
  (`sso_usage_geo_test.go`), one load-bearing seam test (Decision 2 Offer),
  citation refresh, and resolution of the pre-existing `make ci` fmt blockers
  before handoff.
- Confidence is high on evidence (spot-checked), medium on the design's own
  internal consistency (stale line citations; one overstated breakage item).

## 2. Consolidated findings

### Critical / High

None in any deliverable. Agreed across security, protocol, performance, QA.

### Medium

| # | Finding | Source | Evidence | Required action |
|---|---|---|---|---|
| M1 | **Family precision is gated on refresh-introspection traffic.** Only introspection Offers carry thumbprints, so access-token-derived and rotation-first findings stay subject-wide; `revoke_family` silently degrades to the user-wide fallback for those paths. Design-documented (Decision 2) but under-documented for operators. | Security F1 = Protocol F1 (dedup: same issue, same corrective) | `detector.go:254-260` thumbprint gate; `handle_introspect.go:358` the only family-bearing Offer; verified | config-reference sentence (family path activates on refresh-token introspection); negative E2E (same scenario without introspection ⇒ family-less finding ⇒ byte-identical subject fallback). Decision to accept the asymmetry: product/security authority |
| M2 | **Decision 2's load-bearing edit has no planned test.** No Offer-content assertion exists anywhere in `protocols/oauth`; dropping `FamilyID: info.FamilyID` later would silently reinstate the permanent no-op with all other tests green. | QA F2 (direction-1 F3 gap still open) | Verified: `introspectDeps.usageRecorder` never read in tests | New `handle_introspect_test.go` test: full-Event equality (Kind, Endpoint, Thumbprint, FamilyID, SubjectID, ClientID) via `memRefreshStore` + recorder capture |
| M3 | **Self-introspection bursts plant attacker-attributed findings under a victim client's DedupKey and inflate the subject-table baseline.** Any active client can introspect its own token ~20×/minute at near-zero cost; the new subject table folds all kinds/endpoints (uniform definition per design D4), so attacker volume moves the spike signal. Sticky via `mergeFinding` earliest-FirstSeen. | Security F2 — conflicts with design D4 | Verified: RFC 7662 client gate; design D4's uniform fold; `tokenanomaly.go:107-113` | **Design decision required** (see trade-off T1). Preferred: fold `EndpointToken` (issuance) only into the subject table — `defaultSpikeFactor`'s own doc says "issuance count", so the subject table copying the client table's introspection-mixing flaw is a new instance of a pre-existing flaw. Owner: security + maintainers |
| M4 | **Change map still incomplete — same gap class the design criticized in the spec.** `interfaces/sso/sso_usage_geo_test.go` has two seam call sites (:132, :167); omitting them breaks the test binary. | QA F1 | Verified (grep) | Add to change map; both call sites gain `""`; extend `TestRecordIssuedSeams_*` to assert drained `Event.FamilyID` |
| M5 | **`WithMaxTrackedSubjects` has no config surface.** Every sibling knob maps from `TokenAnomalyConfig` → `detectorOptions` (`build_governance.go:409-427`); the new cap is code-only and absent from config-reference. | QA F3 | Verified: `config_snapshot.go:429-455` has no max-subjects key | **Design decision required** (trade-off T3): add `token_anomaly.max_tracked_subjects` key or state default-only. Owner: maintainers |
| M6 | **Windowed scan amplifies threat-executor dispatch per burst by up to ~15×** (window/sweep_interval at defaults), since `Analyze` dispatches every finding each sweep. Bounded, idempotent, fail-open; accepted by design (failure mode 2), security (residual 5), protocol (F5), and QA (F8). | Performance M1 | Verified: `processFinding` → `dispatchThreat` has no dispatch gate | **Design decision required** (trade-off T2): gate dispatch on finding-state transition (FirstSeen/LastSeen advance, never key existence) or keep and document the 15× factor in config-reference. QA F8 pins: E2E asserts idempotent final state only, never dispatch counts. Owner: maintainers |
| M7 | **tokengrant seam test is net-new with no precedent, and its named assertion is mislocated.** No `HandleRefreshGrant` unit test exists (package holds only `refresh_grace_test.go`, `token_ciba_test.go`); tokengrant can only assert the Deps argument — the `Event` is built in `interfaces/sso`. | QA F4 | Verified: `ls internal/handler/tokengrant` | Two-layer test: seam-arg equality at tokengrant (new fake `RefreshGrantDeps` with family-carrying `Consume`); `Event.FamilyID == "fam-x"` at interfaces/sso |
| M8 | **Subject-table cardinality is unobserved.** `TrackedBuckets` covers only the wrapped store; worst case ~4096 rows × 16 minutes ≈ 65k entries ≈ 3–5 MB with map overhead; a feed-guard regression churns the cap invisibly. | Performance M2 | Verified: `TrackedBuckets` at `detector.go:276`; design concedes | Extend the `TrackedBucketReporter`-style hook to report obs + subject rows + subject minute entries; unit test driving the table to cap |

### Low

| # | Finding | Source | Evidence |
|---|---|---|---|
| L1 | **Stale line citations throughout the design** — `dispatchThreat` cited at `detector.go:138-155` (actual :407), `evidenceFor` at :157-175 (actual :432), `spikeForClient` at `detect.go:100-136` (actual :122-155), impl at `server_helpers.go:439` (actual :440). No substantive claim wrong, but implementers will mis-locate symbols; the doc's "all evidence verified" claim is overstated for citations. | Protocol F2 | Verified by grep |
| L2 | **`Detail` wording change: breakage item #3 overstated.** No test asserts the generated rate_spike `Detail` (existing tests assert ClientID/Count only) and nothing in-tree matches on it; the wording change is correct and breaks nothing. | Protocol F3 + QA (moot) | Verified: `detector_test.go:171-179` |
| L3 | **`detect.go` budget drift risk unlisted in the design's breakage list** (155 → plausibly 300-400 lines, ~345 headroom). Under 500, but complexity (windowed scan + subject table + eviction) is the real risk; pre-plan a `subject_rates.go` sibling file. | Security F5 | Verified 155 lines |
| L4 | **Legitimate-burst false positive: 20+ logins in one minute for one subject trips a subject-scoped spike → subject-wide `DeleteAllForSubject`** — self-inflicted DoS on a real user under `default_action: revoke`. Design documents the blast radius but not the false-positive reachability from legitimate waves; the subject dimension makes a single user's burst sufficient (new surface). | Security F4 | Verified thresholds (20/3.0) | Partially mitigated by T1's issuance-only fold; pair with `rate_limit`/severity conditions in docs. Product/security decision |
| L5 | **Subject-table row churn can evict victims' rows at cap** (attacker × N clients via dynamic registration). Bounded detection-quality DoS, pre-existing class. | Security F3 | Verified cap/eviction design | Optional per-subject row budget; keep the empty-SubjectID feed guard pinned by test |
| L6 | **Subject-table eviction: O(rows × minutes) linear scan; specify it + the memory bound.** Sort-based eviction gives no benefit; state the ~3-5 MB worst case in the doc instead of "65k entries". | Performance L1 | Design D4 | Implementation guidance |
| L7 | **Double lock acquisition per `Record` for thumbprint events.** Fold the subject update and observation update into one critical section per `Record`; micro-benchmark acceptance < 15% ns/op. | Performance L2 | `detector.go` Record | Implementation guidance; state in the design |
| L8 | **`Analyze` lock-hold scales with the subject scan** (O(cap × window²) if the cap is raised); snapshot the subject table under lock and compute candidates outside. | Performance Info | — | Implementation guidance + option doc sentence |

### Info

| # | Finding | Source |
|---|---|---|
| I1 | **Exported SDK break:** `Server.RecordRefreshTokenIssued` (`accessors_handlers.go:457`) gains a parameter — direct SDK callers break at compile time; needs a changelog note in the same change. | Security F7 |
| I2 | **Cross-tenant governance-view mixing** in the global detector (no tenant predicate on `Inspect`) — pre-existing; family adds only an opaque id. Document for multi-tenant deployments. | Security F6 |
| I3 | **RFC 9700 section citation drift** in `oauthspi/refresh_token.go` (off-by-one per reviewer knowledge; could not verify offline). Check at implementation time. | Protocol F4 |
| I4 | **DedupKey representation flip accepted:** client- and subject-scoped winners upsert the same row across sweeps; one config-doc sentence prevents operator confusion. | Protocol F5 |
| I5 | **CAEP receiver-side dedup** (relied on by the repeated-dispatch story) not verified in this pass. | Performance "Partial" |
| I6 | **E2E naming:** the new family-revoke E2E must be named `TestE2E_*` or the design's own verification line won't run it. | QA F9 |
| I7 | **Pre-existing `make ci` fmt blockers:** `infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go` (modified) and `test/region_token_contract_test.go` (untracked; flagged in direction-1 F5, still unfixed) — the ci chain cannot reach vet/race/examples/proto-lint/route-contract until resolved. Requires maintainer authorization to touch unrelated worktree files. | QA F9, verified |

## 3. Trade-off ledger

| # | Conflict | Options | Recommendation | Consequence | Decision owner |
|---|---|---|---|---|---|
| T1 | **Subject-table fold semantics:** design D4 folds all kinds/endpoints ("uniform signal definition"); Security F2 shows self-introspection (attacker-controlled, near-free) plants findings and inflates baselines; F4 adds legitimate-burst false positives. | (a) uniform as designed; (b) issuance-only (`EndpointToken`) fold; (c) share-weighted or distinct-thumbprint candidates | (b) issuance-only: matches `rate_spike`'s documented "issuance count" semantics, removes the attacker's free signal, narrows F4; the client-side table's introspection mixing is pre-existing and untouched | (b) changes the subject dimension's signal definition (rotation bursts still fully captured — they are issuance); requires a pin test that introspection bursts do not move subject spike signals | Security + maintainers (design deviation from D4) |
| T2 | **Repeated dispatch (~15× per burst):** Performance M1 wants gating on state transition; design/security/protocol/QA accept re-dispatch (matches `anomaly.Runner` semantics, idempotent, rate-limited). | (a) gate on FirstSeen/LastSeen advance; (b) keep + document the 15× factor in config-reference | (b) keep — no SLO or baseline exists to justify a behavioral change now; document in config-reference; E2E asserts idempotent final state only; re-visit when B4 baseline exists | (b) bounded off-path amplification (≈15 idempotent DeleteFamily + bus events per burst) persists; operators see it in logs | Maintainers; perf re-check at B4 |
| T3 | **`WithMaxTrackedSubjects` config surface:** QA F3 vs design D4 (option only). | (a) add `token_anomaly.max_tracked_subjects` key + config-reference row + config-validate-all; (b) state default-only in the design | (a) — every sibling knob is config-mapped; a memory bound operators must size deserves a key; trivial cost | (a) one new config key = documented contract addition in the same change | Maintainers |
| T4 | **Family-precision scope (M1):** the direction's headline benefit is delivered only for introspected lineages; access-token and rotation-first paths keep the user-wide hammer. Design accepts (Decision 2 alternative correctly rejected). | (a) accept + document + negative E2E; (b) descope Improvement 2; (c) issuance-time jti callback (rejected: bigger surface) | (a) accept — proportionate; pin the fallback as load-bearing with the negative E2E | (a) operators must understand when the fallback fires; asymmetry persists until a follow-up (subject table keyed by family where known) | Product + security |
| T5 | **`Detail` wording change (L2):** design lists it as a breakage risk; no test or matcher depends on it. | (a) keep wording, drop the overstated breakage item; (b) keep wording + keep the item as defensive | (a) — the change is correct and free | None | Design author |

## 4. Preconditions, acceptance, rollback, monitoring

### Preconditions before implementation

1. Amend the change map with `interfaces/sso/sso_usage_geo_test.go` (M4) and the Decision-2 seam test (M2).
2. Resolve T1 (fold semantics), T2 (dispatch), T3 (config key) explicitly in the design doc.
3. Re-cite the design's line numbers from HEAD (L1).
4. Resolve the two pre-existing `make ci` fmt blockers with maintainer authorization, or the handoff gate cannot complete (I7).
5. config-reference additions: introspection-coverage dependency (M1), family-scoped revoke guidance (D3), dispatch re-amplification (T2), subject-cap knob if T3(a).

### Executable acceptance checks (at implementation)

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./domains/tokenanomaly/... ./domains/threataction/... ./domains/metering/... -race -count=10
go test ./internal/handler/tokengrant/ -v        # new token_refresh_test.go seam-arg tests
go test ./test/ -run TestE2E -v                  # includes new TestE2E_* family-revoke precision test
make ci                                          # after fmt blockers resolved
```

Plus the reviews' priority pins: DedupKey-collision regression (one row per client across dimension-changing sweeps), windowed-predicate equality (burst at T−2, flat→spike→flat, brand-new client never self-trips), family chain (observation → Finding → Threat → `Evidence["family_id"]` → `DeleteFamily` spy), subject-table cap/guard/pruning, Offer full-Event equality (M2), negative E2E (M1), and — first time in the repo — a composition test wiring `WithTokenAnomalyDetector` end-to-end (direction-1 F2 gap, carried).

### Rollback triggers

- Family revoke mis-scoping (wrong lineage killed) → disable `threat_action` (default noop) — the executor is operator-wired, so rollback is config-only, no redeploy needed.
- Subject-spike false-positive revokes under `default_action: revoke` → disable the policy or the detector section; feature is opt-in and off the request path.
- `Dropped` counter > 0 or drain lag approaching queue depth at the chosen RPS (B3) → raise `queue_size`, lower RPS assumptions.

### Monitoring (gaps to close in the same change)

- Sweep duration gauge (does not exist today), subject-table cardinality (M8), `Dropped`/drain lag, executor invocation count per burst (B4 baseline), finding-store row count. No SLOs exist for any of this — establish baselines, not targets.

### Explicit exclusions (confirmed intentional)

- No `Bucket` dimension, no migration, no store change; no issuance-time jti callback; no grant/introspect/discovery/error-code/audit changes; `RevokeFamilyExecutor` semantics unchanged (reachability only); no new top-level packages; cross-replica E2E out of scope (per-replica observation tables); no certification claims made or implied.

### Residual risks (accepted or owned)

- M1 asymmetry: family-scoped revoke only for introspected lineages (product/security decision T4).
- M6 re-dispatch amplification (maintainers, T2).
- Consecutive-burst baseline dampening (design-documented, accepted).
- L4 legitimate-burst false-positive reachability (mitigated by T1; operators pair `revoke` with `rate_limit`).
- Unobserved subject-table growth until M8 lands.
- Cross-tenant governance-view mixing (pre-existing, I2).

## 5. Missing reviews/evidence and next actions

**What did not run or is not evidenced:**

- **No Go gates ran on the proposal** (no `.go` changed — correct, but the design's verification plan is untested until implementation). QA's baseline (build+vet, maintainability/architecture, `-race` on the three domains, `TestE2E` 4 tests, config-validate, modules-check) all PASS this revision; `make ci` FAILS at fmt on two pre-existing unrelated files (I7) — the chain after fmt (vet, race, examples, proto-lint, route-contract, nested modules) is therefore unverified on this tree.
- **No SLOs, no benchmarks** exist for token telemetry (zero `func Benchmark` in `domains/`/`internal/`); the perf plan B1–B4 is baseline-first and must land with the change.
- **CAEP receiver-side dedup** claim (I5) — one `Partial` in the performance deliverable; verify before relying on the repeated-dispatch story.
- **RFC 9700 numbering** (I3) — verify offline at implementation time.
- **No dedicated architecture, SRE/ops, or compliance deliverable** was supplied for this design; import-direction and budget gates are covered by the committed gates and QA's runs, but sweep-cadence ops behavior and any compliance framing rest on the security review alone.
- **No certification evidence** — none claimed, none exists; the design's conformance posture is RFC-grounded invariants verified against code.

**Narrow next actions to decide (in order):**

1. Maintainers rule on T1 (fold semantics) and T3 (config key) — the only two design decisions that change the doc's surface.
2. Maintainers rule on T2 (dispatch gating vs documented acceptance).
3. Design author: amend change map (M4), add Decision-2 seam test (M2), refresh citations (L1), state T1/T2/T3 resolutions.
4. Maintainer authorization to resolve the two fmt blockers so `make ci` can complete at handoff.
5. Product/security accept T4 (family-precision asymmetry) with the config-doc sentence and negative E2E.

No sign-offs, deadlines, or approval status are asserted beyond this advisory posture.
