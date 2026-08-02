All verification complete. The design (21:22) predates all seven reviews (21:30–21:40) and has **not been amended** in response to them — every principal-review precondition remains unmet in the document.

---

# Gatekeeper cross-check: review findings vs `domains-tokenanomaly-direction3-design.md` (HEAD `35dee544`)

## Resolved or dismissed with reasons (in the design as written)

| Finding | Design disposition | Verdict |
|---|---|---|
| M1 family precision gated on introspection traffic | Decision 2 explicitly accepts the asymmetry, explains why introspection is the correct seam, rejects the issuance-time callback alternative with reasons, and composes the subject dimension for rotation bursts | **Dismissed with reasons** — but the required corrective artifacts (config-reference coverage sentence, negative E2E) are absent from the change map/test plan |
| M6/T2 ~15× dispatch amplification | Failure mode 2 accepts with reasons (idempotent `DeleteFamily`, finding-store upsert, `anomaly.Runner` precedent) | **Dismissed with reasons** — but the supporting claim "receiver-side dedup" is factually wrong (see DS F3 below), and the config-reference sentence is unplanned |
| M8 subject cardinality unobserved | Failure mode explicitly concedes the gauge gap with reason (bounded cap × window) | **Dismissed with reasons** — memory bound understated ("well under" vs ~3–5 MB) |
| L2 `Detail` wording | Deliberate, documented surface change; "breakage" item is defensive only | **Dismissed with reasons** |
| L4 subject-wide revoke scope | Design argues subject-wide is the *correct* scope for the signal | **Dismissed with reasons** — but legitimate-burst false-positive reachability (20+ logins/min ⇒ `DeleteAllForSubject` under `default_action: revoke`) is not documented |
| L5 subject-row churn | Bounded, pre-existing class; feed-guard pin planned | **Dismissed with reasons** |

## Neither resolved nor dismissed — blocking

- **M2 (Medium)** — The load-bearing Decision-2 edit (`handle_introspect.go` Offer + `FamilyID`) has **no planned test**. Verified: zero Offer-content assertions exist in `protocols/oauth` today, and the design's test plan lists none. Regressing this silently reinstates the permanent no-op the design exists to fix.
- **M4 (Medium)** — Change map omits `interfaces/sso/sso_usage_geo_test.go` — **verified 2 seam call sites (:132, :167)**; omitting them breaks the test binary. Same gap class the design itself criticized in the spec.
- **M3/T1 (Medium)** — Subject-fold semantics: design D4 chose uniform all-kinds fold, but the security concern (self-introspection bursts planting attacker-attributed findings under a victim client's sticky `DedupKey` and inflating the subject baseline) is **not dismissed on its own terms**; the principal defers the ruling to maintainers and **no ruling is recorded**.
- **M5/T3 (Medium)** — `WithMaxTrackedSubjects` has no config surface — **verified** `TokenAnomalyConfig` (config_snapshot.go:429) has no such key while every sibling knob is config-mapped. The design states the option without the required "default-only" decision.
- **M7 (Medium)** — tokengrant seam test assertion is mislocated: **verified** no `HandleRefreshGrant` unit test exists and the package holds only `refresh_grace_test.go`/`token_ciba_test.go`; tokengrant can only assert the Deps *arg*, the `Event` is built in `interfaces/sso`.
- **DS F3 (Medium)** — The design's "receiver-side dedup" evidence claim is **factually inaccurate**: verified `publishRevoked` (actions.go:193) carries only `threat_action/threat_type/subject_id` while the sole `KindTokenRevoked` receiver arm (cross_replica.go:102-108) requires `MetaRevokedToken` and drops the executor's event — it is **publish-only**. Failure mode 2's dismissal basis needs correction.
- **DS F1 (Medium)** — Per-replica observation locality never mentioned: family precision additionally requires the introspection to land on the replica holding the observation; undocumented in a fleet deployment.
- **SRE F1/F2/F5/F6 (Medium)** — No liveness/metrics plan in the change map (no sweep-duration gauge, no finding log line, `alerts.yaml` silent), per-replica ephemerality of the new subject table undocumented, sweep-interval-as-latency-budget coupling unvalidated, introspection-coverage sentence missing.
- **L1 (Low)** — Stale citations, verified (`dispatchThreat` :407 not :138; `spikeForClient` :122 not :100); not re-cited from HEAD.
- **L3/L6/L7/L8 (Low)** — `detect.go` budget drift absent from the breakage list; single-lock `Record`, linear eviction + stated memory bound, and `Analyze` snapshot not specified in the doc.
- **I6/I7 (Info)** — new E2E unnamed (design's own `-run TestE2E` line would skip it); pre-existing fmt blockers **verified** (both files fail `gofmt`) keep `make ci` from reaching the rest of the chain at handoff.

## Verdict reasoning

The design is protocol- and security-sound — no Critical/High anywhere, all decision-critical claims independently re-verified. But the gate here is whether the review findings are resolved or dismissed with reasons *in the deliverable*. The design predates the reviews (21:22 vs 21:30–21:40) and was never amended: all seven of the principal review's own preconditions (change-map amendment M4, Decision-2 seam test M2, T1/T2/T3 rulings, citation refresh, config-reference sentences, fmt blockers) remain open. Six Medium findings — including one that breaks the test binary (M4) and one where the design's dismissal basis is factually wrong (DS F3) — are neither resolved nor dismissed. Implementation must not start until the design is amended and the rulings are recorded.

VERDICT: FAIL - design not amended post-review; blocking: (1) M2 no planned test for the load-bearing Decision-2 introspect Offer; (2) M4 change map omits interfaces/sso/sso_usage_geo_test.go (test-binary compile break); (3) M3/T1 subject-fold semantics ruling (issuance-only vs uniform) unrecorded; (4) M5/T3 WithMaxTrackedSubjects config surface ruling unrecorded; (5) M7 tokengrant seam-assertion mislocation; (6) DS F3 inaccurate "receiver-side dedup" claim must be corrected; (7) M1 negative E2E + introspection-coverage config sentence missing; (8) L1 stale line citations; (9) SRE/DS visibility items (liveness, sweep gauge, subject cardinality, per-replica doc) unaddressed in change map; (10) I7 pre-existing gofmt blockers unresolved (block make ci at handoff).
