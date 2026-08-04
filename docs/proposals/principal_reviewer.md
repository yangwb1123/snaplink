All contested claims are now verified against source. I have everything needed for the synthesis.

---

# Principal Review — `infrastructure-redis-direction1-design.md`

**Inputs synthesized:** design doc (664 lines), spec (`infrastructure-redis-direction1-spec.md`), database-architect review (`infrastructure-redis-direction1-database-review.md`), distributed-engineer deliverable, QA-lead deliverable. Independent re-verification performed on the three contested mechanism claims against the pinned go-redis v9.20.0 / miniredis v2.38.0 sources in the module cache and the current worktree.

## 1. Advisory recommendation

**Conditionally ready** (design-stage artifact), with two mandatory conditions before implementation. Evidence confidence: **High** on both conditions — I independently re-verified the source mechanics; **Medium** on the remainder.

The direction itself (single JSON envelope on one non-slot-routed channel, shared-client wiring, no persistence/replay, drop-not-block buffer 16, `BuildInvalidationBus` third-parameter shape, config + doc sync) is sound, multi-reviewer-verified, and consistent with the SPI and peer backends. But the design's **central invariant is not delivered by the mechanism it specifies**, and the fix reshapes the Bus's internal architecture and its acceptance tests:

- **Condition 1 (Critical, C-1):** go-redis v9.20.0 `PubSub.Channel()` does **not** close on connection loss or reconnect exhaustion. Verified in vendored source: `initMsgChan` (pubsub.go:719-752) runs with `ctx := context.TODO()`, closes `c.msgCh` **only** on `pool.ErrClosed` (set only by explicit `Close()`, pubsub.go:211-229), and otherwise retries forever with 100 ms sleeps; `Receive` → `ReceiveTimeout(ctx, 0)` sets no read deadline (internal/pool/conn.go `deadline()` → `noDeadline`); the 3 s health-check ping calls `reconnect` but never closes the message channel. The database architect's empirical run corroborates (channel still open 8 s+ after server death; closes only on client `Close`). **The design must own the receive loop** (`ReceiveMessage`/`ReceiveTimeout` with a bounded read deadline; any error closes `out` exactly once via single `defer close(out)`; `defer ps.Close()` to release the dedicated `pubSubPool` connection per resubscribe cycle).
- **Condition 2 (High, H-1):** `NewBus(rdb goredis.Cmdable, ...)` cannot compile. Verified: `Cmdable` embeds `PubSubCmdable` (Publish only); `Subscribe` is on `UniversalClient` (universal.go:355). Change the parameter type (or a minimal local interface). The wiring claim itself holds (`b.redis` is a `UniversalClient`).

Consequence if shipped as written: during any Redis outage or pub/sub-connection death, a replica goes silently blind — no `invalidation_bus_degraded` audit, gauge stays 1, `/readyz` green, no re-seed on recovery, and `KindTokenRevoked` misses deny-sets for the token's remaining lifetime. This is precisely the "stale invalidation window invisible to operators" that spec improvement 3 exists to close, and **the spec's own acceptance test for improvement 3 is unsatisfiable by the design's own mechanism** (the client-close variant passes vacuously; the miniredis variant observes no closure).

## 2. Consolidated findings

Deduplicated across all supplied reviews. Severity per the shared rubric; evidence labels per README.

### Critical

**C-1 — Loss-detection invariant not delivered by `PubSub.Channel()` on pinned go-redis v9.20.0.**
*Sources: database-review F1 (verified, source + empirical); design F-3/F-4 taxonomy rows and API-surface bullet (contradicted); spec line ~72 premise (contradicted); QA H1 (Partial — mechanism premise wrong, see C-1 note below).*
- **Evidence:** vendored `pubsub.go` `initMsgChan`/`Receive`/`conn`/`Close` as verified in §1; empirical channel-open-at-8s vs close-on-client-Close (database architect, scratch program at exact pinned versions).
- **Impact:** silent blindness during outages; recovery loop never triggered; missed revocations not re-applied.
- **Recommendation:** bus-owned receive loop (per database-review F1 fix, including `ps.Close()` on exit to avoid pooled-connection/goroutine leak per resubscribe attempt). Rewrite the failure taxonomy's rows 2–3 and the "internal heartbeat closes the channel" claim in the same change; correct the spec's mechanism sentence.
- **Executable validation:** unit test that closes the **miniredis server** (not the client) with a live subscription → `out` closes; `Publish` errors; restart on same address (`StartAddr`) → fresh `Subscribe` receives. Verified workable: miniredis `Restart()` (miniredis.go:238) and `StartAddr` (:192) exist in v2.38.0.

*C-1 note on the QA deliverable:* the QA lead's H1 premise — "the PubSub receive channel closes only after reconnect-retry exhaustion (≈1–3 s)" — is **false per source**: there is no retry-exhaustion path in `initMsgChan`; the loop is unbounded. The QA's practical prescriptions (polling with ≥10 s deadlines, reversible loss mechanism) survive, but the stated timing mechanism does not. Post-fix, closure on any receive error is immediate, and the 1–3 s reasoning should not be carried into the test plan.

### High

**H-1 — `NewBus(rdb goredis.Cmdable, ...)` does not compile.**
*Source: database-review F2 (verified: `Cmdable` has no `Subscribe`; `UniversalClient` does).* Fix per §1. No behavioral consequence; blocks the build.

**H-2 — Self-skip instance-ID uniqueness is per-host, not per-process; stock wiring would enable self-skip by default with a collidable ID.**
*Sources: database-review F3 (verified: `ResolveServiceID` fallback is `issuer + "-1"` on hostname failure — identical across all replicas; explicit YAML wins; `build_app_cluster.go:226-232` derivation); design F-1/risk #1 (self-acknowledged "most dangerous failure").*
- The design's mitigation ("unique per host by construction") is weaker than claimed: same-host replicas (host-network containers, multi-process VMs) share a hostname; the hostname-failure fallback is identical everywhere. Since the wiring passes the ID whenever non-empty, the collision risk is live in the stock binary, not hypothetical.
- **Recommendation:** (a) log the effective bus instance ID at construction — the design lists this as possible future work; it must be in this change; (b) per-process uniqueness (pid/random suffix) or self-skip OFF in stock wiring until per-process uniqueness is guaranteed; (c) document the uniqueness requirement at the config key.
- **Executable validation:** boot two replicas with identical config on one host; assert distinct logged instance IDs — fails today by construction on the hostname-failure path.
- **Decision needed:** see trade-off T3 — this is the one failure the degraded loop cannot see, and it touches revocation propagation (security-adjacent availability).

### Medium

**M-1 — Forced-loss recovery E2E lacks a specified, reversible loss-injection mechanism.**
*Sources: QA H1 (verified: `goredis.Client.Close()` is irreversible; miniredis `Close`+`Restart` and `test/ha/tcp_proxy_test.go:19` (unexported, `package ha_test`) are the workable mechanisms); database-review F4 (same, plus mqtt precedent `subscribe_selfheal_test.go:20,52`).* Resolved by C-1 fix + miniredis `Close`/`Restart`; keep the client-close case as a secondary variant. Also verified: `SetInvalidationBusBackoffBaseForTest` lives in `interfaces/sso/export_test.go:125` (package-local), so `test/` (package ssotest) E2E must tolerate the production 1 s initial backoff — poll, don't assert wall-clock; fallback: place the degraded→recover half in `interfaces/sso` where the seam exists.

**M-2 — Two promised failure surfaces have no tests:** initial-subscribe boot failure (Redis unreachable at subscribe time — the contract `StartInvalidationBus` relies on for synchronous boot errors, server_invalidation.go:114-123) and nil-rdb first-use descriptive error (design's infallible-constructor claim). *Source: QA H2 (verified testable: `PubSub.Subscribe` dials synchronously; closed-port client yields a dial error).*

**M-3 — Self-skip exact-match edges untested.** *Source: QA M1.* Must assert: own ID dropped; other ID and **absent** `instance` delivered (the mixed-version direction); near-miss IDs (`"a "`, `"A"`, `"a\n"`) delivered — no normalization.

**M-4 — `Close()` with an active subscription untested** — the path `wireCluster` shutdown relies on. *Source: QA M2.* Test: subscribe → `Close()` → `out` closes exactly once (no double-close panic) → `Publish` returns `ErrClosed`.

**M-5 — No concurrent-publish race scenario enumerated.** *Source: QA M3.* Add `-race -count=10` concurrent-publish + drain (+ concurrent `Close` sub-scenario); precedent `platform/cluster/memory/bus_race_test.go`.

**M-6 — Bus instance ID not pinned to the signing-key replica ID by any test.** *Source: QA M4.* Correction to the QA label: the final design's justification is **accurate** — `build_app_cluster.go:226-232` computes exactly `ReplicaID`-else-`ResolveServiceID` inside `wireCluster`'s file, and the design states it is in scope (the quoted "not in scope" claim is not in the final draft). The substantive point stands: a cmd test must pin bus ID ≡ signing-key replica ID for both the explicit and derived paths.

**M-7 — Silent-stall detection needs a bus-owned read deadline; the read deadline is also the transient-blip absorption window.** *Sources: database-review F5 (verified: with C-1's fix, go-redis's health check is gone; `ReceiveTimeout(ctx,0)` sets no deadline, so a half-open connection blocks for minutes); QA L2 (Partial — its "channel closes only on retry exhaustion" half is false; its point that brief blips are absorbed without degraded signal is true and must be stated).* The design's taxonomy row claiming go-redis's internal heartbeat detects the stall is false (C-1). After the fix: any receive error closes `out`; the chosen read deadline bounds how long a half-open connection blinds the replica. False-positive timeouts are safe (idempotent resubscribe + re-seed) but cost extra re-seed cycles — pick and document the value (30–60 s is a defensible start).

### Low

**L-1 — No real-Redis bus leg in the HA suite.** *Source: QA M5 (verified: `test/ha/ha_recovery_test.go` is gated `SNAPLINK_HA_TEST=1` with a TCP proxy; `tcpProxy` is unexported in `package ha_test` — extract to `test/testkit` if reused).* Tagged/manual suite addition; not default CI.

**L-2 — miniredis fidelity caveats understated:** unbuffered subscriber channel, `Publish` under the server lock; the bus's drop-in-the-decode-goroutine keeps tests safe, but a regression to blocking sends would stall miniredis as a confusing whole-server timeout; real Redis slow-consumer behavior is disconnect-via-output-buffer-limit, not drop. *Source: QA L1 (verified).* One sentence in the design so future editors don't "fix" the drop.

**L-3 — "One `Subscribe` per Bus" is ambiguous and load-bearing.** *Sources: QA L3 (Partial); design API-surface bullet.* The recovery loop (`resubscribeAndReseed`) calls `Subscribe` again after a loss-closure — the design's intent is "one **concurrent** Subscribe," but the contract must state explicitly: repeated sequential `Subscribe` after stream closure is supported; concurrent `Subscribe` is not; `Subscribe` after `Close()` returns `ErrClosed`. An implementer reading "once per Bus" literally would break recovery.

### Info

**I-1 — Backend cutover is a transport switch, not a rolling upgrade.** *Source: database-review F6 (verified: old binary refuses `backend: redis` at boot — fail closed, correct).* The mixed-version section should cover the mixed-**backend** case (some replicas etcd, some redis → no cross-invalidation between groups until rollout completes, TTL-bounded). Document flip-binary-and-config-in-one-window.
**I-2 — Accepted blind spots stand:** F-2 (ping-green-but-pub/sub-dead proxy) and F-5 (cluster fan-out silent drop) — undetectable by any SPI-faithful design, TTL-bounded, correctly excluded. Note these are the *only* silent-loss cases after C-1 is fixed; with the fix, every connection-level loss becomes loud.

## 3. Trade-off ledger

| # | Conflict | Options | Recommendation | Consequence | Decision owner |
|---|---|---|---|---|---|
| T1 | Trust go-redis `Channel()` closure (design/spec) vs bus-owned receive loop (database review, source+empirically proven) | (a) Range `Channel()` as designed; (b) own `ReceiveMessage`/`ReceiveTimeout` loop + read deadline + `ps.Close()` | **(b)**, mandatory (C-1) | False-positive timeouts cause extra resubscribe+re-seed cycles (idempotent, bounded); must manage the `pubSubPool` connection lifetime | Maintainers (design change) + implementer |
| T2 | Detection latency vs re-seed churn: read-deadline length | Short (10–30 s) / long (60 s+) / configurable | Start at a single documented constant (30–60 s); treat timeout as loss; revisit with real-Redis data | Shorter = faster degradation signal + more re-seeds; longer = longer blind window | SRE/maintainers (needs operational data) |
| T3 | Self-skip default-on (efficiency, avoids re-triggering rotation coordination) vs silent collision risk (H-2) | (a) On with host-unique ID (design); (b) on with per-process ID; (c) off in stock wiring unless explicit `replica_id` | **(b) or (c)**; startup log of effective ID is unconditional in all options | (c) costs wasted re-application of own events (must confirm `applyCoordinatedKeyRotation` is idempotent under self-delivery before choosing); (b) keeps efficiency | **Maintainers** (silent availability + revocation-propagation implications; CTO visibility if (a) is insisted on) |
| T4 | Where the degraded→recover E2E lives: `test/` (default CI, no backoff seam, production 1 s backoff) vs `interfaces/sso` (seam available) | Both as designed / split | Convergence half in `test/`; degraded→recover half in `interfaces/sso` (or polling-only in `test/` with ≥10 s deadlines) | Default-CI runtime vs flake risk | Implementer/QA lead |
| T5 | Accept the ping-green/pub-sub-dead blind spot vs add channel heartbeats (violates SPI best-effort) | Accept + document / heartbeats | Accept + document (F-2/F-5); operators must not front pub/sub with a terminating proxy | Residual silent TTL-only window, bounded, never a wrong answer | Maintainers accept; SRE documents |
| T6 | `BuildInvalidationBus` signature: third parameter (design) vs sibling function | Third param / sibling | Third param per `BuildRateLimitPolicy` precedent; nil-rdb guard **before** `NewBus`; memory/etcd branches byte-identical; update `cluster_bus_test.go` + `build_app_coverage_test.go` | Touches one call site and two test files; no behavior change | Implementer |

## 4. Preconditions, acceptance, rollback, monitoring, exclusions, residual risk

**Preconditions before implementation:**
1. Design revised: bus-owned receive loop (C-1), `UniversalClient` (or minimal interface) constructor (H-1), failure-taxonomy rows 2–3 and spec mechanism sentence rewritten, read-deadline value chosen (M-7), startup instance-ID log (H-2), explicit re-`Subscribe`-after-closure contract (L-3).
2. Test plan updated per M-1 (miniredis `Close`/`Restart` mechanism), M-2, M-3, M-4, M-5, M-6, and L-1 placement decided.
3. Maintainer decision on T3 (self-skip default) recorded.

**Executable acceptance checks** (each names a command or test that must pass on a *clean* baseline):
- `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .` — note the current baseline is **dirty**: vet fails on `interfaces/snapshot` duplicate method and maintainability fails on 2 file-size / 10 function-length / 3 cyclo items, all in uncommitted worktree files unrelated to this design (QA §1, verified). These must be reported as pre-existing drift, not absorbed.
- `infrastructure/redis/bus_test.go` suite: round-trip; two-bus fan-out; `ErrClosed`; ctx-cancel exactly-once closure; self-skip edges (M-3); garbage drop; slow-consumer drop; nil-rdb first-use (M-2); subscribe-to-closed-port boot error (M-2); miniredis-close → closure + restart → fresh subscribe (C-1); `Close()`-with-live-subscriber (M-4); concurrent-publish race `-race -count=10` (M-5).
- cmd build tests: `backend=redis` without redis block → `"cluster.bus.backend=redis but no redis block configured (set redis.addrs)"`; with miniredis-backed client → non-nil bus, kind `"redis"`; instance-ID ≡ signing-key replica ID for explicit and derived paths (M-6).
- `test/` E2E: cross-server convergence without etcd; degraded→resubscribe→re-seed→healthy with exactly one degraded + one recovered audit per transition, `sso_invalidation_bus_up` 0→1, post-recovery `KindTokenRevoked` applied.
- `go test ./... -race`, bus tests with `-count=10+`; `make ci`; `docs/config-reference.md:127` row → `off · memory · etcd · redis` + `redis_channel` paragraph.

**Rollback triggers:** degraded audit storms or repeated re-seed cycles after cutover (possible read-deadline sensitivity); silent TTL-only convergence observed in monitoring. **Rollback:** revert binary + config together (old binary refuses `backend: redis` — fail closed; new binary with `backend: etcd` boots). No data migration, backfill, or retention exists (verified: bus creates zero keyspace keys).

**Monitoring:** `sso_invalidation_bus_up`, `invalidation_bus_degraded`/`recovered` audits (once-per-transition), `redis-cli PUBSUB NUMSUB <channel>` == replica count, `redis-cli --scan` over 24 h → no bus keys, effective instance-ID startup log lines distinct per replica.

**Explicit exclusions:** store observability metrics, session-enumeration N+1, `infrastructure/redis/doc.go` drift (all spec-excluded); F-2/F-5 accepted blind spots; no delivery SLO (SPI best-effort).

**Residual risks after fixes:** H-2 collision (mitigated per T3 decision — remains the only silent mode); F-2/F-5 (documented, TTL-bounded); mixed-version and mixed-backend rollout windows (I-1); miniredis fidelity gap (bounded by SPI contract; real-Redis leg per L-1).

## 5. Missing reviews/evidence and next actions

**Not supplied (do not assume they ran):** security review, SRE/ops review, performance review, protocol review. Notable open questions from the supplied material that these would address: the trusted-channel model (F-6 — cross-deployment collision on a shared Redis is a trust-boundary concern, and a garbage/DoS publisher on a shared channel is unauthenticated at the pub/sub layer); real-Redis operational validation of the read-deadline choice (T2) and fan-out assumption; buffer-16 adequacy under revocation storms (no event-rate or message-size measurements exist — `KindTokenRevoked` carries full access tokens; mass-revocation burst behavior is Unknown).

**Evidence gaps:** the database architect's empirical proof ran outside the repo as scratch programs — repeatable in-repo only after implementation; the closure claim is nevertheless source-verified independently here. QA's gate results are the only commands that actually ran this revision (build PASS; vet/maintainability FAIL on pre-existing uncommitted worktree files; `infrastructure/redis/`, invalidation-bus, cluster-bus, and `test/` suites PASS).

**Narrow next actions to decide:**
1. Maintainer: approve the C-1/H-1 design revision (receive-loop ownership + constructor type) and the taxonomy/spec corrections — this unblocks everything downstream.
2. Maintainer: T3 decision on self-skip default-on vs off.
3. Implementer: revise the design doc, then implement per the corrected plan with the QA test matrix; run the mandatory gates on a clean baseline.
4. QA: finalize the forced-loss E2E placement (T4) and the miniredis `Restart` mechanism; record the pre-existing baseline failures as tracked drift.
5. Security review of the shared-channel trust model (F-6) before release of the feature, not at design stage.

**No sign-offs, deadlines, or approvals are fabricated here.** The design is well-evidenced and well-structured, but its load-bearing mechanism claim is disproven by the pinned dependency's source; the revision is small, and the direction remains attractive.
