All research is complete. Here is the QA review. All design claims were re-verified against source; line numbers below are from the current worktree.

---

# QA Review: `infrastructure-redis-direction1-design.md`

**Role discipline:** review-only, advisory. No files modified. Evidence labels: **Verified** / **Partial** / **Missing** / **Inaccurate**. The design is **not yet implemented** — no redis bus code or tests exist; every "test" below is the design's *proposal* mapped to the spec's acceptance checks, grounded in the test infrastructure that already exists.

## 1. Test inventory and commands actually run (this revision)

**Baseline commands run (all at HEAD 26937daf, dirty worktree with 253 modified files):**

| Command | Result | Note |
|---|---|---|
| `go build ./...` | **PASS** | |
| `go vet ./...` | **FAIL** | Pre-existing: `interfaces/snapshot`: method `fixtureBlank.snapshotter` declared twice (`snapshot_test.go:367` vs `restore_modes_test.go:440`) — in uncommitted worktree changes, unrelated to this design |
| `go vet $(go list ./... \| grep -v interfaces/snapshot)` | **PASS** | |
| `go test -run 'TestArchitecture_' .` | **PASS** | |
| `go test -run 'TestMaintainability_' .` | **FAIL** | Pre-existing, all in uncommitted worktree files: file-size ×2 (`build_app_oauth.go` 554, `admin_snapshots.go` 581), function-length ×10, cyclo ×3 (`diff.go:indexCategory` cyclo 40). None in the redis/bus area |
| `go test ./infrastructure/redis/` | **PASS** | |
| `go test ./interfaces/sso/ -run InvalidationBus` | **PASS** | 6 tests: SelfHealsOnChannelClose, CleanCancelNotDegraded, NilBusNoGoroutine, SurvivesTokenRevokePanic, ReseedsOnRecovery, StaysDegradedUntilReseedSucceeds |
| `go test ./cmd/sso-server/ -run 'BuildInvalidationBus\|Cluster'` | **PASS** | 4 tests (`cluster_bus_test.go`) |
| `go test ./test/ -run 'InvalidationBus\|CrossReplica' -count=1` | **PASS** | |

**Design's proposed test inventory** (not yet written): `infrastructure/redis/bus_test.go` (7 unit cases), cmd build-layer config tests, `test/` two-server E2E, forced-loss unit + degraded→recover E2E, `-count=10+` race runs. Verified feasible against the existing scaffolding with the gaps in §3.

## 2. Requirement-to-test matrix (spec acceptance → design plan → status)

| Spec acceptance (from `docs/auto/infrastructure-redis-direction1-spec.md`) | Design plan coverage | Status / evidence |
|---|---|---|
| **I1a** round-trip decode fidelity | `bus_test.go` round-trip | **Covered**; mqtt precedent `TestBus_PublishThenSubscribeReceives` (Verified) |
| **I1b** two buses over one miniredis | "two NewBus instances deliver to each other" | **Covered**; miniredis delivers across connections (Verified, `pubsub.go` subscriber per peer) |
| **I1c** `Close` → `Publish` = `ErrClosed` | covered | **Covered** (mqtt precedent, Verified) |
| **I1d** ctx cancel closes stream exactly once | covered | **Covered**; but bus-`Close()`-with-live-subscriber path is **Missing** (Finding M2) |
| **I1e** self-skip filters own events | covered | **Partial** — exact-match edges untested (Finding M1) |
| **I2** `backend=redis` w/o redis block → boot error; with block → non-nil bus | cmd build tests with miniredis client | **Covered**; error shape mirrors `redisRateLimitPolicy` (Verified, `build_ratelimit_cluster.go:202`) |
| **I2** cross-server E2E in `test/` (package ssotest), convergence without etcd | two servers + redis bus + stores over miniredis | **Partial** — no loss-injection mechanism for the recovery half (Finding H1); `newBusReplica`/`newRevocationReplica` harnesses exist (Verified, `test/invalidation_bus_test.go`, `test/cross_replica_revocation_test.go`) |
| **I2** docs/config-reference.md updated; `make ci` passes | doc-sync included | **Covered** (line 127 Verified as the `off · memory · etcd` row) |
| **I3** unit: transport loss closes subscription; Publish returns error | forced-loss unit (close client or miniredis) | **Partial** — mechanism OK for the unit level; "Redis unreachable at subscribe time" row of the loss taxonomy has **no test** (Finding H2) |
| **I3** integration: degraded → resubscribe → re-seed → healthy, audit once per transition, post-recovery event applied | forced-loss E2E | **Partial** — recovery mechanism unspecified (Finding H1); re-seed assertion half already proven for the loop itself by `TestInvalidationBus_ReseedsOnRecovery` (Verified, passes) |
| **I3** `-race`, `-count=10+` on bus tests | stated | **Partial** — no concurrent-publish race scenario enumerated (Finding M3) |
| Gates after edit: `go build && go vet`, maintainability/architecture, `make ci` | stated | **Blocked by pre-existing baseline** — vet and maintainability gates fail on uncommitted worktree files today (see §1); report separately, not caused by this design |

## 3. Findings

### High

**H1 — The forced-loss recovery E2E has no specified loss-injection mechanism, and the obvious one (client close) is irreversible.** The spec's Improvement-3 acceptance requires degrade **and** recover. `goredis.Client.Close()` permanently kills the pool; the bus holds the closed client, so `resubscribeAndReseed`'s `rdb.Subscribe` fails forever — the test would assert permanent degradation, not recovery. Two verified workable mechanisms exist: (a) miniredis `Close()` + `Restart()` — "restarts a Close()d server on the same port. Values will be preserved" (miniredis v2.38.0 `miniredis.go:238`), the go-redis client survives; (b) a TCP proxy (pattern exists in `test/ha/tcp_proxy_test.go:19`, currently unexported in `package ha_test`). **Required fix:** the design must pick one and specify the test flow. Related timing constraint: with go-redis v9.20.0 defaults, the PubSub receive channel closes only after reconnect-retry exhaustion (PubSub auto-reconnects and resubscribes, `pubsub.go:23,175-183`; default retries ≈ 1–3 s), so degraded-detection assertions need ≥10 s polling deadlines, and in `test/` (package ssotest) the backoff seam `SetInvalidationBusBackoffBaseForTest` is **unavailable** (it lives in `interfaces/sso/export_test.go:125`, compiled only for package sso/sso_test) — recovery assertions must tolerate the production 1 s initial backoff. Test to add: `TestRedisBus_ForcedLossDegradesThenRecovers` in `test/` — flow: two `newBusReplica`-style servers sharing one miniredis + redis bus → `mr.Close()` → `busWaitFor`-style poll for `InvalidationBusReady() != nil` and `invalidation_bus_degraded` count == 1 → `mr.Restart()` → poll for `InvalidationBusReady() == nil`, recovered audit count == 1 with `re_seeded=true`, gauge `sso_invalidation_bus_up == 1` → publish `KindTokenRevoked` on A, assert B's deny-set rejects (pattern from `test/cross_replica_revocation_test.go`). Acceptance assertion: exactly one degraded + one recovered audit event for one transition, and a token revoked during the outage is rejected after recovery.

**H2 — Two promised failure surfaces have no tests: the initial-subscribe boot failure and the nil-rdb first-use error.** The loss taxonomy's first row ("Redis unreachable at subscribe time → `Subscribe` returns error → boot failure surfaces") is the contract `StartInvalidationBus` relies on for synchronous boot errors (`server_invalidation.go:113-118`), and the design explicitly promises `NewBus(nil)` "errors at first use rather than panicking" — neither is in the test plan. Both are testable: go-redis `PubSub.Subscribe` dials and sends SUBSCRIBE synchronously (`pubsub.go:231`), so a client pointed at a closed port returns a dial error. Tests to add in `infrastructure/redis/bus_test.go`: `TestBus_SubscribeFailsWhenRedisUnreachable` — `NewBus` over a client whose `Addr` is a closed listener port → `Subscribe` returns non-nil error within timeout; `TestBus_NilRdbErrorsAtFirstUse` — `NewBus(nil)`: `Publish` and `Subscribe` each return a descriptive error, no panic. Acceptance: both return non-nil, non-`ErrClosed` errors.

### Medium

**M1 — Self-skip exact-match edges untested.** Risk #1 (ID-collision silent coordination loss) is the design's "most dangerous failure," and the only runtime defense is strict own-ID equality. The plan's "filters only own events" test must assert the near-miss edges: instance `"a"` dropped; `"b"` and **absent instance** delivered; `"a "`, `"A"`, `"a\n"` delivered (no normalization). The absent-instance case is the mixed-version direction (older peer, self-skip off → newer peer must not filter). Acceptance: exactly the own-ID message is suppressed; all others arrive.

**M2 — `Close()` with an active subscription is untested.** The design's Close contract ("cancels the internal subscription context so an in-flight Subscribe stream closes") is a distinct path from caller-ctx cancellation and is what `wireCluster`'s shutdown relies on. Test: subscribe → `Close()` → out channel closes exactly once (no panic = no double-close) → subsequent `Publish`/`Subscribe` return `ErrClosed`. Acceptance: closed read on `out` within 3 s; `Publish` returns `ErrClosed`.

**M3 — No concurrent-publish race scenario enumerated.** Spec I1 requires "safe for concurrent use"; the design states `-count=10+` discipline but lists no scenario. Add `TestBus_ConcurrentPublishRace` (`-race -count=10`): N goroutines publishing distinct events while one subscriber drains, with a concurrent `Close()` in a sub-scenario; assert no panic, no deadlock, and every received event decodes to one of the published set. Precedent: `platform/cluster/memory/bus_race_test.go`.

**M4 — Instance-ID wiring equality untested at the build layer.** The design's mitigation for risk #1 is "unique-by-construction ID derivation," but nothing pins the bus's ID to the replica ID the signing-key registry uses. Note the design's justification is **Inaccurate**: "`wireCluster` does not have `ResolveServiceID` in scope at the call site" — `build_app_cluster.go:226-232` computes exactly `replicaID := cfg.Keys.SigningKeyRegistry.ReplicaID` else `ResolveServiceID(cfg.Registry.ServiceID, cfg.Server.Issuer)` inside `wireCluster` today. Add a cmd test: with `replica_id` set and with it empty, the bus instance ID passed by the wiring equals the value used for `WithSigningKeyReplicaID`. Acceptance: both derive from the same expression — a future divergence fails the test.

**M5 — No real-Redis bus leg in the HA suite.** The design's risk #3 concedes the miniredis fidelity gap ("reconnect behavior... only exercised by the forced-disconnect integration test") but proposes no real-Redis validation. `test/ha/ha_recovery_test.go` (gated `SNAPLINK_HA_TEST=1`, real `127.0.0.1:26379` + TCP proxy) already covers redis stores and the etcd bus — add a `testRedisBusReplicaRecovery` leg: proxy sever → degraded audit → proxy re-enable → recovery + re-seed. This is a tagged/manual suite addition, not default CI.

### Low / Info

- **L1 — miniredis fidelity caveat understated in risk #3:** miniredis's subscriber channel is **unbuffered** and `Publish` runs under the server lock (`pubsub.go:20-34`, `direct.go:737-743`). The bus's drop-in-the-bus design keeps the decode goroutine always draining, so tests are safe — but a regression to blocking sends would stall all of miniredis and surface as a confusing whole-server timeout, and real Redis's slow-consumer behavior is disconnect-via-output-buffer-limit, not drop. Worth one sentence in the design so future editors don't "fix" the drop.
- **L2 — Transient-blip absorption unstated:** go-redis reconnects + resubscribes internally for short drops; the channel closes only on retry exhaustion. A brief blip therefore loses events **without** a degraded signal or re-seed — consistent with the best-effort SPI, but the loss-taxonomy table implies every mid-subscription drop surfaces as closure. State it explicitly.
- **L3 — "one `Subscribe` per Bus" is inaccurate:** `resubscribeAndReseed` calls `Subscribe` repeatedly across the bus lifetime (once per recovery). Only *concurrent* `Subscribe` is unsupported. Doc nit.
- **L4 — Decode-API choice unspecified:** whether the goroutine consumes `ps.Channel()` (100-slot buffer, 1-minute-full drop; `pubsub.go:593-607`) or a `Receive` loop changes effective buffering and the drop point. Specify it; the 16-slot out-channel should remain the effective bound.

## 4. Prioritized scenario list

1. **Happy:** publish→subscribe round-trip fidelity (Kind/Key/Payload) — unit.
2. **Happy:** two buses (replicas) over one miniredis; fan-out to both; self-skip on with two distinct IDs (H1's E2E precondition).
3. **Boundary:** envelope version-safety — absent `instance`, unknown extra field, near-miss IDs (M1).
4. **Boundary:** buffer full = drop-not-block; publisher never blocks; subscriber stays alive after drops.
5. **Error:** `ErrClosed` after `Close` (publish + subscribe); `Close` idempotent.
6. **Error:** nil-rdb first-use descriptive error (H2).
7. **Error:** Redis unreachable at initial subscribe → synchronous error (H2).
8. **Error:** garbage payload dropped with log counter; stream stays open (mqtt precedent exists).
9. **Race:** concurrent publish + drain under `-race -count=10`; concurrent `Close` (M3).
10. **Recovery:** forced loss (miniredis `Restart()` or proxy) → degraded audit×1, gauge 0 → resubscribe+re-seed → healthy audit×1, `re_seeded=true` → post-recovery `KindTokenRevoked` applied (H1).
11. **Recovery:** clean ctx-cancel exits without degrading (loop-level, already covered by `TestInvalidationBus_CleanCancelNotDegraded`; must hold with the redis bus).
12. **Manual/tagged:** real-Redis HA leg with TCP proxy sever (M5); real-cluster smoke for fan-out assumption (risk #4).

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**Suite taxonomy (Verified from `Makefile`):** default `make ci` = fmt/vet/race/build/examples/proto-lint/ci-modules/config-validate/modules/route-contract/capabilities/sdk-surface/profiles — includes `go test -race ./...` (so `test/` runs in default CI, but `test/ha` self-skips without `SNAPLINK_HA_TEST=1`). Tagged/manual: `chaos-test` (`-tags chaos`), `dr-drill`, `bench-gate` (opt-in, never in ci), `load-test` (k6, manual), `test/oidc-conformance` (docker compose + `drive_test.py`, manual). The design's new E2E in `test/` **would run in default CI** — it must be miniredis-only (no external services), which it is, and fast enough (≤15 s worst case; see below).

**Gaps:** (1) `test/` has zero miniredis usage today — no precedent for the fixture; (2) the loss/recovery E2E cannot shrink backoff from package ssotest (export seam is interfaces/sso-local) — if it proves too slow/flaky in CI, the fallback is placing the degraded→recover E2E in `interfaces/sso` (package sso_test, seam available, `flakyBus` precedent) and keeping only the convergence half in `test/`; (3) `tcpProxy` is unexported in `package ha_test` — if the proxy mechanism is chosen, extract it to `test/testkit` (exists) rather than duplicating; (4) the design adds no readycheck — correct (Verified: `wireInvalidationBusOpts` registers only the `invalidation-bus` check when bus != nil, and the existing `redis` Ping check covers transport), so no /readyz test changes are needed beyond `InvalidationBusReady` assertions.

**Flake risks:** go-redis retry-exhaustion latency (≈1–3 s) makes wall-clock assertions flaky — use polling with ≥10 s deadlines everywhere a channel-close is awaited; miniredis's unbuffered subscriber channel means any future blocking-send regression manifests as a hang, so all publish-path tests need timeouts; `-count=10+ -race` on the new bus tests is mandatory per AGENTS.md §5 and the design.

**Fixtures needed:** `newTestBus(t)` (miniredis + client + bus, cleanup-aware, per `newTestClient` in `redis_test.go:15`); raw-publish helper for garbage injection (mqtt's `dialConnect` raw-publish precedent); loss/recovery helper wrapping `mr.Close()`+`mr.Restart()`; build-layer test helper for the miniredis-backed `goredis.Cmdable`.

**Exit criteria for the design's test plan to be considered adequate:** all of H1's E2E assertions green under `-race`; H2's two unit tests; M1–M4 tests; the mandatory gates pass on a clean baseline, with the currently-failing vet (`interfaces/snapshot` duplicate method) and maintainability items (2 file-size, 10 function-length, 3 cyclo, all in uncommitted worktree files) either fixed or explicitly tracked as pre-existing drift; `make ci` green; docs/config-reference.md row updated to `off · memory · etcd · redis` with the `redis_channel` paragraph.

**Bottom line:** the design's test plan is well-mapped to the spec and builds on verified, passing infrastructure — but as written it cannot discharge spec Improvement 3 (the recovery half needs a specified, reversible loss mechanism) and leaves two promised failure surfaces (initial-subscribe boot error, nil-rdb first-use) untested. H1 and H2 should be resolved before implementation begins, since they shape the Bus's API surface (e.g., whether `Subscribe` must nil-check and wrap go-redis dial errors).
