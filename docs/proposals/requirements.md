Specification complete: `docs/auto/domains-userlifecycle-prod-spec.md` (exactly 3 `##` decisions, every claim verified against the code before writing).

## Summary

**Direction 3 — 生产化短板** decomposed into three independently shippable improvements, each preserving the module's anchors (无记录=ACTIVE, zero-value=OFF, unwired=byte-identical):

### 1. Durable SQL `Store` peer
- **Problem**: only `memory.Store` exists (`build_userlifecycle.go` returns `userlifecyclememory.New()` unconditionally); state is process-local and lost on restart, so multi-replica deployments diverge silently and AGENTS.md's cross-replica invalidation list omits lifecycle.
- **Evidence**: `domains/userlifecycle/memory/memory.go` package doc ("State is lost on restart…"), `userlifecycle.go` `Store` interface comment ("memory today; a SQL peer can follow the same contract"), zero `userlifecycle` refs under `infrastructure/`, `docs/config-reference.md`.
- **Proposed**: `infrastructure/postgres` backend implementing the same contract — single-statement conditional `INSERT`/`UPDATE` mapped to `ErrStateConflict`, `Get` returns DefaultState for missing rows, config-selected backend, shared conformance suite with memory.
- **Acceptance**: conformance parity both backends; two-handle race test → one success, one `ErrStateConflict`; gates + `make ci`.

### 2. Lease-serialized, cursor-based incremental sweep
- **Problem**: `SweepOnce` walks the full unpaginated roster (`Users.List`); `ListByState` exists but has zero callers (its own doc says the sweep uses the full roster); every replica runs its own ticker and `ErrStateConflict` races are silently swallowed.
- **Evidence**: `sweep.go` `SweepOnce`/`apply`, `userlifecycle.go:143-147`, `shared/core/spi.go:42` (`UserProvider.List` "pagination is the caller's responsibility"), `options_admin.go` `RunUserAutoDeprovision`, `build_stores.go:368`.
- **Proposed**: store-level sweep lease (SQL conditional upsert w/ TTL; memory single-flight), keyset-cursor `ListByStateAfter`, `MaxPerSweep` extended to bound scanned candidates; `SweepOnce` semantics unchanged.
- **Acceptance**: two-holder race test → exactly one applies; O(k) scan for k dormant of N; existing `sweep_test.go` cases unchanged; `-race` + `make ci`.

### 3. Persistent last-active signal written from the login hot path
- **Problem**: `ActivityTracker.Touch` has zero production callers (the only `.Touch(` is `adminTokenStore` in `middleware.go:405`, an unrelated type); default wiring `SessionLastActive` is blind outside the session-retention window — config reference concedes "no other activity backend exists in this wiring today".
- **Evidence**: `memory.go` `ActivityTracker` doc ("Wire it into the login path…"), `dormancy.go` caveat, `build_stores.go:347` seam, login anchors `server_login_auth.go:98` / `server_oauth.go:223`, `spi.go:150` `TrackActivity` is session-scoped.
- **Proposed**: durable last-active store (with improvement 1), `Touch` after `rejectDeactivatedUser` and in `finalizeCallbackSession`, fail-open on write error, durable source becomes the default when SQL is wired, `SessionLastActive` stays fallback.
- **Acceptance**: login → expire sessions → `LastActive` still non-zero and sweep evaluates; injected store failure doesn't block login; monotonicity; gates.

No Go code changed, so no build gates were required; the doc lives alongside the other `docs/auto/domains-*-spec.md` files (note: `docs/` is a symlink target outside the git worktree, matching the existing analysis-doc convention).
