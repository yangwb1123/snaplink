Design doc written to `docs/auto/domains-userlifecycle-prod-design.md` — exactly 3 `##` decisions, each covering API surface, storage model, failure modes, and what could break the design. No Go code changed (doc-only, matching the spec's own convention).

**Verification performed before writing** (all claims checked against the code, not just the spec):

- `Store` interface, `ErrStateConflict` semantics, `ListByState` "no record never returned" contract — `userlifecycle.go`
- Memory store's exact Append rules (missing row treated as `DefaultState`) — `memory.go`
- `SweepOnce` full-roster walk, `MaxPerSweep` applied-only cap, skip-and-log conflicts — `sweep.go`
- Wiring seams: `build_stores.go:347` (`SessionLastActive`), `BuildUserLifecycle` unconditional memory, `BuildIdentityLinkDurable(cfg, pg, dialect)` as the backend-selection precedent
- Login anchors `server_login_auth.go:98` / `server_oauth.go:223`; ceremony coverage verified transitively via `server_mfa.go` replaying `finishLogin`
- Gate context: `maintainability_budget_test.go` skips `infrastructure/postgres`; `permissions/sqlite` + `permissionstest` as the peer/conformance precedents; `defaultimpl/sqlite` as the SQLite-peer precedent

**Three architect-level corrections to the spec, each load-bearing** (documented with rationale in the preamble and per-decision):

1. **Companion interfaces, never `Store`-method additions** — `Store` is SDK surface; `SweepLeaser`/`StaleEnumerator`/`ActivityRecorder` are resolved by type assertion, so external implementers keep compiling and memory builds stay byte-identical.
2. **The spec's `ListByState`-based candidate enumeration is rejected** — it cannot see implicit-ACTIVE users (no record), whom the sweep deprovisions today; it would silently stop sweeping them. Replaced with a keyset cursor over stale last-active values, which provably covers recorded and unrecorded candidates and satisfies the O(k) acceptance.
3. **Last-active is a separate table, not a column on `user_lifecycle`** — a column would make every login create a lifecycle row, breaking "no record = ACTIVE" and the decision-2 cursor simultaneously.

Also resolved a real contradiction in the spec: the lease must live inside `SweepOnce` (opt-in via new zero-value `Holder`/`LeaseTTL` fields) for both "lease at the loop" and "two concurrent `SweepOnce`s — exactly one applies" to hold.
