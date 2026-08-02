Design doc written to `docs/auto/domains-threataction-playbook-design.md`, with every decision verified against the code first.

**Key verification findings that shaped the design:**

- `ThreatExecutors.Execute` is exactly **50 lines** — at the budget ceiling, so the multi-action executor must be an orchestrator over extracted helpers (plan construction + per-action execution), or the change fails `TestMaintainability_`.
- Both production callers (`anomaly/runner.go:225`, `tokenanomaly/detector.go:419`) **discard the `ActionResult` and only check `err`** — so changing the interface to `([]ActionResult, error)` is free at every caller. The interface doc already promises "zero or more Actions"; the single-value signature is an implementation lag, not a contract.
- The sqlite store's own design note ("nothing ever queries by SQL WHERE clause… no migration surface") is the precedent that kills the `priority INTEGER` column idea: `priority`/`actions` stay in the JSON blob, ordering happens in Go via a **single exported comparator** shared by both stores — parity by construction, not parallel maintenance.
- No new `Err*` needed (`ErrInvalidPolicy` + reason strings), so `docs/error-codes.md` is untouched; openapi `required` must drop `action` to `[name, enabled]` or new `actions`-only payloads fail schema validation.

**Notable design calls:**

1. **Dedup before rate-limiting** — the highest-priority owner's `RateLimit` gates the action; a lower-priority duplicate never retries. Faithful generalization of today's first-match (windows were never independent), but worth documenting.
2. **Per-action `recover`** (mirroring `inspectSafe`) — without it, one panicking handler in a list would drop *all* remaining actions of the threat, strictly widening today's blast radius and violating the package's own same-threat guarantee.
3. **`default_action` frozen** as zero-match-only; the "silent takeover" interplay (a catch-all policy makes `default_action` unreachable) is documented as a known consequence.
4. **Mixed-version blob overwrites** flagged: a pre-upgrade server `PUT`-ing a row strips new fields — pre-existing blob-store property, newly consequential during rolling upgrades.
