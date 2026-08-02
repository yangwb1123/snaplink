Gatekeeper report written to `docs/proposals/gate.md` (replacing the stale prior-stage report). Summary of my cross-check:

## Method
I re-verified the contested evidence myself rather than trusting either side: `mergeFinding` (memory/store.go:76-80), `offerUsage` (sso.go:214-217), `spikeForClient`/`Bucket` tenant absence, `Findings()` return type (detector.go:221), `migrate.go` busy_timeout scope + the `_busy_timeout` no-op comment, `permissions/sqlite` `SetMaxOpenConns(1)` + DSN `_pragma` precedent, `maxversions.go`, `CheckSQLiteSchema` call sites, threataction/configaudit readyz absence in `cmd/`, zero tokenanomaly refs in `ops/deploy/`, and `docs/DECISIONS.md` (no gate entry for this stage).

## Result

**A — Resolved or dismissed with reasons:** layerName() correction (verified accurate), reopen-flap documentation, keyset honesty + acceptance wording, total/limit drift documentation, NFS foot-gun, crash-loss window, fail-open/fail-closed boundaries, and store-level enum rejection (dismissed with the design's "store cannot know intent" rationale; no reachable path).

**B — Blocking (neither resolved nor dismissed):**
- **B1 High** — the decision text still quotes the parity-breaking UPSERT SQL (stored≠0 ∧ incoming=0 → epoch); the appended review's fix is not folded into the spec — the doc contradicts itself
- **B2 High** — tenant dimension inert: no seam stamps `ev.TenantID`, `rate_spike` has no tenant source; the tenant filter ships dead, and the appended review doesn't cover it
- **B3 High** — busy_timeout mechanism unpinned; per-connection `Exec` pragma is ineffective under pooling → silent detection loss under the exact multi-replica contention the feature targets
- **B4 High (launch blocker)** — readiness mis-cites a nonexistent peer pattern (neither threataction nor configaudit is wired); readyz-flip drain decision unmade
- **B5–B14** — PATCH same-state retry unspecified; missing `maxversions.go`+`CheckSchema`; retention zero-value contradiction; UpdateStatus TOCTOU (resolved→acknowledged); no-store headers; missing `resolved_at` partial index; compliance minimum (datamap category + erasure/export for durable `subject_id`); zero alerting; test inventory gaps (detector lifecycle, two-pool contention, migration/nanos, handler/wire/audit, cursor-decode); cursor padding/filter-scoping, NUL-safe audit meta, WAL backup wording.

Every factual claim in the design verified true, but the principal reviewer's required edit pass and owner sign-offs never happened — the corrective content lives only in the proposal files and appended review, not in the implementation spec. The design stage cannot advance to implementation as written.

VERDICT: FAIL - decision text must be corrected before implementation: B1 merge-SQL parity (symmetric CASE, both suite orders), B2 inert tenant dimension (seam stamp or explicit tenant-less scope; owner decision), B3 busy_timeout/WAL mechanism unpinned (DSN _pragma + pool sizing), B4 readiness mis-cite + missing owner decision (storage-health/alerts vs readyz), B5 PATCH same-state retry unspecified (200 no-op), B6 missing maxversions.go + boot CheckSchema, B7 retention zero-value contradiction (0=default, negative=forever), B8 UpdateStatus TOCTOU (conditional UPDATE), B9 PATCH no-store headers, B10 missing resolved_at partial index in v1, B11 compliance minimum (datamap category + erasure/export decision for subject_id rows), B12 zero alerting on the subsystem, B13 test inventory gaps (detector lifecycle, two-pool contention, migration/nanos, handler/wire/audit, tenant-overwrite, cursor-decode), B14 doc obligations (cursor padding/filter-scoping, NUL-safe audit meta, WAL backup + local-FS-only NFS, conversion helper).
