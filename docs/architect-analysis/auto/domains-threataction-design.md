# Design: Threat-action policy storage + rate-limit persistence and multi-replica consistency

Design counterpart to `docs/auto/domains-threataction-requirements.md`. Covers the API
surface, storage model, failure modes, and breakage risks for the three improvements.
Every decision below was checked against current code and the AGENTS.md budgets; where
the requirements proposed a location that would breach a gate (config_snapshot.go at
482/500 lines, `BuildThreatAction` at the 50-line function budget, `wireThreatAction`
at ~38 lines), this document says so and relocates or extracts.

Layer map used throughout:

```text
composition (cmd/sso-server, serverbuildplatform, interfaces/sso)
  → domains (threataction)
  → platform (migrate), shared
```

`domains/threataction/sqlite` may import only `platform`, `shared`, and its own
domain — never `infrastructure/` (architecture_layer_test.go, exemptions shrink-only).
That single rule drives Decisions 2 and 5 below.

## Decision 1: Backend selection via `threat_action.backend` + `threat_action.sqlite.dsn`

### API surface

Extend `config.ThreatActionConfig` (config_snapshot.go:472) with the same shape
`ConfigAuditConfig` / `AuditConfig` use (config/config_audit.go:17-18, 322-328):

```go
type ThreatActionConfig struct {
    Enabled       bool                      `yaml:"enabled"`
    DefaultAction string                    `yaml:"default_action"`
    Policies      []threataction.ThreatPolicy `yaml:"policies"`
    // Backend selects the ThreatPolicyStore: "memory" (default) or "sqlite".
    Backend string                      `yaml:"backend"`
    // Sqlite configures the durable backend. DSN required when Backend=sqlite.
    Sqlite  ThreatActionSqliteConfig    `yaml:"sqlite"`
}

// ThreatActionSqliteConfig is the SQLite backend's DSN. Production DSNs use
// "file:" URLs; the file is shared by all replicas pointing at it.
type ThreatActionSqliteConfig struct {
    DSN string `yaml:"dsn"`
}
```

**Relocation**: `ThreatActionConfig` moves from config_snapshot.go (482/500 lines —
no headroom) into a new `config/config_threataction.go`, mirroring how
`AuditConfig`/`ConfigAuditConfig` own config_audit.go. `config.Config` (config.go:92)
keeps `ThreatAction ThreatActionConfig yaml:"threat_action"`; YAML keys, tags, and
round-trip behavior are unchanged. The config/schema document is reflection-generated,
so the new keys appear automatically — no golden file.

### Builder switch

`BuildThreatAction` (cmd/sso-server/serverbuildplatform/build_governance.go:310)
selects the store, mirroring `BuildConfigAuditStore` (same file):

- `""` / `memory` → `threatactionmemory.NewThreatPolicyStore()` — byte-identical default.
- `sqlite` → `threatactionsqlite.New(dsn)`; empty DSN → boot error
  `threat_action.sqlite.dsn required when threat_action.backend=sqlite`; open/migrate
  failure → boot error (fail loud).
- anything else → `unknown threat_action.backend %q (supported: memory, sqlite)`.

**Budget split**: build_governance.go is at 430 lines and `BuildThreatAction` is at
the ~50-line function budget. The switch + seed orchestration moves into a new
`cmd/sso-server/serverbuildplatform/build_threataction.go` holding two package-local
helpers: `openThreatPolicyStore(cfg, logger)` (the switch, returning the store plus an
`io.Closer` for the sqlite case) and `seedThreatPolicies(ctx, store, policies, logger)`
(Decision 4). `BuildThreatAction` shrinks to call them. No new exported API; the
existing `(exec, store, err)` return shape is preserved — the acceptance test's
"`Put` survives `Close` + re-open" works because the caller already receives the store.

## Decision 2: Durable-store hardening — WAL, busy_timeout, single-writer pool

The dormant sqlite store (domains/threataction/sqlite/policy_store.go) was written
and unit-tested but never wired into a process; `New()` does `sql.Open` + `Ping` +
`migrate.Run` and stops. Production sqlite stores in this repo (infrastructure/
defaultimpl/sqlite/shareddb.go) additionally set `journal_mode=WAL`,
`synchronous=NORMAL`, `busy_timeout=5000`, and `MaxOpenConns(1)`. Without these,
two replicas sharing one DSN file hit `SQLITE_BUSY` on concurrent writers and the
rate-limit path (Decision 5) degrades to its fail-open branch — silently losing the
security control this feature exists to provide.

`domains/threataction/sqlite` cannot import infrastructure, so:

- `New()` applies the same four settings locally (a ~12-line `applySharedPragmas`
  helper, comment pointing at the sibling pattern). `NewWithDB` stays as-is — the
  caller owns the pool and its pragmas.
- A package-local `init()` registers a `modernc.org/sqlite` connection hook that
  runs `PRAGMA busy_timeout=5000` when the DSN has no `busy_timeout(` (busy_timeout
  is per-connection; a one-time `Exec` on the pool does not cover runtime connections —
  the exact problem infrastructure/defaultimpl/sqlite/busy_timeout.go documents).
  Registration is idempotent with the infrastructure hook: both set the same pragma
  when both packages are linked (sso-server links both), and the standalone SDK path
  still gets the timeout.

Failure mode this prevents: `SQLITE_BUSY` storms → limiter fail-open → N× budget
returns silently. `busy_timeout=5000` + `BEGIN IMMEDIATE` (Decision 5) make the
write path serialize with bounded wait instead.

## Decision 3: Lifecycle, readiness, storage health, and the schema boot gate

The memory store has no `Close`; the sqlite store does, and its `Ping`/`DB` are
documented for exactly the ready-check/storage-health roles. Wire it like
`anomalyRuntime` (cmd/sso-server/anomaly.go:27-45, 373-386) and `wireAnomaly`
(cmd/sso-server/build_app_selfservice.go:420-449):

- `wireThreatAction` (cmd/sso-server/anomaly.go:54) stashes the sqlite handle on
  `appBuilder` as `threatSQLite *threatactionsqlite.ThreatPolicyStore` (nil for
  memory/disabled), copied to `app` like `anomalyRT` (build_app.go:164/400,
  main.go:268). `shutdownSubsystems` (main_shutdown.go:154) closes it next to
  `a.anomalyRT.close(ctx)` — after `shutdownServers`, so in-flight admin CRUD
  requests drain before the store closes.
- In `wireThreatAction`, when `threatSQLite != nil`, mirror wireAnomaly's tail:
  - `serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, "threat_policies",
    threatactionsqlite.ThreatPolicyMaxVersion())` — this finally wires the
    currently-dead `maxversions.go` (`ThreatPolicyMaxVersion` has zero callers
    today). It is a boot gate: an older binary against a v2-migrated DB must fail
    loud, not serve on a schema it cannot write.
  - `serverbuildsign.AppendReadyCheck(b.opts, "sqlite-threat-policies", store)`
  - `serverbuildsign.AppendStorageHealthSource(b.storageHealthSources,
    "sqlite-threat-policies", store)`
  - boot log line naming the backend, like `wireAnomaly`'s
    `"recent_login_backend", ...` log.

**Budget split**: `wireThreatAction` is ~38 lines; the added block pushes past 50.
Extract the lifecycle/readiness tail into a package-local helper
(`wireThreatActionReadiness` in anomaly.go, which has 386/500 lines of headroom).

No new `sso.Option` is needed: `WithThreatExecutor`/`WithThreatPolicyStore`
(interfaces/sso/accessors_threat.go) already exist and the ready checks reuse
`serverbuildsign` helpers. `interfaces/sso`'s frozen 60-file ceiling is untouched.

## Decision 4: Seed-once boot semantics — YAML is a bootstrap default, never an overwrite

### Problem

`BuildThreatAction`'s unconditional `for _, p := range cfg.Policies { store.Put(...) }`
is correct for memory (seeds are the only source) but, once the store is durable,
every restart would overwrite admin-authored policies with stale YAML — a silent
rollback of a security control. The config comment (config_snapshot.go:479-481)
already promises "further policies can be added/edited at runtime via the admin CRUD
API"; persistence must honor it.

### API surface

New method on the concrete sqlite store (not on the `ThreatPolicyStore` interface —
admin CRUD never needs it):

```go
// SeedIfEmpty applies bootstrap policies only when the store holds none,
// atomically. Returns (seeded, kept, err). Boot-only API; callers log the counts.
func (s *ThreatPolicyStore) SeedIfEmpty(ctx context.Context, policies []threataction.ThreatPolicy) (seeded, kept int, err error)
```

Implementation: one `BEGIN IMMEDIATE` transaction on a pinned connection (the
infrastructure pattern `beginImmediateRMW` is not importable from domains — ~10
local lines) — `SELECT COUNT(*)`, and only if zero, `Put` each seed, `COMMIT`.
`BEGIN IMMEDIATE` takes the write lock up front, so a concurrent replica booting
against the same empty file, or an admin `PUT` racing boot, serializes behind it;
the re-check inside the transaction makes check-then-seed race-free across
processes. SQLite's single-writer rule + `busy_timeout` make this bounded.

`BuildThreatAction` behavior:

- memory backend: unchanged unconditional seed loop (byte-identical; existing
  build_governance_test.go cases pass unmodified).
- sqlite backend: `SeedIfEmpty`; on `err` → boot error (fail loud — a control-plane
  store that cannot be read at boot must not start). Log the decision:
  `logger.Info("threat_action policies seeded", "backend", "sqlite", "seeded", n, "kept", m)`.
  `kept > 0` with `seeded > 0` is impossible (seed only when empty); `kept = m`
  means YAML was skipped — visible, not silent.
- No new knob to force re-seeding. An operator who changes YAML after first boot
  uses admin CRUD, or a fresh DSN. Deleting a policy via CRUD also survives restart
  (deletion is not reverted by seeds). Both facts go in config-reference.md.

## Decision 5: Shared cross-replica rate limiter — `threat_rate_limits` behind the same switch

### Problem

`ThreatExecutors.allow()` (domains/threataction/registry.go:214) is a
process-local map, so N replicas sharing the sqlite policy store still get N× the
configured `RateLimitPolicy.Max` — the documented security control becomes
deployment-dependent, and the `wireThreatAction` doc's "one shared instance, one
rate-limiter, one policy view" guarantee is silently violated.

### API surface (domain)

New file `domains/threataction/ratelimit.go` (keeps registry.go at 301 lines
readable):

```go
// RateLimitStore persists rate-limit counters across processes. Implementations
// must be atomic per key: concurrent Allow calls for one key serialize.
// Errors are fail-open at the caller: log + allow.
type RateLimitStore interface {
    // Allow checks-and-increments one (subject, threatType, action) window.
    // Returns true when the hit is within budget. now is the caller's clock
    // (injectable for deterministic tests).
    Allow(ctx context.Context, subject, threatType string, action Action,
        max int, perWindow time.Duration, now time.Time) (bool, error)
}
```

`ThreatExecutors` gains `WithRateLimitStore(s RateLimitStore)`. `allow()` (internal;
signature gains `ctx`) keeps the current map path when the option is nil —
byte-identical memory behavior, existing registry_test.go/actions_test.go pass
unmodified — and delegates otherwise:

```go
if te.rateLimitStore != nil {
    ok, err := te.rateLimitStore.Allow(ctx, threat.SubjectID, threat.Type, act,
        rl.Max, rl.PerWindow.Duration, time.Now())
    if err != nil {
        te.logger.Error("threat rate-limit store failed", ..., "error", err)
        return true // fail-open: a broken limiter must not block actions
    }
    return ok
}
// ... existing in-process map path, unchanged ...
```

### Storage model

Migration v2 appended to the store's existing `policyMigrations` (same namespace
`threat_policies`, so `ThreatPolicyMaxVersion()` becomes 2 automatically):

```sql
CREATE TABLE IF NOT EXISTS threat_rate_limits (
    subject      TEXT    NOT NULL,
    threat_type  TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    window_start INTEGER NOT NULL,  -- unix nanos of the window's first hit
    window_end   INTEGER NOT NULL,  -- window_start + per_window
    count        INTEGER NOT NULL,
    PRIMARY KEY (subject, threat_type, action, window_start)
) WITHOUT ROWID;
```

Semantics preserve the memory path exactly ("replace if expired", window anchored
at first hit, denied hits never create rows):

1. `BEGIN IMMEDIATE` on a pinned connection (same local helper as Decision 4).
2. `SELECT count, window_end ... WHERE subject=? AND threat_type=? AND action=? AND window_start=?` — the window key comes from the row, not the caller, so a later replica's hit lands in the first writer's window.
3. No row, or `now > window_end` → `INSERT ... (window_start=now, window_end=now+per_window, count=1)`; `COMMIT`; allow.
4. Row exists and `now <= window_end` → `count >= max` ? `COMMIT` (or rollback), deny : `UPDATE count=count+1`, `COMMIT`, allow.

`BEGIN IMMEDIATE` + `busy_timeout` (Decision 2) serialize concurrent replicas on the
same key; SQLite's writer lock makes the read-modify-write atomic across processes.

**Sweep, no goroutines**: the package deliberately avoids background loops (registry.go
doc: no lifecycle hook exists and `layerExemptions` is shrink-only). Bounded growth
instead: the new-window insert also deletes that key's older rows in the same
transaction (per-key rows ≤ 1 per live window), and a counter-gated global
`DELETE FROM threat_rate_limits WHERE window_end <= now` piggybacks every Nth Allow
call (package var, default 1024, test-shrinkable — mirroring `rateLimitSweepThreshold`).
Denied hits write nothing, exactly like the memory path.

### Consistency semantics (documented)

- `backend: sqlite` ⇒ cluster-shared policy view AND cluster-shared rate-limit
  window: `Max` is the budget across all replicas.
- `backend: memory` ⇒ per-replica window — the N× budget-multiplication caveat is
  stated explicitly in config-reference.md, alongside the single-replica guidance.
- Clock skew: window boundaries use the first writer's clock (stored
  `window_end`); correctness requires replica clocks within `per_window` of each
  other (NTP). Skew larger than the window silently splits windows back into
  per-replica budgets — see failure modes.

`BuildThreatAction` passes the sqlite store as the limiter (`WithRateLimitStore`)
only in the sqlite branch; the memory branch passes nothing, so the executor stays
byte-identical today.

## Failure modes

| Surface | Mode | Behavior | Rationale |
|---|---|---|---|
| `backend=sqlite`, missing DSN | boot | error `threat_action.sqlite.dsn required...` | fail loud, mirrors `config_audit` |
| unknown backend | boot | error listing `memory, sqlite` | fail loud, mirrors `BuildConfigAuditStore` |
| open/migrate failure | boot | error | fail loud: control plane unreadable |
| `SeedIfEmpty` store error | boot | error | fail loud: cannot know whether to seed |
| policy-store `List` error at runtime (`Execute`) | runtime | default policy + log (existing) | fail open, unchanged |
| limiter-store error | runtime | log + allow | fail open, matches `allow()`'s posture; protection degrades only under store outage |
| admin CRUD racing boot seed | runtime | serialized by `BEGIN IMMEDIATE`; admin write after commit wins | no lost update |
| two replicas seeding an empty file | boot | both serialize; second sees count>0, seeds 0, keeps N | seed-once invariant holds |
| older binary vs v2 DB | boot | `CheckSQLiteSchema` gate fails loud | regression boundary, wires `ThreatPolicyMaxVersion` |
| expired limiter rows | runtime | per-key cleanup + counter-gated global sweep | bounded table, no goroutine |
| replica clock skew > `per_window` | runtime | window splits per replica; budget multiplies | documented deployment constraint (NTP) |

## What could break the design

1. **Budgets.** config_snapshot.go 482/500 → Decision 1 moves `ThreatActionConfig`
   to config_threataction.go. build_governance.go 430/500 and the `BuildThreatAction`
   function budget → helpers in build_threataction.go. `wireThreatAction` ~38 lines
   + readiness block → helper extraction. registry.go 301 + ~20 lines stays under.
   sqlite/policy_store.go 177 lines: `Allow` + `SeedIfEmpty` + sweep go in a new
   `domains/threataction/sqlite/rate_limit.go` (keeps the policy file focused, and
   the implementation-interface-guard rule puts the `RateLimitStore` conformance
   with the implementation).
2. **Layer rule.** `domains/threataction/sqlite` cannot import
   infrastructure/defaultimpl; WAL pragmas, `BEGIN IMMEDIATE`, and the
   busy_timeout hook are reimplemented locally (~25 lines total). The
   double-registered connection hook is idempotent (both set the same pragma).
3. **The fail-open limiter is the silent-degradation point.** If the sqlite
   limiter errors (SQLITE_BUSY without Decision 2, file permissions, disk full),
   every hit is allowed — the N× budget the feature removes returns with only a
   log line. The failure-injection acceptance test pins this behavior so it is at
   least visible, and the ready check (`sqlite-threat-policies` Ping) trips
   `/readyz` when the file is wedged.
4. **Shared DSN placement.** WAL + advisory file locking are unreliable on NFS/SMB.
   The DSN must be local disk (or a filesystem with correct POSIX locking). The
   repo already treats shared-DSN sqlite as "cluster-shared" (tenant store log),
   so this is a documented constraint, not a new one; config-reference.md states it.
5. **DSN reuse across stores.** Each feature should own its file (notifications
   docs set this precedent: "both notification tables share this database"). Two
   pools on one file work (busy_timeout) but convoy; the docs say "dedicated file".
6. **YAML no longer re-applies after first boot.** Intentional (Decision 4), but an
   operator rotating policies through config alone will see stale policy. The boot
   log line (`kept N, seeded 0`) and config-reference.md make it visible; the
   acceptance test asserts admin edits survive restart.
7. **`sso.WithThreatPolicyStore` type stays `threataction.ThreatPolicyStore`.**
   The admin CRUD surface, OpenAPI, and error codes are untouched — no new `Err*`,
   no new endpoints, no new audit event type (rate-limited outcomes already emit
   `threat_action_executed` with detail `rate-limited`; seed/keep is a boot log
   line, not an audit event, so `auditreport` classification is untouched).
8. **Nested modules / cold builds.** No nested module changes; `make ci` gates
   unchanged. The `threat_action.backend` key flows through the reflection-based
   config schema automatically.
9. **Memory default must stay byte-identical.** The switch's `""`/`memory` branch
   returns the memory store with the unconditional seed loop and no
   `WithRateLimitStore`; existing tests are the regression boundary.

## Test plan (maps to the requirements' acceptance checks)

| Acceptance check | Test |
|---|---|
| sqlite backend returns executor; `Put` survives restart | `BuildThreatAction` with `backend=sqlite` + temp-DSN; seed 2 policies; `Put` an edit; `Close`; `sqlite.New` same DSN; assert edited value + other seed present (restart-survival) |
| missing DSN / unknown backend / empty backend | unit cases: boot error for both; empty backend runs existing build_governance_test.go cases unmodified (byte-identical) |
| seed-once | sqlite store; boot-seed 2; admin-style `Put` edit of one; restart same DSN + same seed config; assert edit survives, no overwrite; boot log line asserts `seeded`/`kept` counts |
| memory seeds always apply | existing tests unchanged |
| two-replica shared window | two `ThreatExecutors` over one shared DSN file; `Max` hits from replica A, one from B → `ActionResult{OK:false, Detail:"rate-limited"}`; after short `PerWindow` elapses, a fresh threat passes |
| fail-open limiter | failure injection (closed store / stub erroring store): `Execute` proceeds and logs |
| memory rate-limit path | registry_test.go / actions_test.go pass unmodified |
| gates | `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; `go test ./... -race`; `make ci` |

## Contract and documentation updates (AGENTS.md §5)

- `docs/config-reference.md` — Active ITDR section: rewrite the
  `threat_action.enabled` row (drops "in-memory"); add `threat_action.backend` and
  `threat_action.sqlite.dsn` rows; rewrite the `threat_action.policies` row to the
  seed-once contract; add a consistency-semantics paragraph (cluster-shared window
  vs per-replica N× caveat, clock-skew + local-disk DSN constraints) and a yaml
  snippet.
- `config.ThreatActionConfig` struct comments (Policies → seed-once; new fields).
- No OpenAPI change (no endpoints), no error-codes.md change (no new `Err*`),
  no auditreport change (no new event type).
