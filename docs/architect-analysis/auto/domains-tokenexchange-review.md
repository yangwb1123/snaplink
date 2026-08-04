# Review — Token-Exchange Hop-Policy Operational Loop (Distributed-Systems Lens)

Source: `docs/auto/domains-tokenexchange-design.md`. Role: distributed-systems
engineer (replicas, retries, partial failure, partitions, failover, clock
anomalies). Advisory only. All claims labeled per `ai-dev/prompts/README.md`;
checks that ran: source reads + grep across `domains/tokenexchange`,
`interfaces/{sso,admin}`, `internal/handler/tokengrant`,
`cmd/sso-server{,/serverbuildplatform}`, `config`, `platform/{audit,cluster}`,
`shared/core`, `docs/auto/domains-tokenexchange-analysis.md`. No `make ci` was
run for this review (design-stage artifact, no `.go` edits made).

## Verdict

The design is structurally sound and its budget math checks out (verified:
`accessors_threat.go` 427, `build_app_oauth.go` 487, `server_routes.go` 488,
`build_governance.go` 430, `interfaces/sso` at exactly 60 non-test files,
`wireOAuthGrantStores` 34 lines so the 497-line inline fallback is viable).
The one material distributed-systems defect is **Decision 4's multi-replica
staleness being unbounded** (Finding 1, High): the design ships an
admin-mutable authorization policy whose cross-replica propagation is
"until restart", which is exactly wrong for the feature's primary use case
(incident-response deny rules) and sits uneasily against AGENTS.md §3's
cross-replica-invalidation invariant. The fix is small and precedented.
Findings 2–3 are bounded design gaps; 4–7 are documentation/test hardening.

---

## 1. State map

| State | Owner | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Policy rule set (proposed) | config at boot; admin `PUT` at runtime | `memory` or `tokenexchange_policy_rules` (sqlite, position PK, JSON list columns) | memory: process; sqlite: DSN file (shared with `oauth.sqlite`) | Per-process: linearizable via mutex + copy-on-write snapshot (Verified pattern: `domains/tokenexchange/memory/store.go`). Cross-process: last-commit-wins on disk, **stale snapshot until restart or local PUT** | None — snapshot is per-process; no bus subscription in design | Crash → boot load re-reads disk (loud). Failover lands on a replica whose snapshot may predate the last PUT (Finding 1) |
| `default_allow` (proposed) | config only; not persisted; no PUT path | n/a | n/a | Per-replica config value; divergence across replicas is silent | None | Config-owned; unchanged by this design |
| Hot-path `Allow` | `internal/handler/tokengrant/token_exchange.go:373` `tokExEnforcePolicy` (Verified) | In-memory snapshot; zero I/O (Verified pattern) | n/a (read-only) | COW: sees old or new set, never a blend | n/a | DB gone after boot → snapshot keeps serving (by design, Decision 6) |
| Admin `GET`/`PUT` (proposed) | `interfaces/admin/tokenexchange_policies.go` + thin wrappers in `accessors_threat.go` | via store | sqlite: single tx delete+reinsert | Validation before any store call; `400` = zero mutation (Verified precedent: `tokenpolicy.HandleAdminPolicies` envelope; GatedRouter supports PUT, `shared/core/router.go:344`) | n/a | `500` on store failure, fail-closed |
| Audit `token_exchange_policy_updated` (proposed) | `platform/audit` recorder | sinks | fail-open (Verified: `recordAdminConnectionAction` `interfaces/admin/connections.go:74`; recorder swallows sink errors) | Mutation-before-audit; dropped event never rolls back a PUT | n/a | n/a |
| Schema version (proposed) | `PolicyStoreMaxVersion()` + `CheckSQLiteSchema` (Verified pattern: `domains/tokenexchange/sqlite/maxversions.go`, `wireRefreshToken` in `cmd/sso-server/build_app_oauth.go`) | sqlite `migrations` | durable | Boot gate: newer live DB fails loud | n/a | n/a |

---

## 2. Findings (severity order)

### F1 — High — Unbounded multi-replica staleness of an admin-mutable authorization policy; no invalidation-bus hook

**Evidence (Verified).**
- Design Decision 4 "Multi-replica note": "an admin PUT on replica A updates
  A immediately and persists, but B serves its stale snapshot until restart"
  — the window is **unbounded** (no TTL, no poll, no bus).
- AGENTS.md §3: "Cross-replica invalidation covers token revocation,
  signing-key rotation, client/authz-policy changes, and tenant suspension."
  A token-exchange hop policy is an authorization policy; the design's
  "future invalidation-bus hook … explicitly out of scope" is a conscious
  deviation from a documented invariant.
- The mechanism exists and is cheap to extend: `platform/cluster/bus.go`
  (`EventKind` set is "open by design"; `KindAuthzPolicyChange` precedent),
  subscriber dispatch `interfaces/sso/server_invalidation.go:333`
  `applyControlPlaneInvalidation` (per-kind arms; `default:` ignores unknown
  kinds → mixed-version safe), and the store already owns the `*sql.DB`
  (`DB()` accessor pattern, `sqlite/chain_store.go:100`).
- Worst-case shape: the bus contract says a dropped event "degrades a replica
  to its existing TTL fallback … never to a wrong answer"
  (`platform/cluster/bus.go:14`). The policy snapshot has **no TTL fallback** —
  the stale answer is served indefinitely, which is strictly weaker than
  every other bus-covered cache.

**Triggering failure.** Incident response: operator PUTs a deny rule
("service A may never act for B") to replica A. Replica B (or the failover
target) keeps ALLOWING the hop — the exact opposite of the operator's intent —
until someone restarts B. Decision 1 itself names the use case: "an incident
response needs deny rules".

**User impact.** Security-control latency unbounded across the fleet; a
governance `GET` on B returns a stale rule set, so even the admin surface
misleads. A management tool doing GET→PUT round-trips on B silently
re-applies the old set (interacting with F4).

**Recovery.** Restart B, or replay the PUT on B (a local PUT swaps B's
snapshot). Neither is discoverable by the operator.

**Corrective pattern (recommended).** Add a new `EventKind` (e.g.
`token_exchange_policy_change`, mixed-version safe by the existing `default:`
arm) published by the PUT handler after commit; add a subscriber arm that
calls `store.Reload()` — re-run the boot-load SELECT and swap the snapshot
under the write lock, fail-open (keep old snapshot + log) on reload error.
~15–25 lines across `platform/cluster/bus.go`,
`interfaces/sso/server_invalidation.go`, and the store; it converts an
unbounded window into the same bounded best-effort semantics every other
kind has. Alternative if the team declines: document the sqlite backend as
**single-replica-only** (a shared-DSN multi-replica deployment is an
unsupported topology), and add a boot warning when more than one process
holds the file.

### F2 — Medium — `Replace`'s transaction is not stated to run under the write mutex: concurrent PUTs can tear memory vs. disk

**Evidence.** Design Decision 4: "commit, then swap the snapshot under the
write lock". The tx is not inside the critical section. SQLite serializes
writers by file lock (commit order); the Go mutex serializes swaps (swap
order). These two orders are **independent** under goroutine preemption:
R1 commits set1 → preempted; R2 commits set2, swaps (mem=set2); R1 resumes,
swaps (mem=set1). Result: disk=set2, memory=set1 — violating the design's own
stated guarantees ("never a partial set on either side", "disk + snapshot on
the OLD set" on failure) and the failure-mode table, which covers
Allow-vs-Replace but not Replace-vs-Replace.

**User impact.** Admin API reports the new set in its 200 echo while the hot
path enforces the old one; next restart silently "fixes" enforcement,
producing a confusing window. Low likelihood (concurrent admin PUTs), but
the design's core invariant is the one broken.

**Recovery.** Restart converges (boot load). No data loss.

**Corrective pattern.** Hold the write mutex across the entire
tx + swap (serialize `Replace`), making commit order = swap order = lock
order. Add a regression test: two goroutines `Replace` concurrently, assert
the sqlite table and the snapshot hold the same set afterward (run
`-count=10+` per AGENTS.md race discipline).

### F3 — Medium — Boot load is an ingest path but is exempted from rule-shape validation

**Evidence.** Decision 3: "Both reject malformed patterns … by validation at
ingest … so the hot path needs no defensive re-check". Decision 4's boot load
validates only JSON decodability ("corrupt JSON … boot error"). The DB is
written by PUT (validated) — but also by an older binary with a pre-fix bug,
a manual edit, or a future writer. A row with `"*x"` or `""` in
scopes/resources loads silently, and the matcher's wildcard semantics on it
are undefined — the plausible outcome is a rule that never matches
(a widened allow), which is precisely the fail-open the design's loud-boot
stance exists to prevent.

**User impact.** Silent governance drift; impossible to detect except by
auditing every row.

**Corrective pattern.** Run the same `ValidateRules` (Name non-empty, cap,
wildcard shape) on boot load and fail boot loudly — consistent with the
design's own corrupt-JSON stance. Also add a memory/sqlite parity test
(same rule set → same `Allow` truth table, same `Replace`/`Rules` order) so
the two `MutablePolicy` implementations cannot drift; this matches AGENTS.md's
conformance-suite precedent for permission backends.

### F4 — Low — No version/etag on the rule set: silent lost-update; `default_allow` fleet divergence is undetectable

**Evidence.** Design: PUT is full-replace, idempotent, "echoes the new set"
— but nothing carries a version, timestamp, or etag. Two operators (or a
GET→PUT round-trip tool) racing: last-write-wins silently, no conflict
signal. `default_allow` is per-replica config; nothing detects two replicas
with different fallbacks (mixed-version or mixed-config fleet), and a
replica whose config says `default_allow: true` re-allows every unmatched
hop while its neighbor denies.

**Corrective pattern.** Optional: monotonic `version` (or `updated_at`) in
GET/PUT with `If-Match` support; at minimum document last-write-wins and
require byte-identical `oauth.token_exchange` config across replicas in
`docs/config-reference.md` and the ops notes.

### F5 — Low — `Rules()` returns the live slice header; read-only is by convention only

**Evidence.** `domains/tokenexchange/memory/store.go:52` returns the active
slice under RLock with no copy. The new admin GET serializes it
(`json.Marshal` is read-only — safe today), but any future in-place mutation
corrupts the snapshot the hot path reads. The 1000-rule cap makes a defensive
copy cheap; have the sqlite store return a copy (or copy in the handler) so
the "read-only for the caller" contract is enforced, not conventional.

### F6 — Info — E2E restart harness: WAL/busy_timeout details

Design already specifies close-server-1-before-boot-2 (correct: guarantees
the second boot's load sees a checkpointed, unlocked file). Add: the temp
DSN should carry `_pragma=busy_timeout(...)` (matching `oauth.sqlite` DSN
conventions) so a lingering connection cannot surface `SQLITE_BUSY` as a
flaky boot failure; assert the post-restart `GET` envelope matches the PUT
body; and run the restart test under `-race` (`test/` boots real servers —
feasible, `admin_*` HTTP tests exist).

### F7 — Info — Readiness vs. snapshot serving interplay

`AppendReadyCheck`/`AppendStorageHealthSource` (Ping) flip readiness when the
DB file is unavailable, while `Allow` keeps serving from memory. Coherent and
consistent with every other sqlite store, but the consequence is: a replica
draining due to DB outage is still enforcing its (possibly stale) snapshot
during failover. With F1 unfixed this is the incident window; state it in the
ops documentation.

---

## 3. Scenario table

| Scenario | Behavior (per design + current code) | Assessment |
|---|---|---|
| Partition: replica B cut off from storage | PUT on B fails → `500` (fail-closed, no mutation). Hot path on B keeps serving its snapshot | Acceptable; B's snapshot may be stale (F1) |
| Partition: B cut off from clients, not storage | PUTs from A land on disk; B's snapshot stale until restart | F1 window |
| Crash between tx-commit and snapshot swap | disk=new, mem=old, process dead → restart loads new; client retry of PUT is idempotent (full-replace) | Consistent, Verified reasoning (commit-then-swap ordering is correct) |
| Crash mid-tx | rollback; disk + snapshot on old set | Consistent |
| Retried PUT after lost 200 | Same rules re-applied; same result | Idempotent by construction |
| Concurrent PUTs | Disk: last-commit-wins. Memory: **may end on the other set** (F2) | Needs F2 fix + test |
| Clock rollback / forward | No clocks in `Evaluate`, rules, or storage (no TTLs, no timestamps, no `RecordedAt` on rules) | Immune by design (Verified: `Evaluate` is clock-free) |
| Stale cache (replica snapshot) | Serves old set until restart or local PUT; no TTL fallback | F1 — the core defect |
| Dependency outage (DB file deleted after boot) | Read path serves from memory (zero I/O); PUT → `500`; readiness flips | Fail-closed writes, availability preserved for reads; draining replica still enforces stale set (F7) |
| Schema drift (live DB newer than binary) | `PolicyStoreMaxVersion` + `CheckSQLiteSchema` boot gate fails loud | Consistent with chain store |
| Corrupt JSON in list column | Boot load error (loud) | Good; shape-validation gap is F3 |
| Audit sink outage on PUT | Mutation stands, event dropped/queued (fail-open) | Matches AGENTS.md; mutation-before-audit order is correct |
| Config errors (file+inline, `backend: redis`, sqlite without DSN) | Boot error, never silent fallback (Verified precedent: `serverbuildstore/build_oauth_stores.go:45` "oauth.sqlite.dsn required") | Good |
| Rule bundle over 1000-rule cap | Boot error (PUT and config share the cap) | Good; must be in `docs/config-reference.md` |

---

## 4. Guarantees, topologies, validation tests, residual risks

### Stated guarantees the design delivers (Verified)

- Hot path stays pure, I/O-free, clock-free; COW snapshot means `Allow`
  sees old or new set, never a blend (Verified: `memory/store.go`).
- `Replace` is all-or-nothing on disk (single tx) and `error = no change`
  (fail-closed); validation happens before any store call (`400`, zero
  mutation).
- Loud boot on open/migrate/load/JSON/schema-drift failures.
- Oracle safety unchanged: deny or policy error collapses to the same
  `invalid_grant` (`tokExEnforcePolicy`, Verified); rule detail only in
  audit/admin.
- `default_allow` is config-owned, never persisted, not PUT-able — one
  mutation path only.
- Byte-compatibility: empty new fields match exactly as today; `Rule` has
  no json/yaml tags and zero production serialization today (Verified:
  no non-test references to `tokenexchange.Rule` outside the package), so
  additive tags are wire-neutral.

### Unsupported / constrained topologies (must be documented)

- **Multi-replica sharing one DSN with live admin PUTs** — stale snapshots
  on all non-writing replicas (F1). Until the bus hook lands, treat the
  sqlite backend as single-replica, or accept the unbounded window knowingly.
- **Per-replica DSNs** — silently divergent. Low practical risk because the
  policy store reuses `oauth.sqlite.dsn` (a per-replica DSN already breaks
  the whole OAuth tier), but note it.
- **`backend: redis`** — boot error by design (no silent memory fallback).
- **Mixed-config fleet** — divergent `default_allow` (F4); operator must
  keep configs byte-identical.

### Validation tests (proposed additions to the design's list)

1. `Evaluate` truth table for all new dimensions (ALL-of scopes,
   ANY-of resources, trailing-`*` prefix, exact `requested_token_type`,
   empty-fields byte-compat) — pure, no store.
2. Memory/sqlite parity: same rules → same `Allow` results; `Replace`
   order preservation; `Rules()` snapshot stability (F3, F5).
3. Concurrent `Replace`-vs-`Replace` → disk and snapshot converge (F2),
   run `-count=10+`.
4. Admin API: all `400` cases with a no-store-call assertion; `500` on
   store failure; 200 echo equals the committed set.
5. Boot-load validation: malformed wildcard row → loud boot error (F3).
6. Bus reload (if F1 is accepted): PUT on A → B reloads within one bus
   delivery; dropped event → B stays on old set (fail-open), logged.
7. Audit registration completeness: the four-gate set the design lists
   (`KnownEventTypes`, `drift_test.go` `wantUncategorizedEventTypes`,
   `cef.go`, `ocsf.go`) — Verified as the correct gate set.
8. E2E: PUT deny → denied in-process → close → second boot, same temp DSN
   (with `busy_timeout` pragma) → still denied; `GET` envelope matches
   (F6).

### Residual risks (accepted or open)

- F1 unfixed: unbounded deny-rule propagation latency across replicas,
  worst at failover — the single most important open item.
- F2 unfixed: torn governance state under concurrent admin PUTs.
- F3 unfixed: malformed DB rows with undefined matcher semantics.
- No version/etag: silent lost-updates; no conflict signal for tools.
- Audit is fail-open by design (AGENTS.md): a dropped
  `token_exchange_policy_updated` event is invisible to the operator —
  acceptable, but the event should also be emitted to the local log on
  sink failure (already the recorder's behavior).

## Non-goals / scope confirmations

- The design's Decision 7 list is accurate and complete; independently
  verified items: the 13-line headroom on `build_app_oauth.go` (the
  relocation to `build_app_tokenexchange.go` is the right call — the
  inline fallback is viable but abandons the named function), the
  `interfaces/sso` 60-file ceiling (mount + wrappers only in
  `accessors_threat.go`), the four audit registration gates, and the
  analysis doc's false "tokenpolicy sqlite backend" claim
  (`docs/auto/domains-tokenexchange-analysis.md:13`) which must not leak
  into `docs/config-reference.md`.
- The E2E restart coupling (two boots, one temp DSN) is feasible; the
  harness note in F6 is the only addition needed.
