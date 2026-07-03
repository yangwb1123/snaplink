# Disaster Recovery Framework

Failure levels, RPO/RTO targets, per-backend replication strategy, and the
recovery validation runbook. Operational reference — see
[deployment.md](deployment.md) for the base architecture and
[config-reference.md](config-reference.md#disaster-recovery) for the `dr.*`
config keys.

- [1. Scope: what this framework covers](#1-scope-what-this-framework-covers)
- [2. Failure levels](#2-failure-levels)
- [3. Data classification + replication strategy](#3-data-classification--replication-strategy)
- [4. SnapshotReplicator](#4-snapshotreplicator)
- [5. Readiness reporting](#5-readiness-reporting)
- [6. Recovery validation runbook](#6-recovery-validation-runbook)

---

## 1. Scope: what this framework covers

This SDK draws a hard line between two data tiers, and the DR framework
below covers only the first one:

1. **Control-plane / operator-managed state** — clients, users (master
   records), roles/assignments/menus, network policy, bootstrap state. This
   is exactly what `interfaces/snapshot.Snapshotter.Export` enumerates. It
   is small, changes infrequently, and losing it means re-registering every
   OAuth client and user by hand.
2. **Hot ephemeral session/token state** — sessions, access/refresh tokens,
   auth codes, PAR requests, JTI-replay records, MFA challenges, rate-limit
   counters. **Intentionally excluded from snapshots** (see the
   `interfaces/snapshot` package doc): identity-bearing, short-lived, and
   dangerous to replay across nodes. Losing this tier forces affected users
   to re-authenticate — it does not lose any durable business data.

The `platform/dr` `SnapshotReplicator` automates tier 1: it periodically
exports the same sealed snapshot the manual/retention snapshot pipeline
produces and copies it, checksum-verified, to an off-node DR replica mount.
Tier 2, and the raw backend bytes behind tier 1's own store (the SQLite
file, the Postgres database, the Redis keyspace, the etcd cluster), are
each backend's own concern — §3 maps every backend this SDK ships to its
own replication/backup mechanism.

## 2. Failure levels

| Level | Scenario | Blast radius | RPO target | RTO target | Response |
|---|---|---|---|---|---|
| **1 — Component** | One dependency call fails (authenticator backend timeout, risk scorer unreachable, geo lookup down) | Single request | 0 (no committed data touched) | Seconds | Handled in-process by the documented fail-open/fail-closed behavior per AGENTS.md §3 (e.g. geo/risk fail-open, signature validation fail-closed). No operator action. |
| **2 — Replica** | One replica process/pod crashes or is evicted | One replica; others keep serving | 0 (durable stores are shared, not per-replica) | Minutes (orchestrator reschedule + `/readyz` pass) | Kubernetes/orchestrator restarts the pod. `/livez` + `/readyz` gate traffic until the replacement is healthy. No data-recovery action — durable state never lived on the replica. |
| **3 — Durable-store loss (single site)** | A backend's data is lost or corrupted in place: SQLite file corruption, Postgres database/volume loss, Redis keyspace flush, etcd cluster loses quorum | All replicas sharing that backend, one site/cluster | Bounded by that backend's own backup/replication cadence (§3) | Tens of minutes (restore + validate before re-admitting traffic) | Restore the affected backend from its own backup/replica (§3), or restore control-plane state from the newest DR replica (§4) if the loss included clients/users/permissions. Validate via §6 before removing the maintenance page. |
| **4 — Site/region loss** | The entire cluster — every replica, every backend, and any DR mount colocated with it — is unreachable (region outage, catastrophic infra failure) | Everything at that site | Bounded by DR replication lag to the OFF-site target (`dr.interval`, reported as `sso_dr_snapshot_replication_lag_seconds`) | Hours (stand up a new cluster, restore control-plane state, re-provision or fail over each backend, re-point DNS/LB, validate) | Stand up a fresh cluster in a surviving region. Restore control-plane state from the DR replica (§4/§6). Each backend's own cross-region strategy (§3) governs how much of tier-2/backend data survives; sessions/tokens are expected to be lost (users re-authenticate). |

RPO/RTO are **targets to configure and measure against**, not guarantees the
SDK enforces. `dr.rpo_target` / `dr.rto_target` (see
[config-reference.md](config-reference.md#disaster-recovery)) feed the
`DRReadiness` verdict and the admin status endpoint (§5) so an operator can
see, continuously, whether the configured targets are actually being met —
they do not by themselves make backups happen faster.

## 3. Data classification + replication strategy

| Backend | Used for (this SDK) | Replication / backup mechanism | Cross-region DR |
|---|---|---|---|
| **SQLite** (`infrastructure/defaultimpl/sqlite`, pure-Go, no CGO) | Default durable backend for identity, OAuth hot stores, MFA, audit, permissions, etc. (`*.backend: sqlite`) | Online `VACUUM INTO` via `POST /api/v1/admin/backup` (`backup.dir` / `backup.keep`); pair with filesystem/volume-level snapshots of the WAL-mode DB file for point-in-time coverage | Ship `backup.dir` output (or a volume snapshot) to the DR site on your own schedule; `platform/dr` does NOT replicate the raw SQLite files — only the control-plane subset enumerated by `Snapshotter` (§1) |
| **PostgreSQL** (`infrastructure/postgres`, shared `*sql.DB` pool) | Durable backend for identity, tenants, audit, permissions, etc. (`*.backend: postgres`) | Operator-managed: native streaming replication to a standby, `pg_dump`/`pg_basebackup`, or a managed Postgres provider's PITR | Cross-region streaming replica or WAL archiving to the DR region — outside this SDK's process; the SDK only needs `postgres.dsn` re-pointed after failover |
| **Redis** (`infrastructure/redis`, shared client) | Hot/ephemeral backend for sessions, OAuth hot stores, rate limiting, JTI replay, MFA challenges (`*.backend: redis`) | Operator-managed: RDB/AOF persistence + a replica (Sentinel/Cluster) for HA within a region | Not recommended cross-region — this tier is intentionally short-lived (§1); a lost Redis keyspace forces re-auth, it does not lose business data. Do not treat Redis as a DR target. |
| **etcd** (`platform/cluster`, `platform/registry`, `platform/netpolicy`, `keys.signing_key_registry`) | Cross-replica coordination: invalidation bus, service registry, network policy, leaderless signing-key aggregation | `etcdctl snapshot save` on a schedule (etcd's own mechanism); etcd's Raft replication already gives in-region HA across its member set | Restore an etcd snapshot into a fresh cluster at the DR site; coordination state (client cache invalidation, key aggregation) rebuilds itself once replicas reconnect — it is not itself an RPO-sensitive business-data store |
| **Control-plane state** (clients, users, roles/assignments/menus, network policy, bootstrap state — backend-agnostic, whichever store above backs them) | Everything `interfaces/snapshot.Snapshotter` enumerates | **`platform/dr.SnapshotReplicator`** (§4) — exports via the SAME `Snapshotter`+`Pipeline` the manual/retention snapshot subsystem uses, copies the sealed+checksummed envelope to `dr.target_dir` on `dr.interval` | This is the ONE tier this framework replicates cross-site by design; point `dr.target_dir` at an off-node/off-region mount |

## 4. SnapshotReplicator

`platform/dr.SnapshotReplicator` (wired by `cmd/sso-server` when `dr.enabled:
true`) runs a background loop:

1. **Export** — calls the configured snapshot pipeline's `Snapshotter.Export`
   + `Pipeline.Save` to produce the same sealed `SealedEnvelope` bytes the
   manual/retention snapshot subsystem would, using an in-memory storage
   shim so this doesn't require a second persistent write.
2. **Copy + verify** — writes the bytes to a temp file in `dr.target_dir`,
   reads them back, compares SHA-256 digests, and only then renames the file
   into place. A replica is either complete-and-verified or absent — never
   partially written or silently corrupt.
3. **Prune** — deletes all but the newest `dr.keep` replicas in
   `dr.target_dir`. Only files matching the `snap_*.snap` naming convention
   are candidates; foreign files sharing the mount are never touched.

The first cycle fires immediately on boot (not after the first `dr.interval`
wait) so a fresh deployment doesn't read as "not ready" for no operational
reason. Export/copy/prune failures are **fail-open**: logged, surfaced via
the admin status endpoint and `LastError()`, retried next cycle — a DR hiccup
never becomes a login-path outage.

## 5. Readiness reporting

`platform/dr.DRReadiness` aggregates the replicator's live lag against
`dr.rpo_target` and a `RecoveryTimeTracker`'s bounded measured-RTO history
(operators call `RecoveryTimeTracker.Start`/`Stop` around an actual restore
or DR drill to populate it) into one verdict, surfaced two ways:

- **`GET /api/v1/admin/dr/status`** (admin:read) — always mounted when
  `dr.enabled`. Returns the readiness verdict, replication lag vs RPO
  target, last replication error, the RTO history, and the DR mount's
  retention inventory. This is the **default** surface — report-only, never
  affects request handling.
- **Prometheus** — `sso_dr_readiness` (1/0, always present once wired),
  `sso_dr_snapshot_replication_lag_seconds` (absent until the first
  successful replication), `sso_dr_last_recovery_seconds` (absent until a
  recovery is timed). See [observability.md](observability.md).
- **`/readyz`** — only when the operator explicitly sets
  `dr.gate_readiness: true`. This is the one place a DR verdict can affect
  live traffic (taking a replica out of a Kubernetes/LB rotation), so it is
  opt-in and off by default. **A stale or missing DR replica never blocks
  auth traffic on its own** — that is the whole point of keeping this
  report-only unless an operator deliberately wires the gate.

## 6. Recovery validation runbook

Run the applicable steps for the failure level in §2. Every step uses a
command or endpoint that already exists in this codebase — no external
tooling required.

### Level 1 / 2 — component or replica failure

1. Confirm the platform recovered on its own: `GET /livez` (process up),
   `GET /readyz` (aggregate readiness — includes any `WithReadyCheck`
   dependency probes, and `dr` only if `dr.gate_readiness: true`).
2. Check `sso_http_requests_total{status_class="5xx"}` returned to baseline
   and the relevant fail-open/fail-closed audit events (per AGENTS.md §3)
   didn't spike.
3. No data-recovery action is expected — escalate to Level 3 only if the
   backend itself (not just the replica process) is unhealthy.

### Level 3 — durable-store loss at one site

1. Identify the affected backend from its own health signal
   (`GET /api/v1/admin/storage-health`, backend-native monitoring for
   Postgres/Redis/etcd).
2. Restore that backend using its own mechanism from §3 (SQLite: restore
   the newest `POST /api/v1/admin/backup` output or a volume snapshot;
   Postgres: promote/restore a replica or PITR; Redis: restore from
   RDB/AOF; etcd: `etcdctl snapshot restore`).
3. If the loss included client/user/permission/netpolicy data, additionally
   restore control-plane state from the newest verified DR replica:
   - Verify it offline first (no running server required):
     `sso-ctl snapshot verify --dir <dr.target_dir> --id <snapshot-id>`.
   - Restore via a fresh first-boot: set
     `--bootstrap-restore-from file://<dr.target_dir>/?name=<snapshot-id>`
     (or `snapshot.restore_from` in config), or drive the admin
     `SnapshotAdminService` restore RPC against a running node.
4. Re-check `GET /api/v1/admin/dr/status` — `ready: true` and a fresh
   `last_replication_at` before removing any maintenance page.
5. Record the wall-clock duration of steps 2-4 via
   `RecoveryTimeTracker.Start`/`Stop` (or by hand against the runbook start
   time) so the measured RTO lands in the admin status endpoint's history
   and can be compared to `dr.rto_target`.

### Level 4 — site/region loss

1. Stand up a fresh `sso-server` deployment in the surviving region,
   pointed at fresh (or freshly restored) backend instances per §3.
2. Restore control-plane state from the DR replica mount that survived
   (it was, by construction, off-site) using the same procedure as Level 3
   step 3.
3. Re-provision each backend's own data per its cross-region strategy in
   §3. Sessions/tokens are expected to be lost — this is intentional
   (§1) — users re-authenticate.
4. Validate the new deployment fully before cutover:
   - `sso-ctl config validate --file config.yaml`
   - `GET /readyz` green on every replica
   - `GET /api/v1/admin/dr/status` `ready: true`
   - A synthetic login + token issuance + `/userinfo` round-trip against
     the new deployment
5. Re-point DNS/LB to the new region. Keep the old region's DR replica
   mount (if it survived in a retrievable form) until the new deployment
   has run a full `dr.interval` + one verified replication cycle of its
   own.
6. Record the total wall-clock RTO for the drill/incident and compare
   against `dr.rto_target`; feed the number back into `dr.rto_target` if
   it's consistently missed — the target should reflect what the runbook
   actually achieves, not an aspirational number nobody has verified.
