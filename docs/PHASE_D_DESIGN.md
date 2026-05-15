# Phase D — Design Doc

Status: D-1 implemented (noop / file / etcd backends + Runner integration
+ audit events + cmd/sso-server wiring); D-2 / D-3 design only.

This document is the design contract for Phase D. AGENTS.md will get a
condensed Capabilities section once each piece lands. Implementation order:
D-1 → D-2 → D-3, because the later phases benefit from a working
distributed lock.

---

## Goals

| ID  | Capability                                | Why                                      |
| --- | ----------------------------------------- | ---------------------------------------- |
| D-1 | Distributed init lock                     | Multi-replica `sso-server` must not race the `bootstrap.Runner`. |
| D-2 | App snapshot — export / restore           | Stand up new node from a known-good state; air-gapped migration; DR. |
| D-3 | Admin app version pin / rollback (frontend + backend paired) | Atomic, paired front+back release switching with rollback. |

The three are independent in surface area but compose: D-3's release
includes an optional snapshot reference (D-2); D-2's restore can run inside
a bootstrap step gated by D-1's lock.

---

## D-1 — Distributed init lock

### Problem

`bootstrap.Runner` + `bootstrap/file.Tracker` are single-node. Two
sso-server replicas booting concurrently both observe
`AppliedVersion=0`, both run `seed_admin_user`, both write — last writer
wins, password printed twice (or worse, two distinct random passwords),
audit corrupted.

### Design

A new `bootstrap/lock` subpackage with the smallest possible SPI:

```go
type Lock interface {
    TryAcquire(ctx context.Context, key string, ttl time.Duration) (Handle, error)
}

type Handle interface {
    Renew(ctx context.Context) error
    Release(ctx context.Context) error
    FencingToken() uint64   // monotonic; 0 if backend doesn't support fencing
}
```

Sentinel: `ErrLocked` (held by another holder), `ErrLockLost` (renewal
failed mid-run).

### Backends (all plugins)

| Backend     | Use case                | Implementation                                            |
| ----------- | ----------------------- | --------------------------------------------------------- |
| `noop`      | single replica, default | Returns Handle that succeeds; FencingToken=0.             |
| `file`      | single host, multi-proc | `syscall.Flock(LOCK_EX\|LOCK_NB)` on a lock file + PID.   |
| `etcd`      | multi-replica HA        | Lease + Txn(Compare=CreateRevision==0); KeepAlive driven. FencingToken=LeaseID. |
| `redis`     | already-have-Redis HA   | `SET NX PX` + Lua release script; FencingToken=Redis-side counter. |
| `postgres`  | already-have-PG HA      | `pg_try_advisory_lock(hashtext(key))`. FencingToken=txid. |

Only `noop` / `file` / `etcd` ship in D-1; the others are designed but
deferred until a deployment actually wants them.

### Runner integration

```go
runner := bootstrap.NewRunner(ns, tracker,
    bootstrap.WithLock(etcdLock, "/sso/bootstrap/" + ns),
    bootstrap.WithLockTTL(30*time.Second),
    bootstrap.WithLockBlocking(false),  // true = wait, false = fail-fast on contention
)
```

Run flow:

```
1. handle, err := lock.TryAcquire(ctx, key, ttl)
   - err == ErrLocked && !blocking → return ErrLocked
   - err == ErrLocked && blocking  → backoff retry
2. ctx, cancel := context.WithCancel(ctx)
3. go renewLoop(handle, ttl/3, cancel)   // renewal failure cancels ctx
4. defer handle.Release(ctx)
5. for each pending step (ctx-aware): run, mark applied
6. cancel()  // stop renewLoop
```

Renewal failure semantics: `renewLoop` cancels the parent ctx so the
in-flight Step receives `ctx.Err()` and aborts. The Tracker write that
follows will see a cancelled ctx and skip. No `MarkApplied` happens after
losing the lock — the next runner will re-attempt this version cleanly.

### Fencing tokens

Forward-compatible interface (`Handle.FencingToken()`), but D-1 doesn't
yet require a fenced Tracker. Today's only Tracker is file-backed
(single machine), where the lock layer alone is sufficient. When
`bootstrap/etcd` Tracker arrives in a future phase it will define
`FencedTracker` (extension) that validates `MarkApplied` against a
monotonic token.

### Audit events (D-1 additions to `audit/event.go`)

| EventType                       | Outcome  | When                                  |
| ------------------------------- | -------- | ------------------------------------- |
| `bootstrap_lock_acquired`       | success  | After successful TryAcquire           |
| `bootstrap_lock_release`        | success  | After explicit Release                |
| `bootstrap_lock_lost`           | failure  | renewLoop's Renew returned error      |
| `bootstrap_lock_contended`      | success  | TryAcquire returned ErrLocked         |

### Configuration

```yaml
bootstrap:
  lock:
    backend: "etcd"          # noop | file | etcd
    key: "/sso/bootstrap/sso-server"
    ttl: 30s
    blocking: false          # fail-fast vs wait
    file:
      path: "./bootstrap.lock"
    etcd:
      endpoints: ["http://etcd-0:2379"]
      dial_timeout: 5s
```

### Caveats

- **TTL too long** → after a crash, peers wait for TTL to take over.
- **TTL too short** → renewal loop has no margin for stop-the-world GCs;
  use `TTL/3` heartbeat with `TTL/6` minimum.
- **Cross-DC etcd** → don't put one etcd cluster across regions for this;
  use per-region etcd + per-region namespace.
- **Don't** use the same lock backend for both registry and bootstrap if
  registry write storms can cause head-of-line blocking on the lock
  Watch channel.

---

## D-2 — App snapshot: export & restore

### Problem

To stand up a new node with a known config, or migrate across
air-gapped networks, an operator needs a single self-describing artifact
that captures clients + users + permissions + netpolicy + bootstrap
state — and a way to apply it idempotently elsewhere.

### Snapshot envelope (versioned)

```jsonc
{
  "schema_version": "1",
  "snapshot_id": "snap_2026-05-15T08:30Z_a1b2",
  "taken_at_unix": 1747300200,
  "source_namespace": "sso-server",
  "source_node_id": "node-eu-west-1",

  "bootstrap_state": {
    "namespace": "sso-server",
    "applied_version": 4,
    "history": [{"v":1,"name":"seed_admin_role","at_unix":...}, ...]
  },

  "resources": {
    "clients":     [Client...],
    "users":       [User...],
    "roles":       [{"client_id":"...", "roles":[Role...]}],
    "assignments": [Assignment...],
    "menus":       [{"client_id":"...", "menus": MenuTree}],
    "netpolicy":   [Policy...],
    "tokens":      []
  },

  "encryption": {"alg": "chacha20-poly1305", "kid": "kms://...", "nonce": "..."},
  "checksum": "sha256:..."
}
```

Active sessions and live tokens are intentionally excluded: their
identity-bearing nature makes them dangerous to ship across nodes.

### Package layout

```
snapshot/
  snapshotter.go        # Export(ctx, opts) (*Snapshot, error)
  restorer.go           # Restore(ctx, snap, opts) (*Report, error)
  codec.go              # JSON | Proto | msgpack (plugin)
  storage/
    file/               # write to local path
    s3/                 # write to S3-compatible
    inline/             # return []byte; no persistence
  encryption/
    none/
    age/                # https://age-encryption.org
    kms/                # cloud KMS-wrapped DEK
```

### Restore semantics

| Mode           | Behavior                                                    |
| -------------- | ----------------------------------------------------------- |
| `Merge`        | Skip resources whose ID already exists; only create missing.|
| `Overwrite`    | Existing IDs replaced with snapshot values.                 |
| `Replace`      | Delete all targeted resources, then load snapshot. Requires `confirm: snapshot_id`. |
| `DryRun: true` | Compute Report without writing.                             |
| `Exclude`      | Skip listed resource categories (e.g. exclude `netpolicy`). |
| `AdvanceBootstrap: true` | Set Tracker's applied_version to snapshot's marker so seed steps don't re-fire. |

Apply order matters:
`roles → menus → clients → users → assignments → netpolicy → bootstrap_state` (last).

### Bootstrap integration

A new builtin step at version 0 runs before the seed steps:

```go
StepFunc("restore_from_snapshot", 0, func(ctx context.Context) error {
    src := os.Getenv("SSO_RESTORE_FROM")
    if src == "" { return nil }
    snap, err := snapshot.LoadFromURI(src)   // file:// s3:// inline://
    if err != nil { return err }
    return restorer.Restore(ctx, snap, RestoreOptions{
        Mode: Overwrite, AdvanceBootstrap: true,
    })
})
```

Because `Version=0 < seed_admin_role.Version=1`, restore happens first;
`AdvanceBootstrap: true` then pushes Tracker's applied_version forward
so `seed_admin_role`/`seed_admin_user`/etc. are skipped on the same boot.

### Admin RPCs

`snapshot.v1.SnapshotService` (registered alongside admin Phase C):

| RPC          | Verb / Path                                       |
| ------------ | ------------------------------------------------- |
| `Export`     | `POST /api/v1/admin/snapshots`                    |
| `List`       | `GET  /api/v1/admin/snapshots`                    |
| `Get`        | `GET  /api/v1/admin/snapshots/{id}`               |
| `Restore`    | `POST /api/v1/admin/snapshots/{id}:restore`       |
| `Delete`     | `DELETE /api/v1/admin/snapshots/{id}`             |

Audit: `snapshot_exported`, `snapshot_restored`, `snapshot_deleted` —
each tagged with actor + affected row counts + restore mode.

### Security

- Encryption is on by default; `encryption.none` requires explicit YAML opt-in.
- Client secrets remain encrypted under the snapshot's encryption layer
  even if the snapshot file itself sits behind another encryption-at-rest
  scheme.
- `Restore` requires `confirm: snapshot_id` for `Replace` mode.

---

## D-3 — Admin app version pin / rollback

### Problem

The admin UI and admin API ship as paired artifacts. Operators need to
roll back the active pair atomically, without ending up with frontend
v3 talking to backend v2.

### Concept

```
Release {
    ID:              "rel-2026-05-15-001"
    Channel:         "stable" | "canary" | "rollback"
    Frontend:        { GitRef: "v3.2.1", Bundle: "s3://...", SHA256: "..." }
    Backend:         { GitRef: "v3.2.1", Image: "ghcr.io/.../api:v3.2.1", Digest: "sha256:..." }
    SchemaVersion:   12
    ConfigSnapshot:  "snap_..."   // optional D-2 snapshot id
    ReleasedAt:      ...
    ReleasedBy:      "alice@org"
    Notes:           "fix permission cache TTL"
}
```

A Release is invalid unless **both** Frontend and Backend refs are set.
CI/CD registers paired releases atomically.

### Package layout

```
releases/
  registry.go        # Register / List / Get / Pin / Current
  pinner.go          # Pinner interface: Apply(release) error
  pinner/
    systemd/         # rewrite unit ExecStart + reload + restart
    k8s/             # set Deployment image + apply ConfigMap + wait for rollout
    docker/          # docker compose pull && up -d
    static/          # frontend-only: replace bundle on disk / sync to CDN
  store/
    file/            # releases.json
    git/             # tag-driven (each release = annotated git tag)
    postgres/
```

### Pin / Rollback flow

**Pin (forward release):**

1. Compare target.SchemaVersion vs current. If forward → run
   pending bootstrap steps (the `bootstrap.Runner` is reused). If
   backward → reject; the operator must use Rollback.
2. `Pinner.Apply(release)` — **backend first**, then frontend (frontend
   tolerates old API better than the reverse).
3. Write `currentlyPinned = release_id`.
4. Health-probe for N seconds; failure auto-pins back.
5. Audit `release_pinned`.

**Rollback:**

1. Confirm target release exists and ConfigSnapshot is restorable.
2. Apply `Pinner` in reverse order — **frontend first** (so old UI
   stops issuing new API calls), then backend.
3. If `ConfigSnapshot` is set, run `snapshot.Restore` before flipping
   the backend.
4. Audit `release_rolled_back`.

### Admin RPCs

`releases.v1.ReleaseService`:

| RPC          | Verb / Path                                          |
| ------------ | ---------------------------------------------------- |
| `Register`   | `POST   /api/v1/admin/releases`                      |
| `List`       | `GET    /api/v1/admin/releases`                      |
| `Get`        | `GET    /api/v1/admin/releases/{id}`                 |
| `GetCurrent` | `GET    /api/v1/admin/releases:current`              |
| `Pin`        | `POST   /api/v1/admin/releases/{id}:pin`             |
| `Rollback`   | `POST   /api/v1/admin/releases/{id}:rollback`        |
| `Diff`       | `GET    /api/v1/admin/releases:diff?a=..&b=..`       |

### Caveats

- **Schema migrations must be backward-compatible across N-1 versions**
  to make rollback possible without down-migrations.
- **Pin order is never symmetric** between forward and rollback.
  Encode it in the Pinner — operators should not have to remember.
- **Don't pin without health checks**; auto-rollback on probe failure.
- **Static assets behind CDN** need cache invalidation on Pin or users
  see mixed-version pages. Pinner SHOULD purge.

---

## Per-layer architecture: core + plugins

Each microservice layer has a small, fixed core and a defined plugin SPI.
"Core" = behavior that defines the service. "Plugin" = anything
deployment-specific.

| Layer                   | Core (fixed)                                                 | Plugin SPI (replaceable)                              | Today                              |
| ----------------------- | ------------------------------------------------------------ | ----------------------------------------------------- | ---------------------------------- |
| **Identity** (`sso/`)   | Auth flow, token orchestration, session lifecycle, HTTP routes | `Authenticator`, `TokenIssuer`, `UserProvider`, `ClientStore`, `SessionManager`, `Router` | 7 authn × 2 token strategies × memory |
| **Permissions**         | Wildcard matcher, menu tree merge                            | `Provider`                                            | memory                             |
| **Audit**               | Recorder, filter chain                                       | `Sink`, `Filter`, `Formatter`                         | memory / writer / webhook / multi  |
| **NetPolicy**           | Priority match, hostname-beats-CIDR, watcher fan-out         | `Store`, `Resolver`, `Classifier`                     | memory / etcd                      |
| **Discovery**           | Register / Discover / Watch                                  | `Registry`                                            | memory / etcd                      |
| **Edge**                | JWKS verify, X-Auth-* injection, X-Network stamp             | Lua modules                                           | OpenResty + 5 modules              |
| **Admin Control Plane** | CRUD orchestration, scope check, audit emission              | `AdminAuthorizer`, `Validator`, `RateLimiter`         | providerAuthorizer                 |
| **Bootstrap**           | Step ordering, version tracking, runner                      | `Tracker`, `Lock` (D-1), `Step`                       | memory / file (+etcd lock D-1)     |
| **Snapshot** (D-2)      | Export / restore orchestration, dependency order             | `Codec`, `Storage`, `Encryption`                      | (planned)                          |
| **Releases** (D-3)      | Register / Pin / Rollback, pair validation                   | `Pinner`, `ReleaseStore`                              | (planned)                          |

### Plugin contract conventions

1. **Small interfaces** (≤ 5 methods). Split into `Reader` / `Writer` /
   `Admin` if a single role would exceed.
2. **Functional Option construction** — `sso.WithClientStore(impl)`. No DI container.
3. **In-process plugin = Go interface satisfaction**. Default. Zero overhead.
4. **Out-of-process plugin = gRPC SPI** (HashiCorp `go-plugin` style).
   Use only when:
   - plugin is in another language;
   - independent crash domain is required;
   - sandboxed permissions are required.

   Don't use Go's `plugin` package — version-fragile, weak cross-platform.
5. **Capability discovery** — every SPI exposes `Capabilities() []string`
   so the core can graceful-degrade.
6. **Sentinel errors per layer**, mapped uniformly to gRPC codes.

---

## System composition

```
                    ┌──────────────────────────────────┐
                    │    Edge (OpenResty + Lua)        │
                    │  JWKS verify · X-Network · audit │
                    └─────────────┬────────────────────┘
                                  │ HTTP
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
        ┌──────────┐       ┌──────────┐         ┌──────────┐
        │ Identity │       │  Admin   │         │  Health  │
        │  /login  │       │  /admin  │         │  /-/jwks │
        └────┬─────┘       └────┬─────┘         └──────────┘
             │                  │
             ▼                  ▼
    ┌────────────────┐   ┌──────────────────┐
    │ Authenticator  │   │ Admin Middleware │ ← admin:* scope
    │   (plugins)    │   │                  │
    └────┬───────────┘   └────────┬─────────┘
         │                        │
         ▼                        ▼
    ┌─────────────────────────────────────────┐
    │           Storage Plane (shared)        │
    │ ┌────────┬─────┬──────────┬──────────┐  │
    │ │Clients │User │Sessions  │ Permsn   │  │
    │ │ Store  │Prov.│  Mgr     │ Provider │  │
    │ └────────┴─────┴──────────┴──────────┘  │
    └─────────────┬───────────────────────────┘
                  │
        ┌─────────┴──────────┬──────────────┬────────────┐
        ▼                    ▼              ▼            ▼
  ┌─────────────┐    ┌──────────────┐ ┌──────────┐ ┌──────────┐
  │  Snapshot   │    │  Bootstrap   │ │  Audit   │ │NetPolicy │
  │ Export/     │    │  Runner +    │ │ Recorder │ │ Store +  │
  │ Restore     │    │  Dist. Lock  │ │ + Sinks  │ │Classifier│
  └─────────────┘    └───────┬──────┘ └──────────┘ └──────────┘
                             │
                             ▼
                       ┌──────────┐
                       │ Releases │
                       │  Pin /   │
                       │ Rollback │
                       └────┬─────┘
                            ▼
                  ┌──────────────────┐
                  │ Pinner: systemd  │
                  │       / k8s      │
                  │       / docker   │
                  └──────────────────┘
```

Cold-boot timeline:

```
node up
  → bootstrap.Lock.TryAcquire("sso/bootstrap/sso-server")
  → snapshot.Restore (if SSO_RESTORE_FROM set)  [D-2]
  → builtin steps (skipping any advanced past by restore)
  → bootstrap.Lock.Release
  → http + grpc serve
  → registry.Register
  → audit boot event
```

---

## Use cases

| Scenario                                    | Capability mix                                                                          |
| ------------------------------------------- | --------------------------------------------------------------------------------------- |
| Multi-tenant SaaS SSO                       | Identity + Admin + per-tenant Snapshot + NetPolicy (per-tenant CIDR) + etcd Lock        |
| Corporate intranet SSO                      | Identity (LDAP/AD plugin) + NetPolicy (intranet/public split) + Edge                    |
| Embedded SSO (per product)                  | `ssoclient` + `ssoclient/bootstrap` (per-product namespace) + memory backends           |
| Compliance-heavy (finance, healthcare)      | Audit Sinks → SIEM/Kafka + scheduled Snapshots + Releases for traceability              |
| Air-gapped migration                        | Snapshot encrypted export → physical media → remote node Restore                        |
| Multi-region active-active                  | etcd partitioned + per-region NetPolicy + cross-region Snapshot replication             |
| One-click CI/CD rollback                    | Releases (paired front+back) + linked Snapshot                                          |
| Disaster recovery drill                     | Scheduled Snapshot + Restore into isolated namespace                                    |

---

## Performance (estimates)

| Operation                                        | Latency / time      | Notes                                  |
| ------------------------------------------------ | ------------------- | -------------------------------------- |
| Bootstrap lock acquire (etcd)                    | 5–50 ms             | Cold boot only                         |
| `seed_admin_user` step (memory provider)         | <1 ms               |                                        |
| `seed_admin_user` step (postgres provider)       | ~20 ms              | Single insert + role assignment        |
| Snapshot export (10k clients + 100k users, JSON) | 15–60 s             | Streaming codec brings to 5 s          |
| Snapshot restore (same)                          | 30–120 s            | Bound by target store write rate       |
| Release Pin (k8s)                                | 20–60 s             | Wait for rollout-ready                 |
| Release Pin (systemd)                            | 1–5 s               | Single process reload                  |
| Admin RPC (memory backend)                       | <2 ms               | Audit synchronous                      |
| Admin RPC (postgres backend)                     | <10 ms              |                                        |
| Edge JWKS cache hit                              | <500 µs             | Lua shared dict                        |
| Edge NetPolicy hit (≤10 policies)                | <300 µs             | Sorted scan                            |

Bottlenecks live in **audit sinks** and **storage backends**, not the
framework. Audit MUST be async-buffered so admin RPC latency doesn't
spike under sink backpressure.

---

## Cross-cutting caveats

1. **Lock TTL tuning.** Short = no margin for GC pause; long = slow
   failover. Defaults: TTL=30s, heartbeat=TTL/3.
2. **Snapshot encryption is non-optional in production.** Client secrets
   + user attributes can carry PII.
3. **Restore is destructive in `Replace` mode.** Require
   `confirm=snapshot_id` parameter on the admin RPC.
4. **Release pinning order matters.** Document and encode in the Pinner;
   don't trust runbooks.
5. **Schema migrations decouple from code deploy.** Releases run
   migrations separately. Backward-compat to N-1.
6. **Seed admin password exposure window.** Default prints once to
   stdout. For prod, switch to operator-injected
   `SSO_INITIAL_ADMIN_PASSWORD_HASH` env (bcrypt) — never plaintext.
7. **Out-of-process plugins cost ~200 µs per call.** Don't put hot path
   (e.g. permission matcher) behind one.
8. **Bootstrap step idempotency is a contract, not a check.** Runner
   guarantees once-per-version; the step itself should still cope with
   `MarkApplied` write failures after the step's side effects landed.
9. **Audit can't depend on the storage it audits.** Don't wire admin
   audit through the same Provider it mutates — circular failure.
10. **Three switching surfaces — code, config, schema — must move
    together.** "Release" is the single abstraction; banning piecemeal
    switching at the API level prevents accidents.

---

## Out of scope (Phase E candidates)

- Multi-tenant isolation primitives (per-tenant key namespace, per-tenant
  audit topics).
- Webhook-based release approvals (Slack interactive / GitHub PR gates).
- Snapshot diff & merge (3-way config merge across nodes).
- Real-time policy push (currently Watch-driven; webhook-out for
  ultra-low-latency invalidation).
- Cross-region snapshot replication transport.
