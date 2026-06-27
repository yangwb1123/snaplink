# Bare-Metal Production HA Data Layer — Design Spec

- **Date:** 2026-06-26
- **Status:** Approved (design); pending implementation plan
- **Scope:** A complete, reproducible production data-layer deployment for the
  `sso-server` binary on self-managed bare-metal / VM infrastructure, engineered
  for high availability, high concurrency, and high load.
- **Driver (confirmed):** Standard production HA — robust failover, no single
  point of failure, normal enterprise scale (≤ low-millions of users, ≤ a
  few-thousand auth RPS).
- **Substrate (confirmed):** Bare-metal / self-managed VMs.
- **Deliverable (confirmed):** This spec + working artifacts + production runbook.

## 1. Goals / Non-Goals

### Goals
- No single point of failure across every tier: edge LB, app, hot store (Redis),
  durable store (Postgres), and coordination (etcd).
- Automatic failover at every tier with bounded, documented recovery times.
- A reproducible full-topology bring-up (one host) plus production configs that
  map directly onto real VMs, and a runbook covering failover drills, backup /
  restore, capacity sizing, and security hardening.
- Zero application-code change required: the topology is realized entirely
  through existing `sso-server` config keys and existing cluster-aware backends.

### Non-Goals (explicit YAGNI — see §9 for reversal triggers)
- **No application-level 分库分表 (sharding).** Postgres holds the durable tables
  comfortably at this scale; the hot keyspace is already sharded across Redis
  Cluster slots.
- **No message queue (Kafka / RabbitMQ / NATS).** The existing etcd-backed
  `cluster.Bus` already carries cross-replica invalidation events.
- **No multi-datacenter active-active.** Single-DC HA only.

## 2. Confirmed Decisions

| Fork | Decision |
|---|---|
| Scale driver | Standard production HA |
| Substrate | Bare-metal / self-managed VMs |
| Durable DB engine + HA model | PostgreSQL + Patroni + floating VIP |
| Reproducible bring-up | docker-compose (full topology on one host); raw configs reusable on VMs; systemd/Ansible documented as the production alternative |
| Deliverable | Spec + artifacts + runbook |

## 3. Architecture

### 3.1 Topology

Reference cluster of **3 VMs** (collapsible to 1 host via compose for dev/CI,
expandable to more app nodes). Each VM co-locates a slice of every tier so the
quorum services (etcd, Patroni, Redis) get their 3 members.

```
            keepalived VRRP floating VIP   (the 「ip漂移」)
            ┌───────────────┴────────────────┐
     HAProxy-A (MASTER)               HAProxy-B (BACKUP)
            └───────────────┬────────────────┘
              L7 round-robin, health-check GET /readyz, XFF re-set
            ┌───────────────┼────────────────┐
     sso-server-1     sso-server-2     sso-server-3      (stateless app tier)
            └───────────────┼────────────────┘
   ┌────────────────────────┼─────────────────────────┐
 Redis Cluster          Postgres HA                 etcd cluster (3)
 3 master + 3 replica    Patroni: 1 leader + 2 repl   • Patroni DCS
 16384 slots             via HAProxy :5432→leader     • sso cluster.Bus
 cluster-aware client    :5433→replicas (read offload) • signing-key registry
 NO load balancer        sync replication
```

### 3.2 Node role matrix

| Tier | Members | Per-VM placement |
|---|---|---|
| Edge LB | 2× HAProxy + keepalived VRRP | haproxy on VM1 + VM2; VIP floats between them |
| App | N× `sso-server` (stateless) | 1 per VM; scale out freely |
| Redis Cluster | 6 nodes (3 master + 3 replica) | 2 redis per VM (1 master + 1 replica of another VM's master) |
| Postgres HA | 1 leader + 2 replicas (Patroni) | 1 patroni-postgres per VM |
| etcd | 3 nodes | 1 per VM |

**Anti-affinity (runbook-enforced):** a Redis master and its own replica never
share a VM; the Patroni leader may run on any VM (etcd elects it).

## 4. Component Design — Durable Tier (Postgres + Patroni)

- **Patroni** supervises Postgres on each DB node and stores cluster state +
  performs leader election in the shared **etcd**.
- **Synchronous replication** (`synchronous_mode: true`, at least one sync
  standby) so a leader loss never loses a committed token / consent / user write.
  Postgres is the durable source of truth, so a lost commit is unacceptable.
- **HAProxy role-routing** via Patroni's REST health endpoint:
  - `VIP:5432` → the current leader (all writes + read-after-write paths).
  - `VIP:5433` → replicas (optional read-only offload; off by default to keep
    read-after-write semantics simple).
- **sso-server DSN** points at `VIP:5432` and *also* lists all DB hosts with
  `target_session_attrs=read-write` as a fallback if HAProxy is mid-failover.
  The pgx pool already supports multi-host DSN — no code change.
- **Failover behavior:** Patroni promotes a synchronous replica (typically <10s);
  HAProxy's health check repoints `:5432` to the new leader; in-flight writes get
  a retriable error. The recently landed **SERIALIZABLE + 40001 retry** on the
  RBAC read-modify-write paths lets those writes ride through a failover-induced
  serialization blip without surfacing a 500.
- **Schema migration** is handled by the app's existing pure-Go migrate runner
  (advisory-lock on Postgres) — safe under concurrent replica boots.

## 5. Component Design — Hot Tier (Redis Cluster)

- **6 nodes, 16384 slots** auto-distributed; **cluster-aware client only**
  (`goredis.NewClusterClient`, already wired). Every multi-key op in the redis
  backend is already CROSSSLOT-safe via hash-tags / `mgetCompat`.
- **No load balancer in front** — the client follows MOVED/ASK redirects and
  gossip-driven failover itself. An L4/L7 LB would break slot routing.
- **Persistence:** AOF `appendfsync everysec` on every node so a full-cluster
  restart recovers recent sessions/tokens; per-shard replica gives fast failover.
- **Read routing stays master-pinned:** `route_by_latency` / `route_randomly` /
  `read_only` remain **off** (the repo default) so single-use / replay reads
  (auth code, refresh, jti) never read a lagging replica and let a replay evade
  detection.
- **TLS** between sso-server and Redis via the existing `redis.tls` config block.

## 6. Component Design — Edge (HAProxy + keepalived)

- **keepalived (VRRP)** floats one virtual IP across the 2 HAProxy nodes
  (MASTER / BACKUP by priority). A `track_script` on haproxy liveness triggers
  VIP release in ~1–3s when an HAProxy dies. **This is the IP漂移.**
- **HAProxy L7**: round-robin across `sso-server` replicas, **health-checked on
  `GET /readyz`** — which already returns 503 when that replica's Redis or
  Postgres ping fails, so HAProxy automatically drains a replica that lost its
  backends. `GET /livez` stays 200 so the process is drained, not killed.
- **Probes outside rate-limiting:** `/metrics`, `/livez`, `/readyz` are matched
  before any auth/ratelimit ACL (mirrors the app's middleware ordering).
- **X-Forwarded-* trust contract (security-critical, AGENTS.md §3):** HAProxy
  **strips inbound** `X-Forwarded-*` and **re-sets** `X-Forwarded-For` /
  `X-Forwarded-Proto` / `Host`. `sso-server` is configured to trust the first hop
  only behind this edge; otherwise client-supplied XFF could spoof geo / ratelimit
  IP keying / base-URL. This is a hard invariant in the runbook checklist.
- **TLS:** reference terminates TLS at HAProxy and forwards
  `X-Forwarded-Proto: https`; passthrough is documented as an alternative.

## 7. Component Design — Coordination (etcd)

- **3-node etcd** (5 for larger fleets) serving **triple duty**: Patroni DCS +
  `sso` `cluster.Bus` (cross-replica invalidation: token revocation, signing-key
  rotation, client change, authz policy change) + the **signing-key registry**
  (leaderless JWKS aggregation). All three are already wired in the app.
- **Fail modes:** Patroni is fail-closed on etcd quorum loss (no leader changes
  while the DCS is unavailable — correct, avoids split-brain); the app's
  `cluster.Bus` is fail-open by existing design (invalidation degrades to
  per-node TTL, never blocks the request path).
- Metadata-only; sized small. TLS + auth (username/password) on the client
  endpoints via existing `etcd_*` config fields.

## 8. sso-server Configuration (no app code change)

A single `config.yaml` ties the tiers together using config keys that already
exist:

```yaml
redis:
  mode: cluster
  addrs: [redis-1a:6379, redis-1b:6379, redis-2a:6379, redis-2b:6379, redis-3a:6379, redis-3b:6379]
  tls: { enabled: true, ca_file: /etc/sso/tls/redis-ca.pem }
  # route_by_latency / read_only left false (master-pinned single-use reads)

postgres:
  dsn: "host=VIP port=5432 user=sso dbname=sso sslmode=verify-full target_session_attrs=read-write"
  dialect: postgres
  max_open_conns: 20   # N replicas × max_open must stay under PG max_connections

cluster:
  bus: { backend: etcd, etcd_endpoints: [etcd-1:2379, etcd-2:2379, etcd-3:2379], etcd_prefix: /sso/bus }
  cross_replica_revocation: true

keys:
  signing_key_registry:
    backend: etcd
    etcd_endpoints: [etcd-1:2379, etcd-2:2379, etcd-3:2379]
    etcd_prefix: /sso/signing-keys
```

Secrets (Redis/Postgres/etcd passwords) injected via env overrides
(`SSO_REDIS__PASSWORD`, `SSO_POSTGRES__DSN`, …), never committed.

## 9. Deferred Items + Reversal Triggers

| Deferred | Reversal trigger | Action when triggered |
|---|---|---|
| App-level 分库分表 | Sustained multi-TB durable data or write-saturation a single PG leader can't absorb | Switch `postgres.dialect` to CockroachDB (already supported) for transparent sharding — never hand-rolled app sharding |
| Message queue | Async fan-out becomes a bottleneck (SSF push to thousands of receivers, external audit/data pipeline, or audit write volume saturating PG) | Introduce NATS or Kafka for that specific async path; keep etcd bus for invalidation |
| Multi-DC active-active | Geographic DR / residency requirement | Region-aware routing + per-region clusters (separate design) |

## 10. Failure-Mode Matrix

| Failure | Detection | Recovery | Client impact |
|---|---|---|---|
| HAProxy node dies | keepalived track_script | VIP floats to BACKUP (~1–3s) | brief connect retry |
| sso-server replica dies / loses backend | HAProxy `/readyz` check | drained from rotation | none (other replicas serve) |
| Redis master dies | cluster gossip | replica promoted (~1–2s) | brief retry on that shard's keys |
| Postgres leader dies | Patroni + etcd | sync replica promoted (<10s); HAProxy repoints | writes retriable; reads via replicas optional |
| etcd node dies | raft | quorum holds with 2/3 | none (Patroni + bus continue) |
| etcd quorum lost (2/3 down) | raft | no PG leader change (fail-closed); app bus fail-open | no failover until quorum restored |

## 11. Deliverables — Repo Layout (`ops/deploy/baremetal-ha/`)

```
ops/deploy/baremetal-ha/
  docker-compose.yml            # full topology on one host (CI/dev/demo)
  .env.example                  # parameters (VIP, passwords-via-secrets, sizes)
  haproxy/haproxy.cfg           # frontend VIP, sso-server backend (/readyz), PG leader/replica backends
  keepalived/keepalived.master.conf
  keepalived/keepalived.backup.conf
  patroni/patroni.yml           # template; per-node overrides documented
  postgres/                     # init SQL / pg_hba template
  redis/redis-cluster.conf      # per-node template (AOF, cluster-enabled)
  redis/cluster-create.sh       # one-shot 3-master+3-replica bootstrap
  etcd/etcd.env                 # 3-node static bootstrap
  sso/config.yaml               # the wired server config (§8)
  RUNBOOK.md                    # bring-up order, failover drills, backup/restore, sizing, hardening checklist
  README.md                     # container→VM mapping, quick start
```

## 12. Capacity & Sizing (runbook content)

- **sso-server:** stateless; size replica count to peak auth RPS ÷ per-replica
  throughput; HAProxy `maxconn` and per-backend conn limits documented.
- **Redis:** memory = peak concurrent sessions/tokens × avg record size × safety
  factor; AOF disk headroom; `maxmemory-policy noeviction` for token correctness.
- **Postgres:** `max_connections` ≥ Σ(replicas × `max_open_conns`) + Patroni +
  admin headroom; sync-standby count vs latency tradeoff.
- **etcd:** default; metadata-only.

## 13. Validation / Testing

- `docker-compose up` brings the full topology healthy; an end-to-end smoke
  (issue token via VIP, validate on a different replica, refresh, revoke) proves
  cross-replica correctness.
- Scripted **failover drills** (kill PG leader, kill an HAProxy, kill a Redis
  master) asserting continuity, included as runbook procedures + optional CI.
- Confirms the app's existing `/readyz` gating drains a replica whose backend is
  cut.

## 14. Open Questions

- None blocking. Primary bring-up is docker-compose; systemd/Ansible is documented
  as the production alternative rather than authored as a second artifact set in
  this pass (can be a follow-up).
