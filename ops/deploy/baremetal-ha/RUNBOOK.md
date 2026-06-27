# Bare-Metal HA Runbook — sso-server

Operator procedures for the production HA deployment of `sso-server` (OAuth2 /
OIDC). Topology and rationale: `docs/superpowers/specs/2026-06-26-baremetal-ha-data-layer-design.md`.
Artifacts in this directory drop directly onto VMs; the `docker-compose.yml` here
stands up the same topology on one host for CI / dev / demo.

Tiers: 3-node etcd (Patroni DCS + `cluster.Bus` + signing-key registry) ·
Postgres HA (Patroni, 1 leader + 2 sync-capable replicas) · Redis Cluster (3
master + 3 replica, 16384 slots) · stateless `sso-server` app tier · HAProxy +
keepalived edge presenting VIP `10.0.0.100`.

Real names used throughout: `etcd1-3`, `pg1-3` (Patroni scope `sso`),
`redis-1a/2a/3a` (initial masters) + `redis-1b/2b/3b` (initial replicas),
`sso1-3`, `haproxy-a`/`haproxy-b`. Real ports: `8080` edge HTTP (compose maps
host `8080`→haproxy-a `:80`, `8081`→haproxy-b `:80`), `8404`/`8405` HAProxy
stats, `5432` PG leader, `5433` PG replicas, `8008` Patroni REST, `6379` Redis,
`2379`/`2380` etcd client/peer.

> Two run modes. Commands below show the **compose** form
> (`docker compose exec <svc> ...`). On VMs the same config files run under
> **systemd** units (one service per process); drop the `docker compose exec
> <svc>` prefix and run the inner command on the owning VM. Per-step systemd
> notes are inline.

---

## 1. Container → VM mapping

Reference cluster: **3 VMs**, each co-locating one member of every quorum tier so
etcd / Patroni / Redis all get their 3 members and survive any single VM loss.

| Service | VM1 | VM2 | VM3 |
|---|---|---|---|
| etcd | `etcd1` | `etcd2` | `etcd3` |
| Postgres (Patroni) | `pg1` | `pg2` | `pg3` |
| Redis master | `redis-1a` | `redis-2a` | `redis-3a` |
| Redis replica | `redis-2b` | `redis-3b` | `redis-1b` |
| sso-server | `sso1` | `sso2` | `sso3` |
| Edge | `haproxy-a` + keepalived **MASTER** | `haproxy-b` + keepalived **BACKUP** | — |

Rules:

- **Redis anti-affinity (HARD):** a Redis master is **never** co-located on the
  same VM as its own replica. The layout above places each `-b` replica on a
  different VM from the master it serves (VM1 `redis-2b` serves `redis-2a` on
  VM2; VM2 `redis-3b` serves `redis-3a` on VM3; VM3 `redis-1b` serves
  `redis-1a` on VM1). `redis-cli --cluster create ... --cluster-replicas 1` with
  the masters-first node order assigns each replica to a master on a different
  node when topology allows, but you **must verify** the actual assignment and
  repair it if any pair landed together:

  ```bash
  # Show every shard: master node-id + endpoint, then its replica(s).
  docker compose exec redis-1a redis-cli -a "$SSO_REDIS_PASSWORD" cluster shards
  # If a replica shares a VM with its master, re-point it (run on the replica):
  #   redis-cli -a "$SSO_REDIS_PASSWORD" -h <replica> cluster replicate <other-vm-master-node-id>
  ```

- **Patroni leader floats:** the leader may run on any VM; etcd elects it. Do not
  pin it. `tags.nofailover` stays `false` on all three.
- **Edge / VIP:** `haproxy-a` + keepalived `state MASTER` (priority 150) on VM1;
  `haproxy-b` + keepalived `state BACKUP` (priority 100) on VM2. The VIP
  `10.0.0.100/24` (`virtual_router_id 51`) floats between VM1 and VM2 only. VM3
  runs no edge.
- App tier is stateless: scale `sso-server` out to more VMs freely (mind the
  Postgres connection budget, §5).

VM-mode file placement (per VM): the relevant config file(s) from this directory
plus a systemd unit. Example VM1: `etcd`, `patroni/patroni.yml`,
`redis/redis-cluster.conf`, `sso/config.yaml`, `haproxy/haproxy.cfg`,
`keepalived/keepalived.master.conf`. VM2 uses
`keepalived/keepalived.backup.conf`. Set each `keepalived` `interface` to the
VM's real NIC.

---

## 2. Bring-up order

Strict dependency order: **etcd → Patroni (pg1-3) → Redis (6) + redis-init →
sso1-3 → haproxy-a/b → keepalived.** Wait for the health gate at each step before
starting the next; a later tier started early will fail readiness and self-heal,
but gating keeps the bring-up deterministic.

Compose one-host bring-up uses the same order (compose `depends_on` enforces most
of it). On VMs, start the corresponding systemd unit on each VM and run the same
gate command.

### Step 0 — env

```bash
cd ops/deploy/baremetal-ha
cp .env.example .env        # replace every change-me-* before any non-dev use
```

### Step 1 — etcd (coordination)

```bash
docker compose up -d etcd1 etcd2 etcd3
# GATE: all three healthy
docker compose exec etcd1 etcdctl endpoint health --cluster
```
Expected: three `http://etcdN:2379 is healthy` lines. (systemd: `systemctl start
etcd` on VM1-3, then the same `etcdctl endpoint health --cluster`.)

### Step 2 — Postgres (Patroni)

```bash
docker compose up -d pg1 pg2 pg3
sleep 25
# GATE: exactly one Leader + at least one Sync Standby, all running
docker compose exec pg1 patronictl -c /etc/patroni/patroni.yml list sso
# One-time app role + db (run against the LEADER):
docker compose exec -e PGPASSWORD="$POSTGRES_SUPER_PASSWORD" pg1 \
  sh -c 'psql -h localhost -U postgres -f -' < postgres/init.sql
```
Expected: 3 members; one `Leader`; >=1 `Sync Standby`; state `running`. The
app's migrate runner builds the schema on first `sso-server` boot (advisory-lock,
safe under concurrent replica boots). (systemd: `systemctl start patroni` per DB
VM; same `patronictl list sso`.)

### Step 3 — Redis Cluster

```bash
docker compose up -d redis-1a redis-2a redis-3a redis-1b redis-2b redis-3b
docker compose up redis-init          # one-shot, idempotent cluster create
# GATE: cluster_state:ok and all 16384 slots assigned
docker compose exec redis-1a redis-cli -a "$SSO_REDIS_PASSWORD" cluster info
```
Expected: `cluster_state:ok`, `cluster_slots_assigned:16384`,
`cluster_known_nodes:6`. Then verify anti-affinity per §1 (`cluster shards`).
(systemd: `systemctl start redis-cluster` per node; run `cluster-create.sh` once
from any VM — it exits cleanly if already formed.)

### Step 4 — sso-server app tier

```bash
docker compose up -d --build sso1 sso2 sso3
sleep 20
# GATE: every replica ready (proves Redis + Postgres + etcd reachable from each)
for s in sso1 sso2 sso3; do
  echo -n "$s readyz: "; docker compose exec "$s" wget -qO- http://localhost:8080/readyz; echo
  echo -n "$s livez:  "; docker compose exec "$s" wget -qO- http://localhost:8080/livez;  echo
done
```
Expected: each `/readyz` + `/livez` returns 200. `/readyz` is the gate HAProxy
uses; it goes 503 when a replica's Redis or Postgres ping fails. (systemd:
`systemctl start sso-server` per app VM; same `wget` gate.)

### Step 5 — HAProxy edge

```bash
# Validate config first (do this before every reload):
docker compose run --rm --no-deps haproxy-a haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
docker compose up -d haproxy-a haproxy-b
sleep 8
# GATE: app reachable through the edge; :5432 lands on the writable leader
curl -ks https://localhost:8080/readyz                       # -> 200
docker compose exec -e PGPASSWORD="$SSO_DB_PASSWORD" haproxy-a sh -c \
  'apk add --no-cache postgresql-client >/dev/null 2>&1; \
   psql "host=localhost port=5432 user=sso dbname=sso" -tAc "select pg_is_in_recovery()"'
```
Expected: `haproxy -c` prints `Configuration file is valid`; `/readyz` 200; the
`:5432` psql returns `f` (leader, not in recovery). Stats UI: `http://VM1:8404/`.
(systemd: `systemctl start haproxy` on VM1 + VM2; reload only after `haproxy -c`
passes.)

### Step 6 — keepalived (VIP) — VMs only

Single-host bridge compose has no L2 multicast / `NET_ADMIN`, so VRRP is a
VM-only step. On VM1 (master) and VM2 (backup):

```bash
# Syntax check (either VM):
keepalived -t -f /etc/keepalived/keepalived.conf       # master.conf on VM1, backup.conf on VM2
systemctl start keepalived
# GATE: VIP is up on the MASTER and answers
ip addr show eth0 | grep 10.0.0.100                    # present on VM1
curl -ks https://10.0.0.100/readyz                     # -> 200 from any client
```
Expected: `10.0.0.100/24` bound on VM1's NIC; edge reachable via the VIP. End of
bring-up: run `sh smoke.sh https://10.0.0.100` for the cross-replica check.

---

## 3. Failover drills

Each drill: **action / expected detection / expected recovery / verify
continuity.** Run them in a staging copy before relying on the numbers.

### 3.1 Postgres leader loss

- **Action:** `docker compose kill pg1` (or `systemctl stop patroni` on the
  leader VM).
- **Detection:** Patroni loses its lease in etcd; the synchronous standby is
  promoted.
- **Recovery (<10s):** new Leader visible in `patronictl`; HAProxy's
  `option httpchk GET /leader` (port 8008) repoints `:5432` to it within
  `inter 3s × fall 3`. `synchronous_mode: true` guarantees no committed write was
  lost.
- **Verify:**
  ```bash
  docker compose exec pg2 patronictl -c /etc/patroni/patroni.yml list sso   # new Leader, old node now replica/stopped
  # writes resume through the edge :5432 (returns f = writable leader):
  docker compose exec -e PGPASSWORD="$SSO_DB_PASSWORD" haproxy-a sh -c \
    'psql "host=localhost port=5432 user=sso dbname=sso" -tAc "select pg_is_in_recovery()"'
  ```
  In-flight writes get a retriable error during the blip; the app's
  `SERIALIZABLE + 40001` retry on the RBAC read-modify-write paths rides through
  the failover-induced serialization without surfacing a 500.

### 3.2 HAProxy MASTER loss (VIP float — VM drill)

- **Action:** on VM1, `systemctl stop haproxy` (or kill the process).
- **Detection:** keepalived `vrrp_script chk_haproxy` (`killall -0 haproxy`,
  `interval 2`, `fall 2`) fails on VM1; VM1 releases the VIP.
- **Recovery (~1-3s):** VM2 (BACKUP, priority 100) takes `10.0.0.100`. This is
  the IP漂移.
- **Verify:**
  ```bash
  ip addr show eth0 | grep 10.0.0.100      # now bound on VM2
  curl -ks https://10.0.0.100/readyz       # still 200, now served via haproxy-b
  ```
  When VM1's HAProxy recovers, keepalived (priority 150) reclaims the VIP.

### 3.3 Redis master loss

- **Action:** `docker compose kill redis-1a` (or `systemctl stop redis-cluster`
  on that node).
- **Detection:** Redis Cluster gossip marks `redis-1a` failed after
  `cluster-node-timeout 5000`.
- **Recovery (~1-2s after detection):** its replica (on a different VM per §1) is
  promoted to master for that shard's slots.
- **Verify:**
  ```bash
  docker compose exec redis-2a redis-cli -a "$SSO_REDIS_PASSWORD" cluster shards
  # the promoted replica now shows role master for redis-1a's slot range
  docker compose exec redis-2a redis-cli -a "$SSO_REDIS_PASSWORD" cluster info | grep cluster_state
  ```
  Token / session ops on that shard's keys resume after a brief client retry
  (the cluster-aware client follows the failover via MOVED). When `redis-1a`
  returns it rejoins as a replica of the new master.

---

## 4. Backup & restore

### 4.1 Postgres — base backup + WAL archiving + PITR

**WAL archiving** (set once in `patroni/patroni.yml` `postgresql.parameters`,
then `patronictl edit-config sso`):

```yaml
archive_mode: "on"
archive_command: "test ! -f /backup/wal/%f && cp %p /backup/wal/%f"
```

**Base backup** (against any running node; use the leader for freshness):

```bash
docker compose exec -e PGPASSWORD="$POSTGRES_SUPER_PASSWORD" pg1 \
  pg_basebackup -h localhost -U replicator -D /backup/base/$(date +%F) -Ft -z -Xs -P
```

**Point-in-time restore** (new/empty data dir): unpack the base backup, then
recover to a target time, replaying archived WAL:

```bash
# on the restore target, in the empty PGDATA:
#   tar xzf /backup/base/<date>/base.tar.gz -C $PGDATA
echo "restore_command = 'cp /backup/wal/%f %p'"            >> $PGDATA/postgresql.auto.conf
echo "recovery_target_time = '2026-06-26 12:00:00+00'"     >> $PGDATA/postgresql.auto.conf
touch $PGDATA/recovery.signal
# start Postgres standalone to reach the target, promote, then re-attach to Patroni:
#   patronictl -c /etc/patroni/patroni.yml reinit sso <node>   # rebuild the other replicas from the restored leader
```
After PITR, rebuild the standbys with `patronictl reinit sso <node>` so all three
share the restored timeline.

### 4.2 Redis — AOF backup / restore

AOF is on (`appendonly yes`, `appendfsync everysec`). Back up the AOF set per
node:

```bash
docker compose exec redis-1a redis-cli -a "$SSO_REDIS_PASSWORD" BGREWRITEAOF      # compact first
# copy the append dir out (path depends on dir/appenddirname; default /data):
docker cp ssoha-redis-1a-1:/data/appendonlydir /backup/redis/redis-1a/$(date +%F)
```

Restore a node: stop it, place the backed-up `appendonlydir` into its data dir,
start it. A single replaced master re-syncs from the cluster on rejoin; for a
**full-cluster** cold restore, restore every node's AOF, start all six, and the
cluster reloads slots from `nodes.conf` + AOF. `noeviction` guarantees the AOF
was never truncated by eviction.

### 4.3 etcd — snapshot save / restore

```bash
# Save (any healthy member):
docker compose exec etcd1 etcdctl snapshot save /backup/etcd-$(date +%F).db
docker compose exec etcd1 etcdctl snapshot status /backup/etcd-$(date +%F).db -w table
```

Restore (disaster: lost quorum, rebuild from snapshot on all three, then restart
the cluster fresh):

```bash
# on each node, restore into a new data dir with matching peer URLs:
etcdctl snapshot restore /backup/etcd-<date>.db \
  --name etcd1 \
  --initial-cluster etcd1=http://etcd1:2380,etcd2=http://etcd2:2380,etcd3=http://etcd3:2380 \
  --initial-cluster-token ssoha-etcd \
  --initial-advertise-peer-urls http://etcd1:2380 \
  --data-dir /etcd-data-restored
# repeat per node with its own --name / --initial-advertise-peer-urls, then start all three.
```
After restore, restart Patroni so it re-reads the DCS; the app's `cluster.Bus`
reconnects automatically (fail-open, never blocked the request path while etcd
was down).

---

## 5. Capacity & sizing

### 5.1 sso-server replicas vs auth RPS / HAProxy maxconn

Stateless tier — size by `peak_auth_RPS ÷ per_replica_throughput`, then add one
replica for N+1 headroom. HAProxy `maxconn 20000` (global) is the edge ceiling.

| Peak auth RPS | sso replicas | HAProxy global `maxconn` | Notes |
|---|---|---|---|
| <= 500 | 3 (one per VM) | 20000 | reference baseline |
| ~1000 | 4-5 | 20000 | add app VMs; watch PG conn budget (§5.3) |
| ~2000-3000 | 6-9 | 20000-40000 | upper end of "standard production HA" scope |

Per-replica throughput is workload-specific (token issue vs introspect vs
refresh); measure on staging. Keep one replica more than the RPS math requires so
a single replica loss (drained by `/readyz`) does not saturate the rest.

### 5.2 Redis memory

```
maxmemory_per_node = peak_concurrent(sessions + tokens) * avg_record_bytes * safety_factor
```
- `safety_factor` >= 1.5 (fragmentation + headroom).
- **AOF disk headroom:** provision >= 2-3x the live dataset per node for the AOF
  file plus a `BGREWRITEAOF` rewrite happening alongside the live append.
- **`maxmemory-policy noeviction` is mandatory** (already set in
  `redis-cluster.conf`): tokens/sessions must never be evicted. With noeviction a
  node at `maxmemory` returns OOM on writes rather than silently dropping a valid
  token — size memory so this never happens; alert at ~70% used.
- Set `maxmemory` per node = `maxmemory_per_node` ÷ 3 (3 masters share the
  keyspace), with the same value on replicas.

### 5.3 Postgres max_connections

```
max_connections >= sum(sso_replicas * postgres.max_open_conns) + patroni_overhead + admin_headroom
```
- `postgres.max_open_conns = 20` per replica (`sso/config.yaml`).
- `patroni_overhead` ~= a handful (Patroni health/replication probes).
- `admin_headroom` >= 10 (psql, backups, monitoring).
- Patroni sets `max_connections: 200` (`patroni.yml`). Budget:

| sso replicas | app conns (×20) | + Patroni/admin (~15) | fits in 200? |
|---|---|---|---|
| 3 | 60 | 75 | yes (large margin) |
| 6 | 120 | 135 | yes |
| 9 | 180 | 195 | at the edge — raise `max_connections` before scaling past 9 |

To scale past ~9 app replicas, raise `max_connections` via
`patronictl edit-config sso` (rolling restart) or front Postgres with a pooler.
Sync-standby count is a durability/latency tradeoff: >=1 sync standby is required
(no lost commits); more sync standbys raise commit latency.

### 5.4 etcd

Metadata-only (Patroni DCS + bus keys + signing-key registry). Default sizing is
ample; keep the data dir on fast disk and the default 8 GiB quota. No tuning
needed at this scale.

---

## 6. Security Hardening checklist

- [ ] **XFF trusted-edge contract.** Confirm HAProxy **strips inbound** and
  **re-sets** the forwarded headers (in `haproxy/haproxy.cfg` `frontend
  sso_http`): `http-request del-header X-Forwarded-For` / `del-header
  X-Forwarded-Proto`, then `set-header X-Forwarded-For %[src]` / `set-header
  X-Forwarded-Proto https`. `sso-server` trusts only the first hop
  (`trusted_proxies: [10.0.0.0/8, 172.16.0.0/12]` in `sso/config.yaml`). Verify a
  client-supplied `X-Forwarded-For` is overwritten, not honored — otherwise geo /
  ratelimit IP-keying / base-URL can be spoofed (AGENTS.md §3). This is a hard
  invariant.
- [ ] **TLS at the edge.** HAProxy terminates TLS and forwards
  `X-Forwarded-Proto: https`. Bind a real cert on `:443` (passthrough is an
  alternative). Redirect `:80`→`:443`.
- [ ] **TLS on backend links.** Set `redis.tls.enabled: true` + `ca_file` in
  `sso/config.yaml` (currently `false` for the one-host demo); enable
  `sslmode=verify-full` in the Postgres DSN (demo uses `prefer`); enable TLS +
  client cert on etcd client endpoints.
- [ ] **Secrets via env only, never committed.** `SSO_REDIS__PASSWORD`,
  `SSO_DB_PASSWORD` (interpolated into the DSN), etcd creds. `.env.example` ships
  `change-me-*` placeholders only; the real `.env` / systemd `EnvironmentFile`
  stays out of git. `redis-cluster.conf` carries no password (passed via
  `--requirepass` on the command line).
- [ ] **Redis `noeviction` set** (`maxmemory-policy noeviction`) — verify on every
  node: `redis-cli -a "$SSO_REDIS_PASSWORD" config get maxmemory-policy`.
- [ ] **Probes outside ratelimit.** `/metrics`, `/livez`, `/readyz` are matched
  before any auth/ratelimit ACL (mirrors the app middleware order). Confirm they
  answer through the edge without auth and are not rate-limited.
- [ ] **etcd client auth enabled.** Turn on auth in production
  (`etcdctl user add root`, `etcdctl auth enable`) using `ETCD_ROOT_PASSWORD`;
  give Patroni and `sso-server` scoped users. Restrict `2379`/`2380` to the
  cluster subnet.
- [ ] **Network exposure.** Redis `protected-mode no` is safe ONLY on a private
  cluster subnet — never expose `6379`/`5432`/`2379`/`8008` beyond it. Only the
  VIP `:443` (and `:5432` if external read-write clients exist) faces outward.

---

## 7. Deferred items + reversal triggers

YAGNI by design (spec §9). Do **not** pre-build these. Each has a concrete
reversal trigger and action.

| Deferred | Reversal Trigger | Action when triggered |
|---|---|---|
| **App-level 分库分表 (sharding)** | Sustained multi-TB durable data, or write throughput a single Patroni leader cannot absorb | Switch `postgres.dialect` to CockroachDB (**already supported** by the durable backend) for transparent distributed sharding — never hand-roll app-level sharding. The hot keyspace is already sharded across Redis Cluster slots. |
| **Message queue (NATS / Kafka)** | Async fan-out becomes the bottleneck: SSF push to thousands of receivers, an external audit / data pipeline, or audit write volume saturating Postgres | Introduce NATS or Kafka for that **specific** async path only; keep the etcd-backed `cluster.Bus` for cross-replica invalidation (revocation, signing-key rotation, client/policy change). |
| **Multi-DC active-active** | Geographic DR or data-residency requirement | Out of scope here. Region-aware routing + per-region clusters is a separate design. |
