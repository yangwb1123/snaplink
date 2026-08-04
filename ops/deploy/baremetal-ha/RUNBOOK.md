# Bare-Metal HA Runbook — sso-server

Intended operator procedures for the bare-metal HA reference topology of
`sso-server` (OAuth2/OIDC APIs). Retired design rationale is indexed in
[`docs/HISTORY.md`](../../../docs/HISTORY.md); current runtime architecture is
in `docs/deployment.md`.

> **Current status — executable single-host validation model and VM template.**
> The SSO config passes strict schema validation, the distroless image uses its
> native health probe, HAProxy terminates TLS, and the smoke flow is complete.
> Compose still cannot prove multi-host disks, networks, VRRP, or failure-domain
> isolation. Supply host-native units, persistent storage, authenticated backend
> TLS, immutable image digests, real credentials/certificates, and off-site
> backups, then rehearse every procedure before production use.

Artifacts in this directory are templates for VMs; `docker-compose.yml` is
intended to collapse the same topology onto one host for validation. The server
provides APIs only; product browser frontends are separate deployments.

Tiers: 3-node etcd (Patroni DCS + `cluster.Bus` + signing-key registry) ·
Postgres HA (Patroni, 1 leader + 2 sync-capable replicas) · Redis Cluster (3
master + 3 replica, 16384 slots) · shared-state SSO/Billing/Stripe app tier ·
HAProxy + keepalived edge presenting VIP `10.0.0.100`.

Real names used throughout: `etcd1-3`, `pg1-3` (Patroni scope `sso`),
`redis-1a/2a/3a` (initial masters) + `redis-1b/2b/3b` (initial replicas),
`sso1-3`, `billing-a/b`, `stripe-a/b`, `haproxy-a`/`haproxy-b`. Compose maps cleartext redirect
ports `8080`/`8081` and TLS ports `8443`/`8444`; VM edges use `80`/`443`.
Other ports are `8404`/`8405` HAProxy stats, `5432` PG leader, `5433` PG
replicas, `8008` Patroni REST, `6379` Redis, and `2379`/`2380` etcd client/peer;
Billing `8090` and Stripe `8091` remain host-loopback only.

> Two run modes. Commands below show the **compose** form
> (`docker compose exec <svc> ...`). On VMs the same config files run under
> **systemd** units (one service per process); drop the
> `docker compose exec <svc>` prefix and run the inner command on the owning VM. Per-step systemd
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
| snaplink-billing | `billing-a` | `billing-b` | optional worker-only replica |
| Stripe adapter | `stripe-a` | `stripe-b` | optional worker-only replica |
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
- The app tier is stateless only after **every enabled concern** selects shared
  Redis/Postgres/etcd state. Then scale `sso-server` out while observing the
  Postgres connection budget (§5).

VM-mode file placement (per VM): the relevant config file(s) from this directory
plus a systemd unit. Example VM1: `etcd`, `patroni/patroni.yml`,
`redis/redis-cluster.conf`, `sso/config.yaml`, `haproxy/haproxy.cfg`,
`keepalived/keepalived.master.conf`. VM2 uses
`keepalived/keepalived.backup.conf`. Set each `keepalived` `interface` to the
VM's real NIC.

---

## 2. Bring-up order

Strict dependency order: **etcd → Patroni (pg1-3) → Redis (6) + redis-init →
sso1-3 → haproxy-a/b → keepalived → Billing → Stripe adapter.** Wait for the health gate at each step before
starting the next; a later tier started early will fail readiness and self-heal,
but gating keeps the bring-up deterministic.

Compose one-host bring-up uses the same order (compose `depends_on` enforces most
of it). On VMs, start the corresponding systemd unit on each VM and run the same
gate command.

### Step 0 — env

```bash
cd ops/deploy/baremetal-ha
cp .env.example .env        # replace every change-me-* before any non-dev use
set -a; . ./.env; set +a
# SSO_TLS_PEM_PATH must be a combined certificate-chain + private-key PEM.
# SSO_TLS_CA_PATH must verify that chain from the operator host.
```

### Step 1 — etcd (coordination)

```bash
docker compose up -d etcd1 etcd2 etcd3
# GATE: all three healthy
docker compose exec etcd1 etcdctl endpoint health --cluster
```
Expected: three `http://etcdN:2379 is healthy` lines. On systemd, run
`systemctl start etcd` on VM1-3, then the same
`etcdctl endpoint health --cluster`.

### Step 2 — Postgres (Patroni)

```bash
docker compose up -d pg1 pg2 pg3
sleep 25
# GATE: exactly one Leader + at least one Sync Standby, all running
docker compose exec pg1 patronictl -c /etc/patroni/patroni.yml list sso
# One-time app role + db (run against the LEADER):
docker compose exec pg1 \
  sh -c 'PGPASSWORD="$PATRONI_SUPERUSER_PASSWORD" psql -h localhost -U postgres -f -' \
  < postgres/init.sql
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
# GATE: every replica ready (the explicit probe image reaches the distroless app)
for s in sso1 sso2 sso3; do
  docker compose --profile tools run --rm probe --fail --silent --show-error \
    "http://$s:8080/readyz" >/dev/null
  docker compose --profile tools run --rm probe --fail --silent --show-error \
    "http://$s:8080/livez" >/dev/null
done
```
Expected: each `/readyz` + `/livez` returns 200. `/readyz` is the gate HAProxy
uses; it goes 503 when a replica's Redis or Postgres ping fails. On VMs, query
`http://127.0.0.1:8080/{readyz,livez}` from the host namespace.

### Step 5 — HAProxy edge

```bash
# Validate config first (do this before every reload):
docker compose run --rm --no-deps haproxy-a haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
docker compose up -d haproxy-a haproxy-b
sleep 8
# GATE: verified TLS reaches the app; :5432 lands on the writable leader
curl --fail --silent --show-error --cacert "$SSO_TLS_CA_PATH" \
  --resolve "$SSO_PUBLIC_HOST:8443:127.0.0.1" \
  "https://$SSO_PUBLIC_HOST:8443/readyz"
docker compose exec pg1 sh -c \
  'PGPASSWORD="$SSO_DB_PASSWORD" psql "host=haproxy-a port=5432 user=sso dbname=sso" -tAc "select pg_is_in_recovery()"'
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
curl --fail --silent --show-error --cacert "$SSO_TLS_CA_PATH" \
  "$SSO_ISSUER/readyz"                                # -> 200 from any client
```
Expected: `10.0.0.100/24` bound on VM1's NIC; edge reachable via the VIP. End of
bring-up: point the canonical DNS name at the VIP and run
`sh smoke.sh "$SSO_ISSUER"` for the cross-replica check.

### Step 7 — snaplink-billing commerce tier

The PostgreSQL bootstrap creates a separate `billing` role/database. Compose
runs `billing-a` and `billing-b` in their corresponding HAProxy network
namespaces, so the service can enforce `127.0.0.1:8090`; HAProxy alone exposes
commerce and metering paths over TLS.

```bash
docker compose up -d --build billing-a billing-b
status=$(curl --silent --show-error --cacert "$SSO_TLS_CA_PATH" \
  --resolve "$SSO_PUBLIC_HOST:8443:127.0.0.1" --output /dev/null \
  --write-out '%{http_code}' \
  "https://$SSO_PUBLIC_HOST:8443/api/v1/metering/entitlement")
test "$status" = "401"
```

Before machine traffic, replace `billing/source-bindings.json` with reviewed
desired state, register every tenant-derived Audit Governance source, and
provision the Snaplink machine clients/scopes described in
`cmd/snaplink-billing/README.md`. Automatic renewal remains off by default;
enable it only after wallet reconciliation and database restore drills.

Each host-local Prometheus agent must scrape
`http://127.0.0.1:8090/metrics`; do not add `/metrics` to the public HAProxy
ACL. Load the `snaplink-billing-renewals` rules from
`ops/deploy/grafana/alerts.yaml`. Before enabling renewal, verify both hosts
emit `snaplink_billing_renewal_enabled 1` and that due/oldest-age converge.
Cycle errors warn immediately but do not withdraw traffic. If local `/readyz`
reports `subscription_renewals: error`, the 15-minute tolerance is exhausted:
restore PostgreSQL/worker progress and keep the service running so leases can
drain; do not disable renewal merely to make the probe green.

Provision a distinct `snaplink-billing-quota-relay` OAuth secret with exactly
`tenant-quota:projection:write` and resource/audience `snaplink-sso-quota`.
`sso/config.yaml` contains the matching `tenant-example` source; derive and add
one record per tenant with
`snaplink-billing audit-source-id --prefix snaplink-billing-quota --tenant <id>`.
Verify `tenant_quota_projection: ok` on both Billing replicas before enabling
commercial access. Each replica uses its own quota lease owner, so failover can
reclaim an abandoned claim without double-consuming the independent outbox.

Provision `snaplink-billing-retention-projector` with a third, distinct secret,
exact scopes `audit:platform:cross_tenant audit:policy:write`, and resource
`audit-governance`. The same readiness cursor is acknowledged only after SSO
quota and the Audit Governance `standard`-class retention policy both succeed;
never reuse the event-ingest, quota, Stripe, or provisioner credential.

`billing/audit-runtime.json` controls only the precompiled relay and is polled
every five seconds. Change it atomically on both hosts with one strictly higher
revision; verify both local `/readyz` responses before the next change. Relay
disable leaves facts in the durable outbox. Endpoint, OAuth secret, catalog and
source-binding changes still require a controlled restart.

---

### Step 8 — Stripe payment adapter

The PostgreSQL bootstrap creates the isolated `stripe_adapter` role/database.
Compose and the host-native units run one adapter beside each edge. Both listen
only on `127.0.0.1:8091`; HAProxy routes
`/api/v1/checkout/sessions` and `/webhooks/stripe` to its local replica and
checks `/readyz` before admitting traffic.

Before startup, replace `stripe-adapter/bindings.json`, register every checkout
client for only `billing:checkout:create` and the adapter audience, register
each Billing client for only `billing:payment:order:read billing:payment:write`
and the Billing resource, and create the matching Billing source binding
`payment:stripe`. Keep the Billing secret distinct from SSO admin, quota and
Audit Governance credentials. Explicitly review `STRIPE_LIVE_MODE`,
`STRIPE_ACCOUNT`, both pinned API versions and the key prefix as one change.

```bash
docker compose up -d --build stripe-a stripe-b
status=$(curl --silent --show-error --cacert "$SSO_TLS_CA_PATH" \
  --resolve "$SSO_PUBLIC_HOST:8443:127.0.0.1" --output /dev/null \
  --write-out '%{http_code}' \
  "https://$SSO_PUBLIC_HOST:8443/api/v1/checkout/sessions")
test "$status" = "401"
docker compose --profile tools run --rm probe --fail --silent --show-error \
  http://haproxy-a:8404/ >/dev/null
```

On VMs install `snaplink-stripe-adapter.service` on VM1 and VM2 with separate
mode-0600 environment files and a mode-0400/0440 binding file. A generated
claim owner is unique per process; do not add a shared manual owner. The shared
inbox uses expiring, generation-fenced claims, so both instances are
active-active and an abandoned delivery is reclaimed after the claim lease.

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

The same recovery target must contain the Billing ledger and the adapter's
`stripe_checkout_mappings`, `stripe_event_inbox`, `stripe_event_receipts`, and
schema-version row. Keep both adapters stopped while reconciling. Compare
receipts and effect keys with retained Stripe events and Billing payment facts;
never delete receipts to make a webhook replay look new. Leave quarantined rows
quarantined until an operator proves the tenant/order/provider mapping and
amount, then replay through the reviewed adapter procedure. Wait at least one
`SNAPLINK_STRIPE_CLAIM_LEASE` before starting fresh replicas so restored claims
expire naturally. Resume webhook ingestion first, observe pending/quarantined
metrics, and enable checkout only after Billing and adapter reconciliation
produce no unresolved financial difference.

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
After restore, restart Patroni so it re-reads the DCS. The app must resubscribe
to the invalidation Bus, flush affected caches, and re-seed revocation deny
sets before clearing degraded state. A failed re-seed keeps `/readyz` red; do
not treat etcd recovery as transparently fail-open.

---

## 5. Capacity & sizing

### 5.1 sso-server replicas vs auth RPS / HAProxy maxconn

Shared-state tier — once all enabled state is externalized, size by
`peak_auth_RPS ÷ per_replica_throughput`, then add one replica for N+1
headroom. HAProxy `maxconn 20000` (global) is the edge ceiling.

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
max_connections >= sum(each SSO/Billing/Stripe replica's max_open_conns) + patroni_overhead + admin_headroom
```
- `postgres.max_open_conns = 20` per SSO, Billing, or Stripe adapter replica.
- `patroni_overhead` ~= a handful (Patroni health/replication probes).
- `admin_headroom` >= 10 (psql, backups, monitoring).
- Patroni sets `max_connections: 200` (`patroni.yml`). Budget:

| sso replicas | app conns (×20) | + Patroni/admin (~15) | fits in 200? |
|---|---|---|---|
| 3 SSO + 2 Billing + 2 Stripe | 140 | 155 | yes |
| 6 SSO + 2 Billing + 2 Stripe | 200 | 215 | no — raise the limit or add a pooler first |
| 9 SSO + 2 Billing + 2 Stripe | 260 | 275 | no — size and rehearse before rollout |

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
  **re-sets** the forwarded headers (in `haproxy/haproxy.cfg`, frontend
  `sso_https`): forwarded, mesh identity, region, and header-mTLS assertions are
  deleted before canonical `X-Forwarded-*` values are set. `sso-server` trusts
  only the first allowed hop through `security.trusted_proxies`. Verify a
  client-supplied header is overwritten, not honored; otherwise geo, rate-limit
  keying, base URL, region, or mTLS identity can be spoofed.
- [ ] **TLS at the edge.** Supply `SSO_TLS_PEM_PATH` as a restricted combined
  certificate-chain/private-key PEM, verify `haproxy -c`, confirm port 80 returns
  a 308 redirect, and run the smoke test without
  `SNAPLINK_SMOKE_INSECURE_TLS=true`. The checked-in edge enforces TLS 1.2+ and
  HSTS; certificate issuance and rotation remain operator-owned.
- [ ] **TLS on backend links.** Set `redis.tls.enabled: true` + `ca_file` in
  `sso/config.yaml` (currently `false` for the one-host demo); enable
  `sslmode=verify-full` in the Postgres DSN (demo uses `disable`); enable TLS +
  client cert on etcd client endpoints.
- [ ] **Secrets via env only, never committed.** `SSO_REDIS__PASSWORD`, the
  complete `SSO_POSTGRES__DSN`, billing/audit/Stripe credentials, and etcd creds.
  `.env.example` ships
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
