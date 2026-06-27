# Bare-Metal HA Reference Deployment

A reproducible, full-topology high-availability deployment of the `sso-server`
OAuth2/OIDC server: an HAProxy + keepalived edge in front of 3 stateless `sso`
replicas, backed by a 6-node Redis Cluster (hot store), a Patroni-managed
Postgres HA cluster (durable store), and a 3-node etcd cluster (coordination).
`docker-compose.yml` collapses the entire topology onto one host for CI / dev /
demo; the **same config files** (`haproxy/haproxy.cfg`, `patroni/patroni.yml`,
`redis/redis-cluster.conf`, `keepalived/*`, `sso/config.yaml`) drop directly
onto real VMs — see `RUNBOOK.md` for the container→VM mapping. **Explicit YAGNI:**
no application-level sharding (分库分表) and no message queue — transparent Redis
Cluster slot-sharding plus the etcd-backed `cluster.Bus` already cover the hot
keyspace and cross-replica invalidation at this scale (≤ low-millions of users,
≤ a few-thousand auth RPS). See the design spec at
`docs/superpowers/specs/2026-06-26-baremetal-ha-data-layer-design.md`.

## Topology

```
            keepalived VRRP floating VIP   (the IP漂移)
            ┌───────────────┴────────────────┐
     HAProxy-A (MASTER)               HAProxy-B (BACKUP)
            └───────────────┬────────────────┘
              L7 round-robin, health-check GET /readyz, XFF re-set
            ┌───────────────┼────────────────┐
        sso1            sso2            sso3            (stateless app tier)
            └───────────────┼────────────────┘
   ┌────────────────────────┼─────────────────────────┐
 Redis Cluster          Postgres HA                 etcd cluster (3)
 3 master + 3 replica    Patroni: 1 leader + 2 repl   • Patroni DCS
 16384 slots             via HAProxy :5432→leader     • sso cluster.Bus
 cluster-aware client    :5433→replicas (read offload) • signing-key registry
 NO load balancer        sync replication
```

## Quick start (single host)

Requires Docker with Compose v2. The `sso` image is built from the repo
`Dockerfile` (build context is the repo root, three levels up).

```sh
cp .env.example .env
# Edit .env: replace every change-me-* secret (Postgres, Redis, etcd). The VIP
# value is informational on single-host compose; it is the live VRRP IP on VMs.

docker compose up -d --build
# Wait for health to settle (etcd → Patroni Postgres → Redis Cluster bootstrap →
# sso replicas → edge). Watch with:
docker compose ps

# End-to-end smoke through the edge (discovery + /readyz green across replicas):
sh smoke.sh https://localhost:8080
```

Published host ports (from `haproxy-a`):

| Host port | Maps to | Purpose |
|---|---|---|
| `8080` | edge HTTP frontend (`https`) | OAuth2/OIDC traffic through HAProxy |
| `8404` | HAProxy stats | live backend health / round-robin view |
| `5432` | Postgres leader | all writes + read-after-write paths |
| `5433` | Postgres replicas | optional read-only offload (off by default) |

(`haproxy-b` mirrors the edge on host ports `8081`/`8405` for the failover drill.)

## What each tier is

| Tier | Service names | Purpose |
|---|---|---|
| Coordination | `etcd1`, `etcd2`, `etcd3` | 3-node etcd: Patroni DCS + sso `cluster.Bus` (cross-replica invalidation) + leaderless signing-key registry |
| Durable store | `pg1`, `pg2`, `pg3` (+ `redis-init`-style bootstrap) | Patroni-managed Postgres HA — 1 sync leader + 2 replicas, etcd-elected, sync replication |
| Hot store | `redis-1a`,`redis-1b`,`redis-2a`,`redis-2b`,`redis-3a`,`redis-3b` (+ `redis-init`) | 6-node Redis Cluster (3 master + 3 replica, 16384 slots); cluster-aware client, no LB in front |
| App | `sso1`, `sso2`, `sso3` | stateless `sso-server` replicas; scale out freely; drained via `/readyz` |
| Edge | `haproxy-a`, `haproxy-b` + keepalived | L7 round-robin over the app tier; keepalived/VRRP floats one VIP across the two HAProxy nodes |

## Container → VM mapping

Each of the 3 reference VMs co-locates one slice of every tier (1 etcd + 1
Patroni Postgres + 2 Redis + 1 `sso`, with HAProxy + keepalived on two of them)
so the quorum services get their 3 members. See `RUNBOOK.md` for the full 3-VM
mapping, anti-affinity rules, failover drills, backup/restore, capacity sizing,
and the security hardening checklist.

## Notes

- **keepalived / VRRP is a VM-only drill.** The single-host bridge network has no
  L2 multicast, so the VIP failover is not exercised by compose here; the
  `keepalived/*.conf` files are provided for the real-VM deployment. On one host,
  `haproxy-a` is the live edge and `haproxy-b` stands by.
- **Secrets come only from env, never committed.** Redis / Postgres / etcd
  passwords are injected into `sso-server` via env overrides
  (`SSO_REDIS__PASSWORD`, `SSO_DB_PASSWORD`, …) sourced from `.env`. `.env.example`
  ships only `change-me-*` placeholders — replace every one before any non-dev use.
