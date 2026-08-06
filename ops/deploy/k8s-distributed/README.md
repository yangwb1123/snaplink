# Distributed (Tier B) SSO deployment on Kubernetes

Verified working topology for a single-node k8s cluster (no registry: images
are built locally and imported into the node's containerd with
`docker save | sudo ctr -n k8s.io images import -`). It realizes the
distributed model documented in
[`docs/deployment.md`](../../../docs/deployment.md) §6 (Tier B): N `sso-server`
replicas over a shared Redis Cluster hot tier, a shared Postgres durable tier,
and etcd coordination (invalidation bus + leaderless signing-key registry).

```
                     TLS edge / gateway (OpenResty, separate manifest)
                                    |
              sso-server × N  (replica_id = pod name, downward API)
                                    |
        +--------------+------------+------------+
        |              |                         |
   etcd (bus +   Redis Cluster 3+ master   Postgres (durable:
   signing-key   hot stores, noeviction)    users/clients/audit)
   registry)           |
        +--------------+
```

## Why this topology

- Every `sso-server` replica mints tokens with its OWN in-process Ed25519 key.
  Without a shared registry, a token minted by replica A fails verification on
  replica B (`401 invalid_token`) — observed live as "random logout" in the
  admin console. `keys.signing_key_registry.backend: etcd` makes every replica
  publish its public key and adopt peers' keys verify-only, so JWKS and
  validation serve the union while no private key is ever shared.
- Single-use stores (auth codes, refresh families, PAR, device codes), the JTI
  replay store, MFA challenges and the rate limiter must be shared: Redis
  Cluster (`noeviction` — evicting a live refresh-family ledger or jti key is
  a security regression, not a cache miss).
- Revocation must survive any replica: `keys.signing.revocation_backend: redis`
  (shared deny-set, re-seeded at boot) + `cluster.cross_replica_revocation`
  (live propagation over the bus).
- `server.pairwise_subjects.backend: postgres` keeps `sub` pseudonyms stable
  across replicas.

## Components

| File | What it deploys |
|---|---|
| `etcd.yaml` | Single etcd node for coordination (see "HA notes" for 3-node) |
| `redis-cluster.yaml` | Redis Cluster StatefulSet (3 masters, `noeviction`) |
| `config.yaml` | Tier B `sso-server` config (secrets redacted; the live copy lives in the k8s Secret `sso-config-sensitive`) |

`sso-server` deployment deltas vs a single-node setup:

- `replicas: 3`
- env `SSO_KEYS__SIGNING_KEY_REGISTRY__REPLICA_ID` from `fieldRef: metadata.name`
  (unique per pod)
- config secret switches: `redis.mode: cluster` (3 addrs, `db: 0`),
  `cluster.bus.backend: etcd`, `keys.signing_key_registry.backend: etcd`,
  `keys.signing.revocation_backend: redis`,
  `server.topology.mode: multi`, `server.pairwise_subjects.backend: postgres`
- remove any `SSO_CLUSTER__BUS__BACKEND=redis` env override (the config file
  now owns the bus wiring)

## Deploy

```bash
kubectl apply -f etcd.yaml -f redis-cluster.yaml
kubectl -n sv-sso rollout status deployment/etcd
kubectl -n sv-sso rollout status statefulset/redis-cluster

# Form the Redis Cluster (one-time; run from any redis pod):
kubectl -n sv-sso exec redis-cluster-0 -- redis-cli --cluster create \
  redis-cluster-0.redis-cluster:6379 \
  redis-cluster-1.redis-cluster:6379 \
  redis-cluster-2.redis-cluster:6379 \
  --cluster-replicas 0 --cluster-yes
# expect: cluster_state:ok on all three nodes

# Load the Tier B config into the Secret (live secrets, not the redacted copy):
kubectl -n sv-sso create secret generic sso-config-sensitive \
  --from-file=config.yaml=./config.yaml --dry-run=client -o yaml | kubectl apply -f -

# Update the sso-server Deployment: replica_id env (fieldRef metadata.name),
# remove the redis bus env overrides, then:
kubectl -n sv-sso scale deployment sso-server --replicas=3
kubectl -n sv-sso rollout status deployment/sso-server
```

## Verify (run every check against every replica's pod IP)

```bash
# 1. JWKS union: every replica advertises ALL kids (registry adoption)
for ip in <pod-ips>; do curl -s http://$ip:8080/.well-known/jwks.json; done

# 2. Cross-replica validation: a token minted by one replica must validate
#    identically on every other replica (no 401 flapping)
curl -s -H "Authorization: Bearer $TOKEN" http://$ip:8080/api/v1/admin/endpoints

# 3. Revocation propagation: revoke once, expect active:false on ALL replicas
curl -s -X POST http://$ip:8080/token/introspect -H 'Content-Type: application/json' \
  -d '{"token":"'$TOKEN'","client_id":"<confidential-client>","client_secret":"<secret>"}'

# 4. Readiness: /readyz must be 200 on every replica (covers etcd registry)
curl -s http://$ip:8080/readyz
```

Reference verification run (2026-08-06, this repo): 3 replicas, all JWKS
identical (4 kids = 3 replica keys + 1 retiring key), cross-pod validation
10/10 consistent through the gateway, revocation observed as
`{"active":false}` on all 3 pods, `/readyz` 200 on all pods.

## HA notes

- **etcd**: run 3 members (`--initial-cluster` lists all three advertised
  peer URLs) for quorum; `signing_key_registry.lease_ttl` governs how long a
  dead replica's key lingers verify-only.
- **Redis**: add replicas per master (`--cluster-replicas 1`) for shard HA;
  keep `maxmemory-policy noeviction` on masters and leave
  `route_by_latency`/`read_only` off (single-use + replay reads must hit the
  master).
- **Key rotation**: `keys.rotation.grace_period` must be >= the max access
  token TTL; `keys.rotation.coordinated_cutover` retires a demoted kid on
  every replica at the same instant over the bus.
- **Multi-region**: replace Postgres with CockroachDB
  (`postgres.dialect: cockroach`), place Redis per region near the replicas,
  and gate tenant data placement with the `region` residency settings.
  Token hot paths (`/token`) are latency-sensitive to the shared hot tier —
  that is the architecture's real boundary; the product does not decompose
  `sso-server` into per-region microservices.
- **Images on a single-node cluster without a registry**: build locally and
  `docker save <image> | sudo ctr -n k8s.io images import -`.
