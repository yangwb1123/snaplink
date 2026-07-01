# Production HA overlay

> **⚠️ DEPRECATED**: This directory is maintained for backward compatibility.
> New deployments should use the canonical structure at
> **[ops/deploy/kustomize/overlays/prod/](../kustomize/overlays/prod/)**.
>
> This directory (`ops/deploy/k8s-prod/`) is identical to
> `ops/deploy/kustomize/overlays/prod/`.

N stateless `sso-server` replicas behind shared backends — the "Tier B"
topology from [`docs/deployment.md`](../../docs/deployment.md) §6. A Kustomize
overlay over the base in [`../k8s`](../k8s).

```bash
kubectl apply -k ops/deploy/k8s-prod/
```

## What this overlay adds over the base

| Resource | Why |
|---|---|
| `hpa.yaml` (HPA, min 3 / max 20, CPU 70%) | Autoscaling — **safe only because state is shared** (Redis Cluster + Postgres). The base `memory` backend would lose per-pod auth codes/sessions on scale events. |
| `pdb.yaml` (PDB minAvailable 2) | Keeps quorum through node drains / rolling upgrades. |
| `config.yaml` (replaces the base ConfigMap) | Hot stores → Redis Cluster, durable stores → Postgres, coordination → etcd. |
| `patch-deployment.yaml` | Secret-injected backend creds (`SSO_*` env), zone spread, `preStop` drain + `terminationGracePeriodSeconds`, tolerant readiness probe. |
| `secretGenerator` | **Placeholder** — replace with sealed-secrets / external-secrets / Vault. |

## External dependencies you must stand up

- **Redis Cluster** (≥ 3 masters + replicas). **HARD requirement:** the auth
  keyspace must run `maxmemory-policy noeviction` (or `volatile-ttl`).
- **Postgres-wire DB cluster** — PostgreSQL (HA via Patroni / a managed service)
  **or** CockroachDB (set `postgres.dialect: cockroach`).
- **etcd** (3/5-node) — the cluster Bus + registry + leaderless JWKS aggregation.
- A **TLS-terminating edge** (Ingress / OpenResty / Envoy) that strips and
  re-sets `X-Forwarded-*`.

## Production checklist

1. Pin the image to a digest (the base uses `:latest`).
2. Replace the placeholder `sso-server-secrets` with a real secret store.
3. Set `server.issuer` (config.yaml) to the externally-reachable HTTPS URL.
4. Point `redis.addrs`, `postgres` DSN, and `cluster.bus.etcd_endpoints` at your
   real services; mount the Redis CA into the `sso-server-redis-tls` secret.
5. Confirm `/readyz` gates on Redis + Postgres reachability.
