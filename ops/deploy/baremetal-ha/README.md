# Bare-metal HA reference

Reference topology for the API-only `sso-server`:

```text
keepalived VIP
  → two HAProxy edges
  → three sso-server replicas
  → Redis Cluster (hot state)
  → Patroni/Postgres (durable state)
  → three-node etcd (DCS, invalidation bus, signing-key registry)
```

`docker-compose.yml` collapses the topology onto one host. The HAProxy,
Patroni, Redis, keepalived, and SSO configuration files are VM templates, not
production-ready defaults. No application-level sharding or message queue is
part of this design.

Retired rationale is indexed in
[`docs/HISTORY.md`](../../../docs/HISTORY.md). Current backend semantics are in
[`docs/deployment.md`](../../../docs/deployment.md) and
[`docs/config-reference.md`](../../../docs/config-reference.md). Use
[`RUNBOOK.md`](RUNBOOK.md) for VM mapping, startup order, failover, restore,
capacity, and hardening procedures.

## Current blockers

Do not run this as production or describe it as one-command ready:

- healthchecks and runbook commands invoke a shell/`wget` that the distroless
  server image does not contain;
- `sso/config.yaml` uses obsolete `server.addr` and
  `server.trusted_proxies` paths;
- HAProxy's `:443` binding has no TLS certificate but stamps forwarded HTTPS;
- `smoke.sh` contains redacted placeholders; and
- keepalived/VRRP cannot be exercised on the single-host bridge network.

Fix the assets, validate configuration, replace every secret placeholder, add
a real trusted TLS edge, and rehearse every runbook drill in staging.

## Asset map

| Asset | Purpose |
|---|---|
| `docker-compose.yml` | Single-host topology model |
| `haproxy/` | App health routing and Postgres leader/replica routing |
| `patroni/` | Synchronous Postgres HA templates |
| `redis/` | Six-node Redis Cluster with no-eviction requirements |
| `keepalived/` | Two-node VRRP templates for real VMs |
| `sso/` | Shared-state server configuration template |
| `RUNBOOK.md` | Operator procedure and validation gates |

Browser frontends are separate deployments behind the edge.
