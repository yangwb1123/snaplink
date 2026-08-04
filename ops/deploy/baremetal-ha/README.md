# Bare-metal HA reference

Reference topology for the API-only `sso-server`:

```text
keepalived VIP
  → two HAProxy edges
  → three sso-server replicas + two loopback Billing/Stripe pairs
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

## Deployment status

The checked-in SSO config is schema-valid, the distroless image has a native
health probe, HAProxy terminates TLS and rebuilds trusted forwarding headers,
and `smoke.sh` is executable. `docker-compose.yml` remains a single-host
validation model: it cannot prove host, power-domain, switch, or VRRP failover.

Before production, replace every placeholder and image tag, supply an
out-of-repository certificate, enable authenticated TLS for PostgreSQL, Redis,
and etcd, provide persistent volumes and off-site backups, translate the
service definitions into host-native units, and rehearse every runbook drill
across at least three failure domains. Keepalived/VRRP is intentionally a VM
test because a single Docker bridge cannot exercise L2 VIP movement.

## Asset map

| Asset | Purpose |
|---|---|
| `docker-compose.yml` | Single-host topology model |
| `haproxy/` | App health routing and Postgres leader/replica routing |
| `patroni/` | Synchronous Postgres HA templates |
| `redis/` | Six-node Redis Cluster with no-eviction requirements |
| `keepalived/` | Two-node VRRP templates for real VMs |
| `sso/` | Shared-state server configuration template |
| `systemd/` | Hardened host-native SSO/Billing/Stripe units and environment templates |
| `stripe-adapter/` | Reviewed non-secret tenant/client binding for the two adapter replicas |
| `RUNBOOK.md` | Operator procedure and validation gates |

The independent `snaplink-billing` runtime uses the same three-node PostgreSQL
failure domain but a separate `billing` database and role. Run it loopback-only
on each application VM behind a same-host TLS proxy; the external edge may then
balance those three TLS proxies. Its canonical container, Compose, Kustomize,
and Helm assets live in `cmd/snaplink-billing`, `ops/deploy/compose`,
`ops/deploy/billing`, and `ops/deploy/helm/snaplink-billing` respectively.

The optional `snaplink-stripe-adapter` runs active-active as `stripe-a` and
`stripe-b`, one loopback process in each HAProxy namespace. HAProxy routes only
the checkout and Stripe webhook paths and removes an instance when its
PostgreSQL/JWKS `/readyz` check fails. The adapters share a separate
`stripe_adapter` role/database; their inbox leases, generation fences and
effect receipts are durable across process or edge failover. Host-native
deployments install the same systemd unit on the two edge VMs with independent
environment files and the same reviewed binding revision.

Browser frontends are separate deployments behind the edge.
