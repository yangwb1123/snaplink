# Local-dev compose stack

One-command setup for sso-server + etcd, optionally with a Prometheus
+ Grafana observability stack pre-wired to the dashboard from
`ops/deploy/grafana/`.

`sso-server` is a pure HTTP/gRPC API backend. This stack does not include a
hosted login page, self-service portal, setup UI, developer portal, or admin
console; run the separate frontend project behind a reverse proxy when a
browser UI is required.

## Quickstart

```bash
cd ops/deploy/compose

# sso-server + etcd:
docker compose up --build

# add observability (Prometheus + Grafana with the snaplink dashboard
# auto-provisioned):
docker compose --profile observability up --build

# add PostgreSQL-backed commerce/metering behind local Caddy TLS:
docker compose --profile commerce up --build

# add commerce plus the Stripe adapter behind a separate loopback Caddy edge:
docker compose --profile payment up --build

# reconcile Audit Governance desired state against TLS endpoints:
install -d -m 0700 secrets
# The locked parent protects the host path; 0444 lets the nonroot container read
# the bind-mounted file while the provisioner still rejects writable secrets.
install -m 0444 /secure/path/client-secret secrets/audit-provisioner-client-secret
AUDIT_GOVERNANCE_BASE_URL=https://audit.example.internal \
AUDIT_PROVISIONER_TOKEN_URL=https://sso.example.internal/token \
docker compose --profile audit-provisioning up --build snaplink-audit-provisioner
```

The first `--build` pass compiles the sso-server image from the repo
root Dockerfile (one-shot — re-runs are cached unless you edit Go
source).

## What's running

| Service     | Port  | URL                                          |
|-------------|-------|----------------------------------------------|
| sso-server  | 8080  | http://localhost:8080 (API + JWKS + probes + metrics) |
| sso-server  | 8081  | gRPC control plane, authz, audit, and discovery |
| etcd        | 2379  | http://localhost:2379                        |
| prometheus  | 9090  | http://localhost:9090 (profile only)         |
| grafana     | 3000  | http://localhost:3000 (admin/admin)          |
| billing     | 8443  | https://localhost:8443 (local Caddy CA)       |
| Stripe adapter | 8445 | https://localhost:8445 (payment profile; local Caddy CA) |
| audit provisioner | 8092 | http://localhost:8092 (profile probes + metrics) |

Open Grafana → Dashboards → SSO → "snaplink/sso — overview" to see
the dashboard. Anonymous viewer access is enabled so you don't have
to log in.

## Verifying the stack

```bash
# Health probe:
curl -s http://localhost:8080/livez
# {"status":"alive"}

# Metric scrape (manual; Prometheus does it every 5s):
curl -s http://localhost:8080/metrics | head -20

# JWKS for downstream JWT verification:
curl -s http://localhost:8080/.well-known/jwks.json | jq .

# Billing uses a local Caddy CA; `-k` is for this development stack only.
curl -ks https://localhost:8443/livez
curl -ks https://localhost:8443/metrics | grep snaplink_billing_renewal

# Stripe adapter probes and metrics use its independent edge.
curl -ks https://localhost:8445/readyz
curl -ks https://localhost:8445/metrics
```

The commerce profile also exercises entitlement-to-SSO quota projection. Its
committed `quota-local-only` credential is intentionally limited to local
development and has exactly `tenant-quota:projection:write` for resource
`snaplink-sso-quota`. The Billing relay reaches SSO only through the loopback
Caddy bridge, and `config.yaml` binds the same client plus derived
`snaplink-billing-quota` source to `tenant-example`. Add a source record for
each additional test tenant; never copy this credential into production.
When both `commerce` and `observability` profiles run, Prometheus scrapes the
Billing TLS edge every five seconds and evaluates the shared renewal alerts.

The `payment` profile also starts a separate PostgreSQL database and the
`snaplink-stripe-adapter` Docker target. The adapter socket, its SSO bridge and
its Billing bridge all stay on loopback inside `stripe-edge`'s network
namespace; only local TLS port 8445 is published. Defaults prefixed `*_local_*`
are deliberately non-production test credentials. Override `STRIPE_API_KEY`,
`STRIPE_WEBHOOK_SECRETS`, and `STRIPE_BILLING_CLIENT_SECRET` only from your
shell or local secret store. A one-shot initializer copies the reviewed
`stripe-bindings.json` into a shared volume as a regular mode-0444 file; it is
never placed in an environment variable.

## Demonstrating the etcd config source

The sso-server is started with
`--etcd-endpoints etcd:2379 --etcd-prefix /snaplink/config`. The etcd source slots into the
loader chain between env and flag (lowest = file, highest = flag).
Add or change a key in etcd → the next sso-server restart picks up
the override.

```bash
# Tighten log level via etcd:
docker compose exec etcd etcdctl put /snaplink/config/logging/level debug

# Restart sso-server to re-load config:
docker compose restart sso-server
docker compose logs sso-server | head -5
# expect "level=DEBUG" log lines

# Or override audit memory capacity:
docker compose exec etcd etcdctl put /snaplink/config/audit/memory_capacity 50000
docker compose restart sso-server
```

## Demonstrating the env config source

Uncomment the `environment:` block in `compose.yaml`, then
`docker compose up -d --force-recreate sso-server`. Same merge
semantics — env wins over file but loses to etcd (which loses to a
CLI flag if you add one to the `command:` block).

## Stopping

```bash
docker compose down            # stops; keeps the etcd volume
docker compose down -v         # also wipes the etcd volume
```

## Layout

```
ops/deploy/compose/
├── compose.yaml              # services
├── config.yaml               # bind-mounted into sso-server
├── billing.Caddyfile         # local TLS edge + loopback JWKS proxy
├── stripe.Caddyfile          # payment TLS edge + loopback dependency bridges
├── stripe-bindings.json      # non-secret local tenant/client mapping
├── prometheus.yml            # scrape config
├── grafana-provisioning/
│   ├── datasources/
│   │   └── prometheus.yaml   # Prometheus as default datasource
│   └── dashboards/
│       └── snaplink.yaml     # auto-load /var/lib/grafana/dashboards/
└── README.md                 # you are here
```

The actual dashboard JSON + alert rules live in `ops/deploy/grafana/` and
are bind-mounted here — keeps one source of truth across the K8s and
compose paths.

The audit profile mounts `../audit-provisioner/desired-state.example.json` and
a read-only secret file from the mode-0700 `secrets` directory. Replace the
example tenant and client IDs and increase
its revision before use. This platform-control credential is separate from all
event-relay credentials and receives only the provisioner's fixed scope.

## What this stack is NOT

* **Not production-grade.** One API replica uses the configured development
  stores; etcd runs single-node with an ephemeral
  volume; admin/admin Grafana credentials; anonymous viewer access
  on; sso-server has no TLS termination, no rate limiting wired,
  no real users seeded. Memory and local SQLite stores are not shared HA state.
  The commerce/payment profiles also commit local-only PostgreSQL credentials
  and use Caddy's development CA; they demonstrate process/network boundaries,
  not production secret management or database HA. Automatic renewal stays
  off, and the payment profile must never be started with live Stripe keys.
* **Not the K8s shape.** For an in-cluster deployment see
  `ops/deploy/kustomize/` — the manifests there share the same config/image
  shape and expose separate `/livez` and `/readyz` probes. Use the production
  overlay plus externally managed Redis, Postgres, and etcd for HA.
