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
```

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

## What this stack is NOT

* **Not production-grade.** One API replica uses the configured development
  stores; etcd runs single-node with an ephemeral
  volume; admin/admin Grafana credentials; anonymous viewer access
  on; sso-server has no TLS termination, no rate limiting wired,
  no real users seeded. Memory and local SQLite stores are not shared HA state.
* **Not the K8s shape.** For an in-cluster deployment see
  `ops/deploy/kustomize/` — the manifests there share the same config/image
  shape and expose separate `/livez` and `/readyz` probes. Use the production
  overlay plus externally managed Redis, Postgres, and etcd for HA.
