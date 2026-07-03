The document already exists at **`/home/dwp/snaplink/docs/deployment.md`** (294 lines) and covers every section you listed. It has also been updated to reflect recent additions — the key difference from the version you provided is:

| What you wrote | What the file now says |
|---|---|
| Durable stores: `memory` · `sqlite` (Postgres planned) | Durable stores: `memory` · `sqlite` · **`postgres`** — both Redis **and** Postgres backends are wired into the stock binary |
| Tier B: hot→Redis only; durables stay on sqlite | Tier B: hot→Redis Cluster, durable→Postgres/CockroachDB, coordination→etcd — with full `config.yaml` example |
| Postgres/CockroachDB ⚠️ planned in §7 | ✅ `backend: postgres` in the binary today |
| No `postgres:` block in config example | Full `postgres:` block with `dsn`, `max_open_conns`, dialect, plus durable store backends (`identity.backend`, `permissions.backend`, `tenant.backend`, `audit.backend`) |
| Simple ASCII diagram | Added a `Postgres /Cockroach` box alongside Redis in the topology diagram |

The file is complete with all 9 sections. Here's a quick reference:

- **§1 Build** — `python cli.py build`, Docker, `sso-server version`
- **§2 Run** — `:8080` HTTP, `:8081` gRPC, probes `/livez`/`/readyz`/`/metrics`, `sso-ctl config validate`
- **§3 Config** — file < env < etcd < flags, backend matrix (memory/sqlite/redis/postgres/etcd)
- **§4 Client surfaces** — HTTP OAuth2/OIDC, gRPC+REST admin, `ssoclient/remote` (local JWKS verification), SDK embed
- **§5 Kubernetes** — `kustomize` base + `k8s-prod` HA overlay (HPA, PDB, topology spread, preStop drain)
- **§6 Distributed architecture** — Tier A (single sqlite), Tier B (Redis+Postgres+etcd, HA), Tier C (verification fleet). Leaderless JWKS aggregation. Full Tier B `config.yaml` and topology diagram.
- **§7 Distribution-capable modules** — 11 modules, all ✅ in the binary
- **§8 Microservices decomposition** — split issuance vs consumption; don't split the protocol
- **§9 Operational invariants** — X-Forwarded-* trust, clock slew, fail-safe key cutover, anti-enumeration uniformity

See also: [`config-reference.md`](config-reference.md), [`observability.md`](observability.md), [`adr/ADR-0007`](adr/ADR-0007-directory-fanout-and-the-monolith-exemption-class.md).
