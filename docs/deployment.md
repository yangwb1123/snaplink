# Deployment & distributed architecture

How to build, run, deploy (Kubernetes / Compose), call, and scale snaplink/sso.
Every capability below is grounded in what the code actually does — where the
stock binary stops and the SDK begins is called out explicitly, because it
changes how you scale.

The runtime is API-only. Login, admin, self-service, developer and setup UIs
are separate deployments and are normally reverse-proxied at the same public
origin; `sso-server` does not serve their static assets.

- [1. Build](#1-build)
- [2. Run a single instance](#2-run-a-single-instance)
- [3. Configuration model](#3-configuration-model)
- [4. How clients call it (4 surfaces)](#4-how-clients-call-it)
- [5. Kubernetes](#5-kubernetes)
- [6. Distributed architecture](#6-distributed-architecture)
- [7. Which modules are distribution-capable](#7-which-modules-are-distribution-capable)
- [8. Microservices decomposition](#8-microservices-decomposition)
- [9. Operational invariants](#9-operational-invariants)

---

## 1. Build

```bash
python cli.py build            # -> ./bin/{sso-server, sso-ctl}   (make/Taskfile delegate here)
python cli.py configure --profile prototype --version v1.1.1 --build
python cli.py configure --profile minimal --version v1.1.1 --build
python cli.py configure --profile full --version v1.1.1 --build
python cli.py configure --profile billing --version v1.1.1 --build
python cli.py configure --profile standard-kafka --build  # compatibility composition
docker build -t snaplink/sso-server .      # the root Dockerfile
docker build --target snaplink-billing -t snaplink/billing .
docker build --target snaplink-stripe-adapter -t snaplink/stripe-adapter .
docker build --target snaplink-audit-provisioner -t snaplink/audit-provisioner .
CGO_ENABLED=0 go build -trimpath -o bin/snaplink-audit-provisioner ./cmd/snaplink-audit-provisioner
sso-server version                          # version / build time / Git hash / Go version
sso-server modules                          # compiled profile/inventory; configured builds include a lock digest
```

FIPS 140-3 build (opt-in, default off — see [docs/fips.md](fips.md)):

```bash
GOFIPS140=latest CGO_ENABLED=0 go build -o sso-server ./cmd/sso-server
docker build --build-arg GOFIPS140=latest -t snaplink/sso-server-fips .
```

The normal engineering build produces **`sso-server`** (runtime) and
**`sso-ctl`** (offline operator toolbelt: `audit-verify`, `import`, `migrate`,
`snapshot`, `config validate`, `hash`, `version`). The GoReleaser distribution
also includes the separately-moduled **`sso-mcp`** gateway; it is not part of
`python cli.py build`'s two-binary gate. See
[`cmd/sso-mcp/README.md`](../cmd/sso-mcp/README.md) for its tools, configuration,
and security boundary.

`configure` is the cold-module build path. It writes an alternate module graph,
lock and binary under `dist/modules/<profile>/` without editing root
`go.mod`/`go.sum`. `standard` preserves the stock server and
`standard-kafka` adds the Kafka audit module; both are compatibility profiles,
not the new edition hierarchy.

| Edition profile | Build status | Boundary |
|---|---|---|
| `prototype` | Preview; buildable | Loopback/memory SSO + OAuth Code/mandatory PKCE, password and reusable OP-session login, JSON logs, and one stable `default` tenant. OIDC surfaces are excluded. |
| `minimal` | Preview; buildable | Extends `prototype` with OIDC discovery, ID Token, UserInfo and logout plus request tracing. |
| `full` | Supported; buildable | Extends `minimal` with the full current stock `sso-server` composition and registered Kafka audit cold module. Durable backend and topology choices remain operator configuration. |

The separate preview `billing` profile builds
`dist/modules/billing/snaplink-billing`. It selects only locked core plus the
standalone billing composition, is not inherited by `full`, and does not imply
that billing can be hot-loaded into an SSO process.

For source version `v1.1.1`, the three binaries report
`snaplink-v1.1.1.prototype`, `snaplink-v1.1.1.minimal`, and
`snaplink-v1.1.1.full`. `prototype` and `minimal` currently share
`cmd/sso-minimal`, so their different runtime surfaces do not yet imply
different physical dependency graphs. Neither small edition is a production
topology or browser end-to-end artifact. Unless a profile is named explicitly,
the rest of this guide describes the compatibility `sso-server`.

## 2. Run a single instance

```bash
sso-server --config config.yaml      # HTTP :8080, gRPC :8081
```

- **HTTP `:8080`** — OAuth2/OIDC + the REST admin plane (`/api/v1/admin/*`).
- **gRPC `:8081`** — the admin/control plane (`--grpc-listen ''` disables it).
  Plaintext is fail-closed by default (Decision 5 of
  `docs/design/grpcserver-observability-tls.md`): provide TLS material
  (`-grpc-tls-cert/-grpc-tls-key` or the shared `-tls-cert/-tls-key` pair),
  bind a loopback `-grpc-listen`, or pass `-grpc-insecure` for an edge-TLS
  deployment behind a TLS-terminating proxy (the stock deploy trees do this).
- **Probes (served OUTSIDE the rate-limit/metrics stack):** `/livez` (process
  up), `/readyz` (aggregates every `WithReadyCheck` — db ping, etcd reachable,
  signing-backend health), `/metrics` (Prometheus).
- **TLS:** in-process when both `--tls-cert` and `--tls-key` are set; otherwise
  put a TLS-terminating edge in front (see [`ops/deploy/openresty`](../ops/deploy/openresty)).

Validate a config before rollout (no server needed):

```bash
sso-ctl config validate --file config.yaml
```

## 3. Configuration model

One YAML tree, resolved **low → high**: **file < env < etcd < flags**.

```bash
sso-server --config config.yaml                       # file
SSO_SERVER__LISTEN=:9090 sso-server ...               # env: SSO_<SECTION>__<KEY>
sso-server --etcd-endpoints localhost:2379 ...        # etcd: cluster-wide live config
sso-server --listen :9090 ...                         # flag: one-shot override (wins)
```

Each pluggable concern picks a backend via its `backend:` key. **What the
*binary* supports today:**

Keep four independent states separate:

| State | Question it answers |
|---|---|
| Compiled capability | Did the cold profile physically link the capability and dependencies? |
| Runtime backend | Which compiled implementation does startup configuration select? |
| Feature gate | Is an already compiled and wired route or behavior exposed? |
| Hot lifecycle | Can a prepared capability be activated, drained, or stopped without rebuilding/restarting? |

A backend key or feature gate does not prove code was compiled out. General hot
load/unload is not available today.

| Concern | `backend:` values the binary wires |
|---|---|
| Hot stores (auth-code, refresh, session, par, device, ciba, jti-replay, mfa-challenge) + `ratelimit` | `memory` (default) · `sqlite` (`<concern>.sqlite.dsn`) · **`redis`** (shared `redis:` block) |
| Durable stores (clients, users, consent, permissions, tenants, audit, …) | `memory` (default) · `sqlite` · **`postgres`** (shared `postgres:` block) |
| `cluster` (the cross-replica event Bus) | `memory` · **`etcd`** (`etcd_endpoints`, `etcd_prefix`, …) |
| `registry`, `netpolicy` | `memory` · `etcd` |
| `config` source | file · env · `etcd` |

> **Both Redis AND Postgres backends are wired into the stock binary.** Redis
> (`backend: redis` on the hot stores, configured by one shared `redis:` block —
> single/sentinel/cluster) and Postgres/CockroachDB (`backend: postgres` on the
> durable stores, one shared `postgres:` block). Both are root-module
> infrastructure packages, so their dependencies are tracked by the root
> `go.mod`. Sessions take their own `identity.session_backend` so the hot
> session store can be Redis while durable clients/users stay on a Postgres
> cluster. See §6 for the full HA topology.

## 4. How clients call it

| Caller | Surface | Detail |
|---|---|---|
| Any language (SPA / RP / resource server) | **HTTP OAuth2/OIDC** | `/.well-known/openid-configuration`, `/auth/login`, `/token`, `/userinfo`, `/.well-known/jwks.json`. Contract: [`docs/openapi.yaml`](openapi.yaml). |
| Ops / control plane | **gRPC `:8081`** + **REST `/api/v1/admin/*`** | services: admin (clients/users/tenants/permissions/releases/snapshots/tokens), authz, audit, discovery, netpolicy — gated by `admin:read` / `admin:write`. |
| **Go downstream service** | **`interfaces/ssoclient`** | `remote` verifies tokens **locally** against cached JWKS (the SSO server is **off the per-request hot path**) and calls authz/audit over gRPC; also `local` (embed), `dev` (allow-all), `bootstrap`. |
| Go app embedding SSO | **SDK** | `sso.NewServer(opts...).Handler()` on any `net/http` listener. |

Frontend applications are ordinary HTTP clients of these APIs. They are not a
fifth static-file surface in this repository.

Core RP flow over the wire:

```bash
curl https://sso.example.com/.well-known/openid-configuration
# /auth/login (PKCE captured here) -> {"code": "..."}
# /token (authorization_code + code_verifier) -> {"access_token","id_token"}
curl https://sso.example.com/userinfo -H 'Authorization: Bearer <access_token>'
```

## 5. Kubernetes

The canonical Kustomize tree is
[`ops/deploy/kustomize`](../ops/deploy/kustomize):

```bash
kubectl kustomize ops/deploy/kustomize/overlays/dev/
kubectl kustomize ops/deploy/kustomize/overlays/prod/
```

Render and review before applying. The base still models an unsafe
multi-replica/memory shape; development must use one replica and production
must externalize every enabled stateful concern. The canonical
[Kustomize README](../ops/deploy/kustomize/README.md) records current asset
blockers and required external services.

`ops/deploy/compose/` runs the same image with Prometheus + Grafana
(dashboards/alerts provisioned) for a local/observability stack. Its explicit
`commerce` profile starts PostgreSQL, the loopback-only Billing process, and a
same-namespace TLS edge:

```bash
docker compose -f ops/deploy/compose/compose.yaml --profile commerce up
```

The opt-in `payment` profile includes that commerce tier plus an isolated
adapter PostgreSQL database and a second loopback-only TLS edge:

```bash
docker compose -f ops/deploy/compose/compose.yaml --profile payment up
```

Its checked-in `sk_test_`/`whsec_` values are deliberately non-production
placeholders. Live keys must come from an external secret store and require an
explicit, reviewed `SNAPLINK_STRIPE_LIVE_MODE=true` change.

Production Billing has two independently renderable Kubernetes choices:

```bash
kubectl kustomize ops/deploy/billing/
helm lint --strict ops/deploy/helm/snaplink-billing
helm template billing ops/deploy/helm/snaplink-billing --namespace snaplink-sso
```

Both default to three replicas, HPA/PDB/topology spread, an external PostgreSQL
DSN and secrets, and an unprivileged same-Pod TLS edge. Port 8090 is never a
Service/container port; only the edge's named HTTPS port is routable. Automatic
renewal remains explicitly off until operators complete financial restore and
reconciliation drills.

The Stripe adapter has separate Kustomize and Helm forms:

```bash
kubectl kustomize ops/deploy/billing/stripe-adapter/
helm lint --strict ops/deploy/helm/snaplink-stripe-adapter
helm template stripe-adapter ops/deploy/helm/snaplink-stripe-adapter --namespace snaplink-sso
```

These manifests default to three active-active replicas,
HPA/PDB/topology spreading and end-to-end TLS. Its Helm chart requires external
application/TLS Secrets and an external binding ConfigMap, mounts the binding
as one read-only `subPath` file, and accepts an immutable `sha256:` image
digest. PostgreSQL stores checkout mappings, event receipts and the delivery
inbox; it is the only shared state required by adapter replicas.

[`ops/deploy/baremetal-ha`](../ops/deploy/baremetal-ha) is the corresponding
three-node Patroni/Redis/etcd/VRRP reference. Its Compose model is executable on
one host for validation and runs one loopback Billing and Stripe adapter process
inside each edge network namespace. Production use still requires real host separation,
authenticated backend TLS, persistent disks, immutable images, off-site backup,
and rehearsal of the included failure drills.

## 6. Distributed architecture

The design is a **modular monolith that scales horizontally** — N identical
`sso-server` replicas behind an L7 load balancer — not a fine-grained
microservice mesh. Replicas coordinate through two independent mechanisms, and
**they have different maturity in the stock binary**:

### 6a. Coordination — the cluster event Bus (works in the binary)

`platform/cluster` (`backend: etcd`) is a pub/sub Bus that propagates
state-change events so every replica reacts without a database round-trip:

> `KindTokenRevoked` · `KindSigningKeyRotation` · `KindClientChange` ·
> `KindAuthzPolicyChange` · `KindDiscoveryReload` · `KindTenantResidency` ·
> `KindTenantSuspension`

On top of it, `platform/signingkeys` does **leaderless** JWKS key aggregation —
replicas adopt each other's signing keys via the Bus (alg-matched before
install), so JWKS is fleet-consistent with no leader election. `registry`,
`netpolicy` and live `config` likewise share through etcd.

### 6b. Shared state — the part that decides your topology

Coordination events are not the *primary data*. Auth codes, sessions, refresh
tokens, PAR/device/CIBA requests, MFA challenges, and enabled user-lifecycle
state live in **stores**.
`memory` is per-process and a per-pod SQLite DSN is file-local; neither is
shared across replicas. The stock binary also supports shared Redis hot stores
and Postgres durable stores, but the operator must select them explicitly.
With a local backend selected:

> With the default `memory` (or per-pod `sqlite`) backend and >1 replica, an
> authorization code minted on replica A is invisible to replica B, so the
> `/token` exchange (which comes from the RP's backend, a *different* origin than
> the browser that hit `/auth/login` — so LB session-affinity cannot help)
> returns `invalid_grant`. The OAuth code flow breaks.

What IS safe across replicas with the etcd Bus alone:
- **Access-token *validation*** — JWT access tokens are self-contained; downstream
  services verify locally against cached JWKS, and revocation propagates via the
  Bus. This path is fully distributed and off the hot path.

So choose a tier:

| Tier | Topology | Correct for |
|---|---|---|
| **A — single instance** | 1 replica, `sqlite` stores on a PVC, etcd optional | small/medium prod; restart-safe; **no HA** |
| **B — HA, shared hot store** | N replicas, hot stores `backend: redis` (Redis Cluster) + etcd Bus | true horizontal scale; a config choice on the stock binary today |
| **C — verification fleet** | Many downstream services, each `ssoclient/remote` (local JWKS) | always — this side scales freely regardless of the SSO server's tier |

> **Tier B is a config choice on the stock binary.** Set `backend: redis` on
> the hot stores (auth_code, refresh, session via `identity.session_backend`,
> par, device_code, ciba, jti_replay, mfa.challenge) and `ratelimit`, give a
> shared `redis:` block (`mode: cluster`), set `backend: postgres` on the durable
> stores (identity, permissions, tenant, audit, consent, …) with a shared
> `postgres:` block, and turn on the etcd Bus. Both Redis and Postgres backends
> are root-module infrastructure packages wired by `cmd/sso-server`.

User lifecycle participates in Tier B when `user_lifecycle.backend: postgres`;
the state machine and its full transition history then share the durable pool.
The memory default remains single-process and is rejected when lifecycle is
enabled in a declared multi-replica topology.

Tier B `config.yaml` (hot → Redis Cluster, durable → Postgres, coordination → etcd;
secrets via `SSO_REDIS__PASSWORD` / `SSO_POSTGRES__DSN`):

```yaml
redis:
  mode: cluster
  addrs: [redis-0:6379, redis-1:6379, redis-2:6379]
  db: 0                 # cluster requires 0
  pool_size: 100
  read_timeout: 300ms   # fail-closed fast on /token

postgres:
  dialect: postgres      # postgres | cockroach
  dsn: postgres://sso@pgbouncer:6432/sso?sslmode=verify-full
  max_open_conns: 15     # N replicas x this < DB max_connections

oauth:    { backend: redis }        # auth_code / refresh / device_code / par
ciba:     { backend: redis }
mfa:      { challenge: { backend: redis } }
security: { jti_replay: { backend: redis }, rate_limit: { backend: redis } }
identity: { backend: postgres, session_backend: redis } # durable on DB, sessions hot
permissions: { enabled: true, backend: postgres }
tenant: { enabled: true, backend: postgres }
audit: { enabled: true, backend: postgres, hash_chain: true }
user_lifecycle: { enabled: true, backend: postgres }

cluster:
  bus: { backend: etcd, etcd_endpoints: [etcd-0:2379] }
  cross_replica_revocation: true
keys:
  signing: { revocation_backend: redis }
  signing_key_registry: { backend: etcd, etcd_endpoints: [etcd-0:2379] }
```

> **Operator hard requirement:** the Redis auth keyspace MUST run
> `maxmemory-policy noeviction` (or `volatile-ttl`). Evicting a live
> refresh-family ledger, jti key, or active revocation entry is a SECURITY
> regression (reuse/replay/recovery silently fails), not a cache miss. Keep
> single-use/replay reads on the master (`route_by_latency`/`read_only` off) so replica lag can't let a
> replay slip past detection. Migrating single-node → cluster is NOT drop-in
> (hash-tag key layout changes) — drain rather than expect key continuity;
> acceptable since hot state is short-TTL.

Reference distributed topology (Tier B):

```
            ┌────────────── TLS edge (OpenResty/Envoy) — strips+re-sets XFF
            ▼
   ┌───────────────────┐   N replicas, pod anti-affinity
   │  sso-server × N    │── gRPC/REST admin :8081
   └─────┬──────┬──────┘
         │      │
    hot  │      │ durable
    ┌────▼──┐ ┌─▼──────────┐
    │ Redis  │ │ Postgres   │ etcd (cluster Bus:
    │ Cluster│ │ /Cockroach │ revocation, key
    │ codes, │ │ clients,   │ rotation, config,
    │ sess,… │ │ users, …   │ registry, netpolicy)
    └────────┘ └────────────┘
         ▲
         │  optional: KMS/HSM (kms/*), SAML-IdP, LDAP, RADIUS  (separate modules)

   downstream services ──hold──> ssoclient/remote (verify tokens LOCALLY, cached JWKS)
```

## 7. Which modules are distribution-capable

| Module | Distributed via | In stock binary? |
|---|---|---|
| Cluster event Bus (`platform/cluster`) | etcd pub/sub | ✅ |
| Signing keys / JWKS (`platform/signingkeys`) | leaderless adoption over the Bus | ✅ |
| Live config (`config`) | etcd source | ✅ |
| Service discovery (`platform/registry`) | etcd | ✅ |
| Network policy (`platform/netpolicy`) | etcd | ✅ |
| Multi-region / residency / tenant (`region`, `tenant`) | residency gating + Bus invalidation | ✅ |
| CAEP/SSF (`protocols/caep`) | cross-replica SET transmit to the affected client | ✅ |
| Token verification (downstream) | `ssoclient/remote` + cached JWKS | ✅ (off hot path) |
| **Hot-path stores** (codes/sessions/refresh/par/device/ciba/jti/mfa-challenge) + ratelimit | **Redis Cluster** (`infrastructure/redis`) | ✅ `backend: redis` |
| **Durable stores** (clients/users/consent/permissions/tenants/audit/…) | **Postgres/CockroachDB** (`infrastructure/postgres`) | ✅ `backend: postgres` |
| Signing offload | `infrastructure/kms/*` (AWS/GCP/Azure KMS, PKCS#11) | No — nested module plus custom composition; no supported profile yet |

## 8. Microservices decomposition

The natural and supported split is **token *issuance* vs token *consumption***:

- **SSO server replicas** issue/login/admin — scale per §6 (Tier A or B).
- **Downstream services verify locally** (`ssoclient/remote`, cached JWKS) — they
  never call the SSO server per request. This is the key microservices win.
- **Independent services**: Redis, etcd and external KMS/HSM endpoints.
  SAML-IdP, LDAP, RADIUS and ext-authz are nested library modules that still
  require static custom composition; they are not standalone plugin processes.
- The **gRPC control plane** *could* run on a separate exposure from the OAuth
  data plane (same binary), e.g. an internal-only admin Service.

The commercial suite adds independently deployable resource and governance
planes; it does not change that OAuth boundary:

| Component | Owns | Authentication and scaling boundary |
|---|---|---|
| `sso-server` | Login, OAuth/OIDC issuance, authorization and tenant identity | N replicas with shared Redis/Postgres/etcd as described in §6. |
| `snaplink-billing` | Immutable plans, snapshotted subscription renewals, entitlement projections, wallet/payment ledger, usage reservations and durable audit outboxes | N stateless API/relay/optional-renewal-worker replicas on one PostgreSQL cluster. Each process is loopback-only and sits behind the trusted TLS edge. |
| `snaplink-stripe-adapter` | Stripe Checkout creation, signed webhook normalization, immutable event/effect receipts and fenced delivery inbox | N active-active API/relay replicas on one dedicated PostgreSQL database. Checkout clients and per-tenant Billing clients are separate least-privilege OAuth identities; no raw Stripe payload or card data is retained. |
| Audit Governance | Append-only governance ledger, source registration, retention, query and export | Separate durable database and recovery policy. Billing outboxes bridge outages but never replace this system of record. |
| `snaplink-audit-provisioner` | Create-only Audit Governance tenant, source allow-list and schema desired state | One independent controller per desired-state authority. It uses a dedicated platform OAuth client and never shares relay credentials. |
| Aero ID / IM / Vault | Account, notification/chat and file resource transactions | Verify Snaplink access tokens locally. Reserve/commit metered work against the billing API using a pre-registered machine `client_id`; enforce gauges such as stored bytes in the resource owner's transaction. |
| `snaplink-console` and Aero UIs | Browser presentation only | Independently built static assets. The edge may mount them on one origin; no Go API process becomes a static host. |

A same-origin edge can route the suite without sharing process memory:

```text
https://id.example.com/{oauth,oidc,api/v1/admin/identity/*} -> sso-server
https://id.example.com/api/v1/admin/commerce/*             -> snaplink-billing
https://id.example.com/api/v1/metering/*                    -> snaplink-billing
https://id.example.com/api/v1/checkout/sessions             -> snaplink-stripe-adapter
https://id.example.com/webhooks/stripe                      -> snaplink-stripe-adapter
https://id.example.com/admin/                               -> snaplink-console assets

internal Aero service -> cached Snaplink JWKS validation
internal Aero service -> billing machine API (client_credentials + source binding)
billing durable outbox -> Audit Governance (client_credentials + registered source)
billing entitlement cursor -> Audit Governance retention policy (dedicated platform client)
Stripe adapter -> billing payment API (per-tenant client_credentials + binding)
audit provisioner -> Audit Governance control API (dedicated platform client)
```

The edge must strip and re-set forwarding headers, enforce TLS, keep probes on
an operations-only path, and route a given API prefix to exactly one owner.
Business APIs validate issuer, audience, signature and exact scope again at the
service boundary; trusting the edge alone is insufficient. A metering request
never supplies its own tenant or source identity: the signed `client_id` maps to
one server-owned binding containing tenant, source and allowed dimensions.

Keep the service availability decisions independent:

- scaling `sso-server` requires shared OAuth/session stores and invalidation;
- scaling `snaplink-billing` requires one serializable commerce/usage database
  plus unique Audit, quota-projection and renewal lease owners, but no sticky sessions; all
  replicas may run the opt-in renewal worker because claims use
  `FOR UPDATE SKIP LOCKED` and settlement rechecks the exact lease generation;
- scaling `snaplink-stripe-adapter` requires one PostgreSQL inbox/mapping store
  and identical immutable bindings across replicas. Claims use `SKIP LOCKED`,
  an expiring lease and generation fencing; event-id receipts plus unique
  normalized effect keys prevent both same-event and same-effect replay. Keep
  backlog thresholds as alerts, not readiness eviction, and cap aggregate
  delivery concurrency against Billing and Stripe limits;
- entitlement-to-SSO quota delivery uses a cursor independent from Audit
  Governance. Register a dedicated least-privilege OAuth client, deploy the
  exact SSO audience and per-tenant derived source bindings first, then enable
  Billing. Inactive/expired/core-disabled snapshots still send explicit
  hard-zero, so an SSO outage cannot accidentally reopen legacy unlimited
  limits. Cursor lag has its own Billing readiness check and recovers by replay;
- when commercial audit retention is enabled, that same entitlement cursor
  also writes the latest finite retention grant through a distinct client with
  exactly `audit:platform:cross_tenant audit:policy:write`. The cursor is not
  acknowledged until both SSO and Audit Governance succeed; retries are
  idempotent, and retention changes archive eligibility without deleting the
  immutable governance ledger or overriding legal holds;
- the optional Billing audit-relay desired-state file must be rolled out with
  one monotonic revision across replicas before sending `SIGHUP`; each process
  derives generation-specific lease owners and reports a rejected revision via
  readiness, while endpoint and OAuth credential rotation remains a restart;
- the Audit Governance provisioner polls and accepts SIGHUP, but only creates
  exact records. Omission never deletes, 409 is followed by exact comparison,
  and stale/equivocal/remote-drift state degrades its own readiness while
  preserving the last applied revision;
- scaling an Aero resource service requires its own durable resource database
  and idempotency contract. A successful remote quota pre-check alone cannot
  make a local file or message transaction atomic.

**Do not** carve the OAuth protocol itself into per-endpoint services
(login/token/userinfo): it would add latency and break the shared-session and
oracle-leak invariants for no benefit. Scale by *replicas + shared store*, not
by splitting the protocol.

Deploy the provisioner only after SSO and Audit Governance are reachable and
before enabling the event relays. Production examples are provided for
Kustomize (`ops/deploy/audit-provisioner`), Helm
(`ops/deploy/helm/snaplink-audit-provisioner`), Compose's optional
`audit-provisioning` profile, and host-native systemd. Desired state contains no
secret. Mount the dedicated client secret read-only, grant exactly
`audit:platform:cross_tenant audit:policy:read audit:policy:write` for one
resource, and keep the status listener on an operations-only network.
Secret rotation is a rolling restart: SIGHUP reloads the desired manifest, not
startup endpoint or credential configuration.

## 9. Operational invariants

- **X-Forwarded-\* trust** — only safe behind an edge that *strips and re-sets*
  `X-Forwarded-*`; the same governs `security.mtls.backend: header`, rate-limit
  IP keying, and mesh `X-Auth-*` headers.
- **Clock** — session refresh needs a forward/monotonic wall clock; ops must
  **slew, never step**.
- **Signing-key cutover** is fail-safe (deferred retire only widens the verify
  window; it never retires early).
- **Anti-enumeration / oracle-leak** behavior is uniform across replicas — don't
  add a per-replica fast path that changes an error code.

See also: [`README.md`](../README.md), [`config-reference.md`](config-reference.md),
[`observability.md`](observability.md), [`adr/ADR-0007`](adr/ADR-0007-directory-fanout-and-the-monolith-exemption-class.md).
