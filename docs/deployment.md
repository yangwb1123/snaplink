# Deployment & distributed architecture

How to build, run, deploy (Kubernetes / Compose), call, and scale snaplink/sso.
Every capability below is grounded in what the code actually does — where the
stock binary stops and the SDK begins is called out explicitly, because it
changes how you scale.

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
docker build -t snaplink/sso-server .      # the root Dockerfile
sso-server version                          # build version / VCS revision
```

Two binaries ship: **`sso-server`** (the runtime) and **`sso-ctl`** (offline
operator toolbelt: `audit-verify`, `import`, `migrate`, `snapshot`, `config
validate`, `hash`, `version`).

## 2. Run a single instance

```bash
sso-server --config config.yaml      # HTTP :8080, gRPC :8081
```

- **HTTP `:8080`** — OAuth2/OIDC + the REST admin plane (`/api/v1/admin/*`).
- **gRPC `:8081`** — the admin/control plane (`--grpc-listen ''` disables it).
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

| Concern | `backend:` values the binary wires |
|---|---|
| Stores (auth-code, refresh, session, consent, clients, users, par, device, ciba, mfa, password, …) | `memory` (default) · `sqlite` (needs `<concern>.sqlite.dsn`) |
| `cluster` (the cross-replica event Bus) | `memory` · **`etcd`** (`etcd_endpoints`, `etcd_prefix`, …) |
| `registry`, `netpolicy` | `memory` · `etcd` |
| `config` source | file · env · `etcd` |

> **Redis is NOT wired into the stock binary.** A full set of Redis store
> backends exists in `infrastructure/redis/` (auth_code, refresh_token, session,
> consent, clients, users, par, device_code, ciba, jti_replay, mfa_challenge,
> password_credentials, permissions, ratelimit) — but that is a **separate Go
> module**, reachable only via the SDK (so the redis client dependency stays out
> of the core). This is the pivotal fact for scaling — see §6.

## 4. How clients call it

| Caller | Surface | Detail |
|---|---|---|
| Any language (SPA / RP / resource server) | **HTTP OAuth2/OIDC** | `/.well-known/openid-configuration`, `/auth/login`, `/token`, `/userinfo`, `/.well-known/jwks.json`. Contract: [`docs/openapi.yaml`](openapi.yaml). |
| Ops / control plane | **gRPC `:8081`** + **REST `/api/v1/admin/*`** | services: admin (clients/users/tenants/permissions/releases/snapshots/tokens), authz, audit, discovery, netpolicy — gated by `admin:read` / `admin:write`. |
| **Go downstream service** | **`interfaces/ssoclient`** | `remote` verifies tokens **locally** against cached JWKS (the SSO server is **off the per-request hot path**) and calls authz/audit over gRPC; also `local` (embed), `dev` (allow-all), `bootstrap`. |
| Go app embedding SSO | **SDK** | `sso.NewServer(opts...).Handler()` on any `net/http` listener. |

Minimal RP flow over the wire:

```bash
curl https://sso.example.com/.well-known/openid-configuration
# /auth/login (PKCE captured here) -> {"code": "..."}
# /token (authorization_code + code_verifier) -> {"access_token","id_token"}
curl https://sso.example.com/userinfo -H 'Authorization: Bearer <access_token>'
```

## 5. Kubernetes

Manifests live in [`ops/deploy/k8s`](../ops/deploy/k8s) (Kustomize):

```bash
kubectl apply -k ops/deploy/k8s/
```

What the base gives you: a `Deployment` (pod anti-affinity, non-root + seccomp
hardening, `--config /etc/sso/config.yaml`, `SSO_*` env-override hooks), a
`Service` (8080/8081), a `ConfigMap` (hashed → rollout on change), and a
`namespace`. The kubelet hits `/livez` + `/readyz` (outside the rate limiter).

**Before production, in an overlay:** pin the image (`:latest` is for the
quickstart), add an `HPA` + `PodDisruptionBudget`, and — critically — pick a
**shared-state strategy (§6)**, because the base `replicas: 2` with the default
`memory` backend is **not** correct for stateful flows (next section).

`ops/deploy/compose/` runs the same image with Prometheus + Grafana
(dashboards/alerts provisioned) for a local/observability stack.

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
tokens, PAR/device/CIBA requests, MFA challenges live in **stores**, and the
binary's stores are `memory` (per-pod) or `sqlite` (file-local). **Neither is
shared across replicas.** Consequence:

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
| **B — HA, shared store via SDK** | N replicas, **Redis** stores (`infrastructure/redis`) + etcd Bus | true horizontal scale; requires building a binary that wires the redis module (SDK), or extending `sso-server` to wire it |
| **C — verification fleet** | Many downstream services, each `ssoclient/remote` (local JWKS) | always — this side scales freely regardless of the SSO server's tier |

> **Enabling Tier B with the stock binary is a deliberate architectural decision
> you make**, not a config flag today: either (1) embed via the SDK and wire the
> Redis backends, or (2) add Redis wiring to `cmd/sso-server` (which pulls the
> redis client into the core module's dependency tree — the reason it is a
> separate module is to keep that dependency opt-in). Pick consciously.

Reference distributed topology (Tier B):

```
            ┌────────────── TLS edge (OpenResty/Envoy) — strips+re-sets XFF
            ▼
   ┌───────────────────┐   N replicas, pod anti-affinity
   │  sso-server × N    │── gRPC/REST admin :8081
   └───────────────────┘
        │           │
        ▼           ▼
   Redis (shared    etcd (cluster Bus:
   stores: codes,   revocation, key
   sessions, …)     rotation, config,
                    registry, netpolicy)
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
| **Hot-path stores** (codes/sessions/tokens/…) | **Redis** (`infrastructure/redis`) | ⚠️ **SDK module only** |
| Signing offload | `infrastructure/kms/*` (AWS/GCP/Azure KMS, PKCS#11) | via config (separate modules) |

## 8. Microservices decomposition

The natural and supported split is **token *issuance* vs token *consumption***:

- **SSO server replicas** issue/login/admin — scale per §6 (Tier A or B).
- **Downstream services verify locally** (`ssoclient/remote`, cached JWKS) — they
  never call the SSO server per request. This is the key microservices win.
- **Independent deployables**: Redis, etcd, KMS/HSM, and the SAML-IdP / LDAP /
  RADIUS / ext-authz nested modules.
- The **gRPC control plane** *could* run on a separate exposure from the OAuth
  data plane (same binary), e.g. an internal-only admin Service.

**Do not** carve the OAuth protocol itself into per-endpoint services
(login/token/userinfo): it would add latency and break the shared-session and
oracle-leak invariants for no benefit. Scale by *replicas + shared store*, not
by splitting the protocol.

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
