# Deferred Backlog and Intentional Limits

Verified against the repository on 2026-07-27.

This file and [feature-matrix.md](feature-matrix.md) form the bounded
functional-requirements baseline:

- The feature matrix records implemented protocol/product capabilities.
- This file records known partial capabilities, external product boundaries
  and deliberately deferred decisions.
- [ROADMAP.md](ROADMAP.md) prioritizes future work but does not turn every idea
  into a committed requirement.

Retired audits, plans, and migration records are summarized in
[HISTORY.md](HISTORY.md). They are research evidence, not a backlog or promise.

## Status vocabulary

| Status | Meaning |
|---|---|
| **Implemented** | Live code and tests exist; it may still require opt-in wiring. |
| **Partial** | A useful subset exists and the missing boundary is stated here. |
| **External** | Intentionally delivered by another project or operator. |
| **Deferred decision** | Not committed; requires a product/design decision before implementation. |

## Product-surface boundary

| Surface | Status | Boundary |
|---|---|---|
| Go SDK | **Implemented** | `interfaces/sso` exposes the broadest option surface. An SDK option is not automatically a stock-binary YAML feature. |
| `sso-server` | **Implemented** | Pure API backend: OAuth/OIDC, self-service/admin HTTP APIs and gRPC control plane. |
| `cmd/sso-minimal` / `prototype` / `minimal` | **Implemented** | Two buildable single-process editions: `prototype` exposes SSO/OAuth and JSON logs; `minimal` adds OIDC and tracing. Physical isolation from the durable/admin/observability graph is declared in `ops/build/profile-isolation.json` and proven by `python cli.py profiles evidence` (packages, modules, symbols, size). Not production topologies or browser-E2E artifacts. |
| Hosted login, admin, self-service, developer and setup UIs | **External** | Separate frontend projects, normally reverse-proxied beside the server. No static SPA is served by this repository; the API contract those projects must consume is [frontend-contract.md](frontend-contract.md). |
| Admin API-doc viewer | **Implemented** | `WithAPIDocsUI` serves an admin-gated, self-contained API reference. It is not an application UI. |
| TypeScript/Python SDKs | **Implemented** | Generated from `docs/openapi.yaml` via the `ops/build/sdk-surface.json` registry (full documented operation set: admin, SCIM, SSF, Federation included); validated by `python cli.py sdk-surface check`. Not yet published as versioned packages. |
| Nested protocol/infrastructure modules | **Partial** | Strict cold-build profiles and the Kafka static adapter are implemented. The standard host API (`interfaces/ssoext` on `platform/registrar`) now exists outside `cmd/`; migrating SAML/LDAP/Kerberos/RADIUS/KMS families onto it is the remaining work. |

## Partial capabilities

### Static build modules and runtime plugin lifecycle

The catalog, profile inheritance, dependency planner, alternate module graph,
module lock and compiled inventory are implemented. The edition hierarchy is:

| Profile | Status | Open boundary |
|---|---|---|
| `prototype` | Preview, buildable | SSO/OAuth + JSON logs + stable `default` tenant seam; shares the broad `cmd/sso-minimal` dependency graph |
| `minimal` | Preview, buildable | Inherits `prototype`; adds OIDC and tracing but is not yet physically isolated from it |
| `full` | Supported, buildable | Inherits `minimal`; selects the complete current stock `cmd/sso-server` composition and registered Kafka audit cold module |
| `standard`, `standard-kafka` | Supported | Compatibility builds, not edition-layer isolation evidence |

The two smaller editions use an opaque HttpOnly cookie bound to the
CANONICAL session (created by the authorization-code flow, SID propagated
through code and tokens) but have no bundled login UI or browser end-to-end
proof. Their session adapter lives in `cmd/sso-minimal`; package, symbol,
size and SBOM checks (`python cli.py profiles evidence`) now back the
physical dependency isolation claim.

`oauth-client-credentials` is an independent optional machine-to-machine
module, not an SSO edition baseline.

Runtime `FeatureGates` hide already wired routes; they do not load, unload or
drain code. Generation leases, route guards, hot readiness/drain, dynamic
audit taps and the external-process supervisor are not implemented. See
[plugin-system.md](plugin-system.md) and ADR-0009.

### Static HTTP contract and generated clients

Contract reconciliation is complete: `python cli.py check-routes` keeps the
runtime route inventory and OpenAPI in lockstep, and
`python cli.py sdk-surface check` keeps the generated clients reconciled with
both. The configured replica's admin endpoint inventory
(`GET /api/v1/admin/endpoints`) remains the runtime truth for what a given
deployment actually registers.

### Official protocol certification

Protocol unit/integration tests and an OIDF conformance Docker Compose harness
exist. No official OpenID Foundation result or certification listing is
recorded. The harness is interactive, uses an unpinned conformance image and is
not part of default CI. See [sso/oidc-conformance.md](sso/oidc-conformance.md).

### Disaster-recovery snapshot scope

Snapshot schema v2 adds an explicit category manifest plus tenants,
tenant-domain routing and enterprise connections while retaining v1 read
compatibility. It also preserves pairwise subject mappings and broadcasts a
full control-plane cache invalidation after a committed restore. It
intentionally excludes sessions/tokens, MFA enrollments and signing private
keys. Raw Postgres, Redis, SQLite and etcd recovery remains operator-managed.
See [dr-framework.md](dr-framework.md).

### Multi-language SDK parity

The TypeScript/Python generators expose the complete documented operation
surface (parity with the OpenAPI contract). Go SDK and direct HTTP/gRPC
consumers may still access runtime features that are not yet documented in
OpenAPI.

### Identity linking

The stock binary supports memory, SQLite and Postgres identity-link stores and
wires them into static and connection-backed OIDC federation. `link_only`
atomically moves identity-link ownership but deliberately does not merge
sessions, consents, tokens, MFA enrollments or historical audit ownership.
A first-party “connect another identity” ceremony remains an external
frontend/custom-authenticator flow because it requires fresh proof from both
accounts; the API never accepts an unverified provider/subject claim.

### User lifecycle

Lifecycle state now gates every stock end-user login continuation, user token
grant (including the human behind agent delegation), server-side access/ID-token
validation across the full `sub`/`act` chain, and introspection; non-active
transitions also revoke sessions and refresh tokens. It remains additive to
`core.User.IsActive`, and `client_credentials` remains outside this user gate.
The stock Postgres/Cockroach backend persists state and append-only history for
multi-replica deployments. A standardized event channel for resource servers
that validate JWTs fully offline remains future work.

### SMTP transport

The built-in sender uses `net/smtp`: STARTTLS is negotiated when advertised but
may fall back to plaintext. Implicit TLS on port 465 is not supported. Require
TLS at the relay/edge when plaintext fallback is unacceptable.

### CIBA user-code enrollment boundary

Poll, ping and push delivery, `requested_expiry`, exactly-one-hint validation,
and the optional `WithCIBAUserCodeVerifier` protocol seam are implemented.
The verifier owns user-code enrollment, rotation, constant-time comparison and
attempt limits; Snaplink does not store the submitted code or silently reuse
the user's OP password. CIBA Core deliberately leaves code registration out of
scope, so a first-party code-management ceremony remains an external frontend
or operator integration rather than a protocol-handler responsibility.

## External/operator responsibilities

- Deploy and version frontend applications separately from `sso-server`.
- Keep `prototype` and `minimal` on loopback and use them only for evaluation
  or integration; their memory state and command-level OP session are not a
  production topology.
- Use shared Redis hot stores, Postgres durable stores and an etcd event bus for
  multi-replica production; memory/per-pod SQLite state is single-replica.
- Back up and restore backend-native data. The DR framework only replicates its
  snapshot control-plane subset.
- Provide real DNS/LB promotion through the DR `ReplicaPromoter` seam.
- Configure SMTP/SMS, KMS/HSM, SAML/LDAP and other external dependencies.
- Run official conformance suites and retain evidence for claims made to
  customers or auditors.

## Deferred decisions

### Declarative multi-cluster configuration governance

**Status: Partial by design.**

Implemented:

- `POST /api/v1/admin/config/cluster-diff`.
- `SSOConfigDrift` CRD/reconciler for periodic, report-only comparison.
- Secret references and status reporting within the operator's namespace
  permissions.

Not committed:

- Applying peer configuration.
- Canary rollout or automated remediation.
- GitOps reconciliation.

These require an explicit authority/approval model, secret-redaction rules,
rollback semantics and split-brain handling. Diff-only behavior remains
fail-open and non-mutating.

### Verifiable credentials

**Status: Deferred decision.**

OID4VCI/OID4VP, SD-JWT VC, holder binding, DID resolution and token status
lists are not implemented and are not part of the current baseline. Revisit
only with a named user journey and pinned standards/interoperability target.

### Unified authorization policy language

**Status: Deferred decision.**

RBAC, conditional access, ReBAC/FGA and WASM authorization are independent by
design. No automatic translation or precedence model is promised.

### Automatic degraded-mode transitions

**Status: Deferred decision.**

The degradation manager and admin mode endpoint exist. Continuous storage
health currently remains pull-based; `auto_read_only_on_store_loss` records
operator intent but has no in-process driver. An external controller may drive
the mode endpoint.

## Baseline maintenance rule

When a capability changes:

1. Update its row in `feature-matrix.md`.
2. Update this file if a known limitation closes or a new intentional boundary
   is introduced.
3. Update OpenAPI/config/error documentation in the same change.
4. Keep completed implementation narratives out of this backlog; Git history
   is the archive.
