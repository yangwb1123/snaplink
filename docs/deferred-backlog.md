# Deferred Backlog and Intentional Limits

Verified against the repository on 2026-08-20.

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
| `cmd/sso-prototype` / `cmd/sso-minimal` / `prototype` / `minimal` | **Implemented** | Two buildable single-process editions with dedicated composition roots: `prototype` exposes SSO/OAuth and JSON logs; `minimal` adds OIDC and tracing. The edition roots share `internal/composition`; each is physically isolated from the other root and from the durable/admin/observability graph, declared in `ops/build/profile-isolation.json` and proven by `python cli.py profiles evidence` (packages, modules, symbols, size). Not production topologies or browser-E2E artifacts. |
| Hosted login, admin, self-service, developer and setup UIs | **External** | Separate frontend projects, normally reverse-proxied beside the server. No static SPA is served by this repository; the API contract those projects must consume is [frontend-contract.md](frontend-contract.md). |
| Admin API-doc viewer | **Implemented** | `WithAPIDocsUI` serves an admin-gated, self-contained API reference. It is not an application UI. |
| TypeScript/Python SDKs | **Implemented** | Generated from `docs/openapi.yaml` via the `ops/build/sdk-surface.json` registry (full documented operation set: admin, SCIM, SSF, Federation included); validated by `python cli.py sdk-surface check`. Not yet published as versioned packages. |
| Nested protocol/infrastructure modules | **Implemented** | Strict cold-build profiles and the Kafka static adapter are implemented. The standard host API (`interfaces/ssoext` on `platform/registry/typed`) now exists outside `cmd/`; SAML (consumed via `saml.handler`), the LDAP/Kerberos/RADIUS authenticator families, and the KMS external-signer family (awskms/gcpkms/azurekeyvault/pkcs11) are migrated onto it — each nested module embedding the corresponding `ssoext` Deps bundle (`ldapauth.Deps` / `kerberosauth.Deps` / `radiusauth.Deps` / the four `kms/*` `Deps` embedding `ssoext.ExternalSignerDeps`) and exposing a `Build` adapter. `keys.signing.external` resolves through the canonical `ssoext.ExternalSignerRegistry`; `serverbuildsign`'s `ExternalSignerFactory` / `ExternalSignerRegistry` / `RegisterExternalSigner` are delegating aliases kept so pre-existing fork binaries compile and behave identically, and the health/metrics/readiness wrapping stays in `serverbuildsign`. No remaining migration work. |

## Partial capabilities

### Static build modules and runtime plugin lifecycle

The catalog, profile inheritance, dependency planner, alternate module graph,
module lock and compiled inventory are implemented. The edition hierarchy is:

| Profile | Status | Open boundary |
|---|---|---|
| `prototype` | Preview, buildable | SSO/OAuth + JSON logs + stable `default` tenant seam; own composition root `cmd/sso-prototype`, physically isolated from `cmd/sso-minimal` and the durable/admin/observability graph |
| `minimal` | Preview, buildable | Inherits `prototype`; adds OIDC and tracing on its own composition root `cmd/sso-minimal`, physically isolated from `cmd/sso-prototype` |
| `full` | Supported, buildable | Inherits `minimal`; selects the complete current stock `cmd/sso-server` composition and registered Kafka audit cold module |
| `standard`, `standard-kafka` | Supported | Compatibility builds, not edition-layer isolation evidence |

The two smaller editions use an opaque HttpOnly cookie bound to the
CANONICAL session (created by the authorization-code flow, SID propagated
through code and tokens) but have no bundled login UI or browser end-to-end
proof. Their session adapter lives in `internal/composition`; package, symbol,
size and SBOM checks (`python cli.py profiles evidence`) now back the
physical dependency isolation claim, including the per-edition composition
roots.

`oauth-client-credentials` is an independent optional machine-to-machine
module, not an SSO edition baseline.

Runtime `FeatureGates` hide already wired routes; they do not load, unload or
drain code. The reusable lifecycle manager provides generation leases, fixed
route slots, hot readiness/drain and transition observation, and the
independent billing service exercises it for a low-risk audit relay. The stock
`sso-server` now wires the precompiled generic webhook exporter as a narrow
dynamic audit tap; the external-process supervisor now provides a typed,
digest-pinned Unix/TLS host/worker boundary, signed provenance admission for
local workers and SPIFFE-aware mTLS for remote workers. The stock server now
exposes one narrowly scoped `audit.external_worker` product path. The stock
server now integrates the precompiled ReBAC `/authz/check` business route
through a fixed generation slot with readiness, graceful drain and transition
audit; arbitrary third-party business route workers remain deferred. See
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
exist. The harness is headless and repeatable (`run-headless.sh`, pinned to
`registry.gitlab.com/openid/conformance-suite:release-v5.2.1`), stays
outside default CI, and archives its runs under
`test/oidc-conformance/results/<commit>[-https]/` (git-ignored). Local smoke
topologies pass the `oidcc-server` Basic-certification module (HTTP issuer:
59 SUCCESS + 1 expected https-only failure; HTTPS issuer behind a self-signed
local proxy: 60 SUCCESS). No official OpenID Foundation result or
certification listing is recorded. The remaining boundary: an official run
against an externally reachable HTTPS issuer with a CA-trusted certificate,
and an issued OIDF listing. See [sso/oidc-conformance.md](sso/oidc-conformance.md).

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
multi-replica deployments. Lifecycle transitions are now also projected onto the
CAEP/SSF event channel: the existing transmitter maps
`admin_user_lifecycle_changed` to signed SETs (`risc/account-disabled` +
`caep/session-revoked` on non-active targets, `risc/account-enabled` on
reactivation) pushed to the affected tenant's opted-in clients — the
standardized event channel for resource servers that validate JWTs fully
offline. The fan-out resolves receivers through the user's OWN tenants
(`caep.WithTenantUserStore`); the stock binary does not wire tenant membership,
so in a default deployment lifecycle events resolve to no receivers
(conservative silence, never a broadcast-to-all). See
[design/lifecycle-caep-events.md](design/lifecycle-caep-events.md).

### SMTP transport

The built-in sender uses `net/smtp`: STARTTLS is negotiated when advertised but
may fall back to plaintext. Implicit TLS on port 465 is supported via a
`crypto/tls.Dial`-first transport, auto-selected on port 465 or with
`smtp.tls_mode: implicit`; certificate verification is fail-closed (ServerName
pinned to the relay host, TLS 1.2 floor, no `InsecureSkipVerify`). Require TLS
at the relay/edge when plaintext fallback on STARTTLS-capable ports is
unacceptable.

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
- `SSOConfigDrift` CRD/reconciler for periodic comparison, report-only by
  default, with an opt-in apply mode: when `spec.apply.enabled` AND the
  one-shot approval annotation (`sso.snaplink.io/apply-approve: "true"`)
  AND a non-empty diff are present, the reconciler POSTs cluster A's
  (server-redacted) running snapshot to cluster B's
  `/api/v1/admin/config/apply?approve=true` (with its canonical digest and
  `spec.apply.reason`) and records the outcome in `status.apply`. The
  approval is consumed after one successful apply (at most one apply per
  approval, latency ≤ PollInterval), and an apply failure never suppresses
  the drift report (fail-open). A separate explicit rollback mode requires
  `spec.rollback.enabled`, a reason, an expected current version, and the
  one-shot `sso.snaplink.io/rollback-approve` annotation; the server applies
  an atomic CAS guard and the controller records the outcome in
  `status.rollback`. Designs:
  `docs/design/operator-config-apply.md` and
  `docs/design/operator-config-rollback.md`.
- Secret references and status reporting within the operator's namespace
  permissions.
- `POST /api/v1/admin/config/apply` and `.../config/rollback` — the
  declared peer-config baseline write path: an operator applies a peer
  cluster's snapshot (verified against its sha256 digest — split-brain
  guard) as this cluster's new applied baseline, gated by `admin:write` +
  mandatory `?approve=true`; the write is transactional (baseline +
  `config_history` entry in one write), stores only redacted snapshots,
  retains every version for rollback, and emits
  `admin_config_applied`/`admin_config_rolled_back` audit events (metadata
  only). Design: `docs/design/config-apply-mode.md`.
- Optional `?canary=true&window=...` apply observation — requires an existing
  predecessor, persists `observing|confirmed|rolled_back` state in the
  built-in Memory/SQLite stores, rejects concurrent mutations, rolls back on a
  definitive unhealthy probe, and recovers an interrupted observation by
  rolling back on process restart. Unknown probe results fail open. Design:
  `docs/design/config-canary-apply.md`.

Not committed:

- GitOps reconciliation.

The apply and explicit rollback paths carry the authority/approval model,
secret-redaction rules, CAS rollback semantics and split-brain handling the
boundary requires. Rollback is never inferred from drift or health and does
not mutate runtime configuration. GitOps still needs its own rollout-ordering
and source-of-truth model.
Diff-only behavior remains fail-open and non-mutating (the apply path
records a declared baseline, it never mutates live runtime config).

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

**Status: Implemented (opt-in).**

The degradation manager, admin mode endpoint, and the in-process auto driver
now exist. With `degradation.auto_read_only_on_store_loss: true` the server
polls its wired storage-health sources (every store with a Ping, audit sinks
excluded — audit is fail-open by contract) and drops to `read_only` after
`degradation.auto_read_only.grace` of continuous loss, restoring the configured
`initial_mode` on recovery. Each replica still runs its own pull-based health
loop; cross-replica coordination (a cluster-wide decision) remains an external
controller's job via the same mode endpoint. See
[design/degradation-auto-driver.md](design/degradation-auto-driver.md).

## Baseline maintenance rule

When a capability changes:

1. Update its row in `feature-matrix.md`.
2. Update this file if a known limitation closes or a new intentional boundary
   is introduced.
3. Update OpenAPI/config/error documentation in the same change.
4. Keep completed implementation narratives out of this backlog; Git history
   is the archive.
