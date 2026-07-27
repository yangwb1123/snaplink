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
| Hosted login, admin, self-service, developer and setup UIs | **External** | Separate frontend projects, normally reverse-proxied beside the server. No static SPA is served by this repository. |
| Admin API-doc viewer | **Implemented** | `WithAPIDocsUI` serves an admin-gated, self-contained API reference. It is not an application UI. |
| TypeScript/Python SDKs | **Partial** | Generated curated subset; not complete parity with admin/SCIM/SSF/Federation routes. |
| Nested protocol/infrastructure modules | **Partial** | Strict cold-build profiles and the Kafka static registrar are implemented. SAML, LDAP, Kerberos, RADIUS, ext-authz, MQTT and KMS/HSM still require custom composition or migration to the module host API. |

## Current implementation deviations

These are observed implementation/documentation drifts, not accepted product
limits. The target contract remains the invariant in `AGENTS.md`.

- **Device grant oracle collapse:** `AGENTS.md` §3 requires an unknown,
  expired, consumed or mismatched device code presented to `/token` to return
  `400 invalid_grant`. The current
  `internal/handler/tokengrant/token_device.go` implementation returns
  `expired_token` for the unknown/expired/consumed branches while using
  `invalid_grant` for client mismatch/store errors. Reconcile the handler and
  its tests to the invariant; do not treat the current distinction as a stable
  wire contract.

## Partial capabilities

### Static build modules and runtime plugin lifecycle

The catalog, dependency planner, alternate module graph, module lock, compiled
inventory, `standard` profile and `standard-kafka` profile are implemented.
The `minimal` profile is an executable extraction plan but deliberately fails
to build while its modules remain inside the stock composition.

Runtime `FeatureGates` hide already wired routes; they do not load, unload or
drain code. Generation leases, route guards, hot readiness/drain, dynamic
audit taps and the external-process supervisor are not implemented. See
[plugin-system.md](plugin-system.md) and ADR-0009.

### Static HTTP contract and generated clients

The runtime has recently added SSF, Federation, FGA, branding, provider and
device/security administration routes faster than the OpenAPI/generated-client
surface was updated. The configured replica's admin endpoint inventory is the
runtime truth; contract reconciliation is P0 in the roadmap.

### Official protocol certification

Protocol unit/integration tests and an OIDF conformance Docker Compose harness
exist. No official OpenID Foundation result or certification listing is
recorded. The harness is interactive, uses an unpinned conformance image and is
not part of default CI. See [sso/oidc-conformance.md](sso/oidc-conformance.md).

### Disaster-recovery snapshot scope

Snapshot schema v1 covers clients, users, roles, assignments, menus, network
policy and bootstrap state. It intentionally excludes sessions/tokens, and
currently also excludes tenants, enterprise connections, pairwise subject
mappings, MFA enrollments and signing private keys. Raw Postgres, Redis, SQLite
and etcd recovery remains operator-managed. See
[dr-framework.md](dr-framework.md).

### Multi-language SDK parity

The TypeScript/Python generators deliberately expose a curated surface. Go SDK
and direct HTTP/gRPC consumers have access to more features.

### Identity linking

The stock binary wires an in-memory identity-link store. The merge policy is an
extension point for custom login integrations; the stock `/auth/login` handler
does not perform account merging.

### User lifecycle

Lifecycle state is governance metadata with a memory store. It does not replace
`core.User.IsActive` and does not itself gate authentication.

### SMTP transport

The built-in sender uses `net/smtp`: STARTTLS is negotiated when advertised but
may fall back to plaintext. Implicit TLS on port 465 is not supported. Require
TLS at the relay/edge when plaintext fallback is unacceptable.

### CIBA

Poll, ping and push delivery seams exist. CIBA `user_code` mode is not
implemented.

## External/operator responsibilities

- Deploy and version frontend applications separately from `sso-server`.
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
