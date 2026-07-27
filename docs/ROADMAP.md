# Roadmap

> Current planning baseline, verified against the repository on 2026-07-27.
> Older roadmap revisions remain available in Git history; they are not kept
> inline because many of their gaps have since been implemented.

This roadmap records planned product work. It is not a compliance statement
and does not imply that a proposed item is committed to a release. Shipped
capabilities are catalogued in [feature-matrix.md](feature-matrix.md);
intentional limitations and open decisions are in
[deferred-backlog.md](deferred-backlog.md).

Delivery classes and the API-only/external-frontend boundary are defined in the
feature matrix and deferred backlog. This file contains priorities only; closed
work stays out of it.

## P0 — trustworthy contracts and release evidence

### 1. Synchronize routes, OpenAPI and capability metadata

The runtime has moved faster than the static documentation. Recent SSF,
Federation, FGA, branding, provider and device/security administration routes
must be represented consistently in OpenAPI and generated SDK inputs.

Deliverables:

- Generate or verify OpenAPI coverage from the runtime endpoint inventory.
- Add a CI failure for a new public route without an OpenAPI operation or an
  explicit internal-only exemption.
- Maintain one machine-readable capability registry with availability
  (`sdk`, `stock-binary`, `module-only`, `external-frontend`), default state,
  feature gate and required store.
- Generate the human feature matrix from that registry once the schema is
  stable.

### 2. Produce auditable OIDC/FAPI conformance evidence

The implementation has extensive local protocol tests, but this project has
not recorded an official OpenID Foundation conformance run and is not
certified. The current Docker Compose harness is browser-driven and outside
default CI.

Deliverables:

- Pin the official conformance-suite image instead of using `latest`.
- Define supported test profiles from actual response types and configured
  features; do not claim implicit or hybrid OP profiles while the runtime only
  accepts `code` and direct-mint `token`.
- Run the suite in a repeatable environment, archive plan/result artifacts and
  publish the tested commit/configuration.
- Only use “OpenID Certified” or FAPI certification language after an issued
  listing exists.

### 3. Make production topology failures loud

Memory and per-pod SQLite stores are valid for a single replica but cannot
provide cross-replica OAuth single-use semantics. A production deployment
should not silently combine multiple replicas with local auth-code, refresh,
session, PAR, device, CIBA, JTI or MFA-challenge state.

Deliverables:

- Validate replica/topology intent at startup or admission time.
- Require an explicit unsafe acknowledgement for multi-replica local state.
- Keep the production overlay on Redis hot stores, Postgres durable stores and
  an etcd event bus; test loss/recovery semantics against real backends.
- Reconcile engineering-gate documentation, generated thresholds and committed
  tests so a green release signal has one meaning.

### 4. Remove obsolete frontend configuration semantics

The parsed `hosted_login` block has no runtime frontend to enable.
`feature_gates.web_spa` now controls only the public `/branding` lookup.

Deliverables:

- Deprecate or remove `hosted_login` in a versioned configuration migration.
- Rename or clearly alias `web_spa` to a branding/API-oriented name without a
  silent compatibility break.
- Publish the API contract an external frontend must use for login, consent,
  self-service, admin and first-run setup.

## P1 — production completeness

### 5. Expand snapshot/DR control-plane coverage

Snapshot schema v1 includes clients, users, roles, assignments, menus, network
policy and bootstrap state. It intentionally excludes hot sessions/tokens, but
it also does not currently cover tenants, enterprise connections, pairwise
subject mappings, MFA enrollments or signing private keys.

Deliverables:

- Design snapshot schema v2 with per-category capability negotiation.
- Prioritize tenants, connections and pairwise subject mappings because their
  loss changes routing or external subject identity.
- Keep session/token state excluded and document re-authentication as the
  recovery behavior.
- Emit the required cache/invalidation events after restore.

### 6. Reach API-client parity

The generated TypeScript and Python clients cover a curated subset.

Deliverables:

- Derive clients from the reconciled OpenAPI contract.
- Cover admin, self-service, SCIM, SSF and Federation operations intended for
  public consumption.
- Add SemVer/API-diff checks and publish versioned packages only after the
  contract is stable.

### 7. Define the external frontend release contract

Frontend implementation is outside this repository. Backend work is limited to
stable APIs and integration metadata.

Deliverables:

- Version login UI metadata, branding, consent, setup and error contracts.
- Document CSP/cookie/reverse-proxy requirements for separately deployed UIs.
- Add cross-project compatibility tests; do not re-introduce static SPA bundles
  into `sso-server`.

### 8. Strengthen secrets at rest

Password/client credentials are hashed by their stores, but active OAuth bearer
artifacts such as SQLite refresh tokens and authorization/device codes are
stored as lookup keys in plaintext. Encrypted snapshots do not protect a live
database or Redis export.

Deliverables:

- Design deployment-keyed HMAC lookup keys and a backwards-compatible
  migration for active opaque artifacts.
- Preserve atomic consume, family replay detection and oracle-safe errors.
- Document key rotation and disaster-recovery implications before enabling the
  feature by default.

Non-prioritized product directions remain in
[deferred-backlog.md](deferred-backlog.md); they do not enter release ordering
until promoted here.

## Release ordering

1. Contract/capability synchronization.
2. Conformance evidence and release-gate integrity.
3. HA topology validation.
4. Obsolete frontend-config migration.
5. Snapshot schema v2 and API-client parity.
6. New protocol families only after the production-completeness work above.
