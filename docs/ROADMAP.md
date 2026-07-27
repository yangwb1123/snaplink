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

### 5. Isolate the SSO edition hierarchy

The resolver, inherited profiles, module lock, compatibility builds and
profile-specific entry points are implemented. `sso-prototype` is a buildable
preview from `cmd/sso-minimal`: it provides an in-memory, loopback-only
Authorization Code + PKCE OIDC flow and exercises opaque HttpOnly OP-session
reuse across two registered clients in an HTTP integration test. It preserves
the original `auth_time`, but does not yet provide browser end-to-end evidence;
that requires the separate same-origin login frontend.

That behavior is usable for evaluation, but it is not physical isolation.
`cmd/sso-minimal` still reaches the broad dependency graph through
`interfaces/sso`, and its OP-session adapter does not yet place the canonical
session SID into the authorization code and resulting tokens.

Deliverables:

- Move OP-session creation, `prompt`/`max_age`, logout and SID propagation into
  the canonical session/authorization-code lifecycle.
- Extract standard typed route and capability registrars outside `cmd/`.
- Isolate core HTTP, identity/OAuth stores, password authentication, Ed25519
  signing and OIDC packages without changing the prototype wire behavior.
- Prove physical removal with `go list`, `go version -m`, symbols, binary-size
  deltas and per-profile SBOMs.
- Make the inherited `sso-production` profile buildable with durable state,
  security controls, observability and supported topology evidence.
- Make `sso-complete` buildable only after the production base and its advanced
  protocol/product modules have independent release evidence.
- Keep `oauth-client-credentials` as an independent optional machine-to-machine
  module rather than an SSO profile foundation.
- Migrate SAML, LDAP/Kerberos/RADIUS, KMS/HSM and other nested modules to the
  standard host API after that boundary is stable.
- Add generation leases, static route slots and drain before classifying any
  in-process capability as hot; keep installable third-party code out of
  process.
- Publish profile locks, binary SBOMs, signatures and provenance.

## P1 — production completeness

### 6. Expand snapshot/DR control-plane coverage

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

### 7. Reach API-client parity

The generated TypeScript and Python clients cover a curated subset.

Deliverables:

- Derive clients from the reconciled OpenAPI contract.
- Cover admin, self-service, SCIM, SSF and Federation operations intended for
  public consumption.
- Add SemVer/API-diff checks and publish versioned packages only after the
  contract is stable.

### 8. Define the external frontend release contract

Frontend implementation is outside this repository. Backend work is limited to
stable APIs and integration metadata.

Deliverables:

- Version login UI metadata, branding, consent, setup and error contracts.
- Document CSP/cookie/reverse-proxy requirements for separately deployed UIs.
- Add cross-project compatibility tests; do not re-introduce static SPA bundles
  into `sso-server`.

### 9. Strengthen secrets at rest

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
5. Canonical OP-session/SID integration and physical profile isolation.
6. Snapshot schema v2 and API-client parity.
7. New protocol families only after the production-completeness work above.
