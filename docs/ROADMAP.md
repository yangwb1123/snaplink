# Roadmap

> Current planning baseline, verified against the repository on 2026-07-28.
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

### 1. Derive generated SDK inputs from committed contracts

Runtime/OpenAPI drift is now blocked by `python cli.py check-routes`: it
compiles the real Go route constants, compares every statically registered
stock-server route with OpenAPI and rejects missing or duplicate operation
identifiers. Capability availability is now declared in
`ops/build/capabilities.json`; `python cli.py capabilities check` validates its
runtime-gate/module links and blocks generated feature-matrix drift. The
remaining work is to derive generated SDK inputs from these committed
contracts.

Deliverables:

- Define supported generated SDK languages and their compatibility policy.
- Generate SDK operation surfaces from OpenAPI and capability availability
  without duplicating route or edition metadata.

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

### 4. Remove obsolete frontend configuration semantics — DONE

The parsed `hosted_login` block has no runtime frontend to enable:
`feature_gates.branding` (renamed from `web_spa`) now controls only the
public `/branding` lookup.

Delivered:

- `hosted_login` is a parsed no-op with a loud startup deprecation warning;
  removal lands with the next schema-version bump.
- `feature_gates.web_spa` is a deprecated alias of the canonical
  `feature_gates.branding`; both set fails loud at boot, only `web_spa`
  warns and folds into `branding`. SDK `FeatureGates.Branding` is the
  canonical field; `WebSPA` remains a source-compatible alias. Runtime gate
  name, metric label, audit reason and reload paths use `branding`;
  `/feature_gates/web_spa` reload paths stay accepted.
- The external-frontend API contract (login, consent, self-service, admin,
  first-run setup, CSP/cookie/proxy requirements) is published in
  [frontend-contract.md](frontend-contract.md).

### 5. Isolate the SSO edition hierarchy

The resolver, inherited profiles, module lock, compatibility builds and
profile-specific entry points are implemented. The public hierarchy is
`prototype → minimal → full`: the prototype is SSO/OAuth with JSON logs
and a stable default-tenant seam; minimal adds OIDC and tracing; full
selects the complete current stock `sso-server` composition plus the registered
Kafka audit cold module. Version output carries the edition suffix.

The two smaller editions are usable for evaluation, but are not yet physically
isolated. Both target `cmd/sso-minimal`, which still reaches the broad
dependency graph through `interfaces/sso`; their OP-session adapter does not
yet place the canonical session SID into the authorization code and resulting
tokens.

Deliverables:

- Move OP-session creation, `prompt`/`max_age`, logout and SID propagation into
  the canonical session/authorization-code lifecycle.
- Extract standard typed route and capability registrars outside `cmd/`.
- Isolate core HTTP, identity/OAuth stores, password authentication, Ed25519
  signing and OIDC packages without changing either smaller edition's wire
  behavior.
- Prove physical removal with `go list`, `go version -m`, symbols, binary-size
  deltas and per-profile SBOMs.
- Prove the `full` profile against durable state, security controls,
  observability and supported topology evidence.
- Keep `oauth-client-credentials` as an independent optional machine-to-machine
  module rather than an SSO profile foundation.
- Migrate SAML, LDAP/Kerberos/RADIUS, KMS/HSM and other nested modules to the
  standard host API after that boundary is stable.
- Add generation leases, static route slots and drain before classifying any
  in-process capability as hot; keep installable third-party code out of
  process.
- Publish profile locks, binary SBOMs, signatures and provenance.

## P1 — production completeness

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

Non-prioritized product directions remain in
[deferred-backlog.md](deferred-backlog.md); they do not enter release ordering
until promoted here.

## Release ordering

1. Contract/capability synchronization.
2. Conformance evidence and release-gate integrity.
3. Obsolete frontend-config migration.
4. Canonical OP-session/SID integration and physical profile isolation.
5. API-client parity and the external frontend contract.
6. New protocol families only after the production-completeness work above.
