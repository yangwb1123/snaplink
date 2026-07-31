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

### 1. Derive generated SDK inputs from committed contracts — DONE

Runtime/OpenAPI drift is blocked by `python cli.py check-routes`;
capability availability is declared in `ops/build/capabilities.json`.
Generated SDK inputs are now derived from committed contracts:

Delivered:

- `ops/build/sdk-surface.json` declares the generated-SDK operation surface
  as validated data (grouped, capability-linked, with per-language
  compatibility policy); the generators (`cmd/gensdk`) carry no allowlist
  of their own.
- `python cli.py sdk-surface check` validates the registry against
  `docs/openapi.yaml` (every operationId must exist) and
  `ops/build/capabilities.json` (every capability reference must exist),
  and `sdk-surface generate` re-emits every language from the registry.
- The compatibility policy (additive, semver-tracked, operationId
  verbatim naming) is committed in the registry itself.

### 2. Produce auditable OIDC/FAPI conformance evidence — PARTIAL

The harness in `test/oidc-conformance/` is repaired and runnable as
checked in: the official suite image is pinned to a release tag
(`registry.gitlab.com/openid/conformance-suite:release-v5.2.1`), the server
under test uses a committed, `--validate-only`-checked config, and the
supported-profile allowlist excludes implicit/hybrid (the runtime rejects
those response types). What remains is the interactive run itself: a
browser-driven suite run with archived plan/result artifacts per the
harness README, and an official OpenID Foundation listing before any
certification language is used.

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

### 5. Isolate the SSO edition hierarchy — PARTIAL (core isolation landed; nested-module migration + release signing remain)

The resolver, inherited profiles, module lock, compatibility builds and
profile-specific entry points are implemented. The public hierarchy is
`prototype → minimal → full`: the prototype is SSO/OAuth with JSON logs
and a stable default-tenant seam; minimal adds OIDC and tracing; full
selects the complete current stock `sso-server` composition plus the
registered Kafka audit cold module. Version output carries the edition
suffix.

Delivered:

- **Canonical OP-session/SID lifecycle**: OP-session creation,
  `prompt`/`max_age` resume, logout and SID propagation now live in the
  canonical session/authorization-code lifecycle. `AuthResult` carries
  SessionID/CreateSession; the code flow creates/validates sessions through
  the SessionManager, stamps SID into the code, and the exchange-minted
  id_token emits the sid claim. The minimal edition's parallel
  `opSessionStore` is gone — its cookie IS the canonical session ID
  (see `cmd/sso-minimal/op_session.go` and the SID propagation test).
- **Standard typed registrars outside cmd/**: `platform/registrar` is the
  single generic typed registry; the SAML route registrar moved to the new
  `interfaces/ssoext` host API; `serverbuildsign`'s external-signer
  registry now builds on the same machinery.
- **Physical isolation + evidence**: `python cli.py profiles evidence`
  builds every profile binary, asserts the declared
  `ops/build/profile-isolation.json` boundaries (the small editions must
  not link the durable/admin/observability graph; the full edition must
  link it) and archives per-binary package lists, `go version -m` SBOMs,
  symbol counts and size deltas under `dist/profiles/`. Wired into
  `make ci`. Full-profile evidence (durable state, security controls,
  observability, topology) is documented in
  `docs/architecture/profile-isolation.md`.
- **Module discipline**: `oauth-client-credentials` is verified as an
  independent optional machine-to-machine cold module (conflicts with the
  stock server; not a profile foundation). Nested modules remain separate
  Go modules; the standard host API (`interfaces/ssoext` +
  `platform/registrar`) is the migration target.

Remaining:

- Migrate SAML, LDAP/Kerberos/RADIUS, KMS/HSM and other nested modules to
  the standard host API now that the boundary is stable.
- Add generation leases, static route slots and drain before classifying
  any in-process capability as hot; installable third-party code stays out
  of process.
- Publish profile locks, binary SBOMs, signatures and provenance for
  release artifacts (evidence bundles exist; release signing is the
  release pipeline's job — see docs/RELEASE.md).

## P1 — production completeness

### 7. Reach API-client parity — DONE

The generated TypeScript and Python clients cover the complete documented
operation set.

Delivered:

- Clients are derived from the reconciled OpenAPI contract via the
  `ops/build/sdk-surface.json` registry (validated by
  `python cli.py sdk-surface check`); no route or edition metadata is
  duplicated in the generators.
- Admin, self-service, SCIM, SSF and Federation operations intended for
  public consumption are all covered (312 operations).
- The compatibility policy (additive, semver-tracked, operationId
  verbatim naming) is committed in the registry.

Remaining (non-blocking): SemVer/API-diff checks and versioned package
publication once the contract is declared stable by the maintainers.

### 8. Define the external frontend release contract — DONE

Frontend implementation is outside this repository. Backend work is limited to
stable APIs and integration metadata.

Delivered:

- [docs/frontend-contract.md](../frontend-contract.md) versions the login,
  consent, setup, self-service, admin and error contracts (JSON shapes,
  oracle-safe error vocabulary, session_id/sid semantics).
- CSP/cookie/reverse-proxy requirements for separately deployed UIs are
  documented (deployment shape + proxy section of that file).
- Cross-project compatibility tests: `test/frontend_contract_test.go` walks
  the documented contract end-to-end from outside the server (discovery,
  PKCE login, token exchange, `/me`, endpoint inventory, error vocabulary,
  logout), so drift fails CI. No static SPA bundle is re-introduced into
  `sso-server`.

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
