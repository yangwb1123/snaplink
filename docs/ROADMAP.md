# Roadmap

> Current planning baseline, verified against the repository on 2026-08-20.
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

### 2. Produce auditable OIDC/FAPI conformance evidence — PARTIAL (headless + local HTTP/HTTPS topologies landed; FAPI local follow-up reached the query-suffix boundary; external official run + OIDF listing + archive upload strategy remain)

The harness in `test/oidc-conformance/` is repaired and **headless-runnable
as checked in**: the official suite image is pinned to a release tag
(`registry.gitlab.com/openid/conformance-suite:release-v5.2.1`), the server
under test uses a committed, `--validate-only`-checked config, and the
supported-profile allowlist excludes implicit/hybrid (the runtime rejects
those response types). `./run-headless.sh` drives the whole run — build,
DCR-register the suite's OIDC login client, signup admin user, create the
Basic-certification discovery plan, run a module through headless Chrome
(auto-fulfilling the JSON logins), and archive plan/log/info under
`results/<commit>[-https]/`.

Smoke evidence (local topologies, suite `release-v5.2.1`, `oidcc-server`
module of the Basic discovery+dynamic plan):

- HTTP issuer baseline trio (`results/34ea1d3d/`, `results/af3bc485/`,
  `results/7400ba0c/`): **59 SUCCESS + 1 FAILURE** each; the sole failure
  is the expected `VerifyClientManagementCredentials` https-URI
  requirement.
- HTTPS issuer behind the self-signed local proxy
  (`results/7400ba0c-https/`): **60 SUCCESS + 0 FAILURE** — the https-only
  client-management check now passes (`registration_client_uri` is
  `https://sso-issuer:8181/...`).

FAPI 2.0 SP follow-up evidence is also archived. The first executable run at
`07832dda` reached the happy-flow module and produced **12 SUCCESS + 1
FAILURE** at the suite's static-client callback lookup. The redirect-pattern
follow-up at `1b2867c6` (HTTPS local topology) accepted the static clients,
discovery/JWKS checks, the first per-test callback, PAR, token exchange,
DPoP-protected UserInfo, callback `state`/`iss`, and TLS cipher checks; it
recorded **156 SUCCESS + 1 FAILURE + 3 WARNING** before the suite's second
client appended a query suffix to its callback. The current opt-in unlock is
`redirect_uri_patterns`: HTTPS only, fixed host, and exactly one interior path
segment wildcard (`https://host/test/*/callback`); query-bearing candidates
remain deliberately rejected by the v1 grammar. See
[redirect-uri-patterns](design/redirect-uri-patterns.md) and the detailed
[conformance evidence](sso/oidc-conformance.md).

The certification-readiness evidence kit (evidence table, reproduction
manual, module coverage matrix, remaining blockers) is packaged in
[oidc-conformance.md](sso/oidc-conformance.md).

Remaining: decide and review any future query-bearing callback-pattern
extension separately; then run the suite against an externally reachable
HTTPS issuer (requires deployment; the local HTTPS topology is self-signed
and non-reachable), submit through an OpenID Foundation account, and define an
archive upload strategy for the release that claims the run — before any
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

### 5. Isolate the SSO edition hierarchy — PARTIAL (core isolation, nested-module host API, and bounded stock hot lifecycle landed; arbitrary third-party business routes remain deferred)

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
  (see `internal/composition/op_session.go` and the SID propagation test).
- **Standard typed registrars outside cmd/**: `platform/registry/typed` is the
  single generic typed registry; the SAML route registrar moved to the new
  `interfaces/ssoext` host API; `serverbuildsign`'s external-signer
  registry now builds on the same machinery.
- **Physical isolation + evidence**: `python cli.py profiles evidence`
  builds every profile binary, asserts the declared
  `ops/build/profile-isolation.json` boundaries (the small editions must
  not link the durable/admin/observability graph or each other's
  composition root; the full edition must
  link it) and archives per-binary package lists, `go version -m` SBOMs,
  symbol counts and size deltas under `dist/profiles/`. Wired into
  `make ci`. Full-profile evidence (durable state, security controls,
  observability, topology) is documented in
  `docs/architecture/profile-isolation.md`.
- **Module discipline**: `oauth-client-credentials` is verified as an
  independent optional machine-to-machine cold module (conflicts with the
  stock server; not a profile foundation). Nested modules remain separate
  Go modules; the standard host API (`interfaces/ssoext` +
  `platform/registry/typed`) is now the canonical integration boundary for the
  nested protocol and infrastructure adapters.
- **Nested-module migration**: the B9 physical split and module-boundary
  migration is complete; each nested module owns its `go.mod` and no
  `go.work` is used.

Remaining:

- The reusable generation manager, lease accounting, fixed route slots,
  readiness/drain lifecycle and an independent billing audit-relay proof now
  exist. Stock `sso-server` wires the precompiled ReBAC `/authz/check` route
  through a generation lease with readiness, graceful disable and bounded
  transition audit, and wires the generic webhook exporter as a narrowly
  scoped dynamic audit tap. Provenance admission and stock-server worker
  configuration are complete for the narrow `audit.external_worker`
  capability. Local workers require signed module/release/profile provenance
  and remote workers require mTLS with optional SPIFFE checks; arbitrary
  third-party business routes remain deliberately out of process/cold.

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
  public consumption are all covered (321 operations, as reported by the registry gate).
- The compatibility policy (additive, semver-tracked, operationId
  verbatim naming) is committed in the registry.
- `python cli.py sdk-surface diff --baseline-ref <ref>` (or
  `--baseline-file <path>`) compares the real registry group/operation data
  with an explicit local baseline. A ref reads the registry and
  `docs/openapi.yaml` from the same local commit without fetching; a registry
  file remains explicitly registry-only unless paired with
  `--baseline-openapi-file`. The report stably separates operation surface and
  schema breaking/additive changes. The bounded `components.schemas` diff
  catches schema/property removal, required additions, `$ref`/type/format
  changes, `additionalProperties` tightening, enum removals, and nested/items
  breaking changes; optional properties, required removals, and enum additions
  are additive. Documentation metadata is ignored, while composition and
  unsupported keyword changes are conservatively breaking. Bad refs, JSON/YAML,
  missing files, and malformed schema structures fail closed. No version is
  changed automatically, and the SDK CI runs the check against the pull
  request base with a full local checkout.
- `python cli.py sdk-surface versions` now reads the four fixed package
  manifests, validates SemVer 2.0.0 and the TypeScript lock root, and compares
  all package versions. `sdk-surface check` and `make ci` execute this same
  read-only gate; the current four package versions are `0.3.0`.

Remaining (non-blocking): versioned package publication once the contract is
declared stable by the maintainers. Versioned package publication remains an
external boundary owned by the registry-specific workflows. The schema check
is intentionally a bounded structural subset, not a complete vendor-level
OpenAPI diff.

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
