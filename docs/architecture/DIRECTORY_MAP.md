# Directory map — the 30-second view

snaplink is an **OAuth 2.0 + OIDC + SAML + SCIM identity platform**, shipped as an
embeddable Go SDK plus a runnable server. The tree is **physically layered**: every
library package lives under its architectural layer directory, so the first path
segment IS the layer. The dependency direction is **enforced** by
`architecture_layer_test.go` (`TestArchitecture_LayerBoundaries`, package
`archgate` at the repo root, [ADR-0006](../adr/ADR-0006-cognitive-architecture.md)).

## Layered library layout

```
shared/          dependency-free kernel        core · spi · security · i18n · trust
domains/         business capabilities         tenant · region · permissions · federation · connections · metering · anomaly · authenticators · conditionalaccess · identitylink · threataction · tokenanomaly · tokenexchange · tokenpolicy · tokenusage · userlifecycle
protocols/       identity-protocol use-cases   oauth · oidc · scim · fapi · caep · selfservice · compliance · lifecyclereactions · scimprovision
platform/        cross-cutting capabilities    cluster · signingkeys · registry · netpolicy · metrics · tracing · bootstrap · buildinfo · releases · migrate · geo · audit · sse · configaudit · lifecycle (dr · rotation)
interfaces/      inbound delivery + Server API grpcserver · adapters · admin · apidocs · middleware · cors · ratelimit · ssoclient · snapshot · sso (public API-only Server)
infrastructure/  concrete SPI impls            defaultimpl · redis · postgres · sms · optional nested ldap/kerberos/radius/saml/extauthz/kafka/mqtt/kms modules
internal/        unexported helpers            internal/auth/* (domains) · internal/{handler,adminuser} (interfaces)
cmd/ · config/ · docs/ · gen/ · proto/ · test/ · ops/ · checks/  composition/tooling
```

`cmd/sso-server/servermodules` is the explicit cold-module registration hook
for the stock compatibility composition. `prototype` and `minimal` target the
dedicated `cmd/sso-minimal` composition root. `prototype` exposes SSO/OAuth,
basic JSON logs and the stable `default` tenant seam; `minimal` adds OIDC and
tracing. Both share `interfaces/sso` (the product SDK surface) but are
physically isolated from the durable/admin/observability graph — the
boundary is declared in `ops/build/profile-isolation.json` and proven by
`python cli.py profiles evidence` (packages, modules, symbols, size; see
[`profile-isolation.md`](profile-isolation.md)). Neither
bundles a login UI or represents a production topology.

`ops/build/` owns strict manifests/profiles and `ops/scripts/` materializes an
alternate module graph under ignored `dist/modules/`. The public hierarchy is
`prototype → minimal → full`; `full` overrides the smaller command
target with the complete current `cmd/sso-server` composition and registered
Kafka audit cold module. `standard` and `standard-kafka` preserve only the
historical stock composition. See [`plugin-system.md`](../plugin-system.md).

The repo root holds **no library `.go` files** — only the committed gate tests
(`package archgate`: architecture + maintainability budgets). The public Server
API is `github.com/yangwb1123/snaplink/interfaces/sso` (package `sso`).
It serves APIs only; hosted UIs are separate frontend projects.

## Dependency direction (one-way, toward the shared kernel)

```
composition (cmd, config, docs/examples)        can import everything
      ▼ interfaces (grpcserver, adapters, interfaces/sso — the Server API)
      ▼ infrastructure (defaultimpl, redis, kms…)   implements the abstractions
      ▼ protocols (oauth, oidc, scim, fapi…)        orchestrate the domains
      ▼ domains (tenant, permissions, federation…)  business capabilities
      ▼ platform (cluster, metrics, audit-mech…)    cross-cutting capabilities
      ▼ shared (core, spi, security)                dependency-free kernel
```

A package may import only its own layer or a **lower** (more-shared) one. The
compiler stops *cycles*; this gate stops the *upward* imports that precede them (a
domain reaching into infrastructure, a protocol reaching into the HTTP edge). The
few grandfathered upward edges live in `layerExemptions` (ratchet: shrink-only).

¹ `audit` is the Recorder/Sink **mechanism** used by every layer (observability),
not a DDD "audit domain" — hence platform.

## Notes on the layered tree

- This layout was reached by physically moving packages without changing the
  root module path. That was an import-path-breaking in-place reorganization;
  retired migration records are indexed in [HISTORY.md](../HISTORY.md).
- Nested modules
  (`infrastructure/{ldap,kerberos,radius,saml,extauthz,kafka,mqtt,kms/*}` and
  `cmd/{sso-mcp,sso-operator}`) retain their own `go.mod`. Redis and Postgres
  are root-module packages.
- Cold-module builds use positive profiles and a generated explicit registrar;
  they do not add `go.work`, edit the root module graph, or use blank imports.
- Compiled capability, runtime backend selection, feature-gate exposure, and
  hot activation/drain are separate states. Only the first is decided by a
  cold profile; the current server has no general hot-plugin lifecycle.
- `gen/` (generated protobuf Go) and `proto/` (`.proto` sources) stay top-level —
  they are codegen-coupled (`buf`).

## Adding a package

1. Put it under the layer directory that owns the concern (extend, don't proliferate).
2. The first path segment classifies it automatically in `layerName()`
   (`architecture_layer_test.go`); a genuinely new top-level segment must be added
   there — an **unclassified** package fails the gate by design.
3. Keep imports pointing down the stack. A needed upward dependency means the
   abstraction belongs lower (move the interface to `shared/core` / `shared/spi`),
   not that the rule should bend.
4. Keep directory depth ≤ 3 — flatten a new backend/variant into the parent name
   (`webauthnsqlite`), don't nest a 4th level (gate: `maxdepth_test.go`).
5. Stay within the budgets (file ≤ 500 lines, function ≤ 50 / cyclo ≤ 15) and
   **never add a maintainability exemption for new code** — the lists are
   count-capped and only shrink. Full contributor rule:
   [AGENTS.md §0.6](../../AGENTS.md).
