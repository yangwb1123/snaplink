# Directory map — the 30-second view

snaplink is an **OAuth 2.0 + OIDC + SAML + SCIM identity platform**, shipped as an
embeddable Go SDK plus a runnable server. The tree is **physically layered**: every
library package lives under its architectural layer directory, so the first path
segment IS the layer. The dependency direction is **enforced** by
`architecture_layer_test.go` (`TestArchitecture_LayerBoundaries`, package
`archgate` at the repo root, [ADR-0006](../adr/ADR-0006-cognitive-architecture.md)).

## Top-level layout (≤15 dirs)

```
shared/          dependency-free kernel        core · spi · security
domains/         business capabilities         tenant · region · permissions · federation · connections · metering · anomaly · authenticators
protocols/       identity-protocol use-cases   oauth · oidc · scim · fapi · caep · selfservice · compliance
platform/        cross-cutting capabilities    cluster · signingkeys · registry · netpolicy · metrics · tracing · bootstrap · releases · migrate · geo · audit · dr
interfaces/      inbound delivery + Server API grpcserver · adapters · admin · middleware · cors · ratelimit · web · ssoclient · snapshot · sso(the public Server)
infrastructure/  concrete SPI impls            defaultimpl · ldap · kerberos · radius · saml · redis · extauthz · kms/*
internal/        unexported helpers            internal/auth/* (domains) · internal/handler (interfaces)
cmd/ · config/ · docs/ · gen/ · proto/ · test/ · ops/ · checks/
```

The repo root holds **no library `.go` files** — only the committed gate tests
(`package archgate`: architecture + maintainability budgets). The public Server
API is `github.com/snaplink/sso/interfaces/sso` (package `sso`).

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

- This layout was reached by physically moving the packages (a breaking
  import-path change); the move table, import codemod, and consumer-migration
  script are in [V2-MIGRATION.md](V2-MIGRATION.md). When published it warrants a
  major-version tag ([ADR-0003](../adr/ADR-0003-protocol-grouping.md)).
- Nested modules (ldap, kerberos, radius, saml, redis, extauthz, kms/*) keep their
  own `go.mod` and module paths; only their directories moved under
  `infrastructure/` (their `replace github.com/snaplink/sso => ../../` was adjusted).
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
   count-capped and only shrink. Full contributor rule: AGENTS.md §0.6.
