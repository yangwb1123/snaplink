# ADR-0009: Static build modules and safe runtime activation

**Status:** Accepted, incremental

## Context

The stock `sso-server` is currently one large composition. Functional options
make the SDK extensible at startup, and seven feature gates can hide already
wired routes at runtime, but neither mechanism removes code or dependencies
from the binary. Disabling a YAML feature therefore does not reduce the supply
chain, attack surface in memory, startup work, or binary size.

Several useful module boundaries already exist:

- SAML, LDAP, Kerberos, RADIUS, Kafka, MQTT, external authorization and KMS/HSM
  integrations have independent `go.mod` files.
- Kafka, SAML and external signers have boot-time factory registries.
- `FeatureGates` use atomic flags and `core.GatedRouter` for live route
  visibility.

Those boundaries are incomplete:

- `cmd/sso-server` always executes a fixed foundation → domains → edge
  assembly.
- `interfaces/sso.mountCoreOAuthOIDC` mixes probes, OAuth grants, browser
  login, OIDC, device, PAR, DCR, CIBA and logout.
- `Server` stores many optional concrete types directly.
- routes, readiness checks, audit sinks and metrics collectors are primarily
  append-only startup structures.
- a feature gate can hide a route but cannot construct, replace, drain or
  unload its dependencies.

The desired operator model resembles NGINX: select static modules when
building, inspect the compiled result, and activate only the runtime-safe
subset without rebuilding.

Go's `plugin` package does not meet that requirement. It cannot unload a
plugin, supports only a subset of operating systems, and requires the host and
plugin to match the toolchain, build tags and dependency versions. Those
properties are especially unsuitable for a security-sensitive identity
process.

## Decision

### 1. Use four precise terms

| Term | Meaning |
|---|---|
| **kernel** | Non-removable process lifecycle, configuration host and security invariants |
| **cold module** | Selected before compilation, statically linked, activated at boot, changed by rebuilding/restarting |
| **hot precompiled module** | Code is already in the binary; an instance may be enabled, replaced or disabled with leases and drain |
| **hot external module** | Independently installed process reached through a typed, authenticated RPC contract |

“Hot plugin” never means loading or unloading a Go `.so` inside `sso-server`.
Current feature gates are runtime route switches, not hot modules.

### 2. Adopt NGINX-style positive build profiles

The source of truth is:

```text
ops/build/modules.json
ops/build/profiles/*.json
<module-root>/snaplink.module.json
```

Operators use positive selection:

```bash
python cli.py modules plan --profile standard-kafka
python cli.py configure --profile standard-kafka --build
```

`--with-module`, `--without-module`, and `--add-module` modify the selected
profile. The resolver:

1. validates strict JSON data;
2. computes the capability dependency closure;
3. rejects missing or ambiguous providers, conflicts and cycles;
4. applies target and declared module CGO/FIPS/license metadata policy;
5. sorts modules in stable dependency order;
6. materializes an alternate `go.mod/go.sum`;
7. generates one explicit registration function;
8. produces a canonical `modules.lock.json`;
9. builds with `-mod=readonly`, `-trimpath` and a fixed positive build tag;
10. verifies selected Go modules are present in the final binary metadata.

The builder never edits the repository's root `go.mod` or `go.sum`. By default,
generated files live under ignored `dist/modules/<profile>/`; an external
`--out` is also supported. `dist/` is excluded from the committed Go
maintainability and architecture scans, so the default profile build cannot
invalidate those source-tree gates. A profile is staged and published as one
owned directory only after validation and any requested build succeeds.

Registration is explicit. Generated code calls named, allow-listed host
adapters from `servermodules.Register()`. Module manifests cannot contain
shell commands, templates, arbitrary Go expressions, blank imports or `init`
hooks.

The build uses a Go overlay only for the single hard-coded
`cmd/sso-server/servermodules/register_configured.go` path. It may not replace
arbitrary repository files.

### 3. Keep compatibility honest during extraction

The current profiles are:

| Profile | State | Meaning |
|---|---|---|
| `standard` | supported | Historical stock composition |
| `standard-kafka` | supported | Stock composition plus statically linked Kafka audit sink |
| `minimal` | planned | Target client-credentials-only OAuth authorization server |

`standard` remains the normal build during migration. `minimal` deliberately
fails configuration while any selected module is marked `planned`; a route
gate or unused config block is not accepted as proof of binary isolation.

The target `minimal` profile contains only:

- process/config/lifecycle kernel;
- HTTP transport plus liveness/readiness;
- in-memory client registry;
- Ed25519 token issuer/validator and JWKS;
- `/token` with `client_credentials`;
- OAuth authorization-server metadata.

It intentionally has no users, sessions, browser login, authorization code,
refresh, device, PAR/JAR, OIDC ID tokens/userinfo, self-service, admin API,
federation, CAEP, SCIM, WebAuthn, cluster, Redis, Postgres, etcd, OTel or WASM.
A future `minimal-sso` profile may add browser login, authorization code + PKCE,
OIDC and the required identity/session modules.

Security wire invariants are kernel policy, not removable modules. A profile
cannot disable signature validation, oracle collapse, credential-response
cache headers, anti-enumeration, trusted-proxy enforcement or mandatory PKCE
rules for a selected flow.

### 4. Embed the compiled inventory

Every configured binary receives:

- profile ID;
- canonical module-lock digest;
- ordered compiled module IDs.

It exposes them without loading runtime configuration:

```bash
sso-server modules
sso-server modules --json
```

This is the `nginx -V` equivalent. It contains no secrets or runtime module
configuration.

### 5. Require a generation-based lifecycle before calling a module hot

The future runtime manager belongs under `platform/lifecycle/modules` so it
does not increase `platform/`'s frozen top-level fan-out. Its definitions come
from the cold build result; runtime config cannot invent a new in-process
module.

Each active instance has a generation and three lease classes:

- request leases;
- dependent-module leases;
- background-work leases.

Replacement is blue/green:

1. prepare and start generation N+1 without publishing it;
2. verify readiness;
3. atomically publish N+1 for new acquisitions;
4. stop new acquisitions from generation N;
5. wait for all N leases to drain;
6. quiesce and stop N;
7. release its dependencies in reverse order.

A failed candidate is cleaned up without affecting the active generation.
Runtime rollback after publication is not automatic because a module may have
already produced external side effects.

Routes for hot modules have a static method/path/security shape created at
boot. Route matching must acquire a generation lease before module middleware
runs. Disabling the slot must preserve the existing native-404 contract and
must not close resources until matched requests finish.

One static readiness check reports manager health; modules do not append
readiness checks at runtime. Audit exporters require a startup-installed
copy-on-write tap that drains before close. The primary audit sink, redaction
and hash chain remain cold.

### 6. Keep unsafe capabilities cold

The following remain cold until a narrower design proves otherwise:

- global middleware ordering and trusted-proxy boundaries;
- client, user, session and OAuth single-use stores;
- signing issuers, key material, JWKS and KMS/HSM;
- OAuth/OIDC grants, discovery and advertised protocol shape;
- cluster bus, revocation propagation and signing-key aggregation;
- primary audit sink, redaction and hash chain;
- login/MFA/device/CIBA/SAML flows with cross-request state, unless generation
  affinity and state-TTL retirement are implemented.

Good first hot candidates are fail-open background detectors, notification or
webhook exporters behind isolated queues, and a prevalidated WASM policy
generation behind a fail-closed slot.

### 7. Run installable third-party hot modules out of process

External modules use a typed protocol over a Unix-domain socket; remote
deployment requires mutual TLS or SPIFFE identity. The control plane includes
handshake, readiness, quiesce, shutdown and heartbeat. Data planes are
capability-specific (`Authenticate`, `EvaluatePolicy`, `DeliverAuditBatch`,
etc.); there is no generic `Execute(any)` escape hatch.

The host retains token/client authentication, tenant resolution, request
limits, error mapping, audit and failure-mode policy. Plugins receive only the
minimum typed data required by their capability and never receive signing
private keys or reusable bearer credentials by default.

## Migration

1. **Build proof:** supported `standard`/`standard-kafka`, strict manifests,
   dependency plans, alternate modfile, overlay, lock and binary inventory.
2. **Stable host API:** extract executable orchestration from `package main`;
   replace transitional factory adapters with a versioned registrar outside
   `cmd/`.
3. **Real cold isolation:** split the stock route and builder monolith into
   explicit modules; prove dependency and binary-size removal for each.
4. **Minimal release:** make the target profile buildable and test protocol,
   dependency, SBOM and size deltas against `standard`.
5. **Hot manager:** add generation leases, route guards, drain, readiness and
   transition audit; migrate one low-risk background module first.
6. **External supervisor:** add signed artifact policy and typed RPC processes.
7. **Release profiles:** publish per-profile binary SBOMs, locks, signatures and
   provenance.

Nested module paths and versions must be made publishable before remote
`module@version` is supported. Local `--add-module` replacements are a
development mechanism, not release provenance.

## Consequences

Positive consequences:

- operators can inspect and reproduce the exact compiled extension set;
- optional dependencies can eventually leave minimal binaries entirely;
- runtime activation gains explicit failure, drain and readiness semantics;
- third-party crashes and dependency conflicts do not enter the identity
  process address space.

Costs:

- the current monolith must be decomposed incrementally;
- build profiles expand the build/test matrix and require a future supported
  per-profile release matrix;
- hot activation requires indirection and lease accounting;
- module ABI, schema, SBOM and signing policy become maintained contracts.

## References

- [NGINX configure options](https://nginx.org/en/docs/configure.html)
- [NGINX `load_module`](https://nginx.org/en/docs/ngx_core_module.html#load_module)
- [Go `plugin` package warnings](https://pkg.go.dev/plugin)
- [Go build constraints](https://pkg.go.dev/go/build#hdr-Build_Constraints)
- [Module system guide](../plugin-system.md)
