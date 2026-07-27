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
python cli.py modules plan --profile prototype
python cli.py configure --profile prototype --version v1.1.1 --build
```

`--with-module`, `--without-module`, and `--add-module` modify the selected
profile. A profile may extend another profile and may select its own `./cmd/`
build package, binary name and required composition module. The resolver:

1. validates strict JSON data;
2. resolves profile inheritance and the positive module set;
3. computes the capability dependency closure;
4. rejects missing or ambiguous providers, conflicts and cycles;
5. applies target and declared module CGO/FIPS/license metadata policy;
6. sorts modules in stable dependency order;
7. materializes an alternate `go.mod/go.sum`;
8. generates one explicit registration function;
9. produces a canonical `modules.lock.json`;
10. builds the selected package with `-mod=readonly`, `-trimpath` and a fixed
    positive build tag;
11. verifies selected Go modules and the embedded inventory.

The builder never edits the repository's root `go.mod` or `go.sum`. By default,
generated files live under ignored `dist/modules/<profile>/`; an external
`--out` is also supported. `dist/` is excluded from the committed Go
maintainability and architecture scans, so the default profile build cannot
invalidate those source-tree gates. A profile is staged and published as one
owned directory only after validation and any requested build succeeds.

Registration is explicit. A module that needs host registration uses a named,
allow-listed adapter; manifests cannot contain shell commands, templates,
arbitrary Go expressions, blank imports or `init` hooks. The current Kafka
adapter still enters through `servermodules.Register()`; a standard versioned
registrar outside `cmd/` remains an extraction target.

The generated Go overlay may replace only the single hard-coded
`cmd/sso-server/servermodules/register_configured.go` path. It may not replace
arbitrary repository files. A profile-specific entry point such as
`cmd/sso-minimal` is selected as profile data rather than injected through
another overlay.

### 3. Keep compatibility honest during extraction

The current profiles are:

| Profile | State | Meaning |
|---|---|---|
| `standard` | supported | Historical stock composition |
| `standard-kafka` | supported | Extends `standard` with the statically linked Kafka audit sink |
| `prototype` | preview | Smallest SSO/OAuth runtime: Authorization Code + mandatory PKCE, password/OP-session SSO, JSON logs, memory defaults and the stable `default` tenant seam |
| `minimal` | preview | Extends `prototype` with OIDC discovery, ID Token, UserInfo and logout plus request tracing |
| `production` | supported | Extends `minimal` with the complete current stock `sso-server` composition and registered Kafka audit cold module |

`standard` remains the compatibility default during migration.
`prototype` and `minimal` are separate build profiles and expose different
runtime surfaces, but both currently target `cmd/sso-minimal`. That command
still uses `interfaces/sso`, so the broad package dependency graph remains
linked even when a profile hides routes. Their opaque HttpOnly OP session is
also a command-level adapter. The stable `default` tenant keeps the tenancy
boundary available for later migration without exposing tenant management in
the prototype.

The extraction target is therefore:

- move OP session creation, `prompt`/`max_age`, SID propagation and logout into
  the canonical session and authorization-code lifecycle;
- split protocol routes into standard typed registrars outside `cmd/`;
- isolate HTTP, stores, authentication, signing and OIDC implementation
  packages;
- prove excluded dependencies are absent with package, binary-size, symbol and
  SBOM evidence.

`production` overrides the smaller command target with `cmd/sso-server`, so
its inventory describes the full current server instead of stamping a larger
edition name onto the small runtime. It compiles the current stock surfaces
and registered Kafka audit cold module; other independently packaged
integrations still require a maintained host registration. Runtime
configuration and backend topology decide which compiled capabilities are
active and safe to operate. A route gate or unused config block is never
accepted as binary-isolation proof.

The `oauth-client-credentials` grant is an independent optional
machine-to-machine module, not the definition or foundation of minimal SSO.

Security wire invariants are kernel policy, not removable modules. A profile
cannot disable signature validation, oracle collapse, credential-response
cache headers, anti-enumeration, trusted-proxy enforcement or mandatory PKCE
rules for a selected flow.

### 4. Embed the compiled inventory

Every configured binary receives:

- source version;
- profile ID;
- canonical module-lock digest;
- ordered compiled module IDs.

It exposes them without loading runtime configuration:

```bash
<configured-binary> modules
<configured-binary> modules --json
```

This is the `nginx -V` equivalent. It contains no secrets or runtime module
configuration. Public edition builds make their identity visible through the
normal `version` command: a `v1.1.1` build reports
`snaplink-v1.1.1.prototype`, `snaplink-v1.1.1.minimal`, or
`snaplink-v1.1.1.production`.

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

1. **Build proof:** retain supported compatibility profiles, strict manifests,
   inherited plans, alternate modfiles, lock and binary inventory.
2. **Edition proof:** keep `prototype`, `minimal`, and `production` buildable;
   verify their ordered inheritance, runtime boundaries, compiled inventories,
   and edition-qualified versions.
3. **Canonical SSO lifecycle:** move the prototype adapter into the real
   session/auth-code flow and propagate SID through codes and tokens.
4. **Stable host API and cold isolation:** replace transitional `cmd/`
   adapters with versioned registrars; split the route and builder monolith and
   prove dependency removal.
5. **Production evidence:** prove the `production` composition against durable
   state, OAuth/OIDC controls, observability and supported topology.
6. **Hot manager:** add generation leases, route guards, drain, readiness and
   transition audit; migrate one low-risk background module first.
7. **External supervisor:** add signed artifact policy and typed RPC processes.
8. **Release evidence:** publish per-profile SBOMs, locks, signatures and
   provenance.

Nested module paths and versions must be made publishable before remote
`module@version` is supported. Local `--add-module` replacements are a
development mechanism, not release provenance.

## Consequences

Positive consequences:

- operators can inspect and reproduce the exact compiled extension set;
- optional dependencies can eventually leave profile binaries entirely;
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
