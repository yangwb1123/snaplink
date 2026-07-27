# Module build and plugin lifecycle

Snaplink uses NGINX-style positive build profiles for cold modules. Safe hot
activation remains a later lifecycle phase; a feature gate is not a hot
plugin.

The normative design is
[ADR-0009](adr/ADR-0009-static-and-runtime-modules.md). This guide describes
the commands and profiles available in the current tree.

## Current status

| Capability | Status |
|---|---|
| Strict catalog, manifests and capability resolution | Implemented |
| Profile inheritance and profile-specific build targets | Implemented |
| Alternate `go.mod`/`go.sum`, canonical lock and embedded inventory | Implemented |
| `standard` and `standard-kafka` compatibility builds | Supported |
| `sso-prototype` functional SSO build | Preview, buildable |
| `sso-production` and `sso-complete` editions | Planned |
| Package-level dependency isolation for the prototype | Incomplete |
| In-process hot lifecycle or external plugin supervisor | Not implemented |

`sso-prototype` is functionally small, not yet physically small. Its dedicated
`cmd/sso-minimal` entry point still reaches the broad dependency graph through
`interfaces/sso`. Feature gates reduce the active HTTP surface but do not prove
that excluded packages or transitive dependencies left the binary.

## Profile hierarchy

| Profile | Maturity | Purpose |
|---|---|---|
| `sso-prototype` | preview | Loopback-only, in-memory Authorization Code + PKCE OIDC SSO for evaluation and integration |
| `sso-production` | planned | Extends `sso-prototype` with durable state, production OAuth controls, operations and HA-capable providers |
| `sso-complete` | planned | Extends `sso-production` with advanced protocols, enterprise identity, provisioning, tenant, authorization, threat and governance capabilities |
| `standard` | supported | Compatibility profile for the historical stock `sso-server` composition |
| `standard-kafka` | supported | Extends `standard` with the statically linked Kafka audit sink |

Inheritance is additive: a child selects its parent's modules and adds its own
edition bundle. It inherits the build target unless it explicitly overrides
one. `sso-production` and `sso-complete` deliberately point at future,
currently absent composition commands; the missing command remains a resolver
blocker instead of letting a profile inventory describe the prototype binary.
Planned profiles remain unbuildable while any selected module is still
`planned`.

`oauth-client-credentials` is an independent optional machine-to-machine
module. It is not the core of any SSO edition.

## Inspect, configure and build

Validate and inspect the catalog:

```bash
python cli.py modules check
python cli.py modules list
python cli.py modules plan --profile sso-prototype
python cli.py modules graph --profile sso-production
python cli.py modules why op-session-sso --profile sso-production
```

Build the preview prototype:

```bash
python cli.py configure --profile sso-prototype --build
# or
make build-prototype

dist/modules/sso-prototype/sso-server
# alice/s3cret
# demo-app/demo-secret       -> http://127.0.0.1:3000/callback
# demo-app-b/demo-secret-b   -> http://127.0.0.1:3001/callback
```

Build compatibility profiles:

```bash
python cli.py configure --profile standard --build
python cli.py configure --profile standard-kafka --build
```

Generated output defaults to `dist/modules/<profile>/`:

```text
.snaplink-modules-output
modules.mod
modules.sum
overlay.json
register_configured.go
modules.lock.json
sso-server
```

The builder stages the full output and publishes it atomically only after
resolution, compilation and inventory verification succeed. It does not edit
the repository root's `go.mod` or `go.sum`; final compilation uses
`-mod=readonly` and `-trimpath`.

Inspect a configured artifact:

```bash
dist/modules/sso-prototype/sso-server modules
dist/modules/sso-prototype/sso-server modules --json
go version -m dist/modules/sso-prototype/sso-server
```

The inventory contains the profile ID, ordered module IDs and canonical lock
digest. The lock records the resolved capability and Go module graphs plus
build inputs; it is not a binary package inventory or an SBOM. Use
`go version -m`, symbol inspection and the release SBOM to prove physical
dependency removal.

## Prototype boundary

`cmd/sso-minimal` provides a working single-process SSO slice:

- password authentication with cost-matched unknown-user handling;
- Authorization Code only, with mandatory PKCE S256;
- OIDC discovery, JWKS, access token, ID token and UserInfo;
- in-memory users, clients, credentials and authorization codes;
- an opaque HttpOnly OP cookie with `prompt`/`max_age` handling and local
  logout;
- a two-client HTTP integration test proving passwordless reuse of the OP
  session and preservation of the original `auth_time`;
- loopback-only listening and environment/flag seed configuration.

It is deliberately not a production deployment:

- process memory is the only persistence and coordination boundary;
- signing keys and sessions do not provide durable or multi-replica semantics;
- the HTTP cookie-jar test is not browser end-to-end evidence; a browser flow
  requires a same-origin external login frontend because this binary exposes a
  POST login API and bundles no UI;
- the OP session is currently a command-level adapter rather than the
  canonical `SessionManager`/authorization-code lifecycle;
- authorization-code issuance does not yet carry the real OP session SID
  through the code, access token and ID token;
- protocol route registrars and implementation packages are not yet isolated
  from `interfaces/sso`.

The extraction target preserves the prototype behavior while moving OP session
creation, SID propagation, `prompt`/`max_age` and logout into standard typed
registrars outside `cmd/`. Only after package, binary, SBOM and size evidence
shows excluded dependencies are absent may the profile be described as a
physically minimal binary.

## Profile modification

Positive additions and exclusions are available for compatible graphs:

```bash
python cli.py modules plan \
  --profile standard \
  --with-module audit-kafka

python cli.py configure \
  --profile standard \
  --with-module audit-kafka \
  --build
```

Resolution fails before compilation for missing or ambiguous providers,
conflicts, cycles, an excluded locked/embedded module, unsupported targets,
planned modules, unknown registration adapters or declared policy violations.
Manifest metadata does not certify transitive licenses or FIPS compliance;
release SBOM and compliance checks remain separate gates.

`--target GOOS/GOARCH` supports cross-compilation. `--out` may point outside the
repository or below `dist/`; other in-repository output paths are rejected.

## Maintained cold modules

A maintained module must:

1. define narrow provided/required capabilities and a failure policy;
2. keep security wire invariants in the non-removable kernel;
3. use a strict `snaplink.module.json` manifest;
4. register only through a typed, allow-listed adapter;
5. avoid `init`, blank imports, shell/template fields and arbitrary generated
   expressions;
6. prove dependency inclusion and exclusion with the lock, binary metadata,
   SBOM and behavior tests.

`--add-module` accepts a local module directory or manifest:

```bash
python cli.py configure \
  --profile standard \
  --add-module ../corp-audit-kafka \
  --with-module corp-audit-kafka \
  --build
```

An isolated local module must keep `source` inside its manifest directory and
provide a matching `go.mod`. Local replacements are a development mechanism;
supported releases require publishable versions, checksums, signatures and
provenance. Kafka remains the only implemented third-party registration
adapter; a versioned registrar outside `cmd/` is required before other module
families are supported.

## Cold and hot boundary

| Keep cold | Candidate for a future hot lifecycle |
|---|---|
| Middleware order and trusted proxies | Fail-open background detectors |
| Identity/OAuth stores and migrations | Isolated notification/webhook exporters |
| Issuers, keys, JWKS and KMS/HSM | Prevalidated WASM policy generations |
| Grants, OP sessions and discovery shape | Precompiled admin/debug route slots |
| Cluster/revocation/key buses | External typed authenticator processes |
| Primary audit/redaction/hash chain | Secondary audit taps |

A hot-precompiled module requires static route/capability slots, generation
leases, blue/green readiness, drain, reverse-order cleanup and transition
audit. The current router, readiness checks and audit sink registry do not meet
that contract.

Installable third-party hot modules will run out of process over a typed,
authenticated protocol. Go `.so` plugins are not supported.

## Verification

```bash
python cli.py modules check
python -m pytest checks/test_modules.py -q
go test ./cmd/sso-minimal
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```
