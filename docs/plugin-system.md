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
| `prototype`, `minimal`, and `full` edition builds | Buildable |
| Package-level dependency isolation for `prototype`/`minimal` | Incomplete |
| In-process hot lifecycle or external plugin supervisor | Not implemented |

`prototype` and `minimal` are behaviorally distinct but not yet physically
isolated from one another. Both target `cmd/sso-minimal`, which still reaches
the broad dependency graph through `interfaces/sso`. Their build profile and
runtime surface are real boundaries; their package inventory is not yet proof
that every excluded capability or dependency left the binary.

## Profile hierarchy

| Profile | Maturity | Purpose |
|---|---|---|
| `prototype` | preview | Smallest SSO/OAuth runtime: password login, Authorization Code + mandatory PKCE, reusable OP session, basic JSON logs, memory defaults and a stable `default` tenant migration seam |
| `minimal` | preview | Extends `prototype` with OIDC discovery, ID Token, UserInfo and logout plus request tracing |
| `full` | supported | Extends `minimal` with the full current stock `sso-server` composition and the registered Kafka audit cold module |
| `standard` | supported | Compatibility profile for the historical stock `sso-server` composition |
| `standard-kafka` | supported | Extends `standard` with the statically linked Kafka audit sink |

Inheritance is additive: a child selects its parent's modules and adds its own
edition bundle. It inherits the build target unless it explicitly overrides
one. `prototype` and `minimal` use `cmd/sso-minimal`; `full` selects
`cmd/sso-server` so its inventory describes the complete stock composition
rather than the smaller runtime. Compilation does not turn every production
option on: runtime configuration, feature gates and backend availability
remain separate concerns.

`oauth-client-credentials` is an independent optional machine-to-machine
module. It is not the core of any SSO edition.

## Inspect, configure and build

Validate and inspect the catalog:

```bash
python cli.py modules check
python cli.py modules list
python cli.py modules plan --profile prototype
python cli.py modules graph --profile full
python cli.py modules why op-session-sso --profile full
```

Build the public editions:

```bash
python cli.py configure --profile prototype --version v1.1.1 --build
python cli.py configure --profile minimal --version v1.1.1 --build
python cli.py configure --profile full --version v1.1.1 --build

dist/modules/prototype/snaplink version
dist/modules/minimal/snaplink version
dist/modules/full/snaplink version
# alice/s3cret
# demo-app/demo-secret       -> http://127.0.0.1:3000/callback
# demo-app-b/demo-secret-b   -> http://127.0.0.1:3001/callback
```

The first output lines are respectively
`snaplink-v1.1.1.prototype`, `snaplink-v1.1.1.minimal`, and
`snaplink-v1.1.1.full`. The explicit source version is also recorded in
the module lock.

`production` remains accepted as a compatibility alias for the `full` profile;
new automation and artifact paths should use `full`.

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
<profile-binary>
```

The builder stages the full output and publishes it atomically only after
resolution, compilation and inventory verification succeed. It does not edit
the repository root's `go.mod` or `go.sum`; final compilation uses
`-mod=readonly` and `-trimpath`. Public editions name the binary `snaplink`;
the compatibility profiles retain `sso-server`.

Inspect a configured artifact:

```bash
dist/modules/prototype/snaplink modules
dist/modules/prototype/snaplink modules --json
go version -m dist/modules/prototype/snaplink
```

The inventory contains the profile ID, ordered module IDs and canonical lock
digest. The lock records the resolved capability and Go module graphs plus
build inputs; it is not a binary package inventory or an SBOM. Use
`go version -m`, symbol inspection and the release SBOM to prove physical
dependency removal.

## Edition boundaries

`prototype` is the smallest working single-process SSO slice:

- password authentication with cost-matched unknown-user handling;
- Authorization Code with mandatory PKCE S256;
- OAuth authorization-server metadata, JWKS and access tokens, but no OIDC
  discovery, ID Token, UserInfo or OIDC end-session surface;
- basic structured JSON logging;
- memory users, clients, credentials and authorization codes;
- one active tenant with the stable ID and slug `default`, preserving the
  tenant seam for migration to a larger edition;
- an opaque HttpOnly OP cookie with `prompt`/`max_age` handling and local
  logout.

`minimal` retains those defaults and adds the common OIDC surface
(discovery, ID Token, UserInfo and logout), the `openid`, `profile`, and
`email` scope baseline, and request tracing.

`full` uses the complete stock `cmd/sso-server` composition and adds the
registered Kafka audit cold module. The capability table in
[feature-matrix.md](feature-matrix.md) identifies independently packaged
integrations that still require maintained registration. Operators must also
select durable backends and a production topology; an edition name cannot make
memory defaults multi-replica-safe.

The two smaller editions are deliberately not production deployments:

- process memory is their persistence and coordination boundary;
- signing keys and sessions do not provide durable or multi-replica semantics;
- their HTTP tests are not browser end-to-end evidence; a browser flow
  requires a same-origin external login frontend because the binary exposes a
  POST login API and bundles no UI;
- their OP session is currently a command-level adapter rather than the
  canonical `SessionManager`/authorization-code lifecycle;
- protocol route registrars and implementation packages are not yet isolated
  from `interfaces/sso`.

The extraction target preserves both smaller runtime behaviors while moving OP
session creation, SID propagation, `prompt`/`max_age` and logout into standard
typed registrars outside `cmd/`. Only package, binary, SBOM and size evidence
can establish physical dependency removal.

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
