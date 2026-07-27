# Module build and plugin lifecycle

Snaplink is moving from a fixed stock composition to an NGINX-style module
build. The first delivered slice is cold-module configuration; safe hot
activation is an explicit later phase.

The architectural decision and lifecycle rules are in
[ADR-0009](adr/ADR-0009-static-and-runtime-modules.md). This guide describes
what can be run today.

## Current status

| Capability | Available now |
|---|---|
| Strict module catalog and profiles | Yes |
| Capability dependency/conflict/cycle validation | Yes |
| Independent profile modfile/sum and local module replacement | Yes |
| Canonical module lock and embedded digest | Yes |
| Explicit static registration without `init` or blank imports | Yes |
| `sso-server modules [--json]` inventory | Yes |
| Kafka audit module profile | Yes |
| Real minimal binary | No; the plan fails with named extraction blockers |
| Runtime module load/unload | No |
| External-process plugin supervisor | No |

Feature gates remain useful attack-surface switches for already compiled and
wired routes. They do not unload code or dependencies and are not listed as
hot plugins.

## Inspect the catalog

```bash
python cli.py modules check
python cli.py modules list
python cli.py modules plan --profile standard-kafka
python cli.py modules graph --profile minimal
python cli.py modules why audit-kafka --profile standard-kafka
```

Equivalent Make/Task wrappers:

```bash
make modules-check
make modules-list
make modules-plan PROFILE=minimal
task modules args=list
```

`minimal` currently returns a valid plan with `buildable: no`. That is
intentional: until the named modules no longer reach the stock composition,
claiming a minimal binary would be misleading.

## Configure and build

Preserve the historical composition:

```bash
python cli.py configure --profile standard --build
```

Build the stock server with the Kafka audit implementation linked:

```bash
python cli.py configure --profile standard-kafka --build
```

By default, outputs live in `dist/modules/<profile>/`:

```text
.snaplink-modules-output   # ownership marker for atomic replacement
modules.mod
modules.sum
overlay.json
register_configured.go
modules.lock.json
sso-server                 # when --build is present
```

The repository root's `go.mod` and `go.sum` are not changed. The initial
dependency resolution populates only the alternate files; the final build uses
`-mod=readonly`. Inputs are built in a sibling staging directory and published
as a unit only after graph, lock and compile verification succeed. Native
builds also execute `modules --json` after registration and compare its
profile, ordered module IDs and digest to the generated lock. A failed rebuild
leaves the previous profile directory intact.

Inspect the result:

```bash
dist/modules/standard-kafka/sso-server modules
dist/modules/standard-kafka/sso-server modules --json
go version -m dist/modules/standard-kafka/sso-server
```

The profile and lock digest are embedded with linker values. The lock includes
the selected capability graph, complete resolved Go module graph needed to
reproduce Minimal Version Selection, selected local build-input digests and
effective Go target/toolchain environment. It is not the binary's linked-package
inventory or an SBOM; use `go version -m` and the release SBOM for those views.
After compilation the tool re-hashes the selected inputs, verifies exact linked
module paths, and, for a native build, executes `modules --json` before
publishing the profile atomically.

Make and Task wrappers accept extra arguments:

```bash
make configure PROFILE=standard-kafka
make build-profile PROFILE=standard-kafka
task build-profile profile=standard-kafka
```

## Modify a profile

The resolver supports positive additions and explicit exclusions:

```bash
python cli.py modules plan \
  --profile standard \
  --with-module audit-kafka

python cli.py configure \
  --profile standard \
  --with-module audit-kafka \
  --build
```

Locked or still-embedded modules cannot be excluded. A missing/ambiguous
capability provider, dependency cycle, conflict, unsupported target, planned
module, unknown registration adapter, or violation of declared module
CGO/FIPS/license metadata fails before compilation. This manifest policy does
not scan transitive dependency licenses or certify FIPS compliance; release
SBOM and compliance verification remain separate gates.

Use `--target GOOS/GOARCH` for cross-compilation. `--out PATH` may select an
external directory or a path below repository `dist/`; other in-repository
paths are rejected so generated Go files cannot affect source-tree gates.

## Add a local cold module

`--add-module` accepts a directory containing `snaplink.module.json`, or the
manifest path itself:

```bash
python cli.py configure \
  --profile standard \
  --add-module ../corp-audit-kafka \
  --with-module corp-audit-kafka \
  --build
```

The v1alpha1 manifest is strict JSON:

```json
{
  "$schema": "/path/to/snaplink/ops/build/module.schema.json",
  "schema_version": 1,
  "id": "corp-audit-kafka",
  "summary": "Company Kafka audit transport",
  "kind": "cold",
  "state": "isolated",
  "activation": "restart",
  "host_api": "v1alpha1",
  "version": "v0.0.0",
  "module_path": "example.com/security/corp-audit-kafka",
  "source": ".",
  "provides": ["audit.sink.kafka.v1"],
  "requires": ["audit.host.v1"],
  "conflicts": ["audit-kafka"],
  "registration": {
    "type": "audit.kafka.factory.v1",
    "package": "example.com/security/corp-audit-kafka",
    "symbol": "Factory"
  },
  "targets": {
    "goos": ["linux"],
    "goarch": ["amd64", "arm64"],
    "cgo": false,
    "fips": "unknown"
  },
  "licenses": ["Apache-2.0"],
  "security": {
    "removable": true,
    "failure_policy": "fail-open"
  }
}
```

For an isolated module, `source` must remain inside the manifest directory and
contain a `go.mod` whose `module` directive exactly matches `module_path`.
Registration symbols must be exported. The source and manifest are fingerprinted
without recording an absolute local path.

The only current registration adapter is the Kafka audit factory seam. This
restriction is deliberate: manifests cannot inject code-generation snippets.
A stable typed registrar outside `cmd/` is required before additional module
families or remote versions become supported.

Local replacements use repository-relative build metadata and content digests
without absolute paths in the lock. They are suitable for development builds;
supported releases must pin publishable module versions and checksums.

## Profile meanings

### `standard`

The compatibility bundle. It still links the current large composition and is
the default for `go build ./cmd/sso-server` and `python cli.py build`.

### `standard-kafka`

The compatibility bundle plus `github.com/snaplink/sso/kafka`, registered
explicitly at process startup. Enabling `audit.kafka` without this compiled
module still fails boot closed.

### `minimal`

The target client-credentials-only OAuth server selects these dependencies:

```text
core-runtime -> core-http, identity-memory, signing-ed25519
core-http + identity-memory + signing-ed25519 -> oauth-client-credentials
core-http + signing-ed25519 -> oauth-metadata
```

It is not yet buildable. `python cli.py modules plan --profile minimal` is the
resolver-backed extraction backlog and must reach `buildable: yes` before a
minimal artifact is published.

## Cold versus hot capability boundary

| Keep cold | Candidate for later hot activation |
|---|---|
| middleware order and trusted proxies | fail-open background detectors |
| identity/OAuth stores and migrations | isolated notification/webhook exporters |
| issuers, keys, JWKS, KMS/HSM | prevalidated WASM policy generations |
| grant handlers and discovery shape | precompiled admin/debug route slots |
| cluster/revocation/signing-key bus | external typed authenticator processes |
| primary audit/redaction/hash chain | secondary audit taps after dynamic drain exists |
| stateful login/MFA/device/CIBA/SAML flows | stateless adapters with no cross-request state |

Runtime activation requires a static route/capability slot, generation leases,
blue/green readiness, drain, reverse-order cleanup and transition audit. The
current router, readiness slice and audit sink registry do not satisfy those
requirements.

Third-party installable hot plugins will be separate processes over a typed,
authenticated protocol. Go `.so` plugins are not a supported extension
mechanism.

## Adding a maintained module

1. Define the capability and failure policy; security invariants remain kernel.
2. Put implementation code in its owning architectural layer or nested module.
3. Add a strict manifest and catalog/profile entry.
4. Add only a typed, allow-listed registration adapter; no `init`, blank import
   or arbitrary generator expression.
5. Prove dependency closure and absence from profiles that exclude it with
   `go version -m`, binary symbols/SBOM and behavioral tests.
6. Update the feature matrix, this guide and release profile documentation.
7. Run:

   ```bash
   python cli.py modules check
   python -m pytest checks/test_modules.py -q
   go build ./... && go vet ./...
   go test -run 'TestMaintainability_|TestArchitecture_' .
   ```
