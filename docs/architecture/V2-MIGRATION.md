# v2 topology migration — the breaking convergence plan

**Status: EXECUTED in-place (uncommitted).** The layered tree below has been
applied: the ~38 library packages moved into the 6 layer dirs, the public Server
API moved to `interfaces/sso`, nested modules moved under `infrastructure/`, and
all imports were rewritten — **WITHOUT** bumping the module path (it is still
`github.com/snaplink/sso`, an internal reorg). Top-level dirs 60→15, root `.go`
files 53→4, all gates + tests green. NOTE: because the module path was NOT bumped,
this is a *breaking change without a version change* for any external consumer —
when committed/published it SHOULD ride a `…/v2` major tag (the codemod below
becomes the consumer migration). The original blueprint follows for reference.

---

This is the concrete blueprint for collapsing
the ~38 flat public packages into ~9 layered top-level directories. It is a
**breaking, major-version (v2) change**: every moved package's import path
changes, so every downstream consumer must update its import lines. Do NOT run any
of this on a v1 line — see [ADR-0003](../adr/ADR-0003-protocol-grouping.md).

The v1-safe cognitive view (layer map + enforced gate) lives in
[DIRECTORY_MAP.md](DIRECTORY_MAP.md); it delivers the "9 groups, not 60 dirs"
newcomer model **without** breaking imports. This document is what to execute only
when you deliberately cut `github.com/snaplink/sso/v2`.

## Why it must be a major version

A Go import path **is** the on-disk directory path. Moving `oauth/` to
`protocols/oauth/` changes `github.com/snaplink/sso/oauth` →
`github.com/snaplink/sso/v2/protocols/oauth`. There is no non-breaking way to
relocate a public package:

- Type aliases + function re-exports from the old path would **double** the
  package count (shim + real), making topology worse, and Go has no
  package-level alias, so every exported symbol needs a hand-written forwarder.
- `go.mod` `retract` / `replace` do not rewrite import paths for consumers.

So the only honest options are (a) keep paths flat on v1 (the map handles
cognition), or (b) take the break in a v2 tag. This plan is (b).

## Target structure (9 top-level dirs)

```
github.com/snaplink/sso/v2/
├── cmd/            (unchanged — binaries)
├── docs/           (unchanged)
├── test/           (unchanged — integration suite)
├── shared/         core, spi, security
├── domains/        tenant, region, permissions, federation, connections,
│                   metering, anomaly, authenticators, compliance
├── protocols/      oauth, oidc, scim, fapi, caep, selfservice
├── platform/       cluster, signingkeys, registry, netpolicy, metrics,
│                   tracing, bootstrap, releases, migrate, geo, audit
├── interfaces/     grpcserver, adapters, admin, middleware, cors, ratelimit,
│                   web, ssoclient, snapshot, gen, proto   (+ root Server pkg)
├── infrastructure/ defaultimpl (+ /sqlite, /vaulttransit), kms/*
└── internal/       (unchanged path; already layer-aligned)
```

The buckets are exactly `layerName()` in `architecture_layer_test.go` — the gate
already proves the dependency direction holds, so the physical move cannot
introduce a new cycle that the gate would not already have caught.

## Per-package move table

| From (v1, flat) | To (v2) |
|---|---|
| `core`, `spi`, `security` | `shared/` |
| `tenant`, `region`, `permissions`, `federation`, `connections`, `metering`, `anomaly`, `authenticators`, `compliance` | `domains/` |
| `oauth`, `oidc`, `scim`, `fapi`, `caep`, `selfservice` | `protocols/` |
| `cluster`, `signingkeys`, `registry`, `netpolicy`, `metrics`, `tracing`, `bootstrap`, `releases`, `migrate`, `geo`, `audit` | `platform/` |
| `grpcserver`, `adapters`, `admin`, `middleware`, `cors`, `ratelimit`, `web`, `ssoclient`, `snapshot` | `interfaces/` |
| `defaultimpl` | `infrastructure/` |
| root `package sso` (`*.go`) | stays at module root (the facade) OR `interfaces/sso/` |

## Nested modules need their own decision

`saml`, `ldap`, `kerberos`, `radius`, `extauthz`, `redis`, and `kms/*` each own a
`go.mod`. They are **separate modules**, not subdirectories of this one — moving
them is a per-module v2 tag of *that* module, independent of the core module.
Recommend: relocate them under `infrastructure/` / `protocols/` paths in the
same sweep but tag each module's own v2 (e.g. `…/v2/infrastructure/ldap`), and
update the core module's `require`/`replace` accordingly.

## Execution (deterministic, scriptable)

1. **Bump the module path** in `go.mod`: `module github.com/snaplink/sso/v2`.
2. **Move directories** (one layer at a time, compile after each):
   ```sh
   mkdir -p protocols && git mv oauth oidc scim fapi caep selfservice protocols/
   # …repeat per layer table…
   ```
3. **Rewrite imports** across the tree with a path-aware codemod. Per moved
   package, one rule:
   ```sh
   gofmt -w -r '"github.com/snaplink/sso/oauth" -> "github.com/snaplink/sso/v2/protocols/oauth"' .
   # gofmt -r only rewrites expressions, NOT string import paths — so use the
   # import-path-aware tool instead:
   find . -name '*.go' -not -path './vendor/*' \
     -exec sed -i 's#snaplink/sso/oauth"#snaplink/sso/v2/protocols/oauth"#g' {} +
   ```
   Generate the full sed script from the move table (≈38 rules). Order
   longest-prefix-first so `…/oauth/handle_*` style sub-package paths rewrite
   before the bare `…/oauth`.
4. **Regenerate** protobuf/gateway stubs (their `go_package` options carry the
   import path): update `proto/**/*.proto` `option go_package`, re-run `buf
   generate`.
5. `go mod tidy` per module; `go build ./...`; `go vet ./...`.
6. Run the full gate + race suite: `make fmt vet race build proto-lint lint
   ci-modules` (NOT `make ci` — it triggers `make harness` which rewrites
   tracked files; see the project's harness-pollution note).
7. Update `architecture_layer_test.go` `layerName()` to key off the **new**
   path segments (now `protocols/oauth` etc.) — most of the switch collapses to
   "first path segment IS the layer," shrinking the classifier.
8. Update `DIRECTORY_MAP.md`, `ADR-0001`, `ADR-0003` to record the cut.

## Consumer migration (ship with the v2 tag)

Provide a one-shot codemod consumers run against their own trees:
```sh
# snaplink-v2-imports.sh — rewrites v1 import paths to v2 layered paths
sed -i -E \
  -e 's#snaplink/sso/(oauth|oidc|scim|fapi|caep|selfservice)"#snaplink/sso/v2/protocols/\1"#g' \
  -e 's#snaplink/sso/(tenant|region|permissions|federation|connections|metering|anomaly|authenticators|compliance)"#snaplink/sso/v2/domains/\1"#g' \
  -e 's#snaplink/sso/(cluster|signingkeys|registry|netpolicy|metrics|tracing|bootstrap|releases|migrate|geo|audit)"#snaplink/sso/v2/platform/\1"#g' \
  -e 's#snaplink/sso/(grpcserver|adapters|admin|middleware|cors|ratelimit|web|ssoclient|snapshot)"#snaplink/sso/v2/interfaces/\1"#g' \
  -e 's#snaplink/sso/(core|spi|security)"#snaplink/sso/v2/shared/\1"#g' \
  -e 's#snaplink/sso/defaultimpl#snaplink/sso/v2/infrastructure/defaultimpl#g' \
  $(find . -name '*.go')
```
Pair it with a `MIGRATING.md` mapping table and a CHANGELOG `BREAKING` entry.

## Risk / effort

- **Mechanical, not behavioral.** No logic changes — pure path moves + import
  rewrites. The layer gate already proves the dependency graph is acyclic and
  downward, so the move cannot surface a hidden cycle.
- **Blast radius is total but shallow:** every file's import block changes; no
  function bodies do. The race suite + integration tests are the safety net.
- **Effort:** ~1 focused day for the core module + a few hours per nested
  module, dominated by proto regen + CI wiring, not by the moves themselves.
- **Reversible** before the tag is published; **irreversible** for consumers
  once `v2` is out (hence: do it once, batch ALL layers in the same cut).

## Recommendation

Do this only when there is an independent reason to cut a major version (a real
API break you already owe consumers). Bundling the topology move into *that* cut
makes it free-of-marginal-breakage. Until then, the flat paths + the enforced
layer map are the correct steady state for a published SDK.
