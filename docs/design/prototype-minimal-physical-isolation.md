# Design: prototype/minimal physical package extraction

Promotes the open boundary declared in `README.md` ("package-level isolation
remains an extraction target"), `docs/architecture/DIRECTORY_MAP.md`
("prototype and minimal target the dedicated `cmd/sso-minimal` composition
root"), and `docs/deferred-backlog.md` ("shares the broad `cmd/sso-minimal`
dependency graph" / "not yet physically isolated from it") into an
implemented, evidence-backed extraction. All file/line references were
re-verified against the working tree before writing.

## Current state (verified)

- `ops/build/profiles/prototype.json` and `ops/build/profiles/minimal.json`
  BOTH select `build.package: "./cmd/sso-minimal"` with binary/program
  `snaplink`. The two editions compile the same 14-file, 2158-line package;
  the runtime difference is `buildinfo.BuildProfile` (ldflags) plus the
  `edition.go`/`surface.go` runtime switches inside the package.
- `cmd/sso-minimal` non-test files: `app.go` (206), `commands.go` (114),
  `config.go` (217), `edition.go` (38), `grant_filter.go` (64), `logger.go`
  (52), `main.go` (59), `op_session.go` (325), `server.go` (64),
  `surface.go` (182). Tests: `config_test.go`, `edition_test.go`,
  `flow_test.go`, `surface_test.go`.
- `ops/build/profile-isolation.json` currently declares `billing` / `small` /
  `full`; the `small` row is "prototype + minimal editions share one binary
  (`cmd/sso-minimal`)" and its `must_link` includes `protocols/oidc`.
  `python cli.py profiles evidence` builds and asserts it.
- `docs/architecture/profile-isolation.md` already states the boundary rule
  that constrains this design: *"The protocol SDK itself is deliberately
  shared: `interfaces/sso` is the product's SDK surface... Physical isolation
  therefore targets the infrastructure/admin/durable graph, not the SDK."*
- `ops/scripts/profile_release.py` writes `not_claimed:
  ["complete_package_level_physical_dependency_isolation"]` into every SKU
  evidence bundle (pinned by `checks/test_profile_release.py`).
- `interfaces/sso` is at its 60-file ceiling (AGENTS.md budget table);
  it directly imports `protocols/oidc` in ~20 files, and
  `internal/handler`, `internal/handler/tokengrant`, and
  `infrastructure/defaultimpl` also import `protocols/oidc`.

## Decision 1 — Extraction shape: two cmd roots + one shared composition library

**Decision.** Create `cmd/sso-prototype` as the prototype composition root;
keep `cmd/sso-minimal` as the minimal composition root; sink the
edition-generic composition code into a new library package
`internal/composition` that both roots import. This is the "three packages"
option (two `package main` roots + one library), not two self-contained roots
and not a third cmd root.

**Evidence and reasoning (criterion: minimal change + verifiable isolation
increment):**

- *Two roots sharing one cmd package* (today) provides zero isolation — the
  edition-decision code lives in one package and both profiles build it.
- *Two fully self-contained cmd roots* (naive copy) is rejected by the
  no-duplicate rule (Decision 2): `op_session.go` (325 lines), `logger.go`,
  `server.go`, and `grant_filter.go` are edition-generic and would be copied
  verbatim with drift risk and no behavioral gain.
- *A third cmd root* cannot host shared code: "no package imports `cmd/`"
  (AGENTS.md architecture invariants), so shared composition code must be a
  library package. The only question is where it lives (Decision 2).
- *Verifiable isolation increment:* after the split the two binaries' package
  graphs are disjoint at the composition layer — `cmd/sso-prototype` links
  into the prototype binary only, `cmd/sso-minimal` into the minimal binary
  only, and each binary must NOT link the other edition's root. This is
  mechanically provable with `go list -deps` through the
  `must_link`/`must_not_link` machinery that already backs
  `python cli.py profiles evidence`.

## Decision 2 — Shared-code disposition: sink, never copy; per-edition files stay per-root

**Rule.**

1. A file whose behavior is byte-identical across editions AND required by
   both editions sinks to `internal/composition` (single source of truth):
   `op_session.go`, `logger.go`, `server.go`, `grant_filter.go`, the
   `execute()` flow, the command/inventory handling, and the generic parts of
   `config.go`/`app.go` (parsing, validation, seeding, server assembly —
   parameterized by an `Edition` descriptor and injected per-edition option
   hook).
2. A file that must differ per edition stays per-root, each edition-flavored:
   `edition.go` (the descriptor), `surface.go` (metadata narrowing + route
   gating), and the thin per-root `app.go` wiring (the OIDC/tracing option
   hook).
3. Never copy code that would be dead in the other edition. In particular the
   prototype root contains **zero** OIDC surface references: no OIDC metadata
   keys, no `userinfo`/`end_session`/OIDC-discovery routes, no `openid`
   default scope, no `WithIDTokenIssuer`/`WithTracingMiddleware` wiring. The
   minimal-only OIDC surface is compiled out of prototype by not existing in
   its root.

**Why `internal/composition` and not `interfaces/sso` or `shared`:**

- `cmd/` packages cannot be imported, so the shared code cannot stay there.
- `interfaces/sso` is at its 60-file ceiling and is the public product SDK
  surface ("public API-only Server" in DIRECTORY_MAP); the CLI/HTTP/seed
  composition is not SDK material. A subpackage `interfaces/sso/composition`
  would also be classified as the `interfaces` layer by the first-segment
  rule, letting interfaces-layer packages import composition — semantically
  wrong.
- `shared/` is the dependency-free kernel (`shared/core` imports no Snaplink
  package); composition imports the SDK, so it cannot live there.
- `internal/` is the documented home for unexported helpers
  (`internal/auth` → domains, `internal/handler` → interfaces), and the layer
  gate already classifies `internal/*` packages by content. `internal/composition`
  is classified as the `composition` layer — exactly the rank that is allowed
  to import everything and that only `cmd/`-layer packages import downward.
  This requires the standard `layerName()` classification entry for a new
  `internal/` package (a required classification, not a maintainability
  exemption; exemptions stay frozen).

**Boundary honesty.** `protocols/oidc` remains linked into BOTH binaries
through the shared product SDK: `interfaces/sso` (≈20 files),
`internal/handler`, `internal/handler/tokengrant`, and
`infrastructure/defaultimpl` all import it unconditionally. Physically
excluding it from prototype would require restructuring the shared SDK used
by `cmd/sso-server` (full) and the standard compositions — forbidden by the
hard boundary "do not touch full/standard". This matches the existing
declared boundary (`docs/architecture/profile-isolation.md`: isolation
targets the infrastructure/admin/durable graph, not the SDK) and
`profile_release.py`'s explicit `not_claimed` list. The residual is
documented, not papered over; the OIDC **surface** (metadata, routes, scopes,
wiring) moves out of the prototype composition root while the shared SDK
protocol code remains a tracked shared dependency.

## Decision 3 — Profile wiring

- `ops/build/profiles/prototype.json`: `build.package` →
  `"./cmd/sso-prototype"` (binary/program stay `snaplink`;
  `composition_module` stays `sso-prototype-runtime`).
- `ops/build/profiles/minimal.json`: unchanged (`"./cmd/sso-minimal"`).
- `checks/test_modules.py::test_prototype_uses_its_own_build_target` and
  `checks/test_profile_release.py` prototype expectations update to
  `./cmd/sso-prototype`; `.goreleaser.yaml` `snaplink-prototype` build
  `main:` updates to `./cmd/sso-prototype`.
- Verification: `python cli.py configure --profile prototype --build` and
  `--profile minimal --build` both succeed (lock + binary + native inventory
  + version checks are part of configure), and the unlocked (non-configured)
  fallback inventory in each root reports only its own edition's modules.

## Decision 4 — Isolation evidence (`python cli.py profiles evidence`)

- `ops/build/profile-isolation.json`: the `small` row **splits** into
  `prototype` and `minimal` rows (the old row asserted one binary serving
  both editions; after extraction each edition is its own binary):
  - `prototype`: binary `./cmd/sso-prototype` → `sso-prototype`;
    `must_link` includes `cmd/sso-prototype`, `domains/authenticators`,
    `infrastructure/defaultimpl`, `interfaces/sso`,
    `platform/lifecycle/sessionhub`, `protocols/oauth`, `shared/core`;
    `must_not_link` includes `cmd/sso-minimal`, `cmd/sso-server`,
    `config/`, `interfaces/grpcserver`, `infrastructure/postgres`,
    `infrastructure/redis`, `protocols/scim`, and the rest of the
    small-edition exclusions.
  - `minimal`: binary `./cmd/sso-minimal` → `sso-minimal`;
    `must_link` additionally includes `protocols/oidc` (it must serve the
    OIDC surface); `must_not_link` includes `cmd/sso-prototype` plus the
    same durable/admin/observability exclusions.
- `ops/scripts/profile_evidence.py`: the summary delta line compares `full`
  vs `minimal` (the larger small edition), and the per-row output now shows
  prototype/minimal/billing/full. An extra printed delta shows the
  prototype↔minimal composition-root difference.
- What the evidence proves, precisely:
  - prototype links `cmd/sso-prototype` and NOT `cmd/sso-minimal`; minimal
    links `cmd/sso-minimal` and NOT `cmd/sso-prototype` — the two editions'
    composition code is physically disjoint (before this change prototype
    *was* `cmd/sso-minimal`).
  - both keep the durable/admin/observability graph out (unchanged
    exclusions);
  - `protocols/oidc` is *not* asserted absent from prototype — it is linked
    through the shared SDK. This is documented in the evidence doc and in
    `docs/architecture/profile-isolation.md`; `profile_release.py` keeps its
    `not_claimed` contract unchanged.
- Acceptance (testable): prototype binary `go list -deps` contains
  `cmd/sso-prototype` and not `cmd/sso-minimal`; minimal contains
  `cmd/sso-minimal` and not `cmd/sso-prototype`; the `profiles evidence`
  command exits 0 with zero violations; minimal's package set includes
  `protocols/oidc`.

## Decision 5 — Hard boundaries

1. **No runtime behavior change.** Both editions serve exactly the routes,
   metadata, scopes, and session semantics they serve today; per-edition
   tests are the same assertions that currently run against `cmd/sso-minimal`
   (split by edition, none skipped). The unlocked-build inventory fallback
   keeps reporting the same module/capability identity per edition.
2. **full/standard untouched.** Their build packages, modules, and evidence
   rows are unchanged; `internal/composition` is imported only by the two
   small cmd roots.
3. **No maintainability exemptions.** `internal/composition` gets ≤10
   non-test files per directory, each ≤500 lines, complexity ≤15; both cmd
   roots stay at 4 non-test files each; `layerName()` gains only the required
   classification for the new `internal/` package; no `layerExemptions` entry.
4. **cmd/ directory budgets.** `cmd/sso-prototype` ≤10 non-test .go files
   (4 planned), no new subdirectories; directory depth ≤3
   (`internal/composition` = depth 2).

## Implementation checklist

1. New `internal/composition` package (edition-generic code + `Edition`
   descriptor + `Execute`/`BuildHandler`/surface envelope).
2. New `cmd/sso-prototype` root (main, edition descriptor, surface, app
   wiring) with prototype-flavored flow/edition/surface tests; adapt
   `cmd/sso-minimal` to thin minimal root with minimal-flavored tests.
3. Profile/evidence wiring: `prototype.json`, `profile-isolation.json`,
   `profile_evidence.py`, `checks/test_modules.py`,
   `checks/test_profile_release.py`, `.goreleaser.yaml`.
4. Doc sync: README, DIRECTORY_MAP, deferred-backlog,
   `docs/architecture/profile-isolation.md`, `docs/plugin-system.md`,
   `docs/RELEASE.md`, `docs/deployment.md`, `docs/feature-matrix.md`,
   `docs/fips.md`, `docs/ROADMAP.md`; CHANGELOG.md Added.
5. Verify: both `configure --profile {prototype,minimal} --build`,
   `profiles evidence`, `go build ./... && go vet ./...`,
   `go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .`,
   and both roots' tests; conventional commit (AI co-author trailer,
   `dist/`/`bin/` stay ignored).
