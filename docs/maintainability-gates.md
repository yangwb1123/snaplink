# Maintainability gates

Automated guardrails that keep this codebase maintainable over long, largely
autonomous (AI-agent-driven) development — where the failure mode isn't a broken
build but *silent erosion*: god-files, import cycles, leaf-package creep. The
Go compiler and the per-**function** complexity linters don't catch these, so we
encode the missing rules as **committed tests** that run inside the normal
`go test ./...` / `make ci` gate.

## Why tests (not Makefile / hooks / CI scripts)

`make harness` generates a separate gate stack (`.check-*.sh`, `.githooks/`,
`docs/agent-os/HARNESS.md`, `SKILLS/`) and historically also rewrites `Makefile` / `AGENTS.md`,
so anything placed there is fragile and gets clobbered. A gate written as a
committed Go test is **conflict-free**: it can't be regenerated away, it runs
everywhere `go test` runs (CI's `go test -race`, `make race`, a developer's
`go test ./...`), and it needs zero extra wiring. New gates should follow this
pattern.

> `make ci` is `fmt vet race build proto-lint ci-modules`. The file-size and
> architecture gates ride the `race` step (`go test -race -count=1 ./...`).
> Do **not** run `make harness` with uncommitted work — it pollutes the tree
> (see the gitignore'd harness paths).

## The gates

### 1. Per-file size budget — `maintainability_budget_test.go`

Fails any non-exempt, non-generated production `.go` file over **500 lines**.
Files much larger than this are disproportionately expensive for humans and for
agents to hold in context, and accrete into god-files. (This gate exists because
a session grew `handlers.go` to 4405 lines unnoticed.)

### 2. Architecture import boundaries — `architecture_gate_test.go`

Enforces the dependency-direction invariants `AGENTS.md` declares (parsed via
`go/parser`):

- `oauth` MUST NOT import `oidc` — prevents the `oauth`↔`oidc` cycle.
- `core` MUST import **no** internal package — it is the SPI/types/sentinels leaf.
- `oidc` MUST NOT import `oauth` — fully enforced, **zero exemptions**. The two
  formerly-grandfathered files were decoupled (`oidc.SubjectRefreshRevoker` for
  refresh revocation; `core.CloneRawJSON` for RAR cloning), so the rule now holds
  with no grandfathered files.

### 3. Cognitive layer boundaries — `architecture_layer_test.go`

Enforces the seven-layer cognitive model (ADR-0006, `docs/architecture/DIRECTORY_MAP.md`):
`shared < platform < domains < protocols < infrastructure < interfaces < composition`.
A package may import only its own layer or a lower (more-shared) one; an upward
import — or an **unclassified** package — fails the build. This is the erosion
guard the flat layout otherwise lacks (the compiler stops cycles, not the
one-way-rule violations that precede them), and it runs over the existing tree
with no import-path moves. Pre-existing upward edges are grandfathered in a
shrink-only `layerExemptions` (9 at adoption, mostly the root god-package fan-in).

### 4. Per-function complexity & length — `maintainability_complexity_test.go`

Fails any non-exempt parent-module function over **cyclomatic 15** or **50
lines** (the line span runs `func` keyword to closing brace and includes nested
closures; the count is the gocyclo algorithm). This is the committed,
whole-module equivalent of the golangci `funlen`/`gocyclo` linters: it runs
inside `make ci` without the linter binaries installed, keys exemptions
precisely by `file:func` (not by substring), and freezes each exemption's value
at introduction as a ceiling so an exempt function may not regress. **The
`cycloExemptions` and `funcLenExemptions` maps are now empty (caps 0) — every
function is within budget.** Regenerate after a refactor with
`SEED_MAINTAINABILITY=1 go test -run TestSeedMaintainabilityExemptions -v .`.

### 5. Directory fan-out — `directory_fanout_test.go`

Fails any directory holding more than **10 non-test `.go` files** or more than
**15 subdirectories**. Oversized *flat* packages are hard for humans and agents
to navigate; this nudges new code toward cohesive sub-packages. Same
frozen-ceiling ratchet: the dirs already over a cap (the large library packages
plus the module root's subdir count) are grandfathered shrink-only; a new
over-cap dir fails. Reducing a library package means a sub-package split — a
public-API (import-path) change — so the existing ones are grandfathered rather
than force-split; `package main` dirs (e.g. `cmd/`, consolidated to
`sso-server` + `sso-ctl`) come down first. Regenerate with
`SEED_DIRFANOUT=1 go test -run TestSeedDirectoryFanout -v .`.

### 6. Directory depth — `maxdepth_test.go`

Fails any package nested deeper than **3 levels** under the module root
(`gen/`, `ops/deploy/`, `testdata` exempt). Keeps the tree shallow enough to
navigate; a new backend/variant flattens into the parent name
(`webauthnsqlite`, `encryptionaesgcm`) rather than nesting a 4th level.

## The ratchet rule (important)

Every gate above carries a frozen exemption list of the files / functions / dirs
that already violated the rule when the gate was introduced (the per-function
and per-file lists have since reached **zero**). **A list may only shrink.**

- A **new** violation fails the build — fix it, don't add to the list.
- The gate also flags **stale** exemptions (a file refactored back under budget,
  or whose forbidden import was removed) so they get deleted. The backlog
  therefore trends monotonically to zero.

## When a gate fails — what to do

| Failure | Do | Don't |
|---|---|---|
| File > 500 lines | Split cohesive groups into `*_<domain>.go` in the same package (see `handlers_admin.go` / `handlers_b2b.go` — pure relocation, `goimports -w`, build+test). | Add it to the exemption map. |
| Function > 50 lines / cyclo > 15 | Extract behavior-preserving sub-functions (see `skills/refactor-high-complexity.md`); keep wire codes / gate order verbatim. | Self-exempt the new function. |
| Dir > 10 `.go` files / > 15 subdirs | Split the flat package into cohesive sub-packages (for `package main` dirs this is non-breaking). | Grandfather a new dir. |
| Forbidden import | Invert the dependency (move the shared type to `core`, or pass a dep via an interface). | Add it to `exempt`. |
| Stale exemption flagged | Delete the entry. | Leave it. |

## How to add a new gate

Write a committed `*_test.go` in `package sso` at the repo root (or in `test/`),
walking the tree with `filepath.WalkDir` (reuse `skipDirs`), and `t.Error` on
violations with a ratcheting exemption map. Prove it both passes today **and**
fails a deliberately-bad probe before committing.

## Relationship to the existing gates

- **golangci** (`.golangci.yml`, `make lint`): additional per-**function**
  checks (`gocognit`, style/bug linters) beyond the committed cyclo/funlen gate
  (gate 4 above), which is the source of truth for cyclomatic ≤ 15 / length ≤ 50
  and runs inside `make ci` without the linter installed. (Note: `lint` is a
  separate target — not part of the committed `make ci`; CI runs it as its own
  job.)

## Roadmap (not yet built)

- **Coverage floor**: a `tools/covercheck` + ratcheting `coverage_budget.json`
  (per-package floors that only rise). Can't be a self-contained test — coverage
  is finalized after the run — so it needs a CI step (a standalone
  `.github/workflows/quality.yml`, not the harness-owned `ci.yml`).
- **Latency budget**: an in-memory hot-path (`/auth/login`, `/token`) p95 test
  with a generous catastrophe ceiling (rides `go test`), plus `benchstat`-vs-baseline
  regression checking in CI for fine-grained SLOs.
