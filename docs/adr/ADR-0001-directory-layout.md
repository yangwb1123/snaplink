# ADR-0001 — Directory layout: flat library, composition-only root

## Status

Accepted. (Reaffirmed by the 2026-06-19 architecture audit.)

## Context

snaplink is an OAuth2/OIDC SSO **library + binary**, not a deployable app. Its
~53 top-level package directories (`oauth/`, `oidc/`, `core/`, `security/`,
`defaultimpl/`, …) and its public import paths (`github.com/snaplink/sso/...`)
are a **published API contract** that external embedders and the 11 nested
modules depend on.

A proposal surfaced to retree the repo into an application-style
`domains/ application/ infrastructure/ interfaces/` hierarchy with a fixed
"max 10 root directories" allowlist. An audit measured the impact against the
real tree:

- 53 dirs hold Go code; 47 fall outside the proposed allowlist (i.e. nearly the
  whole codebase would be "illegal").
- The move would rewrite import paths across 367+ files (root), 219 (core),
  106 (oauth), and rename 11 nested `go.mod` module paths whose
  `replace => ../` directives are depth-sensitive — a breaking change for every
  downstream consumer, for naming benefit only.
- It would also have to be co-ordinated atomically with the path-keyed
  committed gates or CI breaks (see ADR-0005).

## Decision

1. **Keep the flat, domain-per-directory layout.** Directory count is not
   capped; a new cohesive concern gets its own top-level package.
2. **The repo root is composition-only.** Root may hold *only*
   server-wiring/composition files (`sso.go`, `server_*.go`, `accessors*.go`,
   `options*.go`, `handlers.go`, `aliases.go`, `mesh_authz.go`,
   `signing_key_aggregation*.go`, `storage_health.go`, `sso_*.go`). No
   `*_handler.go` / `*_service.go` / `*_store.go` / `*_grant.go` and no business
   logic in root. Non-exempt root file count ≤ **15**.
3. **No `domains/application/infrastructure/interfaces` retree** unless and
   until a major (v2) version with deprecation-alias windows is explicitly
   undertaken. The target tree is recorded as conceptual documentation, not an
   executable migration.

## Consequences

**Pros**
- Public import paths stay stable; no consumer breakage.
- New work extends existing packages instead of inventing root directories.
- The root god-package problem is addressed by *internal* decomposition
  (hexagonal `HandleX(deps Deps, ctx)` extraction), not by moving files across
  module boundaries.

**Cons**
- The root `package sso` remains large (the one genuine cohesion smell); it is
  shrunk gradually and sequentially, not via a big-bang.
- "Many top-level directories" can look like sprawl to newcomers; this ADR plus
  the AGENTS.md module map are the orientation.

**Risks**
- Drift: someone adds a business file to root. Mitigated by `python cli.py
  check-root` (`checks/root_business_code.py`) and the ≤15 count
  (`checks/root_files.py`, surfaced in `cli.py accept` `[U8]`).

## Enforcement

`python cli.py check-root` · root file count in `python cli.py accept`.
Manifest: [`.arch/rules.yaml`](../../.arch/rules.yaml) `root:`.
