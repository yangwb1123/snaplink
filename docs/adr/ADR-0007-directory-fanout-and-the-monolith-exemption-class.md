# ADR-0007 — Directory fan-out budget and the permanent monolith-exemption class

## Status

Accepted (2026-06-20).

## Context

[ADR-0005](ADR-0005-size-and-complexity-budgets.md) set per-**file** (≤500 lines)
and per-**function** (cyclo ≤15, length ≤50) budgets and explicitly rejected a
per-package file-count cap ("would flag healthy, cohesive packages"). A later
gate — `directory_fanout_test.go` — nonetheless added a per-**directory** budget:
**≤10 non-test `.go` files** and **≤15 subdirectories**, with the same
shrink-only ratchet. The motivation is navigability for humans and long-running
agents: a flat 50-file package is hard to form a model of, even when every file
is healthy.

These two budgets are in **direct tension for one cohesive type**: the per-file
500-line limit *splits* a large type's surface across many small files, and the
per-dir 10-file limit then *counts* those files. For a genuinely monolithic type
(one struct with many methods/options, or a binary's composition root), there is
no split that satisfies both **without exporting internals or breaking a
published import path** — which would trade encapsulation / API stability for a
file-count number.

A 2026-06-20 decomposition campaign drove the fan-out backlog down by splitting
every package that *could* be cleanly sub-packaged (re-export facade for public
packages; free-function/SCC grouping for the binary), and a 7-package adversarial
residual scan then confirmed which directories are irreducible. This ADR records
the outcome and blesses the residual as a permanent class.

## Decision

**1. Keep the per-directory fan-out gate** (≤10 files / ≤15 subdirs), ratchet
shrink-only, enforced as a committed test (`directory_fanout_test.go`), per the
[maintainability-gates](../maintainability-gates.md) doctrine.

**2. Recognise a permanent exemption class** — alongside the mechanical
`gen/ops/testdata` exemptions — for directories that cannot reach ≤10 without
violating a higher-priority invariant:

- **monolithic-shared-state** — one cohesive exported type whose methods/options
  bind to its unexported fields; sub-packaging needs the whole field set exported
  (Go also forbids defining methods on a type outside its package).
- **binary-composition-root** — a `package main` whose wiring is one shared
  builder; it has no importers, so the navigability rationale is weakest, and
  splitting needs the builder's fields exported.
- **depth-blocked** — already at the depth-3 limit ([ADR-0001]); a sub-package
  would be depth-4 and fail `maxdepth_test.go`.
- **kernel / highest-blast-radius** — a dependency-free leaf whose consts are
  referenced by literal name (cannot be type-aliased through a facade) by
  hundreds of sites.
- **security-timing-critical** — bcrypt/AMR/anti-enumeration code where a split
  is only acceptable as pure, reviewed relocation.

**A package in this class stays grandfathered; every other over-cap directory
remains on the shrink-only ratchet and must be driven to removal by a split.**
The default split tool for a public package is the re-export facade (type aliases
+ `var`/`const` forwarders), proven repeatedly this campaign (`servercache`,
`config/sources`, the `defaultimpl`/`oauth`/`audit` leaves). **Never break a
published import path to satisfy this gate** — that is a v2-major decision
([ADR-0006]), not a refactor.

**3. The current exemptions and why each is permanent** (counts after the
campaign):

| Directory | Files | Class | Why it cannot shrink further |
|---|---|---|---|
| `interfaces/sso` | 52 | monolithic-shared-state | the public SDK `Server`: ~400 `(s *Server)` methods + ~98 `WithXxx` options bound to its unexported fields (the six embedded `*State` structs). Only the self-contained `servercache` infra was extractable. |
| `infrastructure/defaultimpl/sqlite` | 34 | depth-blocked | already depth-3; a sub-package is depth-4. Also a public store registry. |
| `config` | 26 | monolithic-shared-state | one `Config` aggregate of field-type DTOs read directly as public API by `cmd/`; only the `Source` backends (`config/sources`) were separable. |
| `infrastructure/defaultimpl` | 26 | monolithic-shared-state | the Ed25519/ECDSA/RSA JWS issuer island shares the **unexported** `ed25519Payload` wire type + claim helpers; a per-alg split would export an oracle-relevant claim-mapping surface. Non-crypto clusters already extracted. |
| `domains/federation` | 24 | monolithic-shared-state | 11 of 24 files carry methods on `TrustChainResolver`/`RegistrationClientStore`; `trust_marks`/`registration` call back into the resolver (cycle). The metadata-policy engine is extractable but doesn't bring the dir under budget. |
| `cmd/sso-server` | 23 | binary-composition-root | the `appBuilder` method-core + lifecycle + routes are bound to the unexported `app` struct (`package main`, no importers). Free-function helpers already extracted into `serverbuild{authn,store,sign,platform}`. |
| `shared/core` | 21 | kernel | dependency-free; consts referenced by literal name at ~238 sites cannot be type-aliased through a facade — a split is the highest-blast-radius change in the tree. |
| `protocols/scim` | 19 | monolithic-shared-state | a central `*Handler` with ~46 methods over shared unexported infra; the filter/patch helpers operate on the public `scim.User`/`Group` types and are called by the handler (cycle). |
| `domains/authenticators` | 18 | security-timing-critical | 9 authenticators sharing pervasive `Method*`/`AuthMethod*` consts; bcrypt-dummy-cost + AMR + anti-enumeration timing make a split a reviewed change, not a mechanical one. |
| `platform/audit` | 16 | monolithic-shared-state | the `Recorder` + hash-chain core; the stateless sinks + SPI already extracted into `auditspi`/`auditsink`. |
| `interfaces/snapshot` | 14 | monolithic-shared-state | the `Snapshotter`/`Restorer` core; the storage/encryption/loader backends already live in sub-packages. |

The root directory's subdir count (`.` = 20) is the sole `dirSubdirExemptions`
entry — one subdir per architectural layer plus tooling, not sprawl.

## Consequences

**Pros** — the gate keeps nudging *new* and *splittable* code toward cohesive
sub-packages while no longer pretending a cohesive public type or a binary root
is a defect. The exemption table is self-documenting: each entry names its class
and the invariant that pins it, so a future contributor sees immediately that
re-attempting the split means breaking the SDK or exporting internals.

**Cons** — the per-file and per-dir budgets remain in tension for these types;
the exemption is the deliberate release valve. The table must be kept honest:
when a class-changing refactor *does* become worthwhile (e.g. a v2-major that
re-homes import paths), the corresponding entry should fall.

**Non-goal** — driving these counts to ≤10 by exporting a `Server`/`Config`'s
internal field set, or by relocating published packages. That inverts the
priority order: API stability and encapsulation outrank a file-count number.
