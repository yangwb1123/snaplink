Design doc produced: `docs/auto/domains-tokenpolicy-direction3-design.md` (418 lines, mirrored to `docs/architect-analysis/auto/`), following the direction-2 design convention.

## What I verified before writing

Re-checked every spec citation against the tree — all held, plus three findings that shaped the design:

- **`server_token.go` is at exactly 500 lines** — the scope-combo call-site edit must be an argument added on the existing line; any added line fails the file gate. This is now breakage-risk #1.
- **`createSession` already takes `tenantID`** (`server_logout.go:345`) — the session seam needs no new plumbing at its call site, and `ensureJITMembership` runs *before* it (line 46 vs 149), so a JIT-provisioned role is visible to the seam on first login.
- **`TestParseYAML_Empty` asserts a stray `other: 1` key parses as "no policies"** — strict parsing flips this to an error; the fixture must change in the same edit (spec didn't call this out).

## Design decisions (`##` headings)

1. **Selector model** — `Policy`/`PolicyInput` gain `TenantID`/`Subject`/`SubjectRoles`; empty tenant = global; additive union with existing strictest-wins keeps tenant rules tighten-only; zero input tenant ⇒ single-tenant byte-compat.
2. **`matches()` refactor** — shared `prefixOrExact` helper (same semantics as `scopePresent`); subject selectors match the *local* subject ID, not pairwise `sub` (documented).
3. **Strict YAML + `Validate([]Policy)`** in a new `validate.go` — `DisallowUnknownField` (conditionalaccess precedent), bare/interior `*` rejected, roles validated against `core.TenantRole` constants (tokenpolicy already imports `shared/core` — single source of truth, no literal duplication); wired into both the File and inline config paths so strictness isn't bypassable.
4. **Four-seam threading** — tenant always read from `client.TenantID` (consistent with `tenantTokenStrategies` key isolation, never the header-derived tenant); role resolution inline at the session seam, fail-open; refresh-seam role no-op documented as a known limitation with the extension point named.
5. **`core.Subject.TenantID`** — mint-time stamp at all 10 verified issue sites, explicitly **not** a JWT claim (buildAccessPayload enumerates claims; a claim-set test pins it).
6. **Admin/docs** — zero new endpoints; verbatim serialization carries the new fields; openapi.yaml:6836 + config-reference.md:588 synced in the same change.

Plus **Storage model** (no new storage — one read-only `TenantUserStore.Get` at one seam), **Failure modes** (12-row table), **What could break the design** (10 risks with pins), **Test plan**, and the §5.6 contract table. No `.go` files were changed; no gates run, per convention.
