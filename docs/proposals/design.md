Design doc written to `docs/auto/domains-tokenpolicy-design.md`, grounded in grep-verified code (not just the spec). Key decisions, each under its own `##`:

**API surface**
- `ParseYAML` → `DisallowUnknownField` only (stays a pure parser; `Validate` needs `defaultTTL`, which is a wiring concern, so the conditionalaccess-style combined loader doesn't transfer — strictness parity is what matters).
- `Policy.Validate(defaultTTL) error` (hard errors: negatives, renew ∉ (0,1], empty name) split from `AdvisoryWarnings(defaultTTL) []string` (MaxTTL > default) so warnings can never block.
- `Store` gains `Get`/`Put`/`Delete` + `ErrPolicyNotFound` (value-returning `Get`, unlike threataction's pointer). Breaking change, but grep shows only in-repo implementers.
- Three `:name` admin routes with the threataction decode-vs-semantic split (`invalid_request` vs `invalid_policy` + description), `admin:read`/`admin:write` via the default middleware method rule, mounted only under `WithTokenPolicy`.
- `HandleAdminPutPolicy` returns `bool` — the minimal contract change letting the thin server wrapper publish the invalidation event without pulling the bus into the domain package.

**Two deliberate spec refinements (called out in the doc)**
1. Default-TTL visibility: `PolicyInput.DefaultTTL` + `NewClampingIssuer(inner, store, defaultTTL)` with a new `WithTokenPolicyDefaultTTL` wired from `cfg.Server.TokenTTL` — the same value `build_signing_issuers.go` already feeds the issuers. The doc flags the #1 risk: if those two plumbing points diverge, the min-clamp can still widen.
2. The spec's "sqlite 与 File/Policies 互斥" + "空表时播种" tension: resolved as `sqlite` + optional seed-source, seed applied only when the table is empty (first boot), with a loud skip log. Strict exclusivity would make the spec's own seed sentence unreachable.

**Storage model**: single `token_policies (name PK, policy_json)` table, `platform/migrate` v1 baseline, `modernc.org/sqlite`; memory store becomes map-keyed COW preserving *insertion order* (deliberately not name-sorted — re-sorting would silently change which deny reason lands in the audit for overlapping rules); sqlite orders by name, divergence documented. Snapshot model: write-sync refresh + bus-triggered `Refresh` (`KindTokenPolicyChange`, keyless whole-list event like `KindDiscoveryReload`) + recovery reseed; `Policies()` never touches disk.

**Failure modes**: full table — all fail-open contracts preserved; new loud failures at boot and `400 invalid_policy` on write.

**What could break it**: 9 risks ranked, with mitigations — TTL-plumbing divergence (worst), Store-interface breakage, deny-reason ordering drift across backends, seed-skip surprise, stale-snapshot over-deny, dropped publish, strict-parse boot breaks for existing typo'd configs, `NewClampingIssuer` signature churn, migration namespace collisions.

The doc closes with the acceptance-test mapping and the `make ci` gate sequence.
