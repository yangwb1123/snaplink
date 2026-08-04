# Architecture Review — Tokenpolicy Governance Lifecycle Design

**Review subject:** `docs/auto/domains-tokenpolicy-design.md` (12 decisions + distributed-systems
appendix) against the current tree. Advisory analysis only; no files modified. Evidence labels:
**Verified** = checked in this review against current code; **Proposed** = design decision, not yet
implemented; **Corroborated** = independently re-verified here, also raised by a prior reviewer.

**Checks that actually ran for this review:** read of the design, the spec
(`docs/auto/domains-tokenpolicy-spec.md`), `AGENTS.md`, `docs/architecture/DIRECTORY_MAP.md`,
`ai-dev/prompts/README.md`; grep/read verification of every wiring seam and precedent cited below;
a compiled Go probe confirming NaN propagation through `RenewExceeded`/`RenewAt`. The QA lead ran
the build/vet/gate commands for this revision (PASS except a pre-existing `make ci` `fmt` failure
in a dirty worktree); I did not re-run the full gates because this review changes no Go code.

## 1. Scope, assumptions, and verified architecture summary

**Scope.** The design adds a validation lifecycle (strict parse + `Policy.Validate` + advisory
warnings), a writable admin surface (GET/PUT/DELETE `:name`), a durable SQLite backend with
first-boot seeding, and cross-replica invalidation to the existing token-policy governance engine.
It touches no credential, revocation, JTI, or session state; evaluation stays fail-open; wire
responses stay oracle-safe. This is a governance-administration change inside the stock
`sso-server`, with no new standardized protocol surface.

**Layer map (Verified).** Every proposed change lands inside an existing layer, respecting the
one-way dependency direction with no new top-level segment and no `layerExemptions`:

| Layer | Proposed surface | Placement |
|---|---|---|
| composition | `wireTokenPolicy` branch (sqlite), seed wiring, `WithTokenPolicyDefaultTTL` | `cmd/sso-server/build_app_security.go:281`, `serverbuildplatform/build_governance.go:197`, `serverbuildsign/build_signing_issuers.go:44,68,97` |
| interfaces | thin wrappers + publish link + bus receive arm | `interfaces/sso/{sso.go:349,489-498, server_helpers.go:67, server_routes_admin.go:122-140, server_invalidation.go, options_misc.go:279, sso_protocol.go:50}` |
| domains | engine + admin handlers + stores | `domains/tokenpolicy/` (+ new `validate.go`, `admin.go` handlers, new `sqlite/`) |
| platform | new bus kind + dispatch arm | `platform/cluster/bus.go`, `interfaces/sso/server_invalidation.go` `applyControlPlaneInvalidation` |
| shared | consts + error reuse | `shared/core/{consts_wire.go, consts.go:214-225, errors.go:313}` |

Verified sound before review: `domains/tokenpolicy/sqlite` at directory depth 3 imports only
`domains/tokenpolicy`, `platform/migrate`, `modernc.org/sqlite` — downward, mirroring
`domains/threataction/sqlite` (Verified). The `Store` SPI extension's in-repo blast radius is
exactly `memory.Store` + test fakes (Verified: `tokenpolicy.Store` appears only in
`memory/store.go`, `interfaces/sso/{sso_protocol.go,options_misc.go}`, `serverbuildplatform`,
and test files). `interfaces/sso` is at exactly **60 non-test files** (Verified) — the design
correctly extends existing files rather than adding new ones. `domains/tokenpolicy` has 5 non-test
files (the spec says 6 — it counts `memory/store.go`); adding `validate.go` + `sqlite/` stays
inside the 10-file / 15-subdirectory budgets (Verified).

**Assumptions.** (a) The stock binary is the composition of record; SDK embedders are a secondary
consumer. (b) Policy sets are small governance lists, so whole-list bus events + full snapshot
refresh are O(n)-per-write and negligible; the design makes no new hot-path cost (Verified:
`Policies()` is the only hot-path call and stays snapshot-only). (c) Multi-replica deployments
share one POSIX SQLite file, per the design's unsupported-topology list. (d) The two deliberate
spec refinements (default-TTL visibility; seed-only-when-empty reconciliation of the spec's
mutually-exclusive sentences) are accepted as reading of intent — flagged in §5 for product
sign-off because they deviate from the spec's literal text.

**Architecture verdict in one paragraph.** The design is structurally correct: it keeps the
hexagonal boundary (domain handlers + thin server wrappers), preserves every verified fail-open /
oracle-safe contract, reuses the exact in-repo precedents for the sqlite store, migration, boot
schema check, admin gating, and bus arms, and its only breaking change (`Store` SPI +
`NewClampingIssuer` signature) has a verified minimal blast radius. The three issues that must be
resolved before implementation are: (A1) NaN/Inf defeats the headline validation contract with a
silent mass forced-refresh availability kill (probe-verified); (A2) the TTL dual-plumbing seam —
the design's own #1 risk — has a regression gate that cannot actually catch the divergence at the
cmd seam, and a 1h Server-field default that masks missed wiring; (A3) the writable admin API is
mounted for the memory backend too, where admin writes on a multi-replica deployment diverge
**permanently** (no refresh source exists) while `haCoherenceIssues` — the stock guard built for
exactly this class — is not extended to flag it. A4–A6 are bounded and fixable at design time.

## 2. Findings

| # | Sev | Evidence | Impact | Recommendation |
|---|---|---|---|---|
| **A1** | **High** | **Verified by probe.** `Validate`'s proposed check `RequireRenewAfter < 0 \|\| > 1` is false for NaN. Propagation verified in `evaluate.go`: `stricterRenew(0, NaN)` returns NaN; `RenewExceeded`'s `renewAfter <= 0` guard passes NaN; `time.Duration(NaN*ttl)` = MinInt64 on amd64 → `elapsed >= threshold` is **true**; `RenewAt` returns a year-1734 timestamp. Consumer: `protocols/oauth/handle_introspect.go:279-283` → `{active:false}` | A NaN fraction in a bundle or PUT body passes boot validation and the PUT `400 invalid_policy` gate, then force-invalidates **every** matching token at introspection — a silent availability kill the design's hard-error contract claims to prevent. Corroborated: security F1, QA F3 | Required: formulate the check as `!(f > 0 && f <= 1)` (rejects NaN and ±Inf) at both `Validate` seams; defense-in-depth: `RenewExceeded`/`RenewAt` treat `!(renewAfter > 0 && renewAfter <= 1)` as unmeasurable. Tests: `validate_test.go` NaN/Inf rows; `evaluate_test.go` NaN row asserting false |
| **A2** | **High** | **Verified.** `build_signing_issuers.go:44,68,97` feed `srv.TokenTTL` to EdDSA/ECDSA/RSA issuers; `config_load.go:82-83` defaults `TokenTTL` to `core.DefaultTokenTTL` (1h, `consts_oauth.go:134`). The design's rootcov regression gate exercises the Server option, **not the cmd seam** — a future wiring divergence (engine 1h vs issuer 30m) keeps every test green while `max_ttl: 2h` widens 30m-default clients to 1h | The single remaining widening channel is invisible to the proposed test suite. The `tokenPolicyDefaultTTL` field default of `core.DefaultTokenTTL` (1h) actively masks a missed `WithTokenPolicyDefaultTTL` call — silently wrong instead of known-legacy. Corroborated: security F2, protocol H1, QA F2 | Required: default the Server field to **0** (legacy semantics), wire `WithTokenPolicyDefaultTTL(b.cfg.Server.TokenTTL)` unconditionally at the one call site that also feeds the issuer builders, invariant comments on both seams, and a **cmd-level** assertion (serverbuildsign/build_app_security test) that both consumers receive the same `b.cfg.Server.TokenTTL`, plus the rootcov test with a non-1h value |
| **A3** | **High** | **Verified.** Design 决策 7 mounts PUT/DELETE whenever `tokenPolicyStore != nil` (either backend); design 决策 8's receive arm refreshes via optional `Refresh` — which `memory.Store` (the **stock-wired** backend today, Verified: `build_app_security.go:281` → `BuildTokenPolicyStore` returns `memory`) cannot implement (no durable source). `cmd/sso-server/build_stores.go:95-131` `haCoherenceIssues()` — the stock multi-replica guard — does not list the token-policy store | On a multi-replica memory-backend deployment (valid topology today), the first admin PUT diverges peers **permanently** — no event can heal them, unlike the sqlite bounded window. Silent: no guard, no metric. Corroborated: DB F-DB-1 | Required: extend `haCoherenceIssues` with a token-policy entry (per-pod backend when the writable surface is wired and topology declares HA), so multi-replica + memory fails boot unless `AllowPerPodState` — the guard pattern the repo already ships. Publish only when the store implements the shared-backend contract; document memory = single-replica for writes |
| **A4** | **Medium** | **Verified.** `Policy` carries slices (`Scopes`, `BlockScopeCombos`). The proposed value-returning `Get` aliases the live snapshot's backing arrays in both stores; `Policies()` has an explicit read-only contract the design never extends to `Get` | An accidental mutation of a `Get` result corrupts the hot-path snapshot — no COW protection. Corroborated: QA F5 | Required: state the contract in `tokenpolicy.go` and deep-copy on `Get` in both stores (trivial cost for governance-sized sets), with the QA F5 test pinning the invariant |
| **A5** | **Medium** | **Verified.** Design 决策 11: "if the table is empty, seed once" — a check-then-insert sequence with no atomicity mechanism; no in-repo seed precedent exists (threataction/sqlite has no seed path, Verified) | Two replicas first-booting one shared file both seed: plain INSERT → PK-conflict boot failure; upsert → nondeterministic LWW seed winner across replicas. Corroborated: security F3, protocol M1, DB F-DB-2 | Required: seed inside one `BEGIN IMMEDIATE` transaction with per-row `INSERT OR IGNORE` (conflict = success); document that the seed bundle must be identical across replicas; concurrent-`New` test |
| **A6** | **Medium** | **Verified.** No audit event proposed for PUT/DELETE; threataction parity (its admin.go records zero audit calls) — a documented parity choice, not a regression | Operators cannot reconstruct who changed the issuance-deny set and when — the forensics class AGENTS.md §3 reserves for audit. Corroborated: protocol M2 | Product decision (§5). Either one bounded event (`token_policy_changed`, classified in `auditreport`, `audit.SetMeta` for name+method) or an explicit parity note in the design |
| **A7** | **Low** | **Verified.** `TokenPolicyConfig.Sqlite string yaml:"sqlite"` deviates from the repo-wide `.sqlite.dsn` sub-struct convention (`notifications.sqlite.dsn`, `config_audit.sqlite.dsn`, `identity_link` `sqlite_dsn`, Verified in `docs/config-reference.md`) | Inconsistent config surface; threataction has no stock-wired sqlite config to copy, so there is no precedent pulling the other way | Adopt `sqlite: {dsn: ...}` at design time — free now, migration surface later. Corroborated: DB F-DB-5 |
| **A8** | **Low** | **Verified.** The design's "dot notation per the existing convention" is inaccurate: `bus.go` kinds are mixed — underscores (`tenant_suspension`, `discovery_reload`, `token_revoked`, `session_suspended`, `config_digest`) and dots (`tenant.residency`, `client.change`, `connection.change`, `control_plane.restore`); dots are the **newer** convention | Cosmetic; `token_policy.change` is consistent with the newer kinds | Fix the doc claim; keep the kind name. Corroborated: DB F-DB-7 |
| **A9** | **Low** | **Verified.** `tokenpolicy.Store` and `NewClampingIssuer` are public SDK surface (`github.com/yangwb1123/snaplink/domains/tokenpolicy`); the design covers in-repo implementers (grep-verified: memory + fakes only) but not external SDK embedders | Breaking change without a release note for downstream embedders | Add a changelog/migration note in the same change (AGENTS.md §5.6 contract discipline) |
| **A10** | **Info** | **Verified.** `token_policies` is the third JSON-blob policy table (`threat_policies`, `tokenexchange_chain_hops`) | The three stores are near-identical shapes; a future consolidation candidate | Explicit non-goal now; leave a pointer in DIRECTORY_MAP |
| **A11** | **Info** | **Verified by reading the spec.** The spec's "sqlite 与 File/Policies 互斥" and "空表时播种" sentences are mutually exclusive (strict exclusivity makes the seed sentence unreachable); the design's reconciliation is the correct reading | The design goes slightly beyond the spec (sqlite + File/Policies as a first-boot seed contract) — a config-semantics change | Product sign-off (§5); document in config-reference as the design does |
| **A12** | **Info** | **Verified.** `docs/feature-matrix.md` has no `require_renew_after` / `renew_at` row (grep: zero matches), contrary to the QA review's row-145 citation; the design's decision-12 doc list omits feature-matrix | Doc-sync gap is one line either way | Add or explicitly skip a feature-matrix delta in decision 12 |

**Corroborated but not re-derived here** (prior reviewers verified with their own evidence, and my
reads are consistent): sqlite `Get` snapshot-vs-DB serving ambiguity (DB F-DB-3), missing DR/restore
path (DB F-DB-4, SRE F3), no `/readyz` decision / snapshot-age metric for the new store (SRE F2),
bus-degradation alert gap (SRE F1), publish-negative-path test (QA F4), `error_description` text
discipline + no-store-header choice (protocol L1/L2), DELETE-retry 404 semantics (DS F4, protocol
parity), response-before-publish ordering (security F5, protocol I3).

## 3. Decision options

**D1 — Store SPI shape.** (a) Extend `tokenpolicy.Store` with Get/Put/Delete (design; matches
threataction precedent; breaking but verified-minimal blast radius). (b) Keep `Store` stable and
have the server type-assert an optional admin/write interface (same pattern the design already
uses for `Refresh`; zero breaking change for embedders; extra assertion surface + two interfaces
to document). **Preferred: (a)** — the tree is the composition of record, the in-repo blast
radius is proven, and (b) spreads the SPI across two interfaces for a consumer class the repo
does not ship to. Mitigate with A9's release note.

**D2 — Default-TTL fallback value.** (a) Server field defaults to `core.DefaultTokenTTL` (design)
vs (b) 0 = legacy (clamp to MaxTTL) until wired. **Preferred: (b)** — a missed wiring then
reproduces *known* pre-change behavior instead of silently clamping to a wrong 1h. Combined with
the cmd-seam test (A2) this closes the design's own risk #1.

**D3 — Memory backend + writable admin in multi-replica.** (a) Extend `haCoherenceIssues`
(boot error unless `AllowPerPodState`) + publish only for shared-backend stores; (b) document-only
"memory is single-replica for writes". **Preferred: (a)** — it reuses the guard the repo already
enforces for session/JTI/CIBA stores; (b) leaves a silent permanent-divergence topology that
contradicts the design's own convergence claims. Deployment impact is bounded: the guard fires
only when topology declares HA intent.

**D4 — Seed semantics.** (a) Design's seed-only-when-empty reconciliation; (b) strict
three-way exclusivity (spec literal — makes the spec's own seed sentence unreachable);
(c) sqlite-only, no seeding. **Preferred: (a)**, with A5's atomicity fix and product sign-off.

**D5 — Validation seams.** (a) Design's split (strict parse only in `ParseYAML`; Validate at boot
+ PUT with `defaultTTL`); (b) conditionalaccess-style combined loader. **Preferred: (a)** —
verified justification: `Validate` needs `defaultTTL`, a wiring concern; the strictness parity
being fixed (unknown-field acceptance) is fully achieved by `DisallowUnknownField` alone.

**D6 — `Get` aliasing.** (a) Contract-only (document read-only); (b) deep-copy on `Get` in both
stores. **Preferred: (b)** — governance sets are tiny; removes the hazard class without relying on
caller discipline. Keep the `Policies()` zero-copy contract unchanged (hot path).

**D7 — sqlite config shape.** (a) Flat `sqlite: <dsn>` (design); (b) `sqlite: {dsn: ...}`.
**Preferred: (b)** — repo convention (A7), free at design time.

## 4. Prioritized implementation sequence

Milestones are ordered to front-load the highest-risk seams and keep every slice independently
green behind the mandatory gates (`go build ./... && go vet ./...`,
`go test -run 'TestMaintainability_|TestArchitecture_' .`, then `go test ./... -race`,
`test/` E2E, `make ci`).

**M1 — Validation core (决策 1–2).** Strict `ParseYAML` + `validate.go` + `AdvisoryWarnings`.
Includes A1's NaN/Inf fix and the existing `TestParseYAML_Empty` split (its `other: 1` case is
verified to fail under `DisallowUnknownField`). No wire changes.
*Accept:* `yaml_test.go` rejection table (incl. `max_ttl_`, top-level `other: 1`); `validate_test.go`
NaN/Inf/negative/empty-name rows; existing fixtures byte-identical; package gates green.

**M2 — Default-TTL visibility (决策 3) — highest-risk seam first.** `PolicyInput.DefaultTTL`,
min-clamp in `Evaluate`, `NewClampingIssuer` signature, Server option (default 0 per D2),
cmd wiring at the single `b.cfg.Server.TokenTTL` call site, invariant comments, **cmd-level**
single-source assertion test + rootcov non-1h default-client test.
*Accept:* `expires_in == 1800` for `token_ttl: 30m` + `max_ttl: 2h` + `RequestedTTL==0` (rootcov
and cmd-level); nil-store no-op byte-identical; `TestClampingIssuer_ImposesCeilingOnUnset` updated
for the new signature with the equality (`MaxTTL == DefaultTTL`) row.

**M3 — Store SPI + memory CRUD (决策 5–6).** Interface extension, `ErrPolicyNotFound`, memory
map-COW with insertion order, `Get` deep-copy (D6), `staticStore` fake update (breaks on the SPI
extension — make it explicit in the acceptance mapping).
*Accept:* memory CRUD + `-race -count=10+` COW tests; `var _ tokenpolicy.Store` guards; aliasing
test (QA F5).

**M4 — Admin surface + bus (决策 7–8).** Handlers, three `:name` routes, mount block, publish on
`bool`, `KindTokenPolicyChange` receive arm + recovery flush, publish-only-for-shared-backend,
`haCoherenceIssues` extension (D3).
*Accept:* rootcov split tests (`invalid_request` vs `invalid_policy`, 401 `realm="admin"`,
unmounted 404 ×3, name-from-route); store-failure PUT → 500 with **zero** published events
(QA F4); two-server `test/` integration (PUT via A visible on B after flush; no-bus negative
control); mixed-version unknown-kind ignored.

**M5 — sqlite backend + seed + wiring (决策 9–11).** Store, migration, atomic seed (A5),
`sqlite: {dsn:...}` (D7), builder branch, boot `CheckSQLiteSchema`, storage-health + `/readyz`
source, shutdown `Close()`.
*Accept:* CRUD/reopen/double-`New` idempotency/concurrent-seed tests; shared-file coexistence with
`threat_policies`; `ORDER BY name` pin; DB-closed-after-boot `Policies()` fail-open proof.

**M6 — Contracts + docs (决策 12, A9, A12).** openapi ops, error-codes row, config-reference
(single-source + seed semantics + unsupported topologies), DIRECTORY_MAP, AGENTS.md §4, feature-
matrix delta, changelog note.
*Accept:* `python cli.py check-routes` PASS; `make ci` green (after the pre-existing `fmt`
blockers are resolved by the batch owner).

**Compatibility plan.** Old binary vs new table/key: ignored with a warning (verified config-
loader pattern) — governance silently OFF during rollback, documented (SRE). New binary vs old
DB: migration creates the table. Mixed-version: old binary ignores `KindTokenPolicyChange` via
the `default` arm (Verified `applyControlPlaneInvalidation`). Forward-migration: `CheckSQLiteSchema`
fails old binaries loud. Breaking SPI: release note (A9).

## 5. Unknowns needing owner/product decisions

1. **Audit trail (A6):** is a bounded `token_policy_changed` event required for governance
   mutations, or is documented threataction parity (no audit) acceptable? Security-adjacent; AGENTS.md
   §3's audit table is the tiebreaker.
2. **Seed-contract spec deviation (A11):** sign-off that `sqlite` + File/Policies-as-seed-source
   supersedes the spec's literal exclusivity sentence.
3. **Multi-replica memory deployment (A3/D3):** boot-guard via `haCoherenceIssues` (breaks a
   currently-valid topology unless `AllowPerPodState`) vs warn-only. Deployment-impact decision.
4. **DR/restore scope:** is a restore/backup path for `token_policies` part of this change or a
   follow-up? (Stock binary wires no backup sources today — SRE F3.)
5. **Observability scope:** bus-degradation alert + snapshot-age metric (`last_refresh` gauge) —
   same change or a follow-up workstream? (SRE F1/F2.)
6. **SDK contract policy (A9):** release-note/changelog handling for the `Store` SPI breaking
   change, or is the in-repo blast radius the only bar (AGENTS.md's composition-of-record reading)?
7. **Ready-check inclusion:** should the sqlite store join `/readyz` via the existing
   `AppendReadyCheck` pattern (recommended) — the design currently registers only storage-health
   and schema-check.
