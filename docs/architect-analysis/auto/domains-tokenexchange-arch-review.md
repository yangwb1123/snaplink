# Architecture Review — Token-Exchange Hop-Policy Operational Loop

Source: `docs/auto/domains-tokenexchange-design.md` (design),
`docs/proposals/requirements.md` (spec). Role: senior architect — layer
mapping, dependency direction, coupling/ownership, scalability, failure
isolation, compatibility, migration cost, technical debt. Advisory only; no
files modified. All claims labeled per `ai-dev/prompts/README.md`. Checks
that ran for this revision: source reads + `wc -l` + grep across the layer
gates (`directory_fanout_test.go`, `architecture_layer_test.go`,
`maintainability_budget_test.go`), `interfaces/{sso,admin}`,
`domains/{tokenexchange,tokenpolicy}`, `cmd/sso-server{,/serverbuildplatform,
/serdebuildsign}`, `config`, `platform/{audit,cluster}`,
`internal/handler/tokengrant`, `shared/core`, and the four prior artifacts
(analysis, requirements, design, distributed/security/QA reviews). No `make
ci` (design-stage, zero `.go` edits).

## 1. Scope, assumptions, verified architecture summary

**Scope.** Three improvements forming one closed loop: admin `GET`/`PUT` for
the token-exchange hop-policy rule set (operations face), sqlite + config
assembly (state face), Scopes/Resources/RequestedTokenType matching
(expression face). Constraints: no new `interfaces/sso` file (60-file frozen
exemption), no new top-level package, no `layerExemptions`/exemption-map
growth, oracle-safe `/token` collapse unchanged, audit registration complete
in the same change.

**Assumptions.** The requirements doc is intent, not shipped behavior
(AGENTS.md §1); where it conflicts with a gate, the gate wins and the
deviation must be recorded. `make ci` is the handoff gate.

**Verified architecture summary** (all measured this revision):

| Layer | Verified state | Design impact |
|---|---|---|
| `domains/tokenexchange` (domains) | 2 non-test files + 3 subdirs (`memory`, `sqlite`, `agentidentity`); `Evaluate` pure, clock-free; `ruleMatches` 12 lines; `Rule` has no tags; `memory.Store.Replace`/`Rules` zero production callers | Seam + matcher + validation here; fan-out 2→4 ≤ 10 — legal |
| `domains/tokenexchange/sqlite` (domains) | chain-store precedent: `DB()` accessor (`chain_store.go:100`), `ChainStoreMaxVersion` (`maxversions.go`), migrations | New `policy_store.go` in the same package — root-module, layer-legal, no new classification |
| `domains/tokenpolicy` (domains) | `HandleAdminPolicies` **in the domain package** (`admin.go`), lenient `ParseYAML` (`yaml.go:20`), trailing-`"*"` ALL-of selector (`evaluate.go:150-176`) | The actual precedent for handler placement and wildcard semantics |
| `interfaces/admin` (interfaces) | **10 non-test files = `maxGoFilesPerDir` 10 (`directory_fanout_test.go:34`), absent from `dirFileCountExemptions`**; `ActorFromContext` (`middleware.go:482`); `HandleTokenExchangeChain` lives in `lifecycle.go:109` | **A new file here → 11 > 10 → gate fails** (Finding 1) |
| `interfaces/sso` (interfaces) | exactly 60 non-test files (frozen exemption 60); `accessors_threat.go` 427 (imports `interfaces/admin` at :12; chain mount pattern :197-210); `server_routes.go` 488 (+1 call site); `server_routes_admin.go` 332; `handleAdminTokenPolicies` wrapper precedent (`sso.go:349`); `WithTokenExchangePolicy` (`options_grants.go:191`) | Zero new files; mount + two ~4-line wrappers fit in `accessors_threat.go` (~465) |
| `cmd/sso-server` (composition) | 23 non-test files, exemption 24; `build_app_oauth.go` 487 (13 headroom); `wireOAuthGrantStores` at :201, ~34 lines; `wireTokenExchangeChainLifetime` at :276 (10 lines, call site :226); `CheckSQLiteSchema` (`serverbuildsign/build_readiness.go:44`); `BuildTokenPolicyStore` (`serverbuildplatform/build_governance.go:197`, 430 lines) | Relocation is required (Finding 4); 23→24 = **exactly at the ceiling** (Finding 7) |
| `config` (composition) | frozen 26-file ceiling; `OAuthTokenExchangeConfig` = single `MaxChainLifetime` field whose doc says the Policy SPI is "deliberately NOT YAML-driven" (`config_oauth2.go:26-32`); strict loader (`config/source.go:264`) | Extend existing file; **comment contradicts the design (Finding 3)** |
| `platform/cluster` + `interfaces/sso/server_invalidation.go` | `EventKind` open set; `KindAuthzPolicyChange` (`bus.go:48`); `default:` arm ignores unknown kinds (`server_invalidation.go:331` — mixed-version safe) | Bus hook is precedented and ~15-25 lines (Finding 2) |
| `platform/audit` | `KnownEventTypes`; drift gate is **either/or** — claimed by a control area **or** listed in `wantUncategorizedEventTypes` (`auditreport/drift_test.go:95`); CEF/OCSF conformance requires non-fallback entries (`auditsink/conformance_test.go:151`) | The design's 4-file registration list is sufficient for the gate; `control_areas.go` is needed only if the event is claimed (recommended) |
| `shared/core` | `PathAdminTokenExchangeChain` const precedent (`consts_wire.go:289`); `GatedRouter.PUT` (`router.go:339`) | Path const + gated mount — legal |
| `internal/handler/tokengrant` | `tokExEnforcePolicy` (`token_exchange.go:373`) fail-closed, collapses to `invalid_grant`, logs only on error | Wire behavior unchanged — Verified |

**Dependency direction.** All new imports point downward: the proposed
`domains/tokenexchange/admin.go` needs only `shared/core`, `shared/spi`,
`platform/audit` — legal. The `interfaces/sso` wrapper already imports
`interfaces/admin`, so extracting the actor via `admin.ActorFromContext` and
passing it as a parameter adds no edge. No new top-level package → no
`layerName()` change, no `layerExemptions` growth. The one inherited upward
edge (`protocols/scim -> interfaces/admin`, `architecture_layer_test.go:126`)
is untouched. **The design's import graph is clean; its file placement is
not.**

## 2. Findings

| # | Sev | Evidence (Verified) | Impact | Recommendation |
|---|---|---|---|---|
| **1** | **Critical** | `interfaces/admin` = 10 non-test files, `maxGoFilesPerDir = 10`, **absent from `dirFileCountExemptions`** (`directory_fanout_test.go:34,51-65`). Design Decision 2's "no ceiling" claim is false — absence from the exemption map means the default cap, not unlimited. Headroom audit: largest admin file has 96 lines free (`token_portfolio.go`); handlers + validation ≈ 150+. The design's own Decision 7 §5 caught this exact trap class for `interfaces/sso` and missed it for `interfaces/admin` — a systematic verification gap, not a one-off | `TestArchitecture_DirectoryFileFanout` fails → `make ci` fails → release blocker; the feature cannot land as designed | Follow the precedent the design itself cites: `domains/tokenpolicy/admin.go` hosts `HandleAdminPolicies` in the **domain** package. New `domains/tokenexchange/admin.go` (2→4 files, ≤10 — legal) holds both handlers + `ValidateRules`; the `accessors_threat.go` wrapper extracts actor/IP (`admin.ActorFromContext`, `audit.ClientIP`) and passes them in. Matches AGENTS.md §5's "domain free function + thin Server wrapper". Fallback: `interfaces/admin/tokenexchangepolicies/` subpackage (depth 3, layer-legal) |
| **2** | **High** | AGENTS.md §3 lists "client/**authz-policy changes**" under cross-replica invalidation; the bus mechanism exists (`EventKind` open set, `KindAuthzPolicyChange` precedent `bus.go:48`, mixed-version-safe `default:` arm `server_invalidation.go:331`); the design defers it explicitly. Bus contract: dropped events degrade "to the existing TTL fallback … never to a wrong answer" — the policy snapshot has **no TTL fallback**, so a stale deny set is served indefinitely, strictly weaker than every other bus-covered cache | An incident-response deny PUT to replica A is not enforced on B..N (or the failover target) until restart — the exact scenario Decision 1 names as the feature's purpose; governance `GET` on B lies; a GET→PUT round-trip tool on B silently re-applies the old set | Wire a new `EventKind` + subscriber arm calling `store.Reload()` (re-run boot-load SELECT, swap under the write lock, fail-open on error) — ~15-25 lines, precedented. If declined: explicit owner acceptance + `as_of` on GET + "sqlite = single-replica-only" topology documentation. See Decision option 3 |
| **3** | **High** | `OAuthTokenExchangeConfig`'s doc (`config/config_oauth2.go:26-32`) states the Policy SPI is "deliberately NOT YAML-driven" — the design's `policies`/`policies_file`/`backend` knobs directly contradict the shipped config contract's rationale, and neither Decision 7 nor the contract-updates list rewrites it | Doc/config drift on a public contract surface; `docs/config-reference.md` derives from this comment | Rewrite the comment and the config-reference section in the same change; note the `BuildTokenPolicyStore` precedent makes YAML-driven rule ingest a supported pattern — the comment is stale, not sacred. Also record the requirements-doc deviation: guardrail "cmd/sso-server（现有文件）" conflicts with the mandatory relocation (Finding 4) |
| **4** | **High** | `build_app_oauth.go` 487/500 with a 13-line headroom and zero exemptions (`fileSizeExemptions` is empty, capped at zero); `wireTokenExchangeChainLifetime` at :276; `wireOAuthGrantStores` ~34 lines (inline fallback 487+10=497 viable). `test/` boots `sso.NewServer(opts...)`, never the appBuilder — the cmd wiring path has **no executable acceptance path**; `WithTokenExchangePolicy` has zero cmd callers | Requirement's "配置装配…拒绝启动" acceptance is unverifiable by the planned E2E; a broken wire (wrong DSN inheritance, silent redis fallback) ships green | Relocate `wireTokenExchangeChainLifetime` into new `cmd/sso-server/build_app_tokenexchange.go` + `wireTokenExchangePolicy` (Decision 5 — correct call). Cover the builder with the `TestBuildTokenPolicyStore_*`-mirror set (`build_governance_test.go:242-290`); keep the wire function trivially thin; state the no-appBuilder-test precedent explicitly |
| **5** | **Medium** | Design's own asymmetry: "validation at ingest … so the hot path needs no defensive re-check" (Decision 3) vs. boot load validating only JSON decodability (Decision 4). `ValidateRules` = count cap + Name + wildcard shape — no per-string caps; server body limit defaults to **0 = unlimited** (`options_httpstack.go:57-63`); `scopeMatches`/`resourceMatches` prefix scans run per exchange over whatever strings are stored | A shape-valid-but-inert row (`"*x"`, `""`) from a restored/edited DB silently stops denying (widened allow); an `admin:write` holder can degrade the `/token` hot path with multi-MB strings | One `ValidateRules` choke point shared by PUT, YAML ingest, **and boot load** (fail loud, naming the row); per-string length caps (≤256B) + `MaxBytesReader` on the PUT body; constants in `consts.go`. This is the same class the design already treats as fail-loud for corrupt JSON — close the gap |
| **6** | **Medium** | Design Decision 4: "commit, then swap the snapshot under the write lock" — the tx is outside the critical section; SQLite commit order (file lock) and Go swap order (mutex) are independent under preemption | Concurrent PUTs can leave disk=new/memory=old — violating the design's own "never a partial set on either side" invariant and its failure table (which covers Allow-vs-Replace but not Replace-vs-Replace) | Hold the write mutex across tx + swap; concurrent-Replace regression test (`-count=10+`). The same mutex serves the Finding 2 `Reload()` path |
| **7** | **Medium** | Three drift surfaces the design's contract list omits: (a) `adminAPIEndpointCandidates()` (`server_resource.go:370`) is hand-maintained and its comment warns the inventory drifts; (b) the audit gate is either/or (control-area claim **or** `wantUncategorizedEventTypes`, `drift_test.go:95`) plus CEF/OCSF non-fallback entries (`conformance_test.go:151`); (c) `cmd/sso-server` 23→24 = the frozen exemption **exactly** — zero future headroom; `build_app_oauth.go` ~490, `accessors_threat.go` ~465 | New endpoints invisible to the admin inventory (governance surface lies); audit registration failure = `make ci` fail; the next cmd/sso-server feature needs a subdirectory (or an exemption — forbidden) | Register both endpoints in the inventory with the `MutablePolicy` mount predicate; claim the new event in a control area (recommended for a security-relevant mutation) or list it uncategorized; plan future cmd code in `serverbuild*` subdirs |
| **8** | **Low** | `memory.Store.Rules()` returns the live slice header (`memory/store.go:52`); no version/etag on the rule set; per-replica `default_allow` divergence is undetectable | Read-only-by-convention; silent lost-update on concurrent PUTs; mixed-config fleet divergence invisible | Sqlite store returns a copy (1000-rule cap makes it cheap); document last-write-wins; optional `If-Match`/`as_of` (see Decision options 3/6) |

Cross-references: Finding 1 = security F-1 = QA F1; Finding 2 = distributed
F1 = security F-3; Finding 5 = distributed F3 = security F-5/F-4 = QA F3b;
Finding 6 = distributed F2; Finding 7 = security F-7/F-10; Finding 8 =
distributed F4/F5. The three prior reviews are mutually consistent; I
re-verified each load-bearing claim independently (numbers above).

## 3. Decision options

**D1 — Handler placement (Finding 1).**
- **(a) `domains/tokenexchange/admin.go`** — *preferred*. Matches the
  `tokenpolicy` precedent the design itself cites; AGENTS.md §5 pattern
  (domain free function + thin wrapper); `ValidateRules` co-located with its
  consumers (YAML parser, sqlite boot load); imports stay downward
  (`shared/core`, `shared/spi`, `platform/audit`); fan-out 2→4 ≤ 10.
  Cost: the domain package gains HTTP-context-shaped handlers (acceptable —
  `tokenpolicy` already does this); actor/IP plumbing moves into the wrapper
  (one extra parameter).
- **(b) `interfaces/admin/tokenexchangepolicies/` subpackage** — fallback.
  Keeps handlers adjacent to `ActorFromContext`; layer-legal (first segment
  = `interfaces`, depth 3, per-directory fan-out = 1); but splits the
  feature's domain logic from its package and still needs `ValidateRules`
  exported from the domain for boot-load/YAML sharing.
- **(c) extend an existing admin file** — impossible (max headroom 96 lines
  vs ~150 needed).
**Preferred: (a).**

**D2 — cmd wiring (Finding 4, Decision 5 conflict).**
- **(a) relocate `wireTokenExchangeChainLifetime` → new
  `cmd/sso-server/build_app_tokenexchange.go`** — *preferred*. Cohesive
  token-exchange governance wiring; keeps the named `wireTokenExchangePolicy`
  (requirement's literal demand); nets `build_app_oauth.go` ~490. Cost:
  consumes the last `cmd/sso-server` file slot (24/24) and deviates from the
  requirement's "现有文件" guardrail — record both.
- **(b) inline into `wireOAuthGrantStores`** (487+10=497) — keeps the
  requirement's letter and the cmd slot, but abandons the named function,
  leaves 3 lines of headroom, and buries policy wiring in a 44-line
  function.
**Preferred: (a); (b) is the documented fallback if the team rejects new cmd
files.**

**D3 — Cross-replica invalidation (Finding 2).**
- **(a) wire the bus now** (~15-25 lines: `EventKind` + publish after commit
  + subscriber arm + `store.Reload()` fail-open). Precedented
  (`KindAuthzPolicyChange`), mixed-version safe (`default:` arm), converts
  an unbounded window into the same best-effort semantics every other kind
  has, and satisfies AGENTS.md §3 without a recorded deviation.
- **(b) defer with explicit acceptance**: sqlite = single-replica-only
  topology; `as_of` on GET; rolling-restart runbook after every PUT. Cost:
  ongoing ops burden and a standing invariant deviation.
- **(c) ship as designed** (unbounded staleness, undocumented) — rejected.
**Preferred: (a); document the topology constraints of (b) regardless.**

**D4 — Config surface.** memory/sqlite only, strict YAML
(`DisallowUnknownField` — the deliberate deviation from lenient
`tokenpolicy.ParseYAML` is correct and must not be "simplified" back),
file+inline mutual exclusion, fail-loud on redis/DSN. No viable alternative;
matches `BuildTokenPolicyStore`. Endorse. One subtlety to document:
`token_exchange.backend: sqlite` requires `oauth.sqlite.dsn` to be set even
when `oauth.backend` is not sqlite — the DSN knob is independent of the
backend selector.

**D5 — Validation choke point (Finding 5).** `ValidateRules` in the domain,
shared by PUT/YAML/boot-load, with string caps. The only alternative —
defensive re-checking on the hot path — is rejected: it erodes the pure-
function guarantee the whole design rests on.

**Build-vs-buy.** No external dependency is needed anywhere: GatedRouter,
admin middleware, sqlite migrate, audit recorder, and the invalidation bus
all exist. The only "buy" question is D3(a)'s bus hook, and the mechanism is
in-tree. The design correctly builds on every precedent it names — except
where it misplaces the `tokenpolicy` precedent (Finding 1).

## 4. Prioritized implementation sequence

**M0 — Baseline.** Run `make ci` at HEAD; report any pre-existing failure
separately (QA noted uncommitted worktree drift). Exit: known-good baseline.

**M1 — Domain seam + matcher (Decisions 1, 3).** `MutablePolicy` beside
`Policy`; `Replace([]Rule) error` + `Rules()` + `DefaultAllow()`; compile
guard `var _ MutablePolicy = (*Store)(nil)`; `Rule` json/yaml tags (additive
— nothing serializes `Rule` today, verified); `scopeMatches`/`resourceMatches`
extraction; `ValidateRules` incl. string caps. Tests: full truth table
(ALL-of scopes + trailing-`*`, ANY-of resources **with the intent-carrying
pin comment**, exact `requested_token_type`, deny short-circuit, empty-new-
fields byte-compat), `ValidateRules` table. Exit: `go build ./... && go vet
./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`;
`go test ./domains/tokenexchange/... -race`.

**M2 — Sqlite policy store (Decision 4).** `sqlite/policy_store.go` with the
**Finding 6 fix** (write mutex across tx + swap), **Finding 5 fix** (boot
load runs `ValidateRules`, fails loud naming the row), COW snapshot (zero
I/O read path), `PolicyStoreMaxVersion` + `CheckSQLiteSchema` drift gate.
Tests: persist-across-reopen (file DSN, order preserved), readonly-file
Replace failure → disk + snapshot on old set, corrupt-JSON **and**
shape-invalid row → `New()` error, memory/sqlite parity suite,
concurrent Allow-vs-Replace and Replace-vs-Replace (`-race -count=10`).
Exit: `go test -race -count=10 ./domains/tokenexchange/...`.

**M3 — Admin surface (Decision 2, Finding 1 fix).** `domains/tokenexchange/
admin.go` handlers + `ValidateRules`; `accessors_threat.go` wrappers
(actor/IP via `admin.ActorFromContext` + `audit.ClientIP`) + mount gated on
`tokenExchangePolicy != nil && MutablePolicy`; audit event with all
registration points (KnownEventTypes, control-area claim **or**
`wantUncategorizedEventTypes`, `cefEventNames`, `ocsfEventActivities`) in
the same commit; **endpoint inventory entries** (Finding 7a); OpenAPI with
the mount-predicate wording. Tests: envelope keys + evaluation order,
PUT 400-table with call-recording store (zero mutation), idempotent re-PUT,
`default_allow` in body ignored, Replace-error → 500 with no audit event,
audit fail-open (erroring sink → 200, mutation stands), mount-gating
three-case table (nil / immutable / mutable → 404/404/200). Exit:
`go test ./interfaces/admin/ ./domains/tokenexchange/... -race`; fan-out
gate green with the new files present.

**M4 — Config + wiring (Decision 5).** `OAuthTokenExchangeConfig` fields +
**comment rewrite (Finding 3)**; strict `yaml.go` parser; `BuildTokenExchange
PolicyStore` beside `BuildTokenPolicyStore` (lean — parsing in the domain);
relocation to `build_app_tokenexchange.go` (D2); `TestBuildTokenExchange
PolicyStore_*` mirror set (Finding 4): absent/inline/file-strict/conflict/
sqlite-without-DSN/redis-inherited/over-cap/defaultAllow; `docs/config
-reference.md` (incl. DSN subtlety, 1000-rule cap, topology note). Exit:
`go test ./cmd/sso-server/...`; config tests green.

**M5 — Bus (if D3(a) accepted).** New `EventKind`; publish after PUT commit;
subscriber arm → `store.Reload()` fail-open; mixed-version test (unknown
kind ignored by old peer). Exit: two stores on one DSN, PUT via A, B serves
new set after one bus delivery; dropped event → B stays on old set + logged.

**M6 — E2E + full gates.** Restart test: admin PUT deny (client A + `admin:*`
scope) → exchange → `invalid_grant` → close server 1 → boot server 2 on the
same **file** DSN (with `busy_timeout` pragma; never `memDSN`) → still
denied; oracle byte-identity assert (deny vs. policy error — same body);
`make ci` incl. kin-openapi, nested modules, module validation. Exit:
`make ci` green; every touched file `wc -l` ≤ 500 re-measured in the same
commit.

**Compatibility plan.** `Replace` error return: zero in-tree callers
(verified; only `memory/store_test.go:33`) — accepted out-of-tree break,
guarded by the interface assertion. Rule tags: additive, wire-neutral. Empty
new fields: byte-compatible (existing tests stay as regression pins).
Unwired / immutable / memory backend: byte-identical (mount gating + same
`Evaluate`). Schema: new namespace + `PolicyStoreMaxVersion` — an old binary
against a forward-migrated DB fails loud at boot; a new binary against an
old DB migrates. Bus: `default:` arm keeps mixed-version rollouts safe.
Audit: new event type registered in all gates in the same change.

**Risks.** Budget exhaustion is the dominant one: `cmd/sso-server` 24/24,
`build_app_oauth.go` ~490, `accessors_threat.go` ~465 — every touched file
needs a `wc -l` in the commit. E2E flake: WAL/busy_timeout, unique temp
DSNs, serialize concurrent HTTP PUTs (SQLite single writer). Audit
registration completeness (five points, Finding 7b). Doc drift: the false
"tokenpolicy sqlite backend" claim (`domains-tokenexchange-analysis.md:13`)
must not leak into `docs/config-reference.md`.

## 5. Unknowns needing owner or product decisions

1. **Finding 2 scope** — is the invalidation-bus hook in-scope for this
   change, or is an explicit acceptance record (single-replica topology +
   `as_of` + runbook) acceptable against AGENTS.md §3's
   cross-replica-invalidation invariant? This is the only decision that
   changes the feature's security posture, not just its mechanics.
2. **Version/etag** — `If-Match`/`base_version` on PUT (hardens against
   replayed stale bodies and lost-update), or documented last-write-wins?
3. **Per-deny `/token` observability** — security F-9: a rate-bounded
   `token_exchange_policy_denied` audit event. The requirements doc lists
   deny observability as a follow-up direction; confirm out of scope.
4. **`default_allow` runtime flip** — deliberately excluded (single mutation
   path); confirm this remains a non-goal.
5. **Audit categorization** — claim `token_exchange_policy_updated` in a
   control area (recommended) vs. list it uncategorized (both satisfy the
   gate; the design only listed the latter).
6. **Requirements-doc revision** — record the two guardrail deviations (new
   cmd file; handler placement in the domain) in `docs/proposals/
   requirements.md` or an ADR, so the spec and the gates stop contradicting
   each other.
7. **Shared-DSN multi-replica topology** — supported (with Finding 2
   resolution) or documented single-replica-only; affects the
   `docs/config-reference.md` wording regardless of D3's outcome.

**Bottom line.** The architecture is sound: clean downward import graph,
correct budget math everywhere it was measured, oracle-safe wire behavior
preserved, and every mechanism the feature needs already exists in-tree. One
critical placement error (Finding 1) is a verified release blocker whose fix
— domain-package handlers per the `tokenpolicy` precedent — is also the
better architecture. Two decisions need owner sign-off before
implementation: the invalidation-bus scope (Finding 2) and the audit
categorization (Unknown 5). Everything else is bounded hardening that
belongs in the same change.
