# domains/tokenexchange — 跳授权策略运营闭环 设计 QA 评审（risk-based test review）

Review of `docs/auto/domains-tokenexchange-design.md` at worktree HEAD
`9606997b` ("Stage: design"). The design is **Stage: design** — no
implementation landed (Verified: `memory.Store.Replace` still returns no
error, `Rule` has no json/yaml tags, `ruleMatches` compares only
SubjectID/ActorSubject/ClientID, no admin policies endpoint, no
`EventTokenExchangePolicyUpdated`, `OAuthTokenExchangeConfig` has only
`MaxChainLifetime`). This review re-verifies every evidence claim against the
code, maps the requirements' acceptance checks to existing/required tests,
and measures the baseline the change builds on. All commands below ran for
this revision; no result is inherited from documentation or prior reviews.

## 0. Design-evidence re-verification (all claims checked against source)

| Design claim | Verdict |
|---|---|
| `memory.Store.Replace`/`Rules` have zero production callers; `Replace` gains an error return for free | **Verified** — `domains/tokenexchange/memory/store.go:48` has no error return; only `store_test.go:29` calls it |
| `Rule` has no serialization tags today; adding tags is wire-neutral | **Verified** — `domains/tokenexchange/tokenexchange.go:63-75`; nothing serializes `Rule` (grep: no `json.Marshal` of `Rule` anywhere) |
| `ruleMatches` is ~12 lines; extracting `scopeMatches`/`resourceMatches` keeps it under budget | **Verified** — `ruleMatches` is 12 lines (`tokenexchange.go:96-107`) |
| Budgets: `build_app_oauth.go` 487 (13 headroom), `accessors_threat.go` 427 (73), `build_governance.go` 430 (70), `server_routes.go` 488 | **Verified** — `wc -l` measured exactly those numbers |
| `cmd/sso-server` 23 non-test files, exemption 24 → a new `build_app_tokenexchange.go` fits | **Verified** — 23 non-test files; `directory_fanout_test.go:46` exemption 24 |
| `interfaces/sso` is at its 60-file ceiling → zero new files there | **Verified** — exactly 60 non-test files; frozen exemption 60 |
| **`interfaces/admin` has no ceiling → new `tokenexchange_policies.go` allowed** | **FALSE — Critical, see F1** — `interfaces/admin` has exactly 10 non-test files, `maxGoFilesPerDir = 10` (`directory_fanout_test.go:34`), and is **not** in `dirFileCountExemptions`; a new file → 11 → `TestArchitecture_DirectoryFileFanout` fails |
| No existing `interfaces/admin` file can absorb the handlers | **Verified** — headroom: connections.go 498/500 (2), middleware.go 492 (8), governance.go 483 (17), lifecycle.go 481 (19), tenants.go 466 (34), users.go 464 (36), break_glass.go 436 (64), token_portfolio.go 404 (96); handlers + validation ≈ 150+ lines |
| Audit event requires 4 simultaneous registrations or `make ci` fails | **Verified** — `auditspi/event_types.go:321` `KnownEventTypes` + self-healing `event_types_completeness_test.go` (AST guard); `auditreport/drift_test.go:28` `wantUncategorizedEventTypes`; `auditsink/conformance_test.go:155` `TestConformance_EveryEventTypeHasCEFAndOCSFMapping` |
| `tokenpolicy.ParseYAML` is lenient; strict loader is the conditionalaccess precedent | **Verified** — `domains/tokenpolicy/yaml.go:23` `yaml.Unmarshal` (lenient); `domains/conditionalaccess/yaml.go:33` `yaml.UnmarshalWithOptions(..., yaml.DisallowUnknownField())`; `config/source.go:264` same strict pattern |
| Trailing-`"*"` prefix-wildcard precedent in tokenpolicy | **Verified** — `domains/tokenpolicy/evaluate.go:165-176` `scopePresent` |
| Chain-store sqlite precedent: `ChainStoreMaxVersion`, `CheckSQLiteSchema` drift gate, `DB()` accessor | **Verified** — `domains/tokenexchange/sqlite/maxversions.go:10`, `chain_store.go:100`, `serverbuildsign/build_readiness.go:44` |
| Admin mount pattern: gated router + `adminAPIGateOn` + thin wrapper | **Verified** — `accessors_threat.go:202-210` (`mountAdminTokenExchangeChainRoutes`), `server_routes.go:101` call site; note the requirements doc's alternative home `server_routes_admin.go` is 332 lines (168 headroom) |
| `cmd/sso-server` wires only the chain-lifetime cap today | **Verified** — `build_app_oauth.go:276` `wireTokenExchangeChainLifetime`; grep: `WithTokenExchangePolicy`/`WithTokenExchangeChainStore` have zero cmd callers |
| E2E harness can drive admin API + exchange over HTTP; restart test needs two boots on one temp DSN | **Partial** — harness boots `sso.NewServer(opts...)` (`token_exchange_chain_policy_test.go:36`), never the `cmd/sso-server` appBuilder; admin bearer minting pattern exists (`test/admin_middleware_test.go:78`); **no test anywhere boots the appBuilder, and no restart (two-boot) test exists in `test/`** (see F2) |
| `BuildTokenPolicyStore` builder + tests are the pattern to mirror | **Verified** — `build_governance.go:197`; tests at `build_governance_test.go:242-290` (Absent/Inline/FileBundle/Conflict) |
| `interfaces/admin` middleware 401/403 coverage exists | **Verified** — `TestAdminHTTP_*` in `test/admin_middleware_test.go` (all PASS this revision) |
| `invalid_request`/`internal_error` exist in `docs/error-codes.md` | **Verified** — lines 70-71 |
| `docs/openapi.yaml` validated by `make ci` (kin-openapi) | **Verified** — `Makefile:179` |
| tokenexchange/memory has a concurrency test precedent | **Partial — the precedent is tokenpolicy's** — `domains/tokenpolicy/memory/store_test.go:78-88` `TestStore_ConcurrentReadWrite`; `domains/tokenexchange/memory` has **no** concurrent test today; neither does `domains/tokenexchange/sqlite` |

## 1. Test inventory and commands actually run for this revision

| Command | Result | Notes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | full module |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | includes `TestArchitecture_DirectoryFileFanout` (ran explicitly, PASS at 10/10) |
| `go test ./domains/tokenexchange/...` | PASS | 4 packages, cached |
| `go test -race -count=1 ./domains/tokenexchange/...` | PASS | race baseline for the stores the design extends |
| `go test ./interfaces/admin/` | PASS | includes `tokenexchange_chains_test.go` handler tests |
| `go test ./test/ -run 'TestTokenExchange_' -count=1 -v` | PASS | 43 tests, 0 failures (policy deny, unwired default, chain store, scope/resource/actor paths) |
| `go test ./test/ -run 'TestAdminHTTP_' -count=1` | PASS | admin gate 401/403/200 contract |
| `go test -cover ./domains/tokenexchange/... ./interfaces/admin/` | PASS | tokenexchange 34.5%, agentidentity 94.0%, memory 98.2%, sqlite 83.7%, interfaces/admin 32.3% (line coverage only; behavioral adequacy argued in §3-4) |

Not run: `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`
— the change is design-stage with zero `.go` edits; the targeted gates above
are the proportional baseline. `make ci` timing and flake behavior are
unmeasured this revision (noted in §5).

## 2. Requirement-to-test matrix

Status: **Exists** (green today), **Extend** (existing test must gain
cases/asserts), **Add** (net-new test required), **Blocked** (cannot be
written until the F1 placement is revised).

| Requirement (docs/proposals/requirements.md) | Acceptance check | Status | Evidence / required test |
|---|---|---|---|
| §1 管理 API — GET snapshot | GET returns current rule set in evaluation order with `{default_allow, rules, total}` | **Add** | No admin policies endpoint exists. Test: seed `memory.Store` with 2 rules, GET → exact envelope keys, order preserved. Mirror `HandleTokenExchangeChain` handler test pattern (`interfaces/admin/tokenexchange_chains_test.go:36`) |
| §1 — PUT atomic replace; concurrent `Allow` sees old or new, never a blend | **Add** | `-race` test mirroring `tokenpolicy/memory` `TestStore_ConcurrentReadWrite` for both `memory.Store` and the new sqlite `PolicyStore` (see F6) |
| §1 — invalid payload `400`, `Rules()` unchanged, no store call | **Add** | Table test: bad JSON, empty Name, >1000 rules, `"*x"`/`""` wildcard shapes, non-array body; assert 400 + zero store mutation via a call-recording store (see F7) |
| §1 — mutation emits audit event with actor | **Add** | Recording sink asserts `token_exchange_policy_updated`, `ActorID`, `rules_before`/`rules_after`, `rule_names`; plus 4 registration points (`KnownEventTypes`, drift_test, cef, ocsf) |
| §1 — unwired build byte-identical, endpoint not mounted | **Add** | Mount-gating table test: nil policy / immutable `Policy` / `MutablePolicy` → 404/404/200 (see F4) |
| §1 — openapi.yaml + E2E admin PUT → deny → `invalid_grant` | **Add** | OpenAPI: 2 new paths + schemas, kin-openapi valid. E2E: mint admin bearer (`admin_middleware_test.go:78`), PUT deny rule, exchange → 400 `invalid_grant` (oracle collapse: no rule detail on wire) |
| §2 持久化 — write → close → reopen → rules recovered in order | **Add** | `TestPolicyStore_PersistsAcrossReopen`: temp **file** DSN (NOT `memDSN` — shared-cache memory DB dies with last connection), Replace, Close, New on same DSN, assert order + fields; `NewWithDB` for schema-drift gate tests |
| §2 — Replace tx mid-failure → disk and memory both on old set | **Add** | Failure injection: chmod 0400 the DB file after boot → Replace fails; assert error, `Allow` still old set, fresh boot still old set (see F3a) |
| §2 — concurrent Allow during Replace, no torn state | **Add** | `-race -count=10` goroutine test on sqlite `PolicyStore` (see F6) |
| §2 — config: inline/file mutual exclusion, invalid rules (empty Name / unknown key) reject boot; memory backend byte-identical | **Add** | Mirror `TestBuildTokenPolicyStore_*` (`build_governance_test.go:242-290`): AbsentReturnsNil, Inline, FileBundle(strict), FileAndInlineConflict, SqliteWithoutDSN, RedisInheritedFailsLoud, OverCapBundle, DefaultAllowTrue (see F2) |
| §2 — `make ci` incl. nested modules, config, module validation; docs same-change | **Add** | Design's own Decision 7.4/7.10 lists the mandatory registration set — correct |
| §3 匹配维度 — scope prefix-wildcard hit/miss, partial-subset miss, resource ANY-of hit, requested_token_type exact, deny short-circuits later allow, empty new fields byte-identical | **Add** | Pure truth-table tests in `tokenexchange_test.go` (Evaluate is pure — no store needed). Include the ANY-of pin comment (F8) and malformed-pattern inertness pin (F3b) |
| §3 — `go test ./domains/tokenexchange/... -race`; no budget crossing | **Add** | New files: `domains/tokenexchange/yaml.go` (+admin.go per F1) — package has 2 non-test files today, no fan-out issue |
| §3 — E2E: sqlite persistence + admin PUT `client A + scope admin:*` deny → restart → exchange denied `invalid_grant` | **Blocked** | See F1/F2: the acceptance test itself is sound, but (a) it cannot exercise `wireTokenExchangePolicy` because `test/` never boots the appBuilder, and (b) the sqlite `PolicyStore` the test needs cannot be built until the F1 placement revision lands |

## 3. Findings

### F1 — Critical — `interfaces/admin` fan-out gate contradicts Decision 2; the handler placement is unimplementable as written

**Evidence.** `directory_fanout_test.go:34` `maxGoFilesPerDir = 10`;
`interfaces/admin` has exactly 10 non-test files and is **absent** from
`dirFileCountExemptions` (`directory_fanout_test.go:46-57`). `go test -run
TestArchitecture_DirectoryFileFanout .` passes today at exactly 10/10
(measured). Adding `tokenexchange_policies.go` → 11 > 10 → gate fails →
`make ci` fails. No existing admin file can absorb the handlers
(measured headroom: largest is `token_portfolio.go` at 96; handlers +
validation ≈ 150+ lines). Exemption maps are frozen (AGENTS.md §2: "Exemption
maps never grow").

**Impact.** The design's central placement — and its claim "no ceiling there"
— is false. This is a hard-gate violation, not a preference: the feature
cannot land as designed.

**Recommendation (required fix).** Follow the actual precedent the design
cites but misplaces: `domains/tokenpolicy/admin.go` hosts `HandleAdminPolicies`
in the **domain** package. Put `HandleTokenExchangePolicies` +
`HandlePutTokenExchangePolicies` + `ValidateRules` in a new
`domains/tokenexchange/admin.go` (package has 2 non-test files today — no
fan-out issue; domain placement is also the design's own preference for
sharing validation with the YAML parser and sqlite boot load). The thin
`interfaces/sso/accessors_threat.go` wrapper (73-line headroom, ~38 used)
extracts the actor via `admin.ActorFromContext` (`interfaces/admin/
middleware.go:482`; interfaces/sso already imports interfaces/admin) and
passes it as an explicit parameter — `recordAdminConnectionAction`
(`interfaces/admin/connections.go:79`) is the calling pattern. Fallback:
`interfaces/admin/tokenexchangepolicies/` subpackage (depth 3, layer
classified by first path segment per `architecture_layer_test.go:61`,
sibling import of package admin for `ActorFromContext` is same-layer).

**Executable validation.** After the revision:
`go test -run 'TestArchitecture_DirectoryFileFanout' .` passes with the new
files present; `wc -l` on every touched file ≤ 500.

### F2 — High — The cmd wiring path (`BuildTokenExchangePolicyStore` + `wireTokenExchangePolicy`) has no test plan and no E2E precedent

**Evidence.** `WithTokenExchangePolicy` has zero cmd callers today
(requirements §2 evidence, re-verified). `test/` boots `sso.NewServer(opts...)`
(`token_exchange_chain_policy_test.go:36`) — no test in `test/` exercises the
`cmd/sso-server` appBuilder or config→builder→wire. The design's restart E2E
(Decision 7.9) therefore proves store persistence + admin API but **cannot**
catch a broken wire (wrong DSN inheritance, `backend: redis` silently
accepted, `WithTokenExchangePolicy` never called — the exact failure modes
Decision 5/6 claim to fail loud).

**Impact.** The requirement's §2 acceptance ("配置装配… 拒绝启动") is
unverifiable by the planned tests.

**Exact tests to add** (mirror `build_governance_test.go:242-290`):
`TestBuildTokenExchangePolicyStore_AbsentReturnsNil`,
`_InlinePolicies`, `_FileBundleStrictRejectsUnknownKey`,
`_FileAndInlineConflict`, `_SqliteWithoutDSNErrors`, `_InheritedRedisBackendErrors`,
`_BundleOverRuleCapErrors`, `_DefaultAllowDefaultsTrue`.
**Acceptance assertion.** Each: builder returns the documented error or
store; `go test ./cmd/sso-server/serverbuildplatform/ -run
TestBuildTokenExchangePolicyStore` green; a `config` package test proves
`token_exchange.backend: sqlite` with missing `oauth.sqlite.dsn` fails config
load. The wire function itself stays trivially thin (builder + nil check +
option + log) so builder tests cover the logic; note in the design that no
appBuilder-level test precedent exists in this repo and none is introduced.

### F3 — High — Two fail-loud guarantees are asserted in prose but have no test and one is incomplete

**(a) Replace rollback.** Decision 4/6 promise "any failure rolls back, disk
and snapshot stay on the old set" but name no injection mechanism. A natural
tx failure is hard to produce from the store's own code (DELETE+INSERT on a
position PK cannot conflict post-delete). Use the real-world analogue:
`chmod 0400` the DB file after boot → INSERT fails (SQLITE_READONLY, same
class as disk-full). **Test:** boot, Replace → error; `Allow` still returns
old-set outcome; close; reopen → old set on disk.
**Acceptance:** the two surfaces are asserted, not just the error return.

**(b) Boot-load validation gap.** Decision 3 says the hot path needs no
defensive re-check because ingest validates; Decision 4's boot load
normalizes `null` → `[]` but never states that loaded rows run
`ValidateRules`. A row written by an older binary or manual DB edit with
`scopes: ["*x"]` or `[""]` loads silently; per tokenpolicy `scopePresent`
semantics (`evaluate.go:165-176`) `"*x"` is an exact literal that never
matches → a **dead deny rule → silently widened allow**, the exact class
Decision 6's "corrupt JSON" row treats as fail-loud. **Test:**
`TestPolicyStore_New_RejectsInvalidStoredWildcard` — hand-write a DB (or
insert via raw SQL) with an invalid pattern, `New()` must error naming the
row. **Acceptance:** boot fails loudly; a valid-row boot succeeds with
identical semantics to memory.Store.

### F4 — High — Mount-gating byte-identity (Decision 1/2) has no planned test

`mountAdminTokenExchangePolicies` gated on `tokenExchangePolicy != nil &&
MutablePolicy` is net-new routing logic. A regression either silently
exposes an admin mutation endpoint on builds where none was intended, or
hides it. **Test (interfaces/sso level):** three-case table — nil policy →
route absent (404 from router), hand-written immutable `Policy` → absent,
`memory.Store` → 200 with full envelope. Also decide and pin the 
unmounted-route behavior in `docs/openapi.yaml` (same wording as the chain
endpoint: "Mounted only when a mutable policy is wired"). Note: the existing
chain mount has **no** mount-level test either
(`mountAdminTokenExchangeChainRoutes` is only exercised via handler tests) —
this is the first, cheap to add.

### F5 — Medium — `Replace` signature change and `Rules()` aliasing need pinning tests

The design updates `memory/store_test.go` for the new error return (correct),
but the exported-API break (Decision 7.3) deserves a compile-time guard:
`var _ MutablePolicy = (*Store)(nil)` beside the existing
`var _ tokenexchange.Policy = (*Store)(nil)` (`store.go:63`). Also
`memory.Store.Rules()` returns the internal slice header today — a caller
mutating it corrupts active rules (the sqlite store must return a copy or
document the same contract). The GET handler must not share the store's
internal slice with the caller. **Test:** mutate the `Rules()` result →
subsequent `Allow` unchanged, for both stores.

### F6 — Medium — No concurrency test is planned for either store

Requirement §2 acceptance names "并发 Allow 在 Replace 期间无撕裂" but the
design's test list doesn't include it, and neither `tokenexchange/memory` nor
`tokenexchange/sqlite` has a concurrent test today (the precedent is
`domains/tokenpolicy/memory/store_test.go:78-88`). **Test:** mirror that test
for both stores (8 goroutines × Allow/Replace), plus Replace-vs-Replace
serialization for sqlite (two concurrent PUTs → last-writer-wins, contiguous
positions, no interleave). **Acceptance:** `go test -race -count=10
./domains/tokenexchange/...` green.

### F7 — Medium — Admin handler contract tests are listed as acceptance prose but not specified

Requirements §1 acceptance lists GET snapshot, PUT atomic, 400-no-change,
audit-with-actor; the design restates them. The exact cases that pin the
wire contract: (a) GET envelope keys exactly `{status, default_allow, rules,
total}` with rules in evaluation order; (b) PUT idempotency (same body twice
→ 200, same total); (c) PUT body carrying `default_allow` is **ignored**
(Decision 7.7) — assert echo unchanged; (d) 400 table: bad JSON, empty Name,
>1000 rules, `"*x"` scope, `""` resource, non-array body — each with a
call-recording store proving zero mutation; (e) `Replace` error → 500, rules
unchanged, **no** audit event (pin: audit only on success); (f) audit
metadata via recording sink: actor, before/after counts, `rule_names`
truncation bounded. **Acceptance:** each case asserts status + body + store
state, not just status.

### F8 — Medium — The Resources ANY-of pin needs an intent-carrying test

Decision 7.8(b) warns a future "optimization" to ALL-of would silently widen
allows, but the truth-table test must carry the pin. **Test:** a deny rule
with `resources: ["aud1"]` against a hop with `["aud1","aud2"]` → deny, with
a comment stating the defensive-any-of intent; also the negative (hop
`["aud2"]` only → no match). Same for scopes ALL-of: hop `["a","b"]` vs rule
`["a"]` → match (superset), hop `["a"]` vs rule `["a","b"]` → no match.
**Acceptance:** the two dimension tests fail if anyone switches ANY-of ↔
ALL-of.

### F9 — Medium — Audit fail-open ordering is untested

Decision 6: "audit sink error on PUT → mutation stands, event dropped". The
handler must Replace-then-audit (not audit-then-Replace) and a failing
recorder must not change the 200. **Test:** PUT with an erroring sink →
200, GET shows the new rules, no event recorded. **Acceptance:** mutation
survives sink failure — this pins the fail-open contract (AGENTS.md §3)
against a future "fix" that rolls back on audit error.

### F10 — Low — Docs drift risks

(a) `docs/config-reference.md` must not copy the analysis doc's false
"tokenpolicy sqlite backend" claim (Design 7.10 acknowledges — verify with
`grep -n sqlite docs/config-reference.md` after landing); (b) `docs/
openapi.yaml` must stay kin-openapi-valid (`Makefile:179` runs validate in
ci); (c) `docs/feature-matrix.md` should gain the new endpoint/config knobs —
presence of a drift gate for it is **Unknown** (not found in this review);
(d) document the 1000-rule cap (Design 7.11) and the multi-replica staleness
limitation (Decision 4) in the config reference.

### F11 — Info — Coverage baseline (measured this revision)

`domains/tokenexchange` 34.5% (chainstore.go drags it down; `Evaluate`/
`ruleMatches` are covered by the 4 pure tests), `memory` 98.2%, `sqlite`
83.7%, `agentidentity` 94.0%, `interfaces/admin` 32.3%. Targets for the new
code: sqlite `policy_store.go` ≥ 80% via F3/F6 tests; the handler file via
F7. Line coverage alone does not establish adequacy — the §4 scenario list
is the behavioral bar.

## 4. Prioritized scenario list

Happy / boundary / error / race / recovery, in execution priority:

| # | Scenario | Layer | Priority |
|---|---|---|---|
| 1 | GET returns `{status, default_allow, rules, total}`, rules in evaluation order, no secrets | admin handler | P0 |
| 2 | PUT full-replace: 2-rule set replaces 1-rule set; order preserved; echo matches GET | admin handler | P0 |
| 3 | PUT invalid payload table (bad JSON / empty Name / 1001 rules / `"*x"` / `""` / non-array) → 400, zero store mutation | admin handler | P0 |
| 4 | Deny via admin PUT → `/token` exchange → 400 `invalid_grant` with no rule detail on the wire (oracle collapse) | E2E | P0 |
| 5 | sqlite: Replace → Close → New(same file DSN) → rules recovered in order; `default_allow` from constructor (config-owned), not disk | sqlite store | P0 |
| 6 | Replace failure (readonly file) → error; disk + snapshot on old set; second boot sees old set | sqlite store | P0 |
| 7 | Boot load rejects corrupt JSON column and invalid wildcard shape, naming the row (fail loud) | sqlite store | P0 |
| 8 | Scope ALL-of: superset match, partial-subset miss, trailing-`*` hit/miss, `"*"` matches all | Evaluate (pure) | P0 |
| 9 | Resource ANY-of: hit on any listed audience incl. extra audiences (pin comment); no match otherwise | Evaluate (pure) | P0 |
| 10 | RequestedTokenType exact; empty = wildcard; empty new fields byte-identical to today | Evaluate (pure) | P0 |
| 11 | First-match-wins ordering: empty-field deny shadows later rules; deny short-circuits later allow; defaultAllow fallback | Evaluate (pure) | P0 |
| 12 | Concurrent Allow during Replace (both stores), Replace-vs-Replace serialization, `-race -count=10` | stores | P1 |
| 13 | Mount gating: nil / immutable Policy / MutablePolicy → absent / absent / present | interfaces/sso | P1 |
| 14 | Audit event: actor, before/after counts, rule_names truncation; failing sink → mutation stands (fail-open) | admin handler + sink | P1 |
| 15 | Builder: absent → nil,nil; inline; file+inline conflict; sqlite without DSN; inherited redis backend; bundle over cap → all fail loud / correct | build_governance | P1 |
| 16 | Strict YAML: unknown rule key rejects boot; inline config strict unmarshal rejects unknown key | config | P1 |
| 17 | E2E restart: PUT deny (client A + `admin:*` scope) → close server 1 → boot server 2 on same DSN → exchange denied `invalid_grant`; GET shows persisted rules | E2E | P1 |
| 18 | Schema drift: `PolicyStoreMaxVersion` ahead of live DB → `CheckSQLiteSchema` boot gate fails (live-newer-than-binary direction) | cmd gate | P2 |
| 19 | 401/403 admin gate on both verbs; probe path does not 200 | middleware E2E | P2 |
| 20 | PUT with `default_allow` in body ignored; idempotent re-PUT; empty rules array → default_allow governs | admin handler | P2 |
| 21 | Multi-replica staleness documented (no test — accepted limitation) | docs | P3 |
| 22 | `memory.Store.Rules()` result mutation does not affect active set (both stores) | stores | P3 |

## 5. CI/manual-suite gaps, flake risks, fixtures needed, exit criteria

**Gaps.**
- No mount-gating test exists for the chain endpoint and none is planned for
  the policies endpoints (F4) — add the first at interfaces/sso level.
- No appBuilder-level wiring test precedent in the repo; the design should
  state explicitly that `wireTokenExchangePolicy` is kept trivially thin and
  covered via builder tests, or introduce the first wiring test — do not
  silently rely on E2E.
- `make ci` was not run this revision (design-stage; zero `.go` edits).
  Known pre-existing drift from earlier batches (uncommitted worktree
  modifications) may affect it — report separately if it fails at
  implementation time.
- The requirements doc's own guardrail places new interfaces/sso code in
  `accessors_threat.go`/`server_routes_admin.go`; the design uses only
  `accessors_threat.go` (+1 line in `server_routes.go:101`). Both fit;
  `server_routes_admin.go` (332/500) is the requirements' stated home if the
  mount needs more room.

**Flake risks.**
- sqlite file DSNs must be unique per test (`file:` + `t.TempDir()` pattern
  from `domains/tokenexchange/sqlite/chain_store_test.go:15`); never share a
  DSN across parallel tests.
- The restart E2E must close server 1 before boot 2 (WAL/locking) and use a
  **file** DSN — `memDSN` (`test/storage_health_test.go:23`, shared-cache
  memory) vanishes with the last connection and would make the test pass
  vacuously or fail spuriously.
- Two concurrent admin PUTs hit SQLite's single writer; serialize in E2E or
  accept `SQLITE_BUSY` retry semantics — do not assert strict concurrency
  over HTTP.
- `rule_names` truncation must be bounded (cap 1000 already bounds it); a
  truncation test prevents an unbounded audit-cardinality regression.

**Fixtures needed.**
1. Strict-YAML bundle fixture containing an unknown rule key (reject case)
   and a valid bundle (accept case).
2. Hand-written sqlite DB fixture with invalid stored rows (corrupt JSON,
   invalid wildcard shape) for F3b.
3. Erroring audit sink (record + return error) for F9.
4. Call-recording store for the 400-before-store-call proof (F7d).
5. Immutable hand-written `Policy` (non-Mutable) for F4.
6. Admin bearer minting already exists (`test/admin_middleware_test.go:78`).

**Exit criteria.**
- F1 revised placement lands with `TestArchitecture_DirectoryFileFanout`
  green and every touched file ≤ 500 lines.
- All three requirements' acceptance checks map to named tests (§2 matrix
  fully green), including the four audit registrations in one change.
- `go test -race -count=10 ./domains/tokenexchange/...` green (F6).
- E2E: `go test ./test/ -run TestTokenExchange_ -count=1 -v` green with the
  new admin-PUT + restart tests; oracle collapse asserted on the wire.
- `make ci` green including kin-openapi validation of the new paths and
  config checks; `docs/config-reference.md` correct (no tokenpolicy-sqlite
  drift, cap + staleness documented).
