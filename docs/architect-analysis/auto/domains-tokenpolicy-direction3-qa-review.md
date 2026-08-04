# QA review: domains/tokenpolicy direction-3 design (tenant/subject selectors)

Review of `docs/auto/domains-tokenpolicy-direction3-design.md` (418 lines,
mirrored here). Role: QA lead, risk-based test review of a DESIGN-ONLY
revision. No `.go` files changed by the design; this review verified every
design citation against the tree and reviewed the test plan against the
spec's acceptance checks and AGENTS.md invariants.

## 1. Test inventory and commands actually run (this revision)

| Command | Result | Notes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | root module, current worktree |
| `go test -run 'TestMaintainability_\|TestArchitecture_' .` | PASS | 0.25s; file/function/depth budgets + layer map |
| `go test ./domains/tokenpolicy/... ./cmd/sso-server/serverbuildplatform/ -count=1 -race` | PASS | fresh (uncached) run; tokenpolicy 1.01s, memory 1.01s, serverbuildplatform 1.11s |
| `go test ./domains/tokenpolicy/ ./interfaces/sso/ ./internal/handler/tokengrant/ ./config/ -race` | PASS | interfaces/sso 65.96s; the design's own gate list |
| `make ci` | **FAIL (pre-existing)** | `fmt` stage: `infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go` (modified) and `test/region_token_contract_test.go` (untracked) are unformatted — unrelated in-flight work, not this design. Must be resolved before the implementation phase's handoff gate |

Design claims verified against the tree (all held unless noted):

- **Verified**: `Policy` selector = ClientID+Scopes only (`domains/tokenpolicy/tokenpolicy.go:53-98`); `PolicyInput.Subject` populated but never read (`evaluate.go:53-63`); `scopePresent` trailing-`*` (`evaluate.go:69-78`); `ParseYAML` non-strict (`yaml.go:19-24`); conditionalaccess `DisallowUnknownField` precedent (`domains/conditionalaccess/yaml.go:33`); `TestParseYAML_Empty` asserts `other: 1` parses as empty (`yaml_test.go:59-72`); `TestEvaluate_SelectorMatching` at `evaluate_test.go:177`; `TestEvaluate_DenyReasonDeterministic` present (`evaluate_test.go:201`).
- **Verified**: `server_token.go` exactly 500 lines, call at line 168 (`s.denyTokenScopeCombo(ctx, client.ID, scopes)`); `server_helpers.go` 493, `EnforceRefreshDepthPolicy` seam at 131-149; `wireCodeForPolicyDeny` at 109-115; `sessionPolicyCapExceeded` (`server_oauth.go:151-199`) called at `server_logout.go:357`; `createSession` already takes `tenantID` (`server_logout.go:345`); `ensureJITMembership` before `createSession` (`server_finish_login.go:46` vs 149); `RefreshGrantDeps` interface at `token_refresh.go:36-42`, call at 116; compile-time guards `accessors_handlers.go:363-371`; no test double implements `RefreshGrantDeps` (ripple is exactly 3 sites).
- **Verified**: `core.Subject` has ClientID+ServingRegion, no TenantID (`types_token.go:160-230`); `TenantRole` closed set member/admin/guest (`shared/core/tenant_user.go:9-26`); `WithTenantUserStore` (`options_passwd.go:363`), accessor (`accessors.go:234`), Get precedent (`server_logout.go:321-330`); `BuildTokenPolicyStore` at `build_governance.go:197-223`; `HandleAdminPolicies` verbatim serialization (`admin.go`); `buildAccessPayload` explicit claim enumeration, no tenant (`issue_payload.go:26-43`); `memory.Store` COW `Replace`; OpenAPI policies item schema at `docs/openapi.yaml` 6870-6888; config row at `docs/config-reference.md:588`.
- **Minor citation drift (non-material)**: `token_refresh.go` literal at 247 (exact); `server_login.go:112`/`server_native_sso.go:190` exact; a few ±1-5 line shifts vs. the spec's cites are due to unrelated in-flight work (refresh conditional-access + serving-region). Design's line budget table (500/493/481/430/277/160/176/24/69) matches `wc -l` exactly.
- **Does NOT hold** (see Findings H1, H2, M1): the "10 mint-time call sites" census is incomplete (12 exist); "tenant is read from `client.TenantID` at every seam" is false for the federated-callback session path; "7th non-test file" is a miscount (6th — impact nil, ceiling is 10).

## 2. Requirement-to-test matrix

Status legend: **Covered** = test exists today; **Planned** = in the design's
test plan; **Missing** = required by spec/invariant, absent from the plan.

### Preserved invariants (AGENTS.md §3, spec §Preserved)

| Invariant | Status | Evidence / planned pin |
|---|---|---|
| Oracle-safe wire: denies stay generic `invalid_scope`/`invalid_grant` via `wireCodeForPolicyDeny` | Covered + Planned | `TestRcov_TokenPolicy_ScopeComboDenied` (`rootcov_token_policy_test.go:21`); plan's seam tests assert generic codes on both tenant A and B |
| Single-tenant byte-compat: zero input tenant ⇒ tenant rules never match, global rules unchanged | Planned | evaluate matrix (a): `{TenantID:""}` non-match; (f) all-empty selectors byte-identical; `TestEvaluate_SelectorMatching` retained as regression pin |
| Additive strictest-wins, tenant rules tighten-only | Planned | spec acceptance (b): tenant 10m + global 5m ⇒ 5m (reverse combination, no widening); `TestEvaluate_TTLStrictestWins` (`evaluate_test.go:46`) retained |
| Domain purity: `tokenpolicy` stays pure; role resolution lives in `interfaces/sso` | Covered | `TestArchitecture_*` layer gate; design layer map honors it |
| Budgets: no file/function overflow | Covered | `TestMaintainability_*`; `server_token.go:168` same-line edit is the tightest point (risk #1) |
| Fail-open: store errors, role errors, nil store | Planned | seam tests: `tenantUserStore` nil ⇒ role rules inert; `Get` error ⇒ same; existing `TestRcov_TokenPolicy_UnwiredIsByteIdentical` |
| **Every access-token mint site stamps `Subject.TenantID`** | **Missing (partial)** | see Finding H1 — 2 of 12 sites absent from census; no per-flow integration pin |
| **Tenant input source = `client.TenantID` at every seam** | **Missing (partial)** | see Finding M1 (callback path passes empty) and M2 (source not pinned) |

### Improvement 1 — TenantID selector

| Acceptance (spec) | Status | Planned test |
|---|---|---|
| evaluate: `{TenantID:"ta"}` matches, `tb`/`""` non-match | Planned | `evaluate_test.go` table: (a) |
| strictest-wins both directions (no widening) | Planned | (b) incl. reverse combination |
| global rule byte-identical for any tenant input | Planned | (c) vs. `TestEvaluate_SelectorMatching` |
| seam: tenant A client scope-combo denied `invalid_scope`, tenant B allowed | Planned | `interfaces/sso` seam tests, memory store |
| seam: refresh-depth tenant rule fires via `client.TenantID` (`invalid_grant`) | Planned | tokengrant seam test |
| seam: clamp — `subject.TenantID` clamps only that tenant's client; unstamped ⇒ old bytes | Planned | `clamp_issuer_test.go` extension |
| all mint sites stamped | **Missing** | Finding H1: census lists 10, tree has 12; per-flow integration pins absent (M3) |
| openapi schema + config-reference synced | Planned | `docs/openapi.yaml` policies item (6870-6888) + `config-reference.md:588` |

### Improvement 2 — Subject / SubjectRoles selectors

| Acceptance (spec) | Status | Planned test |
|---|---|---|
| `Subject:"svc-*"` matches `svc-payments`, not `alice` | Planned | (a) |
| `SubjectRoles:["admin"]` matches `["member","admin"]`, not `["member"]` | Planned | (b) |
| empty input roles ⇒ role selector non-match (fail-open) | Planned | (c) |
| empty Subject+Roles ⇒ old behavior for any subject | Planned | (d) |
| session seam: ta admin over cap denied, member unaffected; store nil/err ⇒ fail-open | Planned | seam tests (memory tenant store) |
| refresh seam: `svc-*` depth rule fires for `svc-payments`, humans unaffected | Planned | seam test, wire `invalid_grant` |
| **Selector×dimension liveness documented for ALL seams** | **Missing** | Finding H2: 4 dead combos; only roles×refresh documented; clamp-seam subject no-op undocumented and untested |

### Improvement 3 — wildcard + strict YAML

| Acceptance (spec) | Status | Planned test |
|---|---|---|
| `ClientID:"payments-*"` matches/non-matches; exact regression | Planned | evaluate (c) + `prefixOrExact` unit cases |
| misspelled field ⇒ parse error | Planned | `yaml_test.go` unknown-field cases |
| bare `*`, interior `*`, invalid role ⇒ error | Planned | `validate_test.go` (new) |
| legal full document parses, fields land | Planned | `yaml_test.go` FullDocument extension |
| `TestParseYAML_Empty` fixture drops `other: 1` | Planned | design calls this out explicitly |
| **inline `TokenPolicyConfig.Policies` invalid rule ⇒ boot failure** | **Missing** | Finding M4: spec acceptance requires the config-path test; plan only has `validate_test.go` unit cases |
| legacy `scopes: ["*"]` bundle still loads | **Missing** | Finding L1: no pin that Validate leaves scopes untouched |
| existing bundle with `*` in `client_id` now fails boot — release-note item | **Missing** | Finding L1 |

### Contract surface

| Contract | Status |
|---|---|
| Admin read API carries the three new fields | Planned docs; **Missing** round-trip test (Finding M5) |
| No new endpoints/Err*/metrics/events | Verified — no contract delta |
| Claim surface: no `tenant_id` claim on access tokens | Planned (claim-set pin) — the design's critical boundary |

## 3. Findings

### H1 — High: mint-site census is incomplete; 2 of 12 sites silently escape tenant TTL clamping

**Evidence**: The design lists 10 stamp sites. An exhaustive `core.Subject{`
census of the tree (non-test) finds **12**:
the 8 tokengrant sites + `server_login.go:112` + `server_native_sso.go:190`
(the design's 10) **plus** `domains/tokenexchange/agentidentity/grant.go:185`
(`mintDelegationToken`, the agent-delegation grant, wired into the stock
server via `interfaces/sso/options_grants.go` `WithAgentDelegationGrant`,
minting through `d.IssuerForClient(client)` → ClampingIssuer, `client` in
scope) and `interfaces/sso/accessors_feature_gates.go:257` (break-glass
impersonation mint through `s.issuerForClient(nil)`). The design's claim
"all stamp ClientID + ServingRegion in the same literal" is also false for
these two (neither stamps ServingRegion today).

**Impact**: Agent-delegation tokens for a tenant-bound client never get
tenant `max_ttl` rules — the exact silent-erosion direction the design's own
risk #3 names, from a site the design believes it enumerated. Fail-open, so
no exploit, but a governance blind spot on a real grant flow. (Break-glass
exemption may be *desirable* — emergency credential — but it must be a
deliberate, documented exemption, not an omission.)

**Exact test to add**: `internal/handler/tokengrant/...` — extend the seam
suite: `TestRcov_TokenPolicy_TenantMaxTTL_AgentDelegation` — register the
agent-delegation grant with a tenant-bound client (`client.TenantID: "ta"`),
seed `tenant_id: "ta"` + `max_ttl: 5m`, mint via `/token` agent_delegation;
**acceptance assertion**: `expires_in == 300`; and a break-glass sibling
asserting either the clamp or an explicit exemption comment + test.

### H2 — High: subject/roles × max_ttl and subject × block_scope_combos are silent dead combinations, undocumented

**Evidence**: `ClampingIssuer.Issue` builds `PolicyInput{ClientID, Scopes,
Kind, RequestedTTL}` — no `Subject` (`clamp_issuer.go:44-52`; design's
Decision 4 adds only `TenantID`). `denyTokenScopeCombo` builds
`PolicyInput{ClientID, Scopes, Kind}` — no `Subject` (`server_helpers.go`).
So a policy `{subject: "svc-*", max_ttl: 5m}` or `{subject_roles: ["admin"],
max_ttl: 5m}` or `{subject: "alice", block_scope_combos: ...}` **loads
cleanly through `Validate` and never fires anywhere**. The spec's
Improvement-2 motivation explicitly names "human vs machine differentiated
TTL"; the design documents only ONE of the four dead combos (roles ×
refresh). `Validate`'s charter (reject shapes that "silently change meaning")
cannot catch this, because a dead combo is not a shape error.

**Impact**: Operators write rules that silently do nothing on the most-used
dimension (`max_ttl`). Same trust failure class the design's strictness
decision exists to prevent.

**Exact test to add** (pins the no-op so it is at least deterministic, and
docs it): `domains/tokenpolicy/evaluate_test.go` —
`TestEvaluate_SubjectSelector_NoMatchWhenSubjectAbsent`: `Evaluate(PolicyInput{ClientID:"c", TenantID:"ta", Scopes:...}, []Policy{{Subject:"svc-*", MaxTTL: 5m}})` —
**acceptance assertion**: `EffectiveTTL` unchanged (no clamp) when
`in.Subject == ""`; plus a config-reference liveness table
(selector×dimension×seam) replacing the single refresh-seam note. Either
that, or the design must add `Subject: subject.ID` to the clamp input and
resolve the pairwise-projection identity question it raises (subject.ID is
the projected `sub` there, unlike the local ID at the other seams).

### M1 — Medium: "tenant read from client.TenantID at every seam" is false for the federated-callback session path

**Evidence**: `createSession` has three callers; `finalizeCallbackSession`
(`server_oauth.go:223`) passes `("", "", ...)` by design — comment: "Federated
callback has no OAuth client in play — pass an empty clientID (and tenant)".
The other two callers (`server_login_auth.go:487`, `server_finish_login.go:149`)
pass `client.TenantID`. The design's seam table cites only
`server_logout.go:357` and does not audit the other callers; tenant-scoped
`max_active_sessions` rules are inert on the callback path.

**Impact**: Fail-open and consistent with the byte-compat contract, but the
design's claim overstates the seam, and the limitation is undocumented (the
refresh-role limitation got documentation; this one doesn't).

**Exact test to add**: `interfaces/sso` — `TestRcov_TokenPolicy_SessionCap_TenantRuleInertOnCallbackPath`:
tenant-bound rule `{tenant_id:"ta", max_active_sessions:1}`, two callback
logins for the same user through a server with `WithTenantUserStore` +
tenant ta roster; **acceptance assertion**: second login succeeds (global
rules would deny; tenant rule does not fire) — pinning the empty-tenant
input; document the limitation in config-reference.

### M2 — Medium: no test pins the tenant SOURCE (client.TenantID vs request/middleware tenant)

**Evidence**: The plan's "tenant A denied / tenant B allowed under the same
rule, per seam" only proves a tenant value flows through the seam; it cannot
distinguish `client.TenantID` from a middleware/header-derived tenant when
both are equal in the fixture. Design risk #3's "a seam passing the
middleware-resolved request tenant instead of client.TenantID" is therefore
not actually pinned.

**Exact test to add**: one seam test that constructs a tenant-bound client
(`client.TenantID = "ta"`) and a request whose middleware stash carries a
*different* tenant (`"tb"`), then asserts the `ta` rule fires. If the
interfaces/sso test harness cannot set a conflicting stash tenant, say so in
the design and add the test at the `dispatchTokenGrant` boundary with a
hand-built `HandlerContext`; **acceptance assertion**: deny for `ta` rule +
`tb` stash, proving policy input keys on the client binding.

### M3 — Medium: no per-flow mint-stamp integration test; 12 stamp lines are otherwise unpinned

**Evidence**: The only TTL-clamp integration test is
`TestRcov_TokenPolicy_MaxTTLClampsIssuedToken` (`rootcov_token_policy_test.go:71`)
via client_credentials with a *global* rule. The planned clamp tests are
unit-level (`clamp_issuer_test.go` with hand-built subjects). A site that
forgets the stamp passes every planned test (fail-open is byte-identical).

**Exact test to add**: table-driven
`TestRcov_TokenPolicy_TenantMaxTTL_PerGrantFamily` — tenant-bound client +
`{tenant_id:"ta", max_ttl: 5m}`; drive authcode, client_credentials, device,
ciba, jwt_bearer, saml2_bearer, exchange, login, native_sso, refresh, agent
delegation; **acceptance assertion**: `expires_in == 300` for every family
in the table. This is the single highest-value test in the plan.

### M4 — Medium: inline-config validation has no boot-level test

**Evidence**: Spec acceptance requires "config snapshot test:
`TokenPolicyConfig.Policies` with an invalid `subject_roles` ⇒ config load
fails". The design plan covers `validate_test.go` unit cases but nothing at
`BuildTokenPolicyStore` (`cmd/sso-server/serverbuildplatform/build_governance_test.go`
currently has no such case), so a future edit that forgets to wire `Validate`
into the inline path (design risk 4b) would slip through.

**Exact test to add**: `cmd/sso-server/serverbuildplatform/build_governance_test.go` —
`TestBuildTokenPolicyStore_InlineInvalidRuleFailsBoot`: inline policy with
`SubjectRoles:["owner"]`; **acceptance assertion**: non-nil error, and
`go test ./cmd/sso-server/serverbuildplatform/` green with the design's
`Validate` call in place.

### M5 — Medium: admin read API has no round-trip test for the three new fields

**Evidence**: `TestRcovAdmin_TokenPoliciesInventory`
(`rootcov_admin_token_policies_test.go:44`) asserts `name`/`client_id` only.
The design's contract table says "verbatim serialization carries the new
fields" but the plan has no assertion.

**Exact test to add**: extend that test with a policy carrying all three
fields; **acceptance assertion**: response `policies[0]` contains
`tenant_id == "ta"`, `subject == "svc-*"`, `subject_roles == ["admin"]`,
and a global rule omits all three keys (omitempty byte-compat).

### L1 — Low: legacy-compat pins for the strictness flip

**Evidence**: (a) `Validate` deliberately leaves `scopes` unvalidated — a
legacy `scopes: ["*"]` bundle must keep loading; no test pins this, so a
future over-eager `Validate` change breaks existing bundles silently. (b) An
existing bundle with `*` in `client_id`/`subject` now fails boot — same
class as the unknown-top-level-key flip the design does call out, but this
one is only in risk 4's release-note sentence, not the test plan.

**Exact test to add**: `yaml_test.go` —
`TestParseYAML_LegacyBareStarScopeStillLoads` (`scopes: ["*"]` ⇒ no error);
**acceptance assertion**: parse succeeds and the scope survives.

### L2 — Info: "7th non-test file" is a miscount

`domains/tokenpolicy` has 5 non-test files today; `validate.go` makes 6, not
7. Impact nil (ceiling is 10), but the census-style claims in this design
should be exact — see H1.

### Pre-existing failure (not caused by this design)

`make ci` is currently red at the `fmt` stage:
`infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go` (modified) and
`test/region_token_contract_test.go` (untracked) are unformatted. Unrelated
in-flight work; must be resolved before the implementation phase can use
`make ci` as its handoff gate. Reported separately per AGENTS.md §5.7.

## 4. Prioritized scenario list (implementation phase)

Happy path:
1. Tenant A client + `tenant_id:"ta"` scope-combo rule ⇒ `400 invalid_scope`; tenant B same rule ⇒ token issued. (M2 variant with conflicting stash tenant.)
2. Tenant-bound client + `tenant_id:"ta"` max_ttl ⇒ `expires_in` clamped at every grant family (M3 table).
3. `subject:"svc-*"` + `max_refresh_depth` fires for the service account at rotation cap ⇒ `invalid_grant`; human subject unaffected.
4. ta-admin over `max_active_sessions` cap ⇒ `access_denied`; ta-member under cap succeeds; JIT-provisioned first login sees the role (ensureJITMembership order).
5. Admin API lists the three new fields; global rule omits them.

Boundary:
6. Empty input tenant + tenant rule ⇒ non-match (byte-compat); global rule unchanged (`TestEvaluate_SelectorMatching` regression).
7. Reverse strictest-wins: tenant 10m + global 5m ⇒ 5m (no widening).
8. `prefixOrExact`: exact, trailing-`*`, bare `*` (match-all at engine level), empty selector.
9. `subject_roles` intersection: single hit, multiple roles, empty input.

Error/failure:
10. `TenantUserStore.Get` error ⇒ session created, roles inert, error logged (fail-open).
11. Store nil (unwired) ⇒ all four seams byte-identical.
12. `Policies()` error at each seam ⇒ fail-open with log.
13. Misspelled `tennat_id`, bare/interior `*`, invalid role ⇒ boot failure (both File and inline paths).
14. Unknown top-level YAML key ⇒ parse error (was: empty policy set).

Race/concurrency:
15. `memory.Store` COW under concurrent `Policies` + `Replace` with tenant rules (existing `TestStore_ConcurrentReadWrite` pattern, extended with new fields).
16. Session seam: concurrent logins of the same user at the cap boundary — cap is count-then-mint (pre-existing semantics; no new shared state; run `-count=10+`).

Recovery:
17. Role-resolution outage mid-login ⇒ login proceeds (fail-open), subsequent login re-resolves.
18. Tenant rule present but client tenant changes between mint and evaluate — request-scoped stamp, no cross-request state (assert no caching introduced).
19. Config reload (Replace) with a rule set dropping a tenant rule ⇒ next request unclamped, no stale state.

Security/oracle:
20. Deny reason never on the wire for tenant/subject rules (generic codes, both tenants, per seam).
21. Claim-surface pin: tenant-bound subject's access token contains no `tenant_id` claim; JWT claim set byte-identical for single-tenant deployments.
22. Tenant/subject values absent from error bodies and admin responses beyond the governance read.

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**CI gaps**:
- `make ci` red on two pre-existing unformatted files — unblocks nothing today but must be green for the implementation handoff.
- No E2E coverage of token policies exists (`test/` has zero token-policy tests); the plan adds none. At minimum one E2E flow: tenant-bound client + tenant rule + admin API field presence (`go test ./test/ -run TestE2E -v`). Medium priority — wire contract unchanged, so E2E is a safety net, not a release gate.
- The design's gate list omits `go test ./... -race` and the E2E suite that AGENTS.md §2 lists before handoff; add both to the implementation checklist.

**Flake risks**:
- Existing seam tests are `t.Parallel()` under `rcovNewServer`; new tenant/role tests must not share store state across cases (each test seeds its own `memory.New` + `NewMemoryTenantUserStore`).
- The session-cap tests count sessions via `ListByUser`; keep each case's session set isolated (unique user IDs) to avoid cross-test eviction interference.
- No time-sensitive assertions should be added beyond the existing `expires_in` integer compares (already deterministic via issuer defaults).

**Fixtures needed**:
- YAML bundle with a tenant/subject/roles rule (legal + one misspelled-field variant + one bare-`*` variant) for `yaml_test.go`/`validate_test.go`.
- Tenant-bound client fixture (client with `TenantID` set) in `interfaces/sso` seam tests — check whether `rcovNewServer`/`rcovDo` fixtures support setting `Client.TenantID`; if not, add a tenant-aware constructor.
- Memory tenant store seeded with member/admin/guest roles for the session seam.
- A conflicting-stash request fixture for M2 (if the harness can express it).

**Exit criteria** (implementation phase):
1. All H1/H2/M1-M5 tests land in the same change as the code (AGENTS.md §5.6: contracts in the same change; the two doc files synced).
2. `go build ./... && go vet ./...`, `TestMaintainability_|TestArchitecture_`, and the design's `-race` gate list all green; `make ci` green (after the pre-existing fmt fix).
3. `server_token.go` stays at 500 lines (same-line edit), `server_helpers.go` ≤ 500 (exactly two `PolicyInput` lines), `server_oauth.go` ≤ 500.
4. The 12-site stamp census (10 + agentidentity + break-glass) has an explicit decision per site: stamp or documented exemption.
5. Selector×dimension liveness matrix documented in `docs/config-reference.md` (replaces the single refresh-seam note).
6. Claim-surface pin test present and passing (no `tenant_id` JWT claim).

Advisory only: this review approves nothing; it gates nothing. The findings
are required fixes or explicit documentation obligations for the
implementation change that follows this design.
