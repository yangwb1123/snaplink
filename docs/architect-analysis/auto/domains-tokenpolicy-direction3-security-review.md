# Security Review: token-policy tenant/subject/role selectors (direction 3)

Reviewer role: principal security engineer (adversarial production behavior).
Input: `docs/auto/domains-tokenpolicy-direction3-design.md` (418 lines) plus the
underlying `domains-tokenpolicy-direction3-spec.md`. Scope: the six decisions —
selector model (`TenantID`/`Subject`/`SubjectRoles`), `prefixOrExact` matching,
strict YAML + `Validate`, four-seam tenant threading, `core.Subject.TenantID`
mint-time stamp, and the admin/docs surface — against authentication,
authorization, tenant isolation, credential lifecycle, session/token replay, and
privilege boundaries at every exposed entry point.

This is an advisory review of a **proposal**. No `.go` file was changed, so no
Go gate ran; every claim below was re-verified against the current tree at
`HEAD` (`ff690260`) by source inspection (reads + greps only). Unrelated
worktree modifications (`cmd/sso-server/*`, `.pi/*`, `ai-dev/*`) were not
touched.

## Verification run for this review (all source-level, no gates executed)

- Selector baseline: `Policy` selector is `ClientID` + `Scopes` only
  (`domains/tokenpolicy/tokenpolicy.go:53-98`); `matches()` never reads
  `in.Subject` (`evaluate.go:53-63`); `scopePresent` trailing-`*` precedent at
  `evaluate.go:69-78`. **Verified**
- Strictest-wins union: `Evaluate` (`evaluate.go:20-32`) = per-dimension min
  (`clampTTL` `evaluate.go:81-90`, `stricterRenew` :93-101) + first-deny-wins in
  policy order (`denyReason` :106-118, fixed dimension order). A tenant rule
  joining the same union can only tighten. **Verified**
- Seam surface: the design names four seams. Grep finds **five** `Evaluate`
  call sites: `clamp_issuer.go:47`, `server_helpers.go:94` (scope-combo +
  refresh via `enforceTokenPolicy`), `server_oauth.go:177` (session cap),
  `sso_protocol.go:486` (**introspection renew — not in the design**).
  **Verified**
- Issue-site enumeration: the design claims "the 10 verified mint-time call
  sites". Grep for `core.Subject{` in non-test code finds **12** runtime sites
  plus one codegen template. The two unreported runtime sites are
  `protocols/oidc/handle_silent_renewal.go:210` (reachable in the stock server:
  `interfaces/sso/server_discovery.go:66` → `server_login_resolve.go:169`) and
  `domains/tokenexchange/agentidentity/grant.go:185` (wired via
  `interfaces/sso/options_grants.go`, opt-in `WithAgentIdentityGrant`); the
  template is `cmd/sso-ctl/generate/templates_handler.go`. All funnel through
  `Server.IssuerForClient` (`accessors_handlers.go:158`) → `issuerForClient`
  → `tokenpolicy.NewClampingIssuer` (`server_helpers.go:67`). **Verified —
  design's completeness claim is WRONG (12 vs 10).**
- Claim surface: `buildAccessPayload` enumerates claims explicitly
  (`infrastructure/defaultimpl/issue_payload.go:26-45`); `ed25519Payload`
  (`ed25519_types.go:15-46`) has no `tenant_id`; ECDSA/RSA share the payload
  builder; `SessionTokenIssuer` (`defaulttoken/session_issuer.go:51-66`) reads
  only `subject.ID`. Adding `Subject.TenantID` cannot leak a claim. **Verified**
- Tenant source + gate order: `/token` seams run after `clientTenantOK`
  (`server_token_clientauth.go:171`, gate ladder at :159-187); login paths gate
  tenant before session creation (`server_login_client.go:46`,
  `server_login_resolve.go:160`); key isolation precedent uses
  `client.TenantID` (`server_helpers.go:39-40`). **Verified**
- Refresh subject identity: the refresh record stores the LOCAL `UserID`
  (`token_authcode.go:139,220`; pairwise applied only at issuance via
  `ApplyPairwiseSubject` :113), so `info.UserID` at the refresh seam is the
  local subject — matches the design's Decision 2 contract. **Verified**
- Strictness: `ParseYAML` is non-strict `yaml.Unmarshal` (`yaml.go:19-24`);
  `TestParseYAML_Empty` asserts `other: 1` parses as "no policies"
  (`yaml_test.go:59-72`); conditionalaccess precedent `DisallowUnknownField`
  (`conditionalaccess/yaml.go:33`); `BuildTokenPolicyStore` validates the File
  path via `ParseYAML` but has NO validation on the inline `cfg.Policies` path
  (`cmd/sso-server/serverbuildplatform/build_governance.go:197-223`). All as the
  design states. **Verified**
- Budgets: `server_token.go` is exactly 500 lines; `server_helpers.go` 493;
  `server_oauth.go` 481; `token_refresh.go` 430; `tokenpolicy.go` 160;
  `evaluate.go` 176; `types_token.go` 277; `clamp_issuer.go` 69. **Verified**
- Token exchange tenant gate: guest/home-tenant cross-check exists
  (`token_exchange.go:405-474`) before minting. **Verified**
- No dynamic policy reload: `memory.Store.Replace` exists but `HandleAdminPolicies`
  is GET-only (`admin.go`); config is boot-time. **Verified**

---

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets

| Asset | Owner | Notes |
|---|---|---|
| Policy set (`[]Policy`, memory COW store) | Operator config (YAML file / inline) | Now carries tenant/subject/role selectors — governance data, no secrets |
| `client.TenantID` binding | Client store (admin/DCR-registered record) | The single source of the tenant dimension; immutable at request time |
| `core.Subject.TenantID` mint-time stamp | Request-scoped | Policy input only, never persisted, never a claim |
| `TenantUserStore` membership edges | In-process memory / sqlite | New read dependency at the session seam |
| Access/refresh/ID tokens, sessions, auth codes | Existing credential stores | Unchanged by this design |
| Admin read API (`/api/v1/admin/token-policies`) | `admin:read` | Now serializes the three new selector fields |

### Trust boundaries

1. **Operator config → engine.** Policies are trusted operator input, but the
   design's strictness work exists because a *typo* must not silently demote a
   tenant rule to a fleet-wide rule. This is the boundary the design hardens
   (strict parse + `Validate` + inline-path validation). The remaining trust
   gap is the programmatic `memory.NewFromSlice` seed (documented residual).
2. **Client store → seams.** `client.TenantID` crosses from the client record
   into every policy input. The record is admin-controlled; request headers
   never feed it. The tenant-mismatch gate (`clientTenantOK`) runs before all
   `/token` and login seams, so the request-tenant assertion cannot diverge
   from the record.
3. **Roster store → session seam.** `TenantUserStore.Get(client.TenantID,
   userID)` crosses into `SubjectRoles`. Fail-open by design; the store is
   in-process (memory/sqlite), so the outage window is bounded to a replica.
4. **Token boundary.** `core.Subject.TenantID` must never cross into the JWT
   claim set. Explicit enumeration in `buildAccessPayload` is the boundary;
   the claim-set test is the pin.

### Attacker capabilities

- **Unauthenticated network attacker**: can hit `/token`, `/auth/login`,
  `/authorize` (prompt=none), introspection, admin gate (401). Can submit any
  `scope`, `grant_type`, `client_id`, headers. Cannot influence
  `client.TenantID`, the roster, or the policy set.
- **Authenticated user (resource owner)**: controls their own `userID`,
  scopes, and client choices. Can create sessions, refresh, exchange tokens.
  Cannot change their own role or another tenant's policies.
- **Compromised client**: can request any allowed grant, any scope subset.
  Cannot change `client.TenantID` (record-bound) or the tenant rules that bind
  it.
- **Roster-store operator / admin**: can move membership edges — that is the
  intended authority surface for role selectors. Not an attacker.

### Entry points touched by the design

| Entry point | Seam | Selectors that work after the design |
|---|---|---|
| `/token` (all grants) | scope-combo gate `server_token.go:168` | tenant (+client/scope) |
| `/token` refresh grant | `EnforceRefreshDepthPolicy` `token_refresh.go:116` | tenant, subject (+client/scope) |
| `/auth/login`, `/auth/callback` | session cap `server_logout.go:357` (createSession) | tenant, subject, subject_roles |
| all issuance | TTL clamp `clamp_issuer.go:47` | tenant (+client/scope) — subject/roles INERT |
| introspection | renew seam `sso_protocol.go:486` | client/scope only — tenant/subject/roles INERT (not in design) |

---

## 2. Findings (severity-sorted)

### F1 — High: issue-site enumeration is incomplete — tenant `max_ttl` silently inert at silent renewal and agent-delegation mint (12 sites, not 10)

**Evidence (Verified).** `core.Subject{` is constructed at 12 runtime sites;
the design's Decision 5 list covers 10 and omits:
`protocols/oidc/handle_silent_renewal.go:210` (`issueSilentRenewalToken`, via
`Server.handleSilentRenewal` `server_discovery.go:66`, reached from the
`prompt=none` path `server_login_resolve.go:169`) and
`domains/tokenexchange/agentidentity/grant.go:185` (`mintDelegationToken`,
wired by the stock `WithAgentIdentityGrant` option). Both already stamp
`ClientID: client.ID` with `client` in scope — exactly the pattern the 10
listed sites follow — and both resolve the issuer through
`IssuerForClient` → `NewClampingIssuer` (`server_helpers.go:67`), so the clamp
seam *does* run. Under the design, `subject.TenantID` stays `""` there and
every `tenant_id:` `max_ttl` rule is a non-match. `cmd/sso-ctl/generate/
templates_handler.go` (codegen) is a third unlisted file.

**Exploit preconditions.** Operator configures a tenant-scoped TTL rule
(`tenant_id: A, max_ttl: 5m`) and believes the uniform clamp enforces it
everywhere (the design's own promise: "the UNIFORM seam that applies max_ttl
to every grant flow").

**Exploit steps.** Any RP with a live session calls the authorize/prompt=none
path (no user interaction, no fresh authn) and receives an access token with
the client's full `AccessTokenTTL` — unclamped by tenant policy. Same for an
agent-delegation grant when that option is wired. No error, no log, no
audit: the design's failure-table row "Old/third-party issue site misses the
stamp" explicitly blesses this outcome as "fail-open; matches pre-feature
bytes".

**Impact.** Silent governance bypass: tenant A's TTL ceiling is not enforced on
two reachable mint paths, including the highest-risk one (silent renewal mints
a bearer token without re-authentication). Bounded — no cross-tenant access,
no credential compromise, no oracle leak; the issuer default /
`client.AccessTokenTTL` still caps lifetime. But the design's central
"uniform clamp" invariant is quietly false, and the completeness claim that
would have caught it ("all 10 verified") is wrong with no mechanism to detect
an 11th site.

**Remediation.** Stamp `TenantID: client.TenantID` at all 12 runtime sites
plus the codegen template; correct the design's site list; add a static
comment contract on `ClampingIssuer.Issue` ("a site that mints via
`IssuerForClient` MUST stamp `Subject.TenantID`") and a seam-level test per
added site so a future 13th site is caught by review, not by an operator's
audit.

**Regression test.** Server-level test: tenant-bound client + `tenant_id: A,
max_ttl: 5m` rule; (a) drive `HandleSilentRenewal` with a valid hint token →
assert the minted access token's TTL is clamped to 5m; (b) drive the agent
delegation mint → same assertion. Without the stamps both fail.

### F2 — Medium: three undocumented inert-selector surfaces — subject/roles at the clamp and scope-combo seams, and a fifth evaluation point (introspection renew) missing from the design entirely

**Evidence (Verified).** `ClampingIssuer.Issue` builds `PolicyInput{ClientID,
Scopes, Kind, RequestedTTL}` only (`clamp_issuer.go:44-52`) — the design adds
`TenantID` but not `Subject`, so `subject:`/`subject_roles:` + `max_ttl` never
matches. `denyTokenScopeCombo` (`server_helpers.go:123-129`) supplies no
subject, so `subject:`/`subject_roles:` + `block_scope_combos` never matches.
`IntrospectionRenewExceeded` (`sso_protocol.go:485-505`) — a fifth `Evaluate`
call site absent from the design's four-seam framing — supplies only
`ClientID`/`Scopes`; because Decision 5 deliberately keeps tenant out of the
token claims, this seam *cannot* resolve tenant/subject/roles without a
client-store lookup it does not do. The design documents only the
refresh-seam role no-op (Decision 4 + risk #7); the failure table and the
`docs/config-reference.md` plan name no other inert combination.

**Exploit preconditions.** Operator writes a plausible rule: `subject: alice,
max_ttl: 5m`, or `tenant_id: A, require_renew_after: 0.5`, or
`subject_roles: [guest], block_scope_combos: [...]`. `Validate` accepts all of
them (only wildcard shape and role closed-set are checked).

**Exploit steps.** The rule loads at boot, appears in the admin read API, and
never fires. For `require_renew_after` the failure is on an *enforcement*
surface: tenant A tokens are reported `active` at introspection past the
intended renew point. For `max_ttl` the failure is on the TTL surface the
design's headline decision is about.

**Impact.** Silent governance no-ops the operator cannot distinguish from
enforcement — the exact "invisible no-op" failure class the design itself
flags for refresh (risk #7) but mitigates only there. No widening relative to
today's bytes (fail-open), but the feature's advertised capability is
overstated in the docs plan.

**Remediation.** (a) Enumerate in the failure table and config-reference every
inert (seam × selector) combination: clamp (subject/roles), scope-combo
(subject/roles), introspection (tenant/subject/roles); (b) explicitly name
introspection renew as the fifth evaluation point and choose: document
inertness, or thread tenant via a client-store lookup at introspection (cost:
one read on a hot path — the design's "one read at one seam" claim changes);
(c) note that the clamp seam sees the pairwise-projected `sub` at login/refresh
sites, so adding `Subject` there would violate the documented "local subject
ID" contract — do not plumb it; document instead.

**Regression test.** `Evaluate` with the exact introspection shape
(`ClientID`+`Scopes` only) against a tenant-scoped `require_renew_after` rule
→ `RenewAfter == 0`; clamp shape with a `subject:` `max_ttl` rule → TTL
unclamped; scope-combo shape with a `subject_roles:` combo rule → no deny.
Each pins the documented inertness so it stays intentional.

### F3 — Medium: fail-open role resolution widens member/guest caps during roster lookup failure (bounded, deliberate — needs an operator-visible signal)

**Evidence (Verified).** Decision 4's snippet returns empty `SubjectRoles` on
`Get` error / `ErrNoMembership`, so every role-scoped rule stops matching and
only the global rules bind. The typical rule layout is global ceiling + tighter
role rules (guest cap 1, member cap 3, global 10); during a roster-store error
a guest receives the global cap. This is the AGENTS.md §3 fail-open precedent
(tenant-suspension lookup outage) and the design pins it with a test, so it is
a deliberate tradeoff — but the failure is logged only at `Error` level with no
metric, and the consequence is *privilege-widening for the constrained class*
(guests), not merely availability.

**Exploit preconditions / steps.** A replica whose roster store errors (or a
deployment with JIT disabled where a user has no membership edge) while role
rules are in force. The attacker does not cause the outage; they benefit from
it. The third `createSession` call site (`server_oauth.go:223`, federated
callback without a client, `tenantID=""`) also makes role rules inert by
construction — intended, but unnamed in the failure table.

**Impact.** Bounded: global ceilings still hold, deny-only, no cross-tenant
data access. But the constrained class (guests/members) transiently gets
member/global caps — more concurrent sessions / longer-lived sessions than
policy intends during an outage window.

**Remediation.** At minimum, add a bounded metric for "role rules present but
role resolution failed" so the fail-open window is observable (no new
unbounded labels — reuse the existing denial/error families). Optionally
offer a fail-closed mode: scan the loaded policy set for role selectors
before evaluation (the design rejected the scan as premature optimization; a
scan-only-when-rules-exist variant is the natural place to decide).

**Regression test.** Existing planned test ("`Get` error ⇒ same") pins the
behavior; add an assertion that the fail-open path is observable (metric or
log) so a silent widening window cannot ship unnoticed.

### F4 — Low: `tenant_id` selector is unvalidated — silently-inert spellings and the missing-key-implies-global trap

**Evidence (Verified by reading the design).** `Validate` gates `*` for
`client_id`/`subject` and the closed set for `subject_roles`, but has no rules
for `tenant_id`: `tenant_id: "*"` or `" ta "` (whitespace) or `"TenantA"`
(case) load cleanly and never match (fail-closed, silent), while omitting the
key silently creates a FLEET-WIDE rule (fail-open for operator intent — the
exact hazard Improvement 3 exists to kill, in the opposite direction).

**Impact.** Config-authoring errors degrade to silent inert rules (both
directions) instead of the fail-loud behavior the strictness work promises.
Bounded: no attacker input reaches `tenant_id` (record-derived).

**Remediation.** `Validate`: reject `*`, whitespace padding, and empty-adjacent
spellings in `tenant_id`; document in config-reference that a missing key =
global rule and that the admin read API shows the effective binding.

**Regression test.** `Validate` rejects `tenant_id: "*"` and `tenant_id: " a "`
in the new `validate_test.go`.

### F5 — Low: budget/doc consistency in the seam plan (server_oauth.go math; unnamed no-tenant session seam)

**Evidence (Verified).** `server_oauth.go` is 481 lines; the design's
"481→~489" math omits the `logger.Error` line its own Decision 4 snippet
contains (closer to ~491), and "no logging additions" contradicts the snippet.
The design's own warning — review feedback that adds lines to
`server_token.go` (exactly 500) breaks the gate — is sound, but the same
discipline is not stated for `server_oauth.go` (9 lines from the gate) and
`server_helpers.go` (493). The third `createSession` call site
(`server_oauth.go:223`) passes `tenantID=""`; role rules are inert there — a
correct, intended outcome that the failure table does not name (its
"single-tenant input" row covers only the zero-input-tenant case).

**Impact.** None security-wise; gate-breakage risk during implementation and
an under-specified failure row.

**Remediation.** Fix the math in the design; add the "no-tenant-context
session (federated callback without client)" row to the failure table.

### F6 — Info: pre-existing session-count quirk becomes more likely to bite with role rules

**Evidence (Verified).** `sessionPolicyCapExceeded` counts `ListByUser(userID)`
— the subject's TOTAL live sessions across all clients (`server_oauth.go:186`,
`server_logout.go:349-357`) — while `max_active_sessions` rules may be
client- or role-scoped. A client-scoped/role-scoped cap can deny based on
sessions held on other clients. Pre-existing (unchanged by the design), but
role rules make the false-deny more likely for admins/members with many
clients.

**Remediation.** Document in config-reference; do not change semantics in this
change.

---

## 3. Abuse-case table

| # | Abuse case | Reachable? | Verdict / mitigation |
|---|---|---|---|
| A1 | **Identity spoofing — subject selector**: attacker mints a token whose policy-evaluated subject is `alice` to dodge or trigger a `subject:` rule | No | Subject at every seam comes from the authenticated session/refresh record (`result.UserID`, `info.UserID` — local, stored at authn). Pairwise projection happens only at issuance and is NOT the selector key (Decision 2, documented). No input-controlled subject path found. **Verified** |
| A2 | **Identity spoofing — role selector**: attacker obtains `admin`/`member` roles to widen caps or dodge guest rules | No | `SubjectRoles` resolves only from `TenantUserStore.Get(client.TenantID, userID)`; roles are store-admin-controlled; JIT provisions only `member`. The best an attacker can do is cause a lookup failure → roles empty → role rules inert (F3, bounded by global rules). **Verified** |
| A3 | **Replay — stale policy state / token replay**: reuse of a minted token to bypass a tightened tenant rule | Partial | Policies are evaluated at mint time; a token minted before a rule ships keeps its TTL until expiry (existing TTL semantics, unchanged). No new replay surface: no new claims, no new stores, refresh-family rotation/reuse invariants untouched. **Verified** |
| A4 | **Cross-tenant access — tenant rule applied to wrong tenant or forged tenant input** | No | Tenant is always `client.TenantID` (record, admin-set), never header-derived (Decision 4). `clientTenantOK` mismatch gate precedes all `/token` seams (`server_token_clientauth.go:171`) and login seams (`server_login_client.go:46`). Token exchange has its own home-tenant cross-check (`token_exchange.go:405-474`). **Verified** |
| A5 | **Cross-tenant access — tenant-less legacy client in tenant A dodges tenant A rules** | Partial | A client with empty `TenantID` never matches tenant rules and gets only the global ceiling (looser). Config hygiene, not an input forgery: operators must bind clients to tenants for tenant rules to bind them. Document in config-reference. **Residual** |
| A6 | **Cross-tenant access — silent renewal bypasses tenant `max_ttl`** | **Yes** | F1: `prompt=none` mint does not stamp `Subject.TenantID` under the design as written → tenant TTL ceiling not enforced on silent-renewal tokens. Fix: stamp the site + test. **Verified** |
| A7 | **Proxy/header forgery — XFH/tenant header steers policy input** | No | Design reads only `client.TenantID`; forwarded-host/proto and tenant headers remain trusted-proxy-gated middleware concerns, unchanged. Policy input cannot be influenced by a forged edge header. **Verified** |
| A8 | **Resource exhaustion — role lookup amplification / YAML parse DoS** | No | One `TenantUserStore.Get` per login when wired + tenant-bound (in-process memory/sqlite); no new loops; `prefixOrExact` O(1); strict YAML adds no alias/parse amplification (goccy, same parser family as conditionalaccess). **Verified** |
| A9 | **Sensitive-data leakage — tenant/subject in tokens or responses** | No | `buildAccessPayload` enumerates claims; `ed25519Payload` has no `tenant_id`; `SessionTokenIssuer` reads only `subject.ID` (claim-surface pin). Denies stay generic `invalid_scope`/`invalid_grant` (`wireCodeForPolicyDeny`, `server_helpers.go:110-115`); tenant/subject never enter response bodies or error text. Admin read API is `admin:read`-gated and serializes no secrets. **Verified** |
| A10 | **Oracle — policy reason learned via timing/body differences** | No | Reason lands only in metric + server log; wire responses are byte-identical per deny class; tenant/subject are evaluation inputs only (Decision 6). **Verified** |
| A11 | **Widening — tenant rule raises a global ceiling** | No | Strictest-wins union verified in `Evaluate`: `clampTTL`/`stricterRenew` take minima; any deny denies. A tenant rule can only tighten; the reverse-combination test pins it. **Verified** |
| A12 | **Config bypass — strictness defeated through the inline path or a stray-key bundle** | No (design fixes it) | Today `cfg.Policies` inline skips `Validate` (`build_governance.go:197-223`); design 3c wires it — required, not optional. `other: 1` fixture flips to an error (design 3d) — intended strictness break; release note needed. Programmatic `memory.NewFromSlice` seeds remain unvalidated (documented residual, trusted operator code). **Verified** |
| A13 | **Outage widening — roster failure lifts guest caps** | Partial (bounded) | F3: fail-open by design with AGENTS.md precedent; needs an observable signal. **Verified** |
| A14 | **Session-cap false deny — role/client-scoped caps count cross-client sessions** | Partial | F6: pre-existing counting quirk; document, do not change here. **Verified** |

---

## 4. Positive controls verified

1. **Tenant rules tighten-only.** `Evaluate`'s per-dimension minima + first-deny
   guarantee a tenant rule can never widen a global ceiling; the reverse
   combination (tenant 10m + global 5m ⇒ 5m) is the right pin. **Verified**
   (`evaluate.go:20-32,81-118`).
2. **Claim surface sealed.** Explicit claim enumeration
   (`issue_payload.go:26-45`), no `tenant_id` on `ed25519Payload`, opaque
   session issuer reads only `subject.ID`; the claim-set test is well-chosen.
   **Verified**
3. **Tenant input is record-derived, not header-derived.** All seams read
   `client.TenantID`, consistent with the `tenantTokenStrategies` key-isolation
   precedent (`server_helpers.go:39-40`); mismatch gate precedes the seams.
   **Verified**
4. **Oracle safety preserved.** No new `Err*`, generic wire codes unchanged,
   reason confined to metric/audit, no tenant/subject in bodies. **Verified**
5. **Fail-open stance consistent with AGENTS.md §3** (store errors, roster
   errors, missed stamps all fail open with logging) — with the F3 caveat.
   **Verified**
6. **No new storage/endpoints/metrics labels**; one read-only `Get` at one
   seam; bounded-cardinality discipline kept (deny metrics remain
   reason-only). **Verified**
7. **Strictness surface is complete after 3c/3d**: File path (via
   `ParseYAML`), inline path (new `Validate` call), and the `other: 1`
   fixture flip. The conditionalaccess precedent is real
   (`conditionalaccess/yaml.go:33`). **Verified**
8. **Local-subject semantics are correct at every populated seam** (refresh
   `info.UserID`, session `userID`); pairwise projection never feeds a
   selector. **Verified**
9. **Cross-tenant exchange gate exists** (`token_exchange.go:405-474`);
   `tokExSubject` stamps the requesting client, consistent with the design.
   **Verified**
10. **File-budget awareness is accurate** (500/493/481 exact counts) with the
    F5 consistency caveat. **Verified**

## Residual risks (accepted or to be decided)

- F1's two unlisted mint sites (must be fixed, not accepted).
- F3's fail-open role window (accepted, needs observability).
- F2's inert-selector surfaces (must be documented + pinned; introspection
  seam needs an explicit decision).
- Legacy tenant-less clients dodge tenant rules in mixed deployments
  (config-reference documentation).
- Programmatic `memory.NewFromSlice` seeds bypass `Validate` (documented
  residual).
- Strict-parse boot failures for existing bundles with stray keys (intended;
  release note).

## Prioritized validation plan

1. **Before implementation**: stamp all 12 sites (+codegen template); update
   the design's site list; add the F1 silent-renewal and agent-delegation
   clamp tests.
2. **Same change**: document + pin every inert (seam × selector) combination
   (F2); name the introspection seam; fix the `server_oauth.go` math (F5).
3. **During implementation**: `Validate` coverage for `tenant_id` spellings
   (F4); role-fail-open observability (F3); the planned test matrix
   (selector matrix, strictest-wins both directions, strict-parse cases,
   claim-surface pin, per-seam tenant A denied / tenant B allowed).
4. **Gates**: `go build ./... && go vet ./...`;
   `go test -run 'TestMaintainability_|TestArchitecture_' .`;
   `go test ./domains/tokenpolicy/ ./interfaces/sso/ ./internal/handler/tokengrant/ ./config/ -race`;
   then `make ci` (nested modules, OpenAPI + config-reference checks — both
   docs must land in the same change per F2's remediation).
