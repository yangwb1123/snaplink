# Design: tenant-dimension and subject-aware token-policy selectors (direction 3)

Design counterpart to `docs/auto/domains-tokenpolicy-direction3-spec.md`. Covers the API
surface, storage model, failure modes, and breakage risks for the three improvements.
Every claim in the spec was re-verified against current code before writing this doc:

- `Policy` selector is `ClientID` (exact) + `Scopes` only (`domains/tokenpolicy/tokenpolicy.go:53-98`);
  `PolicyInput` has no `TenantID` and its `Subject` (lines 117-118, "may be empty for
  client_credentials") is populated by `EnforceRefreshDepthPolicy` (`interfaces/sso/server_helpers.go:
  131-149`) and `sessionPolicyCapExceeded` (`interfaces/sso/server_oauth.go:151-199`, called at
  `server_logout.go:357`) but never read by `matches()` (`evaluate.go:53-63`).
- `scopePresent` trailing-`*` prefix-wildcard precedent is in the same file
  (`evaluate.go:69-78`); `ParseYAML` is non-strict `yaml.Unmarshal` (`yaml.go:19-24`) while
  `conditionalaccess` already uses `yaml.DisallowUnknownField()` (`conditionalaccess/yaml.go:33`).
- All four seams have the tenant available but unpassed: `dispatchTokenGrant` holds `*Client`
  at `server_token.go:168` (file at exactly 500 lines); `token_refresh.go:116` holds `client`
  (the `RefreshGrantDeps.EnforceRefreshDepthPolicy` declaration is at `token_refresh.go:42`,
  compile-time guard at `interfaces/sso/accessors_handlers.go:363`); `createSession` ALREADY
  takes `tenantID` as a parameter (`server_logout.go:345`) and calls the session-cap seam with
  it in scope (line 357); `ClampingIssuer.Issue` reads only `subject.ClientID`
  (`clamp_issuer.go:44-52`).
- `core.Subject` has `ClientID` + `ServingRegion` but no `TenantID` (`shared/core/types_token.go:161-170`).
  The 10 mint-time call sites all stamp `ClientID` + `ServingRegion` in the same literal with
  `client` in scope: `token_authcode.go:118`, `token_client_credentials.go:40`,
  `token_refresh.go:247` (`refreshRotatedSubject`), `token_device.go:82`, `token_ciba.go:99`,
  `token_jwt_bearer.go:95`, `token_saml2_bearer.go:103`, `token_exchange_stages.go:390`
  (`tokExSubject(client, ...)`), `server_login.go:112`, `server_native_sso.go:190`.
- `TenantUserStore`/`TenantRole` closed set (member/admin/guest) live in
  `shared/core/tenant_user.go:9-26`; `interfaces/sso` already owns the store
  (`options_passwd.go:364`, `accessors.go:234`, Get precedent at `server_logout.go:322-330`),
  and `ensureJITMembership` runs BEFORE `createSession` on the login path
  (`server_finish_login.go:46` vs 149) so a JIT-provisioned role is visible to the seam.
- `HandleAdminPolicies` (`domains/tokenpolicy/admin.go`) serializes `Policy` verbatim, so new
  fields ride the existing admin read API automatically; `docs/openapi.yaml:6836` and
  `docs/config-reference.md:588` are the two contract docs to sync.
- Line budgets: `server_helpers.go` 493/500, `server_oauth.go` 481/500, `server_token.go`
  EXACTLY 500, `token_refresh.go` 430, `tokenpolicy.go` 160, `evaluate.go` 176, `yaml.go` 24,
  `types_token.go` 277, `clamp_issuer.go` 69.
- One spec-adjacent discovery: `TestParseYAML_Empty` (`yaml_test.go:59-72`) asserts that a
  document containing a stray top-level key (`other: 1`) parses as "no policies". Strict
  parsing flips this to an error — a deliberate, documented behavior change (see Decision 3).

Layer map:

```text
composition (cmd/sso-server, interfaces/sso)
  → domains (tokenpolicy)          # pure; tenant/subject are STRING selector inputs
  → shared (core)                  # core.Subject.TenantID mint-time field; TenantRole constants
  (domains/tenant, platform/audit: NOT imported by tokenpolicy — role resolution lives in
   interfaces/sso, which already owns tenantUserStore)
```

## Decision 1: Selector model — `TenantID`, `Subject`, `SubjectRoles` fields, additive matching

### API surface

`Policy` gains three selector fields in `domains/tokenpolicy/tokenpolicy.go` (pure increment;
the yaml/json tags shape both `ParseYAML` and the admin governance read API):

```go
// TenantID restricts the rule to one tenant. Empty = a GLOBAL default rule
// (applies to every tenant — the backward-compatible fleet-wide form).
TenantID string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
// Subject restricts the rule to one resource-owner subject. Trailing "*" is
// a prefix wildcard (same semantics as the scope selector). Empty = any subject.
Subject string `yaml:"subject,omitempty" json:"subject,omitempty"`
// SubjectRoles restricts the rule to subjects holding at least one of these
// tenant roles (closed set: member/admin/guest). Empty = any role. Roles are
// resolved by the CALLER seam (interfaces/sso) — the domain never does I/O.
SubjectRoles []string `yaml:"subject_roles,omitempty" json:"subject_roles,omitempty"`
```

`PolicyInput` gains two fields (zero value = "no tenant context" / "no roles known"):

```go
TenantID     string
SubjectRoles []string
```

### Matching semantics (the load-bearing part)

`matches()` stays conjunctive; each new selector is an additional AND:

| Selector | Non-match condition | Effect |
|---|---|---|
| `TenantID` | `p.TenantID != "" && p.TenantID != in.TenantID` | empty policy tenant = global rule; zero input tenant (single-tenant deployment) ⇒ tenant rules NEVER match |
| `Subject` | `p.Subject != "" && !prefixOrExact(in.Subject, p.Subject)` | trailing-`*` prefix wildcard, exact otherwise |
| `SubjectRoles` | `p.SubjectRoles != "" && no intersection with in.SubjectRoles` | empty input roles ⇒ no intersection ⇒ role selector does not match (fail-open) |

Combination semantics are UNCHANGED — `Evaluate` (`evaluate.go:20-32`) is untouched: a request
matches the union of its tenant's rules and all global rules; per dimension the strictest wins
(`clampTTL` / `stricterRenew` / first-deny-wins). Because tenant rules join the SAME
strictest-wins combination, a tenant rule can only tighten a global ceiling, never widen it —
the acceptance test pins the reverse combination (tenant 10m + global 5m ⇒ 5m).

Single-tenant byte-compatibility: when `PolicyInput.TenantID` is zero, every non-empty
`tenant_id` rule is a non-match and global rules behave exactly as today — the existing
`TestEvaluate_SelectorMatching` (evaluate_test.go:177) is the regression pin.

## Decision 2: `matches()` refactor — shared `prefixOrExact` helper

### API surface

One unexported helper in `domains/tokenpolicy/evaluate.go`, reused by the client and subject
selectors (the `scopePresent` slice form stays as-is — it already implements the same
semantics for scopes/combos):

```go
// prefixOrExact reports whether a == want, or a has want's non-empty prefix
// when want ends in "*" (the selector wildcard — same semantics as scopePresent).
func prefixOrExact(a, want string) bool {
    if strings.HasSuffix(want, "*") {
        return strings.HasPrefix(a, strings.TrimSuffix(want, "*"))
    }
    return a == want
}
```

`matches()` becomes: tenant check → client check (`prefixOrExact`) → subject check
(`prefixOrExact`) → role-intersection check → scope checks. Evaluation order is irrelevant to
the result (pure conjunction) but the tenant check goes first for readability.

Runtime semantics of a bare `"*"` selector: `HasPrefix(a, "")` is true — it matches everything,
exactly like `scopePresent` today. This is deliberate: `Validate` (Decision 3) is the single
gate that keeps a bare `*` OUT of every configuration surface; `matches()` keeps one uniform
prefix semantics across all three wildcard sites rather than special-casing.

Subject selector identity: policy subjects match the LOCAL subject ID as supplied at the
seams (`info.UserID` at refresh, `userID` at session cap) — NOT the pairwise-projected `sub`
that lands on the token. Policy evaluation happens pre-issuance on the local identity; an
operator writing `subject: alice` matches regardless of pairwise config. Documented in
`docs/config-reference.md` so the token `sub` is not mistaken for the selector key.

## Decision 3: Strict YAML parsing + shared `Validate([]Policy)` pure function

### API surface

**3a. `ParseYAML`** (`domains/tokenpolicy/yaml.go`) switches to
`yaml.UnmarshalWithOptions(data, &f, yaml.DisallowUnknownField())` (the
conditionalaccess/yaml.go:33 precedent), then calls `Validate` on the result. Unknown fields —
a misspelled `tennat_id: ta` — now fail at parse time instead of silently dropping the field
and demoting a "tenant rule" to a fleet-wide global rule.

**3b. New pure function** in a new `domains/tokenpolicy/validate.go` (7th non-test file in the
package, under the 10-file ceiling; `yaml.go` stays parse-only):

```go
// Validate rejects selector shapes that would silently change meaning:
// a bare "*" wildcard (the ONLY spelling of "any" is the empty field) and
// non-closed-set roles. Load-time fail-loud only; the evaluator is not called.
func Validate(policies []Policy) error
```

Rules (per policy):
- `client_id` / `subject`: if the value contains `*`, it must be exactly one TRAILING `*` with
  a non-empty prefix. Bare `*` and interior/multiple `*` (e.g. `pay*ments*`) are rejected —
  both are ambiguous spellings that would silently widen or never-match.
- `subject_roles`: every entry must be a member of the closed set. Validated against the
  `core.TenantRole` constants (`shared/core/tenant_user.go:9-26`) — `domains/tokenpolicy`
  already imports `shared/core` via `clamp_issuer.go`, so this is single-source-of-truth at
  compile time (a refinement of the spec's "string constants": the three literals are
  referenced, not duplicated).
- `scopes` / `block_scope_combos`: deliberately UNVALIDATED beyond existing semantics —
  today's bare-`*` match-all in `scopePresent` is existing shipped behavior for scope
  selectors and must not become a boot failure for existing bundles. Only the two new
  selector wildcards are gated.

**3c. Config path**: `BuildTokenPolicyStore` (`cmd/sso-server/serverbuildplatform/build_governance.go:
197-223`) calls `Validate` on the INLINE `TokenPolicyConfig.Policies` list too (the File path
already validates via `ParseYAML`). A typo in `token_policies.policies` fails boot, not at
first request — no "looks active but is actually global" intermediate state.

**3d. Behavior change**: a bundle with a stray top-level key (`other: 1`) now fails to parse.
This is the strictness point (it was previously tolerated as "no policies"); the
`TestParseYAML_Empty` fixture must drop that case and `TestParseYAML_Malformed` gains
unknown-field cases. Empty documents (`""`, `token_policies: []`) still parse to nil — the
"no policies" contract is preserved.

## Decision 4: Tenant threading + role resolution at the four seams

### API surface

The tenant is read from `client.TenantID` at every seam — the client's authoritative binding,
already validated against the middleware-resolved request tenant by the upstream
tenant-mismatch gate, and the same value `issuerForClient` uses for key isolation
(`server_helpers.go:39-40`). Never the raw header-derived tenant: policy input must not be
influenced by a header an untrusted edge could forge (trusted-proxy gating is the middleware's
job, and the mismatch gate runs before all four seams).

| Seam | Signature change | Call-site edit |
|---|---|---|
| scope-combo | `denyTokenScopeCombo(ctx HandlerContext, clientID, tenantID string, scopes []string)` + `TenantID` in its `PolicyInput` | `server_token.go:168`: `s.denyTokenScopeCombo(ctx, client.ID, client.TenantID, scopes)` — SAME LINE, file is at exactly 500 lines |
| refresh-depth | `EnforceRefreshDepthPolicy(ctx, clientID, subject, tenantID string, scopes []string, depth int)` — ripples to the `RefreshGrantDeps` interface (`token_refresh.go:42`) and the compile-time guard (`accessors_handlers.go:363`) | `token_refresh.go:116`: pass `client.TenantID` |
| session cap | `sessionPolicyCapExceeded(ctx, userID, clientID, tenantID string)` + `TenantID` + resolved `SubjectRoles` in its `PolicyInput` | `server_logout.go:357`: `tenantID` already a parameter of `createSession` (line 345) — pass it through |
| TTL clamp | none (signature untouched) — `ClampingIssuer.Issue` adds `TenantID: subject.TenantID` to its `PolicyInput` | `clamp_issuer.go:44-52` reads the mint-time stamp |

### Role resolution (session seam only, fail-open)

`sessionPolicyCapExceeded` resolves roles inline after loading policies, before `Evaluate`:

```go
if tenantID != "" && s.tenantUserStore != nil {
    if m, err := s.tenantUserStore.Get(rctx, tenantID, userID); err == nil && m != nil {
        in.SubjectRoles = []string{string(m.Role)}
    } else if err != nil {
        s.logger.Error("token policy: role resolution failed — role selectors inert (fail-open)",
            "tenant", tenantID, "user", userID, "error", err)
    }
}
```

- One `Get` per login when the store is wired and the client is tenant-bound — a single
  point read against the same in-process/local store residency gates use; a policy-set scan
  to skip it when no role rules exist is rejected as premature optimization.
- `ErrNoMembership` / nil membership ⇒ roles stay empty ⇒ role selectors don't match
  (fail-open); subject exact/wildcard rules are unaffected by the role lookup entirely.
- `ensureJITMembership` runs before `createSession` (`server_finish_login.go:46` vs 149), so
  a JIT-provisioned member's role is visible to the seam on the very first login.

### Refresh seam role limitation (documented, not fixed here)

The `tokengrant` package has no store access and `RefreshGrantDeps` gains NO role resolver in
this change: a rule combining `subject_roles` with `max_refresh_depth` is a guaranteed no-op
at the refresh seam (roles empty ⇒ no match). `subject` + `tenant_id` selectors work fully at
refresh. This is the spec's accepted fail-open shape; `Validate` deliberately does NOT reject
the combination (a policy may legitimately pair roles with `max_active_sessions`, which the
session seam enforces). Documented in `docs/config-reference.md` as a known limitation.

## Decision 5: `core.Subject.TenantID` — mint-time stamp, NOT a JWT claim

### API surface

`core.Subject` gains one field in `shared/core/types_token.go` (277 lines, headroom):

```go
// TenantID is the OAuth client's tenant binding at mint time, read from the
// client being served. Policy-input ONLY: the ClampingIssuer reads it to
// scope max_ttl rules. It is NOT a token claim — issuers emit only the
// fields they enumerate in buildAccessPayload. Empty = no tenant affinity
// (single-tenant deployments stay byte-identical).
TenantID string
```

Stamped at the same 10 issue sites that already stamp `ClientID` + `ServingRegion` in the
same literal (all verified to have `client` in scope):
`token_authcode.go:118`, `token_client_credentials.go:40`, `token_refresh.go:247`,
`token_device.go:82`, `token_ciba.go:99`, `token_jwt_bearer.go:95`, `token_saml2_bearer.go:103`,
`token_exchange_stages.go:390`, `server_login.go:112`, `server_native_sso.go:190` — each adds
one line `TenantID: client.TenantID,`.

### The claim surface is the critical boundary

`buildAccessPayload` (`infrastructure/defaultimpl/issue_payload.go`) assembles claims by
EXPLICIT enumeration — adding `Subject.TenantID` does not automatically leak a claim. The
design therefore REQUIRES: no `tenant_id` field on `ed25519Payload`/`TokenClaims`, no stamp in
`buildAccessPayload`/`applyOptionalClaims`. Tenant identity is governance input, not a token
assertion; emitting it would be a wire-visible change and a cross-tenant metadata surface.
A claim-set test pins this (see Test plan).

An issue site that misses the stamp is safe-by-construction: `subject.TenantID == ""` ⇒
tenant rules don't match at the clamp ⇒ TTL unclamped (fail-open, byte-identical to today).

## Decision 6: Admin read API and contract docs — zero new endpoints

- `HandleAdminPolicies` (`domains/tokenpolicy/admin.go`) serializes `Policy` verbatim, so
  `GET /api/v1/admin/token-policies` carries `tenant_id` / `subject` / `subject_roles`
  automatically (omitempty keeps global rules byte-identical). No endpoint, route, or
  permission change; `admin:read` gating untouched.
- `docs/openapi.yaml:6836`: the policies item schema gains the three optional fields and the
  description mentions tenant/global combination + wildcard semantics (the `make ci` OpenAPI
  check requires it in the same change).
- `docs/config-reference.md:588`: the selector row gains the three selectors, the trailing-`*`
  wildcard rule, empty-tenant = global semantics, local-subject-ID semantics, the role
  closed-set, and the refresh-seam role limitation.
- No new `Err*` ⇒ `docs/error-codes.md` unchanged. No new metrics/events ⇒
  `docs/observability.md` unchanged (deny metrics stay reason-only — a tenant label would be
  unbounded cardinality; direction 2 handles the audit side separately).
- Wire contract unchanged: denies still surface `wireCodeForPolicyDeny` output
  (`server_helpers.go:110-115`) — generic `invalid_scope`/`invalid_grant`. Tenant and subject
  are evaluation inputs only.

## Storage model

No new storage, no schema change, no migration, no new interface.

- `tokenpolicy.Store` (`Policies(ctx)`) is untouched; the memory COW `Store`
  (`memory/store.go`, `Replace` swaps slices) remains the only policy source. The new
  selector fields ride the existing `[]Policy` value shape — the config surface is YAML /
  inline config, not a database.
- New READ dependency at ONE seam: `TenantUserStore.Get` (existing interface, memory/sqlite
  implementations already shipped, `interfaces/sso` already owns the instance). One keyed
  point lookup per login when wired + tenant-bound; no write, no new table, no caching.
- `core.Subject.TenantID` is request-scoped mint-time context: not persisted in any store,
  not a claim, discarded with the request.
- Cross-replica: policies are per-replica config (unchanged from today); tenant rules ride
  the same config surface. No invalidation-bus or replication interaction.

## Failure modes

| Failure | Behavior | Why it is safe |
|---|---|---|
| `tenantUserStore` nil (not wired) | session seam skips role lookup; role selectors inert | single-tenant/legacy build byte-identical; fail-open (AGENTS.md §3) |
| `TenantUserStore.Get` error | logged; roles empty; role selectors don't match; session still created | a roster outage must never block login; subject/tenant selectors unaffected |
| `ErrNoMembership` / nil membership | roles empty; role selectors don't match | non-member = no org role, honest absence |
| Policy-store `Policies()` error (any seam) | existing fail-open (issue / allow) | unchanged governance stance |
| `ListByUser` error (session seam) | existing fail-open (allow session) | unchanged |
| No policy store wired | all four seams no-op; byte-identical issuance | default-off invariant |
| Single-tenant input (`TenantID == ""`) | non-empty tenant rules never match; global rules exact old behavior | the byte-compat contract |
| Old/third-party issue site misses `Subject.TenantID` stamp | tenant clamp rules inert at that site; TTL unclamped | fail-open; matches pre-feature bytes |
| Role rules evaluated at the refresh seam | no match (roles empty) — documented no-op | fail-open, spec-accepted |
| Misspelled selector field (`tennat_id`) | parse/config-load error, boot fails | fail loud — the core hazard of Improvement 3 |
| Bare `*` / interior `*` / invalid role in config | `Validate` error, boot fails | fail loud; no silent match-all/widening |
| Unknown top-level YAML key in a bundle | parse error (NEW — previously tolerated) | strictness point, matches conditionalaccess |
| Programmatic `memory.New(...)` seed with a bare `*` | NOT validated (store-level); `matches()` treats it as match-all (same as `scopePresent`) | documented residual: `Validate` is the config gate; programmatic seeds are trusted operator code |
| Canceled context between role lookup and evaluate | request is failing anyway; policy contributes no new behavior | no new failure class |

## What could break the design

1. **`server_token.go` is at EXACTLY 500 lines — the tightest gate in this change.** The
   scope-combo call-site edit must be an argument added on the existing line
   (`s.denyTokenScopeCombo(ctx, client.ID, client.TenantID, scopes)`); ANY added line fails
   the file budget. Same discipline for `server_helpers.go` (493→495: exactly the two
   `PolicyInput` lines, nothing else) and `server_oauth.go` (481→~489: tenant param + inline
   role block, no extracted helper, no logging additions). Review feedback that adds lines to
   these three files breaks the gate — the response is to split the file, not to add a line.
2. **Tenant leaking into the token claim surface.** `buildAccessPayload` enumerates claims
   explicitly today, but a future edit adding `tenant_id` to `ed25519Payload`/`TokenClaims`
   would be a wire-visible change and a cross-tenant metadata carrier. The claim-set test
   (access token with a tenant-bound subject contains no `tenant_id` claim) is the pin; the
   `core.Subject.TenantID` doc comment states the non-claim contract.
3. **Tenancy input drift.** A seam passing the middleware-resolved request tenant instead of
   `client.TenantID` would diverge from the key-isolation precedent and could be influenced
   by forwarded headers at an untrusted edge. A seam FORGETTING the tenant is the silent
   direction: tenant rules quietly stop matching (fail-open but policy-silent — an operator's
   "tenant A TTL ≤ 5m" stops applying with no error). The seam-level tests pin both
   directions: tenant A denied / tenant B allowed under the same rule, per seam.
4. **Strictness regression surface.** (a) `TestParseYAML_Empty` currently asserts a stray
   `other: 1` key parses as empty — that fixture MUST change or CI fails on the new strict
   parse; (b) the inline `TokenPolicyConfig.Policies` path must call `Validate` in
   `BuildTokenPolicyStore` or the strictness is bypassable through config; (c) existing
   deployed bundles with unknown fields now fail boot — intended (fail loud), but a
   release-note item.
5. **Role-set drift.** If `core.TenantRole` ever gains a fourth value, `Validate` must track
   it. Mitigated by validating against the `core.TenantRole` constants (compile-time
   reference, no duplicated literals); a duplicated string set would silently diverge.
6. **Bare-`*` semantics asymmetry.** `Validate` rejects bare `*` for `client_id`/`subject`
   but `scopePresent` still treats a bare `*` scope as match-all (existing behavior,
   preserved for compat). The two surfaces now have different strictness — intentional, but
   a future "unify the wildcard" cleanup could either break existing scope bundles or
   silently re-open the widening hazard. Keep `Validate` and `scopePresent` decoupled.
7. **Role-selector no-op at refresh is invisible.** A rule pairing `subject_roles` with
   `max_refresh_depth` loads fine and never fires at refresh; an operator could believe it is
   enforced. Mitigation is documentation (config-reference) plus the acceptance test that
   pins "roles empty ⇒ role selector doesn't match" so the semantics are at least pinned, not
   accidental. A future `RoleResolver` accessor on `RefreshGrantDeps` is the extension point.
8. **`Evaluate` combination semantics must not be touched.** The whole "tenant rules only
   tighten" argument rests on `Evaluate` staying as-is. A future "improvement" that makes a
   tenant rule REPLACE global rules per dimension would widen ceilings — the strictest-wins
   union is the invariant; the acceptance test pins the reverse combination (tenant 10m +
   global 5m ⇒ 5m).
9. **Docs gate.** `make ci` checks `docs/openapi.yaml` and `docs/config-reference.md`; both
   must be updated in the same change. Missing either fails CI, but a wrong description
   (e.g. claiming tenant rules can widen) passes CI while misdocumenting the invariant.
10. **Determinism regression.** The new conjuncts only filter; first-deny-wins order and
    dimension order are untouched. A refactor that reorders `denyReason` checks or makes
    `matches()` order-dependent would resurface as a flaky reason — the existing
    `TestEvaluate_DenyReasonDeterministic` guards it.

## Test plan (maps to the spec's acceptance checks)

- `domains/tokenpolicy/evaluate_test.go` (table-driven, `TestEvaluate_SelectorMatching`
  regression retained): (a) tenant match/non-match/global matrix; (b) strictest-wins both
  directions incl. the reverse combination proving no widening; (c) `ClientID:"payments-*"`
  prefix matching + exact regression; (d) `Subject:"svc-*"` match/non-match;
  (e) `SubjectRoles` intersection + empty-input-roles no-match; (f) all-empty selectors
  byte-identical to old behavior; (g) `prefixOrExact` unit cases incl. bare `*` (match-all)
  and exact.
- `domains/tokenpolicy/validate_test.go` (new): misspelled field ⇒ error; bare `*` /
  interior `*` / empty-prefix wildcard ⇒ error; non-closed-set and empty-string roles ⇒
  error; full legal document (all three new fields) passes and lands correctly; valid
  global rule with all new fields empty passes (compat).
- `domains/tokenpolicy/yaml_test.go`: `TestParseYAML_Empty` drops the `other: 1` case (now an
  error); `TestParseYAML_Malformed` gains unknown-field cases; `TestParseYAML_FullDocument`
  gains a tenant/subject/roles rule.
- `domains/tokenpolicy/clamp_issuer_test.go`: `subject.TenantID` stamped ⇒ tenant MaxTTL
  clamps only that tenant's client; unstamped subject (old call sites) ⇒ no clamp, byte-old
  behavior.
- `interfaces/sso` seam tests (memory stores): tenant A client denied scope-combo (generic
  `invalid_scope`), tenant B client allowed under the same rule; refresh-depth tenant rule
  fires with `client.TenantID` threaded (generic `invalid_grant`); session cap: admin role
  user of tenant ta over cap denied, member unaffected; `tenantUserStore` nil ⇒ role rules
  inert, session created (fail-open); `Get` error ⇒ same.
- Claim-surface pin (defaultimpl): an access token minted for a tenant-bound client carries
  NO `tenant_id` claim.
- Gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `go test ./domains/tokenpolicy/ ./interfaces/sso/ ./internal/handler/tokengrant/ ./config/ -race`,
  then `make ci` (nested modules, OpenAPI + docs checks).

## Contract and documentation updates (AGENTS.md §5)

| Change | Location |
|---|---|
| `Policy.TenantID` / `Subject` / `SubjectRoles`; `PolicyInput.TenantID` / `SubjectRoles` | `domains/tokenpolicy/tokenpolicy.go` |
| Selector matching + `prefixOrExact` | `domains/tokenpolicy/evaluate.go` |
| Strict parse + `Validate` | `domains/tokenpolicy/yaml.go`, new `domains/tokenpolicy/validate.go` |
| Inline-config validation | `cmd/sso-server/serverbuildplatform/build_governance.go` (`BuildTokenPolicyStore`) |
| `core.Subject.TenantID` mint-time stamp | `shared/core/types_token.go` + the 10 verified issue call sites |
| Tenant threading (scope-combo / refresh / session / clamp) | `interfaces/sso/server_token.go`, `server_helpers.go`, `server_oauth.go`, `server_logout.go`, `internal/handler/tokengrant/token_refresh.go` (interface + call site), `domains/tokenpolicy/clamp_issuer.go` |
| Role resolution (session seam, fail-open) | `interfaces/sso/server_oauth.go` via `s.tenantUserStore` |
| Admin read API schema | `docs/openapi.yaml:6836` (three optional selector fields + description) |
| Config rule schema | `docs/config-reference.md:588` (selectors, wildcard, local-subject, role closed set, refresh-seam limitation) |

Wire contract unchanged: denies stay generic `invalid_scope` / `invalid_grant` via
`wireCodeForPolicyDeny`; tenant/subject never enter a response body; no new error codes; no
new token claims; no new metrics/events.

No `.go` files were changed for this design; no build gates were run.
