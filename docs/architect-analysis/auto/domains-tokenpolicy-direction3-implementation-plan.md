# Implementation plan: tenant-dimension + subject-aware token-policy selectors (direction 3)

Budget-safe implementation plan for `domains-tokenpolicy-direction3-design.md`, incorporating
the security review (F1–F5), SRE review (F1–F8), and QA review (H1/H2, M1–M5, L1/L2). Every
line number and budget figure below was re-derived from the tree at HEAD `ff690260` by source
read; the two disputed arithmetic items (security F5, SRE F7) were resolved by simulating the
exact planned edits and counting the results. No `.go` file was changed to produce this plan.

## 0. Verification basis (all re-checked, all hold)

- `interfaces/sso/server_token.go` — **exactly 500 lines**; scope-combo deny at
  `dispatchTokenGrant` line 168 (`s.denyTokenScopeCombo(ctx, client.ID, scopes)`); the gate
  (`maintainability_budget_test.go:34`, `maxFileLines = 500`) fails only at `> 500`, so
  500 is legal but the edit MUST be same-line. **Verified**
- `interfaces/sso/server_helpers.go` — 493 lines; `denyTokenScopeCombo` (108–114) and
  `EnforceRefreshDepthPolicy` (139–147) are the two seam functions. **Verified**
- `interfaces/sso/server_oauth.go` — 481 lines; `sessionPolicyCapExceeded` (162–192),
  called from `createSession` (`server_logout.go:357`), which already takes `tenantID`
  (param at `server_logout.go:345`). Federated callback `server_oauth.go:223` passes
  empty clientID AND tenantID (SRE F6 / QA M1). **Verified**
- `internal/handler/tokengrant/token_refresh.go` — 430 lines; `RefreshGrantDeps`
  interface at :42, call site at :116 (`client` in scope), `refreshRotatedSubject`
  mint at :247 (client param). **Verified**
- Mint census — `core.Subject{` / `Subject{` in non-test code: **13 issue sites** +
  1 codegen template (see §3). The design's "10" omits `handle_silent_renewal.go:210`,
  `agentidentity/grant.go:185`, and `accessors_feature_gates.go:257`; the security
  review's "12" and the QA review's "12" each omit one of the three. **Verified**
- `config/source.go:260-281` — `decodeStrictWithFallback`: strict pass warns and
  re-decodes the WHOLE config leniently; lenient decode silently drops unknown fields
  (empirically confirmed: `tennat_id` under a policy item decodes to `TenantID: ""`).
  This runs BEFORE `BuildTokenPolicyStore`, so semantic-only `Validate` on the inline
  path cannot catch the typo (SRE F2). **Verified + probed**
- goccy `DisallowUnknownField` is RECURSIVE (probed): it catches unknown fields inside
  nested items (`token_policies[].tennat_id`) on both the bundle and the config-shaped
  document. **Verified + probed**
- A type-alias `UnmarshalYAML` on the item type survives BOTH outer decode modes:
  under lenient `yaml.Unmarshal` a misspelled item field still errors (probed), which
  is the mechanism that closes SRE F2 (see §4.2). **Verified + probed**
- `TestParseYAML_Empty` (`yaml_test.go:59-72`) asserts `other: 1` parses as zero
  policies; strict parse flips it to an error (probed: `""` and `token_policies: []`
  still parse clean). **Verified + probed**
- `WithTenantUserStore` appears nowhere in `cmd/` (SRE F1) — stock binary never wires
  the roster store; `TenantUserStore` is an alias of `core.TenantUserStore`
  (`aliases.go:125`), `s.tenantUserStore` exists on `Server`, `Get(ctx, tenantID,
  userID)` precedent at `server_logout.go:322-330`. **Verified**
- `platform/metrics/metrics_token.go` — 155 lines; three token-policy metrics, all
  decision/reason-only, registered only when a store is wired. **Verified**
- `make ci` has no docs gate (SRE F5): `checks/route_contract.py` validates routes +
  operationIds only. **Verified**
- Evaluate call sites: 4 direct (`enforceTokenPolicy` `server_helpers.go:94`, session
  seam `server_oauth.go:177`, `IntrospectionRenewExceeded` `sso_protocol.go:486`,
  `ClampingIssuer.Issue` `clamp_issuer.go:44`) — the introspection site is the
  unnamed fifth seam (security F2). **Verified**

## 1. Corrected budget arithmetic (the four gate-critical files)

The design's risk table and the two reviews disagree on three numbers. The plan below is
the resolved, edit-by-edit arithmetic — every figure reproduced by applying the exact
edits to copies and counting.

### 1.1 `server_token.go` — 500 → 500 (the tightest gate)

The ONLY edit to this file is the call-site argument on the existing line 168 (§2).
Zero added lines. The function edit itself (`denyTokenScopeCombo` signature + literal)
lives in `server_helpers.go`, not here.

### 1.2 `server_helpers.go` — 493 → 495 (SRE F7 rebutted)

SRE F7 claims 493 + 4 = 497 because "both seam functions change signature (+1 line
each)". That is a miscount: **the two signatures fit on one line and gofmt does not
wrap**, so the parameter addition is a same-line edit, not a new line:

- `func (s *Server) denyTokenScopeCombo(ctx HandlerContext, clientID string, scopes []string) bool {`
  → `func (s *Server) denyTokenScopeCombo(ctx HandlerContext, clientID, tenantID string, scopes []string) bool {`
  (103 chars, one line — +0)
- `func (s *Server) EnforceRefreshDepthPolicy(ctx HandlerContext, clientID, subject string, scopes []string, depth int) bool {`
  → `func (s *Server) EnforceRefreshDepthPolicy(ctx HandlerContext, clientID, subject, tenantID string, scopes []string, depth int) bool {`
  (129 chars, one line — +0)

The only added lines are the two `TenantID: tenantID,` literal entries (one per
function). Final: **495/500, 5 lines headroom**. The design's original 493→495 figure
was correct; F7's correction is not. Implementation discipline: do NOT wrap either
signature and do NOT add comments inside these two functions.

### 1.3 `server_oauth.go` — 481 → 495 (security F5 confirmed, exact count)

Security F5's "closer to ~491" identified the right error class (the design's
"481→~489" missed lines) but the final count is **+14 → 495**: F5 counted only the
`logger.Error` lines; the seam also needs the Evaluate hoist line, the
`ObserveTokenPolicyRoleResolutionError` call (security F3 / SRE F4), and the
constraint comment (AGENTS.md §6: hidden-constraint comments). Exact breakdown of
the session-seam edit (§6):

| Edit | Lines |
|---|---|
| Signature: `(ctx HandlerContext, userID, clientID string)` → `(ctx HandlerContext, userID, clientID, tenantID string)` | +0 (same line) |
| Hoist `dec := tokenpolicy.Evaluate(tokenpolicy.PolicyInput{` → `in := tokenpolicy.PolicyInput{` | +0 |
| New `TenantID: tenantID,` literal entry | +1 |
| Close `}, policies)` → `}` | +0 |
| New `dec := tokenpolicy.Evaluate(in, policies)` after the role block | +1 |
| Role-resolution block (guard + `Get` + assign + else-if + two `logger.Error` lines + metric call) | +9 |
| Constraint comment (fail-open stance, JIT ordering) replacing the removed 2-line comment | +3 (5 − 2) |
| **Total** | **+14 → 495** |

Final: **495/500, 5 lines headroom**. The design's "no logging additions" is
contradicted by its own snippet (F5); the plan keeps the two log lines + the metric
call and counts them. Discipline: no extracted helper, no further comment or
logging additions in this file.

### 1.4 Other budget-adjacent files (see the full table in §10)

- `interfaces/sso/server_login.go` — **499 → 500** (the stamp at :112 is the LAST
  edit that file may ever receive; zero headroom after it).
- `internal/handler/tokengrant/token_exchange_stages.go` — 495 → 496.
- `interfaces/sso/accessors_feature_gates.go` — 498 → 499 (break-glass comment).
- `domains/tokenpolicy/evaluate.go` — 176 → 201; `tokenpolicy.go` — 160 → 182;
  `yaml.go` — 24 → 38; `clamp_issuer.go` — 69 → 70; `types_token.go` — 277 → 282.

## 2. The scope-combo call-site edit (exact)

`interfaces/sso/server_token.go:168`, one line, +0:

```go
// before
	if s.denyTokenScopeCombo(ctx, client.ID, scopes) {
// after
	if s.denyTokenScopeCombo(ctx, client.ID, client.TenantID, scopes) {
```

`client` is `*Client` in scope (from `authenticateTokenClient`); `client.TenantID` is
the record-derived binding — never the header-derived tenant (design Decision 4;
consistent with `issuerForClient`'s `tenantTokenStrategies` key isolation). The
function it calls is edited in `server_helpers.go` (§1.2): signature gains
`tenantID string`, its `PolicyInput` gains `TenantID: tenantID`. Subject/roles remain
unpopulated at this seam (dispatch precedes subject resolution) — documented in the
liveness matrix (§9).

## 3. The mint-time stamp census — 13 sites + 1 template

`core.Subject` gains `TenantID` in `shared/core/types_token.go` (277 → 282:
4 comment lines + 1 field; the doc comment states the non-claim contract). The
stamp `TenantID: client.TenantID,` is added to the `Subject` literal at **every**
site with `client` in scope — 12 sites — plus one documented non-stamp and one
template:

| # | Site | Client in scope | Edit | File budget |
|---|---|---|---|---|
| 1 | `internal/handler/tokengrant/token_authcode.go:118` | yes | +1 line | 287 → 288 |
| 2 | `internal/handler/tokengrant/token_client_credentials.go:40` | yes | +1 | 68 → 69 |
| 3 | `internal/handler/tokengrant/token_refresh.go:247` (`refreshRotatedSubject`) | yes (param) | +1 | 430 → 431 |
| 4 | `internal/handler/tokengrant/token_device.go:82` | yes | +1 | 206 → 207 |
| 5 | `internal/handler/tokengrant/token_ciba.go:99` | yes | +1 | 289 → 290 |
| 6 | `internal/handler/tokengrant/token_jwt_bearer.go:95` | yes | +1 | 116 → 117 |
| 7 | `internal/handler/tokengrant/token_saml2_bearer.go:103` | yes | +1 | 124 → 125 |
| 8 | `internal/handler/tokengrant/token_exchange_stages.go:390` (`tokExSubject`) | yes (param) | +1 | 495 → 496 |
| 9 | `interfaces/sso/server_login.go:112` | yes | +1 | **499 → 500** (gate edge) |
| 10 | `interfaces/sso/server_native_sso.go:190` | yes | +1 | 341 → 342 |
| 11 | `protocols/oidc/handle_silent_renewal.go:210` (security F1) | yes (`IssuerForClient(client)` at :196) | +1 | 410 → 411 |
| 12 | `domains/tokenexchange/agentidentity/grant.go:185` (security F1 / QA H1) | yes (`d.IssuerForClient(client)`) | +1 | 228 → 229 |
| 13 | `interfaces/sso/accessors_feature_gates.go:257` (break-glass, QA H1) | **no** — `issuerForClient(nil)` | **non-stamp**: +1 comment line noting the deliberate empty tenant (break-glass has no tenant binding) | 498 → 499 |
| T | `cmd/sso-ctl/generate/templates_handler.go:193` (doc-comment template) | n/a | +1 line `TenantID: client.TenantID,` in the example literal | 214 → 215 |

Per-site decisions (QA M3): every site above is an explicit decision — 12 stamps, one
deliberate non-stamp (break-glass: `subject.TenantID == ""` is correct, tenant rules
cannot scope a tenant-less break-glass token; a per-site test pins the non-stamp as
"no clamp", not "forgotten stamp"). Sites 11–13 do NOT stamp `ServingRegion` today
(the design's "all stamp ClientID + ServingRegion" claim holds only for its own 10);
adding region stamps is out of scope, but the silent-renewal / agent-delegation clamp
tests must not assume region behavior.

A missed stamp is safe-by-construction (`TenantID == ""` ⇒ tenant rules don't match
at the clamp ⇒ unclamped, fail-open), which is why the two omitted sites were
invisible to the design; the clamp tests per site (QA M3) pin the 12 stamps and the
break-glass non-stamp.

## 4. `validate.go` placement + File/inline strictness wiring

### 4.1 The `decodeStrictWithFallback` ordering problem (SRE F2)

Inline `token_policies.policies` items are decoded as part of the WHOLE config by
`decodeStrictWithFallback` (config/source.go:260-281): the strict pass rejects any
unknown key config-wide, warns, and re-decodes leniently. The lenient pass **silently
drops** a misspelled field (`tennat_id` → `TenantID: ""`) BEFORE `BuildTokenPolicyStore`
runs, so `Validate` on the decoded slice cannot see the typo: the "tenant rule demotes
to global" hazard survives inline. Semantic-only validation (design 3c) is necessary
but not sufficient. The fix must live at DECODE time, not after.

### 4.2 `Policy.UnmarshalYAML` — item-level strictness (the fix)

Add a strict item unmarshaler in `domains/tokenpolicy/yaml.go` (keeps "yaml.go is the
parse file" discipline; 24 → 38 lines):

```go
// UnmarshalYAML strict-decodes ONE policy item with DisallowUnknownField so a
// misspelled selector (e.g. tennat_id) fails load on every YAML surface —
// including the inline token_policies.policies path, where
// decodeStrictWithFallback's whole-config lenient re-decode would otherwise
// drop the field before Validate can see it. The type alias strips the
// method so the inner decode is plain field-by-field (no recursion).
func (p *Policy) UnmarshalYAML(b []byte) error {
	type plain Policy
	var raw plain
	if err := yaml.UnmarshalWithOptions(b, &raw, yaml.DisallowUnknownField()); err != nil {
		return err
	}
	*p = Policy(raw)
	return nil
}
```

Ordering properties (empirically probed with goccy v1.19.2):

- The method runs in BOTH passes of `decodeStrictWithFallback`. A policy-item typo
  errors the strict pass, then errors the lenient fallback re-decode, so `Loader.Load`
  (config/source.go:138) returns an error and **boot fails loud**.
- Unrelated unknown keys ELSEWHERE in the config keep today's warn-and-fallback
  behavior (the whole-config tolerance is unchanged) — the strictness is scoped to
  policy items, exactly the surface the design needs.
- The bundle path is unaffected in behavior: `ParseYAML` already strict-decodes, the
  method just makes item-level strictness explicit there too.
- `Policy` is never YAML-marshaled (the config merge round-trips `map[string]any`,
  not the typed struct) and its JSON admin serialization is `encoding/json` — no
  MarshalYAML/JSON interplay.

### 4.3 `ParseYAML` (File path) — `domains/tokenpolicy/yaml.go`

```go
func ParseYAML(data []byte) ([]Policy, error) {
	var f policyFile
	if err := yaml.UnmarshalWithOptions(data, &f, yaml.DisallowUnknownField()); err != nil {
		return nil, err
	}
	if err := Validate(f.TokenPolicies); err != nil {
		return nil, err
	}
	return f.TokenPolicies, nil
}
```

Stray top-level keys (`other: 1`) now error (design 3d); `""` and `token_policies: []`
still parse to nil (probed). `Validate` runs here for the File path.

### 4.4 `BuildTokenPolicyStore` (inline path) — `cmd/sso-server/serverbuildplatform/build_governance.go:197-223`

Two additions (430 → ~437):

1. **Semantic validation** (design 3c): after the File/dual-source resolution, before
   `tokenpolicymemory.NewFromSlice`:
   ```go
   if err := tokenpolicy.Validate(policies); err != nil {
       return nil, fmt.Errorf("token_policies: %w", err)
   }
   ```
   (The decode-layer strictness of §4.2 handles misspelled fields; `Validate` handles
   bare/interior `*`, whitespace `tenant_id`, and non-closed-set roles.)
2. **SRE F1 boot warning**: a `hasRoleSelectors(policies)` scan (10-line unexported
   helper) plus a `slog.Warn` when any policy carries `subject_roles`, stating that
   role selectors require the tenant-user store (`WithTenantUserStore` / sqlite
   `tenant_user_store`) to be wired — the stock binary never wires it, so without the
   warning role rules are a silent no-op at the session seam. Warning only: the policy
   set still loads (fail-open is the AGENTS.md §3 stance); `docs/config-reference.md`
   states the wiring requirement. Adding a config key + builder to wire the sqlite
   store in stock is explicitly OUT of scope (design's "zero new storage" boundary);
   the warning + docs are the decided resolution. (Net: 430 → 447 with the `slog`
   import.)

### 4.5 New file: `domains/tokenpolicy/validate.go`

Placement: root of the package (6th non-test file; 7 counting `memory/store.go` —
under the 10-file ceiling, `maxGoFilesPerDir = 10`; the QA "7th file" label is a
miscount, the ceiling is unaffected). ~65 lines, one exported function + two
unexported helpers, all well under the 50-line function budget:

- `Validate(policies []Policy) error` — per policy: `client_id` / `subject` wildcard
  spelling via `validateWildcard` (exactly one `*`, trailing, non-empty prefix; bare
  `*` and interior `*` rejected); `tenant_id` rejected if it contains `*` or
  whitespace or differs from its trimmed self (security F4: `tenant_id: "*"` and
  `" ta "` become boot errors); `subject_roles` entries non-empty and in the closed
  set via `isTenantRole` (switch over `core.TenantRoleMember/Admin/Guest` — compile-
  time reference, no literal duplication, drift-proof against a fourth role).
- Deliberately NOT gated (documented in the doc comment): `scopes` /
  `block_scope_combos` bare-`*` (existing shipped scope semantics, compat); the
  roles × `max_refresh_depth` no-op combination (roles legitimately pair with
  `max_active_sessions`).

## 5. `TestParseYAML_Empty` fixture change (exact)

`domains/tokenpolicy/yaml_test.go:59-72` — drop the `other: 1` case (now an error) and
move it to `TestParseYAML_Malformed`, which gains the unknown-field cases:

```go
func TestParseYAML_Empty(t *testing.T) {
	t.Parallel()
	// NOTE: a stray top-level key (e.g. `other: 1`) is now a strict-parse
	// ERROR, not "no policies" — see TestParseYAML_Malformed (3d flip).
	for _, doc := range [][]byte{[]byte(""), []byte("token_policies: []\n")} {
		policies, err := ParseYAML(doc)
		if err != nil {
			t.Fatalf("ParseYAML(%q): %v", doc, err)
		}
		if len(policies) != 0 {
			t.Fatalf("ParseYAML(%q) = %d policies, want 0", doc, len(policies))
		}
	}
}

func TestParseYAML_Malformed(t *testing.T) {
	t.Parallel()
	for _, doc := range [][]byte{
		[]byte("token_policies: [:::not yaml"),
		[]byte("other: 1\n"),                                        // stray top-level key (was tolerated)
		[]byte("token_policies:\n  - name: x\n    tennat_id: ta\n"), // misspelled selector
	} {
		if _, err := ParseYAML(doc); err == nil {
			t.Fatalf("ParseYAML(%q) = nil error, want a decode error", doc)
		}
	}
}
```

`TestParseYAML_FullDocument` gains one rule exercising `tenant_id` / `subject` /
`subject_roles` (design test plan). The `""` and `[]` cases are pinned to still parse
clean (probed).

## 6. Session seam — `sessionPolicyCapExceeded` (exact final text)

`interfaces/sso/server_oauth.go:162-192` → the function below. 31 → 45 lines (+14,
see §1.3); complexity +2 branches (≤ 15); `if`-nesting max 3 (function → tenant
guard → Get branch); no helper extraction, no further logging. The role block uses the
`Get(ctx, tenantID, userID)` signature verified at `server_logout.go:322-330`; the
fail-open stance and the `errMaxActiveSessions` sentinel contract are unchanged.

```go
func (s *Server) sessionPolicyCapExceeded(ctx HandlerContext, userID, clientID, tenantID string) bool {
	if s.tokenPolicyStore == nil || s.sessionMgr == nil {
		return false
	}
	policies, err := s.tokenPolicyStore.Policies(ctx.Request().Context())
	if err != nil {
		s.logger.Error("token policy load failed — allowing session (fail-open)", "error", err)
		return false
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("session cap: list by user failed — allowing session (fail-open)",
			"error", err, "user", userID)
		return false
	}
	in := tokenpolicy.PolicyInput{
		ClientID:       clientID,
		Subject:        userID,
		TenantID:       tenantID,
		ActiveSessions: len(sessions),
	}
	// Role resolution (fail-open): only when the seam has a tenant AND the
	// roster store is wired. An error is logged + counted, roles stay empty,
	// and role selectors simply don't match — a roster outage must never
	// block login. ensureJITMembership runs before createSession, so a
	// JIT-provisioned role is visible on the first login.
	if tenantID != "" && s.tenantUserStore != nil {
		if m, err := s.tenantUserStore.Get(ctx.Request().Context(), tenantID, userID); err == nil && m != nil {
			in.SubjectRoles = []string{string(m.Role)}
		} else if err != nil {
			s.logger.Error("token policy: role resolution failed — role selectors inert (fail-open)",
				"tenant", tenantID, "user", userID, "error", err)
			s.metrics.ObserveTokenPolicyRoleResolutionError()
		}
	}
	dec := tokenpolicy.Evaluate(in, policies)
	if !dec.Deny || dec.Reason != tokenpolicy.DenyActiveSessions {
		return false
	}
	s.metrics.ObserveTokenPolicyEvaluation(metrics.PolicyDecisionDeny)
	s.metrics.ObserveTokenPolicyDenial(string(dec.Reason))
	s.logger.Info("token policy denied session creation",
		"client", clientID, "user", userID, "active", len(sessions))
	return true
}
```

Call site (`server_logout.go:357`, same line, +0): `if s.sessionPolicyCapExceeded(ctx,
userID, clientID, tenantID) {` — `tenantID` is already the `createSession` parameter
(:345).

## 7. Refresh seam and the remaining seams

`internal/handler/tokengrant/token_refresh.go`, both edits same-line (+0):

- Interface (:42): `EnforceRefreshDepthPolicy(ctx core.HandlerContext, clientID, subject, tenantID string, scopes []string, depth int) bool`
- Call (:116): `if d.EnforceRefreshDepthPolicy(ctx, client.ID, info.UserID, client.TenantID, grantScopes, info.Generation) {`

Implementation in `server_helpers.go` per §1.2. The compile-time guard
(`accessors_handlers.go:363`) needs no edit — `*Server` picks up the new signature.
No other implementers exist (grep: only the interface, the call site, and the
implementation). `info.UserID` remains the subject (local ID — design Decision 2);
roles stay unpopulated at this seam (documented no-op, extension point named in
config-reference).

Clamp seam (`domains/tokenpolicy/clamp_issuer.go:44-52`): `PolicyInput` gains
`TenantID: subject.TenantID` (+1 → 70). No `Subject:` population — the clamp seam only
sees the (possibly pairwise-projected) issued `sub`, which would violate the
local-subject-ID semantics; subject rules at max_ttl are inert by design (matrix §9).

Introspection seam (`sso_protocol.go:486`): NO change — it cannot resolve
tenant/subject/roles (Decision 5 keeps tenant out of claims); new selectors are inert
there (security F2), recorded in the matrix and config-reference.

Federated seam (`server_oauth.go:223`): NO code change — empty clientID AND tenantID
means only global, role-less rules apply (SRE F6 / QA M1); documented in
config-reference + observability.

## 8. Review remediation map

| Finding | Plan item |
|---|---|
| Security F1 — 12 vs 10 mint sites | §3: corrected census (13 sites + template), per-site stamps + tests (`TestRcov_TokenPolicy_TenantMaxTTL_SilentRenewal`, `..._AgentDelegation`: `expires_in == 300`) |
| Security F2 — inert selectors + 5th Evaluate site | §7, §9 liveness matrix in config-reference; no-op pin tests (roles empty ⇒ no match at refresh; subject × combo/clamp no-match) |
| Security F3 — fail-open role observability | §6: bounded counter `sso_token_policy_role_resolution_errors_total` (no labels) in `metrics_token.go` (155 → 167) + `ObserveTokenPolicyRoleResolutionError`; `docs/observability.md` |
| Security F4 — tenant_id unvalidated | §4.5 `Validate` rules + `validate_test.go` cases (`"*"`, `" a "`) |
| Security F5 — server_oauth math | §1.3: 481 → 495, exact (F5's ~491 undercounts by the hoist + metric + comment lines)
| SRE F1 — stock never wires tenant-user store | §4.4 boot warning + config-reference wiring statement |
| SRE F2 — inline strictness bypassable | §4.2 `Policy.UnmarshalYAML` (decode-layer, ordering-proven) + config test |
| SRE F3 — rollout/rollback skew | §11 binary-first ordering + `docs/deployment.md` paragraph + release notes (unknown keys now fail boot; `client_id` trailing-`*` activates) |
| SRE F4 — no metric/trace for role lookup | §6 counter + observability.md note (lookup is unconditional when wired + tenant-bound) |
| SRE F5 — no docs gate | §10: `checks/route_contract.py` gains an assertion that the admin token-policies item schema contains the three fields (makes the openapi edit CI-enforced) |
| SRE F6 — federated seam | §7 documentation row |
| SRE F7 — server_helpers math | §1.2: 493 → 495 (F7's 497 rebutted: signatures stay single-line) |
| SRE F8 — no SLO / no read-hop measurement | observability.md: measure `Get` latency contribution to login p95 before/after; SLO out of scope (no committed SLO framework) |
| QA H1 — census + break-glass | §3 sites 11–13 + template, per-site tests |
| QA H2 — subject/roles × max_ttl + subject × combos inert | §9 matrix + config-reference + no-op pins |
| QA M1 — federated empty tenant undocumented | §7, §9 |
| QA M2 — tenant source unpinned | Seam tests: tenant A denied / tenant B allowed under the same rule with a conflicting middleware stash present (proves `client.TenantID` source) |
| QA M3 — stamps unpinned | §3 per-site decision table + per-site clamp tests |
| QA M4 — inline Validate boot-fail test | `build_governance_test.go`: invalid inline policy ⇒ error; valid tenant rule ⇒ store built |
| QA M5 — admin round-trip | `rootcov_admin_token_policies_test.go`: GET carries `tenant_id`/`subject`/`subject_roles`; global rules byte-identical |
| QA L1 — legacy `scopes: ["*"]` compat pin | `TestEvaluate_SelectorMatching` extended with a `scopes:["*"]` rule (match-all preserved) |
| QA L2 — "7th file" miscount | §4.5: 6th non-test file; ceiling unaffected |

## 9. Selector liveness matrix (config-reference §5.6 contract)

| Seam | `tenant_id` | `subject` | `subject_roles` |
|---|---|---|---|
| Scope-combo (`/token` dispatch) | **live** (`client.TenantID`) | inert (no subject at dispatch) | inert |
| Refresh depth | **live** (`client.TenantID`) | **live** (`info.UserID`, local id) | inert (documented no-op; extension point = `RefreshGrantDeps` role resolver) |
| Session cap | **live** (`tenantID` param) | **live** (`userID`) | **live** only when `WithTenantUserStore` wired; fail-open otherwise |
| TTL clamp (ClampingIssuer) | **live** (`subject.TenantID` stamp) | inert (seam sees projected `sub`, deliberately unpopulated) | inert |
| Introspection renew (`IntrospectionRenewExceeded`) | inert (claims carry no tenant) | inert | inert |
| Federated callback session | inert (empty clientID + tenantID) | inert | inert |

Every inert cell is a documented, fail-open non-match — never a widen — and is pinned
by a no-op test (H2). The matrix lands in `docs/config-reference.md:588` (the
`token_policies.policies` row + a liveness paragraph).

## 10. Edit inventory with gate proof

| File | Current | Edit | Final | Gate (≤500 / ≤10 files) |
|---|---:|---|---:|---|
| `domains/tokenpolicy/tokenpolicy.go` | 160 | +17 Policy selectors, +5 PolicyInput fields | 182 | ✓ |
| `domains/tokenpolicy/evaluate.go` | 176 | +9 matches(), +7 prefixOrExact, +9 rolesIntersect | 201 | ✓ |
| `domains/tokenpolicy/yaml.go` | 24 | +11 UnmarshalYAML, +3 ParseYAML Validate | 38 | ✓ |
| `domains/tokenpolicy/validate.go` | — | new (~65) | ~65 | ✓ (6th non-test file; 6 ≤ 10) |
| `domains/tokenpolicy/clamp_issuer.go` | 69 | +1 `TenantID: subject.TenantID` | 70 | ✓ |
| `shared/core/types_token.go` | 277 | +5 field + doc | 282 | ✓ |
| `interfaces/sso/server_token.go` | 500 | +0 (same-line call, §2) | **500** | ✓ (500 ≤ 500) |
| `interfaces/sso/server_helpers.go` | 493 | +2 (two `TenantID:` literal lines) | **495** | ✓ |
| `interfaces/sso/server_oauth.go` | 481 | +14 (session seam, §6) | **495** | ✓ |
| `interfaces/sso/server_logout.go` | 484 | +0 (same-line call) | 484 | ✓ |
| `internal/handler/tokengrant/token_refresh.go` | 430 | +0 seam (same-line), +1 stamp | 431 | ✓ |
| `internal/handler/tokengrant/token_authcode.go` | 287 | +1 stamp | 288 | ✓ |
| `internal/handler/tokengrant/token_client_credentials.go` | 68 | +1 stamp | 69 | ✓ |
| `internal/handler/tokengrant/token_device.go` | 206 | +1 stamp | 207 | ✓ |
| `internal/handler/tokengrant/token_ciba.go` | 289 | +1 stamp | 290 | ✓ |
| `internal/handler/tokengrant/token_jwt_bearer.go` | 116 | +1 stamp | 117 | ✓ |
| `internal/handler/tokengrant/token_saml2_bearer.go` | 124 | +1 stamp | 125 | ✓ |
| `internal/handler/tokengrant/token_exchange_stages.go` | 495 | +1 stamp | 496 | ✓ |
| `interfaces/sso/server_login.go` | 499 | +1 stamp | **500** | ✓ (gate edge — no further edits) |
| `interfaces/sso/server_native_sso.go` | 341 | +1 stamp | 342 | ✓ |
| `protocols/oidc/handle_silent_renewal.go` | 410 | +1 stamp | 411 | ✓ |
| `domains/tokenexchange/agentidentity/grant.go` | 228 | +1 stamp | 229 | ✓ |
| `interfaces/sso/accessors_feature_gates.go` | 498 | +1 comment (break-glass non-stamp) | 499 | ✓ |
| `cmd/sso-ctl/generate/templates_handler.go` | 214 | +1 template line | 215 | ✓ |
| `cmd/sso-server/serverbuildplatform/build_governance.go` | 430 | +3 Validate, +3 warning, +10 helper, +1 slog import | 447 | ✓ |
| `platform/metrics/metrics_token.go` | 155 | +4 counter, +8 observe method | 167 | ✓ |
| `config/config_snapshot.go` | 482 | **0 — no edit needed** (strictness lives in the domain type, §4.2) | 482 | ✓ |
| Tests: `yaml_test.go`, new `validate_test.go`, `evaluate_test.go`, `clamp_issuer_test.go`, `rootcov_token_policy_test.go`, `rootcov_admin_token_policies_test.go`, `build_governance_test.go`, config loader test, defaultimpl claim-surface test | — | `_test.go` excluded from all budgets | — | ✓ |
| Docs: `docs/openapi.yaml` (:6836 endpoint description + item schema at :6868-6884 gains `tenant_id`/`subject`/`subject_roles`), `docs/config-reference.md` (:588), `docs/observability.md` (:52), `docs/deployment.md`, `docs/error-codes.md` (unchanged — no new Err*) | — | — | — | route-contract assertion (§8 SRE F5) makes the openapi change CI-enforced |
| `checks/route_contract.py` | — | +~15 lines schema assertion | — | `make ci` route-contract stage |

No new top-level or `internal/` packages; `interfaces/sso` gains no files (60-file
ceiling untouched); `domains/tokenpolicy` gains 1 file (6 ≤ 10). No
`layerExemptions`, no exemption-map growth. Function budgets: largest new function is
`Validate` (~40 lines) and `sessionPolicyCapExceeded` (41) — both ≤ 50; complexity
≤ 15 at every touched function; `if`-nesting ≤ 3.

## 11. Verification sequence and rollout ordering

Implementation order (domain-first, contract docs in the SAME change per AGENTS.md §5.6):

1. `domains/tokenpolicy` (fields → `matches()`/helpers → `validate.go` → `yaml.go`
   strict decode + ParseYAML) + domain tests, incl. the `TestParseYAML_Empty` fixture
   change (§5) — run `go test ./domains/tokenpolicy/ -race`.
2. `shared/core/types_token.go` + the 13 per-site stamp decisions + template (§3) +
   per-site clamp tests (QA H1/H3) + claim-surface pin (access token for a
   tenant-bound client carries no `tenant_id` claim — defaultimpl test).
3. Seams: `server_helpers.go` (§1.2), `server_oauth.go` (§6), `server_logout.go`
   (§7), `token_refresh.go` (§7), `clamp_issuer.go`; seam tests incl. tenant-source
   pin (M2), JIT-first-login role visibility, reverse strictest-wins, role-outage
   fail-open.
4. `metrics_token.go` counter + `build_governance.go` Validate + SRE F1 warning +
   `build_governance_test.go` boot-fail test (M4) + config loader strict-inline test
   (SRE F2 pin).
5. Docs: openapi.yaml item schema + description, config-reference selector rows +
   liveness matrix + refresh limitation + federated row, observability (counter +
   read-hop note), deployment (rollout ordering, SRE F3) + `checks/route_contract.py`
   assertion (SRE F5).
6. Gates, in order:
   ```bash
   go build ./... && go vet ./...
   go test -run 'TestMaintainability_|TestArchitecture_' .
   go test ./domains/tokenpolicy/... ./cmd/sso-server/serverbuildplatform/ -count=1 -race
   go test ./interfaces/sso/ ./internal/handler/tokengrant/ ./config/ -race
   go test ./... -race
   python cli.py route-contract   # now carrying the token-policy schema assertion
   make ci
   ```
   `make ci` is currently red on PRE-EXISTING unrelated items (fmt on
   `infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go` + untracked
   `test/region_token_contract_test.go`, per the QA review) — reported separately;
   this change's gate evidence is the four `go test` commands + route-contract, and
   `make ci` green once the pre-existing items clear.
7. Rollout (SRE F3): deploy the binary FIRST, config second; on rollback revert
   config before binary. Both flips (unknown keys now fail boot; previously-inert
   `client_id: "prefix*"` rules activate as tighten-only) go in release notes;
   during the rollout window watch cross-tenant deny-rate.

Known residuals, all documented in config-reference: role selectors are stock-inert
without the tenant-user store (SRE F1, fail-open + boot warning); roles × refresh
depth never fire (design Decision 4); introspection and federated seams ignore the
new selectors (F2/F6); programmatic `memory.New` seeds bypass `Validate` (design
failure table, trusted operator code).
