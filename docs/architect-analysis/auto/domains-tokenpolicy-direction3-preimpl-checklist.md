# Direction 3 — Pre-Implementation Checklist: reconciled census, adjudications, merged findings

Authoritative reconciliation of the design (`domains-tokenpolicy-direction3-design.md`)
and the three reviews (security, SRE, QA) for the tenant/subject/role selector
change. Every line cite below was re-verified against the tree at `HEAD`
(`ff690260`) by source inspection (greps + reads; no `.go` changed, no gates
run — design-stage convention). Where a review contradicts another review or
the design, this document is the single source of truth for implementation.

## 1. Census reconciliation — the conflicting "12 sites" claims

### 1.1 The conflict

| Review | Claimed count | Sites it names as missing from the design | Misses |
|---|---|---|---|
| Security F1 | 12 | `handle_silent_renewal.go:210` + `agentidentity/grant.go:185` (+ template named, not counted) | `accessors_feature_gates.go:257` (break-glass) |
| QA H1 | 12 | `agentidentity/grant.go:185` + `accessors_feature_gates.go:257` (break-glass) | `handle_silent_renewal.go:210` |

Both claim 12; neither names the other's unique site. **Both are wrong in the
same way: each is a real but incomplete census.** Neither counted the codegen
template inside its 12.

### 1.2 Ground truth (re-verified at HEAD)

Mint sites were found with two greps, because `interfaces/sso` aliases the
type (`interfaces/sso/aliases.go:132`: `type Subject = core.Subject`):

- `core.Subject{` (non-test): **10** real sites + 1 codegen template
- Aliased `Subject{` (non-test): **3** more sites
- **Total: 13 runtime mint sites + 1 codegen template = 14 items**

Per-review accounting:

| Census | Count | Composition | Arithmetic |
|---|---|---|---|
| Design D5 | 10 | 8 tokengrant + `server_login.go:112` + `server_native_sso.go:190` | misses 3 sites + template |
| Security F1 | 12 | design-10 + silent renewal + agent delegation | `core.Subject{` actually finds 10 real sites; the count of 12 only works if the aliased `Subject{` sites are included. Misses break-glass |
| QA H1 | 12 | design-10 + agent delegation + break-glass | misses silent renewal and the template |
| **Reconciled** | **13 + 1** | union of all three censuses | — |

### 1.3 Authoritative per-site list with clamp decisions (13 + 1)

Decision legend: **STAMP** = add `TenantID: client.TenantID,` to the existing
`Subject` literal; **EXEMPT** = deliberate, commented, test-pinned non-stamp;
**TEMPLATE** = edit the codegen sample.

| # | Site (file:line) | Mint function / flow | Reachability in stock `sso-server` | `client` in scope | Stamps `ServingRegion` today | Decision |
|---|---|---|---|---|---|---|
| 1 | `internal/handler/tokengrant/token_authcode.go:118` | authorization-code | stock (built-in `/token` switch, `server_token.go:186`) | yes | yes | **STAMP** |
| 2 | `internal/handler/tokengrant/token_client_credentials.go:40` | client-credentials | stock (`server_token.go:196`) | yes | yes | **STAMP** |
| 3 | `internal/handler/tokengrant/token_refresh.go:247` | refresh rotation (`refreshRotatedSubject`) | stock (`server_token.go:188`) | yes | yes | **STAMP** |
| 4 | `internal/handler/tokengrant/token_device.go:82` | device code | stock (`server_token.go:190`) | yes | yes | **STAMP** |
| 5 | `internal/handler/tokengrant/token_ciba.go:99` | CIBA backchannel | stock (built-in switch case `server_token.go:192`; gate hook `SetCIBAGateEnabled` wired at `cmd/sso-server/main_wiring.go:190`) | yes | yes | **STAMP** |
| 6 | `internal/handler/tokengrant/token_jwt_bearer.go:95` | JWT bearer | stock (`server_token.go:202`) | yes | yes | **STAMP** |
| 7 | `internal/handler/tokengrant/token_saml2_bearer.go:103` | SAML2 bearer (RFC 7522, registered via `WithCustomGrant` mechanism) | **embedding-only**: `WithSAML2BearerGrant` (`server_setup.go:262`) not referenced in `cmd/` | yes | yes | **STAMP** |
| 8 | `internal/handler/tokengrant/token_exchange_stages.go:390` | token exchange (`tokExSubject`) | stock (`server_token.go:194`) | yes | yes | **STAMP** |
| 9 | `interfaces/sso/server_login.go:112` | direct `/auth/login` mint | stock | yes | yes | **STAMP** |
| 10 | `interfaces/sso/server_native_sso.go:190` | native SSO | stock | yes | yes | **STAMP** |
| 11 | `protocols/oidc/handle_silent_renewal.go:210` | silent renewal, `prompt=none` (`issueSilentRenewalToken`) | **stock** (`server_discovery.go:66` ← `server_login_resolve.go:169`) | yes | **no** | **STAMP** — highest-risk path: bearer mint without fresh authn |
| 12 | `domains/tokenexchange/agentidentity/grant.go:185` | agent delegation (`mintDelegationToken`, grant `delegation_token`) | **embedding-only**: `WithAgentDelegationGrant` (`options_grants.go:416`) is NOT referenced in `cmd/` — both reviews' "stock" framing corrected | yes | **no** | **STAMP** |
| 13 | `interfaces/sso/accessors_feature_gates.go:257` | break-glass impersonation | stock (wired via `build_app_security.go:225` `wireBreakGlass`, store via `WithBreakGlassStore`) | **no client** — `s.issuerForClient(nil)` | **no** | **EXEMPT** — see §2.1 |
| 14 | `cmd/sso-ctl/generate/templates_handler.go:193` | codegen sample mint snippet | n/a (generated-code template) | snippet has `client` | n/a | **TEMPLATE** — add `TenantID: client.TenantID,` to the sample |

Corrections to review claims, recorded:

- Security F1's "both funnel through `IssuerForClient` → `NewClampingIssuer`"
  holds for both sites (verified: `server_helpers.go:37-67` wraps every
  resolved issuer), but its "stock `WithAgentIdentityGrant`" naming is wrong
  on both counts: the symbol is `WithAgentDelegationGrant` and it is not wired
  in `cmd/`.
- QA H1's "wired into the stock server via `WithAgentDelegationGrant`" is
  wrong on the stock part (embedding-only); the symbol name is right.
- Neither review verified `ServingRegion` for its own sites: sites 11-13 do
  NOT stamp `ServingRegion` today. The design's claim "all stamp ClientID +
  ServingRegion in the same literal" is true only of its original 10; the
  reconciled table above is the exact statement. Adding `ServingRegion` to
  11-13 is out of scope (separate pre-existing drift) but must not be claimed
  in design text.

## 2. Clamp decisions (per-site rationale)

1. **Sites 1-12: STAMP** — one line each, `TenantID: client.TenantID,`, in the
   same literal that already stamps `ClientID` (all verified to have `client`
   in scope). Silent renewal (#11) and agent delegation (#12) are not optional:
   the design's failure-table row "old/third-party issue site misses the
   stamp" must NOT be applied to them — they are first-party, in-scope sites.
   The tenant TTL/scope-combo evasion surface on prompt=none (#11) is the
   design's own headline risk and is the reason this census exists.
2. **Site 13 (break-glass): EXEMPT, deliberately.** The site calls
   `s.issuerForClient(nil)` — there is no `client`, so there is no tenant
   binding to read; the mint is a synthetic emergency credential
   (`core.BreakGlassImpersonationClientID`). Decision: add an explicit
   `TenantID: ""` with a comment ("break-glass: no tenant binding — tenant
   rules deliberately do not apply") so the exemption is self-documenting,
   and pin it with a test asserting the break-glass mint is NOT clamped by a
   tenant `max_ttl` rule (QA H1's "deliberate, documented exemption, not an
   omission").
3. **Site 14 (template): TEMPLATE edit** — the sample snippet already shows
   `ClientID: client.ID`; add `TenantID: client.TenantID,` so generated
   handlers follow the convention from birth.
4. **Static tripwire** (security F1 remediation): add a comment contract on
   `ClampingIssuer.Issue` — "a site that mints via `IssuerForClient` MUST
   stamp `Subject.TenantID`" — plus per-site clamp tests (§4, item C1) so a
   future 14th site fails review, not production.

## 3. Adjudications

### 3.1 SRE F1 [High] — `subject_roles` unreachable in the stock binary (TenantUserStore wiring gap)

**Verified.** `WithTenantUserStore` (`options_passwd.go:363`) is referenced
nowhere in `cmd/`; there is no config key, no store builder. The stock
`sso-server` binary is always the nil-store case at the session seam, so
`subject_roles` rules load, evaluate, and never match — silent, no metric, no
audit delta. The design's Decision 4 presents the session seam as the
enforcing seam for role rules; in the shipped binary it enforces nothing.

**Adjudicated decision: SRE option 1 + option 2; option 3 deferred.**

1. **Boot-time warning (implement).** At server startup in `interfaces/sso`
   (where both `tokenPolicyStore` and `tenantUserStore` are known), when the
   wired policy set contains any `subject_roles` rule and the store is nil,
   emit one `slog.Warn` naming the capability and the missing wiring. The
   `Store` interface already exposes `Policies(ctx)` (`tokenpolicy.go:155`),
   so the scan is a read-only startup check, not a hot-path change.
2. **Config-reference statement (implement).** `subject_roles` requires
   `WithTenantUserStore`; the stock `sso-server` does not wire it — the
   dimension is embedding-only until a store builder ships.
3. **Sqlite `TenantUserStore` builder (deferred, out of scope).** It is a new
   storage surface and a new stock dependency; the design's zero-new-storage
   discipline stands for this change. Recorded as a follow-up so the gap is a
   decision, not an accident.
4. **Pins:** nil-store + role rules ⇒ no match (fail-open), boot warning
   fires; embedding with memory store ⇒ rule denies. The delta between the
   two runs is the capability (SRE F1 recovery validation).

### 3.2 SRE F2 [Medium] — Design claim 3c is false for the inline config path

**Verified.** `decodeStrictWithFallback` (`config/source.go:260-275`) runs a
strict decode, and on ANY unknown key warns and re-decodes the whole merged
config non-strictly. A misspelled `tennat_id:` inside
`token_policies.policies` is dropped there; `BuildTokenPolicyStore`
(`serverbuildplatform/build_governance.go:197-223`) then sees a legal global
rule and `Validate` (design 3b) passes it. The design's 3c claim — "a typo in
`token_policies.policies` fails boot" — is therefore false for the inline
path. SRE F2's bonus also holds: any unrelated unknown key elsewhere in
`config.yaml` disables strictness for the entire config on that boot.

**Adjudicated decision: accept warn-and-demote for the inline path; File
bundles are the strict path; document both; pin the behavior.**

1. **Amend the design:** claim 3c becomes "the FILE path (`ParseYAML`) fails
   boot on unknown keys and shape errors; the INLINE path fails boot on shape
   errors (`Validate` at `BuildTokenPolicyStore`) but typo'd keys warn
   (`decodeStrictWithFallback`) and demote to global."
2. **Config-reference statement:** inline-path typos warn (config layer);
   file-path typos fail boot; operators wanting strict governance configs use
   File bundles. This is the SRE F2 remediation item 1.
3. **Rejected option, with reason:** SRE F2's "round-trip `Policies` through
   `ParseYAML` in `BuildTokenPolicyStore`" cannot work — the unknown field
   was already dropped at config decode; the snapshot carries only decoded
   structs, and goccy's unknown-field errors (`[line:col] unknown field
   "name"`) carry no YAML path, so the config layer cannot attribute a key to
   the `token_policies` section either. Fixing this properly means changing
   global config-decode semantics — out of scope.
4. **Pin test:** inline config with `tennat_id: ta` ⇒ boot WARN emitted, rule
   is global (visible via the admin API), boot succeeds; same typo in a File
   bundle ⇒ boot fails. This pins the actual behavior so the drift cannot
   pass CI (SRE F2 remediation item 2).

## 4. Merged pre-implementation checklist

All items carry their source tags. Items are the union of the three reviews
plus the design's own pins; nothing below is optional unless marked.

### A. Census and stamps (Security F1, QA H1/M3)

- [ ] **A1.** Stamp `TenantID: client.TenantID,` at sites 1-12 of §1.3 (one
  line per site, same literal as `ClientID`).
- [ ] **A2.** Break-glass (site 13): explicit `TenantID: ""` + exemption
  comment; no clamp.
- [ ] **A3.** Codegen template (site 14): add `TenantID: client.TenantID,` to
  the sample snippet.
- [ ] **A4.** Static comment contract on `ClampingIssuer.Issue` (mint sites
  MUST stamp).
- [ ] **A5.** Correct the design: D5 site list 10 → 13+1; "all stamp
  ClientID+ServingRegion" claim limited to the original 10; the "7th file"
  miscount → 6th (`validate.go`); failure-table rows added (no-tenant
  federated session, nil `tenantUserStore` in stock, introspection seam,
  break-glass exemption).

### B. Selector model, `Validate`, strictness (Security F2/F4, QA H2/M4/L1, SRE F2)

- [ ] **B1.** `Policy`/`PolicyInput` gain `TenantID`/`Subject`/`SubjectRoles`;
  empty tenant = global; additive strictest-wins (existing `Evaluate` minima +
  first-deny unchanged — regression `TestEvaluate_SelectorMatching`,
  `TestEvaluate_DenyReasonDeterministic`).
- [ ] **B2.** `prefixOrExact` helper; subject selectors match the LOCAL subject
  ID; do NOT plumb `Subject` into the clamp or scope-combo seams (pairwise
  `sub` would violate the documented local-ID contract — Security F2c).
- [ ] **B3.** `validate.go`: bare/interior `*` rejected; roles validated
  against `core.TenantRole`; **NEW: `tenant_id` rules** — reject `*`,
  whitespace padding, empty-adjacent spellings (Security F4); `scopes`/bare
  `*` remain unvalidated (legacy compat).
- [ ] **B4.** Wire `Validate` into `ParseYAML` (File path, strict) and
  `BuildTokenPolicyStore` (inline path) — strictness not bypassable through
  the File path; inline path per §3.2 (documented warn+demote).
- [ ] **B5.** `TestParseYAML_Empty` fixture: drop the `other: 1` case in the
  same edit (design's verified trap); `TestParseYAML_Malformed` gains
  unknown-field cases.

### C. Seams and evaluation points (Design D4, Security F2, QA M1/M2/M3, SRE F6)

- [ ] **C1.** Scope-combo seam: `denyTokenScopeCombo(ctx, clientID, tenantID,
  scopes)` — call-site edit at `server_token.go:168` **same line**
  (`s.denyTokenScopeCombo(ctx, client.ID, client.TenantID, scopes)`);
  `server_token.go` must stay at exactly 500 lines.
- [ ] **C2.** Refresh-depth seam: `EnforceRefreshDepthPolicy` gains `tenantID`
  (ripples to `RefreshGrantDeps` + compile-time guard); call site
  `token_refresh.go:116`.
- [ ] **C3.** Session-cap seam: `sessionPolicyCapExceeded` gains tenantID +
  resolved `SubjectRoles`; `server_logout.go:357` passes the already-present
  `tenantID` param (`createSession` at :345); JIT membership
  (`server_finish_login.go:46`) precedes the seam (:149) — role visible on
  first login.
- [ ] **C4.** Clamp seam: `ClampingIssuer.Issue` adds `TenantID:
  subject.TenantID` to its `PolicyInput` (no signature change).
- [ ] **C5.** **Name the fifth evaluation point** (Security F2): the design
  says "four seams"; `IntrospectionRenewExceeded` (`sso_protocol.go:486`) is
  a fifth `Evaluate` site. Decision: document as intentionally
  client/scope-only (threading tenant needs a client-store lookup on a hot
  path; Decision 5 keeps tenant out of claims) — no code change, liveness
  matrix row + no-op pin test.
- [ ] **C6.** Federated callback seam (`server_oauth.go:223`) passes
  `("", "", ...)`: tenant and role selectors inert there by design (QA M1,
  SRE F6). Liveness matrix row + pin test
  (`TestRcov_TokenPolicy_SessionCap_TenantRuleInertOnCallbackPath`).
- [ ] **C7.** Refresh-seam role no-op: keep documented (design D4); extend to
  the full liveness matrix (QA H2).
- [ ] **C8.** Tenant SOURCE pin (QA M2): client `TenantID="ta"` + conflicting
  middleware stash `"tb"` ⇒ `ta` rule fires — proves policy input keys on
  `client.TenantID`, never the header-derived tenant.

### D. Role resolution wiring (SRE F1/F4, Security F3)

- [ ] **D1.** Boot warning when `subject_roles` rules are wired and
  `tenantUserStore == nil` (startup scan via `Store.Policies()`, §3.1).
- [ ] **D2.** Bounded counter `sso_token_policy_role_resolution_errors_total`
  (no tenant/user labels) on the fail-open path; keep the `logger.Error`
  (add trace correlation if the seam logger gains request context).
- [ ] **D3.** `docs/config-reference.md`: `subject_roles` requires
  `WithTenantUserStore` (embedding-only in stock); the lookup is
  unconditional per login when wired + tenant-bound; fail-open stance
  documented.
- [ ] **D4.** `docs/observability.md`: role-lookup failure counter + login p95
  note (SRE F4 item 3); federated-seam tenant note (SRE F6).

### E. Claim surface and storage (Design D5)

- [ ] **E1.** `core.Subject.TenantID` field added; NOT a claim: no field on
  `ed25519Payload`/`TokenClaims`, no stamp in `buildAccessPayload`/
  `applyOptionalClaims`; claim-set pin test (no `tenant_id` JWT claim).
- [ ] **E2.** Zero new storage: one read-only `TenantUserStore.Get` at the
  session seam; COW memory store unchanged (extend
  `TestStore_ConcurrentReadWrite` with new fields).

### F. Admin/docs contracts (Design D6, QA M5, SRE F5/F3)

- [ ] **F1.** `docs/openapi.yaml` (~:6836 policy item schema) and
  `docs/config-reference.md` (~:588) synced in the SAME change as the code;
  verbatim serialization carries the three fields (omitempty).
- [ ] **F2.** Admin round-trip test: extend `TestRcovAdmin_TokenPoliciesInventory`
  — `tenant_id`/`subject`/`subject_roles` present on a scoped rule, absent on
  a global rule (QA M5).
- [ ] **F3.** Note in handoff: `make ci` does NOT gate docs (SRE F5). Optional
  cheap CI enforcement: route-contract or unit assertion that the policies
  item schema contains the three fields.
- [ ] **F4.** `docs/deployment.md`: rollout-ordering runbook — deploy binary
  first, config after; rollback reverts config before binary; release notes
  call out both flips (unknown keys now fail boot on the File path;
  `client_id` trailing-`*` rules silently activate) (SRE F3).
- [ ] **F5.** Liveness matrix in `docs/config-reference.md` replacing the
  single refresh-seam note: selector × dimension × seam (clamp, scope-combo,
  refresh-depth, session cap, introspection, federated callback, break-glass)
  (QA H2, Security F2).

### G. Test plan (union of all three review plans)

- [ ] **G1.** `TestRcov_TokenPolicy_TenantMaxTTL_PerGrantFamily` — table over
  authcode, client_credentials, device, ciba, jwt_bearer, saml2_bearer,
  exchange, login, native_sso, refresh, silent renewal, agent delegation —
  `expires_in == 300` for every family (QA M3, Security F1 regression). The
  single highest-value test.
- [ ] **G2.** `TestRcov_TokenPolicy_TenantMaxTTL_AgentDelegation` —
  `expires_in == 300` via the delegation grant (QA H1).
- [ ] **G3.** Silent-renewal server-level test: `HandleSilentRenewal` with a
  valid hint token ⇒ clamped (Security F1).
- [ ] **G4.** Break-glass exemption pin: mint via break-glass ⇒ unclamped,
  exemption comment present (QA H1).
- [ ] **G5.** Inert-combination no-op pins: introspection shape vs tenant
  `require_renew_after` ⇒ `RenewAfter == 0`; clamp shape vs `subject:`
  `max_ttl` ⇒ unclamped; scope-combo shape vs `subject_roles:` ⇒ no deny;
  `Evaluate` with `in.Subject == ""` ⇒ no match (Security F2, QA H2).
- [ ] **G6.** `Validate` unit tests: `tenant_id: "*"`, `tenant_id: " a "`
  rejected; bare/interior `*` rejected; `subject_roles` closed-set; legacy
  `scopes: ["*"]` still loads (`TestParseYAML_LegacyBareStarScopeStillLoads`)
  (Security F4, QA L1).
- [ ] **G7.** Boot-level inline validation:
  `TestBuildTokenPolicyStore_InlineInvalidRuleFailsBoot` (`SubjectRoles:
  ["owner"]` ⇒ error) (QA M4); inline typo ⇒ WARN + global rule (§3.2 pin,
  SRE F2).
- [ ] **G8.** Role-wiring pins: nil-store + role rules ⇒ no match + boot
  warning; store outage ⇒ login continues, counter rises (SRE F1/F4,
  Security F3).
- [ ] **G9.** Tenant-source pin (C8), callback-path pin (C6), claim-surface
  pin (E1), admin round-trip (F2), legacy byte-compat (B1 regressions).
- [ ] **G10.** Race: `-count=10+` on session-cap tests with isolated user IDs
  and per-case stores (QA flake risk); COW concurrency with tenant rules.
- [ ] **G11.** E2E note: no token-policy E2E in `test/` today; design's gate
  list must add `go test ./... -race` and `go test ./test/ -run TestE2E -v`
  (QA gap list).

### H. Budget and gate discipline (Design risk #1, Security F5, SRE F7, QA exit)

- [ ] **H1.** `server_token.go`: exactly 500 lines before AND after — the
  scope-combo call-site edit is the only change, argument added on the
  existing line.
- [ ] **H2.** `server_helpers.go`: 493 → **497** (two signature lines +
  two `PolicyInput` lines — SRE F7's corrected arithmetic; headroom 3).
- [ ] **H3.** `server_oauth.go`: 481 → **~491** (count the `logger.Error`
  line the seam snippet contains — Security F5). ≤ 500.
- [ ] **H4.** After every `.go` edit: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .`
- [ ] **H5.** Handoff gates: `go test ./... -race`, E2E, `make ci` — note
  `make ci` is currently red on a PRE-EXISTING fmt failure
  (`infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go` modified +
  untracked `test/region_token_contract_test.go`, unrelated in-flight work;
  resolve before this change uses `make ci` as its gate; report separately
  per AGENTS.md §5.7).

### I. Exit criteria (consolidated)

1. A1-A5, B1-B5, C1-C8, D1-D4, E1-E2, F1-F5, G1-G11 land in the same change
   as the code; both contract docs synced in that change.
2. All gates green (H4/H5); `server_token.go` at exactly 500,
   `server_helpers.go` ≤ 500, `server_oauth.go` ≤ 500.
3. The §1.3 census (13 runtime sites + template) has an explicit decision per
   site: STAMP (12), EXEMPT (break-glass), TEMPLATE (1).
4. Liveness matrix documented (F5); claim-surface pin passing (E1).
5. Oracle safety preserved: no new `Err*`, no new claims, no new metrics
   labels beyond the single label-less role-resolution counter (D2).
6. Rollout ordering + release notes shipped with the change (F4).

## 5. Residual risks after this checklist

- Inline-config typo demotion (warn + global) remains — mitigated by
  documentation and a pin, not eliminated (structural, see §3.2).
- `subject_roles` remains embedding-only in the stock binary (wired decision,
  §3.1) until a store builder ships.
- No docs gate in `make ci` (process risk, SRE F5); optional schema assertion
  is the cheap mitigation.
- No SLO for the new read hop (SRE F8) — login p95 measurement decision is
  deferred to the observability review, noted in D4.
