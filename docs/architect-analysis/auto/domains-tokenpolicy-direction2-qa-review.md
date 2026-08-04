# domains/tokenpolicy — direction 2 design QA review (risk-based test review)

Review of `docs/auto/domains-tokenpolicy-direction2-design.md` (and its spec
counterpart `domains-tokenpolicy-direction2-spec.md`) at revision `3ba906eb`
("Stage: design"). The implementation has **not** landed — Verified: no
`EventTokenPolicyDenied`, no `RecordTokenPolicyDenied`, no
`PolicyDecision.DeniedBy` anywhere in non-test Go (grep over
`platform/audit`, `domains/tokenpolicy`, `interfaces/sso`). This review
therefore: re-verifies every evidence claim in the design against code,
maps every spec acceptance check to an existing or required test, and
measures the baseline the change will build on. All commands below ran for
this revision; no result is inherited from documentation.

Scope note: default CI (`make ci`) is the handoff gate for this change; the
only relevant conformance suite is
`TestConformance_EveryEventTypeHasCEFAndOCSFMapping` (auditsink), which is
**snapshot-based** (see F2). No chaos/load/benchmark suite is implicated: the
change adds one nil-safe helper call on two deny paths and zero new storage.

## 1. Test inventory and commands actually run

| Command | Result | Notes |
|---|---|---|
| `go build ./...` + `go vet` (tokenpolicy, audit*, interfaces/sso) | PASS | tree builds clean |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | budget/architecture gates |
| `go test ./domains/tokenpolicy/ ./platform/audit/auditspi/ ./platform/audit/auditreport/ ./platform/audit/auditsink/ -count=1` | PASS | all 4 touchpoint packages |
| `go test ./interfaces/sso/ -run 'TestRcov_TokenPolicy|TestRcovAdmin_TokenPolicies' -count=1` | PASS | 9 existing seam tests |
| `go test -race` on the 4 touchpoint packages above | PASS | — |
| `make ci` | **NOT RUN** | spec-only revision, no `.go` edits; baseline commands above are the proportional pre-implementation check. `make ci` remains the implementation-time handoff gate. |

Baseline tests at the touchpoints (all green, all cited from grep of the
current tree):

- **domains/tokenpolicy**: `evaluate_test.go` (truth-table style),
  `clamp_issuer_test.go`, `yaml_test.go` — the `Evaluate` core is
  table-testable exactly as the design claims (pure, no I/O).
- **interfaces/sso** (real-server seams, `rcovNewServer`):
  - `rootcov_token_policy_test.go` — `TestRcov_TokenPolicy_ScopeComboDenied`
    (400 `invalid_scope`, oracle-safe), `_SafeScopesAllowed`,
    `_MaxTTLClampsIssuedToken`, `_UnwiredIsByteIdentical`.
  - `rootcov_token_policy_enforce_test.go` —
    `TestRcov_TokenPolicy_MaxRefreshDepthEnforced` (400 `invalid_grant` after
    depth cap), `_MaxRefreshDepthUnwiredUnlimited`, `_MaxActiveSessionsEnforced`
    (login `access_denied`), `_MaxActiveSessionsUnwiredUnlimited`,
    `_RequireRenewSeam`.
  - `rootcov_admin_token_policies_test.go` — admin governance API guards.
  - Audit-wiring precedent: `config_audit_test.go:156-158` —
    `sink := audit.NewMemorySink(16)` + `sso.WithAuditRecorder(audit.New(sink))`
    — the exact harness the design's acceptance tests need.
- **platform/audit/auditspi**: `event_types_completeness_test.go:29`
  `TestKnownEventTypesIsComplete` (AST scan of `event_types*.go` — a new const
  missing from `KnownEventTypes` fails CI, verified).
- **platform/audit/auditreport**: `drift_test.go` — `TestControlAreaDefs_
  NoEventTypeClaimedTwice` (:82), `TestEveryKnownEventTypeIsClaimedOrExplicitly
  Uncategorized` (:95, `wantUncategorizedEventTypes` allowlist + claimed-union
  drift check), `TestBuildSOC2Report_HandlesEveryKnownEventType` (:140, one
  event of EVERY `KnownEventTypes` entry, sum invariant); `soc2_test.go` —
  bucket/Uncategorized/chain-metadata tests.
- **platform/audit/auditsink**: `conformance_test.go:155`
  `TestConformance_EveryEventTypeHasCEFAndOCSFMapping` — **manual snapshot
  `allKnownEventTypes` (:20), does NOT auto-detect new consts** (see F2);
  `cef_test.go`/`ocsf_test.go` rendering tests.

## 2. Evidence re-verification (design claims vs. current code)

Every claim the design lists as pre-verified was re-checked; all hold.

| Design claim | Status | Evidence |
|---|---|---|
| `enforceTokenPolicy` deny branch: metrics + `logger.Info`, zero auditor; `wireCodeForPolicyDeny` unchanged | **Verified** | server_helpers.go:99-104 (metrics+log, no `s.auditor`); `wireCodeForPolicyDeny` at :108-115 returns `invalid_scope`/`invalid_grant` only |
| `sessionPolicyCapExceeded` deny branch behind `dec.Reason != DenyActiveSessions` guard, no audit | **Verified** | server_oauth.go:162-190; guard at :184; metrics+log at :185-188; sole caller `createSession` server_logout.go:357 (grep: exactly one non-test call site) |
| Budgets 493/500, 481/500, 354/500 | **Verified** | `wc -l`: server_helpers.go 493, server_oauth.go 481, recorder_events.go 354 — two one-line insertions fit; nothing more does |
| No token-policy event type in `platform/audit` | **Verified** | grep `EventTokenPolicy`/`token_policy` over event_types.go, aliases_spi.go, control_areas.go: zero hits; `KnownEventTypes` (event_types.go:233) has no entry |
| CC7.2 bucket holds refresh-reuse / FAPI peers | **Verified** | control_areas.go CC7.2: `EventNewDeviceLogin`…`EventRefreshTokenReuse`, `EventRefreshRotationVelocityExceeded`, `EventFAPIComplianceViolation` |
| `PolicyDecision` has Deny/Reason/EffectiveTTL/RenewAfter, no rule identity; `Policy.Name` doc claims audit use, zero consumers | **Verified** | tokenpolicy.go:135-141 struct; tokenpolicy.go:70-71 `Name` doc "governance display + audit; not used in matching"; grep: no consumer |
| Precedents: nil-safe `RecordDeviceCodeDecision` (:80), `RecordRefreshRotationVelocityExceeded(s.auditor, ctx, ...)` (server_helpers.go:487), `EventFromRequest` (handler_helpers.go:37), `Event` fields, `HandlerContext = core.HandlerContext` (aliases.go:110) | **Verified** | recorder_events.go:80 (nil-guard + `EventFromRequest` + `SetMeta` shape); server_helpers.go:487 exact call; handler_helpers.go:37 (traceparent→TraceID/SpanID, EnrichTenant/Geo/Region); auditspi/event.go:21-45; aliases.go:110 |
| One deny ⇒ one event: both token seams funnel through `enforceTokenPolicy`'s single deny branch | **Verified** | `enforceTokenPolicy` has exactly 2 callers: `denyTokenScopeCombo` (server_token.go:168, all grants at top of `dispatchTokenGrant`) and `EnforceRefreshDepthPolicy` (internal/handler/tokengrant/token_refresh.go:116, before `refreshIssueAndRotate` — deny fires before any consume/rotation); session seam disjoint |
| Scope-combo seam never sets Subject | **Verified** | `denyTokenScopeCombo` (server_helpers.go:117-128) builds `PolicyInput{ClientID, Scopes, Kind}` — no Subject; applies to ALL grants incl. subject-bearing ones (server_token.go:161-168) |
| `DeniedBy` same-branch constraint is the real trap | **Verified** | evaluate.go:30-34: `if !d.Deny { if r := denyReason(p, in); r != DenyNone { d.Deny = true; d.Reason = r } }` — a post-loop pass would flip to last-deny attribution |
| Registration machinery: completeness AST scan, drift test, double-claim guard | **Verified** | event_types_completeness_test.go:29; drift_test.go:82/95/140; soc2_test.go bucket tests |
| Metric reason-only labels | **Verified** | metrics_token.go:85-91 `LabelReason` only; consts.go comment "never on client/subject labels" |

## 3. Requirement-to-test matrix (spec acceptance checks → test plan)

| Spec acceptance check | Status | Evidence / required test |
|---|---|---|
| (1a) scope-combo deny ⇒ exactly 1 `token_policy_denied`, `Reason=scope_combo_blocked`, `Outcome=failure`, `ClientID` correct | **Planned (no test yet)** | New: interfaces/sso test on `TestRcov_TokenPolicy_ScopeComboDenied` pattern + `WithAuditRecorder(audit.New(NewMemorySink(16)))`; assert `ActorID` empty, `policy_name` = rule Name, exactly 1 event |
| (1b) refresh-depth deny ⇒ exactly 1, `ActorID=subject` | **Planned** | New: extend `TestRcov_TokenPolicy_MaxRefreshDepthEnforced` flow with MemorySink; assert `ActorID` = `rcovUsername`, `policy_name` present, wire stays `invalid_grant` |
| (1c) session-cap deny via `createSession` ⇒ exactly 1, `ActorID=userID` | **Planned** | New: `TestRcov_TokenPolicy_MaxActiveSessionsEnforced` flow + MemorySink; assert `ActorID` = userID, `Reason=active_sessions_exceeded` |
| (1d) allow ⇒ 0 events | **Planned** | New: `TestRcov_TokenPolicy_SafeScopesAllowed` flow + MemorySink count = 0 |
| (1e) unwired store / store error (fail-open) ⇒ 0 events | **Planned** | Unwired: existing `_UnwiredIsByteIdentical` flow + sink. Store error: needs a new failing `tokenpolicy.Store` stub — `Store` (tokenpolicy.go:155) is one method; errStore fixture pattern established (interfaces/sso/server_conditional_access_test.go:197 cites `domains/conditionalaccess/evaluate_test.go`'s errStore). Also assert issuance SUCCEEDED (the fail-open observable) |
| `DeniedBy` unit: second of two overlapping rules denies ⇒ `DeniedBy` = second name, `Reason` unchanged; first-deny order; no-deny ⇒ empty; zero-value Name ⇒ empty | **Planned** | New cases in `domains/tokenpolicy/evaluate_test.go` (truth-table style). See F4 for the mixed unnamed/ named first-denier edge |
| `go build`/`go vet`; `TestMaintainability_`/`TestArchitecture_`; `-race` on tokenpolicy/audit/interfaces/sso | **Baseline measured, implementation pending** | All PASS at this revision (see §1); must re-run with the change |
| Wire unchanged: body still generic `invalid_scope`/`invalid_grant` | **Covered by existing tests** | `TestRcov_TokenPolicy_ScopeComboDenied` (:38 `invalid_scope`), `TestRcov_TokenPolicy_MaxRefreshDepthEnforced` (`invalid_grant`) — continue to pin the oracle-safe body; the audit event is the only new DenyReason carrier |
| (2) `KnownEventTypes` registration | **CI-enforced** | `TestKnownEventTypesIsComplete` fails CI if the const is missing from `KnownEventTypes` — verified by reading the AST scan |
| (2) CC7.2 claim, exactly once, not in uncategorized list | **CI-enforced** | `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` fails for an unclaimed entry; `TestControlAreaDefs_NoEventTypeClaimedTwice` fails on double-claim. Design's warning (uncategorized-allowlist escape hatch) verified accurate — `wantUncategorizedEventTypes` (drift_test.go:25) is a manual allowlist that would silently absorb the type |
| (2) CEF/OCSF mappings render readable | **Planned + partially CI-enforced** | New targeted CEF/OCSF rendering tests needed (design plans them). The conformance guard does NOT cover a new type (F2) |
| (2) SOC2 bundle lands in CC7.2, correct `TotalEvents`, absent from Uncategorized | **Partially auto-covered** | `TestBuildSOC2Report_HandlesEveryKnownEventType` (drift_test.go:140) auto-exercises every `KnownEventTypes` entry incl. the new one (sum invariant); add the targeted CC7.2-bucket assertion per design plan (soc2_test.go:54 `_BucketsEventsByControlArea` pattern) |
| (3) `DeniedBy`/`policy_name`/`ActorID` mapping | **Planned** | Covered by (1a)-(1c) + evaluate_test.go cases above |
| (3) Metric regression: reason-only labels unchanged | **Covered by existing tests** | metrics_token.go:85-91 untouched; existing metric tests pin the label set |
| `docs/observability.md` updated | **Process obligation only — NOT CI-enforced** | F1 |

## 4. Findings

### F1 — Medium — Design risk #9 is factually wrong: `make ci` does NOT check `docs/observability.md`

- **Evidence**: Makefile `ci:` target = `fmt vet race build examples proto-lint
  ci-modules config-validate-all modules-check modules-smoke route-contract
  capabilities-check sdk-surface-check profiles-evidence` — `docs-check` is not
  in it. `docs-check` (Makefile:184-202) validates only that
  `docs/error-codes.md`, `docs/openapi.yaml`, `docs/SECURITY.md`,
  `.github/SECURITY.md` exist and cross-reference each other; `observability.md`
  appears nowhere in it. Grep of `checks/*.py`, `cli.py`, and the Makefile for
  `observability.md`: zero hits.
- **Impact**: the design tells reviewers "the new event must be documented in
  the same change or CI fails" — false. The observability.md entry (event
  semantics, `Reason` closed set, `policy_name`, and the name-based attribution
  limitation the design itself wants documented) rests on AGENTS.md §5.6
  discipline alone. If skipped, CI stays green and operators lose the
  documented contract for the new event. The metric-table row (line 52) is
  unaffected, but the Audit section entry is new work.
- **Recommendation**: keep the docs update in the change (contract obligation);
  correct the risk row in the design; optional hardening — extend `docs-check`
  to assert `docs/observability.md` documents every `KnownEventTypes` entry
  (mirrors the drift-test philosophy, closes the whole class of silent
  observability-doc drift).
- **Validation**: `make ci` at the design revision — `docs-check` not invoked
  (target list above); after the change, `grep -c token_policy_denied
  docs/observability.md` ≥ 1.

### F2 — Medium — Design Decision 4(3) omits the `allKnownEventTypes` snapshot; CEF/OCSF gap stays silent

- **Evidence**: `TestConformance_EveryEventTypeHasCEFAndOCSFMapping`
  (auditsink/conformance_test.go:155) iterates `allKnownEventTypes` — a
  hand-transcribed snapshot (:20-150). The file's own comment (:9-18) states:
  "adding a new EventType const does NOT automatically fail this test; it
  silently falls back to the generic CEF/OCSF classification until a maintainer
  adds it here AND to cefEventNames / ocsfEventActivities." The count drift
  check (:157) is `t.Logf`, not an error.
- **Impact**: with only the design's plan (add CEF/OCSF entries), a new type is
  rendered via `humanizeEventType` fallback and the new mappings are never
  exercised by the conformance guard. If a future change deletes the mappings,
  the guard still cannot see it. The design's risk #3 ("missing mappings renders
  the event generic/opaque") is accurate but understates that a dedicated
  conformance test exists and will silently skip the new type.
- **Recommendation**: add `auditspi.EventTokenPolicyDenied` to
  `allKnownEventTypes` in the same change, plus the design's targeted CEF/OCSF
  rendering assertions (CEF name "Token Policy Denied"; OCSF
  `class_uid`/`category_uid`/`type_uid` = authentication/IAM/99 triplet).
- **Validation**: after the change, `go test ./platform/audit/auditsink/
  -run TestConformance_EveryEventTypeHasCEFAndOCSFMapping -v` includes a
  passing `token_policy_denied` subtest; delete the snapshot entry and it fails.

### F3 — Info — SOC2 every-type coverage is already mechanical

`TestBuildSOC2Report_HandlesEveryKnownEventType` (drift_test.go:140) builds a
bundle with one event of EVERY `KnownEventTypes` entry and asserts
`sum(areas)+Uncategorized == EventCount`. Once the type is registered, the
SOC2 path is exercised for free. The design's planned targeted SOC2 test
(CC7.2 bucket + `TotalEvents` + absent-from-Uncategorized) is still worth
adding — it pins the *placement*, which the mechanical test does not.

### F4 — Info — `DeniedBy` zero-value edge: unnamed first-denier beats named second-denier

The design's same-branch rule means: first denying policy has empty `Name`,
second has a `Name` ⇒ `DeniedBy` stays `""` while `Reason` comes from the
first. The design's test list covers single-policy zero-value Name only. Add
the mixed case — it is the sharpest pin against the post-loop "second pass"
regression the design itself flags as the one real trap (a post-loop
implementation would report the named second policy).
- **Acceptance assertion**: `Evaluate(in, []Policy{{BlockScopeCombos: [...], /* no Name */}, {Name: "named", BlockScopeCombos: [...]}})` ⇒ `Deny==true`, `Reason==DenyScopeCombo`, `DeniedBy==""`.

### F5 — Info — fail-open store-error test needs a new fixture

No failing `tokenpolicy.Store` exists in the token-policy tests. `Store`
(tokenpolicy.go:155) is a one-method interface; the repo's errStore pattern
(interfaces/sso/server_conditional_access_test.go:197 →
`domains/conditionalaccess/evaluate_test.go`'s errStore) is the established
shape. The acceptance check (1e) must assert both observables: zero events AND
successful issuance/session (fail-open is the point — AGENTS.md §3).

### F6 — Info — emission ordering on the refresh path is already correct

`EnforceRefreshDepthPolicy` runs at token_refresh.go:116 BEFORE
`refreshIssueAndRotate` — the deny (and thus the event) fires before any
consume/rotation, so the event always reflects a decision that preceded state
change; there is no "event for an already-killed family" ordering hazard. The
scope-combo seam (server_token.go:163-168) likewise gates before grant
dispatch. No ordering test needed beyond the count assertions; a one-line
comment in the helper doc noting "emit before the wire write; decision is
final at that point" is sufficient.

## 5. Prioritized scenario list

Happy paths:
1. Scope-combo deny via `/token` client_credentials ⇒ 400 `invalid_scope`, exactly 1 event (`Reason=scope_combo_blocked`, `Outcome=failure`, `ClientID` set, `ActorID` empty, `policy_name` present).
2. Refresh-depth deny (family at cap) ⇒ 400 `invalid_grant`, exactly 1 event (`ActorID=subject`, `policy_name` present, `Reason=refresh_depth_exceeded`).
3. Session-cap deny at login ⇒ `access_denied`, exactly 1 event (`ActorID=userID`, `Reason=active_sessions_exceeded`).
4. `DeniedBy` attribution: second of two overlapping rules denies ⇒ `DeniedBy` = second name, `Reason` unchanged; first-deny order determinism (permute policy order, assert first wins).

Boundary:
5. Zero-value `Policy.Name` ⇒ event emitted, no `policy_name` metadata, `DeniedBy` empty.
6. Unnamed first-denier + named second-denier ⇒ `DeniedBy` empty (F4).
7. No deny / allow ⇒ 0 events; TTL-clamp-only policies (no deny) ⇒ 0 events.
8. Empty subject seam (scope-combo) ⇒ `ActorID` absent from JSON (`omitempty`), event still complete.

Error/failure:
9. No policy store wired ⇒ 0 events, issuance byte-identical (existing `_UnwiredIsByteIdentical` flow + sink).
10. `Policies()` error ⇒ 0 events AND token/session still issued (fail-open, F5 fixture).
11. `ListByUser` error on session seam ⇒ 0 events, session allowed.
12. Nil recorder ⇒ no panic, no event (helper nil-safe contract).
13. Sink error on `Record` ⇒ issuance + wire unaffected (platform fail-open invariant; existing sink-error tests cover the recorder pipeline, not the seam — count assertion on MemorySink is unaffected).

Race:
14. Concurrent `/token` requests against one MemorySink + policy store ⇒ exactly N deny events for N denies, no double-emit (run `-race`, `-count=10+` per AGENTS.md §5.5 for race fixes — here it is new behavior, `-count=10` on the MemorySink seam tests).
15. Concurrent refresh rotation + depth deny against the same family ⇒ one deny event per denied request, family semantics unchanged (existing rotation tests already race-covered).

Recovery/registration:
16. `KnownEventTypes` entry present ⇒ completeness AST test green; absent ⇒ red (CI self-check).
17. CC7.2 claim present, uncategorized allowlist untouched ⇒ drift test green; type in allowlist instead ⇒ green but SOC2-silent (the design's flagged trap — verify by review, not by test).
18. CEF/OCSF mappings + snapshot entry ⇒ conformance subtest `token_policy_denied` green (F2).
19. SOC2 bundle ⇒ event in CC7.2 with correct `TotalEvents`, absent from Uncategorized (F3).
20. Wire regression: deny detail never reaches body — existing `invalid_scope`/`invalid_grant` assertions stay green.

## 6. CI/manual-suite gaps, flake risks, fixtures, exit criteria

Gaps (what the suite will NOT catch without the additions above):
- Observability-doc drift (F1) — no gate exists; the design's claim that CI
  enforces it is wrong.
- CEF/OCSF mapping gap for NEW types (F2) — conformance guard is snapshot-based.
- `DeniedBy` mixed zero-value edge (F4) — only the proposed test pins it.
- Store-error fail-open event count (F5) — no fixture exists today.
- Scope-combo seam subject absence on subject-bearing grants (auth-code/
  password/device): `ActorID` is empty by seam construction for ALL grants,
  not just client_credentials — document this in observability.md so impact
  analysis is understood as client-attributable for scope-combo denials.

Flake risks: low. The MemorySink assertions are deterministic (single
request per test, `t.Parallel()` safe — MemorySink is per-test, not shared).
The refresh-depth test drives real rotation so it must keep `Generation`
bookkeeping assertions intact; adding the sink must not change request
ordering. No timing-based assertions are proposed. Do NOT add event-count
assertions to existing `-count=1` tests without `-race` runs — the seams are
on the hot path and the design correctly keeps the change to two one-line
calls.

Fixtures needed:
- A failing `tokenpolicy.Store` stub (errStore pattern) for acceptance (1e).
- `audit.NewMemorySink` wiring in the three seam tests via
  `sso.WithAuditRecorder(audit.New(sink))` (precedent: config_audit_test.go:156-158).
- `allKnownEventTypes` snapshot entry + CEF/OCSF table entries (F2).

Exit criteria for the change:
1. All tests in §3's matrix green, including the new MemorySink seam tests,
   `DeniedBy` unit cases, CEF/OCSF rendering tests, SOC2 bucket test; run with
   `-race` and `-count=10` on the seam tests.
2. `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`;
   `make ci` green (incl. nested modules, config, route-contract, modules checks).
3. File budgets respected: server_helpers.go ≤ 500 (+1 line), server_oauth.go
   ≤ 500 (+1 line), recorder_events.go ≤ 500; function budgets intact.
4. `docs/observability.md` Audit section documents the event (F1 — by review,
   not CI), including the `policy_name` non-stability caveat and the
   scope-combo `ActorID`-empty semantics.
5. Wire contract unchanged: `openapi.yaml`/`error-codes.md` untouched, body
   still generic `invalid_scope`/`invalid_grant` (existing tests pin it).

No `.go` files changed for this revision; the baseline gates above are the
measured starting point. The design's evidence is fully substantiated; the
test plan is sound with the additions in F2/F4/F5.
