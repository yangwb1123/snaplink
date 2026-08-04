# Security Review: Multi-Action Playbooks and Explicit Priority (`domains-threataction-playbook-design`)

**Review revision:** design `docs/auto/domains-threataction-playbook-design.md` + source spec `docs/auto/domains-threataction-playbook-spec.md` against the current tree (commit `0b382caf`).
**Checks that ran for this revision:** full reads of `domains/threataction/{registry,executor,policy,admin,actions,threataction}.go`, `memory/policy_store.go`, `sqlite/policy_store.go`, `domains/anomaly/runner.go`, `domains/tokenanomaly/detector.go`, `cmd/sso-server/serverbuildplatform/build_governance.go`, `interfaces/admin/middleware.go`, `interfaces/sso/{sso.go,server_routes_admin.go,accessors_threat.go,options_httpstack.go}`, `config/source.go`, `config/config_snapshot.go`, `docs/openapi.yaml` (ThreatPolicy schema + routes), `docs/error-codes.md`, `docs/config-reference.md`, both store test files, `build_governance_test.go`, and the test doubles in `executor_test.go` / `runner_test.go` / `detector_test.go`. Ran: `go test -run 'TestMaintainability_|TestArchitecture_' .` (PASS), `go test -count=1 ./domains/threataction/...` (PASS, all three packages). Did not run `make ci` or E2E (no code modified; review-only).
**Deliverable location:** `docs/proposals/security_engineer_playbook.md` (this file; replaces the prior round's review of the same design revision, whose findings were re-verified and are carried forward with corrections).

All material claims are labeled **Verified** (checked against code/tests at this revision), **Partial** (confirmed with a gap), **Missing** (claimed but not found), or **Inference** (derived, not directly observable).

---

## 1. Assets, trust boundaries, attacker capabilities, entry points

**Assets.** Threat-policy set (memory map in the stock binary; sqlite `threat_policies` table for library users), in-process rate-limit state (`te.rateLimit` map in the composite), the operator's `default_action` failsafe, session store, refresh-token store + family ledger, cluster bus (`KindSessionSuspended`/`KindTokenRevoked`), audit sink/webhook pipeline, and the audit trail (`threat_action_executed` events).

**Trust boundaries.**
- *Operator config (trusted)* → `threat_action.*` YAML seeds the memory store at boot with **no semantic validation** — **Verified** (`build_governance.go:325` `store.Put` loop; `invalidPolicyReason` is called only from the admin PUT handler, `admin.go:91`). The new `actions`/`priority` fields enter through this unvalidated path too. Forward-compat is safe: `decodeStrictWithFallback` (`config/source.go:260`) warns and lenient-decodes unknown keys, so an old binary loading a new config degrades to legacy semantics (warn + ignore), never a boot error.
- *Admin API bearer (`admin:read` / `admin:write`)* → policy CRUD (`PUT /api/v1/admin/threat-policies/:name` etc.). **Verified** gating: routes mount only when a store is wired (`server_routes_admin.go:135-142`); the `/api/v1/admin/` HTTPMiddleware enforces IP-policy → shared rate-limit bucket → destructive-confirm → bearer+scope → idle-timeout → write-quota before the handler (`middleware.go:315-345`). Oracle-safe `401` unchanged.
- *Login path (untrusted)* → `anomaly.Runner` workers (off-path, bounded 5s ctx) → `Execute`. Failed/anonymous signals can carry `SubjectID: ""`; destructive executors are safe no-ops on empty subject (**Verified** in `actions.go`), and all anonymous spray threats share the `("", type, action)` rate-limit key.
- *Token sweep (scheduler)* → `tokenanomaly.Detector.dispatchThreat` → `Execute`. Evidence is bounded upstream by `maxEvidence*` (`registry.go`).
- *Cluster bus* → best-effort publishes from two executors; receivers are idempotent cache-invalidation arms. No new receiver surface in this design.

**Attacker capabilities.** (a) Unauthenticated network attacker: failed-login sprays → anonymous `brute_force_spray` threats; destructive actions no-op, `notify`/audit still fire, shared budget key caps volume. (b) Credential-holding attacker: victim-scoped signals from their own successful logins, amplified by accumulation (see F1, abuse row 8). (c) `admin:write` holder: full policy CRUD including the new `actions`/`priority` fields — no new privilege, but see F9 (mutations are not centrally audited on the HTTP path). (d) Store-wedging attacker (disk full/permissions): `List` failure → logged fallback to `defaultPolicy()` (fail-open, unchanged — **Verified** `registry.go:93-96`).

**Entry points.** `POST /auth/login*` (anomaly dispatch), token-usage sweep, `GET/PUT/DELETE /api/v1/admin/threat-policies[/:name]` (admin-gated, opt-in mount), config boot path, and — for library users — the sqlite store behind a shared DB file.

---

## 2. Findings (sorted by severity)

### F1 — High (release gate) — Unconditional accumulation silently changes which actions fire for legacy-only multi-policy deployments, contradicting the design's own hard constraint — and the spec's own §2 acceptance check contradicts Decision 3

**Evidence (Verified).** Today exactly one policy executes per threat: `matchPolicy` returns the first match in store order (`registry.go:152-166`) and `Execute` has one action path. Both stores order by name (`memory/policy_store.go:37`, `sqlite/policy_store.go:87` `ORDER BY name`). Design Decision 3 replaces this with `matchPolicies` → flatten → dedup **unconditionally**, including when every matching policy uses only the legacy `action` field. The design header's hard constraint ("policies that never use the new fields must evaluate exactly as they do today") and its failure-mode list (which flags only the audit-volume consequence) never name this case, where the executed action *set* changes — not just the event count. The spec's own problem statement (§1) confirms overlapping legacy policies with different actions exist in deployments ("they must invent multiple near-duplicate policies … only one of them can ever fire").
Additionally, **the spec's §2 acceptance check contradicts the final design**: it asserts "p1{priority:10, action:suspend} and p2{priority:20, action:notify} → `Execute` runs suspend only (first-match)". Under Decision 3 both policies match and accumulate → `[suspend, notify]`. An implementer running the spec's acceptance literally fails it; the design never marks §2's first-match acceptance as superseded.

**Exploit preconditions and steps.** (1) A legacy deployment with two overlapping policies with different actions — the documented "catch-all `notify` + specific `suspend`" pattern, where a catch-all named `a-catchall` (notify) name-sorts ahead of `z-impossible-travel` (suspend). (2) Today: only `notify` fires. (3) Rolling upgrade to the new executor. (4) Both policies now match and accumulate → `suspend` executes (session suspension, cluster-bus event, audit event, rate-limit budget consumption) with **zero config change and no log**.

**Impact.** Security-control-relevant behavior change at the response layer, in the direction of *more* actions: session suspension and refresh-family revocation may begin firing against real users (availability regression), an observation-only policy can silently become destructive, and per-(subject,type,action) budgets are consumed differently. No error or log distinguishes new behavior from old.

**Remediation.** Decide and pin in the design before implementation:
1. **Gate accumulation on new-field usage (recommended).** If no matching policy uses `Actions` or `Priority`, keep today's first-match semantics byte-identically; if any matching policy uses the new fields, the whole set evaluates under `(priority, name)` + accumulation. Note this gate means a legacy policy *in a mixed set* also changes behavior — the hard-constraint sentence must be narrowed to "policy sets that never use the new fields", with the mixed-set semantics documented.
2. If accumulation stays unconditional: narrow the constraint text, add the legacy multi-match case to the failure-mode list, emit a boot-time warning when two or more seeded legacy-only policies can overlap, and mark spec §2's first-match acceptance as superseded (with the corrected `[suspend, notify]` expectation).

**Regression test** (pins whichever resolution is chosen): seed two overlapping legacy single-action policies with different actions, name order such that the catch-all sorts first; assert `Execute` returns exactly one result (gated) or the documented N results + boot warning (ungated). Land beside `TestThreatExecutors_PolicyMatchRoutesToHandler` in `registry_test.go`. Second test: the §2 scenario with priorities → asserts the final documented semantics.

### F2 — Medium — `default_action` silent takeover: a catch-all policy quietly disables the operator's fail-safe

**Evidence (Verified).** `WithDefaultAction`/`defaultPolicy()` are the zero-match fallback only (`registry.go`; `build_governance.go` wires it as "the no-match fallback only"). The design's own ladder example adds a catch-all `{severity: warn, action: notify, priority: 20}` that matches *every* threat — making a `default_action: suspend` failsafe unreachable for everything. The design documents this (failure mode 9) and defers the warning as out of scope.

**Exploit preconditions and steps.** (1) Operator runs `default_action: suspend` as a failsafe. (2) Operator adds the design's recommended catch-all notify policy, believing it stacks. (3) Every threat now matches the catch-all; `suspend` stops firing with no error, no log, and audit events that look normal.

**Impact.** Silent loss of the documented fail-safe security control — defender-blindness at the response layer.

**Remediation.** Bring the warning in scope: in `BuildThreatAction`, when `defaultAct != ActionNoop` and any seeded policy has empty `type`/`severity`/`conditions` (a catch-all), log a warning naming the policy. ~10 lines, no new `Err*`, no API change.

**Regression test.** `BuildThreatAction` with a catch-all policy + non-noop default → warning logged once at build time; no warning when no catch-all exists or the default is `noop`.

### F3 — Medium — Mixed-version store operation silently degrades playbooks during rolling upgrades (write-side strip + read-side legacy evaluation)

**Evidence (Verified).** sqlite `Put` overwrites the whole `policy_json` blob (`sqlite/policy_store.go`); a pre-upgrade binary's struct round-trips only known fields, so a pre-upgrade replica `PUT`-ing a row containing `priority`/`actions` silently strips them. The read side is worse: `unmarshalPolicy` ignores unknown JSON fields, so an **old replica evaluating** a new-format row sees `Actions: nil, Priority: 0` — an `actions`-only policy evaluates as **noop** (threat detected, no action fires) without any admin write. New-format config is likewise ignored by old binaries (lenient fallback, `config/source.go:260`).

**Preconditions and steps.** (1) A multi-replica deployment sharing the sqlite store (the only cross-replica-consistent backend). (2) Rolling upgrade; a pre-upgrade replica reads an `actions`-only row and re-PUTs it (GET→edit→PUT scripts, old admin UI), or simply evaluates a threat against it. (3) The playbook silently degrades to noop/legacy single action, on one or all replicas.

**Impact.** A security action vanishes from the response with zero signal; a stripped row is byte-identical to a legitimately legacy row, so the new side cannot detect it. Scope note: the **stock binary wires only the memory store** (`build_governance.go:323`; no `threataction/sqlite` import anywhere in `cmd/` or `interfaces/` — **Verified**), and the memory store is per-replica by construction (admin CRUD is not replicated), so this bites sqlite-backed library deployments and any future stock wiring.

**Remediation.** (a) Document "no admin PUTs against a shared store during the mixed-version window" in `docs/config-reference.md`, not just the PR. (b) New-side regression test pinning the round-trip of the new fields. (c) Optional (cheap now, expensive later): stamp a `policy_version` into the blob so a future migration has a detection hook.

**Regression test.** Extend `TestThreatPolicyStore_RoundTripNestedFields` (`sqlite/policy_store_test.go`): `Put` a policy with `Priority` and a multi-entry `Actions` → `Get`/`List` after reopen return both intact; plus a known-consequence pin: marshal the policy with an old-shape struct (or strip the fields) and assert the legacy-evaluation result, documenting the mixed-version degradation.

### F4 — Low — `actions` entries containing `""` are rejected at admin validation but bypass it via config YAML; execution-time handling is unpinned

**Evidence (Verified).** `invalidPolicyReason` runs only on the admin PUT path (`admin.go:91`); the YAML seed path validates nothing (`build_governance.go:325`) — the "no validate-on-save hook" reality `matchType`'s doc admits. The design rejects `""` entries at admin validation (correctly noting `validAction("") == true` at `admin.go:129`) but never specifies execution-time handling of a YAML-seeded list like `["", "suspend"]`.

**Impact.** If `""` is dispatched instead of dropped, `handlers[""]` is missing and — under the new error contract — every matching threat produces a spurious logged+audited `OK:false, "no handler registered"` result with `threat.action=""` on the audit event, deviating from noop semantics. Operator-trusted input, so Low; must be pinned.

**Remediation.** State in the resolution rule: entries equal to `""` are dropped from the plan exactly like `ActionNoop` — never dispatched, never audited — regardless of entry path.

**Regression test.** Registry test with a store-seeded (config-path) policy holding `actions: ["", "suspend"]` → exactly one `suspend` result, no `""` audit event, no error.

### F5 — Low — "Both set → Actions wins, not rejected" is narrower than stated: an invalid legacy `action` alongside a valid `actions` list is still 400

**Evidence (Verified).** `invalidPolicyReason` validates `policy.Action` unconditionally (`admin.go:110`), so `{"action":"garbage","actions":["suspend"]}` is rejected even though `Actions` wins at execution. The design's "Both set → `Actions` wins. Not rejected." overclaims; its migration guidance ("additive updates must not start failing") is inconsistent with the implementation sketch.

**Impact.** None security-wise (rejection is fail-closed), but the migration guidance is wrong as written: a client migrating to `actions` must keep its legacy `action` value valid.

**Remediation.** Keep the reject (fail-closed, recommended) and fix the design wording, or skip legacy validation when `Actions` is set — decide and pin.

**Regression test.** Admin test: both-set with invalid legacy action → 400; both-set with valid legacy action → 200.

### F6 — Low — No cap on `actions` list length; the admin body limit is operator-set and unlimited by default

**Evidence (Verified).** No length bound in the design. `WithBodyLimit` default is 0 = unlimited (`options_httpstack.go:60`); the stock build sets no path-specific limit for the admin API. Execution cost is nonetheless bounded: dedup caps the plan at the 6-value action enum, so the residual surface is decode-time allocation of a large array on an admin-authenticated endpoint.

**Remediation.** Cap `len(Actions)` in `invalidPolicyReason` (e.g. ≤ 64 — anything above the enum cardinality is a mistake after dedup) so the admin and YAML paths share an explicit bound; optionally document the body-limit default for the admin API.

**Regression test.** Admin PUT with a 1000-entry `actions` list → 400 `ErrInvalidPolicy` with the length reason.

### F7 — Info — "The existing cross-store parity test is extended" is inaccurate: no such test exists today

**Evidence (Verified).** `sqlite/policy_store_test.go` has CRUD, nested-fields round-trip, first-match ordering (sqlite-only), reopen, ping, and version tests; `memory/policy_store_test.go` is a parallel suite. Nothing compares memory vs sqlite `List` order. The design's parity-by-construction argument (single exported comparator) is sound, but the parity test must be **created**, not extended — and since the sqlite store is the only cross-replica-consistent backend (F3), it is the sole guard against the design's own failure mode 5 (store-order divergence silently changing which policy wins per replica).

**Remediation.** Create `TestThreatPolicyStores_ParityOrdering`: same policy set (mixed priorities 0/10/10/20, duplicate priorities with out-of-order names, one legacy `Priority:0` policy) into both stores → `reflect.DeepEqual` on `List` order; plus the regression case that with priorities stripped, order equals pure name order.

### F8 — Info — `docs/error-codes.md` `invalid_policy` row (line 1010) enumerates current reasons; the new reasons (`priority must not be negative`, per-entry `actions` reasons) are not listed

**Evidence (Verified).** The row enumerates `action`-enum, negative-rate-limit, and `conditions.operator` checks. Docscheck validates sentinel existence only, so no gate fails. No new `Err*` is introduced (reuse of `ErrInvalidPolicy` + reason), so AGENTS.md's error-code rule is not triggered — the row simply becomes incomplete.

**Remediation.** Optional one-line row refresh in the same change; or explicitly accept the drift. Also note for the PR body: `threat_action_executed` is outside the `auditreport` classification (pre-existing; the completeness guard covers only `auditspi`-declared consts), and the change multiplies per-threat events of that type — worth stating next to the audit-volume changelog note.

### F9 — Info — HTTP admin mutations of threat policies are not centrally audited; the change raises the consequence of that gap

**Evidence (Verified).** The admin `recorder` audits gated **gRPC** RPCs only (`middleware.go:76-86`, `137-141`, `257-280`); the HTTPMiddleware gates but does not Record (`315-345`), and `HandleAdminPutPolicy`/`HandleAdminDeletePolicy` emit no audit event. Pre-existing, but with `priority` + accumulation, an un-audited PUT can silently change *which* actions fire for real threats (F1 semantics), not just a single action value.

**Remediation.** Optional; not required for this change. If taken up, a new admin-change event type is a new audit event → requires `auditreport` classification per AGENTS.md §4, and the threat-policy handler would need the recorder threaded through. Document in the PR body at minimum.

### F10 — Info — Panic path should carry the recovered value in the audit trail

**Evidence (Inference from the design).** The design mandates an Error log + `OK:false` audit event for a recovered panic but does not pin `ActionResult.Detail`. Without `Detail: "panic: <value>"`, the audit event is `OK:false` with an opaque reason and forensics require correlating log timestamps.

**Remediation.** Specify `Detail: "panic: <recovered value>"` (via `fmt.Sprintf("%v", rec)`) in the recovered result so the existing `MetaKeyThreatDetail` carries it.

**Regression test.** Registry test injecting a panicking `ExecuteFunc`: assert `OK:false` whose Detail contains the panic value, and that sibling actions still ran.

---

## 3. Abuse-case table

| Abuse case | Path | Verdict |
|---|---|---|
| Identity spoofing via policy CRUD | Forge admin bearer → PUT a policy that suspends/revokes arbitrary subjects | **Mitigated** — HTTPMiddleware bearer + method-scoped `admin:read`/`admin:write`, IP-policy, shared rate bucket, idle-timeout, write-quota before the handler; routes mount only when a store is wired; oracle-safe `401 invalid_token` unchanged. New fields add no privilege. |
| Replay / duplicate execution of destructive actions | Same threat seen by N replicas, or repeated within a window | **Bounded (pre-existing)** — per-process in-memory rate limiter unchanged; per-action `RateLimitKey` (`threataction.go:134`) unchanged so existing budget state survives; dedup guarantees ≤1 execution per action per threat per replica (plan capped at the 6-value enum). Multi-replica N× remains a pre-existing per-process-limiter property. |
| Cross-tenant access | Tenant A admin edits tenant B's policies; or a threat for tenant B acts on tenant A sessions | **No new surface** — policy store is global and operator-scoped, not tenant-scoped; executors act on `SubjectID`/`ClientID`/`FamilyID` only; `Threat.TenantID` is never populated by either caller (unchanged). Residual: relies on global uniqueness of `SubjectID`/`ClientID` (unchanged assumption). |
| Proxy/header forgery | Forge XFF/forwarded headers to steer detection or reach the new fields | **No new surface** — no new header consumers; threat fields come from detectors, not request headers; policy fields are admin/config input. |
| Resource exhaustion | Huge `actions` array; many matching policies; audit flood | **Bounded** — dedup caps the plan at the 6-value enum; audit events per threat ≤ distinct actions (≤6), each evidence-bounded (32 keys / 128 / 1024, `registry.go`); rate limits per (subject,type,action) cap repeat storms. Residual: decode-time allocation on the admin endpoint is unbounded by default body limit (F6); config path bypasses list validation (F4). |
| Sensitive-data leakage | Evidence/audit metadata exfiltration via the new fields | **Mitigated** — new fields are enum strings + an int; `recordAudit` evidence bounds unchanged; `MetaKeyThreatAction` carries only the action name; no new event type. Panic Detail (F10) may embed handler-supplied values — handler code is operator-supplied, Low. |
| Silent security-control loss | Catch-all policy shadows `default_action`; mixed-version PUT/evaluation strips playbook fields | **Weakness** — F2 and F3. Both are documented-but-silent; F2's warning was deferred out of scope and should be in scope. |
| Unannounced behavior change on upgrade | Legacy-only multi-policy deployment starts executing accumulated actions | **Weakness** — F1. The only finding that changes *what fires*, not just *how much is recorded*; gate or warn. |
| Stolen-credential amplification | Attacker with victim's password triggers victim-scoped signals → suspend/revoke/step-up fire | **Inherent to the feature (unchanged, amplified by F1)** — destructive mappings on success-path signals are attacker-triggerable availability damage and consume the victim's rate-limit budget (defender-blindness for genuine later threats). Accumulation makes one compromised login trigger more distinct actions. Recommend documenting the NIST 800-63B §5.2.2 lockout-DoS class in `docs/config-reference.md`; severity-floor gating remains a requirements item. |
| Admin mutation without audit trail | `admin:write` holder silently reorders priorities or rewrites `actions` | **Weakness (pre-existing, amplified)** — F9: HTTP admin PUT/DELETE of threat policies emits no audit event; with priority+accumulation the blast of an un-audited mutation grows. |
| Malformed config fail-closed | `actions: [""]`, `priority: -5`, unknown action names via YAML | **Bounded** — config path never validated (unchanged); negative `priority` sorts highest (operator input only); unknown actions → `OK:false` "no handler registered", logged+audited, never propagated; `""` entries must be pinned as drop-like-noop (F4). All fail toward no-action, never toward broader matching. |

---

## 4. Positive controls verified, residual risks, prioritized validation plan

**Positive controls verified.**
- **Interface change is free and compile-time contained.** Both production callers discard the `ActionResult` and check `err` only — `anomaly/runner.go:225`, `tokenanomaly/detector.go:419` (**Verified**). All implementers enumerated in the design's blast-radius table exist. One correction to the table: the three `cmd/sso-server/serverbuildplatform/build_governance_test.go` sites (lines 516, 544, 569) **consume** the return value (`result.Action != ... || !result.OK`), unlike the production callers — they must move to slice indexing and become the primary "legacy payload → one result" regression assertions.
- **Budget discipline is real.** `Execute` is exactly 50 lines (`registry.go:86-135`); the maintainability/architecture gates pass at this revision; `registry.go` (301/500 lines) has headroom. The orchestrator split is mandatory, not optional.
- **Execution is bounded by construction.** Dedup caps the plan at the 6-value action enum; no unbounded loop is expressible through either store.
- **Oracle-safe and credential surfaces untouched.** No new `Err*`, no new endpoints, no new audit event type; admin error mapping unchanged (decode → `ErrInvalidRequest`; semantic → `ErrInvalidPolicy` + reason; missing → `ErrPolicyNotFound` 404; store failure → `ErrInternal` 500). openapi `required` relaxation (`[name, enabled, action]` → `[name, enabled]`) is the safe direction — stricter-runtime validation (`invalidPolicyReason`) remains the real gate.
- **Fail-open/fail-closed discipline preserved.** Per-action failures become logged+audited `OK:false` results, never propagated; store `List` failure still falls back to `defaultPolicy()` with a log; per-action `recover` mirrors the established `inspectSafe` pattern (`runner.go:177`) and strictly narrows today's blast radius (sibling actions survive a panic). Panic remains visible (Error log + `OK:false` audit; Detail pinning is F10).
- **Byte-identical guarantees hold for the cases they can.** Single-match legacy configs, `actions: []` fallback, noop-only lists, and the all-noop edge rule reduce to today's branches; name tie-break keeps `(priority, name)` total (name is the PK). The gap is exactly F1 (multi-match legacy sets).
- **Rate-limit state survives the change.** `RateLimitKey` and `allow()` semantics are unchanged; dedup-before-rate-limit is a faithful generalization (first-match meant windows were never policy-independent).

**Residual risks.**
- **F1 is the release gate**: the legacy multi-match accumulation question must be decided (gated vs warned) and test-pinned before implementation, or the change violates its own hard constraint — and the spec's §2 acceptance check must be superseded.
- Rate limiter remains in-memory and per-process (multi-replica N× is pre-existing); sqlite store is library-only in the stock binary, so cross-replica policy consistency exists only for library users (F3/F7).
- `Threat.TenantID` remains unpopulated by both detectors; policies stay global; subject-ID global uniqueness remains an assumption (same as today).
- `default_action` takeover (F2) and blob stripping (F3) remain silent unless the recommended warnings/documentation land.
- HTTP admin policy mutations are un-audited (F9, pre-existing, amplified).

**Prioritized validation plan.**
1. **F1 first** — decide gating vs warning; add the legacy multi-match regression test; amend the spec's §2 acceptance check. This decides whether the design's hard constraint is true.
2. **F2** — catch-all-shadow warning in `BuildThreatAction` + test; **F3** — new-side round-trip + known-consequence degradation tests; **F7** — create the cross-store parity test with mixed priorities.
3. **F4** — pin `""`-entry drop semantics with a config-path registry test; **F5** — pin the both-set validation rule; **F10** — pin panic Detail.
4. **F6** — `actions` length cap; **F8** — optional error-codes row refresh; **F9** — PR-body note.
5. Design-plan acceptance tests (per-action sibling isolation, rate-limited action inside a list, dedup attribution, legacy byte-identity incl. the three `build_governance_test.go` sites, `priority:-1` rejection) and — before handoff — `go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`, `go test -race ./domains/threataction/... ./domains/anomaly/... ./domains/tokenanomaly/...`, `go test ./docs/docscheck/`, and `make ci`.

**Bottom line.** The design's threat model, oracle-safe discipline, and budget/parity mechanics are sound and verified against the code; the interface change is genuinely free at both production call sites, and execution is bounded by construction. One decision blocks merge — F1: unconditional accumulation silently changes which actions fire for legacy-only multi-policy deployments, contradicting the design's own hard constraint, and the spec's own §2 acceptance check contradicts the final design. F2 and F3 are the two documented-but-silent security-control-loss paths with cheap, test-pinnable mitigations that should be in scope rather than deferred. The remaining findings are Low/Info spec-completion items.
