# Design: token-policy denial audit events — `token_policy_denied` end-to-end

Design counterpart to `docs/auto/domains-tokenpolicy-direction2-spec.md`. Covers the API
surface, storage model, failure modes, and breakage risks for the three improvements.
Every claim in the spec was re-verified against current code before writing this doc:

- `enforceTokenPolicy` deny branch (interfaces/sso/server_helpers.go:99-104): metrics +
  `s.logger.Info`, zero `s.auditor` involvement; `wireCodeForPolicyDeny` at line 110.
- `sessionPolicyCapExceeded` deny branch (interfaces/sso/server_oauth.go:184-190, guarded by
  `dec.Reason != tokenpolicy.DenyActiveSessions`): same metrics + log pattern, no audit;
  reached only from `createSession` (server_logout.go:357).
- `platform/audit` has no token-policy event type; `KnownEventTypes` (auditspi/event_types.go:233)
  lacks any entry; the CC7.2 bucket (auditreport/control_areas.go:157-169) already holds
  `EventRefreshTokenReuse` / `EventFAPIComplianceViolation` — the natural peer group.
- `PolicyDecision` (domains/tokenpolicy/evaluate.go:16-32) has `Deny`/`Reason`/`EffectiveTTL`/
  `RenewAfter` but no rule identity; `Policy.Name`'s doc claims "governance display + audit"
  with zero consumers.
- Precedents confirmed: `RecordDeviceCodeDecision` nil-safe helper (recorder_events.go:80),
  `audit.RecordRefreshRotationVelocityExceeded(s.auditor, ctx, ...)` called from
  server_helpers.go:487, `EventFromRequest` (handler_helpers.go:37) carries W3C trace +
  TenantID enrichment, `Event` has `Type/Outcome/ActorID/ClientID/Reason/Metadata` fields,
  `HandlerContext = core.HandlerContext` (interfaces/sso/aliases.go:110).

Layer map:

```text
composition (cmd/sso-server, serverbuildplatform, interfaces/sso)
  → domains (tokenpolicy)          # pure; must NOT import platform/audit
  → platform (audit, auditspi, auditreport, auditsink, metrics), shared
```

Dependency rule driving every decision: `domains/tokenpolicy` stays I/O-free and import-pure;
the event constant/helper live in `platform/audit` (+`auditspi`); the emission sits in
`interfaces/sso`, exactly where `RecordFAPIViolation` / `RecordRefreshRotationVelocityExceeded`
already run.

## Decision 1: `token_policy_denied` event type, SPI alias, and nil-safe helper

### API surface

**1a. Event type constant** in `platform/audit/auditspi/event_types.go`, in the
"Refresh token rotation security events" group beside `EventRefreshTokenReuse` (line 189):

```go
EventTokenPolicyDenied EventType = "token_policy_denied"
```

**1b. SPI alias** in `platform/audit/aliases_spi.go` beside the other aliases (line 118):

```go
EventTokenPolicyDenied                    = auditspi.EventTokenPolicyDenied
```

**1c. Helper** in `platform/audit/recorder_events.go` (354/500 lines — room; the
`RecordDeviceCodeDecision` precedent is at line 80):

```go
// RecordTokenPolicyDenied emits one token_policy_denied event per governance
// deny decision. reason is a closed-set tokenpolicy.DenyReason string;
// policyName (operator-authored rule name, bounded cardinality) lands in
// metadata only when non-empty. Nil-safe like every helper here.
func RecordTokenPolicyDenied(rec *Recorder, ctx core.HandlerContext, clientID, subjectID, policyName, reason string)
```

Field mapping (all through `EventFromRequest` + `SetMeta`, never `e.Metadata = ...`):

| Event field | Value | Rationale |
|---|---|---|
| `Type` | `EventTokenPolicyDenied` | new type |
| `Outcome` | `OutcomeFailure` | a deny is a failed issuance |
| `ClientID` | caller-supplied | which client was blocked |
| `ActorID` | subject (may be empty) | empty = client_credentials-style seam honestly has no subject |
| `Reason` | closed-set `DenyReason` string | `scope_combo_blocked` / `refresh_depth_exceeded` / `active_sessions_exceeded` |
| `Metadata["policy_name"]` | rule `Name`, only when non-empty | operator-authored, bounded by rule count |
| trace/tenant | inherited from `EventFromRequest` | W3C TraceID/SpanID, TenantID enrichment unchanged |

Signature order follows the `RecordFAPIViolation(rec, ctx, clientID, ruleID, detail, mode)`
convention: recorder, context, identifiers, then detail strings.

### Why platform/audit and not the domain

`domains/tokenpolicy` must not import `platform/audit` (architecture layer + purity of the
`Evaluate` core). The helper lives beside its peers in `platform/audit/recorder_events.go`;
both deny seams already have `s.auditor` in scope and a one-line-call precedent
(server_helpers.go:487).

## Decision 2: `PolicyDecision.DeniedBy` — rule identity in the pure domain

### API surface

Add one field to `PolicyDecision` (domains/tokenpolicy/tokenpolicy.go):

```go
// DeniedBy is the Name of the first matching policy whose deny fired, for
// audit attribution ONLY (mirrors Reason's oracle-safe doc). Empty when no
// deny, or when the denying policy has no Name. Not used in matching.
DeniedBy string
```

### Implementation constraint (the one real trap)

`Evaluate` (evaluate.go:20-32) sets `Reason` inside the first-deny branch:

```go
if !d.Deny {
    if r := denyReason(p, in); r != DenyNone {
        d.Deny = true
        d.Reason = r
        d.DeniedBy = p.Name   // same branch, same policy, same iteration
    }
}
```

`DeniedBy` MUST be assigned in that same branch. A post-loop pass would either pick the last
denying policy (wrong — policy order determinism says first wins) or require a second loop
over the same inputs (fragile). `Evaluate` stays pure, deterministic, I/O-free; the truth
table remains fully table-testable.

Empty `Name` (zero-value policy) yields empty `DeniedBy`, which the helper maps to "no
`policy_name` metadata" — honest absence, not fabrication.

## Decision 3: Emission wiring at both deny seams

### Placement

**Seam A — `enforceTokenPolicy`** (server_helpers.go:99-104). Insert one line between the
existing metric/log calls and the `ctx.JSON` wire write, using `dec` already in scope:

```go
audit.RecordTokenPolicyDenied(s.auditor, ctx, in.ClientID, in.Subject, dec.DeniedBy, string(dec.Reason))
```

**Seam B — `sessionPolicyCapExceeded`** (server_oauth.go:184-190). Insert one line after the
reason guard (`!dec.Deny || dec.Reason != tokenpolicy.DenyActiveSessions`) and before
`return true`:

```go
audit.RecordTokenPolicyDenied(s.auditor, ctx, clientID, userID, dec.DeniedBy, string(dec.Reason))
```

### Placement rules (enforced invariants)

- Emission sits inside the deny branch only: after `dec.Deny` is confirmed (Seam A) or after
  the reason guard (Seam B). Allow, fail-open (store error), and unwired-store paths never
  reach it — zero events, byte-identical default-off.
- Wire write stays the LAST statement of the deny branch in Seam A; response body remains
  `wireCodeForPolicyDeny(dec.Reason)` output — generic `invalid_scope` / `invalid_grant`,
  oracle-safe, unchanged.
- Exactly one event per deny decision: the scope-combo and refresh-depth seams funnel
  through the single deny branch of `enforceTokenPolicy`; the session seam is a disjoint
  decision point (login-time cap, one decision per request). No shared helper exists to
  double-emit.
- Budget: `server_helpers.go` is at 493/500 and `server_oauth.go` at 481/500 — the entire
  change to both files is the two one-line calls above, the same shape as line 487. Nothing
  else may be added to either file in this change.

### Caller-supplied subjects per seam

| Seam | client | subject | policy_name |
|---|---|---|---|
| scope-combo (`denyTokenScopeCombo`) | `in.ClientID` | `in.Subject` (empty — seam never sets it) | `dec.DeniedBy` |
| refresh-depth (`EnforceRefreshDepthPolicy`) | `in.ClientID` | `in.Subject` (carried) | `dec.DeniedBy` |
| session cap (`sessionPolicyCapExceeded`) | `clientID` | `userID` | `dec.DeniedBy` |

## Decision 4: End-to-end registration — KnownEventTypes, SOC2, CEF/OCSF, docs

Four registrations in the same change; each is load-bearing for CI or for the event being
useful downstream:

1. `KnownEventTypes` (auditspi/event_types.go:233) gains `EventTokenPolicyDenied: {}` —
   otherwise `TestKnownEventTypesIsComplete` (AST scan of `event_types*.go`) fails CI.
2. `controlAreaDefs` CC7.2 "Anomaly and lockout monitoring" (auditreport/control_areas.go:
   157-169) gains `audit.EventTokenPolicyDenied` — governance denials are the same evidence
   class as refresh-reuse / FAPI violations. Do NOT add the type to the explicit
   uncategorized list; that would make the drift test pass while silently hiding the event
   from the SOC2 report.
3. Sink mappings:
   - `auditsink/cef.go` (beside line 82-85): `auditspi.EventTokenPolicyDenied: "Token Policy Denied"`.
   - `auditsink/ocsf.go` (beside line 130-133): `{ocsfClassAuthentication, ocsfCategoryIAM, 99, "Token Policy Denied"}` — same class/category/type-uid triplet as refresh-reuse.
4. `docs/observability.md` Audit section (lines 66+): document the type — one event per
   deny on issuance/refresh/session paths, `Reason` from the closed `DenyReason` set,
   metadata key `policy_name`, wire stays generic `invalid_scope`/`invalid_grant`.

`TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` then requires exactly-once
claims: the CC7.2 entry satisfies it. `TestControlAreaDefs_NoEventTypeClaimedTwice` guards
against double-claim.

## Storage model

No new storage, no schema change, no migration, no new interface.

- `tokenpolicy.Store` is untouched: `Policies(ctx) ([]Policy, error)` with the existing
  `Memory*` implementation; the store remains the only policy source. `Policy.Name` is
  already in the YAML/JSON shape — it is simply now *consumed* by the audit path.
- The event is a row in the existing audit pipeline: `EventFromRequest` → `Record` →
  configured sinks (CEF/OCSF/webhook/syslog, hash chain, SOC2 evidence report). No new
  sink; no change to recorder buffering or the hash-chain continuity.
- Cardinality is the platform audit invariant, per-dimension:

| Dimension | Bound | Source |
|---|---|---|
| `Reason` | closed set of 3 | `DenyReason` consts |
| `policy_name` | operator-authored rule count | `Policy.Name` (config, not request input) |
| `ClientID` / `ActorID` | existing identity dims | caller seams |
| trace/tenant | inherited | `EventFromRequest` |

Explicitly NOT stored: raw scopes, client lists, session counts, request input. The metric
`sso_token_policy_denials_total` keeps its reason-only labels (`metrics_token.go:85-91`) —
no client/subject labels, ever.

## Failure modes

| Failure | Behavior | Why it is safe |
|---|---|---|
| Nil recorder (`s.auditor == nil`) | helper short-circuits; no event, no panic | documented nil-safe contract of every `Record*` helper |
| Store `Policies()` error (either seam) | fail-open before evaluation; no event; token/session issued | governance outage never blocks minting, never manufactures deny records (AGENTS.md §3) |
| `ListByUser` error (session seam) | fail-open; no event; session allowed | same stance as tenant-suspension / risk-scorer |
| No store wired | zero events; issuance byte-identical to today | default-off invariant |
| Allow decision | zero events | emission is inside the deny branch only |
| Sink failure on `Record` | audit sink errors fail open with logging; issuance + wire unaffected | platform audit invariant (AGENTS.md §3) |
| Empty subject (scope-combo seam) | `ActorID` empty; `policy_name` still present | honest absence — seam has no subject by construction |
| Empty `Policy.Name` | no `policy_name` metadata; event still emitted | attribution degrades gracefully, no fabrication |
| Canceled request context between emit and wire write | event recorded, no response | event reflects the decision that was made |
| Recorder `Record` synchronous latency | deny path gains helper-call latency before the error response | same hot-path pattern as line 487; deny path already failing the request |

## What could break the design

1. **File budgets are the tightest gate.** `server_helpers.go` (493/500) and
   `server_oauth.go` (481/500) leave room for exactly the two one-line calls. Any review
   feedback that adds logging, renames, or extracts helpers *inside these files* crosses the
   gate. Everything else (helper, registration, docs) lives in files with headroom
   (recorder_events.go 354/500). If the change grows, extract the deny-branch body into a
   new function in a roomier file — but that itself must fit the 50-line function budget.
2. **`DeniedBy` in the wrong branch.** Setting it after the loop (or in a second pass)
   silently changes attribution semantics from "first denying policy" to "last" — the
   spec's determinism acceptance test (`DeniedBy` = second rule when the second rule fires)
   would catch it, but only if that test is written. The same-branch constraint must survive
   any future refactor of `Evaluate`'s first-deny logic.
3. **Registration drift.** Missing `KnownEventTypes` entry fails `TestKnownEventTypesIsComplete`
   (good). Missing the CC7.2 claim while *adding the type to the uncategorized list* would
   pass the drift test but silently hide governance denials from the SOC2 report — review
   must verify the uncategorized list is untouched. Missing CEF/OCSF mappings renders the
   event as a generic/opaque entry in those sinks.
4. **Attribution is name-based, not ID-based.** `DeniedBy` carries `Policy.Name`, a display
   label with no stable identifier. Renaming a rule breaks joins against historical events;
   reordering overlapping deny rules changes `DeniedBy` while `Reason` stays identical.
   Adding a rule ID is out of scope (schema change, admin API surface) — document the
   limitation in `docs/observability.md` so operators don't treat `policy_name` as stable.
5. **Cardinality creep.** The bounded-dimension rule (no scopes, no client lists, no request
   input in metadata) is enforced only by review discipline. A future edit "helpfully"
   adding scopes to the event would violate the platform audit invariant and the reason-only
   metric design. The acceptance tests pin the field set via `MemorySink` assertions.
6. **Wire regression.** The deny detail must never reach the HTTP body. `wireCodeForPolicyDeny`
   is the single mapping and is unchanged; the existing wire tests (generic
   `invalid_scope`/`invalid_grant`) guard it. The audit event is the ONLY new carrier of
   `DenyReason`.
7. **Double emission.** Scope-combo and refresh-depth share `enforceTokenPolicy`'s single
   deny branch, and the session seam is a separate decision — disjoint today. A future seam
   that calls both `enforceTokenPolicy` and `sessionPolicyCapExceeded` for one decision, or
   a helper call added to an allow path, would break "one deny ⇒ one event". The
   `MemorySink` count assertions (exactly 1) pin this.
8. **Seam-guard placement.** In `sessionPolicyCapExceeded` the emission must sit AFTER the
   `dec.Reason != DenyActiveSessions` guard. Placing it before would emit for deny reasons
   that seam cannot legitimately produce (and would fire if a future dimension is added to
   that seam) with wrong semantics.
9. **Docs gate.** `make ci` checks `docs/observability.md`; the new event must be documented
   in the same change or CI fails. Same for the auditreport/soc2 and CEF/OCSF unit tests
   that pin the new mappings.

## Test plan (maps to the spec's acceptance checks)

- `domains/tokenpolicy/evaluate_test.go`: second-of-two overlapping rules denies ⇒
  `DeniedBy` = second rule name, `Reason` unchanged; first-deny order determinism; no deny
  ⇒ empty; zero-value Name ⇒ empty.
- `interfaces/sso` (`audit.NewMemorySink` style): scope-combo deny ⇒ exactly 1
  `token_policy_denied`, `Reason=scope_combo_blocked`, `Outcome=failure`, `ClientID` set,
  `ActorID` empty, `policy_name` present; refresh-depth deny ⇒ exactly 1 with
  `ActorID=subject`; session-cap deny via `createSession` ⇒ exactly 1 with `ActorID=userID`;
  allow ⇒ 0; unwired store ⇒ 0; store error (fail-open) ⇒ 0.
- `platform/audit`: `TestKnownEventTypesIsComplete`,
  `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`,
  `TestControlAreaDefs_NoEventTypeClaimedTwice` green; CEF render contains
  "Token Policy Denied"; OCSF render has the `class_uid`/`category_uid`/`type_uid` triplet;
  SOC2 bundle with the event lands in CC7.2 with correct `TotalEvents`, absent from
  Uncategorized.
- Gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `go test ./domains/tokenpolicy/ ./platform/audit/... ./interfaces/sso/ -race`, then
  `make ci` (nested modules, docs, module validation).

## Contract and documentation updates (AGENTS.md §5)

| Change | Location |
|---|---|
| Event type `token_policy_denied` | `platform/audit/auditspi/event_types.go` + `platform/audit/aliases_spi.go` |
| Emit helper | `platform/audit/recorder_events.go` |
| Two deny seams (one line each) | `interfaces/sso/server_helpers.go`, `interfaces/sso/server_oauth.go` |
| `PolicyDecision.DeniedBy` | `domains/tokenpolicy/tokenpolicy.go` + `evaluate.go` |
| SOC2 / CEF / OCSF | `platform/audit/auditreport/control_areas.go`, `platform/audit/auditsink/cef.go`, `ocsf.go` |
| Observability contract | `docs/observability.md` Audit section |

Wire contract (`openapi.yaml` / `error-codes.md`) is unchanged: the response remains the
generic `invalid_scope` / `invalid_grant`. The `DenyReason` doc comment ("metric label +
audit detail ONLY") becomes true for the first time — no edit needed, but the log lines at
both seams stay (server-side detail is allowed; the audit stream is the new carrier).

No `.go` files were changed for this design; no build gates were run.
