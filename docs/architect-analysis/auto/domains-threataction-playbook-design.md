# Design: `domains/threataction` — Multi-Action Playbooks and Explicit Priority

Source: `docs/auto/domains-threataction-playbook-spec.md`. Scope: policy model,
composite executor, admin CRUD validation, both policy stores, and the public
contracts (`docs/openapi.yaml` `ThreatPolicy`, `docs/config-reference.md`).
Hard constraint: today's single-`action` payloads (config YAML and admin JSON)
must keep working byte-identically, and policies that never use the new fields
must evaluate exactly as they do today.

Three improvements, each independently shippable, in dependency order:
(1) intra-policy ordered action list, (2) explicit `priority` replacing the
accidental name sort, (3) inter-policy accumulation with per-action dedup.

Verified baseline facts the design relies on:

- `ThreatExecutors.Execute` (registry.go) is exactly **50 lines** — at the
  line-budget ceiling. The new executor **must** be an orchestrator over
  extracted helpers, not a grown loop.
- The composite `*ThreatExecutors` implements `threataction.ThreatExecutor`,
  which is consumed through the interface by `anomaly.Runner` (runner.go:225)
  and `tokenanomaly.Detector` (detector.go:419). **Both call sites discard the
  `ActionResult` and only check `err`** — the interface return-shape change
  below is free at every caller.
- `executor.go`'s interface doc already promises "zero or more Actions" and
  "Returns the actions actually taken and any errors per action" — the single-
  value signature is an implementation lag, not an intended contract.
- Both stores sort `List` by name today; sqlite stores the whole policy as a
  JSON blob (`policy_json`), with an explicit precedent of *not* normalizing
  sub-structs into columns ("nothing ever queries by SQL WHERE clause").
- `validAction("")` returns true by design (empty = noop is a meaningful,
  accepted value at runtime and in the admin API).
- No new `Err*` is needed: admin validation reuses `ErrInvalidPolicy` with new
  reason strings, so `docs/error-codes.md` is untouched.

---

## Decision: `ThreatPolicy` gains `Actions []Action`; legacy `Action` is shorthand

Add to `domains/threataction/policy.go`:

```go
Actions   []Action `yaml:"actions,omitempty" json:"actions,omitempty"`
Priority  int      `yaml:"priority,omitempty" json:"priority,omitempty"`
```

Resolution rule (single place, a method on `ThreatPolicy` or a package func —
**not** re-implemented at each call site): `len(Actions) > 0` → use `Actions`;
else use the legacy `Action`. Consequences of the rule, each a decision:

- **Both set → `Actions` wins.** Not rejected at validation. A client doing
  additive updates (`{"action":"suspend"}` → `{"action":"suspend","actions":[...]}`
  during migration) must not start failing; documented precedence is
  predictable.
- **Neither set → noop**, identical to today's accepted empty-action policy
  (`validAction("")` semantics preserved; openapi `required` must drop
  `action`, see the admin decision).
- **`noop` inside a list** contributes nothing and does not suppress siblings:
  it is dropped from the execution plan, not executed, not audited.
- **A list whose entries are all `noop` (or empty after resolution)** behaves
  byte-identically to legacy `action: noop`: one `ActionResult{Action: Noop,
  OK: true}` result, no audit event. This keeps the regression surface at
  exactly zero for the only list a sloppy operator could write that is
  semantically empty.
- An **explicit `actions: []`** is accepted and falls back to legacy `Action`
  per the resolution rule — no special validation branch needed.
- Empty **string entries** inside a non-empty list are rejected at admin
  validation (a list containing `""` is a mistake; the empty-means-noop
  tolerance applies only to the singular legacy field). Note the subtlety:
  `validAction("")` returns true, so the entry check must test `entry == ""`
  explicitly before reusing `validAction`.

Wire compatibility: config YAML seeding (`config.ThreatActionConfig.Policies`)
and admin JSON go through the same struct; old payloads unmarshal with
`Actions == nil`, so the legacy path is taken and behavior is byte-identical.

## Decision: `ThreatExecutor.Execute` returns `[]ActionResult` — one slice per threat

Change `executor.go`:

```go
Execute(ctx context.Context, threat Threat, policy ThreatPolicy) ([]ActionResult, error)
```

The concrete leaf executors in `actions.go` (Suspend, RevokeFamily, StepUpMFA,
Challenge, Notify) each return a one-element slice; `ExecuteFunc` adapts the
same way. This is mechanical — the bodies are unchanged, only the return
wrapping changes.

Blast radius (compile-time enforced, fully enumerated):

| Site | Change |
|---|---|
| `executor.go` interface + `ExecuteFunc` | signature change |
| `actions.go` — 5 concrete executors | return `[]ActionResult{...}` |
| `registry.go` composite | new signature (see executor decision) |
| `anomaly/runner.go:225`, `tokenanomaly/detector.go:419` | **none** — both discard the first return, check `err` only |
| `executor_test.go` `mockExecutor`, `registry_test.go` literals, `anomaly/runner_test.go` `recordingThreatExecutor`, `tokenanomaly/detector_test.go` `failingThreatExecutor` | signature updates |

Error contract, tightened to match the package's own doc ("FAIL-OPEN: all
errors are logged but never propagated"):

- Per-action failures — handler error, no handler registered, rate-limited —
  are logged and audited **inside the composite** and never returned as `err`.
  Today "no handler registered" propagates an error that the caller re-logs;
  under the new contract the composite logs once and the caller's `err != nil`
  branch stops double-logging. No information is lost (each failure is in the
  result slice with `OK:false`).
- The returned `error` is reserved for evaluation-level failure. Today the
  only such path (store `List` error → log, fall back to default policy)
  already returns nil, so `Execute` effectively returns nil error in every
  path; the `error` return is kept for interface stability and future
  catastrophic paths.
- Consequence to document in the PR: `tokenanomaly`/`anomaly` "executor
  failed" log tests exercise test doubles, not the composite; the composite's
  own failure logging is covered by new registry tests.

This is the **only breaking change in the design**, and it is contained,
compiler-enforced, and free at every production call site.

## Decision: Execution = `matchPolicies` → ordered flatten → per-action dedup → execute

Replace `matchPolicy` (first match) with `matchPolicies` (all matches, in the
store's `(priority, name)` order; store `List` failure still falls back to
`defaultPolicy()` with a log, exactly as today).

Plan construction (one extracted helper):

1. For each matching policy, in store order, take its resolved action list
   (Decision 1), in list order.
2. Flatten into an ordered sequence of `(action, owningPolicy)` pairs.
3. **Dedup by action, first occurrence wins** — the highest-priority policy
   that contributes an action owns it. The owner's `RateLimitPolicy` feeds
   `allow()` (per-action `RateLimitKey` unchanged: `subjectID\x00type\x00action`),
   the owner is the `ThreatPolicy` passed to the handler and to `recordAudit`.
   This also collapses intra-policy duplicates (`actions: [suspend, suspend]`).
4. Drop `noop` entries; if the plan is empty, return the single legacy noop
   result (Decision 1 edge rule).

Execution (second extracted helper): for each `(action, owner)` pair, in plan
order — `allow()`; dispatch via `handlers[action]`; `recordAudit` per action
(unchanged shape, so `MetaKeyThreatAction` distinguishes siblings and legacy
single-action audit events are byte-identical); on any error, log, keep the
`OK:false` result, **continue to the next action** — the same-threat sibling
guarantee the package doc already promises, now real.

**Dedup happens before rate limiting.** A rate-limited owner produces one
`OK:false, "rate-limited"` result and a lower-priority duplicate does not
retry. This is not a behavior change but a faithful generalization: today only
the first matching policy executes, so per-action windows were never
independent across policies — `RateLimitKey` was already shared.

**Per-action panic isolation.** Wrap each handler call in a `recover`
(mirroring `anomaly.Runner.inspectSafe`), converting a panic into an
`OK:false` result + log + audit, and continue. Rationale: today a panicking
handler drops the single action of that threat (the runner's per-event
recover saves the worker); with lists, an unprotected panic would drop **all
remaining actions of the threat** — a strict widening of the blast radius
that violates the package's own same-threat guarantee. The recover is small,
follows an established repo pattern, and only changes behavior for panicking
handlers (from "whole threat lost" to "that action lost, siblings run").

**Budgets.** Current `Execute` is exactly 50 lines. The new composite must be
an orchestrator calling the two extracted helpers (plan, execute); both
helpers are flat loops, well under the cyclo ≤ 15 / 50-line ceilings.
`registry.go` has ~200 lines of headroom under the 500-line file budget.

## Decision: `Priority` — lower value wins; `(priority asc, name asc)` total order

`Priority int`, `omitempty`, default 0, **lower = higher precedence** (the
iptables / conditional-access convention, matching the severity ladder mental
model: 10 beats 20). Name remains the deterministic tie-break, so evaluation
stays total and reproducible, and policies that never set `priority` keep
today's pure-name order **byte-identically** — the regression guarantee for
existing deployments.

`matchPolicies` consumes store order and never sorts itself; ordering lives in
exactly one documented place per store. Both stores must change in lockstep or
memory-backed and sqlite-backed replicas diverge on which policy wins.

## Decision: Storage — no schema change; ordering in Go with a shared comparator

Rejected: adding a `priority INTEGER` column to sqlite. It would denormalize
the value already inside `policy_json`, require a migration v2, force `Put` to
write two sources of truth for one value, and buy nothing — the executor loads
the full policy list and matches in Go; nothing queries priority by SQL. This
is exactly the stated precedent of the sqlite store's own design note for
`RateLimit`/`Conditions` ("normalizing them into columns would only add
migration surface with no query benefit").

Adopted: both `List` implementations sort in Go by `(Priority, Name)` using a
**single exported comparator in the domain package** (e.g.
`threataction.SortPolicies([]ThreatPolicy)`) so parity between `memory` and
`sqlite` is guaranteed by construction, not by parallel maintenance. The
sqlite `List` drops its `ORDER BY name` (rows are sorted in Go regardless);
`Get`/`Put`/`Delete`, the blob layout, and the schema are unchanged — old rows
unmarshal with `Priority: 0, Actions: nil` and get legacy semantics. The
existing cross-store parity test in
`domains/threataction/sqlite/policy_store_test.go` is extended with mixed
priorities as belt-and-braces.

## Decision: Admin validation and the OpenAPI contract

`invalidPolicyReason` (admin.go) gains, in order:

1. `Priority < 0` → reject: `"priority must not be negative"` — mirrors the
   existing negative-rate-limit rejection; a negative priority can only be a
   mistake.
2. Each `Actions` entry: reject `""` explicitly, then reuse `validAction` per
   entry with the existing enum reason string (noop allowed — it is dropped
   at execution, per Decision 1).

Accepted without rejection (documented, not validated): both `action` and
`actions` set (Actions wins), `actions: []` (falls back to legacy), noop-only
lists, `action` absent (noop policy — today's accepted empty-action shape).

`docs/openapi.yaml` `ThreatPolicy` schema:

- New `actions`: array of the existing enum, example `[suspend, revoke,
  notify]`; description: executed in array order.
- New `priority`: integer, default 0, "lower value = higher precedence".
- `action` description gains "legacy shorthand for `actions: [action]`".
- `required` changes from `[name, enabled, action]` to `[name, enabled]` —
  keeping `action` required would reject the new `actions`-only payloads.
  This is a safe relaxation direction; a policy with neither field is a valid
  noop policy, consistent with today's accepted empty-action admin payload.
- Schema description rewritten: "all matching policies apply in (priority,
  name) order; duplicate actions dedup to the highest-priority policy".

`docs/config-reference.md`: `threat_action.policies` row gains `priority` and
`actions`; add the ladder example (catch-all `severity: warn` → `notify` at
priority 20, specific `impossible_travel` `critical` → `[suspend, revoke]` at
priority 10); `default_action` row gains the explicit note that catch-all
stacking is expressed with a low-priority catch-all policy, not by changing
`default_action`. No `docs/error-codes.md` change (no new `Err*`).

## Decision: `default_action` semantics are frozen — zero matches only

`WithDefaultAction` and `defaultPolicy()` remain the zero-match fallback,
unchanged. Explicitly **not** extended to stack with matched policies.
Rationale: `default_action` is the fail-safe default for existing deployments;
changing when it fires is a regression boundary, and the new tools make
stacking expressible without touching it — a low-priority catch-all policy
(empty `type`/`severity`/`conditions`) matches every threat and composes with
specifics through Decision 3. It is also visible in `List`/admin UI instead of
hidden in a config default.

Documented interplay: adding a catch-all policy makes `default_action`
unreachable for every threat (the catch-all matches everything). That is the
intended takeover mechanism; operators who want the old default behavior
simply do not add a catch-all.

---

## Failure modes and what could break the design

1. **Interface change is the only break, and it is compile-time contained.**
   Every implementer and call site is enumerated above; the two production
   call sites discard the result. The residual risk is a future implementer
   of `ThreatExecutor` outside this repo — the signature change is a
   source-compat break for them, accepted and documented in the PR.

2. **Audit volume changes are observable by design.** A multi-action threat
   now emits N `threat_action_executed` events (one per action) instead of 1.
   Dashboards and alert rules that count these events will see multiples —
   intended, but call it out in the changelog. Rate limits per
   (subject, type, action) cap the damage; the per-action `RateLimitKey` is
   unchanged, so existing rate-limit state is not invalidated by the change.

3. **Dedup-before-rate-limit has a subtle consequence.** If the
   highest-priority owner of an action is rate-limited, the lower-priority
   duplicate does not get a second chance. This is the documented rule
   (one execution per action per threat); operators wanting independent
   windows for the same action cannot express it — the shared `RateLimitKey`
   already forbade it in spirit.

4. **Mixed-version admin writes can drop new fields.** The sqlite store
   overwrites the whole `policy_json` blob on `Put`. A pre-upgrade server
   reading a row that contains `priority`/`actions` and then `PUT`-ing it
   (its struct round-trips only known fields) silently strips the new fields.
   Pre-existing property of the blob store, newly consequential; document
   "do not run mixed-version admin PUTs against a shared store during
   rolling upgrade".

5. **Store-order divergence between memory and sqlite** would silently change
   which policy wins per replica. Prevented by the shared comparator (parity
   by construction) plus the extended parity test. The sqlite `List` must not
   reintroduce a conflicting SQL ordering.

6. **Panic handling shifts one level.** A panicking handler is now converted
   to an `OK:false` audit event by the per-action recover instead of panicking
   out of `Execute` and being caught by the runner's per-event recover. Sibling
   actions now run where the whole threat previously died — strictly safer,
   but the audit trail is the only place the panic is visible; log at Error.

7. **The `Execute` line budget is already exhausted.** The orchestrator split
   is mandatory, not optional — a naive grow-in-place implementation fails
   `TestMaintainability_` and must not be shipped. Extraction also keeps
   cyclo ≤ 15 (the loop is flat, but plan construction + dedup + fallback
   branches add up).

8. **`required` relaxation in openapi** is a doc-contract change in the safe
   direction (fewer required fields). Generated strict-request validators
   will accept more payloads, never fewer. The runtime validation (`ErrInvalidPolicy`)
   remains the real gate and is unchanged in mechanism.

9. **`default_action` takeover is silent.** Once a catch-all policy exists,
   `default_action` stops firing with no warning. The config-reference note is
   the mitigation; an alternative (warn when both a catch-all policy and a
   non-noop `default_action` are configured) was considered and deferred — it
   needs a wiring-time log that crosses `build_governance.go`, outside this
   change's scope.
