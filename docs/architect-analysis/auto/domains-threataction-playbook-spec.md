# Requirements Specification: `domains/threataction` — Multi-Action Playbooks and Explicit Priority

Expansion direction: **2. 多动作响应 Playbook 与显式优先级（组合动作 + 排序语义）**
(from `docs/auto/domains-threataction-analysis.md`).

Scope: `domains/threataction` (policy model, composite executor, admin CRUD
validation, both stores) plus its public contracts (`docs/config-reference.md`,
`docs/openapi.yaml` schema `ThreatPolicy`). Wire compatibility with existing
config/admin payloads is a hard requirement: every change below must accept
today's single-`action` payloads byte-identically and preserve current
behavior for policies that do not use the new fields.

Three improvements, ordered by dependency: (1) intra-policy ordered action
list, (2) explicit priority replacing accidental name ordering, (3)
inter-policy accumulation so playbooks compose across policies. (2) and (3)
build on (1); each is independently shippable.

## 1. Ordered multi-action playbook per policy (`actions: []`)

**Name**: Replace the single `Action` field with an ordered action list so one
matched policy can express "suspend + revoke family + notify + step-up MFA".

**Problem**: The package contract promises composition, but the data model and
executor can only produce one action per threat. Operators cannot express a
real escalation playbook ("critical impossible_travel → suspend, revoke
family, notify admin, step up MFA") as one policy; they must invent multiple
near-duplicate policies with the same match predicate, and only one of them
can ever fire.

**Evidence**:
- `domains/threataction/threataction.go` — `Action` doc comment: "Multiple
  actions can result from one Threat (suspend session AND notify admin)",
  contradicted by `ActionResult` carrying a single `Action` and
  `RateLimitKey(subjectID, threatType, action)` already being per-action
  keyed (composition was anticipated at the rate-limiter but not the model).
- `domains/threataction/policy.go` — `ThreatPolicy.Action Action` (single
  value field; dual yaml/json tags).
- `domains/threataction/registry.go` — `ThreatExecutors.Execute` returns one
  `ActionResult` and runs exactly one handler: early-return on
  `act == ActionNoop || act == ""`, then a single rate-limit check, single
  handler dispatch, single `recordAudit`. Package doc's FAIL-OPEN promise —
  "A single broken executor ... must not block session-revocation executors
  from acting on the SAME threat" — is unfulfillable by construction.
- `domains/threataction/admin.go` — `invalidPolicyReason`/`validAction`
  validate exactly one action; nothing accepts a list.

**Proposed behavior**:
- Add `Actions []Action` (`yaml:"actions,omitempty" json:"actions,omitempty"`)
  to `ThreatPolicy`. Resolution rule: `len(Actions) > 0` → use `Actions`,
  else legacy `Action` (kept, documented as shorthand for `actions: [action]`).
  Empty action entries are rejected at admin validation; a list containing
  `noop` treats `noop` as "contributes nothing" without suppressing siblings
  (documented).
- `ThreatExecutors.Execute` iterates the resolved list **in order**; for each
  action: existing per-action rate limit (`allow()` + `RateLimitKey` unchanged),
  handler dispatch, `recordAudit` (per action, so `MetaKeyThreatAction`
  distinguishes each). Per-action FAIL-OPEN: one action's handler error is
  logged and audited, remaining actions still execute — the same-threat
  sibling guarantee the package doc already claims.
- Return shape: `Execute` returns `[]ActionResult` (one entry per action
  attempted) so callers/admin see every outcome, not just the first.
- Extend `invalidPolicyReason` in `admin.go` to validate `actions` (known
  enum members, no empty entries); `validAction` is reused per entry.
- Contract updates in the same change: `docs/openapi.yaml` `ThreatPolicy`
  schema (`actions` array property, `action` marked legacy shorthand; example
  `[suspend, revoke, notify]`), `docs/config-reference.md`
  `threat_action.policies` row.

**Acceptance check**:
- Admin PUT of `{"actions":["suspend","notify"]}` with both handlers wired →
  `Execute` returns two `ActionResult`s, both `OK:true`, and two
  `threat_action_executed` audit events whose `threat.action` metas are
  `suspend` and `notify`.
- A notify handler returning an error → the `suspend` result is still
  `OK:true` (sibling isolation), and the error is logged + audited.
- Legacy payload `{"action":"suspend"}` (config YAML and admin JSON) behaves
  byte-identically to today: one result, one audit event.
- A rate-limited action inside a multi-action list is audited as
  `OK:false, "rate-limited"` and the remaining actions still run.

## 2. Explicit `priority` replaces accidental name ordering

**Name**: Add a `Priority` field; policy resolution orders by
`(priority asc, name asc)` instead of the current implicit `name` sort.

**Problem**: First-match-wins is ordered by policy *name* — an identifier
that doubles as the admin CRUD path parameter — so behavior is decided by
lexicographic accident, not operator intent. Adding a policy named
`"a_critical"` silently changes which policy wins over an existing
`"z_critical"`; there is no way to express "this policy takes precedence over
that one" without renaming (which is also the CRUD key, so renaming is a
delete+create with a window of no coverage).

**Evidence**:
- `domains/threataction/registry.go` — `Execute` doc/comment: "first-match
  wins, ordered by name"; `matchPolicy` doc: "Policies are ordered by name
  for deterministic behavior".
- `domains/threataction/memory/policy_store.go` — `List` sorts by
  `Name` for "deterministic first-match ordering".
- `domains/threataction/sqlite/policy_store.go` — `List` sorts by name to
  "match memory.ThreatPolicyStore.List" (both stores must change in lockstep
  or replicas diverge).
- `domains/threataction/admin.go` — `invalidPolicyReason` validates action /
  rate-limit / condition operator only; no ordering concept exists anywhere
  in the CRUD path.
- `docs/openapi.yaml` — `ThreatPolicy` schema description: "Evaluated by
  ThreatExecutors (first-match in name order)".

**Proposed behavior**:
- Add `Priority int` (`yaml:"priority,omitempty" json:"priority,omitempty"`)
  to `ThreatPolicy`. Semantics: **lower value = higher precedence** (like
  `iptables`/conditional-access precedence conventions); default 0.
  Ordering: `(Priority asc, Name asc)` — name remains the deterministic
  tie-break, so evaluation is still total and reproducible.
- Both stores sort by `(Priority, Name)` in `List`; the composite executor
  keeps consuming the store order, so ordering lives in one documented place
  per store and stays identical across `memory` and `sqlite` backends.
- `matchPolicy` (first-match-wins) is unchanged in shape — only the order it
  consumes changes, so existing single-match behavior is preserved except
  where the operator explicitly sets priorities.
- `invalidPolicyReason`: reject `Priority < 0` (a negative priority can only
  be a mistake, mirroring the existing negative rate-limit rejection).
- Contract updates: `docs/openapi.yaml` `ThreatPolicy` (`priority` property,
  description rewritten to "first-match in (priority, name) order"),
  `docs/config-reference.md`.

**Acceptance check**:
- Two policies both matching the same threat: `p1{priority:10, action:suspend}`
  and `p2{priority:20, action:notify}` → `Execute` runs `suspend` only
  (first-match); with priorities swapped it runs `notify` only.
- Equal priorities → name-ordered tie-break, identical result before and
  after the change for policies that never set `priority` (regression
  guarantee: existing deployments with no `priority` anywhere behave
  byte-identically).
- `memory` and `sqlite` stores return the identical `List` order for the same
  policy set (existing parity test pattern in
  `domains/threataction/sqlite/policy_store_test.go` extended with mixed
  priorities).
- Admin PUT of `{"priority":-1}` is rejected with `ErrInvalidPolicy`.

## 3. Multi-policy accumulation: all matching policies fire in priority order

**Name**: Evaluate **all** matching policies (ordered by priority), merging
their action lists with per-action dedup, instead of first-match-wins-only;
`default_action` remains the zero-match fallback.

**Problem**: One threat can only ever trigger one policy, so severity-graded
response ladders cannot be expressed as a *set* of overlapping policies
("generic warn → notify" catch-all + "impossible_travel critical → suspend"
specific rule should both act on a critical impossible-travel threat), and
`WithDefaultAction` cannot stack with concrete policies — it only fires when
zero policies match. Playbooks therefore require duplicating every common
action into every specific policy (schema bloat, drift risk), the exact
failure mode improvement 1 alone does not fix.

**Evidence**:
- `domains/threataction/registry.go` — `matchPolicy` returns a single
  `*ThreatPolicy`; `Execute` has exactly one policy path (match → rate-limit
  → handler → audit); `defaultPolicy()`/`WithDefaultAction` are reachable
  only when `matchPolicy` returns nil.
- `cmd/sso-server/serverbuildplatform/build_governance.go` —
  `BuildThreatAction` wires `threataction.WithDefaultAction(...)` as the
  no-match fallback only (line ~338), confirming the non-stacking semantic.
- `domains/threataction/policy.go` — `ThreatPolicy.Match` already supports
  overlapping matches by design (type wildcards + severity filters +
  evidence conditions are composable predicates, but the executor discards
  all but the first hit).
- `domains/threataction/memory/policy_store.go` / `sqlite/policy_store.go` —
  `List` returns the full ordered set; nothing consumes more than one entry.

**Proposed behavior**:
- Replace `matchPolicy` (returns one) with `matchPolicies` (returns all
  matching policies in the store's `(priority, name)` order). `Execute`
  resolves each matching policy's action list (per improvement 1) and
  flattens them **in policy-priority order**.
- **Dedup by action**: the same action (e.g. two policies both yielding
  `suspend`) fires at most once per threat; the highest-priority policy that
  contributes the action owns its rate-limit window and audit attribution
  (the per-action `RateLimitKey` already makes windows shared, so this is a
  strict reduction in duplicate executions, never a bypass).
- Per-action FAIL-OPEN from improvement 1 is preserved across policies: a
  failing action from policy N does not skip actions from policy N+1.
- `default_action`/`WithDefaultAction` semantics are **unchanged** (zero
  matching policies only) and documented as such: catch-all stacking is
  expressed by adding a low-priority catch-all *policy*, which also makes
  the intent visible in `List`/admin UI instead of hiding it in a config
  default. Explicitly not changing this keeps existing deployments'
  fail-safe default behavior.
- Contract updates: `docs/config-reference.md` (policy `priority` row plus
  an example ladder: catch-all `severity: warn` notify at priority 20 +
  specific `impossible_travel` `critical` suspend at priority 10),
  `docs/openapi.yaml` schema description ("all matching policies apply in
  (priority, name) order; duplicate actions dedup to the highest-priority
  policy").

**Acceptance check**:
- Threat `{type:impossible_travel, severity:critical}` with catch-all
  `{severity:warn, action:notify, priority:20}` + specific
  `{type:impossible_travel, severity:critical, actions:[suspend,revoke],
  priority:10}` → exactly three action results (`suspend`, `revoke`,
  `notify`) in that order, three audit events, and both stores produce the
  same ordering.
- Two matching policies both yielding `suspend` → exactly one `suspend`
  execution and one `suspend` audit event (dedup), attributed to the
  higher-priority policy.
- Threat matching no policy → `default_action` still applies exactly as
  today (regression); a threat matching only the catch-all → catch-all's
  actions fire alone.
- A failing `revoke` handler in the middle of the ladder → `notify` still
  executes (cross-policy sibling isolation), with the failure logged and
  audited.
