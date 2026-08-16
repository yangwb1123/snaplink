# Design: operator apply mode — SSOConfigDrift drives the declared-baseline write

Bounded design for the second step of the deferred-backlog "Declarative
multi-cluster configuration governance" promotion: the `sso-operator`
(`cmd/sso-operator`) gains an **opt-in, explicitly-approved apply mode** that
calls the B10-3 server-side declared-baseline write endpoint
(`POST /api/v1/admin/config/apply`) — and deliberately does NOT drive
rollback. All file/line references were verified against executable code
before writing. Report-only behavior for CRs that never opt in must remain
byte-identical (Decision 6).

Status quo (implemented, unchanged by this design):

- The server exposes the declared peer-config baseline write path:
  `platform/configaudit/handlers.go:161` `HandleApply` (`admin:write`, hard
  `?approve=true` gate at `:256`, split-brain sha256 digest check at `:198`
  → 409 `config_apply_conflict`, redacted-only storage) and `:215`
  `HandleRollback` (409 `config_apply_no_previous`). Design:
  `docs/design/config-apply-mode.md`. The apply writes a NEW applied-config
  baseline on the target; it NEVER mutates the target's RUNNING config
  (that boundary is explicit in config-apply-mode.md Decision 2).
- The operator (`cmd/sso-operator`) reconciles `SSOConfigDrift`:
  `controller/ssoconfigdrift_controller.go:110` Reconcile →
  `runCheck` (`:200`: validateBaseURL → resolveBearer → GET A
  `/config/running` → POST B `/config/cluster-diff` → structural
  validation) → `applyResult` (`:376`, drift fields preserved on failure,
  never reset) → `Status().Update` → `RequeueAfter` (`requeueInterval`
  `:406`: shortRequeue 30s on failure, else the CR's PollInterval, default
  5m). Its doc.go explicitly lists "NO config apply" as a non-goal and
  names what an apply mode would need: an explicit opt-in + approval gate
  and a NEW write-capable endpoint on B (now shipped by B10-3).
- `GET .../config/running` already serves a REDACTED snapshot
  (`platform/configaudit/handlers.go:68` `Redact(running)`), so the
  snapshot the operator forwards to apply carries no secret-shaped values
  (Decision 5).

Goal of this change: `SSOConfigDrift` may, when its spec opts in AND a
one-shot approval is present, POST the fetched peer snapshot to ClusterB's
`/api/v1/admin/config/apply?approve=true` (with the digest and the spec's
reason), and record the outcome in `Status.Apply`. Canary rollout,
automated remediation, GitOps reconciliation, and operator-driven rollback
all remain non-goals (Decision 4).

---

## Decision 1 — Authority model

**Opt-in is a Spec field; approval is a one-shot annotation; reason is a
Spec field.**

| Concern | Mechanism | Why |
|---|---|---|
| Master switch | `spec.apply.enabled` (bool, default false) | Opt-in is *persistent desired state*: it must survive `kubectl apply`/GitOps diffs, be visible in `kubectl get -o yaml`, and changing it must take effect immediately. A Spec field bumps Generation → the controller's `GenerationChangedPredicate` (`ssoconfigdrift_controller.go:432`) reconciles right away. Zero value `false` ⇒ existing CRs behave byte-identically. |
| One-shot approval | annotation `sso.snaplink.io/apply-approve: "true"` | Approval is *transient, per-action state*, not desired state — it must never be committed to GitOps (an `apply`-happy YAML file is an accident waiting to happen). Annotations do NOT bump Generation, which gives two properties for free: (a) adding the annotation cannot self-trigger a reconcile loop, and (b) the approval takes effect on the next *scheduled* reconcile, so apply cadence is naturally bounded by PollInterval (Decision 2). The controller CONSUMES the annotation (deletes it) after a successful apply, so the standing-approval hazard is impossible: one approval authorizes exactly one apply. |
| Mandatory reason | `spec.apply.reason` (string) | The server hard-refuses a blank reason (`handlers.go:172-178`, `invalid_request` — "an unexplained governance mutation is itself an audit finding"). The reason is a standing justification for apply mode and belongs in declarative spec; the controller forwards it verbatim. Admission-time CEL (`!has(self.apply) || !self.apply.enabled || has(self.apply.reason) && self.apply.reason != ""`) plus a controller-side guard (Decision 7, assertion 8) close the blank-reason hole at both layers. |

Rejected alternative — `spec.apply.approved bool`: a Spec bool is standing
state. Left true it re-applies on every poll where drift exists. That is
exactly the "reconcile ClusterB to match ClusterA" auto-remediation this
controller's doc.go names as a non-goal; worse, apply does not change B's
running config (server contract), so the drift report would persist and the
operator would write an identical new baseline version on every tick —
version-chain spam with no effect. Making it one-shot would require the
controller to mutate its own spec (bumping Generation → reconcile loop).
The annotation is the minimal one-shot primitive.

Rejected alternative — approval as a body/query flag on the CR's own
"apply request": there is no per-CR pending-apply subresource; that would
be new CRD machinery. The annotation rides the object's existing metadata.

**Who may approve** — setting the annotation requires `update`/`patch` on
`SSOConfigDrift`, exactly the same principal set that can change the spec.
Kubernetes RBAC has no per-annotation granularity, so the approval cannot
be narrowed below CR-write — this is already covered by doc.go's "Trust
model" section: write access to `SSOConfigDrift` MUST be no broader than
read access to Secrets in the same namespace. The approval changes nothing
about what the controller can DO (it already holds both tokens); it only
gates whether a write is issued, so the existing trust boundary is
unchanged, not widened.

## Decision 2 — Timing

**Trigger** — in a single reconcile, after the check phase succeeds, the
apply phase runs iff all of:

1. `spec.apply.enabled == true`;
2. the approval annotation is present and `== "true"`;
3. the check succeeded (`!checkResult.failed`);
4. the last diff was non-empty (`checkResult.driftDetected`).

No condition → no apply call, `Status.Apply` untouched.

**Throttle — at most one apply per approval.** The approval is consumed
(annotation deleted) immediately after a SUCCESSFUL apply, in the same
reconcile. Because annotation changes don't bump Generation, the next
approval cannot take effect before the next scheduled reconcile
(PollInterval, default 5m, or an in-flight shortRequeue loop) — so apply
rate ≤ 1 per approval and approval latency ≤ PollInterval by construction.
This is the design's answer to "don't call apply every round": the only
state that could make every round call apply is a standing approval, and
no standing approval can survive a successful apply.

**Failure retry — shortRequeue (30s), consistent with check failures.**
An apply failure sets `failed` for `requeueInterval` (`:406`) exactly like
a check failure: `result.failed || (applyOutcome != nil && applyOutcome.failed)`.
The approval is NOT consumed on failure, so the next reconcile (30s later)
re-runs the full check AND retries the apply. This matches the existing
fail-open retry doctrine for transient blips (a rolling restart, a
momentarily-expired token) and keeps one retry cadence instead of inventing
a second. A persistent failure is visible in `Status.Apply` and the
operator can intervene (fix the server, or delete the annotation to stop
retries). Note a persistent 409 is effectively unreachable from a
self-consistent operator (the operator computes the digest over the exact
snapshot it sends, so the server's recomputation always matches — Decision
4 of config-apply-mode.md targets stale/mixed human submissions), so the
short retry is defensive, not hot.

**Relationship with the drift check** — apply never short-circuits the
check: the check always runs first, its result is always written to
`Status` (drift fields updated on success, preserved on failure — unchanged
semantics from `applyResult` `:376`), and only then is apply attempted.
Apply failure does not roll back or suppress the drift report (Decision 5).

## Decision 3 — Result reporting

**New `status.apply` sub-struct**, coexisting with the existing drift
fields (they are written independently):

| Field | Type | Content |
|---|---|---|
| `state` | string | `applied` \| `conflict` \| `rejected` \| `failed` — empty when apply never attempted |
| `lastAttemptAt` | date-time | when the last apply attempt completed |
| `versionID` | string | the new applied-baseline version id from the 200 response (`version` field) |
| `digest` | string | sha256 hex of the snapshot submitted (evidence; a hash, never content) |
| `message` | string | server's own token-free error text on failure (`describeAPIError`), or a short success summary naming the version; NEVER a bearer token or snapshot content |

Outcome mapping (mirrors the server's failure table, config-apply-mode.md
Decision 3):

| Server result | `status.apply.state` |
|---|---|
| 200 | `applied` |
| 400 (approval/invalid_request) | `rejected` |
| 409 `config_apply_conflict` | `conflict` |
| any other non-2xx / transport / malformed response | `failed` |
| blank `spec.apply.reason` (controller-side guard, no HTTP) | `rejected` |

`Status.Message` (the drift summary) and `Status.Apply.Message` are kept
separate: the drift summary keeps its exact current wording for every CR,
so existing truthiness pins (`ssoconfigdrift_truthiness_test.go`) are
untouched; the apply outcome is read from the structured sub-struct. On a
successful apply, `Status.Message` still reports the drift — this is
HONEST: apply records B's applied baseline, it does not change B's running
config, so the drift persists (see the honesty note below).

Rollback results: the operator never drives rollback (Decision 4), so no
`status.rollback` exists today. The `ApplyStatus` struct is the reuse point
if a future boundary adds operator-driven rollback (a `rolled_back` state,
same shape). This is the "apply/rollback result fields" of the brief,
minimally: the apply fields now, the rollback fields when rollback is in
scope — see Decision 4.

**Honesty note (stated, not hidden):** after a successful apply, the
operator's next poll still reports drift, because both clusters' RUNNING
configs are unchanged and the diff compares running configs. Apply mode is
for the operator who has already (manually or via rollout) converged B and
wants B's config-audit applied view/history to record "A's config is the
declared baseline" — the drift report is not its success signal, and the
one-shot approval is what stops pointless repeated applies.

## Decision 4 — Rollback: manual only, never operator-driven

**The operator never calls `/config/rollback`; rollback remains a manual
action against the server API.** Minimal-surface criterion applied to the
question "what signal could the operator observe that a rollback is
wanted?" — the answer is none: the operator's only observations are the two
clusters' running configs and their diff; apply does not change running
configs (server contract), so an apply can never produce an
operator-visible "this baseline is wrong" signal. Rollback is a human
governance decision ("the last apply was a mistake") made against the
applied-baseline history, which the operator does not read. Driving it
would require inventing both a trigger condition and a second approval
channel for an action the operator has no evidence to justify — pure
surface for zero decision value.

consequences, kept minimal:

- No `rollbackPath` constant, no rollback HTTP code, no rollback status
  fields. The parity test pins only the paths the binary actually uses
  (`running`, `cluster-diff`, `apply`).
- The operator still equips the human: `status.apply.versionID` + `digest`
  name the baseline just written; the server's
  `GET .../config/history?resource=config` (and `prev_version` in the
  apply response) gives the exact rollback target.
- `docs/deferred-backlog.md` keeps "operator-driven rollback" in the
  not-committed list.

## Decision 5 — Security boundaries

- **Tokens unchanged**: still read only via `bearerSecretRef` Secret refs,
  used only in the Authorization header, never in Status/logs. The apply
  request reuses the same token-B resolution as the diff call.
- **The apply request body contains no secrets.** The snapshot the
  operator forwards is A's running config AS SERVED by
  `GET .../config/running`, which is already `Redact`ed server-side
  (`platform/configaudit/handlers.go:68`). The operator adds nothing to it
  and never persists it — the snapshot lives only in memory for the
  duration of the reconcile (request marshal + digest + Status hash).
  `status.apply.digest` is a sha256 hex string; `status.apply.message` is
  the server's own error text or a version id; neither can carry content.
- **Split-brain digest**: the operator computes
  `sha256(json.Marshal(snapshot))` hex (sorted-key marshal — `encoding/json`
  sorts map keys, the same canonicalization as `configaudit.Digest`
  `platform/configaudit/digest.go:18`) and sends it as the required
  `digest` field. Self-consistent by construction: the server's
  recomputation matches, so the 409 split-brain guard is satisfied on every
  legitimate submission and remains the defense for any future
  mixed-source manual path.
- **Fail-open**: an apply failure is recorded in `status.apply` and never
  blocks the drift report — the check result is still written (drift
  fields updated from a successful check even when the apply failed;
  preserved on check failure exactly as today), and the reconcile returns
  only the normal shortRequeue. A CR whose apply keeps failing is still a
  fully-functional drift reporter.
- **Approval consumption is a metadata-only write** (annotation delete);
  the controller never mutates spec, so no self-triggered Generation bump
  and no fight with GitOps over desired state.

## Decision 6 — Hard boundaries

- **Non-opted-in CRs: reconcile path byte-identical.** Every existing
  behavior — check order, message wording, failure-preserved drift fields,
  shortRequeue, requeue intervals, parity/truthiness pins — is untouched.
  The only new execution is behind `spec.apply.enabled && approval`, and
  `status.apply` is empty (omitted) until an apply is attempted. Existing
  tests pass unchanged; new tests assert zero apply calls for the
  non-opted-in and not-approved matrices.
- **Zero exemptions**: no `layerExemptions`, no file/function exemptions,
  no `engineering.yaml` changes. `cmd/sso-operator` remains a nested
  module; production code stays root-free (only `shared/core` is imported
  by the existing test-only parity file).
- **Nested module go.mod gains no dependencies.** The digest
  reimplementation uses stdlib only. A test-only import of
  `platform/configaudit` was tried and rejected: it transitively drags
  `platform/tracing` → otelhttp into the operator's `go.sum`. Instead the
  parity pin is a **known-answer test**: hard-coded digests computed once
  from the root module's `configaudit.Digest` (this design doc's fixtures),
  asserting the operator's reimplementation stays byte-identical to the
  server's canonicalization.
- **No rollback surface** (Decision 4). Canary, remediation, GitOps
  reconciliation remain non-goals — doc.go non-goals updated to say
  exactly that.
- **Budgets checked before editing**: controller file 243 → ~360 lines
  (<500); http.go 133 → ~210; apiv1alpha1 types 255 → ~330; Reconcile
  stays ~30 lines by extracting the apply phase into a helper; no function
  exceeds 50 lines.

## Decision 7 — Acceptance assertions (testable, no skips)

All controller tests use fake httptest servers asserting request shape and
a must-not-contact guard for the apply path:

| # | Assertion |
|---|---|
| 1 | opt-in + approval + drift → exactly one `POST {B}/api/v1/admin/config/apply?approve=true`; Authorization carries token-B; body `{"snapshot":<A's redacted running>,"digest":"<sha256 hex of that snapshot>","reason":"<spec.apply.reason>"}`; 200 → `status.apply.state=applied`, `versionID` set, `digest` matches, annotation removed |
| 2 | not opted in (`enabled` false/absent) → zero apply calls, `status.apply` empty, all existing report-only assertions unchanged |
| 3 | opted in, no approval annotation → zero apply calls |
| 4 | apply returns 409 `config_apply_conflict` → `status.apply.state=conflict`, message contains the wire code, approval RETAINED, drift fields still updated (fail-open), requeue short |
| 5 | apply returns 500 → `state=failed`, drift fields still updated, requeue short, message never contains a token |
| 6 | opt-in + approval but empty diff → zero apply calls, approval retained |
| 7 | two sequential reconciles with drift persisting → first applies and consumes the approval; second makes zero apply calls (one-shot throttle) |
| 8 | opt-in + approval + drift but blank `reason` → rejected without any HTTP call, `state=rejected` |
| 9 | digest parity: operator `snapshotDigest` equals the hard-coded `configaudit.Digest` known answers for the design fixtures (non-empty, nested, numeric) |
| 10 | existing parity (`adminpaths_parity_test.go`, extended to pin `applyPath`) + truthiness + validate tests all green; root gates green |

## Wire contract (operator → server)

- `POST {B.BaseURL}/api/v1/admin/config/apply?approve=true`
  - `Authorization: Bearer <tokenB>`, `Content-Type: application/json`
  - body: `{"snapshot":{...redacted A running...},"digest":"<sha256 hex>","reason":"<spec.apply.reason>"}`
  - 200 body: `{"applied":{...},"version":"<id>","prev_version":"<id>","patch":[...]}` →
    `status.apply.{state=applied, versionID=<id>, digest=<digest>, lastAttemptAt, message}`
  - non-2xx: `status.apply.state` per Decision 3, `message` =
    `describeAPIError` (the server's own `{"error","error_description"}`),
    never the token.
- Reuses: `resolveBearer`, `describeAPIError`, `defaultHTTPClient` timeouts,
  `validateBaseURL`, the no-literal-leaks `const` convention
  (`applyPath` pinned to `shared/core.PathAPIPrefix+PathAdminConfigApply`
  by the parity test).
- New CRD surface: `spec.apply.{enabled,reason}` (+ CEL admission rule),
  annotation `sso.snaplink.io/apply-approve`, `status.apply.{state,
  lastAttemptAt,versionID,digest,message}` — all mirrored in
  `apiv1alpha1/ssoconfigdrift_types.go`, `crd-ssoconfigdrift.yaml`,
  `cmd/sso-operator/doc.go`, `docs/deferred-backlog.md`, and root
  `CHANGELOG.md` in the same change.
