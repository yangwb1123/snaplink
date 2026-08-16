# Design: config apply mode — applying peer configuration

Bounded design for the deferred-backlog "Declarative multi-cluster
configuration governance" Partial boundary:
*Applying peer configuration*. All file/line references were verified
against executable code before writing.

Status quo (implemented, unchanged by this design):

- `POST /api/v1/admin/config/cluster-diff` computes a redacted RFC 6902
  patch from a caller-supplied peer snapshot to this cluster's own running
  config (`platform/configaudit/handlers.go:119` HandleClusterDiff). It is
  read-only by construction: a `SetMethodScope` override downgrades its
  POST to `admin:read` (`cmd/sso-server/build_app.go:305`), and it never
  writes anything.
- `SSOConfigDrift` CRD/reconciler (`cmd/sso-operator`) polls two clusters'
  `GET .../config/running` + `cluster-diff` and reports drift in Status.
  Its own doc (`cmd/sso-operator/doc.go`) is explicit that nothing in the
  binary ever issues a write request, and names exactly what an "apply"
  mode would need: an explicit opt-in + approval gate, a NEW write-capable
  endpoint on ClusterB (cluster-diff stays read-only), a canary/rollout
  strategy, and an audit trail distinguishing "detected" from "applied".
- The cross-replica drift loop broadcasts only the sha256 `configaudit.Digest`
  of a replica's running snapshot over the cluster Bus
  (`platform/configaudit/drift.go`, `shared/core` `cluster.KindConfigDigest`),
  never the snapshot itself.

Goal of this change: a bounded, explicitly-approved, audit-recorded
**declared-baseline** write path. After apply, this cluster's config-audit
"applied" view becomes the applied peer snapshot (redacted), history records
the apply with a redacted patch, and the same diff/redact/digest machinery
the read-only endpoints already use stays the single comparison engine.

What this design deliberately does NOT do (boundaries, matching the backlog's
"not committed" list): canary rollout, GitOps reconciliation, automated
remediation, and **live mutation of this cluster's runtime config**. There is
no mechanism in `platform/configaudit` (or anywhere reachable from it without
an upward dependency) to change the running config of a live server — the
running snapshot comes from a read-only `configRunningSnapshotFn` wired at
boot, and the SIGHUP reload machinery (`docs/config-reference.md`
`reload.enabled`) is a separate config-loading concern. "Apply" therefore
records the operator's **declared baseline** and its evidence trail; it does
not rewrite runtime state. That is the honest, minimal promotion of the
boundary and it is what makes the split-brain, redaction, and rollback
semantics well-defined below.

---

## Decision 1 — Authority model

**Single endpoint `POST /api/v1/admin/config/apply` requiring `admin:write`
AND an explicit confirmation flag `?approve=true`. A missing/false flag is
a hard 400 `config_apply_approval_required` before any state is touched.**

Rejected alternative — two-stage `apply-dry-run → apply-commit`: the dry-run
stage already exists as `POST .../cluster-diff` (admin:read, byte-identical
patch computation). A second dry-run endpoint would duplicate surface; the
commit stage would need server-side staged-state (a staging store, TTL,
eviction, replay semantics) — far more surface for zero added safety over
"diff first via cluster-diff, then apply with the digest in hand". The
single-endpoint + mandatory flag form keeps the misoperation barrier
(no accidental `curl`/reconciler bug can apply without an explicit
`approve=true`) at the smallest surface: one route, one query param, no
staging state.

Why `admin:write`: the admin middleware's default HTTP scope rule is
GET/HEAD/OPTIONS → `admin:read`, everything else → `admin:write`
(`interfaces/admin/middleware.go` `scopeForHTTP`). apply/rollback are
POST mutations, so they inherit `admin:write` with **no** `SetMethodScope`
override — the exact opposite of cluster-diff's explicit read override,
which is preserved untouched.

Why `?approve=true` (query) rather than a body field or header: it is
visible in every proxy/audit log, requires no body parsing order, and
mirrors the task's example. It is distinct from the transport-level
`X-Confirm` destructive-action guard (`interfaces/admin/governance.go`
`HeaderConfirm`): that gate is opt-in via config and runs pre-routing;
apply's approval is a semantic confirmation at the handler level and is
ALWAYS required, independent of operator governance config.

**Approval evidence** — every apply/rollback emits:
- an audit event (`admin_config_applied` / `admin_config_rolled_back`,
  registered in `auditspi` + classified in `auditreport` CC6.3) carrying
  `apply_id` (the new version id), `peer_digest`, `prev_id`, actor, and IP —
  metadata only, never snapshot content;
- a `config_history` entry (`resource="config"`, `resource_id=<version id>`,
  actor, redacted patch, reason = the mandatory operator `reason`).

The mandatory `reason` (blank → 400 `invalid_request` with description)
mirrors break-glass / change-approval's mandatory-reason rule: an
unexplained governance mutation is itself an audit finding.

## Decision 2 — Target semantics

**Input** — the full peer config snapshot, not a diff result and not an
etcd revision:

- `snapshot`: the peer's config snapshot (typically the `running` field of
  the peer's own `GET .../config/running` response, passed through verbatim —
  the same input shape `cluster-diff` already accepts).
- `digest`: the peer config's canonical sha256 fingerprint (required). The
  canonicalization is `configaudit.Digest`'s — sorted-key JSON marshal then
  sha256 (`platform/configaudit/digest.go`) — i.e. the same digest the drift
  loop broadcasts. For a bus-connected replica this is the peer's broadcast
  digest; for a cross-deployment peer the operator computes it from the
  snapshot with the same canonicalization. The server recomputes
  `Digest(snapshot)` and compares byte-wise (Decision 4).
- `reason`: mandatory operator reference (ticket/incident).

Why the full snapshot rather than the diff result: a patch is relative to
the current baseline, so it is not self-contained across multiple applies
and cannot anchor a rollback. The full snapshot makes each version a
complete, independently restorable baseline. Why not the etcd config-source
revision: configaudit never reads etcd revisions; the digest mechanism is the
existing cross-replica fingerprint this feature already ships.

**Write path** — a NEW `Store.Apply(ctx, AppliedVersion) (AppliedVersion, error)`
on `configaudit.Store`, plus `Store.Applied(ctx)` and
`Store.Rollback(ctx, actor, reason)`. Not a reuse of `Record`/`List`:
apply must atomically (a) link and replace the current applied baseline,
(b) retain the previous version for rollback, (c) append the `config_history`
entry describing the change — a multi-step invariant a plain append cannot
express. `MemoryStore` (one mutex) and `configaudit/sqlite` (one SQL
transaction, new `config_applied` table in migration v2) both implement it;
both are `Store` so the handler is backend-agnostic. The history entry's
patch is computed inside the store via the same-package `Diff` +
`RedactOps`, over the REDACTED snapshots (the only thing ever stored), so
the entry can never carry a plaintext secret.

**The three views after a successful apply**:

| View | After apply |
|---|---|
| `running` (`GET .../config/running`) | **Unchanged.** Apply never mutates live runtime state (out of scope, see goal). |
| `applied` (`GET .../config/applied`) | The applied peer snapshot (redacted). `Server.AppliedConfigSnapshot()` (interfaces/sso/server_backup.go) consults the store's latest baseline and falls back to the startup capture when none exists — so in every currently-reachable state (no apply ever issued) the view is byte-identical to today. |
| `history` (`GET .../config/history`) | A new `resource="config"` entry with the redacted patch and the operator's reason. |

`GET .../config/diff` follows `applied` automatically: before the first
apply it compares startup-vs-running exactly as today; after an apply it
shows the gap between the declared peer baseline and this cluster's running
config — the same semantics as `cluster-diff`'s response, now persistent.

## Decision 3 — Rollback semantics

- **Transactional writes.** sqlite `Apply`/`Rollback` run in a single
  transaction (baseline replace + history insert commit together; any
  failure rolls back). MemoryStore does both under one lock; an internal
  error mutates nothing. There is no half-state: a failure returns an error
  and leaves the previous baseline + history exactly as they were.
- **Previous version retained.** Every `AppliedVersion` stores `prev_id`;
  versions are append-only. sqlite keeps all rows; MemoryStore keeps applied
  versions in its own bounded list (apply is a low-frequency operator
  action, and the immediately-previous version — the only rollback target —
  is always retained).
- **Explicit `POST /api/v1/admin/config/rollback`** (admin:write +
  `?approve=true` required). Semantics: creates a NEW version whose
  `Snapshot` is the previous version's snapshot (append-only chain, so
  rollback-again is well-defined), `Reason = "config_rollback"`, history
  entry patch = the reverse of the apply, audit event
  `admin_config_rolled_back`. Restoring a previous version means the
  applied view and subsequent diffs revert to that snapshot. Rollback with
  no baseline or no previous version → 409 `config_apply_no_previous`.
- **Secret caveat, documented and tested**: stored baselines are redacted,
  so a rolled-back snapshot restores secret-shaped leaves as `"***"` — the
  operator re-supplies real values in the next apply (typically the peer's
  next snapshot). This is inherent to "audit records never carry secrets"
  and is stated on the endpoint docs.
- **Failure-mode classification** (all handler-level, none leave half-state):

| Failure | HTTP | Wire code |
|---|---|---|
| malformed body / missing `snapshot` / missing or blank `digest` / blank `reason` | 400 | `invalid_request` (+description) |
| `approve` != `true` (apply or rollback) | 400 | `config_apply_approval_required` |
| digest mismatch — split-brain (Decision 4) | 409 | `config_apply_conflict` |
| rollback with no previous version | 409 | `config_apply_no_previous` |
| store not wired (should be unmounted; belt-and-braces guard) | 501 | `config_audit_not_available` |
| store read/write failure | 500 | `internal_error` (logged; nothing applied) |

## Decision 4 — Split-brain protection

**Before any write, the server recomputes `configaudit.Digest(snapshot)`
(sha256 hex over the canonical sorted-key JSON form — the numeric evidence,
same mechanism as `cluster-diff`'s existing digest broadcast) and compares
it byte-wise to the required `digest` field. Mismatch → 409
`config_apply_conflict`, nothing recorded.**

This catches the two split-brain failure modes at the cheapest point:

1. **Stale snapshot**: the operator fetched the peer's running config, the
   peer's config changed (or another replica applied first), and the
   operator now submits the old snapshot against a digest that no longer
   matches it — the submission is internally inconsistent, rejected.
2. **Mixing sources**: submitting a snapshot with a digest computed over
   different bytes (a copy-paste of two different fetches) is rejected
   rather than silently recorded under a false fingerprint.

Scope note, stated honestly: the digest check verifies
self-consistency+freshness of the submission against the claimed
fingerprint. It is not a proof of what the peer's config "really" is —
full cross-cluster trust (out-of-band fingerprint exchange, signatures) is
beyond this bounded promotion and remains with the not-committed GitOps
reconciler. For bus-connected replicas the broadcast digest is
authoritative (in-band trusted channel); for cross-deployment peers the
operator's own fetch is the source, exactly as with `cluster-diff` today.

The digest runs over the RAW request snapshot (`Digest` on the submitted
map, before any redaction) — matching the drift loop's digest basis
(EffectiveConfigSnapshot → Digest in cmd) — while only the REDACTED snapshot
is ever stored.

## Decision 5 — Secret redaction

Reuses `platform/configaudit/redact.go` verbatim — no new redaction code:

- The request snapshot is redacted (`Redact`) before it enters any store
  field; the digest is verified on the RAW snapshot first (a redacted
  "***" would produce a different digest, so redaction never happens before
  the fingerprint check).
- The response's `applied` field is the redacted snapshot; the response
  `patch` goes through `RedactOps`.
- The history entry's patch is `RedactOps(Diff(prevRedacted, newRedacted))`.
- The audit event carries metadata only (`apply_id`, `peer_digest`,
  `prev_id`, actor, IP) — never snapshot content.
- **Test proof**: a secret-scan test asserts that plaintext secret values
  submitted in the apply body appear NOWHERE in (a) stored history entries,
  (b) stored applied baselines, (c) the HTTP response body, (d) the audit
  event. The diff-only regression already proves the same for
  running/applied/diff/cluster-diff.

Documented limitation (already inherent to the redaction contract): because
baselines are stored redacted, a secret value change between two applies is
invisible in history (both redact to `"***"`); the path/op still surfaces
that a secret-shaped key was added/removed. Same trade-off the diff view
already documents.

## Decision 6 — Hard boundaries

- **Diff-only path byte-identical.** No handler in the read-only path is
  touched: `HandleRunning`/`HandleApplied`/`HandleDiff`/`HandleClusterDiff`
  and `Store.Record`/`List` keep their exact behavior. The only shared
  change is `Server.AppliedConfigSnapshot()` consulting the store's
  latest baseline **with fallback to the startup capture when none exists**
  — in every currently-reachable state (no apply ever issued) the output is
  byte-identical, and all existing diff-only tests pass unchanged
  (`platform/configaudit/handlers_test.go`, `interfaces/sso/config_audit_test.go`).
- **Store unwired ⇒ behavior unchanged.** apply/rollback routes are mounted
  only when BOTH a snapshot source AND a config-audit store are wired
  (`mountConfigAuditAPI`, `configaudit.MountRoutes`); a build with no
  `WithConfigAuditStore` has the same route set and the same
  `AppliedConfigSnapshot` behavior as today (startup capture).
- **Zero exemptions.** No `layerExemptions`, no file/function exemptions.
  `platform/configaudit` stays in the platform layer; imports flow downward
  only (`configaudit` → `shared/core`, `shared/spi`, `platform/audit`,
  `platform/cluster` — all already present for drift.go).
- **No new upward dependencies.** The apply/rollback logic, storage, digest
  and redaction all live in `platform/configaudit`; `interfaces/sso`
  contributes thin route/wrapper/accessor lines only. The handler reads the
  admin actor through a new `HandlerDeps` accessor
  (`ActorFromContext`) implemented by the existing
  `Server.ActorFromContext` (interfaces/sso/accessors_handlers.go:496)
  — dependency injection, no import.
- **Line budgets** checked before editing: handlers.go 169 → ~350; store.go 63 → ~110; memory.go 97 → ~200; sqlite/store.go 188 → ~390; mount.go 38 → ~50; server_backup.go 266 → ~310; options_admin.go /
  accessors_handlers.go / aliases.go are NOT touched (at or near their
  budgets).
- **Credential-endpoint hygiene**: apply/rollback responses use
  `tokenNoStoreHeaders` (the established write-endpoint no-store pattern).

## Decision 7 — Acceptance assertions (testable, no skips)

| # | Assertion |
|---|---|
| 1 | apply with valid snapshot+digest+reason+`approve=true` → 200; `GET .../config/applied` returns the redacted peer snapshot; `GET .../config/history` shows the `config` entry with the redacted patch; audit sink contains `admin_config_applied` with `apply_id`/`peer_digest` (memory + sqlite) |
| 2 | apply without `approve=true` → 400 `config_apply_approval_required`, store untouched |
| 3 | apply with digest mismatch → 409 `config_apply_conflict`, store untouched |
| 4 | rollback with `approve=true` after ≥2 applies → 200; applied view restored to the previous applied baseline (the first apply's snapshot after two applies); history shows the rollback entry; audit contains `admin_config_rolled_back` |
| 5 | rollback when nothing to roll back → 409 `config_apply_no_previous` |
| 6 | plaintext secret scan: submitted secrets absent from stored entries/baselines, response body, and audit event (memory + sqlite) |
| 7 | diff-only regression: all existing running/applied/diff/cluster-diff/history tests pass unchanged; a fresh server without the store serves byte-identical applied/diff output |
| 8 | no store or no snapshots ⇒ apply/rollback unmounted (404), and server without store keeps `AppliedConfigSnapshot` = startup capture |
| 9 | apply then rollback then apply again → version chain is append-only and rollback targets are always the immediately-previous version |
| 10 | `go test ./platform/configaudit/... -count=1`, `go test ./interfaces/sso/... -run Config`, maintainability/architecture/directory gates, `cli.py check-routes`, `cli.py sdk-surface check` all green |

## Wire contract

- `POST /api/v1/admin/config/apply?approve=true` — body
  `{"snapshot":{...},"digest":"<sha256 hex>","reason":"<required>"}`.
- `POST /api/v1/admin/config/rollback?approve=true` — body `{"reason":"<required>"}`.
- Response (both): `{"applied":{...redacted...},"version":"<id>","prev_version":"<id|''>","patch":[...]}` — the authoritative history record is read back via `GET .../config/history?resource=config` (the apply writes it in the same transaction as the baseline).
- New wire codes (shared/core/errors.go + docs/error-codes.md):
  `config_apply_approval_required` (400), `config_apply_conflict` (409),
  `config_apply_no_previous` (409).
- New audit events (auditspi + aliases + KnownEventTypes + auditreport
  CC6.3): `admin_config_applied`, `admin_config_rolled_back`.
- OpenAPI: two new operations + `ConfigApplyRequest`/`ConfigApplyResponse`
  schemas in the same commit.
