# SRE Review: `token_policy_denied` audit event — detect / withstand / recover

Reviewer role: SRE engineer. Input: `docs/auto/domains-tokenpolicy-direction2-design.md`
(the audit-event design, spec-only) plus the current tree's operational surface:
`interfaces/sso` deny seams, `platform/audit` pipeline, stock `cmd/sso-server`
wiring, `ops/deploy/grafana/alerts.yaml`, `ops/deploy/openresty` edge prototype,
`docs/deployment.md`, `docs/observability.md`, `docs/config-reference.md`.

Scope: can operators **detect, withstand, and recover** from failures of the
governance-deny signal this design creates, on the API backend and across the
external frontend/proxy boundary? Findings from the compliance, security, and
QA reviews are referenced where they carry the operational consequence; this
review adds the operator-facing layer (alerting, runbooks, evidence
durability, recovery sequencing).

**Verification run for this review.** Read-only; no `.go` files changed, no
build gates run — consistent with the spec being spec-only. Evidence below was
re-derived by direct file reads on the current worktree (revision `3ba906eb`,
which carries unrelated pre-existing modifications under `cmd/sso-server/*`,
`config/*`, `docs/*`, `ai-dev/*`, `.pi/*` — not touched):

- `interfaces/sso/server_token.go:168-181` — scope-combo deny precedes
  `checkGrantRateLimit`; **Verified**
- `interfaces/sso/server_helpers.go:85-115` — `enforceTokenPolicy` deny
  branch (metrics + log, no audit), fail-open store path, `wireCodeForPolicyDeny`;
  **Verified**
- `interfaces/sso/server_oauth.go:150-190` — `sessionPolicyCapExceeded` deny
  branch, reason guard, allow path without evaluation metric; **Verified**
- `internal/handler/tokengrant/token_refresh.go:116` — refresh-depth seam
  funnels through `enforceTokenPolicy`; **Verified**
- `platform/metrics/metrics_token.go:75-125` — `sso_token_policy_{evaluations,
  denials,renew_required}_total`, reason-only labels, "zero traffic when no
  store wired" semantics; **Verified**
- `platform/audit/recorder.go:143-177` — nil-safe `Record`, `WithErrorHandler`
  routing; **Verified**
- `cmd/sso-server/build_app_core.go:195-390` — `wireAudit` composition order
  (primary → webhook → SIEM → kafka → async), ready-check registration
  ("SQLite does, MemorySink silently no-ops"), `WithErrorHandler` =
  `logger.Error("audit sink", ...)`; **Verified**
- `cmd/sso-server/config.yaml:202-280,709-724` — stock audit defaults
  (`backend: memory`, `memory_capacity: 10000`, `hash_chain: false`,
  webhook off, no `audit.async` block) and rate-limit defaults (`enabled:
  true`, `default_per_sec: 1`, burst 60, prefixes only for `/auth/login`,
  `/auth/send-code`); **Verified**
- `platform/audit/async_sink.go:34-108` — three drop counters, drop handler;
  **Verified**
- `platform/audit/auditsink/retrying_sink.go:14-26` — retry defaults
  (3 attempts, 100ms initial, 5s max, jittered); **Verified**
- `ops/deploy/grafana/alerts.yaml` (full read) — 11 rules; **no rule
  references `sso_token_policy_*`, `sso_audit_*` except the two async rules,
  `sso_degradation_mode`, `sso_dr_*`, or `sso_invalidation_bus_up`**;
  **Verified**
- `ops/deploy/openresty/conf.d/sso.conf` — `/token` passes straight through,
  no edge rate limit or body limit; `/_gateway/health` absent; **Verified**
- `cmd/sso-server/main_wiring.go:121-190` — SIGHUP reload covers rate limit +
  feature gates only; `token_policies` is not hot-reloadable; **Verified**
- `interfaces/sso/sso.go:349-354` + `server_routes_admin.go:125` — token
  policies have a **read-only** admin GET; no runtime rule mutation;
  **Verified**
- `platform/audit/handler_helpers.go:30-53` — `EventFromRequest` trace/tenant
  enrichment; **Verified**
- Grep for SLO/burn-rate text in `docs/deployment.md`, `docs/dr-framework.md`,
  `docs/observability.md` — none; **Verified absent**
- Cross-checks against the session's compliance/security/QA deliverables
  (drift on `make ci`/`docs-check`, snapshot-based `allKnownEventTypes`,
  non-blocking auth-code seam, empty `clientID` at the federated seam):
  accepted as re-verified by those reviews.

---

## 1. Service/dependency map and operational assumptions

```text
                 ┌──────────── external boundary (prototype) ────────────┐
  browser SPAs ──┤ OpenResty edge: /token, /auth/* pass through;         │
  (separate      │ /api/v1/* + /userinfo gated by user-JWT auth.verify(); │
   projects)     │ log_by_lua audit.jsonl (debug telemetry only)          │
                 └───────┬───────────────────────────────────────────────┘
                         │ XFF / X-Trace / X-Network / X-Auth-* (trusted-proxies gated)
                ┌────────▼─────────────────────────┐
                │  sso-server replica (stateless)  │  probes OUTSIDE ratelimit:
                │  /livez /readyz /metrics         │  tracing → ratelimit → bodyLimit
                └───┬──────┬──────┬──────┬─────┬───┘  → metrics → CORS → router
                    │      │      │      │     │
        ┌───────────▼┐ ┌───▼──┐ ┌──▼────┐┌────▼───┐┌──────────────┐
        │ SQLite/    │ │Redis │ │Postgres││ etcd   ││ KMS/HSM      │
        │ Postgres   │ │hot   │ │durable ││ bus +  ││ signing      │
        │ audit +    │ │stores│ │stores  ││ registry││ (fail closed)│
        │ stores     │ └──────┘ └────────┘└───┬────┘└──────────────┘
        └────────────┘                        │
                              ┌────────────────▼───────────────┐
                              │ token-policy engine (MEMORY     │
                              │ store, config-sourced at boot)  │
                              │ Evaluate → deny → metric + log │
                              │   + NEW audit event (design)    │
                              └────────────────────────────────┘
        audit pipeline: Recorder (redaction → hash chain) →
          MultiSink[primary(memory|sqlite|postgres) → webhook → SIEM
          (cef/ocsf/syslog) → kafka] → optional AsyncSink (opt-in)
```

**What the design adds to this topology**: one event per deny decision on the
three seams (scope-combo, refresh-depth, session-cap), riding the existing
recorder → sink pipeline. No new storage, no new dependency, no metric
change. The operational delta is entirely **new load on the audit pipeline**
and **new signal for operators to alert/runbook on** — which is where this
review concentrates.

**Operational assumptions (current tree, re-verified):**

- A1. The token-policy store is a **boot-sourced memory snapshot**
  (`BuildTokenPolicyStore`, `serverbuildplatform/build_governance.go:197-218`:
  file or inline YAML, `tokenpolicymemory.NewFromSlice`). There is no sqlite
  store and no admin CRUD in this tree — the previous direction's
  lifecycle design was not implemented. Consequences: (a) the fail-open
  store-error path in both seams is nearly unreachable today (memory store
  never errors after a successful boot) — it is defensive code for a future
  backend; (b) **the only runtime mutation of governance is a config change
  + restart** (SIGHUP reload covers rate limit and feature gates only,
  `main_wiring.go:121-190`; the admin surface is read-only,
  `sso.go:349-354`). Recovery speed for a bad rule is therefore bounded by
  rollout time.
- A2. Stock audit defaults are **volatile and non-tamper-evident**:
  `backend: memory` (10,000-event ring, self-pruning), `hash_chain: false`,
  webhook off, no `audit.async` block in `cmd/sso-server/config.yaml:202-280`.
  The audit API is mounted (`api_enabled: true`). A governance-evidence
  deployment must deliberately choose sqlite/postgres + hash chain — nothing
  fails boot if it does not.
- A3. Synchronous sink errors are **logged only** (stock `WithErrorHandler` →
  `logger.Error("audit sink", ...)`, `build_app_core.go:373-375`): no metric,
  no alert, unless `audit.async` is enabled (then `sso_audit_async_drops_*` +
  `SSOAuditEventsDropped`/`SSOAuditQueueSaturated` cover it).
- A4. The stock rate limiter bounds per-IP `/token` traffic at 1 req/s
  sustained (burst 60, memory backend per-replica; `config.yaml:709-724`).
  The scope-combo deny fires **before** the per-grant limiter
  (`server_token.go:168` vs `:181`) but **after** the middleware limiter.
- A5. The OpenResty edge is a prototype, not a production boundary (its own
  README); `/token` passes straight through with no edge rate limiting.
- A6. No availability SLO is documented anywhere (grep of deployment, DR,
  observability docs). RPO/RTO exist only as DR-report targets
  (`docs/dr-framework.md`).

---

## 2. Readiness table

| Signal | Dependency | Failure behavior | Alert today | Runbook today |
|---|---|---|---|---|
| `/livez` | process | 200 while handler runs | `SSOInstanceDown` (critical) | `ops/deploy/baremetal-ha/RUNBOOK.md` (validation draft) |
| `/readyz` (aggregate, 3s bound) | named checks | 503 + per-check map; pod drained | none per-check | none |
| `/readyz: audit-<backend>` | primary audit sink `Ping` | drains replica — **only when backend is sqlite/postgres; MemorySink no-ops, so the stock default has no audit readiness signal** | none | none |
| `/readyz: redis/postgres/bus/signing/netpolicy/dr/sqlite-*` | backends | drain replica (tolerant threshold 4×5s) | `SSOSigningKeyAggregationDegraded` only | none |
| `/metrics` | — | outside ratelimit | 11 rules; **none reference `sso_token_policy_*`** | dashboard `sso-overview.json` |
| `sso_token_policy_evaluations_total` (NEW event's parent metric) | policy engine wired | series absent when unwired; fail-open paths increment nothing | **none — governance-silent window is undetectable (F2)** | none |
| `sso_token_policy_denials_total` (reason labels) | deny decisions | rising count = governance actively blocking; wire stays generic | **none (F1)** | none |
| `sso_audit_async_drops_*` / queue gauges | AsyncSink | drops = silent trail loss; fail-open | `SSOAuditEventsDropped` (critical), `SSOAuditQueueSaturated` (warning) — **only when `audit.async` enabled** | alert description text only |
| sync sink error (no async) | leaf sink | `logger.Error("audit sink", ...)` only | **none (F3-adjacent detection gap)** | none |
| `GET /api/v1/audit/events` | recorder sink, `admin:read` | 401/403 without admin gate | none | none |
| `sso-ctl audit-verify` | durable audit store + chain | offline tamper check | n/a | `docs/deployment.md:45` |
| `GET /api/v1/admin/token-policies` | memory store snapshot | always 200 (snapshot) | none | none |
| audit retention (`audit.retention.*`) | sqlite sink `Prune` | unset → unbounded growth; set → hash-chain break at prune boundary unless re-chained | none | none (compliance F2) |
| Edge `/token` passthrough | OpenResty | no edge rate limit/body limit | none (edge has no alerting at all) | none |
| Memory ring wrap (default audit backend) | MemorySink capacity 10k | oldest events silently dropped, no counter | **none — silent evidence loss (F3)** | none |

---

## 3. Findings

### F1 [High] — The design creates a new security signal with zero alert and zero runbook coverage

- **Evidence**: `ops/deploy/grafana/alerts.yaml` (full read, 11 rules) — no
  rule references `sso_token_policy_*`; the only 4xx flood signal is
  `SSORateLimitSaturated` (severity **info**, described as login rate-limit
  traffic). `docs/deployment.md` (342 lines) has no token-policy entry.
  The metric the design's event pairs with exists and is reason-labeled only
  (`metrics_token.go:85-91`) — rule-level detail lives exclusively in the
  audit trail the design creates. The prior SRE review's recommended
  denial-rate alert was never added.
- **Production impact**: a misconfigured `block_scope_combos` rule (overly
  broad pattern) or a scope-combo probing campaign produces an
  `invalid_scope` flood that (a) does not page, (b) pollutes the very
  evidence stream this design builds for SOC2, and (c) is
  indistinguishable from ordinary bad requests without SIEM correlation.
  When on-call is eventually paged by a downstream symptom, there is no
  runbook step that says how to identify the denying rule.
- **Remediation** (alert as follow-up; runbook text in this change):
  1. Alert `SSOTokenPolicyDenialRate` — `increase(sso_token_policy_denials_total[10m]) > <baseline>` (reason labels are bounded; per-rule triage happens via audit). Severity warning.
  2. Runbook paragraph in `docs/deployment.md` (or observability.md, which has no gate — see F4): triage via `GET /api/v1/audit/events` filtered to `type=token_policy_denied` (admin:read) reading `policy_name` + `Reason`; **the only mitigation for a bad rule is a config change + restart** (no runtime rule mutation in this tree; SIGHUP does not cover `token_policies` — A1). State the rollback trigger wording (F1 of the design: "unexplained deny rate = rollback-worthy").
- **Recovery validation**: stage — install a deliberately broad combo rule, generate deny traffic, verify the alert fires and the runbook query identifies `policy_name`; fix config, restart, verify denials return to baseline and the alert clears.

### F2 [High] — The governance-silent window is undetectable: no "policy engine silent" alert, and the evaluations counter is seam-incomplete

- **Evidence**: both seams fail open with a log line only
  (`server_helpers.go:89-95`, `server_oauth.go:160-168`); metric help text
  says "Zero traffic when no WithTokenPolicy store is wired"
  (`metrics_token.go`); the exact precedent for the needed alert exists —
  `SSORiskScorerSilent` (alerts.yaml: "Login traffic continues but the
  configured RiskScorer hasn't registered any decisions in 15m. Likely
  fail-open behavior") — but nothing analogous for token policy. The
  session seam increments `ObserveTokenPolicyEvaluation` **only on deny**
  (`server_oauth.go:184-190`); the allow path returns without a metric, so
  `sso_token_policy_evaluations_total` is not a complete gate counter (it
  counts the `enforceTokenPolicy` seam's allows+denies plus session-seam
  denies).
- **Production impact**: removing the `token_policies` section (or a future
  backend's silent failure) disables governance with zero signal — an
  operator cannot distinguish "no denials" from "engine off", which is
  exactly the CC7.2 continuous-operation evidence problem compliance F1
  raises, and exactly the class of failure `SSORiskScorerSilent` was built
  for. The design's own failure-mode table documents the fail-open but no
  detection.
- **Remediation**:
  1. Alert `SSOTokenPolicySilent`, modeled on `SSORiskScorerSilent`:
     token-request traffic > 0 AND `rate(sso_token_policy_evaluations_total[10m]) == 0` for 15m. This works because the `enforceTokenPolicy` seam increments on **every** `/token` request when wired (allow and deny).
  2. In `docs/observability.md`, document the metric's seam coverage so the alert's blind spot (session-seam allows are not counted) is understood and the metric is not oversold as a full gate counter.
- **Recovery validation**: stage — remove `token_policies` from config, run token traffic, verify the alert fires; restore, verify evaluations resume.

### F3 [Medium] — Evidence durability under stock defaults: memory ring, chain off, silent wrap, no readiness signal

- **Evidence**: `cmd/sso-server/config.yaml:203-216` (`backend: memory`,
  `memory_capacity: 10000`, `hash_chain: false`, PII redaction off); ready
  check registration comment — "the SQLite sink does [Ping]; MemorySink
  silently no-ops" (`build_app_core.go:210-224`); `SSOAuditEventsDropped`
  covers async drops only, not ring wrap. The design's storage section says
  the event "rides the existing recorder → sink pipeline" without noting the
  default sink's volatility.
- **Production impact**: the design's entire purpose is evidence; under stock
  defaults every deny record is process-local, lost on restart or rolling
  deploy with zero warning, and not tamper-evident (`hash_chain: false`).
  A SOC2 evidence submission built from the default configuration would be
  unverifiable — `sso-ctl audit-verify` has nothing durable to verify.
- **Remediation** (docs in this change; no code): in `docs/observability.md`
  and `docs/config-reference.md` state the requirement: for
  `token_policy_denied` to count as evidence, `audit.backend` must be
  durable (sqlite/postgres) and `audit.hash_chain: true`; document that the
  memory ring wraps silently (no counter exists — a monitoring gap, see §5).
  Optional follow-up: boot validation that warns when governance rules are
  configured with a volatile audit backend.
- **Recovery validation**: drill — memory backend: deny, restart, audit query
  returns nothing; sqlite + chain: deny, restart, event present and
  `sso-ctl audit-verify` passes.

### F4 [Medium] — The design's "docs gate" does not exist, and the CEF/OCSF conformance list is snapshot-based

- **Evidence**: design risk 9 claims "`make ci` checks `docs/observability.md`" —
  QA review F1 verified this is false (no `docs-check` in `make ci`, and the
  docs check does not validate observability.md). QA F2 / security F3
  verified `TestConformance_EveryEventTypeHasCEFAndOCSFMapping` iterates a
  **hand-transcribed** `allKnownEventTypes` (conformance_test.go:20-153):
  a missing entry silently falls back to the generic OCSF class (classUID 0)
  and a humanized CEF name (accidentally identical for this type — a trap).
- **Production impact**: the four-registration plan's documentation leg
  (event semantics, `policy_name` non-stability, fail-open behavior,
  admin-gate requirement) is enforced by review discipline alone; a future
  edit can ship the event without the alert/runbook/SIEM guidance this
  review and the compliance review require. SIEM consumers can receive a
  generic OCSF record with no CI failure.
- **Remediation**: (1) add `auditspi.EventTokenPolicyDenied` to
  `allKnownEventTypes` in the same change (closes the silent fallback;
  makes the design's own CEF/OCSF test plan enforced, not advisory);
  (2) treat observability.md updates as review discipline; (3) pin the
  `Reason` set membership in the acceptance tests (security F4) so a fourth
  free-form reason fails rather than silently breaking SIEM regexes.
- **Recovery validation**: remove the conformance-list entry → the
  conformance test fails (proves the guard works); re-add → green.

### F5 [Medium] — Deny-path amplification now reaches the audit pipeline; bounded in stock wiring, unbounded otherwise

- **Evidence**: `dispatchTokenGrant` order — `denyTokenScopeCombo`
  (`server_token.go:168`) before `checkGrantRateLimit` (`:181`); public
  clients authenticate by `client_id` alone; the stock middleware rate
  limiter (1 req/s/IP, per-replica memory) bounds per-IP floods
  (`config.yaml:709-724`) but a distributed flood is bounded only by
  client-auth + TLS cost; `audit.async` is absent from the stock config, so
  each deny's `Record` runs **synchronously** through every wired sink
  (with `audit.kafka.required_acks: all` and `async: false`, the broker
  round-trip is on the Record hot path unless `audit.async` is set —
  config-reference:461-462). The RetryingSink masks transient webhook
  hiccups in its own worker (retrying_sink.go:14-26, 47-49), so webhook
  latency is off the hot path.
- **Production impact**: (a) with network sinks and no `audit.async`, a
  slow/hung sink delays the deny response itself (deny path already fails
  the request — bounded impact, but the 400 is what a retrying client
  waits on); (b) unbounded event volume when `security.rate_limit` is not
  wired (SDK embeddings) or under distributed floods — the audit stream
  the design creates becomes the attack surface's exhaust; (c) SOC2
  evidence noise and SQLite growth from probe traffic.
- **Remediation**: (1) document in `docs/observability.md`: deny-path
  emission is unbounded without `security.rate_limit`; `audit.async` is the
  mitigation for sync-sink latency; (2) follow-up task (flagged, out of
  scope for this change): move the scope-combo check after
  `checkGrantRateLimit` — oracle-safe either way, but changes
  429-vs-`invalid_scope` precedence; (3) the design's test plan (MemorySink
  exactly-1 counts) should include a flood scenario asserting the request
  stream is cut by the limiter when one is wired.
- **Recovery validation**: stage — flood `POST /token` with a combo rule
  wired; verify queue gauges stay < 80% with async, drops stay zero, and
  the `MemorySink` count equals the limiter budget, not the request count.

### F6 [Low] — Event semantics vs. wire outcome at two seams: non-blocking auth-code path; empty `clientID` at the federated seam

- **Evidence**: `codeFlowSession` continues after a session-cap deny
  (server_login_auth.go:474-495 — security F2 verified); the federated
  callback passes `clientID: ""` (server_oauth.go:223, security F5). The
  design's field table says `Outcome=OutcomeFailure` is "a deny is a failed
  issuance" — false for the auth-code path, and empty `ClientID` events are
  unattributable in audit queries.
- **Production impact**: operators counting `token_policy_denied` as blocked
  logins overcount (SOC triage noise, false incident rates); federated
  session-cap denials cannot be correlated to a client.
- **Remediation**: document both in `docs/observability.md` (event records
  the *session* decision, not the request outcome; federated seam may carry
  empty `ClientID`); pin with the design's test plan (exactly-1 event on the
  auth-code path **with** a successful token response).
- **Recovery validation**: the pinned test above.

### F7 [Info] — No availability SLO; define the measurement and the evidence-completeness decision

- **Evidence**: no SLO/burn-rate text in deployment, DR, or observability
  docs (grep). For this design specifically there is no
  evidence-completeness target: with `audit.async` enabled, drops are
  counted and alerted (`SSOAuditEventsDropped` — that *is* the measurement);
  without async, sync sink errors are log-only, and memory-ring wrap is
  uncounted (F3).
- **Production impact**: operators cannot state "X% of denials are
  recorded" or "token issuance SLO is Y" — the design's evidence value and
  the platform's availability posture are unmeasurable.
- **Remediation**: (1) define a token-issuance availability SLO from
  existing raw metrics (`sso_tokens_issued_total`,
  `sso_http_requests_total{status_class}`, `sso_login_attempts_total`) with
  a burn-rate alert — a prerequisite decision, not code; (2) for this
  change, decide and document the evidence-completeness posture: durable
  backend + chain required for evidence (F3), async + drop alerts as the
  completeness signal, and (operator decision) a retention window ≥
  evidence window with prune + `audit-verify` runbook steps (compliance
  F2's chain-break caveat).

---

## 4. Failure drills

Each drill: trigger → expected behavior → detection → recovery → validation gate.
Runnable in staging against the current tree plus the design's acceptance tests.

### D1 — Outage: audit primary sink down (sqlite file unreadable / disk full)

- Trigger: `audit.backend: sqlite` file loses reachability mid-flight.
- Expected: `Record` error → fail-open (`recorder.go:176-177`), issuance and
  wire unaffected; `/readyz: audit-sqlite` drains the replica once Ping
  fails; async drops counter rises when `audit.async` is enabled.
- Detection: with async — `SSOAuditEventsDropped` (critical); without async —
  **log line only** (`logger.Error("audit sink", ...)`) — this drill fails
  its detection step today (F3-adjacent gap). `/readyz` drains the pod only
  when the sink pings.
- Recovery: restore file/mount; replica returns to ready; with async,
  queued events drain (bounded by buffer; anything dropped is counted and
  alerted).
- Validation: `/readyz` 200; drops counter stops increasing; a new deny
  event is queryable via the audit API; `sso-ctl audit-verify` passes
  (chain resumes from the last persisted hash — `WithHashChain` tip-resume).

### D2 — Saturation: deny flood from a bad combo rule or probing campaign

- Trigger: overly broad `block_scope_combos` rule; or public-client probing
  with garbage codes (scope-combo deny precedes code validation and the
  per-grant limiter).
- Expected: `sso_token_policy_denials_total` rises (bounded reason labels);
  wire stays generic `invalid_scope`; per-IP middleware limiter bounds the
  stock deployment at 1 req/s/IP; each deny writes synchronously to every
  wired sink (F5).
- Detection: **none today** (F1 — `SSOTokenPolicyDenialRate` required);
  `SSORateLimitSaturated` (info) is the only incidental signal; with async,
  `SSOAuditQueueSaturated` warns before drops.
- Recovery: identify the rule via audit query (`policy_name`); fix config +
  restart (only mitigation in this tree — A1); probe traffic needs no
  action (no tokens minted, no state mutated).
- Validation: denial rate returns to baseline; the offending rule's
  `policy_name` appears in the runbook's audit query; a golden-path login
  succeeds.

### D3 — Bad rollout: token-policy config removed or broken mid-rollout

- Trigger: `token_policies` section dropped from config in a new rollout;
  or a bundle that fails `ParseYAML` (boot fails loud — the parse error is
  a boot gate, `build_governance.go:206-214`).
- Expected: broken bundle → first replica crash-loops (rollout tooling must
  already handle boot failure); **removed section → clean boot with
  governance silently OFF** — no deny, no event, no metric series.
- Detection: crash-loop → `SSOInstanceDown`; **silent-off → nothing (F2 —
  `SSOTokenPolicySilent` required)**.
- Recovery: restore config; roll forward. Old binary + new config is safe
  (feature is additive, default-off; no migration state to reconcile — no
  schema in this design).
- Validation: `sso_token_policy_evaluations_total` resumes; a test deny
  fires its event; the F2 alert clears.

### D4 — Stale state: policy snapshot diverges from intent (rename/reorder)

- Trigger: operator renames a rule or reorders overlapping rules; historical
  events keep the old `policy_name` (name-based attribution, design risk 4).
- Expected: behavior changes at the next boot (memory store is
  config-sourced); audit joins across the rename boundary break.
- Detection: **none — no per-rule metric** (by design, bounded cardinality);
  the drift is visible only when triaging old events against current rules.
- Recovery: none needed for service; document `policy_name` as
  non-stable (observability.md); track stable rule IDs as a follow-up
  (explicitly out of scope — correct call).
- Validation: the design's `DeniedBy` determinism tests (second-of-two rules
  denies ⇒ `DeniedBy` = second rule name); runbook note that renames
  invalidate historical joins.

### D5 — Restore: audit evidence loss / retention boundary

- Trigger: default memory backend after a restart (all denials lost); or
  `audit.retention.*` prune at the chain boundary.
- Expected (with F3 remediation): durable backend + chain configured —
  restart resumes the chain from the persisted tip (`WithHashChain`
  tip-resume, verified in recorder.go); prune breaks the chain at the
  boundary unless re-chained (sqlite maintenance three documented postures,
  compliance F2).
- Detection: memory backend — **nothing** (no counter for ring wrap, no
  boot warning); prune — no alert (operator-owned decision).
- Recovery: restore from the audit file/volume backup; `sso-ctl
  audit-verify` validates the restored chain; document the retention
  window ≥ evidence window and the prune + verify runbook step.
- Validation: after restore, a historical deny event is queryable and the
  chain verifies end-to-end across the restart seam.

---

## 5. Launch blockers, rollback triggers, monitoring gaps, residual risks

### Launch blockers (must land with the design)

1. **F1**: `SSOTokenPolicyDenialRate` alert + runbook paragraph (denial
   triage via audit query; config+restart is the only mitigation).
2. **F2**: `SSOTokenPolicySilent` alert (the `SSORiskScorerSilent` pattern
   applied to `sso_token_policy_evaluations_total`) — closes the
   governance-silent window this design's fail-open table documents but
   does not detect.
3. **F3**: observability/config-reference requirement text — durable audit
   backend + `hash_chain: true` for `token_policy_denied` to count as
   evidence; memory-ring wrap documented as uncounted loss.
4. **F4**: add the event to `allKnownEventTypes` (conformance-guarded
   CEF/OCSF) — closes the silent OCSF fallback.
5. The design's own acceptance tests (exactly-1 counts per seam, allow/
   unwired/store-error = 0, `Reason` set membership, auth-code
   success-with-event semantics).

No change to the wire contract, no new storage, no new config knob — the
blockers are all detection/documentation surface around the new event.

### Rollback triggers (stop-the-roll criteria)

- `sso_token_policy_denials_total` rises for a rule not intended to bite
  (matched-policy deny is the only fail-closed path; treat any unexplained
  deny rate as rollback-worthy — design's own stance, now with an alert).
- `SSOAuditEventsDropped` fires during the rollout window (the new event
  pushed the pipeline over its buffer — the design's emission is the
  deltas).
- Boot failures across the fleet on `ParseYAML` errors (config, not code).
- The design's `DeniedBy`-branch or registration tests fail (branch drift /
  silent uncategorized placement).

Rollback mechanics (verified safe): the old binary predates the event type —
no event emitted, no schema to reconcile (no storage in this design), audit
rows of an unknown type are inert to older binaries (hash chain is
byte-based). The one rollback hazard is **evidence discontinuity**: events
recorded by the new binary sit in the chain with a type older binaries'
tooling may not know — verify `sso-ctl audit-verify` still passes on the
mixed chain, and do not roll back an evidence-bearing deployment without
exporting the audit trail first.

### Monitoring gaps (post-launch backlog)

- No token-policy alert of any kind (F1/F2 — blockers).
- Sync sink errors are log-only; no `sso_audit_sink_errors_total` exists for
  the non-async composition (D1 detection fails without async).
- Memory ring wrap is uncounted (F3) — no metric exists for the stock
  default backend.
- No SLO/burn-rate alert for token issuance (F7 — decision needed).
- No alert on `sso_token_policy_evaluations_total` absence for
  policy-configured deployments (covered by F2's alert).
- Edge/gateway has no alerting at all (5xx, JWKS fetch, cache staleness) —
  prototype boundary (A5); unchanged by this design.
- `audit.retention.*` and prune chain-break have no alert and no runbook
  (compliance F2; operator decision documented in §3 F7).
- The stock config's `audit.api_enabled: true` + `backend: memory` means the
  audit query API reads a process-local ring — cross-replica audit queries
  return different data; the admin gate requirement (compliance F3) is
  composition-dependent and should be stated in the observability doc.

### Residual risks

1. **Amplification without rate limiting** (F5) — accepted with
   documentation for this change; the ordering fix
   (scope-combo after `checkGrantRateLimit`) is a tracked follow-up with an
   oracle-safe 429-vs-`invalid_scope` precedence change.
2. **Evidence volatility under stock defaults** (F3) — accepted only with
   the documented requirement + operator decision; the design's SOC2 value
   is contingent on a durable, chained audit configuration that nothing in
   the build enforces.
3. **Name-based attribution** (design risk 4) — accepted, documented;
   stable rule IDs are a follow-up.
4. **Silent governance-off on config removal** (F2) — accepted only with the
   `SSOTokenPolicySilent` alert.
5. **Evaluation counter seam-incompleteness** — the session seam's allow
   path is not counted; the F2 alert must not be read as a full gate
   counter.
6. **Mixed-version evidence chains** — rolling rollback across an
   evidence-bearing deployment requires export-before-rollback (above).
7. **No availability SLO** — the measurement decision (F7) is a launch
   prerequisite for any availability claim; the design itself does not need
   one, but operators should not assert one exists.

### Bottom line

The design's operational delta is small and well-bounded: one event per deny,
no new storage or dependency, default-off, oracle-safe wire. What is missing
is the **detection layer around the new signal**: two alert rules (denial
rate, engine-silent) that follow existing in-repo patterns exactly
(`SSORiskScorerSilent`), one conformance-list entry, and documentation that
the stock audit defaults do not make this event durable evidence. With the
five launch blockers in place, the outage (D1), saturation (D2), bad-rollout
(D3), stale-state (D4), and restore (D5) drills all pass their detection
steps; today, D1 (non-async), D2, and D3-silent-off fail detection. No
blocker is a code change to the design's two one-line seams — every blocker
respects the 493/500 and 481/500 file budgets by living in alert files, docs,
and test lists.
