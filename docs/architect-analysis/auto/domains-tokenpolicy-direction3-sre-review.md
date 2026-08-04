# SRE Review: tenant-dimension + subject-aware token-policy selectors (direction 3)

Reviewer role: SRE engineer. Input: `docs/auto/domains-tokenpolicy-direction3-design.md`
(design-only; no `.go` changed) plus the current tree's operational surface:
the four policy seams, `domains/tokenpolicy`, `platform/metrics`,
`cmd/sso-server` wiring (build paths, config loader, reload, ready checks),
`ops/deploy/grafana/alerts.yaml`, `ops/deploy/openresty` edge, and the
deployment/DR/observability docs.

Scope: can operators **detect, withstand, and recover** from failures of the
new tenant/subject/role selector dimensions — including the new per-login
`TenantUserStore.Get` dependency, the strictness flip, and the
binary/config skew a rolling rollout introduces? The direction-2 SRE review's
findings (denial-rate + engine-silent alerts, evidence durability, edge
passthrough) are carried forward where this design inherits them; this review
adds the operator-facing layer specific to direction 3.

**Verification run for this review.** Read-only; no `.go` files changed, no
build gates run. Evidence below was re-derived by direct file reads on the
current worktree (HEAD `ff690260` "Stage: design", which carries unrelated
pre-existing modifications under `cmd/sso-server/*`, `config/*`, `docs/*`,
`ai-dev/*`, `.pi/*` — not touched):

- `interfaces/sso/server_token.go` — **exactly 500 lines**; scope-combo deny at
  `dispatchTokenGrant` line 168 (`denyTokenScopeCombo(ctx, client.ID, scopes)`),
  before `checkGrantRateLimit`; **Verified**
- `interfaces/sso/server_oauth.go:162` (481 lines) — `sessionPolicyCapExceeded`;
  `server_logout.go:345` — `createSession(..., tenantID, ...)` calling it at
  `:357`; **Verified**
- `createSession` call sites — `server_finish_login.go:149` (tenantID threaded),
  `server_login_auth.go:487` (tenantID threaded), **`server_oauth.go:223`
  federated callback: empty clientID AND empty tenantID**; `ensureJITMembership`
  at `server_finish_login.go:46` runs before `createSession` at `:149`;
  **Verified**
- `domains/tokenpolicy/evaluate.go:53-63` — `matches()` exact ClientID,
  `scopePresent` trailing-`*` precedent (`:69-78`); `yaml.go:19-24` non-strict
  `yaml.Unmarshal`; `yaml_test.go:59-72` asserts `other: 1` parses as zero
  policies; `domains/conditionalaccess/yaml.go:29-39` `DisallowUnknownField` +
  per-policy Validate precedent; **Verified**
- `platform/metrics/metrics_token.go:75-125` — `sso_token_policy_{evaluations,
  denials,renew_required}_total`, decision/reason labels only, collectors
  registered only when a store is wired; **Verified**
- `cmd/sso-server/` — `WithTenantUserStore` appears **nowhere** (grep across
  `cmd/`); no sqlite tenant-user store builder in `serverbuildstore`; no config
  key; the stock binary wires `WithTenantStore` (tenant.Store) only
  (`build_app_oauth.go:65-67`); **Verified — stock binary never wires the
  tenant-user store**
- `cmd/sso-server/config/source.go:257-275` — `decodeStrictWithFallback`:
  unknown keys **warn and re-decode non-strictly** (whole-config fallback);
  **Verified**
- `cmd/sso-server/build_app_security.go:277-288` — `BuildTokenPolicyStore` +
  `WithTokenPolicy` wiring; `Makefile` `config-validate-all` runs
  `--validate-only` through the server binary; none of the 7 shipped configs
  contains a `token_policies` section; **Verified**
- `cmd/sso-server/main_wiring.go:121-190` — SIGHUP reload covers log level,
  rate limit, feature gates only; `token_policies` not hot-reloadable;
  **Verified**
- `ops/deploy/grafana/alerts.yaml` (full read) — 11 rules; **no rule references
  `sso_token_policy_*`, tenant-store, or role-resolution signals**; **Verified**
- `ops/deploy/openresty/conf.d/sso.conf` — `/token` and `/health` pass
  straight through, no edge rate limit/body limit; **Verified (unchanged)**
- `docs/deployment.md` — no token-policy entry; `docs/observability.md:52`
  documents the three metrics; **Verified**
- `make ci` target (`Makefile:244`) — `fmt vet race build examples proto-lint
  ci-modules config-validate-all modules-check modules-smoke route-contract
  capabilities-check sdk-surface-check profiles-evidence`; **`docs-validate`
  (kin-openapi) and `docs-check` are NOT in ci**; `checks/route_contract.py:
  160-215` validates route presence + operationId only, not schema items;
  **Verified — design risk 9's "make ci OpenAPI check" is overstated**
- `infrastructure/defaultimpl/issue_payload.go:40-58` — `buildAccessPayload`
  enumerates claims explicitly, no tenant field; **Verified**
- `interfaces/sso/server_token_clientauth.go:170` — `clientTenantOK` gate
  precedes token dispatch; `domains/tenant/client_gate.go:18-30` — returns
  true when tenant middleware is not wired (best-effort resolution);
  **Verified**
- `platform/audit` — no `EventTokenPolicyDenied` anywhere (direction-2 event
  remains spec-only); **Verified**
- `docs/dr-framework.md:54-70` — RPO/RTO level targets exist; no availability
  SLO anywhere (grep of deployment/observability/dr docs); **Verified**

---

## 1. Service/dependency map and operational assumptions

```text
                 ┌──────────── external boundary (prototype) ────────────┐
  browser SPAs ──┤ OpenResty edge: /token, /health pass through;         │
  (separate      │ /api/v1/* + /userinfo gated by user-JWT auth.verify();│
   projects)     │ no edge rate limiting                                 │
                 └───────┬───────────────────────────────────────────────┘
                         │ XFF / X-Trace / X-Network / X-Auth-* (trusted-proxies gated)
                ┌────────▼─────────────────────────┐
                │  sso-server replica (stateless)  │  probes OUTSIDE ratelimit
                │  /livez /readyz /metrics         │
                └───┬──────┬──────┬──────┬─────┬───┘
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
                              │ matches(): tenant → client →    │
                              │ subject → roles → scopes        │
                              └────────────────────────────────┘
        NEW (embedding-only) dependency: TenantUserStore.Get (tenant,user)
        at the session seam — one keyed READ per login, fail-open
```

**What the design adds to this topology**:

1. Three new selector dimensions on the existing pure `Evaluate` path — zero
   new storage, zero schema, zero migration. Policy recovery stays
   "config change + restart" (memory store is boot-sourced; SIGHUP does not
   cover it; admin surface is read-only).
2. One new **runtime read dependency** at the session seam:
   `TenantUserStore.Get` — but only when the store is wired, and **the stock
   `cmd/sso-server` never wires it** (see F1). In the stock binary the new
   dependency does not exist; in SDK embeddings it is one keyed point read per
   login (see F4 for the unconditional-lookup cost).
3. A strictness flip: unknown YAML keys in a bundle and new `Validate` shape
   rules become **boot failures** (fail loud), and inline-config typos warn at
   the config layer (see F2 — the inline path does not fail boot).

**Operational assumptions (current tree, re-verified):**

- A1. `subject_roles` is **unreachable in the stock sso-server**: no
  `WithTenantUserStore` wiring, no config knob, no sqlite builder in
  `cmd/`. The dimension exists only for SDK embeddings (tests wire
  `defaultimpl.NewMemoryTenantUserStore`). This is the single most
  operator-relevant fact about this design (F1).
- A2. Tenant and subject selectors ARE reachable in the stock binary:
  `client.TenantID` is a client attribute (tenant config), the mismatch gate
  (`clientTenantOK`, `server_token_clientauth.go:170`) precedes all four
  seams, and `ClientOK` returns true when the tenant middleware is not wired —
  so the design's "tenant always from `client.TenantID`, never the header"
  choice is the correct one (the header-derived tenant is best-effort).
- A3. Inline-config strictness is **warn-only by the config loader's design**
  (`decodeStrictWithFallback`): a misspelled field in
  `token_policies.policies` is dropped with a boot warning, and any unrelated
  unknown key anywhere in config.yaml disables strictness for the whole
  config on that boot (F2).
- A4. Binary/config skew during rolling rollout or rollback silently demotes
  tenant rules to global rules on old binaries (non-strict `yaml.Unmarshal`
  drops the new fields) — tighten-only in direction, but fleet-wide and
  silent (F3).
- A5. The deny metric surface stays reason-only (correct — tenant/subject
  labels would be unbounded cardinality); detection of "a tenant rule stopped
  matching" has **no signal today**: `sso_token_policy_evaluations_total`
  counts decisions, not matches (F2 of direction 2 does not cover this; F1/F4
  here add the two new inertness classes).
- A6. No availability SLO exists; RPO/RTO are DR-report targets only
  (`docs/dr-framework.md`). This design adds no storage, so backup/restore
  surface is unchanged; policy state recovers via config redeploy, not
  backups.

---

## 2. Readiness table

| Signal | Dependency | Failure behavior | Alert today | Runbook today |
|---|---|---|---|---|
| `/livez` | process | 200 while handler runs | `SSOInstanceDown` (critical) | `ops/deploy/baremetal-ha/RUNBOOK.md` (validation draft) |
| `/readyz` (aggregate, 3s bound) | named checks | 503 + per-check map; pod drained | none per-check | none |
| `/readyz: sqlite-tenant` | `tenant.Store` Ping | drains replica (sqlite-backed only) | `SSOSigningKeyAggregationDegraded` for bus only | none |
| `/readyz: audit-<backend>` | primary audit sink Ping | drains replica only for sqlite/postgres; MemorySink no-ops (stock default has no audit readiness signal) | none | none |
| policy store (memory) | boot-sourced snapshot | `Policies()` never errors after boot; no Ping, no ready check | none | none |
| **`TenantUserStore` (NEW read dep)** | **embedding-wired store; NO ready check in stock, and none registered by cmd** | store outage ⇒ fail-open role lookup (roles inert), login unaffected; **undetectable except logs (F4)** | **none** | **none** |
| `/metrics` | — | outside ratelimit | 11 rules; **none reference `sso_token_policy_*`** (direction-2 F1/F2 still open) | dashboard `sso-overview.json` |
| `sso_token_policy_evaluations_total` | engine wired | series absent when unwired; counts decisions, not matches | none | none |
| `sso_token_policy_denials_total` (reason labels) | deny decisions | rising = governance blocking | none | none |
| `GET /api/v1/admin/token-policies` | memory snapshot | always 200; carries new fields verbatim after this change | none | none |
| Edge `/token` + `/health` passthrough | OpenResty | no edge rate limit/body limit | none (edge has no alerting) | none |
| boot config (`--validate-only`, `config-validate-all`) | `BuildTokenPolicyStore` | strict bundle errors fail boot → crash-loop → `SSOInstanceDown`; **inline typos warn only (F2)** | `SSOInstanceDown` | none |

---

## 3. Findings

### F1 [High] — `subject_roles` is unreachable in the stock sso-server, and the inertness is undetectable

- **Evidence**: grep of `cmd/` for `WithTenantUserStore`/`TenantUserStore`:
  **zero hits outside tests**; `interfaces/sso/options_passwd.go:363-366`
  wires it via an SDK option only; no sqlite builder in
  `cmd/sso-server/serverbuildstore/`; no config key; `docs/config-reference.md`
  has no mention. The design's Decision 4 presents the session seam as the
  enforcing seam for role rules ("a policy may legitimately pair roles with
  `max_active_sessions`, which the session seam enforces") and its failure
  table lists `tenantUserStore nil` as "single-tenant/legacy build
  byte-identical" — but **the stock binary is always the nil-store case**, at
  every seam. `sessionPolicyCapExceeded` (server_oauth.go:162) will skip the
  lookup; refresh already no-ops by design.
- **Production impact**: an operator of the shipped API server who configures
  `subject_roles: [admin]` (the design's headline capability) gets a rule that
  loads, evaluates, and **never matches** — with no boot warning, no log, no
  metric delta (evaluations keep counting `allow`), and no audit event (the
  direction-2 deny event remains spec-only in this tree). The design's own
  documented mitigation for the refresh seam ("documented limitation") does
  not exist for the session seam in the stock binary. When direction-2 events
  land, role rules will produce no denies → SOC evidence gap indistinguishable
  from "no violations". This is the README evidence-standard class: an SPI
  existing in the tree does not prove the stock binary exposes it.
- **Remediation** (one of, design-owner decision):
  1. Boot-time warning when the wired policy set contains `subject_roles`
     but no tenant-user store is present (emit in `buildApp` after option
     composition, or a `Server` startup check) — minimum viable detection;
  2. `docs/config-reference.md`: state that `subject_roles` requires
     `WithTenantUserStore`, which the stock `sso-server` does not wire —
     the feature is embedding-only until a store builder ships;
  3. Or wire a sqlite `TenantUserStore` builder into the stock binary
     (scope decision — makes the dimension reachable and adds the
     dependency of F4 to stock).
  Also pin in the acceptance tests: nil-store + role rules ⇒ no match, plus
  the boot-warning behavior.
- **Recovery validation**: build the stock binary with a `subject_roles`
  policy; assert the boot warning fires, evaluations count allows, and no
  deny ever fires; then wire the memory store (embedding) and assert the
  rule denies. The delta between the two runs is the capability.

### F2 [Medium] — Design claim 3c is not achievable for the inline path: misspelled selector fields are dropped by the config loader before `Validate` runs

- **Evidence**: `config/source.go:257-275`
  (`decodeStrictWithFallback`) — unknown keys produce a WARNING and the
  whole merged config is **re-decoded non-strictly**; the misspelled field
  never reaches `Policy`. `BuildTokenPolicyStore`
  (`build_governance.go:197-223`) then sees a legal global rule
  (`TenantID == ""`) and `Validate` passes it. The design's 3c claim ("A typo
  in `token_policies.policies` fails boot ... no 'looks active but is
  actually global' intermediate state") is therefore false for the inline
  path — the exact hazard Decision 3 was built to close survives there. The
  test plan's "misspelled field ⇒ error" cases only exercise the FILE path
  (`ParseYAML`) and direct `Validate` calls, so the drift would pass CI.
  Bonus: any unrelated unknown key elsewhere in config.yaml disables
  strictness for the whole config on that boot.
- **Production impact**: inline config is the more common stock surface;
  a `tennat_id` typo demotes a tenant rule fleet-wide (tighten-only: shorter
  TTLs, and scope-combo denies hitting other tenants' legitimate traffic)
  with only a warning line in boot logs.
- **Remediation**: (1) document in `docs/config-reference.md`: inline-path
  typos warn (config layer), file-path typos fail boot; (2) add an
  acceptance test pinning the actual behavior (inline misspelling ⇒ config
  warning + rule is global); (3) design-owner option: strict-parse the
  inline list by round-tripping `Policies` through `ParseYAML` in
  `BuildTokenPolicyStore` (catches dropped fields) — or accept warn-only.
- **Recovery validation**: stage an inline config with `tennat_id: ta`;
  verify the boot warning + global rule via `GET /api/v1/admin/token-policies`;
  then implement remediation (3) and verify boot fails instead.

### F3 [Medium] — Rolling rollout/rollback skew silently demotes tenant rules to global rules on old binaries

- **Evidence**: old binaries parse bundles with non-strict `yaml.Unmarshal`
  (current `yaml.go:19-24`); a bundle with `tenant_id`/`subject`/`subject_roles`
  deployed while old replicas are still serving drops the fields and applies
  the rule **fleet-wide**. The strictness change protects only the new binary.
  Also: existing bundles containing `client_id: "prefix*"` are inert today
  (exact match never fires) and **silently activate as prefix wildcards** on
  the new binary — previously-inert rules start firing (tighten-only).
- **Production impact**: during a rolling deploy or a binary rollback with a
  shared/newer config, tenant A's "TTL ≤ 5m" or "block [admin:*, openid]"
  rule applies to every tenant on stale replicas — cross-tenant tightening
  with zero error, no metric, and no log. Fail-closed surprise: other
  tenants' legitimate scope combos can be denied with generic
  `invalid_scope` on stale replicas while new replicas allow them
  (request-routing-dependent behavior).
- **Remediation**: (1) rollout-ordering runbook paragraph in
  `docs/deployment.md`: deploy binary first, config after; on rollback,
  revert config before binary; (2) release notes call out both flips
  (unknown keys now fail boot; `client_id` trailing-`*` activates);
  (3) add to the rollback triggers (below) a cross-tenant deny-rate check
  during the rollout window.
- **Recovery validation**: drill D3 — stage one old replica + new config
  behind the LB, verify its denies/TTL clamps apply globally while new
  replicas scope them; then fix ordering and verify the window closes.

### F4 [Medium] — Fail-open role resolution has no metric and no trace correlation; the lookup is a new unconditional per-login read in embeddings

- **Evidence**: the design's seam code logs
  `logger.Error("token policy: role resolution failed — role selectors inert
  (fail-open)", "tenant", ..., "user", ..., "error", ...)` — log-only, no
  counter; the design's "no new metrics" stance keeps it that way. The
  lookup runs on **every** login when the store is wired and the client is
  tenant-bound, even when zero rules use roles (the pre-scan is explicitly
  rejected as premature optimization). `interfaces/sso`'s logger is not
  request-bound (unlike `tokengrant.LogErrorCtx`), so the error line lacks
  trace correlation.
- **Production impact**: in embeddings, a tenant-user store outage (a) makes
  role selectors inert at session creation with no signal except logs,
  (b) emits one error log per login — a flood at login volume, (c) adds the
  store's latency to every login even with zero role rules. Session-creation
  p95 now includes a new read hop the design does not measure.
- **Remediation**: (1) add a bounded counter
  `sso_token_policy_role_resolution_errors_total` (no tenant/user labels) and
  fold it into the direction-2 F2 "engine silent" alert principle; (2)
  document in `docs/observability.md` that the session seam's role lookup is
  unconditional when wired + tenant-bound; (3) measure `Get` latency
  contribution to login p95 before/after; revisit the pre-scan if it moves.
- **Recovery validation**: drill D1 — stage a store outage in an embedding;
  verify login continues (fail-open), the counter rises, and the alert fires;
  restore the store and verify role rules resume.

### F5 [Medium] — The "make ci docs gate" the design relies on does not exist

- **Evidence**: `make ci` (Makefile:244) contains no `docs-validate`
  (kin-openapi schema validation) and no `docs-check`;
  `checks/route_contract.py:160-215` validates route presence + operationId
  only — the policy-item schema fields (openapi.yaml:6836 area) and
  `docs/config-reference.md` prose are enforced by review discipline alone.
  Design risk 9 states "make ci OpenAPI check requires it in the same
  change" — no such check exists; only YAML *syntactic* validity is
  incidentally enforced (route-contract's `yaml.safe_load`).
- **Production impact**: a future edit can ship the new selector fields
  without the docs, or with wrong prose (e.g., "tenant rules can widen"),
  and CI stays green — the design's own invariant documentation is
  unenforced, exactly as direction-2 F4 found for observability.md.
- **Remediation**: state the real gate in the handoff; optionally add a
  route-contract or unit-test assertion that the policies item schema
  contains `tenant_id`/`subject`/`subject_roles` (cheap, makes the docs
  change CI-enforced).
- **Recovery validation**: delete the three fields from openapi.yaml →
  `make ci` stays green (proves the gap); add the assertion → CI goes red
  (proves the fix).

### F6 [Low] — Federated seam excludes tenant AND role selectors; direction-2 events are not in this tree

- **Evidence**: `server_oauth.go:223` —
  `createSession(ctx, result.UserID, "", "", nil, result.AuthTime)` — empty
  clientID and empty tenantID, so tenant and role selectors can never match
  federated-callback logins even in embeddings (only global, role-less rules
  apply). `platform/audit` has no `EventTokenPolicyDenied` (direction-2
  remains spec-only).
- **Production impact**: operators counting federated logins under
  tenant-scoped `max_active_sessions` rules will find them unenforced;
  direction-2 F6 already documented the empty clientID — extend the note to
  the tenant dimension. Sequencing: when direction-2 events land, they
  should carry the tenant via `audit.SetMeta` (bounded cardinality is fine
  for audit), or tenant attribution of policy denials will be impossible.
- **Remediation**: one sentence in `docs/config-reference.md` and
  `docs/observability.md`; note the sequencing in the direction-2 handoff.
- **Recovery validation**: none needed (documentation); pin with the
  design's federated-seam acceptance test if one is added.

### F7 [Info] — The design's `server_helpers.go` budget arithmetic is off by two lines

- **Evidence**: `server_helpers.go` is at 493 lines. The design says
  "493→495: exactly the two `PolicyInput` lines, nothing else" — but both
  seam functions change signature (`denyTokenScopeCombo` and
  `EnforceRefreshDepthPolicy` each gain a `tenantID` param, +1 line each)
  plus the two `PolicyInput` lines ⇒ 493+4 = **497**, not 495. Headroom is
  3 lines, not 5.
- **Production impact**: none today (still under 500), but the design's
  tightest-gate analysis is the one implementers plan against; correcting
  it prevents a surprise gate failure mid-change.
- **Remediation**: correct the design text; keep the "no extracted helper in
  server_oauth.go / server_helpers.go" discipline.
- **Recovery validation**: n/a.

### F8 [Info] — No availability SLO, and no measurement defined for this design's new read hop

- **Evidence**: no SLO/burn-rate text in deployment/DR/observability docs;
  nothing measures role-lookup latency or "tenant rules applying" coverage
  (evaluations count decisions, not matches).
- **Production impact**: operators cannot state "X% of logins have policy
  evaluated with tenant context" or an issuance SLO — unchanged from
  direction-2 F7, but the new per-login dependency makes the measurement
  decision concrete: define login p95 budget including the `Get`, or gate
  the lookup on a policy-set scan.
- **Remediation**: the measurement decision (login latency budget; policy
  coverage metric) is a launch prerequisite only if F1-remediation (3) —
  wiring the store into stock — is chosen; otherwise it is an
  embedding-owner decision.

**Positive verifications** (no finding): tenant selectors are reachable in
the stock binary end-to-end (`client.TenantID` threaded at all four seams,
mismatch gate precedes them, key-isolation precedent matches); fail-open
semantics of every new path are consistent with AGENTS.md §3; no new
storage/schema/migration ⇒ no backup/restore/DR surface change; boot-time
`Validate` fails loud (crash-loop ⇒ `SSOInstanceDown`) and
`config-validate-all` exercises it via `--validate-only` for shipped configs
(none currently carry `token_policies`, so CI is unaffected); the
claim-surface pin (no `tenant_id` JWT claim) matches the explicit
enumeration in `buildAccessPayload`.

---

## 4. Failure drills

Each drill: trigger → expected behavior → detection → recovery → validation
gate. Runnable in staging against the current tree plus the design's
acceptance tests.

### D1 — Outage: tenant-user store down (SDK embedding)

- Trigger: sqlite tenant-user store loses reachability mid-flight.
- Expected: `Get` error → fail-open (roles inert, session still created);
  login and wire unaffected; role selectors silently stop matching.
- Detection: **fails today** — log line only (one per login — flood risk),
  no metric, no alert; `/readyz` drains only if the embedding registered a
  ready check for its store (cmd does not).
- Recovery: restore the store; role rules resume on the next login (no
  cache to warm — one keyed read per login).
- Validation (with F4 remediation): `sso_token_policy_role_resolution_errors_total`
  rises, alert fires, log flood stops; a role-rule deny fires after restore.

### D2 — Saturation: login flood × per-login role lookup

- Trigger: credential-stuffing or probe traffic against a tenant-bound
  client in an embedding; every login adds one `Get`.
- Expected: store read volume scales linearly with login rate; stock
  middleware limiter bounds per-IP traffic (1 req/s/IP, memory backend);
  scope-combo deny still precedes the per-grant limiter (direction-2 F5
  ordering unchanged).
- Detection: none today; store latency/error-rate dashboards are the only
  incidental signal.
- Recovery: rate-limit tuning / store capacity; no policy change needed.
- Validation: store read QPS tracks limiter budget, not request count;
  login p95 stays within the F8 budget.

### D3 — Bad rollout: config/binary skew and strictness flip

- Trigger: (a) new config deployed while old replicas serve (or binary
  rollback with new config); (b) bundle with a bare `*`/interior `*`/
  unknown key; (c) config with `subject_roles` on the stock binary.
- Expected: (a) old replicas silently apply tenant rules **globally** (F3 —
  tighten-only, cross-tenant denies possible); (b) new binary fails boot →
  crash-loop → `SSOInstanceDown` (fail loud, correct); (c) silent no-op
  (F1).
- Detection: (a) **none** — cross-tenant deny-rate delta is the only clue
  (add to rollback triggers); (b) `SSOInstanceDown`; (c) **none** (F1 boot
  warning required).
- Recovery: (a) fix ordering — binary first, config after; on rollback,
  config first; (b) fix config, roll forward; (c) remove role rules or wire
  a store.
- Validation: deny-rate baseline per tenant across the rollout window;
  golden-path login per tenant succeeds on mixed-version fleet.

### D4 — Stale state: per-replica policy snapshot and role roster

- Trigger: one replica misses a config push (tenant rule absent); or role
  roster changes mid-session (embedding).
- Expected: replica without the tenant rule behaves exactly as pre-feature
  (looser = old behavior, acceptable); role changes are read live at each
  login (no staleness); JIT-provisioned membership is visible to the seam on
  first login (verified ordering: `server_finish_login.go:46` before `:149`).
- Detection: per-replica config drift is existing (config source chain);
  no new signal needed.
- Recovery: re-push config; the memory store swaps at next boot only (no
  hot reload — recovery bounded by rollout).
- Validation: admin GET on each replica returns the same policy set;
  a JIT member's first login matches a role rule.

### D5 — Restore: policy state loss / rollback

- Trigger: config removed or reverted; replicas restart with an empty
  policy set.
- Expected: governance off (fail-open, byte-identical pre-feature); no
  storage to reconcile; no schema.
- Detection: **none today** — the direction-2 `SSOTokenPolicySilent` alert
  (still unimplemented) is the required signal; evaluations counter
  flatlines.
- Recovery: redeploy config; validate via `GET /api/v1/admin/token-policies`
  + a test deny; audit trail (when direction-2 lands) is unaffected by
  policy-state loss (events already recorded).
- Validation: evaluations counter resumes; a scoped deny fires;
  direction-2 audit query returns events across the restart seam.

---

## 5. Launch blockers, rollback triggers, monitoring gaps, residual risks

### Launch blockers (must land with the design)

1. **F1**: boot warning + `config-reference.md` statement that
   `subject_roles` requires `WithTenantUserStore`, which the stock binary
   does not wire — or the design-owner wiring decision. Without this, the
   headline capability is a silent no-op in the shipped product.
2. **F2**: either the round-trip strict-parse of inline policies in
   `BuildTokenPolicyStore` or explicit warn-only documentation + a test
   pinning the actual inline behavior (the design's 3c claim is not
   achievable as written).
3. **F4**: bounded role-resolution error counter (plus the direction-2 F2
   alert principle) — the new fail-open dependency needs a detection
   signal.
4. **F3**: rollout-ordering paragraph in `docs/deployment.md` + release-note
   items (strictness flip; `client_id` trailing-`*` activation; old-binary
   demotion).
5. The design's own acceptance tests (selector matrix, strictest-wins both
   directions, claim-surface pin, seam-level tenant A/B tests, nil-store
   fail-open), with the F7 budget arithmetic corrected (497/500, not 495).

### Rollback triggers (stop-the-roll criteria)

- Deny rate rises for a rule not intended to bite **on tenants other than
  the rule's tenant** (F3 demotion — the new cross-tenant signal; any
  unexplained deny rate remains rollback-worthy per direction-2).
- Boot crash-loops fleet-wide on strict-parse/`Validate` errors (config,
  not code — roll back config first, then binary).
- Evaluations counter flatlines on a policy-configured deployment
  (governance-off; direction-2 F2 alert is the trigger once it lands).
- Role-rule denies never fire while `subject_roles` rules are deployed on
  the stock binary (F1 — the capability is off; decide wiring, don't
  roll the binary).
- Rollback mechanics (verified safe): no schema, no storage, no new claims
  — old binaries are byte-identical pre-feature. The **only** rollback
  hazard is config/binary ordering (F3): revert config before binary.

### Monitoring gaps (post-launch backlog)

- No token-policy alert of any kind (direction-2 F1/F2 blockers still open).
- No role-resolution error metric (F4) — fail-open invisible except logs.
- No match-coverage signal for tenant/subject/role selectors: evaluations
  count decisions, not matches, so "tenant rule silently stopped matching"
  (design risk 3) and "tenant rules in an unbound deployment" are both
  undetectable; a bounded per-dimension match counter or boot-time warnings
  are the options.
- openapi.yaml item schema + config-reference prose are not CI-gated (F5).
- No availability SLO / login-latency budget including the new `Get` (F8).
- Edge/gateway has no alerting at all (unchanged; prototype boundary).

### Residual risks

1. **`subject_roles` unusable in the stock binary** (F1) — accepted only
   with the boot warning + documentation; a wiring decision is required
   before the capability can be promoted.
2. **Inline-typo demotion warn-only** (F2) — the config layer's
   warn-and-fallback is the mitigation; boot logs must be read.
3. **Old-binary global demotion during skew** (F3) — accepted with rollout
   ordering discipline; no runtime detection exists for it.
4. **Per-login role lookup is unconditional** in embeddings (F4) — one read
   per login even with zero role rules; revisit the pre-scan if login p95
   moves.
5. **Bare-`*` asymmetry** — `Validate` rejects it for the new selectors while
   `scopePresent` keeps match-all for scopes (existing behavior); keep them
   decoupled (design risk 6).
6. **Programmatic `memory.New` seeds bypass `Validate`** — documented
   residual; trusted operator code only.
7. **No hot reload for policies** — recovery from any bad rule is bounded by
   rollout time (unchanged from direction-2 A1).
8. **No availability SLO** — the measurement decision remains a prerequisite
   for any availability claim.

### Bottom line

The design's tenant and subject dimensions are sound, reachable in the
stock binary, oracle-safe, and add no storage or wire surface — the
mismatch-gate precedence, strictest-wins union, and fail-open stances all
check out against the tree. The operational problems are concentrated in
**two silent-capability gaps the design does not detect** (role selectors
unreachable in the stock binary; tenant-rule inertness with no match
signal), **one strictness claim that does not hold on the inline path**, and
**one rollout hazard the strictness flip cannot fix** (old-binary demotion
during skew). All five blockers are detection/documentation surface — no
blocker changes the design's seam logic or its line budgets beyond the
arithmetic correction in F7.
