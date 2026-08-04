# Architecture Review: `docs/auto/interfaces-cors-observability-design.md`

**Reviewer role**: senior architect. **Scope**: docs-only design (no Go edits at
this revision). **Checks that ran**: full read of the design + spec + AGENTS.md
§2/§4 + DIRECTORY_MAP; line-exact verification of every structural claim
against `interfaces/cors/cors.go`, `interfaces/sso/{server_routes,server_login,
origin_validation}.go`, `platform/metrics/{metrics,metrics_ctor,consts,
middleware,conditional_access}.go`, `platform/audit/{recorder,recorder_events,
auditspi/event_types,aliases_spi,auditreport/control_areas,auditreport/drift_test}.go`,
`docs/observability.md`, `directory_fanout_test.go`,
`maintainability_budget_test.go`, `test/{ops,ciba_ping,cors_e2e}_test.go`;
line counts and fan-out via `wc -l` / `ls`; call-site census via `grep`.

Evidence labels: **Verified** = re-checked against source at this revision;
**Inference** = reasoned from verified facts.

---

## 1. Scope, assumptions, and verified architecture summary

### 1.1 Scope

The design adds execution observability to the CORS reject branch: one
synchronous `BlockObserver` callback in `interfaces/cors`, one
`sso_cors_blocked_total` counter in `platform/metrics`, one
`cors_origin_blocked` audit event in `platform/audit`, and one contract/E2E
layer (`docs/observability.md` rows + `test/cors_observability_test.go`). It
changes no allow/deny semantics, no config surface, no wire behavior. The
login gate's 403 + `iss` (RFC 9207 §2) is preserved; only its log line at
`server_login.go:174` is removed.

### 1.2 Assumptions

1. Direction-三 non-goals hold: no CORS semantics change (方向一), no config
   surface (方向二), no raw-origin/path Prometheus labels, no new
   `Err*`/endpoint/config knob, no audit throttling.
2. The committed budgets are regression boundaries: file ≤ 500 lines,
   ≤ 10 non-test files/dir, `interfaces/sso` at its frozen 60-file ceiling,
   `platform/audit` at its frozen 16-file exemption, exemption maps shrink-only.
3. "One rejected request ⇒ exactly one counter increment, one audit event,
   one log line" is the design's core invariant and is evaluated as such.

### 1.3 Verified architecture summary (layer map, dependency direction, ownership)

All edges in the design's layer map are legal and, except one, already exist:

| Edge | Direction vs. gate | Status |
|---|---|---|
| `interfaces/sso → interfaces/cors` | same-layer | exists (`server_routes.go:12`) |
| `interfaces/sso → platform/metrics` | downward | exists (`server_routes.go:17`; `s.metrics` field) |
| `interfaces/sso → platform/audit` | downward | exists (`s.auditor`) |
| `interfaces/cors → (nothing new)` | — | **Verified**: imports are stdlib-only (`net/http, strconv, strings, time`); `BlockObserver` is a plain interface — the package stays dependency-free and the layer boundary holds |
| `platform/metrics` (internal) | — | new field + register function; self-contained |
| `platform/audit` (internal) | — | new const + helper in existing files |
| `platform/audit → platform/metrics` | same-layer, **new** | legal per `architecture_layer_test.go` (only upward edges are blocked) but avoidable — see I-1 |

Chain order, verified at `server_routes.go:360-466` (outermost → innermost):
`wrapPanicRecovery → tracing → metrics → trustedProxies → ratelimit →
degradation → apiVersioning → bodyLimit → compression → CORS → securityHeaders
→ requestLogger → router`. Consequences that anchor the design:

- **CORS is inside metrics** — a blocked request is already counted by
  `sso_http_requests_total`; the new counter is the origin dimension on top.
- **CORS is inside ratelimit** — preflight/reject floods are bounded when a
  policy is wired (not wired by default: `server_routes.go:393`).
- **Tracing is outermost** — `core.TraceIDFromContext` is stamped before CORS
  runs, so context-based correlation is achievable *if the observer can see
  the context* (it cannot as specified — finding A-1).
- **Probes are outside the chain** (`buildProbeMux`, `server_routes.go:470+`)
  — blocked-origin scrapes cannot self-inflate.
- **CORS is outside securityHeaders/requestLogger** — the observer log is
  *not* the only per-request line when `debugRequestLogging` is on, but that
  logger is debug-gated; at default levels the observer log is the only
  per-request line (consistent with the design's claim).

Ownership (per `DIRECTORY_MAP.md`): the CORS decision belongs to
`interfaces/cors` (2 non-test files, 242/500 lines — headroom verified); the
counter to `platform/metrics`; the event mechanism to `platform/audit`; the
observer implementation and wiring to `interfaces/sso` (60/60 ceiling —
method-in-existing-file is the only legal shape, correctly chosen).

Budget tripwires verified: `metrics_ctor.go` = 497/500 (**design claim
correct**); `metrics.go` = 494/500 (**design missed it** — H-2);
`platform/metrics` = 10 non-test files at the un-exempted cap of 10
(**design missed it** — H-1); `platform/audit` = 16/16 at its frozen
exemption (**design correctly adds no file here**); `interfaces/sso` = 60/60
(**design correctly adds no file here**); `interfaces/cors` = 2/10, 242/500
(**design claim correct**).

---

## 2. Findings table

| ID | Sev | Layer | Finding | Evidence | Recommendation |
|---|---|---|---|---|---|
| **A-1** | **High** | interfaces/cors + sso | **Observer signature cannot satisfy its own emission spec.** `BlockObserver.OriginBlocked(origin, method, path string, preflight bool)` carries no request and no context, but Decision 2 requires the observer to emit `RecordCORSOriginBlocked(s.auditor, ctx, ...)` (trace ID rides the request context) and log `client_ip` (from `RemoteAddr`) and `user_agent` — all request-derived. As written the implementation cannot compile into the specified behavior; the design's own "trace ID rides the context" claim is impossible with a string-only signature. | Design §Shared mechanism interface vs. §Decision 2 observer spec; `core.TraceIDFromContext` requires a context; `RemoteAddr`/`UserAgent()` require `*http.Request`. **Verified** by direct comparison. | Pass `*http.Request` to the observer: `OriginBlocked(r *http.Request, preflight bool)`. The middleware already holds `r`; `interfaces/cors` already imports `net/http`; the Server derives origin/method/path/client_ip/user_agent and reads `r.Context()` for the trace ID. Single-method-interface and 60-file-ceiling constraints are unaffected. |
| **H-1** | **High** | platform/metrics | **New `platform/metrics/cors.go` breaks the directory fan-out gate.** `maxGoFilesPerDir = 10` (`directory_fanout_test.go:34`); `platform/metrics` is **not** in `dirFileCountExemptions` (`:51-65`) and already holds exactly 10 non-test files. Adding `cors.go` → 11 → `TestArchitecture_DirectoryFileFanout` fails; `make ci` fails. The design's central budget-shaped decision (new-file split mirroring `conditional_access.go`) is itself over another budget. | `ls platform/metrics/*.go \| grep -v _test \| wc -l` → 10; exemption map read. **Verified.** | Put `registerCORSBlockedMetrics` in an existing headroom file: `conditional_access.go` (64 lines — the named precedent), `metrics_configaudit.go` (32), `audit_async.go` (90), or `credential_rotation.go` (122). The `metrics_ctor.go` one-line call (497→498) stays as designed. |
| **H-2** | **High** | platform/metrics | **`CORSBlockedTotal` field pushes `metrics.go` past the 500-line budget.** File is 494 lines (`wc -l`); the design's own block (blank + 7-line Help + field = 9 lines) → 503 > 500 → `TestMaintainability_FileSizeBudget` fails. The field cannot leave `metrics.go` (the struct lives there), so the Help comment is the free variable. | `wc -l platform/metrics/metrics.go` → 494; `maintainability_budget_test.go:34` `maxFileLines = 500`; CIBAPingTotal precedent block is 11 lines. **Verified.** | Trim the Help comment to ≤ 4 lines (net +6 → exactly 500, zero margin) and shorten an existing verbose comment in the same change for margin (net ≤ 5). The label/Help contract survives in `docs/observability.md`. |
| **M-1** | Medium | interfaces/sso | **"Must not make it worse" is false for PathOverrides × login gate.** `isOriginAllowed` (`origin_validation.go:103-129`) checks only `AllowedOrigins`/wildcard; the middleware resolves `PathOverrides` (`cors.go:172-180`). With an override allowing an origin on `/auth/login` (prefix match), middleware passes (observer silent by the resolved-policy rule) while the gate still 403s — after the log removal at `server_login.go:174`, telemetry drops from 1 log line to **zero** for that combination. That config is already broken today (403 despite emitted CORS headers), so no working deployment depends on it. | `origin_validation.go:103-129`, `cors.go:172-180`, `server_login.go:166-183`. **Verified** (same finding as security F2 / protocol M-1 / SRE F1, confirmed independently). | **Preferred:** fail-closed config validation — `WithCORS` rejects any `PathOverrides` prefix P where `/auth/login` starts with P (`/`, `/auth`, `/auth/login`), converting an undefined state into a refused config (~10 lines + unit test). **Alternative:** gate-side resolved-policy check emitting a disagreement log (~15 lines, direction-二-adjacent). Document-only (design status quo) is rejected: it breaks the design's own exactly-once invariant for a reachable config. |
| **M-2** | Medium | platform/audit | **`KnownEventTypes` catalog omission.** Decision 2 adds the const and the `aliases_spi.go` re-export but not the entry in the `KnownEventTypes` map (`auditspi/event_types.go:233-290`), whose doc claims "every event type the SDK emits itself" and which backs the webhook-subscription filter UX. No committed test fails on omission (the drift test iterates the map, not the const set), so this is a silent catalog/UX gap, not a gate failure. | `event_types.go:233` map read; `drift_test.go:97-112` iterates `KnownEventTypes`. **Verified.** | Add `EventCORSOriginBlocked: {}` to `KnownEventTypes` in the same change; the CC6.1 classification then satisfies the drift guard as designed. |
| **M-3** | Medium | platform/audit + logging | **Unbounded attacker-controlled values flow into audit metadata and a new all-paths sync log line.** `origin`/`path`/`method` are raw at the HTTP layer (bounded only by Go's 1 MB header/request-line caps; tab is legal in header values); the observer fires pre-auth on **every** path, and the log write is synchronous with no drop path (audit rows are bounded by `sso_audit_async_drops_*`; the log is not). Precedent in-tree is the opposite: `sanitizeMethod` collapses unbounded input (`middleware.go:27`), `observability.md:7` bans per-path labels. | Design Decision 2 emission spec; `recorder.go` fail-open (`Record` swallows sink errors); chain order (ratelimit not wired by default). **Verified.** (Security F1, confirmed.) | Truncate `origin`/`path`/`method` to a fixed cap (e.g., 256 B with an explicit marker) before `SetMeta` and logging; state the volume expectation in `observability.md`; regression-test the cap in `platform/audit` and the closed label set in `platform/metrics`. |
| **L-1** | Low | design text | **"A disallowed preflight is counted as a 2xx" is false** — a disallowed `OPTIONS` with `Access-Control-Request-Method` returns 404 (no CORS headers), i.e. 4xx. Narrative-only; the argument (no origin dimension) survives. | Behavioral probe (protocol/QA reviewers, since deleted); `isPreflight` at `cors.go:148-151`. **Verified.** | Rephrase to "indistinguishable from a legitimate 404/405 in the generic counter"; pin `status 404 + preflight="true"` in E2E case 1. |
| **L-2** | Low | docs | **`observability.md:100` chain diagram already disagrees with code** (`tracing → ratelimit → bodyLimit → metrics → CORS → router` vs. actual `tracing → metrics → trustedProxies → ratelimit → degradation → apiVersioning → bodyLimit → compression → CORS → securityHeaders → requestLogger → router`). Decision 3 edits exactly that block without correcting it; the "preserve documented middleware order" invariant anchors to a wrong diagram. | `server_routes.go:360-466` vs. `observability.md:100`. **Verified.** | Fold the diagram correction into the Decision-3 edit (small, in-scope; E2E case 1 already pins the true order). |
| **L-3** | Low | design text | **Citation drift**: `control_areas.go` CC6.1 at :42-58 not :50-66; `drift_test.go` `wantUncategorizedEventTypes` at :28 not :41; `metrics.go` field at :191; `AdoptionReason*` at `consts.go:201-203` not :142; `test/cors_e2e_test.go` uses `WithCORS` (not a `cors.Middleware` call site — the 10 sites are 9 × `cors_test.go` + 1 × `server_routes.go:452`); `middleware.go` increment at :27 not :16. No material claim is affected. | Direct greps/wc. **Verified.** | Fix the cited lines while the doc is docs-only. |
| **I-1** | Info | platform/audit | **New sibling import edge `platform/audit → platform/metrics`** if the shared `CORSBlockReasonDisallowedOrigin` const lives in `platform/metrics/consts.go` and the helper references it. Legal (same-layer; audit already imports `platform/geo`, `platform/tracing`), but couples audit's event vocabulary to metrics' namespace. | `grep snaplink/ platform/audit/*.go` → zero `platform/metrics` matches today. **Verified.** (Protocol F3 / QA F2, confirmed.) | Parameterize: `RecordCORSOriginBlocked(rec, ctx, reason, origin, method, path string, preflight bool)` — the exact `RecordCIBAPingFailed(rec, ctx, clientID, authReqID, reason string)` precedent (`recorder_events.go:139`). The caller (observer) holds the const; `platform/audit` stays import-free. |
| **I-2** | Info | interfaces/sso | **Panic semantics**: the observer fires before `next.ServeHTTP`; a panic would surface as a 500 via `wrapPanicRecovery` (outermost) instead of the header-less forward — a behavior change in the unreachable case. Nil-guards + closed label vocabulary make it unreachable by construction; acceptable, worth a one-line comment. | Chain order; design failure-mode table. **Verified.** | No action beyond a comment; do not add a `recover()` inside the middleware (consistency with `metrics.Middleware`). |
| **I-3** | Info | interfaces/sso | **PathOverrides-only deployments generate full-volume counter/event baseline** (middleware is not identity when overrides exist; every origin on non-override paths is disallowed, including same-origin fetches). This is the designed misconfig signal; operators need the expected baseline to avoid alerting on self-inflicted noise. | `cors.go:173-176` (identity condition). **Verified.** (Security F4, confirmed.) | One sentence in `observability.md`: "a constant elevated rate with no known probes indicates a PathOverrides posture gap." |

**Verified-positive controls** (no action): oracle-safe response behavior is
untouched (reject branch stays a header-less forward; login gate keeps
403 + `iss` via `authzErrorBody`); cardinality is bounded (≤ 2 series, closed
reason vocabulary, `preflight` structurally bounded by `FormatBool`);
nil-safety (identity short-circuit precedes any observer firing —
structurally impossible to observe disabled CORS); `interfaces/cors` stays
stdlib-only; `platform/audit` adds no file (16/16 ceiling); `interfaces/sso`
adds no file (60/60 ceiling); the variadic `Option` keeps all 10
`cors.Middleware` call sites source-compatible; the drift guard
(`drift_test.go`) forces the CC6.1/CC7.2 decision; CC6.1 is the defensible
bucket (dominant case is benign misconfig, not anomaly); probes/metrics are
outside the chain.

---

## 3. Decision options with trade-offs and preferred option

### D1 — Observer signature (new finding A-1; must be resolved before M2)

| Option | Trade-offs | Verdict |
|---|---|---|
| **A. `OriginBlocked(r *http.Request, preflight bool)`** | Middleware holds `r`; Server derives all Decision-2 payload (origin/method/path/client_ip/user_agent) and reads `r.Context()` for the trace ID. Slight duplication: middleware computes origin for the policy, Server re-reads `r.Header` — trivial. Interface stays single-method; cors package stays stdlib-only. | **Preferred.** Smallest complete fix; the only option that satisfies Decision 2's own emission spec. |
| B. `OriginBlocked(ctx context.Context, origin, method, path string, preflight bool)` | Audit trace correlation works; log loses `client_ip`/`user_agent` (or logs them from nowhere). Payload is partially request-derived. | Acceptable fallback if request-decoupling is valued over log completeness. |
| C. As written (strings only) | Cannot supply ctx/client_ip/user_agent; the audit event would carry no trace ID and the log would lack two of its five fields. | **Rejected** — internally inconsistent with Decision 2. |

### D2 — Shared reason vocabulary across audit + metrics (I-1)

| Option | Trade-offs | Verdict |
|---|---|---|
| **A. Parameterize the helper** (`reason string` param, mirroring `RecordCIBAPingFailed`) | `platform/audit` keeps zero `platform/metrics` imports; the single const lives with the metric where the label-set test enforces it. | **Preferred.** Matches the in-tree precedent exactly. |
| B. Shared const in `platform/metrics` + new same-layer import | Legal; single source of truth in one place; adds a new sibling edge and couples audit's vocabulary to metrics. | Acceptable but unnecessary coupling. |
| C. Duplicate string literals | No import; drift-prone; violates single-source-of-truth. | Rejected. |

### D3 — `metrics.go` 500-line budget (H-2)

| Option | Trade-offs | Verdict |
|---|---|---|
| **A. Trim Help comment to ≤ 4 lines + shorten one existing verbose comment in metrics.go** | Net ≤ 5 added lines (494 → ≤ 499); keeps the operator contract in the Help text and the full contract in `observability.md`. | **Preferred.** |
| B. Trim Help comment to ≤ 4 lines only | Net +6 → exactly 500; zero margin; any unrelated one-line growth in the file breaks the gate. | Fragile; only if A is refused. |
| C. Move the field out of `metrics.go` | Impossible — struct fields must stay in the single struct declaration. | Rejected. |

### D4 — Registration placement (H-1)

| Option | Trade-offs | Verdict |
|---|---|---|
| **A. `registerCORSBlockedMetrics` in an existing headroom file** (`conditional_access.go` 64, `metrics_configaudit.go` 32, `audit_async.go` 90, `credential_rotation.go` 122) | No gate crossing; the file-split intent (isolate CORS metric growth) survives as a function, not a file. | **Preferred.** `conditional_access.go` is the named precedent; `metrics_configaudit.go` has the most headroom. |
| B. New `platform/metrics/cors.go` | Clean file isolation; **fails `TestArchitecture_DirectoryFileFanout`** (10 → 11, no exemption). | Rejected as written (H-1). |
| C. Register body in `metrics_ctor.go` | Fails the 500-line budget (497 + body > 500). | Rejected. |

### D5 — PathOverrides × login-gate silence (M-1)

| Option | Trade-offs | Verdict |
|---|---|---|
| **A. Fail-closed config validation in `WithCORS`** — reject override prefixes P where `/auth/login` starts with P | ~10 lines + unit test; converts an undefined, already-broken config into a refused config; no wire change; keeps exactly-once invariant clean. Does not preclude direction 二's unification later (validation can be lifted then). | **Preferred.** |
| B. Gate-side resolved-policy disagreement log | ~15 lines, direction-二-adjacent; keeps the config legal but adds a second emission path (drift-prone). | Acceptable alternative; more code for the same outcome. |
| C. Document-only (design status quo) | Zero code; breaks the design's own invariant for a reachable config; 1 log → 0 telemetry. | Rejected. |

### D6 — E2E test construction (endorse)

Building a dedicated server with the full option set in
`test/cors_observability_test.go` (rather than overloading `minServer`) is
correct — it keeps the ops test family independent and mirrors the
`ciba_ping_test.go:173-183` wiring pattern (`MemorySink` + `WithMetrics` +
`WithAuditRecorder`). Endorsed as designed.

---

## 4. Prioritized implementation sequence

Milestone boundaries are chosen so each lands green on
`go test -run 'TestMaintainability_|TestArchitecture_' .` and, at the end,
`make ci`.

### M0 — Design fixes (docs-only, current revision)
1. A-1: pin D1-A (`OriginBlocked(r *http.Request, preflight bool)`); restate
   the Decision-2 payload derivation.
2. H-1/H-2: pin D4-A and D3-A; add the `KnownEventTypes` map entry to
   Decision 2's API surface (M-2).
3. L-1: rephrase the preflight claim ("indistinguishable from a legitimate
   404/405"); L-2: note the diagram correction in Decision 3; L-3: fix
   citations.
4. M-3: state the truncation cap and volume expectation in Decision 2.
   **Acceptance:** no `.go` edits; the doc's claims are all source-consistent.

### M1 — `platform/metrics` (counter)
1. Trim a verbose comment + add `CORSBlockedTotal` (net ≤ 5 lines, `metrics.go`
   494 → ≤ 499).
2. Consts (`NameCORSBlockedTotal`, `LabelPreflight`,
   `CORSBlockReasonDisallowedOrigin`) in `consts.go` (headroom verified, 267/500).
3. `registerCORSBlockedMetrics` in an existing headroom file (D4-A); one-line
   call in `NewMetrics` (`metrics_ctor.go` 497 → 498).
4. Unit tests: accepted-label-set assertion `{reason: disallowed_origin} ×
   {preflight: true|false}`; nil guards; name collision check.
   **Acceptance:** `TestArchitecture_DirectoryFileFanout`,
   `TestMaintainability_FileSizeBudget` pass; label-set unit test green.

### M2 — `interfaces/cors` (observer seam)
1. Private `Option` type + `WithBlockObserver`; reject-branch split
   (absent-Origin pass-through before any observer call; observer then
   forward); D1-A signature.
2. Unit tests: empty policy → zero calls (identity fast-path pinned);
   absent Origin → never fires; exactly-once per rejected request;
   PathOverrides-resolved decision (override-allowed origin → silent);
   payload correctness (origin/method/path/preflight derived from `r`).
   **Acceptance:** all 10 existing call sites still compile unmodified
   (`go build ./...`); cors unit suite green.

### M3 — `platform/audit` (event)
1. `EventCORSOriginBlocked` const + `KnownEventTypes` entry (M-2) +
   `aliases_spi.go` re-export.
2. `RecordCORSOriginBlocked(rec, ctx, reason, origin, method, path string,
   preflight bool)` — nil no-op, `SetMeta`-only, truncation cap (M-3).
3. CC6.1 classification in `auditreport/control_areas.go` (block starts :42).
4. Unit tests: nil-recorder no-op; no `Metadata` clobber; oversized values
   truncated ≤ cap with marker; trace ID rides context.
   **Acceptance:** `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`
   green (with and without the CC6.1 entry — the guard fires both ways);
   audit suite green.

### M4 — `interfaces/sso` (observer + wiring)
1. `(*Server).OriginBlocked(r, preflight)` in `origin_validation.go` (file
   grows ~25 lines, 244 → ~270 — headroom verified); counter increment +
   `RecordCORSOriginBlocked` + structured log with `client_ip` from
   `RemoteAddr` (never XFF) and `trace_id` from `r.Context()`.
2. Wiring at `server_routes.go:452` (two lines, always pass `s`).
3. Remove the gate log at `server_login.go:174`; keep 403 + `iss`
   (`authzErrorBody`).
4. D5-A: `WithCORS` override-prefix validation + unit test.
   **Acceptance:** existing `login_early_gate_headers_test.go` and
   `origin_validation_test.go` green (403 + `iss` + no-store preserved);
   `go test -run 'TestMaintainability_|TestArchitecture_' .` green.

### M5 — Contract + E2E
1. `docs/observability.md`: metric row, audit row (with untrusted-input note
   and truncation), middleware-order sentence **plus the diagram correction
   (L-2)**; volume expectation (M-3).
2. `test/cors_observability_test.go` (`package ssotest`): the five pinned
   cases (case 1 now asserts 404 + `preflight="true"`; case 5 asserts 404 on
   blocked request with no series, not "zero series" via `/metrics`), plus a
   D5-A variant (override-prefix rejection) and an M-1 disagreement case if
   D5-B was chosen instead.
   **Acceptance:** `grep sso_cors_blocked_total docs/observability.md` and
   `grep cors_origin_blocked docs/observability.md` hit; E2E suite green.

### Handoff gates
`go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`
after every `.go` edit; `go test ./... -race`; `go test ./test/ -run TestE2E -v`;
`make ci`. Report any pre-existing failure separately.

### Compatibility and rollback plan
- **Source**: variadic `Option` keeps all 10 `cors.Middleware` call sites
  compiling unmodified (verified census: 9 × `cors_test.go` + 1 ×
  `server_routes.go:452`; `test/cors_e2e_test.go` uses `WithCORS`).
- **Wire**: no response change; 403 + `iss` byte-identical; no new
  `Err*`/endpoint/config knob (verified: `error-codes.md`, `openapi.yaml`,
  `config-reference.md` untouched by the design).
- **Ops surface (additive)**: one metric (2 series max), one audit event
  type, one log line whose *field set* changes on `/auth/login` (gains
  `preflight`, `trace_id`) and whose *coverage* widens to all paths —
  documented in `observability.md` and the release notes; operators must
  budget for the widened log volume (M-3).
- **Migration**: none — no schema, no state, no queue. Rollback = revert the
  commit; the gate log returns; counters/events disappear; no data repair.
- **Risks tracked**: double-increment regression (pinned by E2E case 2);
  cardinality creep (const-only vocabulary + label-set test); chain-order
  regression (E2E case 1 asserts counter and `sso_http_requests_total` move
  together); doc drift (grep acceptance in `make ci` scope); metrics/audit
  divergence under sink pressure (designed trade-off, stated in the doc);
  D5-A rejecting a config that direction 二 may later legalize (validation
  is removable at that point).

---

## 5. Unknowns needing owner or product decisions

1. **D5 disposition** — refuse `PathOverrides` prefixes covering `/auth/login`
   at `WithCORS` (fail-closed, my recommendation) or keep the documented
   non-goal and accept the 1-log→0-telemetry corner? Owner: architecture +
   product (direction 一/二 roadmap intent). Decision needed before M4.
2. **Log level and volume budget** — the all-paths `origin_blocked` log at
   Info vs. Debug, and the expected steady-state volume to publish in
   `observability.md`. Owner: SRE/ops. Decision needed before M5.
3. **Truncation cap value** for audit metadata (`origin`/`path`/`method`).
   Security review suggests 256 B with a marker. Owner: security + platform/
   audit. Decision needed before M3.
4. **Alert rule + runbook for `sso_cors_blocked_total`** — the metric's own
   Help text calls for an alert; `alert_rules_test.go` makes a committed rule
   cheap. In-scope for this change or a follow-up? Owner: SRE. Decision
   needed before handoff.
5. **`KnownEventTypes` exposure** — should `cors_origin_blocked` appear in the
   webhook-filter catalog (M-2)? This is additive and harmless; confirm with
   platform/audit ownership. Decision needed before M3.
6. **Metrics/audit divergence semantics** — the designed trade-off (synchronous
   counter vs. best-effort event) should be stated as an explicit contract
   sentence in `observability.md`; confirm the wording with SRE before M5.

---

## Bottom line

The design's architecture is sound where it matters: the observer seam keeps
`interfaces/cors` dependency-free, the emission point is a single reject
branch at the innermost middleware (correct placement by construction), all
layer edges are legal, nil-safety and fail-open semantics mirror in-tree
precedents, and the oracle-safe/OAuth invariants (403 + `iss`, header-less
forward) are untouched. The two budget answers the design *did* check are
correct (`metrics_ctor.go` 497/500, `interfaces/sso` 60/60), and it
correctly avoids adding files to `platform/audit` (16/16).

However, the design misses two hard-gate violations of its own making
(**H-1** fan-out 10→11, **H-2** `metrics.go` 494→503), one internal
inconsistency that makes the specified implementation impossible (**A-1**:
the observer signature cannot carry the context/request its own Decision 2
requires), and one telemetry regression corner it claims to avoid (**M-1**).
All four are small, well-understood fixes (D1-A/D3-A/D4-A/D5-A). With those,
the design is implementable as specified; without them, implementation
verbatim fails `make ci` and cannot meet its own emission spec.
