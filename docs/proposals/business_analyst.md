All contested facts are now verified against code. I have everything needed for the business analysis.

---

# Business Analysis: Unified Middleware Observability (access log + single trace/audit source)

**Subject:** `docs/design/middleware-observability-unified.md` (status: proposed) responding to `docs/proposals/requirements.md` improvements 1–3.
**Verification performed this revision:** re-checked otelhttp v0.68.0 source (server handler `Extract`-only; `Inject` is client-side at `transport.go:142`), `cmd/sso-server/main_logger.go:17` (synchronous `slog.JSONHandler(os.Stdout)`), `server_routes.go:364-407` wrap-order semantics, `server_routes.go:112` (`requestIDMW` gating), `options_security.go:484-497`. Cross-checked against the perf, security, distributed, and QA deliverables. All claims below labeled **Verified / Partial / Proposed / Missing / Contradicted**.

---

## 1. Problem statement, stakeholders, outcomes, non-goals

### Problem statement

The stock `sso-server` today cannot support incident response and forensic correlation without advance operator action:

1. **No access evidence by default.** The only request-level logger is DEBUG-gated and off by default (`RequestLogger`, zero production callers — Verified); the INFO `Logger` records only method/path. During an incident the operator has no per-request record of status/duration/IP — the "fail open with audit/logging" invariant (AGENTS.md §3) is not met for request evidence.
2. **Body logging is an unredacted all-or-nothing boolean.** `WithRequestLogging(logBodies bool)` dumps raw request/response bodies — including `client_secret`, passwords, MFA codes — into the log plane with no allowlist, redaction, or sampling (Verified: `request_log.go`, `options_httpstack.go:224-230`).
3. **Trace correlation is split across two independent chains.** Legacy `Tracing` (self-minted traceparent, `X-Request-Id`) and OTel `tracing.Middleware` are installed simultaneously; audit `EventFromRequest` re-reads legacy headers. Audit trace IDs and span trees diverge (Verified: `build_app_core.go:157-158`, `handler_helpers.go:37-60`).

The design converges these into: an always-on 7-field INFO access log (bodies only via explicit allowlist + redaction + sampling + cap) and one OTel correlation point feeding spans, audit events, and error bodies.

### Stakeholders

| Stakeholder | Interest | What changes for them |
|---|---|---|
| **Operators (sso-server deployers)** | Incident evidence; config simplicity | Gain default-on access records; new `logging.access_log.*` keys (restart-required); OTel endpoint becomes load-bearing for trace correlation; new log-volume/sink-sizing duty |
| **Security / incident responders** | Trustworthy attribution, credential safety | `client_ip` attribution quality; redaction guarantees; audit↔span join now real; **risk:** credential capture via allowlist, forgeable IP in default config |
| **SDK embedders (external)** | Wire stability, compile stability | Source-breaking `WithRequestLogging` signature change; `WithTracingMiddleware`/`WithRequestIDMiddleware` deleted; `WithTracing`-only shape gains `X-Request-Id` headers (see L8) |
| **SRE / DevOps** | Availability, upgrades, log pipeline | Rolling-upgrade mixed-header window; wedged-sink behavior; pipeline sizing for 429 floods |
| **External frontends** | Client-visible headers for support correlation | `X-Request-Id`/`X-Trace-Id`/`Traceparent` availability changes when OTel is unconfigured (one-switch semantics) |
| **Compliance / auditors** | Evidence of record | Audit schema unchanged (provenance only); access log is new, operator-retained, lossy evidence |

### Outcomes (what success looks like, per requirement)

- **R1 (log):** every non-probe request through a default `sso-server` yields exactly one INFO record with fixed fields incl. validated `client_ip` and `status` (429s included); probes exempt; no `query`; no bodies by default.
- **R2 (capture):** body capture requires allowlist + explicit sample rate; redacted (`[redacted]`, over-redaction bias); 4 KB cap; credentials structurally impossible to log **in the default config**.
- **R3 (correlation):** one switch (`WithTracing`) decides span tree + audit `TraceID`/`SpanID`/`ParentSpanID` + `X-Trace-Id`/`Traceparent` + error-body `trace_id`; audit events and spans share one trace ID.
- **Non-functional:** SDK byte-identical by default; zero new durable state; no schema migration; all gates green.

### Explicit non-goals (from design + reviews; business-relevant)

- No new endpoints, durable state, or audit schema change — the log record is the storage (lossy by design).
- No coordinated sampling, no cross-replica ordering/dedup of access records.
- No SLO establishment (none exist in the repo — perf review designs comparison-based gates only, pending operator SLOs).
- No frontend work: external frontend projects are affected only as consumers of response headers, and only in the documented OTel-less direction.
- The access log is **not** a credential-safe record; audit events remain the durable evidence of record. This boundary must survive the implementation (see H4).
- No change to handler/error paths, oracle-safe error semantics, or middleware ordering outside the one new slot.

---

## 2. Requirement table

Classification: **SDK** = `interfaces/middleware` + `interfaces/sso` options; **Stock** = `cmd/sso-server` + `config`; **Edition** = `cmd/sso-minimal` profiles; **External** = frontend projects (contract-only). Priority: P0 = merge-blocking, P1 = same change, P2 = documented follow-up.

| ID | Actor | Requirement | Evidence / status | Priority | Measurable acceptance |
|---|---|---|---|---|---|
| R1.1 | Operator, incident responder | Always-on INFO access log, exactly one record/request, fixed 7-field schema, no `query`, no bodies by default | Problem **Verified** (`request_log.go` DEBUG-gated; `middleware.Logger` 2 fields); behavior **Proposed** | P0 | `accesslog_test.go` A1: full chain → exactly one record with `status`/`duration_ms`/`client_ip`/`request_id`/`trace_id`; zero-value policy ⇒ no `request_body`/`response_body` keys |
| R1.2 | Operator | Slot inside trustedProxies (validated IP) and outside ratelimit (429 evidence); probes exempt | **Verified** prose vs `server_routes.go:364-407` wrap order; **Contradicted** by Decision 2 snippet (inverted — H1) | P0 | Chain-order unit test: `RequestInfoFrom` populated at emit; rate-limited request → record with `status: 429`; `/livez`/`/readyz`/`/metrics` → zero records |
| R1.3 | SDK embedder | SDK default off (`accessLogPolicy == nil`), byte-identical; sso-server default on | **Proposed** (NewServer untouched); tri-state `*bool` precedent **Verified** (`config_gates_test.go`) | P0 | Option-list identity: absent config ⇒ `WithAccessLogging` appended with zero-value policy; `enabled: false` ⇒ option absent, chain identity unchanged |
| R1.4 | Operator | `logging.access_log.enabled` tri-state (nil=on), documented restart semantics | **Proposed**; reload `Ignored` default **Verified** (`config/reload/reload.go` — no code change needed) | P0 | Config tests (gap — QA F7): absent ⇒ option present; explicit false ⇒ absent; reload of key lands in `ignored_requires_restart`, live chain unchanged |
| R1.5 | Operator | Fail-open: log-sink failure never degrades auth | **Contradicted** — `main_logger.go:17` synchronous blocking stdout write; failure table row false; closed pipe can SIGPIPE-kill the process (H3) | **P0 release blocker** | Regression: blocking writer ⇒ request completes and record drops (async fix), or failure table corrected to blocking semantics with EPIPE handling |
| R1.6 | SDK embedder (streaming) | Capture/status writer preserves `Unwrap()`/`Flusher`/`Hijacker`/`Pusher`/`ReaderFrom` | **Missing** in design; no in-tree handler breaks today but admin SSE uses `http.NewResponseController` (QA F5, Sec F6) | P1 | Unit: `NewResponseController(w).Flush()` succeeds through wrapper; SSE e2e (`TestSSEEventsStreamEndToEnd`) with `WithAccessLogging` installed → ≥1 event + heartbeat |
| R1.7 | Incident responder | Panicking requests still emit a record (exactly-one contract) | **Missing** — `Recover` is outermost; post-`next` emission skips panics (Perf F5) | P1 | Unit: panicking handler → exactly one record, `status: 500` |
| R2.1 | Operator | `BodyLogPolicy` (paths allowlist / deprecated `AllowAllPaths` / `sample_rate` / 4 KB cap) replaces boolean; old signature compiles to `{AllowAllPaths: true}` | **Proposed**; zero prod callers **Verified** (only `request_logging_test.go:60`); migration mapping **Contradicted** — `SampleRate` default 0 ⇒ captures nothing (M2) | P0 | B2: non-allowlisted path ⇒ no body fields; allowlisted path ⇒ captured, capped at 4 KB (cap vs cap+1); migration test: `AllowAllPaths` alone captures nothing; `{AllowAllPaths: true, SampleRate: 1.0}` reproduces old behavior modulo redaction/cap |
| R2.2 | Operator, security | Redaction: form+JSON parsed, exact + substring heuristic (`secret\|password\|token\|assertion\|code`), nested walk, fixed `[redacted]`; non-structured = capped raw (documented) | **Proposed**; vocabulary covers current credential fields **Verified** (Sec F7) except WebAuthn keys (QA F6) and JAR `request` (L2) | P0 | B1 table + grep-absence over the whole record: raw values absent incl. nested JSON/arrays, `pwd=`-style names, WebAuthn `clientDataJSON`/`authenticatorData`, `request=<JWT>` |
| R2.3 | Operator, security | Credential endpoints never log bodies even with policy on (req B1: "/token 即使策略开启也永不记录 body") | **Renegotiated by design** (open point; Sec F2 High) — allowlist/`AllowAllPaths` makes `/token` capturable; headline guarantee "凭据从设计上不可能落盘" becomes config-conditional | **P0 decision** (DQ1) | Either hard non-overridable deny-set (credential surfaces enforced under `AllowAllPaths`, contradictory configs rejected at boot; table-driven test incl. out-of-vocabulary names) **or** explicit product renegotiation with reworded acceptance |
| R2.4 | Operator | Sampling: stateless Bernoulli, explicit only, 0=off, capture-only | **Proposed**; `math/rand` global locked source under sampling (Perf F2) | P1 | B3 binomial CI ≈250±45/1000 at 0.25 (accept ±4σ flake tolerance, QA F9); `-mutexprofile` shows no `lockedSource` |
| R2.5 | Operator | Config `logging.access_log.body.*` maps 1:1; contradictory combos rejected | **Proposed**; validation **Missing** (Sec F9) | P1 | Boot-time rejection of `AllowAllPaths`+`Paths` or `SampleRate ∉ [0,1]`; config tests per key |
| R3.1 | Operator, incident responder | Single correlation source: `Correlation` wraps OTel span; `WithTracing` = one switch; audit == span trace IDs; `X-Request-Id` preserve-or-generate | **Proposed**; today's dual-chain divergence **Verified** (Dist/QA); no test anywhere proves audit↔span equality today (QA) | P0 | A3 in `test/` (`package ssotest`): audit `TraceID` == request span trace ID; `X-Trace-Id` + error-body `trace_id` match; async `audit.sink.deliver` `ParentSpanID` == request `SpanID` (QA F8) |
| R3.2 | Client, operator | `Traceparent` response header preserved (observability.md wire contract) | **Design premise false** — otelhttp server handler only `Extract`s, never injects (Verified); header today comes only from the deleted legacy middleware (QA F1) | P0 | Integration test: wrapper sets `Traceparent` **explicitly** from live span context; parseable `00-<32hex>-<16hex>-<flags>`; trace-id == span ID; pinned incoming traceparent preserved, fresh span-id |
| R3.3 | Operator | One-switch semantics: OTel-less deployments lose `X-Trace-Id`/audit `trace_id`; boot warning + docs | Intended (design Decision 12); wire-visible (Sec F3, Dist F5); warning needs provider-liveness accessor — **Missing** from `platform/tracing` (Dist F5) | P0 (warning + docs merge-blocking) | (a) `WithTracing` + no provider ⇒ no `X-Trace-Id`, empty audit `TraceID`, `X-Request-Id` intact; (b) in-memory exporter ⇒ header/audit/error-body all equal span ID; (c) `cmd/sso-server` test asserts boot warning fires once |
| R3.4 | Incident responder | `EventFromRequest` span-first with real parent; header parse demoted to external fallback | **Proposed** | P0 | Unit: live span + hostile `X-Parent-Span-Id`/traceparent ⇒ span wins; no span + headers ⇒ fallback; migrate `handler_helpers_test.go:94-138` (3 tests assert old semantics — QA F3) |
| R3.5 | SDK, Stock, Edition | Legacy surface removed (8 files incl. `cmd/sso-minimal/app.go:102`, `docs/examples/basic/main.go:80`); no residual refs | **Verified** 7 production locations; **incomplete** — 4+ `_test.go` files reference deleted surface and `go build` cannot catch them (QA F3) | P0 | `go test ./... -run '^$'` (compile-only) exits 0 after removal; `cmd/sso-minimal` migrates to `WithTracing("sso-minimal")` under edition flag; `docs/examples/basic` updated |
| R3.6 | Security (gate oracle) | `feature_gate_hotreload_test.go` byte-identical oracle (gated-off ≡ never-mounted) survives the middleware move | **Contradicted as written** — baseline gains a fresh random `X-Request-Id`; sanity check inverts; byte-identity fails on values (QA F2, Dist F4, Sec A9) | P0 | Rewritten oracle: `fghrGet` pins incoming `X-Request-Id` + `Traceparent`; compare after normalizing only generated correlation headers; both sides must carry `X-Request-Id`; `-count=100` deterministic; two-sided header comparison retained |
| R3.7 | QA/CI | Global `TracerProvider` test-isolation protocol (no race/flake from provider teardown in parallel tests) | **Missing** (QA F4) | P1 | Package-level shared in-memory provider (`TestMain`) in `interfaces/sso` + `test/`; `go test ./interfaces/sso/ -race -count=10` green |
| X1 | SRE | Pre-change HTTP baseline + perf gates (B0–B4) | **Missing** — no HTTP load harness, no SLOs, no bench history in repo (Perf §1) | P1 | B0 numbers committed before code lands; proposed bounds: p99 Δ ≤ 1 ms, throughput Δ ≤ 5%, alloc Δ ≤ 1 KB/req at default config (pending operator SLOs) |
| X2 | Docs | config-reference.md, observability.md, **feature-matrix.md** (observability.core row), **deferred-backlog.md** (maintenance rule), changelog (source-breaking notes) | **Partial** — design covers config-reference + observability; feature-matrix/deferred-backlog/changelog updates **Missing** (L10) | P1 | `docscheck`/`make ci` green; changelog lists `WithRequestLogging` signature break, alias deletions, OTel-less header change |

---

## 3. Domain model and key workflows

### Entities

| Entity | Owner | Lifecycle | Notes |
|---|---|---|---|
| `AccessLogRecord` (7 fixed fields) | `interfaces/middleware` → `spi.Logger` → stdout/SIEM | Per-request; no in-process retention; **lossy by design**; operator-managed retention (external responsibility per `deferred-backlog.md`) | Exactly one per non-probe request; `query` never included; emission is **synchronous in the stock binary** (H3) |
| `BodyLogPolicy` (Paths / AllowAllPaths / SampleRate / MaxBodyBytes) | SDK option + config | Boot-fixed (restart to change) | Zero value = capture impossible |
| Capture stack (LimitReader+MultiReader restore; write-through response buffer; per-request buffers) | `interfaces/middleware` | Per-request, freed on return | Body-limit middleware downstream sees byte-identical body (break-risk 6) |
| Redaction engine (exact + substring keys, nested walk, `[redacted]`) | `interfaces/middleware` | Stateless | Vocabulary drift = the review gate (break-risk 5) |
| `Correlation` middleware | `interfaces/middleware` wrapping `platform/tracing` | Per-request span | Stamps ctx `WithTraceID`, `X-Trace-Id`, `X-Request-Id` (preserve-or-generate) |
| Span context (OTel) | `platform/tracing` | Request-scoped | Only valid when a real provider is registered (`tracing.Init` with endpoint — Verified no-op otherwise) |
| `AuditEvent` | `platform/audit` | Durable sinks; bounded async queue (1024, drop-on-full) | Schema unchanged; `TraceID`/`SpanID`/`ParentSpanID`/`RequestID` provenance changes only |
| `logging.access_log.*` config | `config` + `cmd/sso-server` | Boot-fixed; SIGHUP → `Ignored` (requires restart) | Tri-state `enabled` (nil = on) |

### Tenant boundary

- The access log is deliberately **not tenant-scoped** (7 fields, no tenant ID). Tenant-scoped flood evidence stays in `sso_rate_limit_hits_total` (tenant label) and audit events. Decision question: whether tenant incident triage needs a join key on the log record (DQ6).
- No cross-tenant data flows into the log record; body capture of tenant data is operator-allowlisted. Cross-tenant trace-context poisoning (attacker-chosen `Traceparent`) is residual and unchanged from today (W3C trace context is unauthenticated); the span-first `EventFromRequest` is a net improvement over the legacy dual chain.

### Key workflows

| # | Workflow | Steps | Business-relevant failure paths |
|---|---|---|---|
| W1 | Happy path (default sso-server, OTel configured) | Edge → `Correlation` (span + request-id) → metrics → trustedProxies (validated IP) → **AccessLogger** → ratelimit → bodyLimit → router → handler + audit (span-first) → one INFO record | — |
| W2 | Rate-limited flood | 429 written by limiter; AccessLogger outside limiter still emits record with `status: 429` | **Amplification:** rejection volume ≫ admission; synchronous write becomes the flood bottleneck (H3/F3); log pipeline sizing is now operator duty |
| W3 | Probe traffic | `/livez`/`/readyz`/`/metrics` served by `buildProbeMux` outside chain — zero records (Verified structural) | None |
| W4 | Body capture (debug posture) | allowlisted path + sample draw passes → LimitReader(4 KB+1) → redact by content type → MultiReader restore → capped write-through response capture | Credential leak if vocabulary misses a field name (H4/L2); malformed body ⇒ capped raw (documented) |
| W5 | OTel-less deployment | `tracing.Init` no-op ⇒ invalid span context ⇒ no `X-Trace-Id`, empty audit `TraceID`, but `X-Request-Id`/`RequestID` intact | **Silent forensic-correlation regression at upgrade**; SIEM joins keyed on `trace_id` break; mixed-replica rolling window (H6) |
| W6 | Wedged/closed log sink | `spi.Logger` → synchronous stdout write blocks request goroutine; closed pipe ⇒ SIGPIPE process death | **Auth outage from a log-pipeline incident** — violates the design's own failure table and AGENTS.md fail-open invariant (H3, release blocker) |
| W7 | Handler panic | Unwind skips post-`next` emission; `Recover` writes 500 | Missing access record — evidence gap exactly when an incident happened (R1.7) |
| W8 | Default SDK embedding | `accessLogPolicy == nil` ⇒ middleware not installed; zero added allocs | `WithTracing`-only embedders now also get `X-Request-Id` stamped by `Correlation` (L8, wire-visible, not in break-risk list) |
| W9 | Feature-gate hot-reload check | Gated-off vs never-mounted byte-identity | Oracle inverts after the move (H5); naive fix silently loses the gated-off ≡ never-mounted security invariant |
| W10 | SIGHUP reload of `logging.access_log.*` | Unknown keys default to `Ignored` (Verified) | Operator expects live change; needs docs, not code (R1.4) |

### Data lifecycle

- **Create:** per request (log), per event (audit), per span (OTL export). **Store:** operator pipeline (log — no in-process durability, crash loses in-flight records by design); durable sinks (audit); collector (spans — drop-on-full, IDs survive exporter outage, Verified). **Retention:** operator-managed for logs; existing audit retention schedulers unchanged. **Destroy:** per-request capture buffers freed on return; nothing persisted. **Migration:** none — zero new durable state is the design's strongest distributed property (Dist review confirmed).
- **Audit needs:** audit remains the evidence of record; access log is supplementary, lossy evidence; the correlation-field provenance change must be documented and announced (boot warning, changelog), not silent.

---

## 4. Findings (severity, business impact, recommendation, owner, dependency)

**High — release-blocking for the default-on posture:**

| # | Finding | Evidence | Business impact | Recommendation | Owner | Depends on |
|---|---|---|---|---|---|---|
| H1 | **Decision 2 code snippet inverts the stated slot** | **Verified**: wrap-order semantics at `server_routes.go:364-407`; snippet yields `ratelimit → AccessLogger → trustedProxies` | Implementer copies the snippet ⇒ `client_ip` forgeable in the always-on security log (SIEM poisoning) and 429 evidence lost — the exact flood scenario the design cites as rationale | Reorder snippet to match prose (ratelimit first, then AccessLogger, then trustedProxies); add chain-order + 429-record regression tests | Design doc + `interfaces/sso` | None (pre-implementation fix) |
| H2 | **otelhttp does not inject response `Traceparent`; design's load-bearing premise is false** | **Verified**: `otelhttp@v0.68.0/handler.go:97` only `Extract`s; `Inject` is client-side (`transport.go:142`). Header today comes from the deleted legacy middleware | Silent loss of the observability.md wire contract (`Traceparent`) for every client; the "regression boundary" framing is inverted — the wrapper, not otelhttp, is the implementation | Wrapper sets `Traceparent` explicitly from the live span context **unconditionally**; otelhttp stays test-pinned as a boundary | `interfaces/middleware` | None (pre-implementation fix) |
| H3 | **Access-log emission is synchronous on the request critical path; failure table's fail-open row is false for the stock binary** | **Verified**: `cmd/sso-server/main_logger.go:17` — blocking `slog.JSONHandler(os.Stdout)`; no SIGPIPE handling (`main_shutdown.go:29-34`) | A log-pipeline outage (wedged journald/SIEM agent, `\| head` mishap) stalls every request goroutine; a closed pipe kills the process. Violates AGENTS.md "logging failure must never degrade auth". Probes stay green while request path hangs — half-dead replica | Bounded async writer with drop counters (mirror `audit.AsyncSink`, the repo's own proven pattern) + EPIPE safety; or keep sync by default but correct the failure table and publish operator guidance; either way, quantify via B3 | `cmd/sso-server` + design doc | R1.4 (default-on) |
| H4 | **Acceptance B1's credential guarantee is renegotiated** | **Verified** design text: `/token` bodies are capturable when allowlisted; `AllowAllPaths` reproduces old semantics; redaction is heuristic, non-structured is capped-raw | The requirement's headline "凭据从设计上不可能落盘" becomes config-conditional: refresh tokens / auth codes / passwords reachable from a log sink under allowlist + vocabulary miss | Hard non-overridable deny-set for credential surfaces (`/token`, `/par`, `/register`, `/backchannel-authentication`, `/ssf/receive`, `/auth/login`, MFA/webauthn/recovery) enforced even under `AllowAllPaths`; reject contradictory configs at boot — **or** explicit product decision to renegotiate (DQ1) | Product decision + `interfaces/middleware` | DQ1 |
| H5 | **`feature_gate_hotreload_test.go` oracle inverts; a naive "fix" silently loses gate-security coverage** | **Verified** (QA F2, Dist F4, Sec A9): byte-identity between gated-off and never-mounted baseline, currently proven by `X-Request-Id` **absence** | After the move both paths carry a fresh random `X-Request-Id` — test fails by construction; weakening assertions would drop the "gated-off ≡ never-mounted" security invariant | Presence-based rewrite: pin incoming correlation headers, normalize only generated ones, re-prove `fghrAssertIdentical`; `-count=100` | `interfaces/sso` tests | — |
| H6 | **One-switch semantics silently degrade forensic correlation in OTel-less deployments + rolling-upgrade window** | **Verified** (Sec F3, Dist F5): default sso-server without `OTEL_EXPORTER_OTLP_ENDPOINT` stops emitting `X-Trace-Id`/audit `trace_id` after the merge; today it always emits | Audit records — the join key incident investigations run on — lose trace IDs silently at upgrade; SIEM dashboards keyed on `trace_id` break; LB spreads mixed header behavior across replicas during rollout | Boot warning (requires a `tracing.ProviderActive()`-style accessor — currently **missing** from `platform/tracing`), docs dependency statement, release-note rolling window; treat warning+docs as merge-blocking parts of the change, not follow-ups | `cmd/sso-server` + `platform/tracing` + docs | Provider-liveness accessor |

**Medium — planned work in the same change:**

| # | Finding | Evidence | Business impact | Recommendation | Owner |
|---|---|---|---|---|---|
| M1 | Removal list incomplete (4+ test files reference deleted surface); acceptance C3 (`go build`) cannot catch test-file refs | **Verified** (QA F3): `middleware_extra_test.go:250-345`, `test/middleware_test.go:206-281`, `rootcov_options_test.go:103-104`, `handler_helpers_test.go:94-138` | Merge breaks CI on test compilation; acceptance check is structurally blind to it | Migrate listed test files in the same change; extend C3 to `go test ./... -run '^$'` | `interfaces/sso` + `test/` |
| M2 | `AllowAllPaths` migration mapping is self-contradictory — the escape hatch as documented silently captures nothing | **Verified** logic: `SampleRate` default 0 + `AllowAllPaths` only bypasses the path gate | Embedders following the docs get silent loss of body capture (safe direction, but the deprecation contract is wrong) | Mapping must be `{AllowAllPaths: true, SampleRate: 1.0}`; fix Decision 3 + option doc; migration test | Design doc + `interfaces/sso` |
| M3 | Global `TracerProvider` test-isolation protocol undefined | **Verified** (QA F4): otelhttp uses global provider; `initExporter` pattern mutates process state; parallel tests + teardown = race/flake under `-race` | New tracing tests become the largest flake source in CI; `-race` gate at risk | Package-level shared provider (`TestMain`) or serialized provider-owning tests; gate tests assert only `X-Request-Id` (provider-independent) | `interfaces/sso` + `test/` |
| M4 | Capture writer lacks `Unwrap()`/optional interfaces — SSE breaks under the always-on wrapper | **Verified** (QA F5, Sec F6): admin SSE stream uses `http.NewResponseController`; no test exercises it with the wrapper | Streaming consumers (SSE admin export) get `ErrNotSupported` inside the allowlisted+sampled window | Implement `Unwrap()` + Flusher/Hijacker/Pusher/ReaderFrom passthroughs; SSE e2e with access log installed | `interfaces/middleware` |
| M5 | WebAuthn credential fields invisible to redaction vocabulary | **Verified** (QA F6): `clientDataJSON`/`authenticatorData`/`signature`/`rawId`/`userHandle` contain no heuristic substrings | Passkey assertion data lands raw in logs when `/auth/login` is allowlisted | Extend `bodyLogSecretKeys` now (existing endpoints, not future ones); B2-shaped test with grep-absence | `interfaces/middleware` |
| M6 | `client_ip` forgeable in the stock default (no `trusted_proxies` configured) | **Verified** (Sec F4): `build_app_security.go:160` wires trustedProxies only when CIDRs non-empty; `audit.ClientIP` falls back to raw XFF first hop | The always-on production log widens the legacy first-hop posture from debug/audit to SIEM-attribution surface — attackers frame internal hosts, flood SIEM with arbitrary IPs | Boot warning when access log is on without `trusted_proxies`; document dependency next to `logging.access_log.*`; consider always-raw `remote_addr` field | `cmd/sso-server` + docs |
| M7 | Bernoulli sampling uses `math/rand`'s global **locked** source | **Verified** (Perf F2) | Per-request global mutex when sampling is enabled (opt-in debug posture only) | `math/rand/v2` (lock-free) or hash-of-request-id draw; short-circuit `EnabledFor → SampleRate > 0 → draw` | `interfaces/middleware` |
| M8 | Panicking requests emit no access record | **Verified** (Perf F5) | Evidence gap in the exact incidents that panic | Emit in `defer` reading captured status | `interfaces/middleware` |
| M9 | No config-package tests for tri-state defaulting + reload bucket | **Verified** (QA F7) | Default-on behavior ships without regression coverage | Add config + reload tests per R1.4 | `config` |

**Low / Info:**

| # | Finding | Impact | Recommendation | Owner |
|---|---|---|---|---|
| L1 | `X-Request-Id` (attacker-controlled, unbounded) mirrored into headers + both log planes | Record bloat, attacker-chosen forensic identifiers; CRLF/JSON escaping bounds injection | Cap/charset-validate preserved values (e.g. ≤128 chars, `[A-Za-z0-9-]`) | `interfaces/middleware` |
| L2 | Redaction gaps: JAR `request` param (signed JWT), `pwd`-style names, non-structured raw-capped | Defense-in-depth drift; today's vocabulary covers every current credential field (Verified) | Add `request` to exact list; keep review gate (break-risk 5) mandatory | `interfaces/middleware` |
| L3 | `r.URL.Path` decoded control chars (`%0a`) into always-on log | Log-injection in text-format sinks; JSON stock handler escapes | Log `EscapedPath()` or document sink escaping | `interfaces/middleware` |
| L4 | `BodyLogPolicy` contradictory combos unvalidated | Misconfig accepted silently | Validate at option-application time (fail loud, like `NewTrustedProxies`) | `interfaces/sso` |
| L5 | `middleware.Logger`/`LoggerMiddleware` (INFO, 2 fields, zero prod callers) not on removal list | Second, unredacted INFO request logger an embedder could enable; schema confusion for operators | Delete in the same change | `interfaces/middleware` |
| L6 | `trace_id` double-emission hazard — use `l.Info`, not `l.InfoCtx` (stock `withTraceID` appends from ctx) | Duplicate key on records | Explicit contract note | `interfaces/middleware` |
| L7 | B3 sampling CI has ~0.1% inherent flake | Occasional CI red | Accept ±4σ or widen bound | QA |
| L8 | **`WithTracing`-only SDK embedders gain `X-Request-Id` response headers + audit `RequestID` values** (today gated behind `WithTracingMiddleware` — Verified `server_routes.go:112`) | Wire-visible addition for existing embedders, not in the break-risk list; external frontends may observe new headers | Document in changelog; check `frontend-contract.md`/OpenAPI header notes | Docs + `interfaces/sso` |
| L9 | `newRequestID` `crypto/rand` per request; ~4–8 KB capture buffers per sampled request | Pre-existing / debug-posture costs only (Perf F7/F8) | No action; measure first | — |
| L10 | feature-matrix.md / deferred-backlog.md maintenance rule not covered by the design | Docs drift vs the "baseline maintenance rule"; `observability.core` row should reflect the access log | Update both in the same change as config-reference/observability docs | Docs |

---

## 5. Decision questions, missing evidence, success measures

### Decision questions (product/owner level, all blocking or shaping P0 work)

1. **DQ1 — Credential guarantee: absolute or default-posture?** Does the product ship "credentials structurally impossible to log" as an absolute invariant (hard non-overridable deny-set for credential surfaces, boot-time rejection of allowlisting them — Security F2) or as a default-config guarantee with documented operator risk acceptance? This renegotiates requirement B1 and must be resolved before acceptance criteria are finalized. *Recommended: hard deny-set; it preserves the requirement's headline promise and costs ~1 table of paths.*
2. **DQ2 — Sink semantics before default-on ships:** synchronous emission with a corrected failure table + operator guidance (ordering, shutdown drain) vs bounded async writer with drop counters (fail-open, mirrors `audit.AsyncSink`)? The design's current failure table promises fail-open that the stock wiring cannot deliver (H3). *Recommended: async + EPIPE safety; it is the repo's own established pattern for always-on sinks.*
3. **DQ3 — OTel-less transition:** accept the one-switch removal of `X-Trace-Id`/audit `trace_id` immediately (boot warning + docs), or keep a deprecated opt-in legacy stamping for one release to defuse the rolling-upgrade window (H6)? *Recommended: one-switch now, warning + release note; the mixed-replica window is short and the warning is cheap.*
4. **DQ4 — `client_ip` trust in the default binary:** accept the legacy first-hop posture in the always-on log (warning only), or make the access log fail loud without `trusted_proxies` configured? (M6)
5. **DQ5 — `X-Request-Id` normalization:** accept attacker-chosen, unbounded identifiers in forensic fields, or cap/validate? (L1) *Recommended: cap + charset; cheap and improves SIEM hygiene.*
6. **DQ6 — Is the 7-field schema final?** `tenant_id` and `user_agent` are deliberately excluded; tenant-scoped flood triage currently needs the rate-limit metric/audit join. Confirm as a stated non-goal or add fields.
7. **DQ7 — Perf acceptance bounds:** no SLOs exist anywhere in the repo. Approve comparison-based gates (p99 Δ ≤ 1 ms, throughput Δ ≤ 5%, alloc Δ ≤ 1 KB/req vs a to-be-captured B0 baseline) as interim acceptance, and name the operator responsible for real SLOs.

### Missing evidence

- **No pre-change HTTP baseline, load harness, or bench history** — B0 must be built and committed before any code lands (perf review; nothing numeric in this design is currently measured).
- **No test proves audit↔span equality today** — improvement 3's headline benefit is unverified even as a possibility.
- **No SSE-through-status-wrapper test** and no `ResponseController` coverage of the capture writer.
- **No config-package tests** for the tri-state defaulting or the reload bucket.
- **Provider-liveness accessor feasibility** — `platform/tracing` does not expose whether `tracing.Init` produced a real provider; the boot warning (a merge-blocking commitment) depends on adding one.
- **No decision record** for the B1 renegotiation (requirements doc vs design differ; no ADR).
- Store-backed latency baselines have never been measured — out of scope for these middleware deltas, but a standing gap.

### Success measures (post-implementation, per requirement)

- **Operational:** default `sso-server` emits exactly one 7-field record per non-probe request, incl. `status: 429` with validated `client_ip`; a drill can join a reported error across access log ↔ audit ↔ spans via `trace_id` (OTel-enabled) and still get IP/status/request-id evidence when OTel is off.
- **Security:** default config yields zero credential material in any log record (grep-absence suite incl. WebAuthn/JAR/out-of-vocabulary names); gated-off ≡ never-mounted oracle preserved after the test rewrite; `client_ip` never forgeable when `trusted_proxies` is configured.
- **Compatibility:** SDK byte-identical by default; source-breaking changes and the `WithTracing`-only `X-Request-Id` addition (L8) in the changelog; response headers `Traceparent`/`X-Trace-Id`/`X-Request-Id` present and consistent (with OTel).
- **Reliability:** log-pipeline outage demonstrably does not degrade auth or kill the process (H3 regression test); panics still produce a record.
- **Quality gates:** `go build ./... && go vet ./...`; maintainability/architecture tests; `go test ./... -race` (provider-isolated, `-count=10`); `go test ./test/ -run TestE2E -v`; migrated gate tests deterministic at `-count=100`; `make ci`.
- **Performance:** B0 committed; measured deltas within the approved bounds at default config; no `lockedSource` in the sampling mutex profile.

**Bottom line for the business:** the requested behavior is well-grounded and the value proposition is real — default-on incident evidence and true audit↔span correlation are genuine gaps today, and the zero-new-state storage model is the right call. Four items block a safe ship and are all fixable before or in the same change as implementation: the inverted slot snippet (H1), the false `Traceparent` premise (H2), the blocking-sink fail-open contradiction (H3 — the release blocker for "default on"), and the credential-guarantee renegotiation (H4 — needs a product decision, DQ1). The gate-oracle rewrite (H5) and the OTel-less boot warning (H6) must land with the middleware work, not after it.
