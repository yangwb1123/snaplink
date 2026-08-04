# Principal Review: `interfaces-cors-observability-design.md`

**Revision reviewed**: `02bf30be` (design stage, docs-only; no Go edits shipped)
**Inputs**: design doc, security_engineer, protocol_expert, sre_engineer, qa_lead deliverables; independent re-verification of every material claim against source at this revision.
**Verdict**: **Conditionally ready** — the architecture and all protocol/security invariants are sound; two hard-gate violations and one factual error in the design must be corrected in this docs-only revision before any `.go` edit. Evidence confidence: **High** (all blocker claims re-verified against source; the two gate failures are arithmetic facts of the committed budgets).

## 1. Advisory recommendation

**Conditionally ready.** The design preserves every oracle-safe, fail-open/fail-closed, and wire-level invariant it touches (verified: reject branch `cors.go:185-188` unchanged, RFC 9207 `iss` via `authzErrorBody` kept, no-Origin pass-through kept, bounded cardinality honored, probes outside the chain). Its budget analysis was *partially* correct: it caught `metrics_ctor.go` 497/500 but missed two other committed gates (`metrics.go` file size, `platform/metrics` fan-out), and its central "must not make it worse" claim is false for one unsupported configuration. All of it is fixable in the docs-only revision without changing the architecture. Do not proceed to implementation until B-1, B-2, and B-3 below are resolved in the doc.

## 2. Consolidated findings

Legend: all line claims below are my own re-verification at `02bf30be`, not relayed from the sub-reviews.

### Critical / High

None. No verified exploit, data-loss path, or enforcement change exists in the design.

### Medium — release blockers for the design as written

**B-1 — Decision 1 misses TWO committed budget gates (sources: protocol H-1, protocol H-2, QA F1; all three independently, all verified by me).**

| Part | Evidence (my check) | Consequence |
|---|---|---|
| (a) New `platform/metrics/cors.go` | `directory_fanout_test.go:38` `maxGoFilesPerDir = 10`; `platform/metrics` holds exactly 10 non-test files and is **not** in `dirFileCountExemptions` (`:64-78`). `cors.go` → 11 → `TestArchitecture_DirectoryFileFanout` fails | `make ci` fails |
| (b) `CORSBlockedTotal` field in `metrics.go` | `metrics.go` = 494 lines; gate fails at `n > 500` (`maintainability_budget_test.go:34,87`). The design's own block (5-line Help comment + field + blank separator, as the adjacent `CIBAPingTotal` block at `metrics.go:182-191` is formatted) = +7 → **501** | `TestMaintainability_FileSizeBudget` fails |

Note on (b): the sub-reviews' arithmetic (protocol +9 → 503, QA +8 → 502) overstated the block, but the conclusion is common and correct. With no blank separator the file lands at exactly 500 — zero margin and broken by any unrelated edit; not acceptable.
Note on placement: the design explicitly overrode the spec's placement ("registered in `metrics_ctor.go`", `interfaces-cors-observability-spec.md:62`) and picked the one placement that breaks a gate. AGENTS.md §1: the stricter contract wins.
**Fix (verified feasible)**: fold `registerCORSBlockedMetrics` into an existing file with headroom (`conditional_access.go` 64 lines, `metrics_configaudit.go` 32, `audit_async.go` 90, `credential_rotation.go` 122); trim the Help comment to ≤3 lines (net +5 → 499).

**B-2 — "Must not make it worse" is false for `PathOverrides` on `/auth/login` (sources: SRE F1 High, protocol M-1 Medium, security F2 Low; deduped).**

Verified: `isOriginAllowed` (`interfaces/sso/origin_validation.go:103-119`) checks only `AllowedOrigins`/wildcard; the middleware resolves `PathOverrides` (`cors.go:172-180`, `resolveCORSConfig`). With an override allowing an origin on `/auth/login` while the default policy denies it: middleware passes → observer silent → gate 403s (`server_login.go:166-178`) → after the design's log removal at `:174`, telemetry goes **1 log line → 0** for that rejection. Today the same configuration emits one `origin_blocked` line. The design's invariant "one rejected request ⇒ exactly one log line" is kept only for the *supported* configuration; for the unsupported one it deletes the only signal.
**Severity resolution**: consolidated to **Medium**. Enforcement holds (403 + `iss` unchanged — no bypass, no oracle change); the affected configuration is pre-existing "unsupported/undefined", so this is not a regression of supported behavior — but the design explicitly promises "must not make it worse" and its own invariant, and an observability regression at a security boundary is exactly what this change exists to close. SRE's High overstates (the edge predates the change and is undefined); security's Low understates (the promise is part of the design's contract). Protocol's framing is the most defensible.
**Fix (cheapest, honors the invariant)**: protocol option (a) — log ownership for `/auth/login` stays at the gate (observer emits counter+event, gate emits the log); observer logs for all other paths. Exactly-once preserved per surface for the supported config, and the disagreement case keeps its line. Option (b) — config-validation refusal of overrides resolving to `/auth/login` — is fail-closed but adds a new validation error on an existing knob (new `Err*` → `docs/error-codes.md` per AGENTS.md §5.6), i.e., more contract surface than (a). Decision owner: maintainers (direction-二 non-goal respected either way; both stop short of unification).

**B-3 — Unbounded attacker-controlled values in audit metadata + a new all-paths synchronous log line (source: security F1 Medium; QA F6, SRE F5 corroborate).**

Verified: the observer fires pre-auth on every path with attacker-controlled `origin`/`path`/`method` (Go 1 MB header caps, control chars legal in header values); audit rows persist raw values (SQLite/SIEM), and the log write is synchronous with no drop path. Rate limiting wraps CORS only when wired (`server_routes.go:393`), which is not the default. The Prometheus counter is safe (2 series max — `reason` const + `FormatBool`).
**Fix**: truncate `origin`/`path`/`method` to a fixed cap (256 B + truncation marker) before `SetMeta`/logging, matching the `sanitizeMethod` bounded-input precedent; state the volume expectation in `observability.md`. Add unit tests: metadata ≤ cap with marker; accepted label set exactly `{disallowed_origin} × {true,false}`.

### Medium — should land with implementation

**B-4 — Shared reason const implies a new `platform/audit → platform/metrics` import (sources: QA F2 Medium, protocol I-1 Info; deduped).** Verified: `platform/audit` has zero `platform/metrics` imports today; the design's `RecordCORSOriginBlocked` uses `CORSBlockReasonDisallowedOrigin` from `platform/metrics/consts.go`. Same-layer import is legal (architecture gate is upward-only), so not a hard-gate violation — but it couples audit's event vocabulary to metrics' const namespace. **Fix**: parameterize the helper (`reason string` last arg, mirroring `RecordCIBAPingFailed(rec, ctx, clientID, authReqID, reason string)` at `recorder_events.go:139`); caller holds the single const.

**B-5 — Counter ships without an alert rule or runbook (source: SRE F2 Medium).** Verified: `platform/metrics/alert_rules_test.go` cross-references `ops/deploy/grafana/alerts.yaml` against metric-name consts, so adding `sso_cors_blocked_total` rule is gate-verified and cheap; the design's own Help text says "Alert on a rate…". All alerting must use `rate()` (per-replica counters reset on restart — SRE, correct).

**B-6 — `observability.md:100` diagram is drift; Decision 3 edits that exact region (sources: SRE F3 Medium, protocol L-2 Low; deduped).** Verified: doc shows `tracing → ratelimit → bodyLimit → metrics → CORS → router`; code is `tracing → metrics → trustedProxies → ratelimit → degradation → [apiVersioning → bodyLimit → compression → CORS → securityHeaders → requestLogger] → router` (`server_routes.go:364-466`). Fix the diagram in the same edit; the E2E case-1 assertion (both counters move together) pins the true invariant.

### Low / Info — documentation-level

| Finding | Source | Verification | Fix |
|---|---|---|---|
| "A disallowed preflight is counted as a 2xx" is **false** — it is a 404 | protocol L-1, QA F3 | Verified: `StdRouter.ServeHTTP` (`shared/core/router.go:296-315`) has no OPTIONS routes → `http.NotFound`; both reviewers probed behaviorally | Rephrase; pin status 404 + `preflight="true"` in E2E case 1 |
| E2E counter-read mechanism underspecified | QA F4/F7 | Verified: sibling `cibaPingMetricValue` (`test/ciba_ping_test.go:190-226`) scrapes `/metrics` specifically to avoid `prometheus/testutil` (would add an indirect module to go.mod); in-memory read via `CounterVec...Get()` avoids testutil but the nil-metrics "zero series" case has no registry to read — no `/metrics` route without `WithMetrics` (`server_routes.go:481-483`) | Pick `/metrics` scrape (matches precedent); case 5 asserts 404 + no panic |
| Citation drift (line-level) | protocol L-3, QA F5 | Verified: `control_areas.go` CC6.1 at 42-58 (not 50-66); drift guard test at `drift_test.go:103` (not 41 — :41 is inside `wantUncategorizedEventTypes`); `sanitizeMethod`/increment at `middleware.go:25-26` (not 16); `AdoptionReason*` at `consts.go:201-202` (not 142); `cors.Middleware(` call sites = 1 prod (`server_routes.go:452`) + 9 in `cors_test.go`; `test/cors_e2e_test.go` uses `WithCORS`, not `Middleware` | Correct lines; no substance change |
| PathOverrides-only deployments generate full-volume false positives | security F4 | Verified: middleware identity short-circuit requires BOTH lists empty (`cors.go:170-171`); with only overrides set, every origin on non-override paths is denied | One sentence in `observability.md` |
| Audit metadata is attacker-influenced | security F5 | Verified: inherent to the feature | State "untrusted input, never used for decisions" in the audit contract row |
| `blocked` ≠ `refused` semantics for SOC triage | SRE F4 | Verified: non-login paths forward and execute | Document in the event contract |
| Synchronous observer latency on reject path | SRE F6 | Verified by construction (no detached goroutine; bounded work) | One code comment; no action |
| No committed gate enforces `observability.md` rows | SRE F7, protocol | Verified: no such gate | Rely on the spec's grep acceptance folded into `make ci`-adjacent checks |
| Gate PathOverrides-blindness pin test | QA F8 | Verified asymmetry | One unit pin documenting the gate's blindness (not an E2E case on the unsupported combination) |
| Pre-existing: `security.cors.*` documented in `config.yaml:782` but absent from `docs/config-reference.md`; not SIGHUP-reloadable (SRE F7 verified: reload covers only `security.rate_limit.*`, `config/reload/reload.go:19-27`) | SRE F7, my check | Verified | Track separately; out of this change's scope (do not expand) |

## 3. Trade-off ledger

| Conflict | Options | Recommendation | Consequence | Owner |
|---|---|---|---|---|
| Severity of the PathOverrides × login-gate telemetry drop (SRE High / protocol Medium / security Low) | Rate High, Medium, or Low | **Medium** — unsupported config, enforcement intact, but the design's own "not worse" promise and exactly-once invariant are falsified for that combination | Signals SOC attention without blocking release on an undefined config; fix is ~5 lines | Maintainers (choose fix (a) vs (b) in B-2) |
| Decision 1 field placement (spec: `metrics_ctor.go`; design: new `cors.go`) | Spec placement (497→498, within cap) vs new-file (breaks fan-out) | **Spec placement**, i.e., an existing file with headroom; trim Help comment | Design's "budget-shaped answer" was wrong about which budget; both gates pass after correction | Implementer |
| Event classification CC6.1 vs CC7.2 | Access-control vs anomaly bucket | CC6.1 (dominant case is benign misconfig, not anomaly) | Drift test only forces an explicit choice, not the right one; SOC2 report text changes if it flips later | Compliance owner to confirm at implementation |
| E2E counter read: in-memory registry vs `/metrics` scrape | In-memory (design) vs scrape (sibling precedent) | `/metrics` scrape, matching `cibaPingMetricValue`; case 5 = 404 assertion | Avoids `prometheus/testutil` dep; tests the real scrape surface | Implementer |
| Metrics/audit divergence under sink pressure | Synchronous counter + best-effort event | Accepted, stated explicitly (verified `sso_audit_async_drops_*` consts exist, `metrics/audit_async.go:12-16`) | "Exactly-once" is per-output, not cross-output | Design owner (documented) |

## 4. Preconditions, acceptance, rollback, monitoring

**Preconditions (docs-only revision, before any `.go` edit)**:
1. B-1: re-place `registerCORSBlockedMetrics` in an existing `platform/metrics` file; trim the field Help comment (≤3 lines).
2. B-2: choose and record the gate-side emission or config-validation fix; keep direction-二 non-goal.
3. B-3: truncation contract + volume statement in `observability.md`.
4. Fix the preflight-404 sentence; fix the `observability.md:100` diagram; correct the cited lines (B-6, L-3).
5. B-4: parameterized recorder helper signature.
6. B-5: alert rule + runbook row for `sso_cors_blocked_total`.

**Executable acceptance checks** (in order):
- `go test -run 'TestMaintainability_|TestArchitecture_' .` — the exact gates B-1 breaks as written; run after every `.go` edit.
- `go build ./... && go vet ./...`; then new units: `interfaces/cors` observer (exactly-once, no-Origin never fires, identity short-circuit never fires, PathOverrides-resolved basis, empty policy zero calls); `platform/audit` (nil-recorder no-op, `SetMeta`-only, truncation ≤ cap with marker, trace ID rides context); `platform/metrics` (accepted label set exactly `{disallowed_origin} × {true,false}`).
- `test/cors_observability_test.go` five cases, with the two corrections: case 1 pins 404 + `preflight="true"`; case 5 asserts `/metrics` 404 + no panic; case 2 pins exactly-one event on disallowed `/auth/login`; case 4 uses `/.well-known/openid-configuration` override.
- `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`; grep acceptance for `sso_cors_blocked_total` and `cors_origin_blocked` in `observability.md`; `alert_rules_test.go` passes with the new rule.

**Rollback triggers**: a metric-name rename or label-set change fails `alert_rules_test.go` (the gate is the tripwire); CORS misconfig fixes require a restart (`security.cors.*` is not SIGHUP-reloadable — verified). Rollback = revert config + restart; the observer is additive and nil-safe, so rollback of the code change alone restores prior behavior exactly.

**Monitoring**: `rate(sso_cors_blocked_total[5m])` per replica (counters reset on restart); watch `sso_audit_async_drops_*` for sink pressure (the designed metrics/audit divergence); E2E case 1 pins the chain-order invariant so a future CORS-outside-metrics move fails loudly.

**Explicit exclusions**: direction-一 allow/deny semantics and hot-reload; direction-二 `isOriginAllowed`/PathOverrides unification; raw origin/path Prometheus labels; audit throttling; new `Err*`/endpoint/config knob; `docs/config-reference.md` CORS gap (pre-existing, tracked separately); browser/static-asset telemetry.

**Residual risks (accepted, documented)**: metrics/audit divergence under sink pressure; F1-volume log semantics (post-B-3 bounded); the silent-403 corner for the unsupported `PathOverrides`-on-login config (post-B-2 emits its line); attacker-influenced metadata (inherent, documented); synchronous observer latency (bounded, no recover() — a panic would be converted to a 500 by `wrapPanicRecovery`, acceptable).

## 5. Missing reviews/evidence and next actions

- **Compliance**: no compliance review of the CC6.1 classification. The drift test forces an explicit choice, not the correct one; `soc2.go` output changes if it flips. Narrow action: compliance owner confirms CC6.1 at implementation.
- **Performance**: no measurement of the synchronous observer on the reject path (SRE F6) — bounded by construction; a one-line benchmark note in the implementation PR suffices.
- **Proxy evidence**: the OpenResty "no CORS at the proxy" claim is SRE's deployment evidence; I could not verify it from this repository (no ops assets for that proxy in-tree). Partial — not needed to decide the design.
- **Implementation review**: this revision is docs-only; the design-review gates (B-1/B-2/B-3) must be re-checked against the actual `.go` diff at implementation time, since the exact block sizes will differ from the design's code fences.
- **Next actions, narrow**: (1) design doc revision per §4 preconditions; (2) re-run the two gate tests against the revised doc's claims; (3) then implementation with the unit/E2E list above; (4) `make ci` as the handoff gate.

No sign-offs, deadlines, or approval status are fabricated here; this review binds nothing and is advisory to the accountable release owner.
