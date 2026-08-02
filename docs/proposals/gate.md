All claims verified. I now have everything needed for the gate decision.

## Gatekeeper cross-check: review findings vs. design `grpcserver-observability-tls.md` (fbf91c52)

**Revision state:** the design (08:17) predates both on-disk reviews (protocol 08:23, QA 08:30); `git status` shows all three files untracked. The design has **not been revised** in response to any review. I independently re-verified the load-bearing code claims: `ReadyChecks` copies `rc.Check` unconditionally incl. nil (`accessors_handlers.go:343-350`), `/readyz` skips nil checks (`server_health.go:104-107`), `deployment.md:75-83` quickstart becomes a startup error under the new default, `CHANGELOG.md` exists / `RELEASE.md` does not.

| Blocking finding (source) | Status in design | Verdict |
|---|---|---|
| Poller wedge: "poller can never wedge" false — sequential single goroutine, ctx-ignoring SDK check freezes all verdicts (Sec F1 / Prin M2 / Perf P1-P2 / QA F1 **High**) | Decision 2.3 + 7 still assert "poller can never wedge" (line 325); sequential execution, no concurrent evaluation, no wedge test | **Unresolved** |
| Nil `Check` funcs (orphan `WithReadyCheckTimeout`) → panic → permanent NOT_SERVING vs `/readyz` 200 (Proto F1 / Prin M1 / QA F3) | Only an unsupported doc-comment claim (line 57); Decision 2.5 covers nil/nil-map/empty-map only; no skip mechanism, no parity test — claim contradicts Decision 2.3 recover semantics | **Unresolved** |
| `deployment.md` quickstart breaks; contract list omits it and CHANGELOG (SRE H1 / Prin H1) | Zero hits for deployment.md/CHANGELOG/RELEASE in design | **Unresolved** |
| No health-projection telemetry — wedged poller undetectable (SRE H2 / Prin M3) | Zero hits for evaluations/transitions/status gauge | **Unresolved** |
| `-validate-only` exits before TLS decision — preflight can't predict new boot error (Proto F2 / Prin M4 / QA F5) | Zero hits | **Unresolved** |
| Reflection always-on unauthenticated v1+v1alpha, no kill-switch (Sec F2 / Prin M5) | Decision 8 #5 documents acceptance but never acknowledges the `-grpc-no-reflection` option; escalation not recorded | **Dismissed without option considered** |
| v1alpha missing from banner + denylist (Sec F5 / Proto F3 / Prin L1 / QA F6) | Zero hits; denylist names only v1 | **Unresolved** |
| `grpcurl -plaintext localhost:8081 list` contradicts TLS default + misattributed to `make ci` (SRE L1 / Sec F6 / Proto F5b / Prin L3) | Line 431 unchanged | **Unresolved** |
| Memoized allowlist must be `sync.Once`/`atomic.Value` (Sec F7 / Prin L7 / Perf P9 / QA F7) | Zero hits | **Unresolved** |
| `HealthPollInterval` const → slow/flaky tests (QA F2) | Line 105 still "const in obs.go" | **Unresolved** |
| No per-RPC server-class error log (SRE H3 / Prin M6) | No interceptor logging specified (only poller warn log) | **Unresolved** |
| "ends all Watch streams" overstates `Shutdown()` (Proto F5a / Prin L11) | Line 120 unchanged | **Unresolved** |
| Flapping asserted "correct behavior" without naming debounce follow-up (SRE M1 / Prin M7) | Zero hits for debounce/hysteresis | **Unresolved** |

**Resolved/acceptable:** chain-order amendment with panic test lock (Decision 4); otelgrpc fetch acknowledged with minimal-diff criterion (D8#2); cert-rotation/expiry noted out of scope (D7); unauthenticated health/reflection documented (D8#5); `code_class` table fixed/exhaustive/documented; all-or-nothing mapping covered by the planned observability.md "SERVING/NOT_SERVING mapping" row; no test-harness blast radius verified.

**Bottom line:** the required preconditions named by the principal reviewer (M1, M2, M3, M4, M5, H1, L1, L3, L7 + both rewording fixes) are almost entirely absent, and two of the three blocking Mediums (nil-func parity, poller wedge) plus SRE H1 remain exactly as reviewed. Protocol review explicitly stated "should not proceed to implementation with F1 open"; QA marked the wedge finding High. Since these are dismissed neither by revision nor by documented reasoned rejection, implementation must not start.

VERDICT: FAIL - Design not revised since review; blocking findings open: poller-wedge claim (needs concurrent per-check evaluation under the 3s aggregate + wedge test), nil-func parity with /readyz (skip nil + orphan-timeout test), deployment.md/CHANGELOG.md contract updates in the same change, health-evaluation telemetry (sso_grpc_health_evaluations_total), -validate-only preflight coverage, reflection kill-switch decision, v1alpha in banner+denylist, sync.Once/atomic memo spec, grpcurl verification wording, HealthPollInterval injectability, per-RPC server-class error log, and the "ends all Watch streams"/"never wedge" rewording — resolve or explicitly dismiss with reasons before implementation.
