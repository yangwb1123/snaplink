# QA Review — `docs/design/grpcserver-observability-tls.md` (Direction 3)

**Reviewer role:** QA lead, risk-based test review of the design only (no
implementation exists in the tree — no `obs.go`, no `metrics.go`, no
otelgrpc, no TLS flags). Design-stage convention: no `.go` files touched.

**Evidence standard:** every claim below was re-checked against the working
tree at this revision; baseline gates were actually run (see §1). Line
citations are current. Findings from the sibling SRE/security/protocol
reviews were independently re-verified at code level before being folded in
(F1, F3, F6, F7 below).

---

## 1. Test inventory and commands actually run for this revision

| # | Command | Result | What it locks |
|---|---|---|---|
| 1 | `go build ./... && go vet ./...` | PASS | Baseline compile/vet at this revision |
| 2 | `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS (0.145s) | File/function/depth budgets + layer map (obs.go/metrics.go stay within the 10-file ceiling; no new graph edges) |
| 3 | `go test ./interfaces/grpcserver/... ./platform/metrics/... -count=1` | PASS (3 pkgs) | Existing gRPC surface (incl. `recovery_test.go` panic-containment) + metrics vectors (incl. `TestNew_ConstructsAllVectors`) |
| 4 | `go test ./test/ -run TestE2E -v -count=1` | PASS, 4 tests | `TestE2E_LoginThenAuthorizeAcrossWire`, `_DeniedWhenSubjectLacksPermission`, `_NoTokenIsUnauthorized`, `_BadCredentialsRejected` — in-process httptest+bufconn, memory-backed |

**Not run (deferred by design):** full `go test ./... -race` and `make ci`
(no `.go` changed at design stage; the AGENTS.md §5 sequence is the
implementer's handoff gate). `make ci` target (`Makefile:244`) and
`.github/workflows/ci.yml` steps inspected statically: vet, build, examples
build, `go test -race -count=1 ./...`, chaos (`-tags chaos
./test/chaos/... -race -count=2`), config/module validation — **no grpcurl
step anywhere** (confirms security F6; the design's gate section
misattributes the `grpcurl -plaintext localhost:8081 list` enumeration to
`make ci`).

**Static verification performed (read-only):**
- grpc v1.80.0 module cache: `health.Server` has `Check/List/Watch/
  SetServingStatus/Shutdown`, internal `sync.RWMutex` + status map, initial
  Watch send + change-dedupe (`health/server.go:43-96`); `reflection.Register`
  registers **both** `grpc.reflection.v1` and `grpc.reflection.v1alpha`
  (`reflection/serverreflection.go:62-70`). `go doc` confirms `Shutdown()`
  (design Decision 8 #9 verified).
- `go.mod:21-26`: otelhttp v0.68.0 + otel v1.43.0 present; otelgrpc absent
  from go.mod and from the module cache (only `.../instrumentation/net`
  present) — first fetch needs network (design Decision 8 #2 verified).
- grep `-grpc-listen` across `test/` and `examples/`: zero hits — the
  stock-run breaking change has no CI blast radius (design claim verified).
- grep `exec.Command` in `cmd/sso-server/*_test.go`: zero hits — **no test
  execs the binary**; the design's "CLI-level startup-error check if the
  existing test harness supports exec" branch is therefore dead (see F4).
- `docs/observability.md`: zero occurrences of "grpc"; line 9 bounded-
  cardinality statement and line ~99 probe-outside-ratelimit stack verified —
  the contract-update list is genuinely required.
- `docs/docscheck/`: gates Config keys (`config_keys_test.go`), error codes,
  OpenAPI routes. No gate locks metric names or flag docs — the `sso_grpc_*`
  doc rows will be review-only, same as `sso_http_*` today (Info).
- `cmd/sso-server/main.go:96-100`: `-validate-only` exits **before** `run()`
  → before the TLS decision in `grpcServerOptions` (protocol F2 re-verified).
- `interfaces/sso/server_health.go:104-108`: `/readyz` skips nil `Check`
  funcs; `interfaces/sso/accessors_handlers.go:343-350`: the `ReadyChecks`
  accessor copies `rc.Check` **including nil** (orphan
  `WithReadyCheckTimeout` entries; `options_misc.go:407` pre-registers
  `namedReadyCheck{Name, Timeout}` with nil Check) — protocol F1 re-verified.
- `handleReadyz` (`server_health.go:96-129`) runs checks **sequentially**
  under one 3s aggregate ctx; a ctx-ignoring check blocks that request's
  goroutine past the deadline — the mechanism behind F1 below.
- In-memory cert fixture pattern exists for the TLS bufconn test:
  `interfaces/sso/mtls_revocation_test.go`, `test/mtls_bound_test.go`
  (x509.CreateCertificate) — no new fixture needed.
- `platform/registry/memory.New()` exists — usable for the stream-
  interceptor test via `discoveryv1.Discovery.Watch`
  (`interfaces/grpcserver/discovery.go:67`, server-streaming, not
  denylisted).

---

## 2. Requirement-to-test matrix

Requirement sources: `docs/proposals/requirements.md` (acceptance checks
§1–§3) + the design's Decisions 1–8. Status: **Verified** = exists and
passed at this revision; **Proposed** = design names it but nothing exists;
**Missing** = no test planned anywhere; **Partial** = planned but
incomplete.

| Req | Acceptance (source) | Design's planned test | Status | Evidence / gap |
|---|---|---|---|---|
| R1a Health Check SERVING on all-pass | req §1 | `obs_test.go` bufconn, faked check map | Proposed | pattern from `test/admin_grpc_base_test.go` (bufconn + insecure creds) |
| R1b NOT_SERVING on failure, recovery flips back | req §1 | same | Partial | **needs injectable poll interval** (F2) — a 5s const makes this a multi-second timing test |
| R1c Watch streams transitions | req §1 | same | Partial | Watch = initial send + deduped transitions (verified in grpc source); test must assert initial status **and** exactly one transition per change (F10) |
| R1d `stop()` → NOT_SERVING + Watch drain before GracefulStop | Decision 2.6 / req §1 | `obs_test.go` stop case | Partial | stop() flips status — planned. **Ordering vs GracefulStop is not tested** (F9): `shutdownServers` (`main_shutdown.go:125-147`) has no hook today |
| R1e nil/empty check map → SERVING | Decision 2.5 | not named | Partial | empty-map case implied by "SERVING when all pass"; **nil-func entries (orphan timeouts) untested and unhandled** (F3) |
| R1f hung check cannot wedge the poller | Decision 7 (claim) | none | **Missing** | claim is false as specified for ctx-ignoring checks (F1 — High) |
| R1g panicking check survives | Decision 7 | not named | Missing | recover-per-evaluation needs a test (F10) |
| R2 banner lists health+reflection | req §1.3 | none | Missing | banner must list **both** reflection versions (F6) |
| R3a ok + PermissionDenied → `code_class` | req §2 | `metrics_test.go` | Proposed | prometheus test registry pattern from `platform/metrics/metrics_test.go` |
| R3b duration histogram populated | req §2 | named | Proposed | buckets unspecified in design — pin `prometheus.DefBuckets`-parity with HTTP or document divergence |
| R3c unknown methods collapse to `"other"` | req §2 | named | Proposed | also cover failed-type-assertion fallback if reachable |
| R3d health/reflection excluded from both vectors | Decision 3 | named | Partial | **denylist names only v1; v1alpha is registered and untested** (F6) |
| R3e stream interceptor: one count+duration at completion | Decision 3 | none | **Missing** | no streaming RPC test planned (F8) |
| R3f metrics disabled (`m == nil`) passthrough | Decision 3 | not named | Missing | HTTP precedent `middleware.go:14-17`; needs a nil-metrics test (F10) |
| R3g label-cardinality bounded = services+1 | Decision 3 / req §2 | "other"-collapse test | Partial | memoized allowlist **must be race-safe** (F7) |
| R3h `code_class` table exhaustive (17 codes) | Decision 3 | not named | Missing | const-table totality test (F10) |
| R4 chain order: panic counted server-class | req §2 / Decision 4 | named ("synthetic panic") | Partial | acceptance must assert **exactly one** increment + oracle-safe "internal error" body (F10) |
| R4b observability layer panic-safe | Decision 4 | not named | Missing | defensive-recover path needs its own test (F10) |
| R5a TLS matrix (6 rows) | req §3 | table test over pure decision fn | Proposed | must pin loopback edge cases: `localhost`, `::1`, `127.0.0.2`, `[::]:8081`, hostname, empty host `:8081` (F4) |
| R5b TLS1.2 floor enforced | req §3 | one bufconn TLS test | Proposed | self-signed cert via existing in-memory fixture; assert handshake rejection for TLS1.0 client |
| R5c CLI startup-error on stock run | req §3 CLI acceptance | "if harness supports exec" | **Missing** | no exec harness exists (verified); must be an in-process `startGRPCServer` test instead (F4) |
| R5d flag fallback to shared pair | Decision 5 | not named | Missing | `-grpc-tls-cert` unset + `-tls-cert` set → TLS; resolution logic needs a test (F4) |
| R5e `-grpc-listen ''` disables listener | Decision 5 | not named | Missing | `startGRPCServer("")` → `(nil, nil)` without invoking the decision (F4) |
| R6 no new Config keys; docscheck green | Decision 8 #8 | — | Verified-by-construction | docscheck gates backend Config keys only; flags are outside it. Flag subsection in config-reference is review-only |
| R7 gates: build/vet → arch → -race → E2E → make ci | req §1-3 | named | Partial | go.mod minimal-diff (otelgrpc only) is a review criterion, not an automated assertion |
| R7b `-validate-only` preflight | protocol F2 | none | **Missing** | validate-only exits before the TLS decision (F5) |

---

## 3. Findings (severity-sorted)

### F1 — High — "The poller can never wedge" is false as specified; a ctx-ignoring ready check freezes every future verdict

**Evidence (Verified).** Decision 2.3 / Decision 7 claim: "A hung check
cannot wedge the poller: deadline expiry counts as failure" / "poller can
never wedge". The specified mechanism is a single poller goroutine running
all checks sequentially under one `context.WithTimeout(3s)` — exactly the
`handleReadyz` structure (`server_health.go:96-129`). A context deadline
aborts only a check that observes `ctx`. `WithReadyCheck` is a public SDK
seam (`options_misc.go:382`) and nothing forces closures to honor ctx. A
check blocking on I/O without ctx (operator-injected closure, future check)
blocks the **one** poller goroutine forever: no further evaluations, stale
SERVING keeps an LB routing to a dead replica, stale NOT_SERVING sheds a
healthy one, and `stop()`'s ctx cancellation cannot unblock the goroutine.
`/readyz` parity does not rescue this: a hung `/readyz` request occupies one
per-request goroutine and the endpoint keeps serving; the gRPC poller is
one goroutine per server.

**Regression risk.** The design's own acceptance suite (SERVING →
NOT_SERVING → recovery → Watch) uses well-behaved checks and passes while
the wedge remains. The claim is load-bearing for the SRE/security posture
("stale SERVING keeps an LB routing to a replica whose dependency is dead").

**Exact test to add** (`obs_test.go`):
- `checks` returns `{"hanger": func(ctx) error { <-block; return nil }}`
  (blocks on a channel, never reads ctx) plus `{"flapper": failingCheck}`.
- Assert NOT_SERVING lands within ~3s (aggregate bound) while the hanger is
  blocked.
- Release the flapper → assert SERVING arrives within 2 poll intervals.
- With the hanger permanently blocked, run 3 evaluations and assert
  `runtime.NumGoroutine` growth is bounded (≤ 1 extra goroutine per hung
  check), proving no per-evaluation leak.

**Acceptance assertion.** Verdict latency ≤ 3s + ε with a ctx-ignoring
check present; flapper recovery still observed; goroutine growth bounded at
one per hung check. **This test fails against the design as written** — the
design must be amended: evaluate checks concurrently (one goroutine per
check under the aggregate deadline, verdict via select on done/ctx), and
skip re-probing a check whose previous probe is still in flight so a hung
check leaks at most one goroutine and still reports NOT_SERVING. Alternative
(weaker, must be stated as a hard SDK contract): keep sequential execution
and document that ready-check closures MUST honor ctx — then the test
asserts the documented contract instead and the wedge is accepted.

### F2 — Medium — Poll interval is a const; the designed obs_test is slow and timing-flaky

**Evidence (Verified).** Decision 2.1: `HealthPollInterval = 5 * time.Second
(const in obs.go)`. A const cannot be shortened in tests. The planned
obs_test exercises failure → recovery → Watch transitions: each transition
waits up to one poll tick, i.e. a 3-transition test takes up to ~15s of real
time and every Watch assertion is a timing race against a 5s ticker.

**Exact test to add.** None separate — this is a testability amendment:
`healthPollInterval` must be an unexported package-level var (or an
injectable option on `RegisterObservability`); obs_test overrides it to
~10–25ms via a helper.

**Acceptance assertion.** The full obs_test suite completes in < 2s with
the override; no test sleeps longer than 1s; transition assertions use
`eventually`-style polling with a slack of 2× interval.

### F3 — Medium — nil `Check` funcs in the ReadyChecks map: poller would panic → permanent NOT_SERVING while /readyz says 200

**Evidence (Verified).** `WithReadyCheckTimeout` pre-registers a
`namedReadyCheck{Name, Timeout}` with nil Check when the name has no check
yet (`options_misc.go:407-422`). `populateHandlerDepsCallbacks` copies
`m[rc.Name] = rc.Check` verbatim, nil included
(`accessors_handlers.go:343-350`). `/readyz` explicitly skips nil entries
(`server_health.go:104-108`). The design's poller rule is "any failure or
panic → NOT_SERVING" with no nil-skip — calling a nil func panics, the
per-evaluation recover fires, and every service is NOT_SERVING forever while
`/readyz` keeps returning 200 with a skipped check. The design's "matches
/readyz" parity claim breaks exactly in the failure direction.

**Exact test to add.** checks map `{"orphan": nil, "healthy": okCheck}` →
SERVING; map `{"orphan": nil}` only → SERVING (mirrors /readyz empty-after-
skip).

**Acceptance assertion.** The poller skips nil funcs (does not panic, does
not mark NOT_SERVING), matching `/readyz` byte-for-byte on the same check
set.

### F4 — Medium — The CLI startup-error acceptance (req §3) is not executable as planned; must be an in-process `startGRPCServer` test

**Evidence (Verified).** The design says "CLI-level startup-error check if
the existing test harness supports exec of the binary, else the matrix test
+ manual verification". Zero `exec.Command` uses exist in
`cmd/sso-server/*_test.go` (verified) — the conditional branch is dead, and
the requirements' CLI acceptance ("sso-server -grpc-listen :8081 ... exits
with a startup error") goes untested. The wiring layer between the pure
matrix function and the process (flag fallback resolution, listen-host
parsing, `grpcServerOptions` invocation) is exactly where a regression
would land silently.

**Exact test to add** (`cmd/sso-server`): call `startGRPCServer` /
`grpcServerOptions` directly, in-process:
- `startGRPCServer(a, ":8081", ..., "", "")` → error naming the missing
  material and the three escape hatches;
- `127.0.0.1:8081` + no certs → no error (plaintext loopback);
- `:8081` + `-grpc-insecure` → no error;
- `-grpc-listen ''` → `(nil, nil)`, decision not invoked;
- asymmetric pair (`-grpc-tls-cert` only) → error even with `-grpc-insecure`;
- cert + insecure → error;
- `-grpc-tls-cert/-key` unset, shared `-tls-cert/-key` set → TLS (fallback
  resolution);
- loopback edge cases pinned: `localhost`, `[::1]:8081`, `127.0.0.2:8081`
  (net.IP.IsLoopback is 127/8 — decide and pin whether 127.0.0.2 is
  loopback), `[::]:8081` and `0.0.0.0:8081` → error, hostname
  `grpc.example.com:8081` → error.

**Acceptance assertion.** Every row of the Decision 5 matrix plus the
fallback and escape cases returns the documented result; the error string
contains the resolution list.

### F5 — Medium — `-validate-only` cannot preflight the new fail-closed boot error (protocol F2, re-verified)

**Evidence (Verified).** `main.go:96-100` returns after config validation,
before `run()` and therefore before `grpcServerOptions`' TLS decision.
Operators using `-validate-only` in rollout pipelines (its documented
purpose) get a green preflight and a CrashLoop at boot.

**Exact test to add.** If the decision is folded into the validate path:
cmd-level test asserting validate-only with `-grpc-listen :8081` and no
certs exits non-zero with the resolution list. If deliberately kept out of
validate-only (validate-only = config-only by contract): assert the current
exit-0 behavior and document the limitation in the config-reference section.

**Acceptance assertion.** Whichever posture is chosen is test-locked, and
the config-reference text states whether `-validate-only` covers the gRPC
TLS posture.

### F6 — Low — Reflection denylist and banner cover only v1; v1alpha is registered and untested (security F5 / protocol F3, re-verified)

**Evidence (Verified).** `reflection.Register` registers v1 **and** v1alpha
(`serverreflection.go:62-70`). Decision 3's denylist names only
`grpc.reflection.v1.ServerReflection`; the banner lists only v1. The
tooling the design cites (grpcurl/grpcreflect) commonly speaks v1alpha, so
probe traffic lands under `grpc_service="grpc.reflection.v1alpha"` — the
exact noise the denylist exists to exclude.

**Exact test to add.** Denylist by service prefix (`grpc.reflection.`,
`grpc.health.`) or list both full names; send a v1alpha reflection RPC
(client package `google.golang.org/grpc/reflection/grpc_reflection_v1alpha`
is in the module cache) and assert neither vector increments. Banner test:
`logGRPCServices` output contains both reflection service names.

**Acceptance assertion.** v1 and v1alpha reflection RPCs and health
Check/Watch increment neither `sso_grpc_*` vector.

### F7 — Low — Memoized service allowlist must be race-safe and race-tested (security F7)

**Evidence (Proposed design).** "Lazily memoizes … (first RPC per server
instance)". Unary and stream interceptors run on many goroutines
concurrently; a plain map write on first touch is a data race. The planned
metrics tests (ok / PermissionDenied / panic / "other") are sequential and
would not trip `-race`.

**Exact test to add.** Spec `sync.Once` or `atomic.Value` in the design;
metrics_test hammers N goroutines' first RPCs against one fresh server and
runs under `go test -race`.

**Acceptance assertion.** `go test -race -count=1 ./interfaces/grpcserver/`
is clean with the concurrent first-RPC test present; all methods still
classify to the real service name, not `"other"`.

### F8 — Low — Stream interceptor path has no planned test

**Evidence (Proposed design).** Decision 3 specifies stream behavior (one
count + duration at stream completion, status from the completed stream)
but the test list covers only unary RPCs. The stream path is distinct code
(separate interceptor, stream-info plumbing) and the health Watch stream is
denylisted, so no planned test exercises a counted stream.

**Exact test to add.** Register `NewDiscoveryService(platform/registry/memory.New())`
and open `discoveryv1.Discovery.Watch` (server-streaming,
`discovery.go:67`); close the stream; assert exactly one
`sso_grpc_requests_total` increment with `grpc_service="snaplink.discovery.v1.Discovery"`
and one duration observation. A client-cancelled stream asserting the
`Canceled → client` mapping doubles as a code_class boundary test.

**Acceptance assertion.** One count + one duration per completed stream
regardless of message count; cancellation classifies `client`.

### F9 — Low — `stop()` drain-before-GracefulStop ordering is untested and unwired

**Evidence (Verified).** `shutdownServers` (`main_shutdown.go:125-147`)
calls `GracefulStop` with a fallback `Stop`; nothing today calls a health
`stop()`. The design says "wired into the server shutdown path next to
GracefulStop" but lists no test for the ordering, for stop idempotency, or
for stop-before-first-evaluation.

**Exact test to add.** cmd-level: build a grpc.Server via
`startGRPCServer`-adjacent wiring, register observability, connect a
`healthpb.Health_WatchClient`, run `shutdownServers`, and assert the Watch
stream receives NOT_SERVING before `GracefulStop` returns.

**Acceptance assertion.** Watch clients observe the drain transition before
the RPC plane closes; calling `stop()` twice is a no-op; `stop()` before the
first evaluation leaves a consistent state (no panic, no goroutine leak —
assert via goroutine-count delta in the test).

### F10 — Info — Small acceptance-sharpening items

- **Panic-count test (chain-order lock):** assert exactly **one** increment
  (guards against the metrics interceptor's defensive recover double-
  recording on top of Recovery's synthesized Internal) and that the client
  sees the oracle-safe bare "internal error" (`recovery.go` wording), not
  the panic value.
- **code_class totality:** table test that all 17 `codes.Code` values map
  (const table exhaustive) and the mapping matches the doc'd table verbatim.
- **Poller panic recovery:** a panicking check → NOT_SERVING + warn log,
  poller still evaluates next tick.
- **Flapping dedupe:** two consecutive identical statuses produce exactly
  one Watch transition message (grpc's health.Server dedupes — pin it).
- **Nil-metrics passthrough:** `metrics.Metrics(nil)` interceptors pass
  through and panic-safe path still returns Internal for a handler panic.
- **Defensive-recover test:** a panic inside the observability layer itself
  (inject via a metrics hook) → Internal + process alive.

---

## 4. Prioritized scenario list

Ordered by risk; each maps to a finding above.

1. **Wedge (F1, High):** ctx-ignoring hung check + concurrent flapper —
   bounded verdict latency, recovery still observed, bounded goroutine
   growth. This is the only scenario that can silently degrade production.
2. **Chain-order regression (F10/R4):** handler panic → exactly one
   server-class increment, process survives, client sees bare "internal
   error"; a future editor reverting the order must fail this test.
3. **Orphan timeout (F3):** nil-func entries skipped, parity with /readyz on
   the same check set.
4. **TLS matrix (F4):** all 6 rows + loopback edge cases + fallback +
   `-grpc-listen ''` + asymmetric + cert∧insecure; TLS1.2 floor via a
   TLS1.0 client handshake rejection.
5. **Stop/drain (F9):** Watch client observes NOT_SERVING before
   GracefulStop; idempotent stop; no goroutine leak.
6. **Metrics classification (R3):** ok/client/server representatives
   (nil, PermissionDenied, Internal); `"other"` collapse; v1+v1alpha
   denylist; stream single-count; nil-metrics passthrough; concurrent
   first-RPC under -race.
7. **Health transitions (R1):** all-pass → SERVING; fail → NOT_SERVING;
   recover → SERVING; empty map → SERVING; panicking check survives;
   Watch initial + deduped transitions.
8. **Preflight (F5):** validate-only posture pinned one way or the other.
9. **Cardinality boundary:** 50 registered services → 51 label values max;
   unknown service → `"other"` (no per-method growth).
10. **Recovery/E2E:** TestE2E still green with the new chain; manual
    grpcurl enumeration with post-change flags (loopback + `-grpc-insecure`
    or TLS material).

---

## 5. CI/manual-suite gaps, flake risks, fixtures needed, exit criteria

**CI/manual gaps**
- `make ci` / CI have no grpcurl step — the design's "grpcurl -plaintext
  localhost:8081 list" is manual and, post-change, needs adjusted flags
  (loopback + `-grpc-insecure` or TLS material); record it as a manual
  verification step with the corrected invocation.
- No exec harness for the binary: the req §3 CLI acceptance must be
  converted to the in-process `startGRPCServer` test (F4) or a new exec
  harness added.
- The `sso_grpc_*` doc rows in `docs/observability.md` have no automated
  gate (consistent with `sso_http_*` today) — review-only; flag in the PR.
- Optional: a chaos-suite drill (`test/chaos`, `-tags chaos`, run in CI)
  for the flapping scenario (M1 from the SRE review) — a throttled store
  producing SERVING↔NOT_SERVING and the transition-rate signal; optional
  because the unit-level dedupe test (F10) covers the mechanism.
- The `-race` gate is in both `make ci` and `.github/workflows/ci.yml`
  (line 117) — it only helps if a concurrent test exists (F7).

**Flake risks**
- Real 5s poll interval in obs_test (F2) — the top flake source; must be
  injectable.
- Watch-transition assertions — use eventually-polling with 2× interval
  slack, not fixed sleeps.
- Goroutine leaks across tests (poller, streams): every obs/metrics test
  must `t.Cleanup` stop + conn.Close + srv.Stop (pattern from
  `test/admin_grpc_base_test.go`); no goleak in the repo, so hygiene is the
  only guard.
- The chain-order panic test must assert exactly-one increment to avoid
  passing under both orders (F10).

**Fixtures needed (all pre-existing — no new fixtures)**
- bufconn server pattern: `test/admin_grpc_base_test.go` (note: uses single
  `grpc.UnaryInterceptor`, not chain — obs tests must use
  `grpc.ChainUnaryInterceptor`).
- In-memory self-signed certs: `interfaces/sso/mtls_revocation_test.go` /
  `test/mtls_bound_test.go` for the TLS1.2 bufconn test.
- Prometheus test registry: `platform/metrics/metrics_test.go`.
- Memory registry: `platform/registry/memory.New()` for the stream test.
- v1alpha client: `google.golang.org/grpc/reflection/grpc_reflection_v1alpha`
  (module cache).
- Logger: `spi.NopLogger` (used across cmd tests).

**Exit criteria**
1. F1 amendment (concurrent per-check evaluation with in-flight skip) +
   wedge test passing — the only High.
2. F3 nil-skip test, F4 in-process startup-error matrix, F6 v1alpha
   denylist/banner, F7 race test, F8 stream test, F9 stop-ordering test all
   land with the implementation.
3. F2 interval injectability is in the same change as `obs.go` (not a
   follow-up).
4. Full gate sequence per AGENTS.md §5: `go build ./... && go vet ./...`;
   `go test -run 'TestMaintainability_|TestArchitecture_' .`;
   `go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci`
   (with the otelgrpc go.sum addition and network fetch confirmed).
5. Manual: grpcurl enumeration with corrected flags; staged stock-run
   startup-error drill (SRE H1 recovery validation).
6. Baseline at this revision is green (build/vet, architecture gates,
   grpcserver+metrics packages, TestE2E) — implementation starts from a
   measured pass, not an assumption.
