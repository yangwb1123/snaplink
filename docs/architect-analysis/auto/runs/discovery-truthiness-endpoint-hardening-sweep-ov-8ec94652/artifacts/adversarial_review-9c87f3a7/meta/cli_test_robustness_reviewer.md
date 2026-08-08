All five legs verified against the working tree. Verdict: **four legs fully expressible and flake-proof as planned; one leg (the missing-bearer exit-2 claim) is unsupported by any harness and must be re-scoped or converted.**

## 1. Wrong-bearer leg at `readFromURL` level — expressible, no new machinery ✓

- `readFromURL(base, bearer, limit, pageSize, timeout)` is package-local and already exercised directly against `httptest` servers in four existing tests (main_test.go:119,147; coverage_test.go:55-123; checkpoint_test.go:575). The 401 leg works: `fetchEventPage` wraps the failure as `page (offset=0) http 401: <body>` (main.go:485-487), so `strings.Contains(err, "http 401")` holds, and with the real gated server the embedded body is the REQ-2 `{"error":"invalid_token"}\n`.
- The real-gated-server construction is doubly precedented: `rootcov_misc_test.go:169-233` (identical stores/authn/permissions/admin-wrap/login shape, proves login → bearer → 200 on `/api/v1/audit/events`) and, critically, two sibling packages in the same module already import `interfaces/sso` in tests — `cmd/sso-ctl/apiclient/check_test.go:26` (builds a real in-process `sso.NewServer` over httptest, the exact REQ-3 shape) and `snapshotcmd/main_test.go:16`. No import cycle, no new harness machinery; the login POST helper must be re-created locally (~15 stdlib lines, `rcovPostJSON` is package-private) — copy-code, not machinery.
- One coupling to keep: leg (c)'s "no bearer → 401 byte-identical (REQ-2 bytes)" is only true after REQ-2 lands; the plan's §5 step-1 sequencing already handles this.

## 2. Missing-bearer `os.Exit(2)` leg "asserted at binary level" — **FLAG: no harness asserts it at any level**

- **Zero unit coverage exists.** Grep of every auditverify test for `loadEvents`, `usageErr`, or "bearer is required" — no hits. The only mention is the comment at checkpoint_test.go:483 noting these paths "still os.Exit in-process."
- **Zero binary-level CLI harness exists.** No `exec.Command`-of-`sso-ctl` anywhere; `test/main_test.go` is bcrypt-cost-only; the sole exec precedent (scaffold_build_test.go) runs `go build` on generated scaffolds, unrelated; CI has no sso-ctl smoke.
- Therefore REQ-3 check 4's premise ("keep the current unit coverage green") has **no referent**, and the design's acceptance row "(d) … exit 2 at binary level (kept green, not in-process asserted)" overstates: nothing asserts it at *any* level. It is an unasserted keep-green by code inspection only (which is trivially safe — REQ-2 touches only `interfaces/admin`, never `loadEvents`/`usageErr`).
- Options: (a) reword the row honestly as "unasserted legacy keep-green"; or (b) convert the missing-bearer check from `loadEvents`'s `usageErr` to the module's **own established return-code misuse pattern** (`checkMisuse` precedent, main.go:234-244: "New failure paths … RETURN the code so tests can exercise them in-process") — 5 lines, zero new machinery, binary exit-2 byte-identical via `main()`'s `os.Exit(run(args))`. A *genuine* binary-level assertion (subprocess exec of a built sso-ctl) would require new harness machinery — the only leg in the plan that would. Note the same gap covers the sibling `usageErr` legs (neither source flag given / both given).

## 3. Golden permissive-comparison guard — demonstrably fails on permissive binding ✓

- Verified against current code: permissive + `text/plain` + non-JSON → `BindParams` `default:` branch (oauthwire/bind.go:37-46) → `decodeSingleJSON` fails → `handleToken` maps to `400 errorBody(ctx, ErrInvalidRequest)` (server_token.go:29-32). The permissive leg genuinely fails binding at the same error the strict CT gate emits — the comparison is not vacuous.
- Golden arithmetic re-verified: `ErrorBodyWithTrace` with empty trace emits `{"error":"invalid_request"}` (shared/core/error_body.go:31-37) → `json.Encoder` → exactly 28 bytes. Harness must not wire tracing (matches AC-2(b2)).
- The guard is trip-proof on this tree: "fixing" the contrast with a JSON-shaped body → permissive 200 (JSON accepted) → `permCode==400` fails; if text/plain ever became form-bound, empty fields → `invalid_client` 401, not 400. Both escapes fail the pin. Keep the plan's explicit "non-JSON payload" wording (a JSON `{}` body decodes fine → 401, not 400).

## 4. REQ-3 synchronous recorder, N≥1 — cannot flake, structurally ✓

- `Recorder.Record` is fully inline (recorder.go:181-203): stamp → redact → `chainer.stamp` → `sink.Record`. No AsyncSink in the planned construction.
- Login records ≥1 event *before the HTTP response returns*: `recordLoginSuccess` (server_helpers.go:335-353) → `RecordLoginSuccessWithMeta` (recorder_events_session.go:114-133) → `rec.Record` — same goroutine as the response write.
- **Ordering is provably deterministic**: `chainer.stamp` enforces strictly monotonic timestamps (`if !e.Timestamp.After(c.lastTS) { e.Timestamp = c.lastTS.Add(time.Nanosecond) }`), so MemorySink's `sort.SliceStable(Timestamp.After)` (memory_sink.go:79-81) yields exact newest-first chain order and the CLI's reversal is exact chain order — `VerifyChain` cannot false-break. Same machinery the existing tight-loop `chainedEvents` tests already pass on.
- The sink is quiescent during CLI paging: `HandleEvents` only queries (handlers.go:31-48, no `Record`), and the 401 probes short-circuit in the middleware before any handler. The only ordering dependency is the HTTP request/response barrier in the same test goroutine. MemorySink(50) holds ~2-5 login events with no eviction.

## 5. AC-5 timing-leg guards — deterministic in construction, correctly skippable ✓

- The guard set (0a8df02f AC-5, adopted verbatim) is sound: the target is genuinely constant-time per byte (`ConstantTimeStringEq` → `crypto/subtle.ConstantTimeCompare`, shared/security/constant_time.go:10-19); the 1024-char pre-built constants are load-bearing (T-B1 measured per-iteration construction compressing the regression ratio ~150x → ~2.7x, collapsing the 1.5x margin); round-robin interleave removes thermal/frequency drift from the position comparison; medians over 1000 iterations are outlier-robust; an early-exit regression yields a ~1000x position gap ≫ 1.5x — deterministic failure.
- One implementation note to honor: the three existing `client_secret_test.go` tests are all `t.Parallel()` — the new statistical test must be non-parallel *and* must not inherit `t.Parallel` from a shared helper.
- Correct posture confirmed: statistical leg recommended-but-skippable; deterministic companions (per-position mismatch table, length short-circuit, bcrypt path, plus the `/token` seam pin through `ValidateSecret` → `compareClientSecret` → `ConstantTimeStringEq`) are the hard requirement and are all behavior-level pins.

## Bottom line

One flagged leg: **REQ-3 (d)**. As worded ("asserted at binary level", "keep the current unit coverage green") it asserts nothing — no unit coverage and no binary harness exist. Either re-scope to "unasserted keep-green" or, better, convert the check to the module's own return-code misuse pattern (zero new machinery, byte-identical binary behavior). No other leg requires new harness machinery; the `newTokenHarnessOpts` delegation (D7) is a trivial refactor of the verified `test/handle_token_test.go:23` harness, and the e2e server construction has two in-module precedents including one in a sibling `cmd/sso-ctl` package.
