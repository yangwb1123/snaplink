# Refresh-grace startup-failure cleanup

## Goal and boundary

Close the remaining stock `sso-server` lifecycle gap: when a later wiring phase
returns an error after refresh-grace allocation, cancel its pruning worker,
drain it, then release its owned SQLite connection. A PostgreSQL grace wrapper
must stop without closing its caller-owned shared pool. This is composition
lifecycle work (U1-U9, S4/S6 where applicable), not an OAuth behavior change.

## Scope and budgets

- Extend `appBuilder.closeBuildFailure` in `cmd/sso-server/main_shutdown.go`;
  `buildApp` already defers this cleanup on subsequent returned errors.
- Restore missing grace cancel/done ownership transfer in
  `cmd/sso-server/build_app_core.go`'s `assembleExtras`. Without that mapping,
  normal stock shutdown never reaches the already implemented drain/close.
  Cover the real successful `buildApp` path, not only manually assembled apps.
- Reuse `stopScheduler`, `closeGraceAfterPrune`, and the existing
  `shutdownTimeout`; no new lifecycle registry, option, configuration or SPI.
- Tests: `cmd/sso-server/refresh_grace_lifecycle_test.go`, real SQLite and
  environment-gated isolated PostgreSQL, with repeated race execution.
- Keep the 500-line production-file / 50-line function ceilings. Do not grow
  exemptions, modify root dependencies or claim concurrent Browser SSO work.
- Do not change grant issuance, grace replay/reuse, fail-open helpers, schemas,
  public wire errors or normal shutdown ordering. Successful-build ownership
  must be transferred, not closed by the builder's failure-only defer.
- General cleanup of every partially initialized subsystem and panic recovery
  remain out of scope. Existing unrelated audit cleanup may be unbounded;
  only the added grace wait is bounded by the existing shutdown timeout.

## Acceptance

1. Given a live owned SQLite grace store, failure cleanup cancels and drains
   pruning before closing the database; the common cleanup is repeatable.
2. Given actual grace wiring followed by a later grant-wiring error, the
   original error remains unchanged, and the same common failure cleanup
   releases the allocated grace resources before unrelated audit cleanup.
3. Given a caller-owned PostgreSQL pool, the wrapper stops and becomes closed,
   but the pool remains usable. Real backend checks use isolated test schemas.
4. Feature-off and memory grace do not acquire database cleanup handles.
5. A successful build retains ownership until normal shutdown; existing
   runtime, shutdown and token security tests remain green.
6. Reuse deadline-aware waiting rather than closing a database under a running
   worker. If a worker exceeds the wait, retain asynchronous close-after-drain.

## Verification and evidence freshness

After every Go edit run build, vet and committed architecture/maintainability
gates. Run lifecycle tests with `-race -count=10`, current token/backend races,
E2E and complete `make ci`, then independent read-only review. No OpenAPI,
config-reference or error-code change is needed: the public surface is unchanged.

Prior OCI scans/runtime/promotion describe the earlier production bytes. Any
production-code change invalidates their status as the current-source checkpoint;
rebuild/reverify/rescan before calling updated artifacts locally accepted. Dirty
local readiness images are not clean-tag public releases. Native ARM/Mac,
protected publication/signing and production acceptance remain external.

## Execution result

- Both original gaps were reproduced before production edits: failure cleanup
  returned without draining grace, and a real successful `buildApp` lost its
  grace shutdown handles (`lifecycle/red.log`).
- Build, vet and committed architecture/maintainability gates passed after each
  Go edit. Final production file sizes: `build_app_core.go` 500 lines,
  `main_shutdown.go` 466 lines; no exemption growth.
- Final lifecycle, token security and grace-backend tests passed with
  `-race -count=10`, including real SQLite, isolated PostgreSQL, memory/Redis
  where applicable, feature-off and a deterministic expired-deadline wait.
- E2E and complete `make ci` passed with real PostgreSQL16
  (`max_connections=300`) and `GOFLAGS=-p=8`. These are local fixture choices,
  not verification of remote CI defaults or production capacity.
- Independent source-only review found no scoped P0/P1; it did not execute
  tests or certify the product. At that checkpoint one P2 remained: forced HTTP
  shutdown could overlap an unwinding handler with wrapper close. The separate
  [concurrent-close follow-up](refresh-grace-concurrent-close.md) addresses the
  grace wrappers; this original lifecycle-only fix did not establish that safety.
- Current-source logs and reviews: `dist/release-readiness/lifecycle/`.
  Earlier OCI/runtime/scan/promotion evidence stays bound to older bytes;
  it is not the updated source's container acceptance. No commit, push,
  publication, signing, native ARM/Mac or production acceptance was performed.
