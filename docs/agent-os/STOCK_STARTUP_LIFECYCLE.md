# Post-build stock exit lifecycle

## Goal, owner and scope

A migration operator must not treat failed startup or rejected traffic as rollback.
Review found that `main.go::run` closed backing stores via defer, but called
`shutdownServers`/`shutdownSubsystems` only after a successful wait. Bootstrap,
HTTP-handler construction, gRPC-start or wait errors could bypass cancellation,
drain and listener shutdown after `buildApp` had already started workers.
This bounded infrastructure/lifecycle fix covers exits AFTER successful buildApp
and the failed-build ownership boundary for the shared Redis/Postgres pools.
It is neither full startup-effect admission nor historical runtime acceptance.

## Single owner, unchanged deadline

`run` installs one late-bound deferred `shutdownRuntime` immediately after the
existing backing-store defer, before reload hooks/bootstrap/listener work.
The closure sees the actual handles constructed so far, including a partial set.
LIFO defer order drains runtime before `closeAppStores` releases backing pools.

`shutdownRuntime` uses the existing single15-second shutdown context for:

1. Closing the SSE broker.
2. HTTP/pprof and gRPC health/transport shutdown, allowing absent HTTP.
3. Existing subsystem teardown: watch loops, schedulers, ReBAC, delivery/router,
   anomaly/usage, audit exporters, SCIM, CAEP/backchannel and store reapers.
4. Clean-stop logging only after normal completion AND a nil returned error.
   Panic unwinding is not clean completion; panic is not recovered or suppressed.

The gRPC health stop is invoked before the retained-server check, so a failed
bind still owns its readiness poller: `newGRPCServer` registers observability
(and stores its stop on the app) before `net.Listen`, and a bind failure returns
no `*grpc.Server` handle into the runtime server set. Without that ownership the
poller would outlive teardown because the nil-server early return skipped the
stop; the stop remains before `GracefulStop` on the normal path and skips only
the GracefulStop a nil server cannot perform.

No extra server/worker timeout is added and no cancellation policy is disabled.
A closer ignoring context can still exceed the context's deadline; this change
is not hard process termination, full quiescence proof or rollback. Existing
shutdown errors retain their existing logging/error semantics; original run
errors are returned, not replaced by a fabricated successful exit.

## Reviewed lifecycle frontier (not a complete effect graph)

| Stage / source owner | Observed effect / remaining obligation |
|---|---|
| main/load/tracing; main_wiring | Real config-source chain, runtime tuning and optional OTLP initialization precede run; a run failure now flushes tracing and closes config sources before `os.Exit` via the shared defer helpers. Direct `fail()` exits after the source defer is installed (config/capability/validate-only) still bypass those outer defers. External transport/flush admission remains open. |
| build_stores::buildApp | Failure cleanup is installed before peer-trust, Redis/Postgres pool and HA-coherence wiring. A failed build releases the shared Redis/Postgres pools via `closeBuildFailure` (nil-idempotent, reclaiming the builder references) after the partial worker teardown; a failed build still has no completed app, no data reset and no rollback guarantee. |
| foundation/domains/edge | Store migrations/loads/prunes, configured seeds and optional option constructors may write/start workers before finalize; exact effective predicates and retention policies still require admission. |
| build_app::finalize | NewServer, background/governance loops, snapshots/DR, registry and tenant quota start before builtin bootstrap and public listeners. They are not made side-effect-free by a later error. |
| main_shutdown::shutdownWatchLoops | Network classifier, invalidation bus, signing-key registry and rotation are stopped/drained before stores. Context cooperation and concrete backend effects remain to be verified. |
| main_shutdown::shutdownSchedulers | Tenant quota plus16 cancel/done pairs cover retention, DR, push/CIBA/grace, credential/config/break-glass/degradation/trust/CAP/anomaly/user/client-secret work. Mapping and configuration do not prove no initial sweep/write. |
| main_shutdown::shutdownAuditExporters | Async queue drains before webhook/Kafka and external audit/notary close. Flushes may write or contact external sinks. |
| main_shutdown::closeAppStores | Existing connections/config-audit/tenant/network/registry close, then shared Redis/Postgres pools; concrete Close semantics are separate from cancellation and rollback. |

Full effective configuration, every reachable constructor/option/callback/worker,
files/transports, normal/error/panic paths and original-row preservation remain
open. No expired rows, grants, cleanup knobs, bootstrap history or authority are
changed to obtain PASS. Separate owned off/on trackers are still required.

## Regression and acceptance

`main` keeps the outer defers (config-source close, then tracing flush via
`flushTracing`) and the run-error path calls `runErrorCleanup` before
`os.Exit(1)`, because direct process exit skips deferred calls. Both paths share
`flushTracing`, so the failed-run cleanup cannot drift from the normal sequence;
the run error and exit status are unchanged.

`startup_exit_cleanup_test.go` contains source-spine guards for exactly one
late-bound defer before post-build effects, backing-store LIFO order, normal-only
completion, no duplicate teardown and a run-error branch that flushes
tracing/config sources before `os.Exit`. Behavioral cases cover absent HTTP with an
unserved in-memory gRPC server, partial handles, a failed gRPC bind whose
observability stop is still invoked after the nil-handle early return, two
owned loopback stdlib listeners, and the run-error cleanup order with the bounded
flush context; cancellation precedes audit close and clean/error logging differs.
These cooperative synthetic cases call no buildApp, store, bootstrap or historical
service and do not prove arbitrary backend/context or startup/panic behavior. The
build-failure owner is additionally pinned at source level ahead of the shared-pool
wiring and behaviorally against a close-counting client plus an inert in-memory pool,
so a failed build releases both pools exactly once.

```sh
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test -race -count=10 -timeout=60s ./cmd/sso-server -run '^TestStartupExitCleanup_' -v
make ci
```

Committed budgets, full CI, product E2E and explicit owned-PG supplementary
acceptance remain mandatory. No threshold, skip, exemption, dependency, SPI,
YAML/default, grant, session or HTTP contract changes. Independent compatibility/
security/integration review, historical passwords/business/browser equivalence,
30-day wall-clock sessions, deployed recovery/fencing/backups and production
approval remain absent. Step42 full runtime remains failed; Step44's missing
original coverage cause remains unknown. No retrospective upgrade, closed-fixture
replay, production contact, automatic commit/merge/push/deploy or SVERP live
watch/topology/session-policy change follows.
