package main

import (
	"context"
	"io"

	"github.com/snaplink/sso/shared/spi"
	"google.golang.org/grpc"

	"net/http"
)

// closeAppStores releases the long-lived backing stores at process exit. Order
// mirrors the original LIFO defer chain (connections → tenant → netpolicy →
// registry): connections + tenant + netpolicy stores depend on nothing the
// registry close needs, and closing innermost-first matches the prior behavior.
func closeAppStores(a *app) {
	// connections.Store has no Close on the interface; the sqlite backend does.
	if c, ok := a.connectionStore.(io.Closer); ok {
		_ = c.Close()
	}
	// configaudit.Store has no Close on the interface; the sqlite backend does.
	// The governance schedulers are already stopped (shutdownSubsystems ran
	// before this deferred close), so no writer races the connection close.
	if c, ok := a.configAuditStore.(io.Closer); ok {
		_ = c.Close()
	}
	if a.tenantStore != nil {
		_ = a.tenantStore.Close()
	}
	if a.netStore != nil {
		_ = a.netStore.Close()
	}
	_ = a.registry.Close()
	// The shared Redis client + Postgres pool back the stores closed above, so
	// release their connection pools last. Nil for memory/sqlite deployments.
	if a.redisClient != nil {
		_ = a.redisClient.Close()
	}
	if a.pgDB != nil {
		_ = a.pgDB.Close()
	}
}

// closeSSEBroker evicts every live admin event-stream subscriber BEFORE the
// HTTP graceful drain. http.Server.Shutdown does not cancel in-flight request
// contexts, so an idle EventSource connection would otherwise sit open until
// the shutdown deadline forces a hard Close (dropping every other in-flight
// request too); closing the broker first makes the stream handler's
// channel-closed branch return immediately, and the client reconnects with
// Last-Event-ID once the next instance is up. No-op when events.enabled is
// false (Server.SSEBroker returns nil).
func closeSSEBroker(a *app) {
	if a.server == nil {
		return
	}
	if broker := a.server.SSEBroker(); broker != nil {
		broker.Close()
	}
}

// shutdownServers gracefully stops the HTTP, pprof, and gRPC listeners under the
// shared shutdown deadline. HTTP falls back to a hard Close on graceful-shutdown
// error; gRPC falls back to Stop when GracefulStop outlives ctx.
func shutdownServers(ctx context.Context, logger spi.Logger, httpSrv, pprofSrv *http.Server, grpcSrv *grpc.Server) {
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("http graceful shutdown failed", "error", err)
		_ = httpSrv.Close()
	}
	if pprofSrv != nil {
		_ = pprofSrv.Shutdown(ctx)
	}
	if grpcSrv == nil {
		return
	}
	stopped := make(chan struct{})
	go func() { grpcSrv.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-ctx.Done():
		logger.Error("grpc graceful shutdown timed out — forcing stop")
		grpcSrv.Stop()
	}
}

// shutdownApp tears down the wired subsystems in dependency order under the
// shared shutdown deadline. Ordering matters: watch/subscriber loops are
// cancelled + drained before their stores close, and the audit retention
// scheduler stops BEFORE the AsyncSink drains so an in-flight Prune can't race
// the close.
func shutdownSubsystems(ctx context.Context, a *app, logger spi.Logger) {
	shutdownWatchLoops(ctx, a)
	shutdownSchedulers(ctx, a, logger)
	// Anomaly detection: drain queue + close SQLite stores. Bounded
	// by the same shutdown ctx so a hung detector backend can't
	// stall the whole process.
	if a.anomalyRT != nil {
		a.anomalyRT.close(ctx)
	}
	// Drain the audit AsyncSink queue under the same shutdown
	// deadline. Events queued during the final ~milliseconds before
	// SIGTERM matter — they're typically the shutdown events
	// themselves (admin logout, snapshot rotation). Best-effort:
	// remaining events are silently dropped when the deadline fires.
	if a.auditAsyncSink != nil {
		if err := a.auditAsyncSink.Close(ctx); err != nil {
			logger.Error("audit async drain timed out", "error", err)
		}
	}
	// Drain in-flight CAEP SET pushes so a shutting-down replica doesn't
	// abandon a goroutine mid-POST. Bounded by the shutdown ctx; each send
	// also has its own per-receiver timeout.
	if a.server != nil {
		if tx := a.server.CAEPTransmitter(); tx != nil {
			if err := tx.Close(ctx); err != nil {
				logger.Error("caep transmitter drain timed out", "error", err)
			}
		}
	}
}

// shutdownWatchLoops cancels + drains the cross-replica watch/subscriber loops
// (netpolicy classifier, invalidation bus, signing-key registry + rotation)
// before their backing stores are dropped, so each loop exits cleanly instead of
// treating the store close as a watch failure.
func shutdownWatchLoops(ctx context.Context, a *app) {
	// Cancel the Classifier's watch loop so it exits cleanly (no spurious
	// degraded flip), then wait briefly for it to drain any in-flight Apply
	// events before we drop the store reference.
	if a.netCancel != nil {
		a.netCancel()
	}
	waitForStop(ctx, a.netStop)
	// Close the invalidation bus so its subscriber Watch loop exits, then
	// wait briefly for that goroutine to drain — same shape as netStop.
	if a.invalidationBus != nil {
		_ = a.invalidationBus.Close()
	}
	waitForStop(ctx, a.busStop)
	// Close the signing-key registry so its subscriber stream exits, then
	// wait briefly for that goroutine to drain — same shape as busStop.
	if a.signingKeyRegistry != nil {
		_ = a.signingKeyRegistry.Close()
	}
	waitForStop(ctx, a.signingKeyStop)
	// Stop the signing-key rotation loop and wait for it to exit.
	if a.keyRotationCancel != nil {
		a.keyRotationCancel()
	}
	waitForStop(ctx, a.keyRotationStop)
}

// shutdownSchedulers stops the background retention/prune schedulers (audit +
// snapshot retention, push + CIBA pruners). Each is cancelled then waited on
// under the shared deadline; a missed deadline is logged but not fatal.
func shutdownSchedulers(ctx context.Context, a *app, logger spi.Logger) {
	// Stop the audit retention scheduler BEFORE draining the AsyncSink so an
	// in-flight Prune doesn't race the close (handled by the caller's ordering).
	stopScheduler(ctx, logger, a.auditRetentionCancel, a.auditRetentionDone,
		"audit retention scheduler did not exit cleanly")
	stopScheduler(ctx, logger, a.snapshotRetentionCancel, a.snapshotRetentionDone,
		"snapshot retention scheduler did not exit cleanly")
	stopScheduler(ctx, logger, a.drReplicationCancel, a.drReplicationDone,
		"dr snapshot replication scheduler did not exit cleanly")
	stopScheduler(ctx, logger, a.pushPruneCancel, a.pushPruneDone,
		"push approval pruner did not exit cleanly")
	stopScheduler(ctx, logger, a.cibaPruneCancel, a.cibaPruneDone,
		"ciba request pruner did not exit cleanly")
	stopScheduler(ctx, logger, a.refreshGracePruneCancel, a.refreshGracePruneDone,
		"refresh grace pruner did not exit cleanly")
	stopScheduler(ctx, logger, a.credentialSchedCancel, a.credentialSchedDone,
		"credential rotation scheduler did not exit cleanly")
	stopScheduler(ctx, logger, a.configDriftCancel, a.configDriftDone,
		"config drift detection loop did not exit cleanly")
	stopScheduler(ctx, logger, a.breakGlassCancel, a.breakGlassDone,
		"break-glass sweeper did not exit cleanly")
	stopScheduler(ctx, logger, a.continuousVerifyCancel, a.continuousVerifyDone,
		"continuous-verification agent did not exit cleanly")
}

// stopScheduler cancels a background scheduler and waits for its done channel
// under ctx, logging msg if the deadline fires first. No-op when cancel is nil.
func stopScheduler(ctx context.Context, logger spi.Logger, cancel context.CancelFunc, done <-chan struct{}, msg string) {
	if cancel == nil {
		return
	}
	cancel()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
		logger.Error(msg)
	}
}

// waitForStop blocks until stop closes or ctx expires. No-op when stop is nil.
func waitForStop(ctx context.Context, stop <-chan struct{}) {
	if stop == nil {
		return
	}
	select {
	case <-stop:
	case <-ctx.Done():
	}
}
