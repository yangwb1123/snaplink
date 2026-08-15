package grpcserver

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// healthPollInterval is the delay between readiness evaluations. Production
// value 5s — the cadence operators expect from a kubelet-style probe.
// (Package var rather than const only for symmetry with healthEvalTimeout;
// never mutated at runtime — tests inject their own cadence via
// registerObservability.)
var healthPollInterval = 5 * time.Second

// healthEvalTimeout is the aggregate deadline of one evaluation, mirroring
// handleReadyz's 3s bound. It bounds the verdict latency even when a ready
// check ignores its context and blocks forever.
var healthEvalTimeout = 3 * time.Second

// RegisterObservability registers grpc_health_v1.Health backed by the stock
// health.Server and grpc.reflection.v1.ServerReflection (the v1alpha alias is
// registered by reflection.Register for legacy clients) on s. Call it LAST,
// after every RegisterXxxServer call, so the first evaluation already sees
// the full service set.
//
// checks, when non-nil, is a function-value dependency: it returns the ready
// checks to poll (usually an SSO server's BuildHandlerDeps().ReadyChecks —
// the closure set that also feeds /readyz). nil, a nil map, an empty map, and
// nil entries inside a non-empty map all evaluate to SERVING, matching
// /readyz's handling of orphan WithReadyCheckTimeout entries (metadata, not
// checks). Evaluations run every healthPollInterval, immediately once at
// registration, with each check probed in its own goroutine under a single
// 3-second aggregate deadline; a check still in flight from a previous
// evaluation (a hung, context-ignoring closure) is not re-probed — it leaks
// at most one goroutine, produced its NOT_SERVING round when its deadline
// expired, and no longer vetoes later verdicts (a round in which NO probe
// completed keeps NOT_SERVING: no new information). Any failure, panic, or
// deadline expiry flips the overall status and every registered service name
// to NOT_SERVING; a fully green sweep flips them to SERVING. Failures and
// panics are logged at Error level (the spi.Logger has no Warn level;
// handleReadyz uses the same level for the same condition).
//
// The returned stop func cancels the poller and calls health.Server.Shutdown,
// which flips every service to NOT_SERVING and notifies Watch clients — call
// it BEFORE GracefulStop so load balancers drain the replica first. It is
// idempotent; calling it twice is a no-op. logger is optional (nil is safe).
func RegisterObservability(s *grpc.Server, checks func() map[string]func(context.Context) error, logger ...spi.Logger) (stop func()) {
	return registerObservability(s, checks, healthPollInterval, healthEvalTimeout, logger...)
}

// registerObservability is the injectable core of RegisterObservability:
// tests pass a short interval + evaluation deadline instead of mutating
// package state (which would race with a previous test's still-exiting
// poller goroutine).
func registerObservability(s *grpc.Server, checks func() map[string]func(context.Context) error, interval, timeout time.Duration, logger ...spi.Logger) (stop func()) {
	hs := health.NewServer()
	healthpb.RegisterHealthServer(s, hs)
	reflection.Register(s)

	var lg spi.Logger
	if len(logger) > 0 {
		lg = logger[0]
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &healthPoller{
		server:   s,
		health:   hs,
		checks:   checks,
		logger:   lg,
		done:     ctx.Done(),
		inFlight: make(map[string]struct{}),
		interval: interval,
		timeout:  timeout,
	}
	var once sync.Once
	go p.run()
	return func() {
		once.Do(func() {
			cancel()
			hs.Shutdown()
		})
	}
}

// healthPoller owns the single readiness-evaluation goroutine. All state is
// touched only by the poller goroutine except inFlight, which probe
// goroutines mutate under mu.
type healthPoller struct {
	server   *grpc.Server
	health   *health.Server
	checks   func() map[string]func(context.Context) error
	logger   spi.Logger
	done     <-chan struct{}
	interval time.Duration
	timeout  time.Duration
	mu       sync.Mutex
	inFlight map[string]struct{}
}

// run loops evaluations until the poller is cancelled.
func (p *healthPoller) run() {
	p.evaluate()
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			p.evaluate()
		case <-p.done:
			return
		}
	}
}

// evaluate runs one readiness sweep. Checks run concurrently, one goroutine
// each, under the aggregate deadline; the verdict is SERVING only when every
// probe completed in time and none failed. A ctx-ignoring hung check cannot
// wedge the poller: its first probe costs one deadline expiry (NOT_SERVING),
// later evaluations skip re-probing it (one leaked goroutine, no
// per-evaluation growth), and — per the QA-reviewed semantics — a skipped
// check no longer vetoes the verdict; only a round in which NO probe
// completed keeps NOT_SERVING (no new information).
func (p *healthPoller) evaluate() {
	if p.checks == nil {
		p.setStatus(healthpb.HealthCheckResponse_SERVING)
		return
	}
	checks := p.checks()
	if len(checks) == 0 {
		p.setStatus(healthpb.HealthCheckResponse_SERVING)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	launched, skipped, failures, finished := p.launchProbes(ctx, checks)
	timedOut, aborted := awaitProbes(ctx, finished, launched, p.done)
	if aborted {
		cancel()
		return
	}
	if timedOut || failures.Load() > 0 || (launched == 0 && skipped > 0) {
		p.setStatus(healthpb.HealthCheckResponse_NOT_SERVING)
		return
	}
	p.setStatus(healthpb.HealthCheckResponse_SERVING)
}

// launchProbes starts one probe goroutine per ready check, skipping nil and
// still-inflight entries. finished is buffered to the check count so a probe
// that outlives the deadline (or the stop) never blocks on its exit signal;
// the poller drains exactly `launched` signals and anything left in the
// buffer drains when the probe eventually returns.
func (p *healthPoller) launchProbes(ctx context.Context, checks map[string]func(context.Context) error) (launched, skipped int, failures *atomic.Int32, finished chan struct{}) {
	finished = make(chan struct{}, len(checks))
	failures = new(atomic.Int32)
	p.mu.Lock()
	for name, check := range checks {
		if check == nil {
			continue // /readyz parity: orphan timeout entries are metadata
		}
		if _, inflight := p.inFlight[name]; inflight {
			// Previous probe still running (hung ctx-ignoring closure): do
			// not pile up another goroutine. The check already produced its
			// NOT_SERVING round when its deadline expired.
			skipped++
			continue
		}
		p.inFlight[name] = struct{}{}
		launched++
		go p.probe(ctx, name, check, failures, finished)
	}
	p.mu.Unlock()
	return launched, skipped, failures, finished
}

// awaitProbes waits for every launched probe, returning (timedOut, aborted).
// A stop signal aborts the wait; a deadline expiry stops waiting and reports
// the verdict as NOT_SERVING.
func awaitProbes(ctx context.Context, finished <-chan struct{}, launched int, done <-chan struct{}) (timedOut, aborted bool) {
	for received := 0; received < launched; {
		select {
		case <-finished:
			received++
		case <-ctx.Done():
			return true, false // stop waiting; verdict is NOT_SERVING
		case <-done:
			return false, true
		}
	}
	return false, false
}

// probe runs one ready check. The exit signal (finished) is sent after the
// failure accounting so the poller can never observe "all finished, zero
// failures" before a panicking/failing probe recorded itself.
func (p *healthPoller) probe(ctx context.Context, name string, check func(context.Context) error, failures *atomic.Int32, finished chan<- struct{}) {
	defer func() { finished <- struct{}{} }()
	defer func() {
		p.mu.Lock()
		delete(p.inFlight, name)
		p.mu.Unlock()
		if r := recover(); r != nil {
			p.logFailure("grpc health check panicked", name, "panic", r)
			failures.Add(1)
		}
	}()
	if err := check(ctx); err != nil {
		p.logFailure("grpc health check failed", name, "error", err)
		failures.Add(1)
	}
}

// logFailure reports a failed/panicking ready check. Error level matches
// handleReadyz's `readyz check failed` line; the check NAME is the bounded
// operator-registered identifier, never request input.
func (p *healthPoller) logFailure(msg, name string, k string, v any) {
	if p.logger == nil {
		return
	}
	p.logger.Error(msg, "check", name, k, v)
}

// setStatus applies the verdict to the overall status ("") and every
// registered service name, so Check on any concrete service (and the
// empty-name overall probe) all agree. health.Server serializes
// SetServingStatus internally and ignores calls after Shutdown; the poller
// is the only writer, so consecutive evaluations cannot race.
func (p *healthPoller) setStatus(st healthpb.HealthCheckResponse_ServingStatus) {
	p.health.SetServingStatus("", st)
	for name := range p.server.GetServiceInfo() {
		p.health.SetServingStatus(name, st)
	}
}
