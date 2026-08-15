package grpcserver

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	discoveryv1 "github.com/yangwb1123/snaplink/gen/proto/discovery/v1"
	"github.com/yangwb1123/snaplink/platform/registry/memory"
	"github.com/yangwb1123/snaplink/shared/spi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// obsHarness bundles a bufconn gRPC server with observability registered
// (pattern of test/admin_grpc_base_test.go) and the health client.
type obsHarness struct {
	hc   healthpb.HealthClient
	s    *grpc.Server
	ln   *bufconn.Listener
	stop func() // RegisterObservability's stop func
}

// newObsHarness starts a bufconn server registering one real service
// (discovery, so GetServiceInfo is non-empty) plus health + reflection via
// RegisterObservability. checks may be nil. The returned harness is torn
// down by t.Cleanup (stop observability first, then the server).
func newObsHarness(t *testing.T, checks func() map[string]func(context.Context) error) *obsHarness {
	t.Helper()
	ln := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	discoveryv1.RegisterDiscoveryServer(s, NewDiscoveryService(memory.New()))
	// Fast cadence via the injectable core — never mutate the package vars,
	// which would race with a previous test's still-exiting poller.
	stop := registerObservability(s, checks, harnessInterval, harnessTimeout, spi.NopLogger{})
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() {
		stop()
		s.Stop()
		_ = ln.Close()
	})

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &obsHarness{hc: healthpb.NewHealthClient(conn), s: s, ln: ln, stop: stop}
}

// harnessInterval + harnessTimeout are the fast cadence the harness injects
// into registerObservability (never the package vars — mutating those would
// race with a previous test's still-exiting poller). The few assertions that
// reason about poll-window arithmetic use them.
const (
	harnessInterval = 10 * time.Millisecond
	harnessTimeout  = 50 * time.Millisecond
)

// waitStatus polls Check("") until it returns want (or fails the test).
func waitStatus(t *testing.T, hc healthpb.HealthClient, want healthpb.HealthCheckResponse_ServingStatus) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := hc.Check(context.Background(), &healthpb.HealthCheckRequest{})
		if err == nil && resp.Status == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("overall health status never became %v", want)
}

// nextStatus receives one Watch message within timeout (fails the test on
// timeout or stream error).
func nextStatus(t *testing.T, w healthpb.Health_WatchClient, timeout time.Duration) healthpb.HealthCheckResponse_ServingStatus {
	t.Helper()
	ch := make(chan healthpb.HealthCheckResponse_ServingStatus, 1)
	go func() {
		resp, err := w.Recv()
		if err != nil {
			ch <- healthpb.HealthCheckResponse_UNKNOWN
			return
		}
		ch <- resp.Status
	}()
	select {
	case st := <-ch:
		return st
	case <-time.After(timeout):
		t.Fatal("timed out waiting for Watch status")
		return healthpb.HealthCheckResponse_UNKNOWN
	}
}

func okCheck() func(context.Context) error { return func(context.Context) error { return nil } }

func TestRegisterObservability_ServingWhenAllChecksPass(t *testing.T) {
	h := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{"db": okCheck()}
	})
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)

	// Protocol conformance: a registered concrete service carries the same
	// verdict; an unknown service is NOT_FOUND, never SERVING. The poller's
	// service-name sweep can land a tick after the overall watch fires, so
	// poll briefly before declaring failure.
	var resp *healthpb.HealthCheckResponse
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err = h.hc.Check(context.Background(), &healthpb.HealthCheckRequest{Service: "snaplink.discovery.v1.Discovery"})
		if err == nil && resp.Status == healthpb.HealthCheckResponse_SERVING {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Check(registered service) never SERVING: err=%v status=%v", err, resp.GetStatus())
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err = h.hc.Check(context.Background(), &healthpb.HealthCheckRequest{Service: "no.such.Service"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("Check(unknown service) err = %v, want NotFound", err)
	}
}

func TestRegisterObservability_NotServingOnFailureAndRecovery(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	h := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{
			"store": func(context.Context) error {
				if healthy.Load() {
					return nil
				}
				return errors.New("store unreachable")
			},
		}
	})
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)

	healthy.Store(false)
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_NOT_SERVING)

	healthy.Store(true)
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)
}

func TestRegisterObservability_NilEmptyChecksServe(t *testing.T) {
	for name, checks := range map[string]func() map[string]func(context.Context) error{
		"nil fn":    nil,
		"nil map":   func() map[string]func(context.Context) error { return nil },
		"empty map": func() map[string]func(context.Context) error { return map[string]func(context.Context) error{} },
	} {
		t.Run(name, func(t *testing.T) {
			h := newObsHarness(t, checks)
			waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)
		})
	}
}

// TestRegisterObservability_NilCheckFuncsSkipped — orphan
// WithReadyCheckTimeout entries surface as nil funcs in the ReadyChecks map
// (accessors_handlers.go copies rc.Check verbatim). /readyz skips them; the
// gRPC poller must too — invoking a nil func would panic and (with a naive
// recover) flip a healthy node to permanent NOT_SERVING while /readyz says
// 200 (QA F3).
func TestRegisterObservability_NilCheckFuncsSkipped(t *testing.T) {
	h := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{
			"orphan-timeout": nil, // WithReadyCheckTimeout pre-registration
			"healthy":        okCheck(),
		}
	})
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)

	// A map containing ONLY nil entries also serves (mirrors /readyz's
	// empty-after-skip 200).
	h2 := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{"orphan-timeout": nil}
	})
	waitStatus(t, h2.hc, healthpb.HealthCheckResponse_SERVING)
}

// TestRegisterObservability_PanickingCheckSurvives — a panicking check must
// produce NOT_SERVING without killing the poller; the next evaluation (now
// healthy) flips back to SERVING (QA F10).
func TestRegisterObservability_PanickingCheckSurvives(t *testing.T) {
	var panicCheck atomic.Bool
	panicCheck.Store(true)
	h := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{
			"panicky": func(context.Context) error {
				if panicCheck.Load() {
					panic("boom")
				}
				return nil
			},
		}
	})
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_NOT_SERVING)

	panicCheck.Store(false)
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)
}

// TestRegisterObservability_WatchStreamsTransitions — Watch("") streams the
// initial status then exactly one message per status CHANGE (grpc's
// health.Server dedupes identical SetServingStatus calls), ending at
// SERVING with no 4th message (QA F10 dedupe pin).
func TestRegisterObservability_WatchStreamsTransitions(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	h := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{
			"store": func(context.Context) error {
				if healthy.Load() {
					return nil
				}
				return errors.New("down")
			},
		}
	})
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)

	w, err := h.hc.Watch(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if st := nextStatus(t, w, time.Second); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("initial Watch status = %v, want SERVING", st)
	}
	healthy.Store(false)
	if st := nextStatus(t, w, time.Second); st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("Watch after failure = %v, want NOT_SERVING", st)
	}
	healthy.Store(true)
	if st := nextStatus(t, w, time.Second); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("Watch after recovery = %v, want SERVING", st)
	}
	// No 4th message: consecutive identical statuses are deduped.
	select {
	case st := <-recvAsync(w):
		t.Fatalf("unexpected 4th Watch message %v (dedupe broken)", st)
	case <-time.After(200 * time.Millisecond):
	}
}

// recvAsync wraps one blocking Recv in a goroutine so the caller can select
// on it with a timeout.
func recvAsync(w healthpb.Health_WatchClient) <-chan healthpb.HealthCheckResponse_ServingStatus {
	ch := make(chan healthpb.HealthCheckResponse_ServingStatus, 1)
	go func() {
		resp, err := w.Recv()
		if err != nil {
			ch <- healthpb.HealthCheckResponse_UNKNOWN
			return
		}
		ch <- resp.Status
	}()
	return ch
}

// TestRegisterObservability_StopFlipsToNotServingAndIsIdempotent — stop()
// cancels the poller and flips every service to NOT_SERVING (the draining
// signal Watch clients rely on before GracefulStop); a second stop is a
// no-op; post-stop evaluations never resurrect SERVING (health.Server
// ignores SetServingStatus after Shutdown).
func TestRegisterObservability_StopFlipsToNotServingAndIsIdempotent(t *testing.T) {
	h := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{"db": okCheck()}
	})
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)

	w, err := h.hc.Watch(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if st := nextStatus(t, w, time.Second); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("initial Watch status = %v, want SERVING", st)
	}
	stop := h.stop
	stop()
	if st := nextStatus(t, w, time.Second); st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("Watch after stop = %v, want NOT_SERVING", st)
	}
	stop() // idempotent: second call must not panic
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_NOT_SERVING)
	time.Sleep(3 * harnessInterval) // poller is cancelled: status must not flip back
	resp, err := h.hc.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil || resp.Status != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("status after stop + poll window = %v (%v), want NOT_SERVING", resp.GetStatus(), err)
	}
}

// TestRegisterObservability_StopBeforeFirstEvaluation — QA F9: stop()
// immediately after registration (before the first evaluation completes)
// must not panic, must leave a consistent NOT_SERVING state, and must not
// leak the poller goroutine (cancelled before its first tick).
func TestRegisterObservability_StopBeforeFirstEvaluation(t *testing.T) {
	h := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{"db": okCheck()}
	})
	h.stop()
	before := runtime.NumGoroutine()
	time.Sleep(3 * harnessInterval)
	after := runtime.NumGoroutine()
	if leaked := after - before; leaked > 1 {
		t.Errorf("goroutine growth after early stop = %d, want ≤ 1", leaked)
	}
	resp, err := h.hc.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil || resp.Status != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("status after early stop = %v (%v), want NOT_SERVING", resp.GetStatus(), err)
	}
}

// TestRegisterObservability_HungCheckCannotWedgePoller — QA F1, the High
// finding: a ctx-ignoring check blocks forever. The verdict must still land
// NOT_SERVING within the aggregate bound, the flapper's recovery must still
// be observed (SERVING within 2 poll intervals while the hanger stays
// blocked), and goroutine growth stays bounded at one per hung check.
func TestRegisterObservability_HungCheckCannotWedgePoller(t *testing.T) {
	block := make(chan struct{})
	var flapper atomic.Bool
	flapper.Store(false)
	h := newObsHarness(t, func() map[string]func(context.Context) error {
		return map[string]func(context.Context) error{
			"hanger": func(context.Context) error {
				<-block // never reads ctx — the pathological case
				return nil
			},
			"flapper": func(context.Context) error {
				if flapper.Load() {
					return nil
				}
				return errors.New("flap")
			},
		}
	})

	// Bounded verdict latency with the hanger blocked: the first round ends
	// at the aggregate deadline, NOT_SERVING.
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_NOT_SERVING)

	// The flapper recovers while the hanger stays blocked: SERVING arrives
	// within 2 poll intervals (skipped in-flight checks do not veto).
	flapper.Store(true)
	waitStatus(t, h.hc, healthpb.HealthCheckResponse_SERVING)

	// Goroutine growth bounded: with the hanger permanently blocked, run ≥3
	// more evaluations and assert no per-evaluation leak.
	before := runtime.NumGoroutine()
	time.Sleep(6 * harnessInterval)
	after := runtime.NumGoroutine()
	if leaked := after - before; leaked > 2 {
		t.Errorf("goroutine growth with hung check = %d, want ≤ 2 (one hung probe)", leaked)
	}
}
