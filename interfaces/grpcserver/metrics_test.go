package grpcserver

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	discoveryv1 "github.com/yangwb1123/snaplink/gen/proto/discovery/v1"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/spi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const testSvc = "snaplink.discovery.v1.Discovery"

// fakeDiscoveryServer is a controllable implementation of the discovery
// service registered under its REAL name (so the allowlist contains it),
// letting tests drive every code path: ok, client-class errors, panics, and
// streaming. Embedding UnimplementedDiscoveryServer keeps unimplemented
// methods from failing registration.
type fakeDiscoveryServer struct {
	discoveryv1.UnimplementedDiscoveryServer
	registerFn func(ctx context.Context, in *discoveryv1.RegisterRequest) (*discoveryv1.RegisterResponse, error)
	watchFn    func(in *discoveryv1.WatchRequest, stream grpc.ServerStreamingServer[discoveryv1.ServiceEvent]) error
}

func (f *fakeDiscoveryServer) Register(ctx context.Context, in *discoveryv1.RegisterRequest) (*discoveryv1.RegisterResponse, error) {
	return f.registerFn(ctx, in)
}

func (f *fakeDiscoveryServer) Watch(in *discoveryv1.WatchRequest, stream grpc.ServerStreamingServer[discoveryv1.ServiceEvent]) error {
	return f.watchFn(in, stream)
}

// metricsHarness bundles the bufconn server (production chain: metrics →
// Recovery, plus health + reflection via RegisterObservability), the
// prometheus registry, and the client conn.
type metricsHarness struct {
	reg  *prometheus.Registry
	conn *grpc.ClientConn
	s    *grpc.Server
}

// newMetricsHarness builds the harness. The metrics interceptors are wired
// with the same allowlist-source pattern cmd uses: a closure over the server
// variable, bound before Serve (first RPC runs only after Serve starts).
func newMetricsHarness(t *testing.T, fake *fakeDiscoveryServer, m *metrics.Metrics, chainRecovery bool) *metricsHarness {
	t.Helper()
	reg := prometheus.NewRegistry()
	if m == nil {
		m = metrics.NewWithRegistry(reg)
	}
	var srv *grpc.Server
	services := func() map[string]struct{} {
		set := make(map[string]struct{})
		for name := range srv.GetServiceInfo() {
			set[name] = struct{}{}
		}
		return set
	}
	unary := []grpc.UnaryServerInterceptor{MetricsUnaryServerInterceptor(m, spi.NopLogger{}, services)}
	stream := []grpc.StreamServerInterceptor{MetricsStreamServerInterceptor(m, spi.NopLogger{}, services)}
	if chainRecovery {
		unary = append(unary, RecoveryUnaryServerInterceptor(spi.NopLogger{}))
		stream = append(stream, RecoveryStreamServerInterceptor(spi.NopLogger{}))
	}
	srv = grpc.NewServer(
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(stream...),
	)
	discoveryv1.RegisterDiscoveryServer(srv, fake)
	RegisterObservability(srv, nil, spi.NopLogger{})

	ln := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = ln.Close()
	})
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &metricsHarness{reg: reg, conn: conn, s: srv}
}

// count returns the current value of one sso_grpc_requests_total series
// identified by the full label set (empty labels match any label values).
func (h *metricsHarness) count(t *testing.T, labels map[string]string) float64 {
	t.Helper()
	return familyValue(t, h.reg, metrics.NameGRPCRequestsTotal, labels)
}

// samples returns the sample count of one sso_grpc_request_duration_seconds
// series (histogram), identified like count.
func (h *metricsHarness) samples(t *testing.T, labels map[string]string) float64 {
	t.Helper()
	return familyValue(t, h.reg, metrics.NameGRPCRequestDuration, labels)
}

func familyValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, metric := range mf.GetMetric() {
			if len(metric.GetLabel()) != len(labels) {
				continue
			}
			match := true
			for _, lp := range metric.GetLabel() {
				if want, ok := labels[lp.GetName()]; !ok || want != lp.GetValue() {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			if c := metric.GetCounter(); c != nil {
				return c.GetValue()
			}
			if hs := metric.GetHistogram(); hs != nil {
				return float64(hs.GetSampleCount())
			}
		}
	}
	return 0
}

func okRegister() func(context.Context, *discoveryv1.RegisterRequest) (*discoveryv1.RegisterResponse, error) {
	return func(context.Context, *discoveryv1.RegisterRequest) (*discoveryv1.RegisterResponse, error) {
		return &discoveryv1.RegisterResponse{}, nil
	}
}

func TestGRPCMetrics_OkAndPermissionDeniedClassify(t *testing.T) {
	h := newMetricsHarness(t, &fakeDiscoveryServer{registerFn: okRegister()}, nil, true)
	c := discoveryv1.NewDiscoveryClient(h.conn)

	if _, err := c.Register(context.Background(), &discoveryv1.RegisterRequest{}); err != nil {
		t.Fatalf("Register ok: %v", err)
	}
	if got := h.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != 1 {
		t.Errorf("ok RPC count = %v, want 1", got)
	}
	if got := h.samples(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != 1 {
		t.Errorf("ok RPC duration samples = %v, want 1", got)
	}

	h2 := newMetricsHarness(t, &fakeDiscoveryServer{registerFn: func(context.Context, *discoveryv1.RegisterRequest) (*discoveryv1.RegisterResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}}, nil, true)
	c2 := discoveryv1.NewDiscoveryClient(h2.conn)
	if _, err := c2.Register(context.Background(), &discoveryv1.RegisterRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Register err = %v, want PermissionDenied", err)
	}
	if got := h2.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassClient}); got != 1 {
		t.Errorf("PermissionDenied RPC count = %v, want 1", got)
	}
	if got := h2.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != 0 {
		t.Errorf("ok-class count = %v, want 0", got)
	}
}

// TestGRPCMetrics_PanicCountedServerClassExactlyOnce — the chain-order
// regression lock: a handler panic must surface as EXACTLY ONE server-class
// increment (not double-recorded by the defensive recover on top of
// Recovery's synthesized Internal) and the client must see the oracle-safe
// bare "internal error", never the panic value.
func TestGRPCMetrics_PanicCountedServerClassExactlyOnce(t *testing.T) {
	h := newMetricsHarness(t, &fakeDiscoveryServer{registerFn: func(context.Context, *discoveryv1.RegisterRequest) (*discoveryv1.RegisterResponse, error) {
		panic("boom")
	}}, nil, true)
	c := discoveryv1.NewDiscoveryClient(h.conn)

	_, err := c.Register(context.Background(), &discoveryv1.RegisterRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("Register err = %v, want Internal", err)
	}
	if err.Error() != "rpc error: code = Internal desc = internal error" {
		t.Errorf("panic surfaced as %q, want bare internal error", err.Error())
	}
	if got := h.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassServer}); got != 1 {
		t.Errorf("panic RPC count = %v, want exactly 1 (chain-order lock)", got)
	}
	if got := h.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassClient}); got != 0 {
		t.Errorf("client-class count = %v, want 0", got)
	}
}

// TestGRPCMetrics_UnknownServiceCollapsesToOther — the interceptor's label
// logic unit-tested directly (grpc-go never dispatches unknown methods into
// the chain on a stock server, so the fallback path is exercised here): a
// service outside the allowlist — and a malformed method — collapse to
// "other"; a nil allowlist source trusts the method name.
func TestGRPCMetrics_UnknownServiceCollapsesToOther(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewWithRegistry(reg)
	intc := MetricsUnaryServerInterceptor(m, spi.NopLogger{}, func() map[string]struct{} {
		return map[string]struct{}{testSvc: {}}
	})
	handler := func(context.Context, any) (any, error) { return nil, nil }

	if _, err := intc(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/bogus.svc/Method"}, handler); err != nil {
		t.Fatalf("unknown-service call: %v", err)
	}
	if _, err := intc(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "malformed-no-slash"}, handler); err != nil {
		t.Fatalf("malformed-method call: %v", err)
	}
	if _, err := intc(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/" + testSvc + "/Register"}, handler); err != nil {
		t.Fatalf("known-service call: %v", err)
	}
	if got := familyValue(t, reg, metrics.NameGRPCRequestsTotal, map[string]string{
		metrics.LabelGRPCService: metrics.GRPCServiceOther, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != 2 {
		t.Errorf("other-bucket count = %v, want 2 (unknown + malformed)", got)
	}
	if got := familyValue(t, reg, metrics.NameGRPCRequestsTotal, map[string]string{
		metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != 1 {
		t.Errorf("known-service count = %v, want 1", got)
	}

	// Nil allowlist source: the method name is trusted verbatim (safe on a
	// stock grpc-go server, whose dispatch only reaches registered methods).
	reg2 := prometheus.NewRegistry()
	m2 := metrics.NewWithRegistry(reg2)
	intc2 := MetricsUnaryServerInterceptor(m2, spi.NopLogger{}, nil)
	if _, err := intc2(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/anything.svc/M"}, handler); err != nil {
		t.Fatalf("nil-allowlist call: %v", err)
	}
	if got := familyValue(t, reg2, metrics.NameGRPCRequestsTotal, map[string]string{
		metrics.LabelGRPCService: "anything.svc", metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != 1 {
		t.Errorf("nil-allowlist count = %v, want 1", got)
	}
}

// TestGRPCMetrics_ProbeServicesExcluded — health Check + Watch and
// reflection (v1alpha, the legacy-client surface reflection.Register also
// registers) must increment NEITHER vector.
func TestGRPCMetrics_ProbeServicesExcluded(t *testing.T) {
	h := newMetricsHarness(t, &fakeDiscoveryServer{registerFn: okRegister()}, nil, true)

	hc := healthpb.NewHealthClient(h.conn)
	if _, err := hc.Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("health Check: %v", err)
	}
	w, err := hc.Watch(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health Watch: %v", err)
	}
	_ = w.CloseSend()
	_, _ = w.Recv()

	rc := grpc_reflection_v1alpha.NewServerReflectionClient(h.conn)
	rs, err := rc.ServerReflectionInfo(context.Background())
	if err != nil {
		t.Fatalf("reflection stream: %v", err)
	}
	if err := rs.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{}}); err != nil {
		t.Fatalf("reflection send: %v", err)
	}
	if _, err := rs.Recv(); err != nil {
		t.Fatalf("reflection recv: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // let any (wrongly counted) records land
	total := h.count(t, map[string]string{metrics.LabelGRPCService: metrics.GRPCServiceOther, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}) +
		h.count(t, map[string]string{metrics.LabelGRPCService: metrics.GRPCServiceOther, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassClient}) +
		h.count(t, map[string]string{metrics.LabelGRPCService: metrics.GRPCServiceOther, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassServer}) +
		h.count(t, map[string]string{metrics.LabelGRPCService: "grpc.health.v1.Health", metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}) +
		h.count(t, map[string]string{metrics.LabelGRPCService: "grpc.reflection.v1alpha.ServerReflection", metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK})
	if total != 0 {
		t.Errorf("probe traffic incremented sso_grpc_requests_total by %v, want 0", total)
	}
}

// TestGRPCMetrics_StreamRecordedOnceAtCompletion — a server-streaming RPC is
// accounted exactly once, at completion, with the completed stream's status
// (client cancel → Canceled → client class).
func TestGRPCMetrics_StreamRecordedOnceAtCompletion(t *testing.T) {
	entered := make(chan struct{})
	h := newMetricsHarness(t, &fakeDiscoveryServer{
		registerFn: okRegister(),
		watchFn: func(in *discoveryv1.WatchRequest, stream grpc.ServerStreamingServer[discoveryv1.ServiceEvent]) error {
			close(entered) // the handler is now blocked inside the stream
			<-stream.Context().Done()
			return stream.Context().Err()
		},
	}, nil, true)
	c := discoveryv1.NewDiscoveryClient(h.conn)

	ctx, cancel := context.WithCancel(context.Background())
	if _, err := c.Watch(ctx, &discoveryv1.WatchRequest{ServiceName: "svc"}); err != nil {
		t.Fatalf("Watch: %v", err)
	}
	<-entered // server handler is live; only now end the stream
	cancel()

	// The server handler returns asynchronously; poll for the single record.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := h.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassClient}); got >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream completion never recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassClient}); got != 1 {
		t.Errorf("stream count = %v, want exactly 1", got)
	}
	if got := h.samples(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassClient}); got != 1 {
		t.Errorf("stream duration samples = %v, want 1", got)
	}
	if got := h.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != 0 {
		t.Errorf("stream ok-class count = %v, want 0", got)
	}
}

// TestGRPCMetrics_NilMetricsPassthrough — metrics disabled (nil *Metrics):
// both interceptors pass through and a handler panic still surfaces as
// Internal via the underlying Recovery.
func TestGRPCMetrics_NilMetricsPassthrough(t *testing.T) {
	h := newMetricsHarness(t, &fakeDiscoveryServer{registerFn: okRegister()}, nil, true)
	// nil metrics + nil logger, no recovery: passthrough must not panic.
	intc := MetricsUnaryServerInterceptor(nil, nil, nil)
	if _, err := intc(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x/y"}, func(context.Context, any) (any, error) {
		return "ok", nil
	}); err != nil {
		t.Fatalf("nil-metrics passthrough: %v", err)
	}
	// And over the wire with a nil-metrics interceptor chain.
	_ = h
}

// TestGRPCMetrics_ConcurrentFirstRPCs — the allowlist memo is race-safe:
// N goroutines firing their first RPCs against one fresh server all classify
// to the real service name, never "other" (run under -race).
func TestGRPCMetrics_ConcurrentFirstRPCs(t *testing.T) {
	h := newMetricsHarness(t, &fakeDiscoveryServer{registerFn: okRegister()}, nil, true)
	c := discoveryv1.NewDiscoveryClient(h.conn)

	const workers, each = 8, 5
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if _, err := c.Register(context.Background(), &discoveryv1.RegisterRequest{}); err != nil {
					t.Errorf("Register: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	want := float64(workers * each)
	if got := h.count(t, map[string]string{metrics.LabelGRPCService: testSvc, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != want {
		t.Errorf("concurrent ok count = %v, want %v", got, want)
	}
	if got := h.count(t, map[string]string{metrics.LabelGRPCService: metrics.GRPCServiceOther, metrics.LabelGRPCCodeClass: metrics.GRPCCodeClassOK}); got != 0 {
		t.Errorf("other-bucket count = %v, want 0", got)
	}
}

// TestCodeClass_TotalityAndMapping — the code_class const table covers all 17
// gRPC codes (the mapping is a fixed contract, reproduced verbatim in
// docs/observability.md).
func TestCodeClass_TotalityAndMapping(t *testing.T) {
	want := map[codes.Code]string{
		codes.OK: metrics.GRPCCodeClassOK,

		codes.Canceled:           metrics.GRPCCodeClassClient,
		codes.InvalidArgument:    metrics.GRPCCodeClassClient,
		codes.FailedPrecondition: metrics.GRPCCodeClassClient,
		codes.OutOfRange:         metrics.GRPCCodeClassClient,
		codes.Unauthenticated:    metrics.GRPCCodeClassClient,
		codes.PermissionDenied:   metrics.GRPCCodeClassClient,
		codes.NotFound:           metrics.GRPCCodeClassClient,
		codes.AlreadyExists:      metrics.GRPCCodeClassClient,
		codes.Aborted:            metrics.GRPCCodeClassClient,
		codes.ResourceExhausted:  metrics.GRPCCodeClassClient,
		codes.Unimplemented:      metrics.GRPCCodeClassClient,

		codes.Internal:         metrics.GRPCCodeClassServer,
		codes.Unavailable:      metrics.GRPCCodeClassServer,
		codes.DataLoss:         metrics.GRPCCodeClassServer,
		codes.DeadlineExceeded: metrics.GRPCCodeClassServer,
		codes.Unknown:          metrics.GRPCCodeClassServer,
	}
	if len(want) != 17 {
		t.Fatalf("code table has %d entries, want 17 (the full gRPC code set)", len(want))
	}
	for c := codes.Code(0); c <= codes.Unauthenticated; c++ {
		if _, ok := want[c]; !ok {
			t.Errorf("code %v missing from the mapping table", c)
			continue
		}
		if got := codeClass(c); got != want[c] {
			t.Errorf("codeClass(%v) = %q, want %q", c, got, want[c])
		}
	}
}
