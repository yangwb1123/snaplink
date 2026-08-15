package grpcserver

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/spi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcProbeServicePrefixes are the services excluded from BOTH metric
// vectors. Load-balancer health probes and reflection enumeration fire every
// few seconds per replica and would otherwise dominate every dashboard. The
// prefix match covers grpc.health.v1 and both reflection services
// (grpc.reflection.v1 + grpc.reflection.v1alpha — reflection.Register
// registers the v1alpha alias for legacy grpcurl/grpcreflect clients).
// Fixed + documented in docs/observability.md, same bounded-set philosophy as
// sanitizeMethod.
var grpcProbeServicePrefixes = []string{"grpc.health.", "grpc.reflection."}

// codeClass maps a gRPC status code onto a bounded three-value dimension
// mirroring the HTTP status_class spirit: ok | client | server. The mapping
// is a fixed contract — reproduced verbatim in docs/observability.md, never
// derived from anything dynamic:
//
//	client: InvalidArgument, FailedPrecondition, OutOfRange, Unauthenticated,
//	        PermissionDenied, NotFound, AlreadyExists, Aborted,
//	        ResourceExhausted, Canceled, Unimplemented
//	server: Internal, Unavailable, DataLoss, DeadlineExceeded, Unknown
//
// Every one of the 17 gRPC codes maps to a named class (the totality is
// test-locked); the default arm only exists for future/custom extension
// codes and collapses them to server (fail-closed classification).
func codeClass(c codes.Code) string {
	switch c {
	case codes.OK:
		return metrics.GRPCCodeClassOK
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange,
		codes.Unauthenticated, codes.PermissionDenied, codes.NotFound,
		codes.AlreadyExists, codes.Aborted, codes.ResourceExhausted,
		codes.Canceled, codes.Unimplemented:
		return metrics.GRPCCodeClassClient
	case codes.Internal, codes.Unavailable, codes.DataLoss,
		codes.DeadlineExceeded, codes.Unknown:
		return metrics.GRPCCodeClassServer
	default:
		return metrics.GRPCCodeClassServer
	}
}

// grpcServiceAllowlist is the lazily memoized registered-service set for one
// grpc.Server, sourced from a function value (the caller's server, bound
// after construction — grpc builds interceptors before the *grpc.Server
// exists). The source is called at most once, at the first RPC; grpc forbids
// registration after Serve starts, so that snapshot is final. sync.Once
// makes the memo race-safe across concurrent first RPCs. A nil source, or a
// nil/empty snapshot, means "no allowlist": the service name is then taken
// from the full method verbatim — safe on a stock grpc-go server, which
// dispatches ONLY registered methods into the interceptor chain (unknown
// methods are rejected in handleStream before the chain runs; the one
// exception is grpc.UnknownServiceHandler, whose traffic the allowlist
// collapses to "other").
type grpcServiceAllowlist struct {
	mux  sync.Mutex
	set  map[string]struct{}
	src  func() map[string]struct{}
	read bool
}

// contains reports whether service is in the memoized allowlist (or the
// allowlist is unavailable, in which case every name is trusted).
func (w *grpcServiceAllowlist) contains(service string) bool {
	w.mux.Lock()
	defer w.mux.Unlock()
	if !w.read && w.src != nil {
		w.set = w.src()
		w.read = true
	}
	if w.set == nil {
		return true
	}
	_, ok := w.set[service]
	return ok
}

// metricsInterceptor records one count + one duration observation per
// completed RPC. Nil-safe: a nil *metrics.Metrics makes both interceptors
// passthroughs (metrics disabled). Both wrap their body in a defensive
// recover — a panic inside the observability layer itself (never from a
// handler: Recovery beneath converts those to codes.Internal first) is
// converted to a bare codes.Internal and recorded as code_class=server, so
// the process survives instead of crashing every in-flight RPC.
type metricsInterceptor struct {
	m         *metrics.Metrics
	logger    spi.Logger
	allowlist grpcServiceAllowlist
}

// MetricsUnaryServerInterceptor returns a grpc.UnaryServerInterceptor that
// records request count + latency per RPC. Health and reflection RPCs are
// excluded; the grpc_service label is the service prefix of the full method,
// kept only when the memoized allowlist (services, see grpcServiceAllowlist)
// contains it — otherwise "other"; code_class is the fixed ok|client|server
// table. Wire it OUTSIDE Recovery so a panic Recovery synthesizes into
// codes.Internal is still observed as server-class.
func MetricsUnaryServerInterceptor(m *metrics.Metrics, logger spi.Logger, services func() map[string]struct{}) grpc.UnaryServerInterceptor {
	i := &metricsInterceptor{m: m, logger: logger}
	i.allowlist.src = services
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if m == nil {
			return handler(ctx, req)
		}
		start := time.Now()
		defer func() {
			if r := recover(); r != nil {
				logPanic(logger, info.FullMethod, r)
				resp, err = nil, status.Error(codes.Internal, "internal error")
				i.record(info.FullMethod, err, time.Since(start))
			}
		}()
		resp, err = handler(ctx, req)
		i.record(info.FullMethod, err, time.Since(start))
		return resp, err
	}
}

// MetricsStreamServerInterceptor is the streaming-RPC counterpart. A stream
// is accounted exactly once, at completion (status from the completed
// stream), so Watch-style long-lived streams are one count + one duration,
// not one per message.
func MetricsStreamServerInterceptor(m *metrics.Metrics, logger spi.Logger, services func() map[string]struct{}) grpc.StreamServerInterceptor {
	i := &metricsInterceptor{m: m, logger: logger}
	i.allowlist.src = services
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		if m == nil {
			return handler(srv, ss)
		}
		start := time.Now()
		defer func() {
			if r := recover(); r != nil {
				logPanic(logger, info.FullMethod, r)
				err = status.Error(codes.Internal, "internal error")
				i.record(info.FullMethod, err, time.Since(start))
			}
		}()
		err = handler(srv, ss)
		i.record(info.FullMethod, err, time.Since(start))
		return err
	}
}

// record emits one count + one duration for a completed RPC. Probe services
// are excluded before the allowlist lookup so their traffic never even
// touches the label machinery.
func (i *metricsInterceptor) record(fullMethod string, err error, dur time.Duration) {
	if i.m.GRPCRequestsTotal == nil || i.m.GRPCRequestDuration == nil {
		return
	}
	// Normalize away the leading '/' (fullMethod is "/pkg.Service/Method")
	// once, so the probe prefixes, the service name, and the allowlist keys
	// all compare without it.
	method := strings.TrimPrefix(fullMethod, "/")
	if isGRPCProbeMethod(method) {
		return
	}
	service := grpcServiceName(method)
	if !i.allowlist.contains(service) {
		service = metrics.GRPCServiceOther
	}
	class := codeClass(rpcCode(err))
	i.m.GRPCRequestsTotal.WithLabelValues(service, class).Inc()
	i.m.GRPCRequestDuration.WithLabelValues(service, class).Observe(dur.Seconds())
}

// rpcCode extracts the gRPC code from a completed RPC the same way grpc-go
// converts it on the wire: a status error keeps its code, a bare context
// error (stream handlers commonly return one) classifies
// Canceled/DeadlineExceeded instead of Unknown, and any other non-status
// error maps to Unknown. Matching the wire conversion keeps the code_class
// label consistent with what the client saw.
func rpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return status.FromContextError(err).Code()
}

// isGRPCProbeMethod reports whether the slash-normalized method belongs to a
// probe service (health + reflection, v1 and v1alpha) excluded from the
// metric vectors.
func isGRPCProbeMethod(method string) bool {
	for _, prefix := range grpcProbeServicePrefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}

// grpcServiceName extracts the service name from a slash-normalized method
// ("pkg.Service/Method" -> "pkg.Service"). A malformed method (no '/') returns
// "other"; the allowlist membership check in record() decides the final
// label.
func grpcServiceName(method string) string {
	slash := strings.LastIndexByte(method, '/')
	if slash <= 0 {
		return metrics.GRPCServiceOther
	}
	return method[:slash]
}
