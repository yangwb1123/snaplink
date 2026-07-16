package grpcserver

import (
	"context"
	"runtime/debug"

	"github.com/snaplink/sso/shared/spi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryUnaryServerInterceptor returns a grpc.UnaryServerInterceptor that
// recovers a panic raised anywhere in the handler chain and turns it into a
// codes.Internal error instead of letting it escape.
//
// Unlike net/http's ServeMux, grpc-go's default handler dispatch installs NO
// panic recovery of its own: each RPC runs in its own goroutine, and an
// unrecovered panic in ANY goroutine crashes the entire process — taking
// down every OTHER in-flight RPC on every service registered on the same
// grpc.Server (admin, audit, netpolicy, authz, discovery), not just the one
// call that panicked. This package's handlers are intentionally thin
// wrappers that delegate straight into operator-injected interfaces
// (permissions.Provider, registry.Registry, audit.Recorder, netpolicy.Store,
// and every admin store in grpcadmin/) — exactly the seam a misbehaving or
// buggy backend implementation panics from (nil map write, index out of
// range, a bad type assertion). This interceptor is the choke point that
// must be wired on every grpc.Server this package's services are registered
// on (see cmd/sso-server's grpcServerOptions), mirroring the panic
// containment infrastructure/extauthz's Check already has for its single
// MeshAuthorizer call.
//
// The response never carries the panic value (oracle-safe, matches
// AGENTS.md's fail-closed default for an unexplained internal failure): the
// caller sees a bare "internal error" Internal status. logger is optional
// (nil is safe) and is the only place the recovered value + stack surface,
// so an operator can act on it instead of the crash going unexplained.
func RecoveryUnaryServerInterceptor(logger spi.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logPanic(logger, info.FullMethod, r)
				resp, err = nil, status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// RecoveryStreamServerInterceptor is the streaming-RPC counterpart of
// RecoveryUnaryServerInterceptor — see its doc for why this is required.
// Streaming handlers (DiscoveryService.Watch, AuditService.StreamEvents,
// PolicyService's watch RPC) run for the life of the stream and invoke the
// injected interface repeatedly, so the exposure window is wider than a
// single unary request/response.
func RecoveryStreamServerInterceptor(logger spi.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logPanic(logger, info.FullMethod, r)
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(srv, ss)
	}
}

// logPanic reports a recovered handler panic to the optional operator
// logger. Silent (not a crash, not a log line) when logger is nil, matching
// extauthz.safeMeshAuthorize's default — the fail-closed response on the
// wire never depends on logging succeeding.
func logPanic(logger spi.Logger, method string, r any) {
	if logger == nil {
		return
	}
	logger.Error("grpc handler panic recovered", "method", method, "panic", r, "stack", string(debug.Stack()))
}
