package grpcadmin

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// requireCode fails the test unless err carries the expected gRPC status
// code. Centralized so every service test file asserts errors the same way
// (status.FromError under the hood, per the task's white-box-unit style).
func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected a gRPC status error carrying %v, got non-status error: %v", want, err)
	}
	if st.Code() != want {
		t.Fatalf("expected code %v, got %v (err=%v)", want, st.Code(), err)
	}
}

// requireOK fails the test on any non-nil error, printing msg for context.
func requireOK(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}
