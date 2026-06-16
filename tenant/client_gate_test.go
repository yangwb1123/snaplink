package tenant

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/core"
)

// ctxWithResolved returns a HandlerContext carrying the given Resolved
// (nil leaves the context empty, simulating "no tenant middleware ran").
func ctxWithResolved(r *Resolved) core.HandlerContext {
	req := httptest.NewRequest(http.MethodGet, "http://acme.com/", nil)
	hctx := core.NewContext(httptest.NewRecorder(), req)
	if r != nil {
		hctx.Set(HandlerContextKey, r)
	}
	return hctx
}

func TestClientOK(t *testing.T) {
	t.Parallel()

	resolvedT1 := &Resolved{Tenant: &Tenant{ID: "t1"}, Domain: &Domain{Hostname: "acme.com"}}

	tests := []struct {
		name   string
		ctx    core.HandlerContext
		client *core.Client
		want   bool
	}{
		{
			name:   "nil client is allowed",
			ctx:    ctxWithResolved(resolvedT1),
			client: nil,
			want:   true,
		},
		{
			name:   "client without TenantID allowed under any tenant",
			ctx:    ctxWithResolved(resolvedT1),
			client: &core.Client{ID: "c1"},
			want:   true,
		},
		{
			name:   "no tenant resolved allows any client (pre-multi-tenant)",
			ctx:    ctxWithResolved(nil),
			client: &core.Client{ID: "c1", TenantID: "t1"},
			want:   true,
		},
		{
			name:   "matching tenant allowed",
			ctx:    ctxWithResolved(resolvedT1),
			client: &core.Client{ID: "c1", TenantID: "t1"},
			want:   true,
		},
		{
			name:   "mismatched tenant rejected",
			ctx:    ctxWithResolved(resolvedT1),
			client: &core.Client{ID: "c1", TenantID: "t2"},
			want:   false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClientOK(tc.ctx, tc.client); got != tc.want {
				t.Errorf("ClientOK() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientOK_ResolvedPresentButTenantNil(t *testing.T) {
	t.Parallel()
	// A Resolved with a nil Tenant (e.g. domain matched but tenant lookup
	// produced nothing) must be treated as "no tenant" → allow, never panic.
	ctx := ctxWithResolved(&Resolved{Tenant: nil, Domain: &Domain{Hostname: "acme.com"}})
	if !ClientOK(ctx, &core.Client{ID: "c1", TenantID: "t1"}) {
		t.Error("nil resolved tenant should allow the client")
	}
}

func TestClientOK_NilContext(t *testing.T) {
	t.Parallel()
	// FromHandlerContext guards nil; ClientOK must inherit that and allow
	// a tenant-bound client when no context exists at all.
	if !ClientOK(nil, &core.Client{ID: "c1", TenantID: "t1"}) {
		t.Error("nil ctx with tenant-bound client should be allowed (fail-open)")
	}
}

func TestClientOK_NilContextNilClient(t *testing.T) {
	t.Parallel()
	if !ClientOK(nil, nil) {
		t.Error("nil ctx + nil client should be allowed")
	}
}
