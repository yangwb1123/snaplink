package region

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

var errTestRegion = errors.New("region: test error")

type staticResolver struct {
	id  ID
	err error
}

func (r *staticResolver) Resolve(req *http.Request) (ID, error) {
	return r.id, r.err
}

func TestMiddlewareSetsRegion(t *testing.T) {
	resolver := &staticResolver{id: ID("us-east-1")}
	mw := Middleware(resolver, MiddlewareOptions{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	ctx := core.NewContext(rec, req)

	mw(ctx)
	id, ok := FromHandlerContext(ctx)
	if !ok {
		t.Error("expected region in context")
	}
	if id != "us-east-1" {
		t.Errorf("expected 'us-east-1', got %q", id)
	}
}

func TestMiddlewareMissingRegion(t *testing.T) {
	resolver := &staticResolver{err: errTestRegion}
	mw := Middleware(resolver, MiddlewareOptions{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	ctx := core.NewContext(rec, req)

	mw(ctx)
	id, ok := FromHandlerContext(ctx)
	if !ok {
		t.Fatal("expected region context (empty = unconstrained)")
	}
	if id != "" {
		t.Errorf("expected empty region on resolver error, got %q", id)
	}
}

func TestFromHandlerContextEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	ctx := core.NewContext(rec, req)

	_, ok := FromHandlerContext(ctx)
	if ok {
		t.Error("expected false for context without region")
	}
}

func TestWithHandlerContext(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	ctx := core.NewContext(rec, req)

	WithHandlerContext(ctx, ID("eu-west-1"))
	id, ok := FromHandlerContext(ctx)
	if !ok {
		t.Fatal("expected region after WithHandlerContext")
	}
	if id != "eu-west-1" {
		t.Errorf("expected 'eu-west-1', got %q", id)
	}
}

func TestMiddlewareNilResolver(t *testing.T) {
	mw := Middleware(nil, MiddlewareOptions{})
	if mw == nil {
		t.Error("expected non-nil middleware even with nil resolver")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	ctx := core.NewContext(rec, req)

	mw(ctx)
	id, ok := FromHandlerContext(ctx)
	if ok {
		t.Errorf("expected no region from nil resolver, got %q", id)
	}
}

func TestWithHandlerContextNilSafe(t *testing.T) {
	WithHandlerContext(nil, ID("should-not-panic"))
}

func TestMiddlewareOptionsOnError(t *testing.T) {
	called := false
	opts := MiddlewareOptions{
		OnError: func(r *http.Request, err error) {
			called = true
		},
	}

	resolver := &staticResolver{err: errTestRegion}
	mw := Middleware(resolver, opts)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	ctx := core.NewContext(rec, req)

	mw(ctx)
	if !called {
		t.Error("expected OnError to be called")
	}
}
