package region_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/shared/core"
)

func newReq(t *testing.T, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// --- ConfigPinnedResolver ---

func TestConfigPinnedResolver_ReturnsRegion(t *testing.T) {
	t.Parallel()
	r := region.ConfigPinnedResolver{Region: "eu-west-1"}
	got, err := r.Resolve(newReq(t, nil))
	if err != nil || got != "eu-west-1" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestConfigPinnedResolver_ZeroValueUnconstrained(t *testing.T) {
	t.Parallel()
	var r region.ConfigPinnedResolver // zero Region
	got, err := r.Resolve(newReq(t, nil))
	if err != nil || got != "" {
		t.Fatalf("zero pinned resolver should be unconstrained: got %q err %v", got, err)
	}
}

// --- HeaderResolver ---

func TestHeaderResolver_DefaultHeader(t *testing.T) {
	t.Parallel()
	r := region.HeaderResolver{}
	got, err := r.Resolve(newReq(t, map[string]string{region.DefaultServingRegionHeader: "us-east-1"}))
	if err != nil || got != "us-east-1" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestHeaderResolver_CustomHeader(t *testing.T) {
	t.Parallel()
	r := region.HeaderResolver{Header: "X-Region"}
	got, _ := r.Resolve(newReq(t, map[string]string{"X-Region": "ap-south-1"}))
	if got != "ap-south-1" {
		t.Fatalf("got %q", got)
	}
}

func TestHeaderResolver_MissingFallsBackToDefault(t *testing.T) {
	t.Parallel()
	r := region.HeaderResolver{Default: "eu-west-1"}
	got, _ := r.Resolve(newReq(t, nil))
	if got != "eu-west-1" {
		t.Fatalf("missing header should fall back to Default: got %q", got)
	}
}

func TestHeaderResolver_AllowlistAccepts(t *testing.T) {
	t.Parallel()
	r := region.HeaderResolver{Allowed: []region.ID{"eu-west-1", "us-east-1"}}
	got, _ := r.Resolve(newReq(t, map[string]string{region.DefaultServingRegionHeader: "us-east-1"}))
	if got != "us-east-1" {
		t.Fatalf("allow-listed value rejected: got %q", got)
	}
}

func TestHeaderResolver_AllowlistRejectsInjection(t *testing.T) {
	t.Parallel()
	// A value outside the allowlist (e.g. an attacker-injected header) must
	// NOT be echoed — it falls back to Default.
	r := region.HeaderResolver{
		Allowed: []region.ID{"eu-west-1"},
		Default: "eu-west-1",
	}
	got, _ := r.Resolve(newReq(t, map[string]string{region.DefaultServingRegionHeader: "attacker-region"}))
	if got != "eu-west-1" {
		t.Fatalf("injected region not rejected: got %q", got)
	}
}

func TestHeaderResolver_NilRequest(t *testing.T) {
	t.Parallel()
	r := region.HeaderResolver{Default: "eu-west-1"}
	got, err := r.Resolve(nil)
	if err != nil || got != "eu-west-1" {
		t.Fatalf("nil request: got %q err %v", got, err)
	}
}

// --- ChainResolver ---

type errResolver struct{ err error }

func (e errResolver) Resolve(*http.Request) (region.ID, error) { return "", e.err }

func TestChainResolver_FirstNonEmptyWins(t *testing.T) {
	t.Parallel()
	c := region.ChainResolver{Resolvers: []region.Resolver{
		region.ConfigPinnedResolver{}, // ""
		region.ConfigPinnedResolver{Region: "us-east-1"},
		region.ConfigPinnedResolver{Region: "eu-west-1"}, // never reached
	}}
	got, err := c.Resolve(newReq(t, nil))
	if err != nil || got != "us-east-1" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestChainResolver_AllEmptyReturnsEmpty(t *testing.T) {
	t.Parallel()
	c := region.ChainResolver{Resolvers: []region.Resolver{
		region.ConfigPinnedResolver{},
		region.HeaderResolver{},
	}}
	got, err := c.Resolve(newReq(t, nil))
	if err != nil || got != "" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestChainResolver_SkipsNil(t *testing.T) {
	t.Parallel()
	c := region.ChainResolver{Resolvers: []region.Resolver{
		nil,
		region.ConfigPinnedResolver{Region: "eu-west-1"},
	}}
	got, _ := c.Resolve(newReq(t, nil))
	if got != "eu-west-1" {
		t.Fatalf("nil resolver not skipped: got %q", got)
	}
}

func TestChainResolver_ErrorShortCircuits(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	c := region.ChainResolver{Resolvers: []region.Resolver{
		errResolver{err: boom},
		region.ConfigPinnedResolver{Region: "eu-west-1"}, // never reached
	}}
	got, err := c.Resolve(newReq(t, nil))
	if !errors.Is(err, boom) || got != "" {
		t.Fatalf("chain did not short-circuit on error: got %q err %v", got, err)
	}
}

func TestChainResolver_Empty(t *testing.T) {
	t.Parallel()
	var c region.ChainResolver
	got, err := c.Resolve(newReq(t, nil))
	if err != nil || got != "" {
		t.Fatalf("empty chain: got %q err %v", got, err)
	}
}

// --- Middleware ---

func runMiddleware(t *testing.T, mw core.MiddlewareFunc, r *http.Request) core.HandlerContext {
	t.Helper()
	hctx := core.NewContext(httptest.NewRecorder(), r)
	mw(hctx)
	return hctx
}

func TestMiddleware_StashesResolvedRegion(t *testing.T) {
	t.Parallel()
	mw := region.Middleware(region.ConfigPinnedResolver{Region: "eu-west-1"}, region.MiddlewareOptions{})
	hctx := runMiddleware(t, mw, newReq(t, nil))
	got, ok := region.FromHandlerContext(hctx)
	if !ok || got != "eu-west-1" {
		t.Fatalf("got %q ok %v", got, ok)
	}
}

func TestMiddleware_NilResolverIsNoOp(t *testing.T) {
	t.Parallel()
	mw := region.Middleware(nil, region.MiddlewareOptions{})
	hctx := runMiddleware(t, mw, newReq(t, nil))
	// A nil resolver stashes nothing — FromHandlerContext reports absence.
	if _, ok := region.FromHandlerContext(hctx); ok {
		t.Fatal("nil resolver middleware stashed a value")
	}
}

func TestMiddleware_ResolverErrorStashesEmptyAndProceeds(t *testing.T) {
	t.Parallel()
	boom := errors.New("malformed region source")
	var reported error
	mw := region.Middleware(errResolver{err: boom}, region.MiddlewareOptions{
		OnError: func(_ *http.Request, err error) { reported = err },
	})
	hctx := runMiddleware(t, mw, newReq(t, nil))

	// Non-fatal: an empty region is stashed (ran, but resolved nothing).
	got, ok := region.FromHandlerContext(hctx)
	if !ok || got != "" {
		t.Fatalf("error path should stash empty region: got %q ok %v", got, ok)
	}
	if !errors.Is(reported, boom) {
		t.Fatalf("OnError not invoked with the resolver error: %v", reported)
	}
}

func TestMiddleware_AllowlistDropsUnlistedRegion(t *testing.T) {
	t.Parallel()
	mw := region.Middleware(
		region.ConfigPinnedResolver{Region: "us-east-1"},
		region.MiddlewareOptions{AllowedRegions: []region.ID{"eu-west-1"}},
	)
	hctx := runMiddleware(t, mw, newReq(t, nil))
	got, ok := region.FromHandlerContext(hctx)
	// Unlisted region dropped to "" — request still proceeds (not rejected).
	if !ok || got != "" {
		t.Fatalf("unlisted region not dropped: got %q ok %v", got, ok)
	}
}

func TestMiddleware_AllowlistKeepsListedRegion(t *testing.T) {
	t.Parallel()
	mw := region.Middleware(
		region.ConfigPinnedResolver{Region: "eu-west-1"},
		region.MiddlewareOptions{AllowedRegions: []region.ID{"eu-west-1"}},
	)
	hctx := runMiddleware(t, mw, newReq(t, nil))
	got, _ := region.FromHandlerContext(hctx)
	if got != "eu-west-1" {
		t.Fatalf("listed region dropped: got %q", got)
	}
}

func TestWithHandlerContext_RoundTrip(t *testing.T) {
	t.Parallel()
	hctx := core.NewContext(httptest.NewRecorder(), newReq(t, nil))
	region.WithHandlerContext(hctx, "ap-south-1")
	got, ok := region.FromHandlerContext(hctx)
	if !ok || got != "ap-south-1" {
		t.Fatalf("got %q ok %v", got, ok)
	}
}

func TestFromHandlerContext_NilContext(t *testing.T) {
	t.Parallel()
	if _, ok := region.FromHandlerContext(nil); ok {
		t.Fatal("nil context reported a value")
	}
}

func TestWithHandlerContext_NilContextNoPanic(t *testing.T) {
	t.Parallel()
	region.WithHandlerContext(nil, "eu-west-1") // must not panic
}
