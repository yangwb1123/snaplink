package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tokenexchange"
	"github.com/snaplink/sso/domains/tokenexchange/memory"
	"github.com/snaplink/sso/shared/core"
)

// chainParamCtx layers a :jti route param onto a core.Context — StdRouter
// would inject it via path matching in production; tests supply it
// directly (same pattern as token_portfolio_test.go's tpParamCtx).
type chainParamCtx struct {
	*core.Context
	jti string
}

func (p chainParamCtx) Param(name string) string {
	if name == "jti" {
		return p.jti
	}
	return p.Context.Param(name)
}

func newChainCtx(jti string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokenexchange/chains/"+jti, nil)
	w := httptest.NewRecorder()
	return chainParamCtx{Context: core.NewContext(w, r), jti: jti}, w
}

// TestHandleTokenExchangeChain_HappyPath proves a recorded multi-hop chain
// round-trips through the REAL in-memory ChainStore and comes back
// oldest-first via the admin endpoint.
func TestHandleTokenExchangeChain_HappyPath(t *testing.T) {
	store := memory.NewChainStore()
	now := time.Now()
	hops := []tokenexchange.ChainHop{
		{JTI: "jti-root", SubjectID: "alice", ClientID: "svc-a", RecordedAt: now},
		{JTI: "jti-leaf", ParentJTI: "jti-root", SubjectID: "alice", ActorSubject: "svc-b", ClientID: "svc-b", ChainDepth: 1, RecordedAt: now.Add(time.Minute)},
	}
	for _, h := range hops {
		if err := store.RecordHop(context.Background(), h); err != nil {
			t.Fatalf("RecordHop(%s): %v", h.JTI, err)
		}
	}

	ctx, w := newChainCtx("jti-leaf")
	HandleTokenExchangeChain(store, testLogger{}, ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		JTI   string                   `json:"jti"`
		Chain []tokenexchange.ChainHop `json:"chain"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.JTI != "jti-leaf" {
		t.Errorf("jti = %q, want jti-leaf", out.JTI)
	}
	if len(out.Chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(out.Chain))
	}
	if out.Chain[0].JTI != "jti-root" || out.Chain[1].JTI != "jti-leaf" {
		t.Errorf("chain order = %+v, want [jti-root, jti-leaf] (oldest first)", out.Chain)
	}
	if out.Chain[1].ActorSubject != "svc-b" {
		t.Errorf("leaf hop ActorSubject = %q, want svc-b", out.Chain[1].ActorSubject)
	}
}

// TestHandleTokenExchangeChain_UnknownJTI proves a jti with no recorded
// chain is a 404, not a 200 with an empty body.
func TestHandleTokenExchangeChain_UnknownJTI(t *testing.T) {
	store := memory.NewChainStore()
	ctx, w := newChainCtx("never-recorded")
	HandleTokenExchangeChain(store, testLogger{}, ctx)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// TestHandleTokenExchangeChain_MissingJTI proves an empty :jti (e.g. a
// trailing-slash route match) is a 400, never a panic/500.
func TestHandleTokenExchangeChain_MissingJTI(t *testing.T) {
	store := memory.NewChainStore()
	ctx, w := newChainCtx("")
	HandleTokenExchangeChain(store, testLogger{}, ctx)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// TestHandleTokenExchangeChain_NilStore proves an unwired store (should
// never be reachable in production — the route isn't mounted without one)
// degrades to 404 rather than panicking.
func TestHandleTokenExchangeChain_NilStore(t *testing.T) {
	ctx, w := newChainCtx("jti-leaf")
	HandleTokenExchangeChain(nil, testLogger{}, ctx)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// TestHandleTokenExchangeChain_ScopeGating proves the endpoint is gated by
// the SAME admin-scope convention every other /api/v1/admin/* route uses
// (AdminMiddleware, GET -> admin:read): a request lacking the scope is
// rejected with 403 BEFORE the handler ever runs, and one holding it reaches
// the handler. Exercises the real HTTPMiddleware end-to-end (not just the
// pure handler), reusing fakeValidator/providerAuthorizer/allowAllAuthorizer
// from middleware_test.go (same package).
func TestHandleTokenExchangeChain_ScopeGating(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	// Deny: providerAuthorizer with a nil Provider always denies.
	denyMW := &Middleware{
		validator:    fakeValidator{claims: &core.TokenClaims{Subject: "u1"}},
		authorizer:   providerAuthorizer{},
		methodScopes: defaultMethodScopes(),
	}
	ts := httptest.NewServer(denyMW.HTTPMiddleware(next))
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/tokenexchange/chains/jti-leaf", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET (deny): %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET without admin:read = %d, want 403", resp.StatusCode)
	}
	if reached {
		t.Fatal("handler ran despite denied scope")
	}

	// Allow: allowAllAuthorizer grants every scope check.
	allowMW := &Middleware{
		validator:    fakeValidator{claims: &core.TokenClaims{Subject: "u1"}},
		authorizer:   allowAllAuthorizer{},
		methodScopes: defaultMethodScopes(),
	}
	ts2 := httptest.NewServer(allowMW.HTTPMiddleware(next))
	defer ts2.Close()
	req2, _ := http.NewRequest(http.MethodGet, ts2.URL+"/api/v1/admin/tokenexchange/chains/jti-leaf", nil)
	req2.Header.Set("Authorization", "Bearer t")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET (allow): %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET with admin:read = %d, want 200", resp2.StatusCode)
	}
	if !reached {
		t.Fatal("handler did not run despite allowed scope")
	}
}
